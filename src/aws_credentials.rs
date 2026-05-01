use crate::{
    aws_profile::{AssumeSsoProfile, SsoProfile},
    aws_sso_credentials::{self},
    cache::{get_cached_credentials, store_cached_credentials},
};
use anyhow::{anyhow, Result};
use aws_config::sso::credentials::Builder;
use aws_sdk_sso;
use aws_sdk_sts;
use aws_smithy_types_convert::date_time::DateTimeExt;
use aws_types::region::Region as sdkRegion;
use aws_types::sdk_config::SharedCredentialsProvider;
use chrono::{DateTime as CDateTime, Local};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use whoami;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct AWScredentials {
    Version: u8,
    pub AccessKeyId: String,
    pub SecretAccessKey: String,
    pub SessionToken: String,
    pub Expiration: String,
}

impl AWScredentials {
    fn is_expired(&self) -> bool {
        info!("Checking if credentials are expired");
        let now = Local::now().timestamp_millis();
        let exp_dt = match CDateTime::parse_from_rfc3339(&self.Expiration[..]) {
            Ok(date) => date.timestamp_millis(),
            Err(e) => {
                error!("{}", e);
                return true;
            }
        };
        debug!(
            "aws_credentials.AWScredentials.isexpired.exp_dt: {:?}",
            exp_dt
        );
        now > exp_dt
    }

    // Cache-or-fetch helper. Looks up credentials by profile name in the local
    // cache, returning them if still valid; otherwise calls the supplied AWS
    // fetch closure, stores the result, and returns it. Centralises the
    // identical control flow shared by get_role_credentials and get_assume_role.
    async fn get_or_refresh<F, Fut>(cache_key: &str, fetch_from_aws: F) -> Result<Self>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Self>>,
    {
        let credentials = get_cached_credentials(cache_key).await;
        match credentials.filter(|creds| !creds.is_expired()) {
            Some(creds) => {
                debug!("aws_credentials.AWScredentials.get_or_refresh: cached credentials for {} still valid", cache_key);
                Ok(creds)
            }
            None => {
                debug!("aws_credentials.AWScredentials.get_or_refresh: refreshing credentials for {} from AWS", cache_key);
                let creds = fetch_from_aws().await.map_err(|e| {
                    error!("aws_credentials.AWScredentials.get_or_refresh {}", e);
                    e
                })?;
                store_cached_credentials(cache_key, &creds).await?;
                Ok(creds)
            }
        }
    }

    pub async fn get_role_credentials(profile: SsoProfile) -> Result<Self> {
        info!("Getting role credentials");
        let cache_key = profile.profile_name.clone();
        Self::get_or_refresh(&cache_key, move || {
            Self::get_role_credentials_from_aws(profile)
        })
        .await
    }

    pub async fn get_assume_role(
        assume_profile: AssumeSsoProfile,
        sso_profile: SsoProfile,
    ) -> Result<Self> {
        info!("Getting assume role credentials");
        let cache_key = assume_profile.profile_name.clone();
        Self::get_or_refresh(&cache_key, move || {
            Self::get_assume_role_from_aws(assume_profile, sso_profile)
        })
        .await
    }

    async fn get_role_credentials_from_aws(profile: SsoProfile) -> Result<Self> {
        info!("Getting role credentials from AWS");
        debug!(
            "aws_credentials.AWScredentials.get_role_credentials_from_aws({})",
            profile.profile_name
        );
        let sdkregion = sdkRegion::new(profile.sso_region);
        let provider = Builder::new()
            .region(sdkregion.clone())
            .role_name(&profile.sso_role_name)
            .account_id(&profile.sso_account_id)
            .start_url(&profile.sso_start_url)
            .build();
        let config = aws_sdk_sso::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest())
            .credentials_provider(provider)
            .build();

        let aws_sso_credentials =
            aws_sso_credentials::SsoCredentials::get(profile.profile_name).await?;

        let client = aws_sdk_sso::Client::from_conf(config);
        let output = match client
            .get_role_credentials()
            .role_name(&profile.sso_role_name)
            .account_id(&profile.sso_account_id)
            .access_token(&aws_sso_credentials.accessToken)
            .send()
            .await
        {
            Ok(role_creds) => role_creds,
            Err(e) => {
                error!(
                    "aws_credentials.AWScredentials.get_role_credentials_from_aws {}",
                    e
                );
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let credentials = match output.role_credentials {
            Some(role_creds) => role_creds,
            None => {
                error!("aws_credentials.AWScredentials.get_role_credentials_from_aws output.role_credentials is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        // Ok(output) => match output.credentials {
        let string_access_key_id = match &credentials.access_key_id {
            Some(access_key) => access_key.to_owned(),
            None => {
                error!("aws_credentials.AWScredentials.get_role_credentials_from_aws credentials.access_key_id is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialAccessKeyError));
            }
        };
        let string_secret_access_key = match &credentials.secret_access_key {
            Some(secret_key) => secret_key.to_owned(),
            None => {
                error!("aws_credentials.AWScredentials.get_role_credentials_from_aws credentials.secret_access_key is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialSecretKeyError));
            }
        };
        let string_session_token = match &credentials.session_token {
            Some(token) => token.to_owned(),
            None => {
                error!("aws_credentials.AWScredentials.get_role_credentials_from_aws credentials.session_token is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialErrorSessionToken));
            }
        };
        let string_expiration = match CDateTime::from_timestamp(credentials.expiration() / 1000, 0)
        {
            Some(expiration) => expiration.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            None => {
                error!("aws_credentials.AWScredentials.get_role_credentials_from_aws credentials.expiration is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialExpirationError));
            }
        };
        Ok(Self {
            Version: 1_u8,
            AccessKeyId: string_access_key_id,
            SecretAccessKey: string_secret_access_key,
            SessionToken: string_session_token,
            Expiration: string_expiration,
        })
    }

    pub async fn get_assume_role_from_aws(
        assume_profile: AssumeSsoProfile,
        sso_profile: SsoProfile,
    ) -> Result<Self> {
        info!("Getting assume role credentials from AWS");
        debug!(
            "aws_credentials.AWScredentials.get_assume_role_from_aws({})",
            assume_profile.profile_name
        );
        let sso_creds = match AWScredentials::get_role_credentials(sso_profile.clone()).await {
            Ok(cred) => cred,
            Err(e) => {
                error!(
                    "aws_credentials.AWScredentials.get_assume_role_from_aws {}",
                    e
                );
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let sdkregion = sdkRegion::new(sso_profile.clone().sso_region);
        let credentials = aws_sdk_sts::config::Credentials::new(
            &sso_creds.AccessKeyId,
            &sso_creds.SecretAccessKey,
            Some(sso_creds.SessionToken),
            None,
            "",
        );
        let shared_cred_provider = SharedCredentialsProvider::new(credentials);
        let mut config_builder = aws_sdk_sts::Config::builder();
        config_builder.set_credentials_provider(Some(shared_cred_provider));
        config_builder.set_behavior_version(Some(aws_sdk_sts::config::BehaviorVersion::latest()));
        config_builder.set_region(Some(sdkregion));

        let config = config_builder.build();
        let client = aws_sdk_sts::Client::from_conf(config);
        let username = whoami::username();
        let output = match client
            .assume_role()
            .set_role_session_name(Some(username))
            .set_role_arn(Some(assume_profile.role_arn))
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                error!(
                    "aws_credentials.AWScredentials.get_assume_role_from_aws {}",
                    e
                );
                return Err(anyhow!(MyErrors::AssumeRoleError));
            }
        };
        let credentials = match output.credentials {
            Some(cred) => cred,
            None => {
                error!(
                    "aws_credentials.AWScredentials.get_assume_role_from_aws output.credentials is none",
                );
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };

        let string_expiration = match credentials.expiration().to_chrono_utc() {
            Ok(expiration) => expiration.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            Err(e) => {
                error!(
                    "aws_credentials.AWScredentials.get_assume_role_from_aws {}",
                    e
                );

                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        Ok(Self {
            Version: 1_u8,
            AccessKeyId: credentials.access_key_id().to_string(),
            SecretAccessKey: credentials.secret_access_key().to_string(),
            SessionToken: credentials.session_token().to_string(),
            Expiration: string_expiration,
        })
    }

    pub fn as_json(&self) -> Result<String> {
        match serde_json::to_string(&self) {
            Ok(ser) => Ok(ser),
            Err(e) => {
                error!("aws_credentials.AWScredentials.as_json {}", e);
                Err(anyhow!(MyErrors::GetRoleCredentialError))
            }
        }
    }
}

#[derive(Debug)]
enum MyErrors {
    GetRoleCredentialError,
    GetRoleCredentialAccessKeyError,
    GetRoleCredentialSecretKeyError,
    GetRoleCredentialExpirationError,
    AssumeRoleError,
    GetRoleCredentialErrorSessionToken,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetRoleCredentialError => write!(f, "Error getting credentials!"),
            Self::AssumeRoleError => write!(f, "Error getting Assume Role from AWS!"),
            Self::GetRoleCredentialAccessKeyError => {
                write!(f, "Could not get access key from credentials!")
            }
            Self::GetRoleCredentialSecretKeyError => {
                write!(f, "Could not get secret key from credentials!")
            }
            Self::GetRoleCredentialExpirationError => {
                write!(f, "Could not get expiration from credentials!")
            }
            Self::GetRoleCredentialErrorSessionToken => {
                write!(f, "Could not get access token from credentials!")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_creds() -> AWScredentials {
        AWScredentials {
            Version: 1,
            AccessKeyId: "AKIAIOSFODNN7EXAMPLE".to_string(),
            SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            SessionToken: "FwoGZXIvYXdzEA...".to_string(),
            Expiration: "2099-01-01T00:00:00+00:00".to_string(),
        }
    }

    // --- as_json() ---

    #[test]
    fn test_as_json_produces_valid_json() {
        let creds = make_creds();
        let json_str = creds.as_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(value.is_object());
    }

    #[test]
    fn test_as_json_contains_all_fields() {
        let creds = make_creds();
        let json_str = creds.as_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(value["Version"], 1);
        assert_eq!(value["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            value["SecretAccessKey"],
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(value["SessionToken"], "FwoGZXIvYXdzEA...");
        assert_eq!(value["Expiration"], "2099-01-01T00:00:00+00:00");
    }

    #[test]
    fn test_as_json_camel_case_keys() {
        let creds = make_creds();
        let json_str = creds.as_json().unwrap();
        assert!(json_str.contains("\"AccessKeyId\""));
        assert!(json_str.contains("\"SecretAccessKey\""));
        assert!(json_str.contains("\"SessionToken\""));
        assert!(json_str.contains("\"Expiration\""));
        assert!(json_str.contains("\"Version\""));
    }

    // --- Serde ---

    #[test]
    fn test_serde_round_trip() {
        let creds = make_creds();
        let json = serde_json::to_string(&creds).unwrap();
        let deser: AWScredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.AccessKeyId, creds.AccessKeyId);
        assert_eq!(deser.SecretAccessKey, creds.SecretAccessKey);
        assert_eq!(deser.SessionToken, creds.SessionToken);
        assert_eq!(deser.Expiration, creds.Expiration);
        assert_eq!(deser.Version, creds.Version);
    }

    #[test]
    fn test_deserialize_from_json() {
        let json = r#"{
            "Version": 1,
            "AccessKeyId": "AK",
            "SecretAccessKey": "SK",
            "SessionToken": "ST",
            "Expiration": "2099-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.Version, 1);
        assert_eq!(creds.AccessKeyId, "AK");
    }

    #[test]
    fn test_deserialize_missing_field_error() {
        let json = r#"{"Version": 1, "AccessKeyId": "AK"}"#;
        let result = serde_json::from_str::<AWScredentials>(json);
        assert!(result.is_err());
    }

    // --- Clone ---

    #[test]
    fn test_clone() {
        let creds = make_creds();
        let cloned = creds.clone();
        assert_eq!(cloned.AccessKeyId, creds.AccessKeyId);
        assert_eq!(cloned.SecretAccessKey, creds.SecretAccessKey);
    }

    // --- MyErrors Display ---

    #[test]
    fn test_error_display_get_role_credential() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialError),
            "Error getting credentials!"
        );
    }

    #[test]
    fn test_error_display_assume_role() {
        assert_eq!(
            format!("{}", MyErrors::AssumeRoleError),
            "Error getting Assume Role from AWS!"
        );
    }

    #[test]
    fn test_error_display_access_key() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialAccessKeyError),
            "Could not get access key from credentials!"
        );
    }

    #[test]
    fn test_error_display_secret_key() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialSecretKeyError),
            "Could not get secret key from credentials!"
        );
    }

    #[test]
    fn test_error_display_expiration() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialExpirationError),
            "Could not get expiration from credentials!"
        );
    }

    #[test]
    fn test_error_display_session_token() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialErrorSessionToken),
            "Could not get access token from credentials!"
        );
    }

    // --- Proptest ---

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_as_json_always_valid(
            ak in "[A-Z0-9]{20}",
            sk in "[A-Za-z0-9/+=]{40}",
            st in "[A-Za-z0-9/+=]{20,100}",
            exp in "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        ) {
            let creds = AWScredentials {
                Version: 1,
                AccessKeyId: ak,
                SecretAccessKey: sk,
                SessionToken: st,
                Expiration: exp,
            };
            let json_str = creds.as_json().unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
            prop_assert!(parsed.is_object());
            prop_assert_eq!(parsed["Version"].clone(), serde_json::json!(1));
        }
    }
}
