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

    pub async fn get_role_credentials(profile: SsoProfile) -> Result<Self> {
        info!("Getting role credentials");
        let credentials = get_cached_credentials(profile.profile_name.as_str()).await;
        let creds_ = credentials.filter(|creds| !creds.is_expired());
        match creds_ {
            Some(creds) => {
                debug!("aws_credentials.AWScredentials.get_role_credentials.creds from Cache still valid");
                Ok(creds)
            }
            None => {
                debug!("aws_credentials.AWScredentials.get_role_credentials.creds expired retrieving from AWS");
                let creds = Self::get_role_credentials_from_aws(profile.clone()).await;
                let mycreds = match creds.as_ref() {
                    Ok(creds) => creds,
                    Err(e) => {
                        error!("aws_credentials.AWScredentials.get_role_credentials {}", e);
                        return Err(anyhow!(MyErrors::ExpirationParser));
                    }
                };
                store_cached_credentials(&profile.profile_name, mycreds).await?;
                creds
            }
        }
    }

    pub async fn get_assume_role(
        assume_profile: AssumeSsoProfile,
        sso_profile: SsoProfile,
    ) -> Result<Self> {
        info!("Getting assume role credentials");
        let credentials = get_cached_credentials(assume_profile.profile_name.as_str()).await;
        let creds_ = credentials.filter(|creds| !creds.is_expired());
        match creds_ {
            Some(creds) => {
                debug!(
                    "aws_credentials.AWScredentials.get_assume_role.creds from Cache still valid"
                );
                Ok(creds)
            }
            None => {
                debug!("aws_credentials.AWScredentials.get_assume_role.creds expired retrieving from AWS");
                let creds =
                    Self::get_assume_role_from_aws(assume_profile.clone(), sso_profile.clone())
                        .await;
                let mycreds = match creds.as_ref() {
                    Ok(creds) => creds,
                    Err(e) => {
                        error!("aws_credentials.AWScredentials.get_assume_role {}", e);
                        return Err(anyhow!(MyErrors::GetRoleCredentialError));
                    }
                };
                store_cached_credentials(assume_profile.profile_name.as_str(), mycreds).await?;
                creds
            }
        }
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
    ExpirationParser,
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
            Self::ExpirationParser => write!(f, "Could no parse AWS expiration date!"),
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
