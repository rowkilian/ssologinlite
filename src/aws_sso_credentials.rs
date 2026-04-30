use crate::aws_profile::SsoProfile;
use crate::aws_sso_registration::SsoRegistration;
use crate::cache::{cache_sso_credentials, get_cached_sso_credentials};
use crate::config::ProgramConfig;
use crate::mywebbrowser::open_url;
use anyhow::{anyhow, Result};
use aws_config::sso::credentials::Builder;
use aws_sdk_ssooidc;
use aws_types::region::Region as sdkRegion;
use chrono::{Duration, Local, NaiveDateTime};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::time::{Duration as StdDuration, Instant};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[allow(non_snake_case)]
pub struct SsoCredentials {
    pub expiresAt: String,
    pub region: String,
    pub startUrl: String,
    pub accessToken: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UrlCode {
    pub device_code: String,
    pub url: String,
    // Lifetime of the device_code in seconds, as returned by AWS OIDC
    // StartDeviceAuthorization. Polling beyond this is guaranteed to fail.
    pub expires_in: i32,
    // AWS-recommended polling interval in seconds.
    pub interval: i32,
}

impl SsoCredentials {
    pub async fn get(profile_name: String) -> Result<SsoCredentials> {
        info!("get SsoCredentials for {}", profile_name);
        let profile = SsoProfile::get(profile_name)?;
        let url = profile.sso_start_url.clone();
        let mut hash_url = sha1_smol::Sha1::new();
        hash_url.update(url.as_bytes());

        match get_cached_sso_credentials(hash_url.digest().to_string().as_str()).await {
            Some(creds) => {
                if creds.is_expired() {
                    info!("SSO credentials are expired. Refreshing.");
                    SsoCredentials::refresh(profile).await
                } else {
                    Ok(creds)
                }
            }
            None => {
                info!("No SSO credentials found. Refreshing.");
                SsoCredentials::refresh(profile).await
            }
        }
    }

    pub async fn from_url(url: &str) -> Result<SsoCredentials> {
        info!("get sso_credentials from url");
        let mut hash_url = sha1_smol::Sha1::new();
        hash_url.update(url.as_bytes());
        match get_cached_sso_credentials(hash_url.digest().to_string().as_str()).await {
            Some(creds) => Ok(creds),
            None => {
                error!("No credentials found in cache for url.");
                Err(anyhow!(MyErrors::CredentialsFromURLError))
            }
        }
    }

    async fn refresh(profile: SsoProfile) -> Result<SsoCredentials> {
        info!(
            "refresh (calling AWS api) SsoCredentials for {}",
            profile.profile_name
        );
        let conf = ProgramConfig::new()?;
        debug!("getting login url from AWS");
        let url_code = SsoCredentials::login_url_from_aws(profile.clone())
            .await
            .map_err(|e| {
                error!("aws_sso_credentials.SsoCredentials.refresh {}", e);
                anyhow!(MyErrors::GetUrlError)
            })?;

        // AWS returns a device_code with a fixed lifetime (typically ~10 minutes)
        // and a recommended polling interval. Bound the loop with these values
        // so a user who closes the browser tab doesn't leave us spinning forever.
        // .max(1) guards against zero/negative values from unexpected API responses.
        let expires_in_secs = url_code.expires_in.max(1) as u64;
        let interval_secs = url_code.interval.max(1) as u64;
        let device_code = url_code.device_code;
        let url_as_str = url_code.url;

        debug!("opening browser with url: {}", url_as_str);
        open_url(conf, url_as_str.clone()).map_err(|e| {
            error!("aws_sso_credentials.SsoCredentials.refresh open_url: {}", e);
            anyhow!(MyErrors::GetUrlError)
        })?;

        let deadline = Instant::now() + StdDuration::from_secs(expires_in_secs);
        while Instant::now() < deadline {
            tokio::time::sleep(StdDuration::from_secs(interval_secs)).await;
            match SsoCredentials::create_token(profile.clone(), device_code.clone()).await {
                Ok(creds) => {
                    debug!("device-code authorization completed");
                    return Ok(creds);
                }
                Err(e) => {
                    // create_token errors are expected during the polling phase
                    // (AuthorizationPendingException), so treat them as "not yet"
                    // and keep polling until the deadline.
                    debug!("device-code not yet authorized: {}", e);
                    continue;
                }
            }
        }
        Err(anyhow!(
            "SSO device-code authorization timed out after {} seconds; \
             the browser flow was not completed in time",
            expires_in_secs
        ))
    }

    pub async fn login_url_from_aws(profile: SsoProfile) -> Result<UrlCode> {
        info!("getting login url from AWS");
        let sdkregion = sdkRegion::new(profile.sso_region.clone());
        let provider = Builder::new()
            .region(sdkregion.clone())
            .role_name(&profile.sso_role_name)
            .account_id(&profile.sso_account_id)
            .start_url(profile.sso_start_url.clone())
            .build();
        let config = aws_sdk_ssooidc::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
            .credentials_provider(provider)
            .build();

        let client = aws_sdk_ssooidc::Client::from_conf(config);
        let registration = SsoRegistration::get(&profile.sso_region).await?;
        let output = match client
            .start_device_authorization()
            .set_client_id(Some(registration.clientId.to_owned()))
            .set_client_secret(Some(registration.clientSecret.to_owned()))
            .set_start_url(Some(profile.sso_start_url))
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                error!(
                    "aws_sso_credentials.SsoCredentials.login_url_from_aws {}",
                    e
                );
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };

        let res_device_code = match output.device_code {
            Some(code) => code,
            None => {
                error!(
                    "aws_sso_credentials.SsoCredentials.login_url_from_aws res_device_code is None"
                );
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let res_url = match output.verification_uri_complete {
            Some(url) => url,
            None => {
                error!("aws_sso_credentials.SsoCredentials.login_url_from_aws res_url is None");
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        Ok(UrlCode {
            url: res_url,
            device_code: res_device_code,
            expires_in: output.expires_in,
            interval: output.interval,
        })
    }

    pub async fn create_token(profile: SsoProfile, device_code: String) -> Result<SsoCredentials> {
        info!("getting token from AWS");
        let registration = SsoRegistration::get(&profile.sso_region).await?;
        let sdkregion = sdkRegion::new(profile.sso_region.clone());
        let provider = Builder::new()
            .region(sdkregion.clone())
            .role_name(&profile.sso_role_name)
            .account_id(&profile.sso_account_id)
            .start_url(&profile.sso_start_url)
            .build();
        let config = aws_sdk_ssooidc::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
            .credentials_provider(provider)
            .build();

        let client = aws_sdk_ssooidc::Client::from_conf(config);

        let output = match client
            .create_token()
            .set_client_id(Some(registration.clientId.to_owned()))
            .set_client_secret(Some(registration.clientSecret.to_owned()))
            .set_device_code(Some(device_code))
            .set_grant_type(Some(
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ))
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                error!("aws_sso_credentials.SsoCredentials.create_token {}", e);
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let access_token = match output.access_token {
            Some(token) => token,
            None => {
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let expiration = Local::now().naive_local() + Duration::seconds(output.expires_in.into());
        let url = profile.sso_start_url.clone();
        let mut hash_url = sha1_smol::Sha1::new();
        hash_url.update(url.as_bytes());

        let res = SsoCredentials {
            expiresAt: expiration.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            region: profile.sso_region,
            startUrl: profile.sso_start_url,
            accessToken: access_token,
        };

        cache_sso_credentials(hash_url.digest().to_string().as_str(), &(res.clone())).await?;
        Ok(res)
    }

    pub fn expires(&self) -> Result<(chrono::Duration, bool)> {
        info!("checking token expiration");
        let now = Local::now().naive_local();
        let pre_exp = &self.expiresAt;
        let exp_dt = match NaiveDateTime::parse_from_str(&pre_exp[..], "%Y-%m-%dT%H:%M:%SZ") {
            Ok(expiration) => expiration,
            Err(e) => {
                error!("aws_sso_credentials.SsoCredentials.create_token {}", e);
                return Err(anyhow!(MyErrors::ExpirationParser));
            }
        };
        let expires_in = exp_dt - now;
        Ok((expires_in, now > exp_dt))
    }

    pub fn is_expired(&self) -> bool {
        match self.expires() {
            Ok((_, expired)) => expired,
            Err(_) => true,
        }
    }

    pub fn get_access_token(&self) -> String {
        self.accessToken.clone()
    }
}

// Error definitions
#[derive(Debug)]
enum MyErrors {
    ExpirationParser,
    GetRoleCredentialError,
    GetUrlError,
    CredentialsFromURLError,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpirationParser => write!(f, "Could not parse AWS expiration date!"),
            Self::GetRoleCredentialError => write!(f, "Error getting credentials!"),
            Self::GetUrlError => write!(f, "Error getting URL!"),
            Self::CredentialsFromURLError => write!(f, "Error getting credentials with URL!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_creds(expires_at: &str) -> SsoCredentials {
        SsoCredentials {
            expiresAt: expires_at.to_string(),
            region: "us-west-2".to_string(),
            startUrl: "https://my-sso.awsapps.com/start".to_string(),
            accessToken: "test-access-token-123".to_string(),
        }
    }

    // --- expires() ---

    #[test]
    fn test_expires_future_date() {
        let future = (Local::now().naive_local() + Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&future);
        let (dur, expired) = creds.expires().unwrap();
        assert!(!expired);
        assert!(dur.num_minutes() > 100);
    }

    #[test]
    fn test_expires_past_date() {
        let past = (Local::now().naive_local() - Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&past);
        let (dur, expired) = creds.expires().unwrap();
        assert!(expired);
        assert!(dur.num_minutes() < 0);
    }

    #[test]
    fn test_expires_invalid_format() {
        let creds = make_creds("not-a-date");
        assert!(creds.expires().is_err());
    }

    #[test]
    fn test_expires_empty_string() {
        let creds = make_creds("");
        assert!(creds.expires().is_err());
    }

    // --- is_expired() ---

    #[test]
    fn test_is_expired_future() {
        let future = (Local::now().naive_local() + Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&future);
        assert!(!creds.is_expired());
    }

    #[test]
    fn test_is_expired_past() {
        let past = (Local::now().naive_local() - Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&past);
        assert!(creds.is_expired());
    }

    #[test]
    fn test_is_expired_invalid_returns_true() {
        let creds = make_creds("garbage");
        assert!(creds.is_expired());
    }

    // --- get_access_token() ---

    #[test]
    fn test_get_access_token() {
        let creds = make_creds("2099-01-01T00:00:00Z");
        assert_eq!(creds.get_access_token(), "test-access-token-123");
    }

    // --- Serde ---

    #[test]
    fn test_sso_credentials_serde_round_trip() {
        let creds = make_creds("2099-01-01T00:00:00Z");
        let json = serde_json::to_string(&creds).unwrap();
        let deser: SsoCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.expiresAt, creds.expiresAt);
        assert_eq!(deser.region, creds.region);
        assert_eq!(deser.startUrl, creds.startUrl);
        assert_eq!(deser.accessToken, creds.accessToken);
    }

    #[test]
    fn test_url_code_serde_round_trip() {
        let uc = UrlCode {
            device_code: "dev-code".to_string(),
            url: "https://example.com".to_string(),
        };
        let json = serde_json::to_string(&uc).unwrap();
        let deser: UrlCode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.device_code, "dev-code");
        assert_eq!(deser.url, "https://example.com");
    }

    // --- Default ---

    #[test]
    fn test_sso_credentials_default() {
        let creds = SsoCredentials::default();
        assert_eq!(creds.expiresAt, "");
        assert_eq!(creds.region, "");
        assert_eq!(creds.startUrl, "");
        assert_eq!(creds.accessToken, "");
    }

    #[test]
    fn test_url_code_default() {
        let uc = UrlCode::default();
        assert_eq!(uc.device_code, "");
        assert_eq!(uc.url, "");
    }

    // --- MyErrors Display ---

    #[test]
    fn test_error_display_expiration_parser() {
        assert_eq!(
            format!("{}", MyErrors::ExpirationParser),
            "Could not parse AWS expiration date!"
        );
    }

    #[test]
    fn test_error_display_get_role_credential() {
        assert_eq!(
            format!("{}", MyErrors::GetRoleCredentialError),
            "Error getting credentials!"
        );
    }

    #[test]
    fn test_error_display_get_url() {
        assert_eq!(format!("{}", MyErrors::GetUrlError), "Error getting URL!");
    }

    #[test]
    fn test_error_display_credentials_from_url() {
        assert_eq!(
            format!("{}", MyErrors::CredentialsFromURLError),
            "Error getting credentials with URL!"
        );
    }

    // --- Proptest ---

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_expires_sign_matches_bool(offset in -168i64..168i64) {
            let dt = Local::now().naive_local() + Duration::hours(offset);
            let formatted = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let creds = make_creds(&formatted);
            if let Ok((dur, expired)) = creds.expires() {
                // If expired is true, duration should be negative (or close to 0)
                // If expired is false, duration should be positive (or close to 0)
                if expired {
                    prop_assert!(dur.num_seconds() <= 1);
                } else {
                    prop_assert!(dur.num_seconds() >= -1);
                }
            }
        }
    }
}
