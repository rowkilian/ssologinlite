use crate::aws_profile::SsoProfile;
use crate::aws_sso_registration::SsoRegistration;
use crate::cache::{cache_sso_credentials, get_cached_sso_credentials};
use crate::config::ProgramConfig;
use crate::mywebbrowser::open_url;
use anyhow::{anyhow, Result};
use aws_sdk_ssooidc;
use aws_types::region::Region as sdkRegion;
use chrono::{Duration, NaiveDateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::time::{Duration as StdDuration, Instant};

// Refresh this many seconds before the real expiry so a token with only moments
// left isn't returned and then rejected by AWS mid-call.
const EXPIRY_SKEW_SECS: i64 = 60;

// Consecutive unclassified create_token failures tolerated while polling before
// the device-code login is abandoned.
const MAX_CONSECUTIVE_ERRORS: u32 = 5;

// Added to the poll interval each time AWS answers SlowDownException.
const SLOW_DOWN_BACKOFF_SECS: u64 = 5;

// True when `e` is the given MyErrors variant. create_token tags its expected
// polling responses this way so refresh() can tell them apart from real errors.
fn is_error(e: &anyhow::Error, want: MyErrors) -> bool {
    e.downcast_ref::<MyErrors>()
        .is_some_and(|got| std::mem::discriminant(got) == std::mem::discriminant(&want))
}

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

        // The verification URL embeds the user_code; logging it would let
        // anyone with read access to the log complete the SSO authorization
        // as the user. Log a benign message instead.
        debug!("opening browser to complete SSO authorization");
        open_url(conf, url_as_str.clone()).map_err(|e| {
            error!("aws_sso_credentials.SsoCredentials.refresh open_url: {}", e);
            anyhow!(MyErrors::GetUrlError)
        })?;

        let deadline = Instant::now() + StdDuration::from_secs(expires_in_secs);
        let mut poll_interval = StdDuration::from_secs(interval_secs);
        let mut consecutive_errors: u32 = 0;
        while Instant::now() < deadline {
            tokio::time::sleep(poll_interval).await;
            match SsoCredentials::create_token(profile.clone(), device_code.clone()).await {
                Ok(creds) => {
                    debug!("device-code authorization completed");
                    return Ok(creds);
                }
                // AuthorizationPending is the normal "user hasn't clicked through
                // yet" response — keep polling at the same rate.
                Err(e) if is_error(&e, MyErrors::AuthorizationPending) => {
                    consecutive_errors = 0;
                    debug!("device-code not yet authorized; continuing to poll");
                }
                // SlowDown means AWS is rejecting our poll rate. Continuing to
                // poll at the rejected interval just keeps getting refused, so
                // actually back off.
                Err(e) if is_error(&e, MyErrors::SlowDown) => {
                    consecutive_errors = 0;
                    poll_interval += StdDuration::from_secs(SLOW_DOWN_BACKOFF_SECS);
                    debug!(
                        "AWS asked us to slow down; polling every {}s from now on",
                        poll_interval.as_secs()
                    );
                }
                // Anything else (network blip, transient 5xx, an SDK error we
                // don't classify) gets a bounded number of retries. Aborting the
                // whole login on the first one lets a single hiccup kill a
                // browser flow the user has already started — the original
                // implementation retried every error until the device code
                // expired, which was too permissive in the other direction.
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        error!(
                            "aws_sso_credentials.SsoCredentials.refresh: giving up after \
                             {} consecutive errors while polling for the device code: {}",
                            consecutive_errors, e
                        );
                        return Err(e);
                    }
                    warn!(
                        "aws_sso_credentials.SsoCredentials.refresh: error while polling \
                         ({}/{}), retrying: {}",
                        consecutive_errors, MAX_CONSECUTIVE_ERRORS, e
                    );
                }
            }
        }
        // Logged, not just returned: this is the cold path's most likely dead end
        // and the polling detail above is debug-only, so at the default INFO level
        // this line is the only record of why the login produced nothing.
        error!(
            "aws_sso_credentials.SsoCredentials.refresh: device-code authorization \
             timed out after {} seconds",
            expires_in_secs
        );
        Err(anyhow!(
            "SSO device-code authorization timed out after {} seconds; \
             the browser flow was not completed in time",
            expires_in_secs
        ))
    }

    pub async fn login_url_from_aws(profile: SsoProfile) -> Result<UrlCode> {
        info!("getting login url from AWS");
        let sdkregion = sdkRegion::new(profile.sso_region.clone());
        // No credentials_provider: start_device_authorization authenticates with
        // the registered client_id/client_secret, not SSO credentials. Attaching
        // an SSO provider here would be circular (it resolves the very token this
        // flow exists to obtain).
        let config = aws_sdk_ssooidc::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
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
        // No credentials_provider: create_token authenticates with the client
        // secret + device_code, not SSO credentials (see login_url_from_aws).
        let config = aws_sdk_ssooidc::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
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
                // Tag the two expected polling responses with their own
                // variants so refresh() can tell "keep waiting" from "keep
                // waiting, but slower". Everything else (invalid client/grant,
                // expired device code, access denied, network errors) collapses
                // to GetRoleCredentialError, which refresh() retries a bounded
                // number of times before giving up.
                use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
                match e.as_service_error() {
                    Some(CreateTokenError::AuthorizationPendingException(_)) => {
                        debug!(
                            "aws_sso_credentials.SsoCredentials.create_token (pending): {}",
                            e
                        );
                        return Err(anyhow!(MyErrors::AuthorizationPending));
                    }
                    Some(CreateTokenError::SlowDownException(_)) => {
                        debug!(
                            "aws_sso_credentials.SsoCredentials.create_token (slow down): {}",
                            e
                        );
                        return Err(anyhow!(MyErrors::SlowDown));
                    }
                    _ => {}
                }
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
        // Store the expiry as a real UTC instant. The `Z`-suffixed format below
        // labels the value as UTC, so it must be built from UTC — using local
        // time here would mislabel a local wall-clock time as UTC.
        let expiration = Utc::now().naive_utc() + Duration::seconds(output.expires_in.into());
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
        let now = Utc::now().naive_utc();
        let pre_exp = &self.expiresAt;
        let exp_dt = match NaiveDateTime::parse_from_str(&pre_exp[..], "%Y-%m-%dT%H:%M:%SZ") {
            Ok(expiration) => expiration,
            Err(e) => {
                error!("aws_sso_credentials.SsoCredentials.create_token {}", e);
                return Err(anyhow!(MyErrors::ExpirationParser));
            }
        };
        let expires_in = exp_dt - now;
        // expires_in stays the true remaining time, but the "expired" flag trips
        // EXPIRY_SKEW_SECS early so we refresh before a token can lapse mid-use.
        let expired = now + Duration::seconds(EXPIRY_SKEW_SECS) > exp_dt;
        Ok((expires_in, expired))
    }

    pub fn is_expired(&self) -> bool {
        match self.expires() {
            Ok((_, expired)) => expired,
            Err(_) => true,
        }
    }
}

// Error definitions
#[derive(Debug)]
enum MyErrors {
    ExpirationParser,
    GetRoleCredentialError,
    GetUrlError,
    CredentialsFromURLError,
    // Tags create_token's expected polling responses so the refresh() loop can
    // distinguish "keep waiting" (AuthorizationPending), "keep waiting, but
    // slower" (SlowDown), and a real error that only gets a bounded retry.
    AuthorizationPending,
    SlowDown,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpirationParser => write!(f, "Could not parse AWS expiration date!"),
            Self::GetRoleCredentialError => write!(f, "Error getting credentials!"),
            Self::GetUrlError => write!(f, "Error getting URL!"),
            Self::CredentialsFromURLError => write!(f, "Error getting credentials with URL!"),
            Self::AuthorizationPending => {
                write!(f, "device-code authorization is still pending")
            }
            Self::SlowDown => write!(f, "AWS asked us to slow down polling"),
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
        let future = (Utc::now().naive_utc() + Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&future);
        let (dur, expired) = creds.expires().unwrap();
        assert!(!expired);
        assert!(dur.num_minutes() > 100);
    }

    #[test]
    fn test_expires_past_date() {
        let past = (Utc::now().naive_utc() - Duration::hours(2))
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
        let future = (Utc::now().naive_utc() + Duration::hours(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let creds = make_creds(&future);
        assert!(!creds.is_expired());
    }

    #[test]
    fn test_is_expired_past() {
        let past = (Utc::now().naive_utc() - Duration::hours(2))
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
            expires_in: 600,
            interval: 1,
        };
        let json = serde_json::to_string(&uc).unwrap();
        let deser: UrlCode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.device_code, "dev-code");
        assert_eq!(deser.url, "https://example.com");
        assert_eq!(deser.expires_in, 600);
        assert_eq!(deser.interval, 1);
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
        fn test_expires_sign_matches_bool(offset_secs in -604800i64..604800i64) {
            let dt = Utc::now().naive_utc() + Duration::seconds(offset_secs);
            let formatted = dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let creds = make_creds(&formatted);
            if let Ok((dur, expired)) = creds.expires() {
                // The "expired" flag trips EXPIRY_SKEW_SECS before real expiry.
                // (±1s slack absorbs the clock ticks between building dt and now.)
                if expired {
                    prop_assert!(dur.num_seconds() <= EXPIRY_SKEW_SECS + 1);
                } else {
                    prop_assert!(dur.num_seconds() >= EXPIRY_SKEW_SECS - 1);
                }
            }
        }
    }
}
