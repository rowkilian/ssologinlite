use crate::{cache::get_cached_sso_registration, constants::PROGRAM_NAME};
use anyhow::{anyhow, Result};
use aws_sdk_ssooidc;
use aws_types::region::Region as sdkRegion;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use log::{debug, error, info};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[allow(non_snake_case)]
pub struct SsoRegistration {
    pub clientSecret: String,
    pub clientId: String,
    pub expiresAt: String,
}

impl SsoRegistration {
    pub async fn get() -> Result<SsoRegistration> {
        match SsoRegistration::from_cache().await {
            Some(reg) => {
                if reg.is_expired() {
                    info!("SSO registration is expired. Registering new client.");
                    SsoRegistration::register_client().await
                } else {
                    Ok(reg)
                }
            }
            None => {
                info!("No SSO registration found. Registering new client.");
                SsoRegistration::register_client().await
            }
        }
    }

    async fn from_cache() -> Option<SsoRegistration> {
        get_cached_sso_registration().await
    }

    pub fn is_expired(&self) -> bool {
        let now = Local::now().naive_local();
        // let st_exp: &str = &self.expiresAt[..];
        let exp_dt = match NaiveDateTime::parse_from_str(&self.expiresAt[..], "%Y-%m-%dT%H:%M:%S%z")
        {
            Ok(expiration) => expiration,
            Err(e) => {
                error!("{}", e);
                return true;
            }
        };
        debug!("SsoRegistration.is_expired.now {:?}", now);
        debug!("SsoRegistration.is_expired.exp_dt {:?}", exp_dt);
        debug!("SsoRegistration.is_expired.is_expired {:?}", now > exp_dt);
        now > exp_dt
    }

    pub async fn register_client() -> Result<SsoRegistration> {
        let sso_region = "us-west-2";
        let sdkregion = sdkRegion::new(sso_region);

        let config = aws_sdk_ssooidc::Config::builder()
            .region(sdkregion)
            .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
            .build();

        let client = aws_sdk_ssooidc::Client::from_conf(config);

        let mut rng = rand::thread_rng();
        let id: u32 = rng.gen_range(100000000..999999999);
        let client_name = format!("{}-{}", PROGRAM_NAME, id);
        let output = match client
            .register_client()
            .set_client_name(Some(client_name.to_string()))
            .set_client_type(Some(("public").to_string()))
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                error!("{}", e);
                return Err(anyhow!(MyErrors::RegisterClientError));
            }
        };
        let client_secret = match output.client_secret {
            Some(secret) => secret,
            None => {
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let client_id = match output.client_id {
            Some(id) => id,
            None => {
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };
        let timestamp = output.client_secret_expires_at;
        // let naive = NaiveDateTime::from_timestamp(timestamp, 0);
        let datetime: DateTime<Utc> = match DateTime::from_timestamp(timestamp, 0) {
            Some(dt) => dt,
            None => {
                return Err(anyhow!(MyErrors::GetRoleCredentialError));
            }
        };

        // self.registrationExpiresAt = datetime.to_rfc3339();
        let res = SsoRegistration {
            clientSecret: client_secret,
            clientId: client_id,
            expiresAt: datetime.to_rfc3339(),
        };
        Ok(res)
    }
}

// Error definitions
#[derive(Debug)]
enum MyErrors {
    GetRoleCredentialError,
    RegisterClientError,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetRoleCredentialError => write!(f, "Error getting credentials!"),
            Self::RegisterClientError => write!(f, "Error registering client!"),
        }
    }
}
