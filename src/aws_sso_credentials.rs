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
use std::thread;
use std::time::Duration as StdDuration;
// use webbrowser::{open_browser, Browser};

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
                return Err(anyhow!(MyErrors::CredentialsFromURLError));
            }
        }
    }

    async fn refresh(profile: SsoProfile) -> Result<SsoCredentials> {
        // let registration = SsoRegistration::get().await?;
        info!(
            "refresh (calling AWS api) SsoCredentials for {}",
            profile.profile_name
        );
        let conf = ProgramConfig::new()?;
        // open_url(conf, url);
        debug!("getting login url from AWS");
        let res_url = SsoCredentials::login_url_from_aws(profile.clone()).await;
        let device_code = match res_url.as_ref() {
            Ok(code) => code.clone().device_code,
            Err(e) => {
                error!("aws_sso_credentials.SsoCredentials.refresh {}", e);
                return Err(anyhow!(MyErrors::GetUrlError));
            }
        };
        let url_as_str = match res_url {
            Ok(code) => code.url,
            Err(e) => {
                error!("aws_sso_credentials.SsoCredentials.refresh {}", e);
                return Err(anyhow!(MyErrors::GetUrlError));
            }
        };
        debug!("opening browser with url: {}", url_as_str);
        if open_url(conf, url_as_str.clone()).is_ok() {
            loop {
                debug!("wating 1 second");
                thread::sleep(StdDuration::from_millis(1000));
                match SsoCredentials::create_token(profile.clone(), device_code.clone()).await {
                    Ok(creds) => {
                        debug!("url {} validated.", url_as_str);
                        return Ok(creds);
                    }
                    _ => {
                        debug!("url not validated yet.");
                        continue;
                    }
                }
            }
        }

        Err(anyhow!(MyErrors::ExpirationParser))
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
        let registration = SsoRegistration::get().await?;
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
        })
    }

    pub async fn create_token(profile: SsoProfile, device_code: String) -> Result<SsoCredentials> {
        info!("getting token from AWS");
        let registration = SsoRegistration::get().await?;
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
        // let st_exp: &str = &self.expiresAt[..];
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
            Self::ExpirationParser => write!(f, "Could no parse AWS expiration date!"),
            Self::GetRoleCredentialError => write!(f, "Error getting credentials!"),
            Self::GetUrlError => write!(f, "Error getting URL!"),
            Self::CredentialsFromURLError => write!(f, "Error getting credentials with URL!"),
        }
    }
}
