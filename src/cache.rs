use crate::aws_credentials::AWScredentials;
use crate::aws_sso_credentials::SsoCredentials;
use crate::aws_sso_registration::SsoRegistration;
use crate::constants::{CREDS_CACHE, PROGRAM_FOLDER};
use crate::file_helper::{get_home_os_string, restrict_file_permissions};
use anyhow::{anyhow, Result};
use log::{debug, error, info};
use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
use serde::Serialize;
use serde_json;

// Get cache
pub async fn get_cached_credentials(profile: &str) -> Option<AWScredentials> {
    let key = format!("{}-creds", profile);
    match get_cache(key.as_str()).await {
        Some(cache) => match serde_json::from_str(cache.as_str()) {
            Ok(res) => Some(res),
            Err(e) => {
                error!("{}", e);
                None
            }
        },
        _ => None,
    }
}

// Store cache
pub async fn store_cached_credentials(profile: &str, credentials: &AWScredentials) -> Result<()> {
    let key = format!("{}-creds", profile);
    store_cache(key.as_str(), credentials).await
}

// Get sso credentials
pub async fn get_cached_sso_credentials(url_id: &str) -> Option<SsoCredentials> {
    let key = format!("{}-credentials", url_id);
    match get_cache(key.as_str()).await {
        Some(cache) => match serde_json::from_str(cache.as_str()) {
            Ok(res) => Some(res),
            Err(e) => {
                error!("{}", e);
                None
            }
        },
        _ => None,
    }
}

// Store sso credentials
pub async fn cache_sso_credentials(url_id: &str, account: &SsoCredentials) -> Result<()> {
    let key = format!("{}-credentials", url_id);
    store_cache(key.as_str(), account).await
}

// Get sso registration
pub async fn get_cached_sso_registration() -> Option<SsoRegistration> {
    match get_cache("sso_registration").await {
        Some(cache) => match serde_json::from_str(cache.as_str()) {
            Ok(res) => Some(res),
            Err(e) => {
                error!("{}", e);
                None
            }
        },
        _ => None,
    }
}

// Store registration
pub async fn cache_sso_registration(sso_cache: &SsoRegistration) -> Result<()> {
    store_cache("sso_registration", sso_cache).await
}

// Generic get cache
pub async fn get_cache(key: &str) -> Option<String> {
    let str_cache_file =
        match get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, CREDS_CACHE).as_str()) {
            Ok(rel_cache_file) => rel_cache_file,
            Err(e) => {
                error!("{}", e);
                return None;
            }
        };

    // cache
    let cache_str = match str_cache_file.to_str() {
        Some(cache_str) => cache_str,
        None => {
            error!("Problem with cache file path!");
            return None;
        }
    };
    debug!("opening cache file {} for reading.", &cache_str);
    debug!("getting {key} from cache.");
    let db = match PickleDb::load_read_only(&str_cache_file, SerializationMethod::Bin) {
        Ok(res) => res,
        Err(e) => {
            error!("cache.get_cache: {}", e);
            return None;
        }
    };

    let _ = restrict_file_permissions(&str_cache_file);
    db.get::<String>(key)
}

// Generic store cache
pub async fn store_cache<T>(key: &str, object: &T) -> Result<()>
where
    T: Serialize,
{
    let str_cache_file =
        match get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, CREDS_CACHE).as_str()) {
            Ok(rel_cache_file) => rel_cache_file,
            Err(e) => {
                error!("{}", e);
                return Err(anyhow!(MyErrors::Cache));
            }
        };

    // cache
    let cache_str = match str_cache_file.to_str() {
        Some(cache_str) => cache_str,
        None => {
            return Err(anyhow!(MyErrors::Cache));
        }
    };
    info!("opening cache file {} for writing.", cache_str);
    let mut db = PickleDb::load(
        str_cache_file.clone(),
        PickleDbDumpPolicy::AutoDump,
        SerializationMethod::Bin,
    )
    .unwrap_or(PickleDb::new(
        str_cache_file.clone(),
        PickleDbDumpPolicy::AutoDump,
        SerializationMethod::Bin,
    ));
    let _ = restrict_file_permissions(&str_cache_file);
    let j_creds = match serde_json::to_string(object) {
        Ok(j_creds) => j_creds,
        Err(e) => {
            error!("{}", e);
            return Err(anyhow!(MyErrors::Cache));
        }
    };
    match db.set(key, &j_creds) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("{}", e);
            Err(anyhow!(MyErrors::Cache))
        }
    }
}

// Error definitions
#[derive(Debug)]
enum MyErrors {
    Cache,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cache => write!(f, "Problem caching data!"),
        }
    }
}
