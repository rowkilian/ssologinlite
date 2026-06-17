use crate::aws_credentials::AWScredentials;
use crate::aws_sso_credentials::SsoCredentials;
use crate::aws_sso_registration::SsoRegistration;
use crate::constants::{CREDS_CACHE, PROGRAM_FOLDER};
use crate::file_helper::{get_home_os_string, restrict_file_permissions};
use anyhow::{anyhow, Result};
use chrono::Local;
use log::{debug, error, info};
use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
use serde::Serialize;
use serde_json;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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

// Get sso registration. Keyed by region because an OIDC client registration is
// only valid against the regional ssooidc endpoint it was created on; a user
// with SSO profiles in multiple regions must not share one registration.
pub async fn get_cached_sso_registration(sso_region: &str) -> Option<SsoRegistration> {
    let key = format!("sso_registration-{}", sso_region);
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

// Store registration (keyed by region — see get_cached_sso_registration).
pub async fn cache_sso_registration(sso_region: &str, sso_cache: &SsoRegistration) -> Result<()> {
    let key = format!("sso_registration-{}", sso_region);
    store_cache(key.as_str(), sso_cache).await
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
    // Hold a shared lock for the read so we never observe a half-written dump
    // from a concurrent store_cache. Best-effort: if the lock can't be taken we
    // still attempt the read. Kept alive (named binding) until function return.
    let _lock = match acquire_cache_lock(false) {
        Ok(l) => Some(l),
        Err(e) => {
            error!("cache.get_cache: could not acquire lock: {}", e);
            None
        }
    };
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

// Path of the sidecar lock file guarding the credential cache. We lock a
// separate file rather than the Bin cache itself because PickleDb's AutoDump
// may replace the data file's inode, which would detach an flock held on it.
fn cache_lock_path() -> Result<std::ffi::OsString> {
    get_home_os_string(format!("{}/{}.lock", PROGRAM_FOLDER, CREDS_CACHE).as_str())
}

// Acquire an advisory (flock) lock on the sidecar lock file: exclusive for
// writers, shared for readers. The returned File releases the lock on Drop —
// including on process exit/panic, which matters for short-lived
// credential_process runs. Both readers and writers must lock for it to be
// meaningful.
fn acquire_cache_lock(exclusive: bool) -> Result<File> {
    let lock_path = cache_lock_path()?;
    pre_create_secure(lock_path.as_os_str())?;
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(Path::new(&lock_path))?;
    // Fully-qualified so this always resolves to fs2's trait method. Rust 1.89
    // added inherent File::lock_exclusive/lock_shared, which would otherwise win
    // method resolution and break the 1.77.2 MSRV.
    if exclusive {
        fs2::FileExt::lock_exclusive(&f)?;
    } else {
        fs2::FileExt::lock_shared(&f)?;
    }
    Ok(f)
}

// Open the cache DB for writing, recovering from an unreadable file without
// destroying it. If the file exists but PickleDb can't load it (corruption,
// partial concurrent write, format change), it is renamed aside to
// `<cache>.corrupt.<timestamp>` and a fresh DB is created — we never silently
// truncate a file that may hold other profiles' credentials.
fn open_or_recover_db(path: &OsStr) -> Result<PickleDb> {
    let p = Path::new(path);
    if p.exists() {
        match PickleDb::load(p, PickleDbDumpPolicy::AutoDump, SerializationMethod::Bin) {
            Ok(db) => return Ok(db),
            Err(e) => {
                let ts = Local::now().format("%Y%m%dT%H%M%S");
                let quarantine = format!("{}.corrupt.{}", p.to_string_lossy(), ts);
                error!(
                    "cache: existing cache failed to load ({}); moving aside to {}",
                    e, quarantine
                );
                std::fs::rename(p, &quarantine).map_err(|re| {
                    error!("cache: failed to quarantine unreadable cache: {}", re);
                    anyhow!(MyErrors::Cache)
                })?;
            }
        }
    }
    // File absent (or just quarantined): start fresh, secured to 0o600 first.
    pre_create_secure(path)?;
    Ok(PickleDb::new(
        p,
        PickleDbDumpPolicy::AutoDump,
        SerializationMethod::Bin,
    ))
}

// Create the cache file with 0o600 permissions *before* PickleDb opens it, so
// the credential data it will hold is never momentarily world/group-readable.
// PickleDb::new/load would otherwise create the file at the process umask
// (typically 0o644), leaving a TOCTOU window before restrict_file_permissions
// runs. A no-op if the file already exists.
fn pre_create_secure(path: &OsStr) -> Result<()> {
    let p = Path::new(path);
    if p.exists() {
        return Ok(());
    }
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(p)?;
    Ok(())
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
    // Serialize the whole load-modify-dump against concurrent writers/readers.
    // Held until function return.
    let _lock = match acquire_cache_lock(true) {
        Ok(l) => l,
        Err(e) => {
            error!("cache.store_cache: could not acquire lock: {}", e);
            return Err(anyhow!(MyErrors::Cache));
        }
    };
    let mut db = open_or_recover_db(str_cache_file.as_os_str())?;
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
