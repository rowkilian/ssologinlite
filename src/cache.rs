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
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

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

// Longest we wait for the cache lock before giving up. flock has no writer
// preference on macOS, so a steady stream of short-lived readers — the
// `ssoexpiration` statusline poller runs every few seconds — can stall or
// starve a *blocking* exclusive request indefinitely. Both call sites already
// degrade gracefully when the lock can't be taken, so a bounded wait is
// strictly better than hanging a credential_process invocation.
const LOCK_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const LOCK_RETRY_INTERVAL: StdDuration = StdDuration::from_millis(50);

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

    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        // Fully-qualified so this always resolves to fs2's trait method. Rust
        // 1.89 added inherent File::try_lock_exclusive/try_lock_shared, which
        // would otherwise win method resolution and break the 1.77.2 MSRV.
        let attempt = if exclusive {
            fs2::FileExt::try_lock_exclusive(&f)
        } else {
            fs2::FileExt::try_lock_shared(&f)
        };
        match attempt {
            Ok(()) => return Ok(f),
            Err(e) => {
                // Only contention is worth retrying; anything else (no flock
                // support on the filesystem, bad descriptor) will never succeed.
                if e.raw_os_error() != fs2::lock_contended_error().raw_os_error() {
                    return Err(e.into());
                }
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "timed out after {:?} waiting for the cache lock",
                        LOCK_TIMEOUT
                    ));
                }
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
        }
    }
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
    // Best-effort: locking is a concurrency optimization, not a correctness
    // requirement for a single invocation. If the lock can't be taken (e.g. a
    // filesystem without flock support), log and proceed unlocked rather than
    // failing — failing here would discard credentials we already fetched from
    // AWS. Held until function return.
    let _lock = match acquire_cache_lock(true) {
        Ok(l) => Some(l),
        Err(e) => {
            error!(
                "cache.store_cache: could not acquire lock, proceeding unlocked: {}",
                e
            );
            None
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

// Remove the credential cache and any quarantined copies of it from `dir`,
// returning the paths that were removed.
//
// The `.lock` sidecar is deliberately left in place: it holds no credentials,
// and unlinking it while another process has it open would silently break
// mutual exclusion — that process keeps its flock on the now-detached inode
// while a newcomer creates a fresh file and locks that instead.
//
// The `.corrupt.<timestamp>` quarantine files written by open_or_recover_db
// *are* removed: they are verbatim copies of a cache that held credentials.
fn remove_cache_files(dir: &Path, cache_name: &str) -> Result<Vec<PathBuf>> {
    let quarantine_prefix = format!("{}.corrupt.", cache_name);
    let mut removed: Vec<PathBuf> = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // Never logged in on this machine — nothing to remove is a successful
        // logout, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name == cache_name || file_name.starts_with(&quarantine_prefix) {
            let path = entry.path();
            std::fs::remove_file(&path)?;
            removed.push(path);
        }
    }
    // read_dir order is filesystem-defined; sort so output is stable.
    removed.sort();
    Ok(removed)
}

// Delete every locally cached credential. The SSO access token, the per-profile
// role credentials and the OIDC client registration all live in the one
// PickleDb file, so removing it logs the user out of everything at once and the
// next command falls back to a fresh browser SSO login.
pub async fn clear_cache() -> Result<Vec<PathBuf>> {
    let cache_file = get_home_os_string(format!("{}/{}", PROGRAM_FOLDER, CREDS_CACHE).as_str())?;
    let dir = match Path::new(&cache_file).parent() {
        Some(dir) => dir.to_path_buf(),
        None => return Err(anyhow!(MyErrors::Cache)),
    };

    // Take the writer lock so the file can't be unlinked out from under a
    // concurrent store_cache mid-dump. Best-effort for the same reason as
    // store_cache: failing to lock is not a reason to refuse to log out.
    let _lock = match acquire_cache_lock(true) {
        Ok(l) => Some(l),
        Err(e) => {
            error!(
                "cache.clear_cache: could not acquire lock, proceeding unlocked: {}",
                e
            );
            None
        }
    };

    let removed = remove_cache_files(&dir, CREDS_CACHE)?;
    for path in &removed {
        info!("removed cached credentials file {}", path.display());
    }
    Ok(removed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const CACHE: &str = ".ssologinlite_cache";

    fn touch(dir: &Path, name: &str) {
        fs::write(dir.join(name), b"x").unwrap();
    }

    fn names(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_remove_cache_files_removes_cache_and_quarantines() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        touch(dir, CACHE);
        touch(dir, ".ssologinlite_cache.corrupt.20260823T120000");
        touch(dir, ".ssologinlite_cache.corrupt.20260824T130000");

        let removed = remove_cache_files(dir, CACHE).unwrap();

        assert_eq!(
            names(&removed),
            vec![
                ".ssologinlite_cache",
                ".ssologinlite_cache.corrupt.20260823T120000",
                ".ssologinlite_cache.corrupt.20260824T130000",
            ]
        );
        assert!(!dir.join(CACHE).exists());
    }

    #[test]
    fn test_remove_cache_files_keeps_lock_and_unrelated_files() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        touch(dir, CACHE);
        // The lock sidecar holds no credentials, and unlinking it would break
        // mutual exclusion for a process that already has it open.
        touch(dir, ".ssologinlite_cache.lock");
        touch(dir, "profiles.json");
        touch(dir, "config.exported.20260528T152832");

        let removed = remove_cache_files(dir, CACHE).unwrap();

        assert_eq!(names(&removed), vec![".ssologinlite_cache"]);
        assert!(dir.join(".ssologinlite_cache.lock").exists());
        assert!(dir.join("profiles.json").exists());
        assert!(dir.join("config.exported.20260528T152832").exists());
    }

    #[test]
    fn test_remove_cache_files_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        touch(dir, CACHE);

        assert_eq!(remove_cache_files(dir, CACHE).unwrap().len(), 1);
        // Logging out twice is not an error.
        assert!(remove_cache_files(dir, CACHE).unwrap().is_empty());
    }

    #[test]
    fn test_remove_cache_files_missing_dir_is_not_an_error() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("never-logged-in");
        assert!(remove_cache_files(&missing, CACHE).unwrap().is_empty());
    }

    #[test]
    fn test_remove_cache_files_ignores_directories_named_like_the_cache() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        // A directory would make remove_file fail; make sure a name that only
        // *starts* with the cache name but isn't a quarantine file is skipped.
        fs::create_dir(dir.join(".ssologinlite_cache_backups")).unwrap();
        touch(dir, CACHE);

        let removed = remove_cache_files(dir, CACHE).unwrap();

        assert_eq!(names(&removed), vec![".ssologinlite_cache"]);
        assert!(dir.join(".ssologinlite_cache_backups").is_dir());
    }
}
