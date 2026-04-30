use crate::constants::AWS_CONFIG;
use anyhow::{anyhow, Result};
use chrono::Local;
use home::home_dir;
use log::{debug, error};
use std::ffi::OsString;
use std::fs::{copy, metadata, set_permissions, File, OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn backup_config() -> Result<()> {
    let aws_config = get_aws_config()?;
    let today = Local::now().format("%Y%m%dT%H%M%S").to_string();
    let aws_config_str = match aws_config.to_str() {
        Some(s) => s,
        None => {
            return Err(anyhow!(MyErrors::Path));
        }
    };
    debug!(
        "Backing up {} to {}_{}.bak",
        aws_config_str, aws_config_str, today
    );
    let backup_file = format!("{}_{}.bak", aws_config_str, today);
    copy(aws_config, backup_file)?;
    debug!("Backup complete");
    Ok(())
}

pub fn get_relative_os_string(input: &str) -> Result<OsString> {
    match std::env::current_exe() {
        Ok(current_exe) => match current_exe.parent() {
            Some(current_fold) => {
                let mut res = current_fold.to_path_buf();
                for part in input.split('/') {
                    res.push(part);
                }
                Ok(res.into_os_string())
            }
            None => Err(anyhow!(MyErrors::Path)),
        },
        Err(e) => {
            error!("{}", e);
            Err(anyhow!(MyErrors::CurrentExe))
        }
    }
}
pub fn get_home_os_string(input: &str) -> Result<OsString> {
    match home_dir() {
        Some(home) => {
            let mut res = home;
            for part in input.split('/') {
                res.push(part);
            }
            Ok(res.into_os_string())
        }
        _ => Err(anyhow!(MyErrors::Path)),
    }
}

pub fn get_aws_config() -> Result<OsString> {
    debug!("getting aws config file");
    get_home_os_string(AWS_CONFIG)
}

pub fn get_exe_path() -> Result<OsString> {
    match std::env::current_exe() {
        Ok(pathbuf) => Ok(pathbuf.into_os_string()),
        Err(e) => {
            error!("{}", e);
            Err(anyhow!(MyErrors::CurrentExe))
        }
    }
}

pub fn restrict_file_permissions(file: &OsString) -> Result<()> {
    let perm: u32 = 0o600;
    let mut permissions = metadata(file)?.permissions();
    permissions.set_mode(perm);
    set_permissions(file, Permissions::from_mode(perm))?;
    Ok(())
}

// Open a file for writing with mode 0o600 atomically on creation,
// truncating existing content. If the file already exists with broader
// permissions, chmod it to 0o600 before opening so the subsequent write
// never lands in a world-readable file.
pub fn create_restricted_file(file: &OsString) -> Result<File> {
    if Path::new(file).exists() {
        set_permissions(file, Permissions::from_mode(0o600))?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(file)
        .map_err(|e| anyhow!(e))
}

// Ensure a file exists with mode 0o600 without truncating it. Used for
// files whose contents are managed by an external library (e.g. PickleDb)
// so that the library's writes land in a file with restricted permissions
// from the start.
pub fn ensure_restricted_file(file: &OsString) -> Result<()> {
    if Path::new(file).exists() {
        set_permissions(file, Permissions::from_mode(0o600))?;
    } else {
        OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(file)?;
    }
    Ok(())
}

// Error definitions
#[derive(Debug)]
enum MyErrors {
    CurrentExe,
    Path,
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentExe => write!(f, "Current exe not working!"),
            Self::Path => write!(f, "Can not find Path"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;

    // home_dir() reads HOME (USERPROFILE on Windows) live, so tests that depend
    // on it set HOME to a tempdir for determinism in CI/sandbox environments
    // where the real home may be missing or non-writable. Env-var mutation is
    // process-global, hence #[serial].
    fn with_temp_home(f: impl FnOnce(&Path)) {
        let tmp = tempfile::TempDir::new().unwrap();
        let saved = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(tmp.path())));
        match saved {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    // --- get_home_os_string() ---

    #[test]
    #[serial(env_vars)]
    fn test_get_home_os_string_returns_ok() {
        with_temp_home(|_| {
            assert!(get_home_os_string(".aws/config").is_ok());
        });
    }

    #[test]
    #[serial(env_vars)]
    fn test_get_home_os_string_contains_segments() {
        with_temp_home(|_| {
            let result = get_home_os_string(".aws/config").unwrap();
            assert!(Path::new(&result).ends_with(".aws/config"));
        });
    }

    #[test]
    #[serial(env_vars)]
    fn test_get_home_os_string_starts_with_home() {
        with_temp_home(|home| {
            let result = get_home_os_string("test/file").unwrap();
            assert!(Path::new(&result).starts_with(home));
        });
    }

    // --- get_aws_config() ---

    #[test]
    #[serial(env_vars)]
    fn test_get_aws_config_returns_ok() {
        with_temp_home(|_| {
            assert!(get_aws_config().is_ok());
        });
    }

    #[test]
    #[serial(env_vars)]
    fn test_get_aws_config_ends_with_aws_config() {
        with_temp_home(|_| {
            let result = get_aws_config().unwrap();
            assert!(Path::new(&result).ends_with(".aws/config"));
        });
    }

    // --- get_exe_path() ---

    #[test]
    fn test_get_exe_path_returns_ok() {
        let result = get_exe_path();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_exe_path_non_empty() {
        let result = get_exe_path().unwrap();
        assert!(!result.is_empty());
    }

    // --- get_relative_os_string() ---

    #[test]
    fn test_get_relative_os_string_returns_ok() {
        let result = get_relative_os_string("some/path");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_relative_os_string_ends_with_input() {
        let result = get_relative_os_string("some/path").unwrap();
        let path = Path::new(&result);
        assert!(path.ends_with("some/path"));
    }

    // --- restrict_file_permissions() ---
    // restrict_file_permissions uses Unix-only PermissionsExt::set_mode, so the
    // tests are gated to Unix targets.

    #[cfg(unix)]
    #[test]
    fn test_restrict_file_permissions_sets_600() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = OsString::from(tmp.path().as_os_str());
        restrict_file_permissions(&path).unwrap();
        let meta = metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_restrict_file_permissions_nonexistent_errors() {
        let mut path = std::env::temp_dir();
        path.push("nonexistent_file_ssologinlite_test_12345");
        assert!(restrict_file_permissions(&OsString::from(path)).is_err());
    }

    // --- MyErrors Display ---

    #[test]
    fn test_error_display_current_exe() {
        assert_eq!(
            format!("{}", MyErrors::CurrentExe),
            "Current exe not working!"
        );
    }

    #[test]
    fn test_error_display_path() {
        assert_eq!(format!("{}", MyErrors::Path), "Can not find Path");
    }
}
