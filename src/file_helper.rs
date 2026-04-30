use crate::constants::AWS_CONFIG;
use anyhow::{anyhow, Result};
use chrono::Local;
use home::home_dir;
use log::{debug, error};
use std::ffi::OsString;
use std::fs::{copy, metadata, set_permissions, Permissions};
use std::os::unix::fs::PermissionsExt;

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
    use std::path::Path;

    // --- get_home_os_string() ---

    #[test]
    fn test_get_home_os_string_returns_ok() {
        let result = get_home_os_string(".aws/config");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_home_os_string_contains_segments() {
        let result = get_home_os_string(".aws/config").unwrap();
        let path = Path::new(&result);
        assert!(path.ends_with(".aws/config"));
    }

    #[test]
    fn test_get_home_os_string_starts_with_home() {
        let result = get_home_os_string("test/file").unwrap();
        let home = home_dir().unwrap();
        let path = Path::new(&result);
        assert!(path.starts_with(&home));
    }

    // --- get_aws_config() ---

    #[test]
    fn test_get_aws_config_returns_ok() {
        let result = get_aws_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_aws_config_ends_with_aws_config() {
        let result = get_aws_config().unwrap();
        let path = Path::new(&result);
        assert!(path.ends_with(".aws/config"));
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

    #[test]
    fn test_restrict_file_permissions_sets_600() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = OsString::from(tmp.path().as_os_str());
        restrict_file_permissions(&path).unwrap();
        let meta = metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_restrict_file_permissions_nonexistent_errors() {
        let path = OsString::from("/tmp/nonexistent_file_ssologinlite_test_12345");
        assert!(restrict_file_permissions(&path).is_err());
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
