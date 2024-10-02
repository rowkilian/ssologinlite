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
