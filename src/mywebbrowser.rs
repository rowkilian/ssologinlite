use crate::config::ProgramConfig;
use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::string::String;
use webbrowser::{open_browser, Browser};

pub fn open_url(config: ProgramConfig, url: String) -> Result<()> {
    info!("mywebbrowser.open_url");
    debug!("mywebbrowser.open_url: {:?}", url);
    match config.browser {
        Some(value) if value == String::from("chrome") => {
            match open_browser(Browser::Chrome, url.as_str()) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("mywebbrowser.open_url: {}", e);
                    return Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e));
                }
            };
        }
        Some(value) if value == String::from("firefox") => {
            match open_browser(Browser::Firefox, url.as_str()) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("mywebbrowser.open_url: {}", e);
                    return Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e));
                }
            };
        }
        Some(value) if value == String::from("safari") => {
            match open_browser(Browser::Safari, url.as_str()) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("mywebbrowser.open_url: {}", e);
                    return Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e));
                }
            };
        }
        _ => {
            match open_browser(Browser::Default, url.as_str()) {
                Ok(_) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("mywebbrowser.open_url: {}", e);
                    return Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e));
                }
            };
        } //
          // There was a thought of having a command in the config to launch any
          // browser but thinking about it, it feels like a security risk.
          // Some(value) => {
          //     let cmd = format!("{} {}", value, url);
          //     let output = std::process::Command::new("sh")
          //         .arg("-c")
          //         .arg(cmd)
          //         .output()?;
          //     if !output.status.success() {
          //         let msg = format!("Error opening browser: {:?}", output);
          //         error!("{}", msg);
          //         return Err(anyhow!(msg));
          //     }
          //     Ok(())
          // }
    }
}
