use crate::config::ProgramConfig;
use anyhow::{anyhow, Result};
use log::{debug, error, info};
use std::string::String;
use webbrowser::{open_browser, Browser};

pub fn open_url(config: ProgramConfig, url: String) -> Result<()> {
    info!("mywebbrowser.open_url");
    debug!("mywebbrowser.open_url: {:?}", url);
    match config.browser {
        Some(value) if value == *"chrome" => match open_browser(Browser::Chrome, url.as_str()) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("mywebbrowser.open_url: {}", e);
                Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e))
            }
        },
        Some(value) if value == *"firefox" => match open_browser(Browser::Firefox, url.as_str()) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("mywebbrowser.open_url: {}", e);
                Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e))
            }
        },
        Some(value) if value == *"safari" => match open_browser(Browser::Safari, url.as_str()) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("mywebbrowser.open_url: {}", e);
                Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e))
            }
        },
        // A configurable "launch arbitrary command as the browser" option was
        // considered and deliberately rejected: it would let the config file
        // turn into an arbitrary-command-execution vector.
        _ => match open_browser(Browser::Default, url.as_str()) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("mywebbrowser.open_url: {}", e);
                Err(anyhow!("mywebbrowser.open_url browser failed {:?}", e))
            }
        },
    }
}
