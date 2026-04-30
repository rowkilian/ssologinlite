use crate::constants::{CONFIG_FILE, PROGRAM_NAME};
use crate::file_helper::get_home_os_string;
use anyhow::{anyhow, Result};
use config::Config;
use log::error;
use serde::{Deserialize, Serialize};
// use std::{collections::HashMap, ffi::OsString};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProgramConfig {
    pub browser: Option<String>,
    pub default_sso_url: Option<String>,
}
impl ProgramConfig {
    pub fn new() -> Result<Self> {
        let config_file = get_home_os_string(CONFIG_FILE)?;
        let cf_str = match config_file.to_str() {
            Some(s) => s,
            None => {
                error!("config.get_conf: to_str failed");
                return Err(anyhow!("config.get_conf: to_str failed"));
            }
        };
        let p_name = PROGRAM_NAME.to_string().to_uppercase();
        let env_prefix = p_name.as_str();
        let settings = Config::builder()
            .add_source(Config::default())
            .add_source(config::File::with_name(cf_str).required(false))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(config::Environment::with_prefix(env_prefix))
            .build()?;
        match settings.try_deserialize() {
            Ok(settings) => Ok(settings),
            Err(e) => {
                error!("config.get_conf: try_deserialize failed: {:?}", e);
                Err(anyhow!("config.get_conf: try_deserialize failed: {:?}", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_loads_without_crash() {
        // .required(false) means missing config file is OK
        let result = ProgramConfig::new();
        assert!(result.is_ok());
    }

    #[test]
    fn test_env_var_browser() {
        std::env::set_var("SSOLOGINLITE_BROWSER", "firefox");
        let conf = ProgramConfig::new().unwrap();
        assert_eq!(conf.browser.as_deref(), Some("firefox"));
        std::env::remove_var("SSOLOGINLITE_BROWSER");
    }

    #[test]
    fn test_env_var_default_sso_url() {
        std::env::set_var(
            "SSOLOGINLITE_DEFAULT_SSO_URL",
            "https://my-sso.awsapps.com/start",
        );
        let conf = ProgramConfig::new().unwrap();
        assert_eq!(
            conf.default_sso_url.as_deref(),
            Some("https://my-sso.awsapps.com/start")
        );
        std::env::remove_var("SSOLOGINLITE_DEFAULT_SSO_URL");
    }

    #[test]
    fn test_serde_round_trip_some() {
        let conf = ProgramConfig {
            browser: Some("chrome".to_string()),
            default_sso_url: Some("https://url".to_string()),
        };
        let json = serde_json::to_string(&conf).unwrap();
        let deser: ProgramConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.browser, conf.browser);
        assert_eq!(deser.default_sso_url, conf.default_sso_url);
    }

    #[test]
    fn test_serde_round_trip_none() {
        let conf = ProgramConfig {
            browser: None,
            default_sso_url: None,
        };
        let json = serde_json::to_string(&conf).unwrap();
        let deser: ProgramConfig = serde_json::from_str(&json).unwrap();
        assert!(deser.browser.is_none());
        assert!(deser.default_sso_url.is_none());
    }

    #[test]
    fn test_default() {
        let conf = ProgramConfig::default();
        assert!(conf.browser.is_none());
        assert!(conf.default_sso_url.is_none());
    }

    #[test]
    fn test_clone() {
        let conf = ProgramConfig {
            browser: Some("safari".to_string()),
            default_sso_url: None,
        };
        let cloned = conf.clone();
        assert_eq!(cloned.browser, conf.browser);
        assert_eq!(cloned.default_sso_url, conf.default_sso_url);
    }
}
