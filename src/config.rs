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
