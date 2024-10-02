use crate::constants::PROGRAM_FOLDER;
use crate::file_helper::get_home_os_string;
use anyhow::{anyhow, Result};
use log::error;
use log::LevelFilter;
use log4rs::append::rolling_file::policy::compound::{
    roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger, CompoundPolicy,
};
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;

pub fn logger(level: &str) -> Result<()> {
    let loglevel: LevelFilter = match level {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let log_file = get_home_os_string(format!("{PROGRAM_FOLDER}/logs/ssologinlite.log",).as_str())?;
    let log_file_pattern_str =
        get_home_os_string(format!("{PROGRAM_FOLDER}/logs/ssologinlite_{{}}.log",).as_str())?;
    let log_file_pattern = match log_file_pattern_str.as_os_str().to_str() {
        Some(s) => s,
        None => {
            error!("Error converting log file pattern to string");
            return Err(anyhow!("Error converting log file pattern to string"));
        }
    };

    let window_size = 3; // log0, log1, log2
    let fixed_window_roller: FixedWindowRoller =
        match FixedWindowRoller::builder().build(log_file_pattern, window_size) {
            Ok(fwr) => fwr,
            Err(e) => {
                error!("logger.logger {}", e);
                return Err(anyhow!(e));
            }
        };

    let size_limit = 1024 * 1024; // 1MB as max log file size to roll
    let size_trigger = SizeTrigger::new(size_limit);

    let compound_policy: Box<CompoundPolicy> = Box::new(CompoundPolicy::new(
        Box::new(size_trigger),
        Box::new(fixed_window_roller),
    ));

    let requests = match RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)(utc)} [{l}]: {m}{n}",
        )))
        .build(&log_file, compound_policy)
    {
        Ok(rfa) => rfa,
        Err(e) => {
            error!("logger.logger {}", e);
            return Err(anyhow!(e));
        }
    };

    let config = match Config::builder()
        .appender(Appender::builder().build("requests", Box::new(requests)))
        .logger(Logger::builder().build("app::backend::db", loglevel))
        .logger(
            Logger::builder()
                .appender("requests")
                .additive(false)
                .build("app::requests", loglevel),
        )
        .build(Root::builder().appender("requests").build(loglevel))
    {
        Ok(c) => c,
        Err(e) => {
            error!("logger.logger {}", e);
            return Err(anyhow!(e));
        }
    };

    match log4rs::init_config(config) {
        Ok(_) => (),
        Err(e) => {
            error!("logger.logger {}", e);
            return Err(anyhow!(e));
        }
    };
    Ok(())
}
