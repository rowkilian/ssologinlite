// Import necessary dependencies
use anyhow::{anyhow, Result};
// use aws_config::imds::credentials;
use clap::Parser;
use log::{debug, error};
use ssologinlite::aws_profile::{Profile::AssumeSsoProfile, Profile::SsoProfile, Profiles};
use ssologinlite::aws_sso_credentials::SsoCredentials;
use ssologinlite::config::ProgramConfig;
use ssologinlite::eks::EksToken;
use ssologinlite::logger::logger;
use ssologinlite::parser::{Cli, Commands};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Set up logging based on debug flag
    if cli.debug {
        let _ = logger("debug");
    } else {
        let _ = logger("info");
    };

    // Match on the command provided
    match &cli.command {
        Commands::Setup => {
            debug!("Setting up profiles");
            Profiles::setup_file()?;
        }
        Commands::Token(args) => {
            debug!("Getting creds for {:?}", args.profile);
            let profile = Profiles::get_profile(args.profile.clone())?;
            debug!("Profile {:?}", profile);

            // Match on the profile type and get the token
            match profile {
                SsoProfile(profile) => {
                    let token = profile.get_token().await?;
                    println!("{}", token);
                }
                AssumeSsoProfile(profile) => {
                    let token = profile.get_token().await?;
                    println!("{}", token);
                }
                _ => {
                    error!("Profile not found");
                    return Err(anyhow!(MyErrors::ProfileNotFoundError));
                }
            }
        }
        Commands::Eks(args) => {
            debug!("Getting creds for {:?}", args.profile);
            let profile = Profiles::get_profile(args.profile.clone())?;
            debug!("Profile {:?}", profile);

            // Match on the profile type and get the token
            let (credentials, profile_region) = match profile {
                SsoProfile(profile) => (profile.get_credentials().await?, profile.region),
                AssumeSsoProfile(profile) => {
                    (profile.get_credentials().await?, Some(profile.region))
                }
                _ => {
                    error!("Profile not found");
                    return Err(anyhow!(MyErrors::ProfileNotFoundError));
                }
            };
            let region = match args.region.clone() {
                Some(region) => region,
                None => match profile_region {
                    Some(region) => region,
                    None => {
                        error!("Region not found");
                        return Err(anyhow!(MyErrors::RegionNotFoundError));
                    }
                },
            };
            let eks_token = EksToken::from_credenials(credentials, region)?;
            println!("{}", eks_token);
        }
        Commands::SSOExpiration => {
            let conf = ProgramConfig::new()?;
            let credentials = match conf.default_sso_url {
                Some(url) => SsoCredentials::from_url(url.as_str()).await?,
                None => {
                    return Err(anyhow!(MyErrors::NoDefaultError));
                }
            };

            let (expires_in, _) = credentials.expires()?;
            let sso_expiration = match { expires_in.num_seconds() <= 0 } {
                true => "SSO Expired".to_string(),
                false => format!(
                    "SSO Expires in {:02}:{:02}:{:02}",
                    expires_in.num_hours(),
                    expires_in.num_minutes() % 60,
                    expires_in.num_seconds() % 60
                ),
            };
            print!("{}", sso_expiration);
        }
        Commands::SSOExpiresSoon => {
            let conf = ProgramConfig::new()?;
            let credentials = match conf.default_sso_url {
                Some(url) => SsoCredentials::from_url(url.as_str()).await?,
                None => {
                    return Err(anyhow!(MyErrors::NoDefaultError));
                }
            };
            let (expires_in, _) = credentials.expires()?;
            match { expires_in.num_hours() <= 1 } {
                true => {
                    return Ok(ExitCode::from(0));
                }
                false => {
                    return Ok(ExitCode::from(1));
                }
            };
        }
    }

    Ok(ExitCode::from(0))
}

// Custom error enum
#[derive(Debug)]
enum MyErrors {
    RegionNotFoundError,
    ProfileNotFoundError,
    NoDefaultError,
}

// Implement Display trait for custom error
impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionNotFoundError => write!(f, "Region not found!"),
            Self::ProfileNotFoundError => write!(f, "Profile not found!"),
            Self::NoDefaultError => write!(f, "No default SSO URL found"),
        }
    }
}
