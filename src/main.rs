// Import necessary dependencies
use anyhow::{anyhow, Result};
// use aws_config::imds::credentials;
use clap::Parser;
use log::{debug, error};
use ssologinlite::aws_credentials::AWScredentials;
use ssologinlite::aws_profile::{Profile::AssumeSsoProfile, Profile::SsoProfile, Profiles};
use ssologinlite::aws_sso_credentials::SsoCredentials;
use ssologinlite::config::ProgramConfig;
use ssologinlite::eks::EksToken;
use ssologinlite::logger::logger;
use ssologinlite::parser::{Cli, Commands};
use ssologinlite::{cache, codeartifact, ecr, rds, redshift, tui};
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
            let (credentials, profile_region) = creds_and_region(args.profile.clone()).await?;
            let region = resolve_region(args.region.clone(), profile_region)?;
            let cluster = match args.cluster.clone() {
                Some(cluster) => cluster,
                None => {
                    error!("Cluster not found");
                    return Err(anyhow!("no cluster argument"));
                }
            };
            let eks_token = EksToken::from_credentials(credentials, region, &cluster)?;
            println!("{}", eks_token);
        }
        Commands::Ecr(args) => {
            let (credentials, profile_region) = creds_and_region(args.profile.clone()).await?;
            let region = resolve_region(args.region.clone(), profile_region)?;
            let password = ecr::get_login_password(credentials, region).await?;
            println!("{}", password);
        }
        Commands::Rds(args) => {
            let (credentials, profile_region) = creds_and_region(args.profile.clone()).await?;
            let region = resolve_region(args.region.clone(), profile_region)?;
            let token = rds::generate_db_auth_token(
                credentials,
                region,
                &args.host,
                args.port,
                &args.db_user,
            );
            println!("{}", token);
        }
        Commands::CodeArtifact(args) => {
            let (credentials, profile_region) = creds_and_region(args.profile.clone()).await?;
            let region = resolve_region(args.region.clone(), profile_region)?;
            let token = codeartifact::get_authorization_token(
                credentials,
                region,
                &args.domain,
                &args.domain_owner,
                args.duration_seconds,
            )
            .await?;
            println!("{}", token);
        }
        Commands::Redshift(args) => {
            let (credentials, profile_region) = creds_and_region(args.profile.clone()).await?;
            let region = resolve_region(args.region.clone(), profile_region)?;
            let creds_json = redshift::get_cluster_credentials(
                credentials,
                region,
                &args.cluster_id,
                &args.db_user,
                args.db_name.clone(),
                args.auto_create,
            )
            .await?;
            println!("{}", creds_json);
        }
        Commands::Logout => {
            let removed = cache::clear_cache().await?;
            if removed.is_empty() {
                println!("No cached credentials to remove.");
            } else {
                for path in removed {
                    println!("Removed {}", path.display());
                }
            }
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
            let sso_expiration = match expires_in.num_seconds() <= 0 {
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
        Commands::Tui => {
            tui::run()?;
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
            match expires_in.num_hours() < 1 {
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

// Resolve a profile name to its credentials and (optional) configured region.
// Shared by every credential-emitting subcommand.
async fn creds_and_region(profile_name: String) -> Result<(AWScredentials, Option<String>)> {
    debug!("Getting creds for {:?}", profile_name);
    let profile = Profiles::get_profile(profile_name)?;
    debug!("Profile {:?}", profile);
    match profile {
        SsoProfile(p) => {
            let region = p.region.clone();
            Ok((p.get_credentials().await?, region))
        }
        AssumeSsoProfile(p) => {
            let region = Some(p.region.clone());
            Ok((p.get_credentials().await?, region))
        }
        _ => {
            error!("Profile not found");
            Err(anyhow!(MyErrors::ProfileNotFoundError))
        }
    }
}

// A region from the CLI argument wins; otherwise fall back to the profile's
// configured region; otherwise it's an error.
fn resolve_region(arg_region: Option<String>, profile_region: Option<String>) -> Result<String> {
    arg_region.or(profile_region).ok_or_else(|| {
        error!("Region not found");
        anyhow!(MyErrors::RegionNotFoundError)
    })
}

// Custom error enum. The shared "Error" suffix is intentional and matches
// the pattern used by sibling modules' MyErrors enums.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
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
