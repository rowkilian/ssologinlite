use clap::{Args, Parser, Subcommand};
// use clap_builder::derive::Parser;
/// Oidc helper for aws sso login
/// sets itself up in the aws config file as credential_process

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// log in debug mode
    #[arg(short, long)]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Setup config ~/.aws/config file.
    /// Will back up current config file.
    Setup,
    /// Get a auth token for a profile
    Token(TokenArgs),
    /// Gets EKS auth token.
    Eks(EksArgs),
    /// Time left before the next sso login.
    SSOExpiration,
    /// Exit code 0 if sso login is required.
    SSOExpiresSoon,
}

#[derive(Args)]
pub struct TokenArgs {
    /// Account Number
    #[arg(short('p'), long)]
    pub profile: String,
}

#[derive(Args)]
pub struct EksArgs {
    /// Profile to use for EKS
    #[arg(short('p'), long)]
    pub profile: String,
    /// Region of the cluster
    #[arg(short('r'), long)]
    pub region: Option<String>,
    /// Cluster name
    #[arg(short('c'), long)]
    pub cluster: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_setup_subcommand() {
        let cli = Cli::try_parse_from(["ssologinlite", "setup"]).unwrap();
        assert!(matches!(cli.command, Commands::Setup));
        assert!(!cli.debug);
    }

    #[test]
    fn test_token_subcommand() {
        let cli = Cli::try_parse_from(["ssologinlite", "token", "--profile", "dev"]).unwrap();
        match cli.command {
            Commands::Token(args) => assert_eq!(args.profile, "dev"),
            _ => panic!("expected Token"),
        }
    }

    #[test]
    fn test_eks_subcommand_required_only() {
        let cli = Cli::try_parse_from(["ssologinlite", "eks", "--profile", "prod"]).unwrap();
        match cli.command {
            Commands::Eks(args) => {
                assert_eq!(args.profile, "prod");
                assert!(args.region.is_none());
                assert!(args.cluster.is_none());
            }
            _ => panic!("expected Eks"),
        }
    }

    #[test]
    fn test_eks_subcommand_all_args() {
        let cli = Cli::try_parse_from([
            "ssologinlite",
            "eks",
            "--profile",
            "prod",
            "--region",
            "us-west-2",
            "--cluster",
            "my-cluster",
        ])
        .unwrap();
        match cli.command {
            Commands::Eks(args) => {
                assert_eq!(args.profile, "prod");
                assert_eq!(args.region.as_deref(), Some("us-west-2"));
                assert_eq!(args.cluster.as_deref(), Some("my-cluster"));
            }
            _ => panic!("expected Eks"),
        }
    }

    #[test]
    fn test_sso_expiration_subcommand() {
        let cli = Cli::try_parse_from(["ssologinlite", "sso-expiration"]).unwrap();
        assert!(matches!(cli.command, Commands::SSOExpiration));
    }

    #[test]
    fn test_sso_expires_soon_subcommand() {
        let cli = Cli::try_parse_from(["ssologinlite", "sso-expires-soon"]).unwrap();
        assert!(matches!(cli.command, Commands::SSOExpiresSoon));
    }

    #[test]
    fn test_debug_long_flag() {
        let cli = Cli::try_parse_from(["ssologinlite", "--debug", "setup"]).unwrap();
        assert!(cli.debug);
    }

    #[test]
    fn test_debug_short_flag() {
        let cli = Cli::try_parse_from(["ssologinlite", "-d", "setup"]).unwrap();
        assert!(cli.debug);
    }

    #[test]
    fn test_token_short_profile() {
        let cli = Cli::try_parse_from(["ssologinlite", "token", "-p", "staging"]).unwrap();
        match cli.command {
            Commands::Token(args) => assert_eq!(args.profile, "staging"),
            _ => panic!("expected Token"),
        }
    }

    #[test]
    fn test_eks_short_flags() {
        let cli = Cli::try_parse_from([
            "ssologinlite",
            "eks",
            "-p",
            "prod",
            "-r",
            "eu-west-1",
            "-c",
            "cluster-1",
        ])
        .unwrap();
        match cli.command {
            Commands::Eks(args) => {
                assert_eq!(args.profile, "prod");
                assert_eq!(args.region.as_deref(), Some("eu-west-1"));
                assert_eq!(args.cluster.as_deref(), Some("cluster-1"));
            }
            _ => panic!("expected Eks"),
        }
    }

    #[test]
    fn test_missing_subcommand() {
        let result = Cli::try_parse_from(["ssologinlite"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_missing_profile() {
        let result = Cli::try_parse_from(["ssologinlite", "token"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_eks_missing_profile() {
        let result = Cli::try_parse_from(["ssologinlite", "eks"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_subcommand() {
        let result = Cli::try_parse_from(["ssologinlite", "foobar"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_default_false() {
        let cli = Cli::try_parse_from(["ssologinlite", "setup"]).unwrap();
        assert!(!cli.debug);
    }
}
