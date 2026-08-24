use clap::{Args, Parser, Subcommand};
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
    /// Print an ECR registry login password (like `aws ecr get-login-password`).
    Ecr(EcrArgs),
    /// Generate an RDS IAM database auth token (like `aws rds generate-db-auth-token`).
    Rds(RdsArgs),
    /// Get a CodeArtifact authorization token.
    CodeArtifact(CodeArtifactArgs),
    /// Get temporary Redshift cluster credentials (JSON).
    Redshift(RedshiftArgs),
    /// Remove every locally cached credential (SSO access token, role
    /// credentials, OIDC client registration). The next command starts a
    /// fresh browser SSO login.
    Logout,
    /// Time left before the next sso login.
    SSOExpiration,
    /// Exit code 0 if sso login is required.
    SSOExpiresSoon,
    /// Browse / add profiles in an interactive TUI.
    Tui,
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

#[derive(Args)]
pub struct EcrArgs {
    /// Profile to authenticate with
    #[arg(short('p'), long)]
    pub profile: String,
    /// Registry region (defaults to the profile's region)
    #[arg(short('r'), long)]
    pub region: Option<String>,
}

#[derive(Args)]
pub struct RdsArgs {
    /// Profile to authenticate with
    #[arg(short('p'), long)]
    pub profile: String,
    /// Database endpoint host
    #[arg(short('H'), long)]
    pub host: String,
    /// Database port
    #[arg(short('P'), long, default_value_t = 5432)]
    pub port: u16,
    /// Database user to connect as
    #[arg(short('u'), long)]
    pub db_user: String,
    /// Region (defaults to the profile's region)
    #[arg(short('r'), long)]
    pub region: Option<String>,
}

#[derive(Args)]
pub struct CodeArtifactArgs {
    /// Profile to authenticate with
    #[arg(short('p'), long)]
    pub profile: String,
    /// CodeArtifact domain
    #[arg(short('d'), long)]
    pub domain: String,
    /// Domain owner account ID
    #[arg(short('o'), long)]
    pub domain_owner: String,
    /// Token lifetime in seconds
    #[arg(long)]
    pub duration_seconds: Option<i64>,
    /// Region (defaults to the profile's region)
    #[arg(short('r'), long)]
    pub region: Option<String>,
}

#[derive(Args)]
pub struct RedshiftArgs {
    /// Profile to authenticate with
    #[arg(short('p'), long)]
    pub profile: String,
    /// Cluster identifier
    #[arg(short('c'), long)]
    pub cluster_id: String,
    /// Database user to connect as
    #[arg(short('u'), long)]
    pub db_user: String,
    /// Database name
    #[arg(short('n'), long)]
    pub db_name: Option<String>,
    /// Create the DB user if it does not exist
    #[arg(long, default_value_t = false)]
    pub auto_create: bool,
    /// Region (defaults to the profile's region)
    #[arg(short('r'), long)]
    pub region: Option<String>,
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
    fn test_ecr_subcommand() {
        let cli =
            Cli::try_parse_from(["ssologinlite", "ecr", "-p", "prod", "-r", "us-west-2"]).unwrap();
        match cli.command {
            Commands::Ecr(args) => {
                assert_eq!(args.profile, "prod");
                assert_eq!(args.region.as_deref(), Some("us-west-2"));
            }
            _ => panic!("expected Ecr"),
        }
    }

    #[test]
    fn test_rds_subcommand_defaults_port() {
        let cli = Cli::try_parse_from([
            "ssologinlite",
            "rds",
            "-p",
            "prod",
            "-H",
            "db.example.com",
            "-u",
            "appuser",
        ])
        .unwrap();
        match cli.command {
            Commands::Rds(args) => {
                assert_eq!(args.profile, "prod");
                assert_eq!(args.host, "db.example.com");
                assert_eq!(args.port, 5432);
                assert_eq!(args.db_user, "appuser");
            }
            _ => panic!("expected Rds"),
        }
    }

    #[test]
    fn test_rds_missing_host_errors() {
        let result = Cli::try_parse_from(["ssologinlite", "rds", "-p", "prod", "-u", "u"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_codeartifact_subcommand() {
        let cli = Cli::try_parse_from([
            "ssologinlite",
            "code-artifact",
            "-p",
            "prod",
            "-d",
            "mydomain",
            "-o",
            "123456789012",
        ])
        .unwrap();
        match cli.command {
            Commands::CodeArtifact(args) => {
                assert_eq!(args.domain, "mydomain");
                assert_eq!(args.domain_owner, "123456789012");
                assert!(args.duration_seconds.is_none());
            }
            _ => panic!("expected CodeArtifact"),
        }
    }

    #[test]
    fn test_redshift_subcommand() {
        let cli = Cli::try_parse_from([
            "ssologinlite",
            "redshift",
            "-p",
            "prod",
            "-c",
            "my-cluster",
            "-u",
            "appuser",
        ])
        .unwrap();
        match cli.command {
            Commands::Redshift(args) => {
                assert_eq!(args.cluster_id, "my-cluster");
                assert_eq!(args.db_user, "appuser");
                assert!(!args.auto_create);
            }
            _ => panic!("expected Redshift"),
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
    fn test_logout_subcommand() {
        let cli = Cli::try_parse_from(["ssologinlite", "logout"]).unwrap();
        assert!(matches!(cli.command, Commands::Logout));
    }

    #[test]
    fn test_logout_takes_no_arguments() {
        // Logout is deliberately all-or-nothing: the SSO token, every profile's
        // role credentials and the client registration share one cache file, so
        // there is no per-profile logout to offer.
        assert!(Cli::try_parse_from(["ssologinlite", "logout", "--profile", "prod"]).is_err());
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
