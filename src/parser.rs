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
    /// Gets EKS auth token(not working yet).
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
