// CodeArtifact authorization token, the equivalent of
// `aws codeartifact get-authorization-token`. Used to authenticate npm/pip/
// maven/etc. against a CodeArtifact repository.

use crate::aws_credentials::AWScredentials;
use anyhow::{anyhow, Result};
use aws_types::region::Region;
use log::error;

pub async fn get_authorization_token(
    credentials: AWScredentials,
    region: String,
    domain: &str,
    domain_owner: &str,
    duration_seconds: Option<i64>,
) -> Result<String> {
    let config = aws_sdk_codeartifact::Config::builder()
        .behavior_version(aws_sdk_codeartifact::config::BehaviorVersion::latest())
        .region(Region::new(region))
        .credentials_provider(credentials.credentials_provider())
        .build();
    let client = aws_sdk_codeartifact::Client::from_conf(config);

    let mut request = client
        .get_authorization_token()
        .domain(domain)
        .domain_owner(domain_owner);
    if let Some(d) = duration_seconds {
        request = request.duration_seconds(d);
    }

    let output = request.send().await.map_err(|e| {
        error!("codeartifact.get_authorization_token: {}", e);
        anyhow!("error getting CodeArtifact authorization token")
    })?;

    output
        .authorization_token()
        .map(|t| t.to_string())
        .ok_or_else(|| anyhow!("CodeArtifact returned no authorization token"))
}
