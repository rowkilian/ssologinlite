// ECR registry login password, the equivalent of `aws ecr get-login-password`.
// Calls ECR GetAuthorizationToken with the profile's credentials and returns
// the decoded password (the part after `AWS:` in the base64 token), suitable
// for `docker login --username AWS --password-stdin`.

use crate::aws_credentials::AWScredentials;
use anyhow::{anyhow, Result};
use aws_types::region::Region;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::error;

// The authorization token decodes to "AWS:<password>"; return the password.
fn extract_password(token_b64: &str) -> Result<String> {
    let decoded = STANDARD
        .decode(token_b64)
        .map_err(|e| anyhow!("ECR authorization token is not valid base64: {e}"))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|e| anyhow!("ECR authorization token is not valid UTF-8: {e}"))?;
    match decoded.split_once(':') {
        Some((_user, password)) => Ok(password.to_string()),
        None => Err(anyhow!(
            "ECR authorization token is not in 'user:password' form"
        )),
    }
}

pub async fn get_login_password(credentials: AWScredentials, region: String) -> Result<String> {
    let config = aws_sdk_ecr::Config::builder()
        .behavior_version(aws_sdk_ecr::config::BehaviorVersion::latest())
        .region(Region::new(region))
        .credentials_provider(credentials.credentials_provider())
        .build();
    let client = aws_sdk_ecr::Client::from_conf(config);

    let output = client.get_authorization_token().send().await.map_err(|e| {
        error!("ecr.get_login_password: {}", e);
        anyhow!("error getting ECR authorization token")
    })?;

    let token_b64 = output
        .authorization_data()
        .first()
        .and_then(|d| d.authorization_token())
        .ok_or_else(|| anyhow!("ECR returned no authorization data"))?;

    extract_password(token_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_password_ok() {
        let token = STANDARD.encode("AWS:s3cr3t-password");
        assert_eq!(extract_password(&token).unwrap(), "s3cr3t-password");
    }

    #[test]
    fn test_extract_password_allows_colons_in_password() {
        let token = STANDARD.encode("AWS:pa:ss:word");
        assert_eq!(extract_password(&token).unwrap(), "pa:ss:word");
    }

    #[test]
    fn test_extract_password_rejects_non_base64() {
        assert!(extract_password("not base64!!!").is_err());
    }

    #[test]
    fn test_extract_password_rejects_missing_colon() {
        let token = STANDARD.encode("noseparator");
        assert!(extract_password(&token).is_err());
    }
}
