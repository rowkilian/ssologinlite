// RDS / Aurora IAM database authentication token, the equivalent of
// `aws rds generate-db-auth-token`. The token is a SigV4-presigned URL for the
// `connect` action on the `rds-db` service, with the `https://` scheme
// stripped — built entirely locally (no AWS API call) from the profile's
// credentials. Valid 15 minutes.

use crate::aws_credentials::AWScredentials;
use crate::sigv4::{self, GetSignedUrlOptions, EMPTY_SHA256_HASH};

const RDS_SERVICE: &str = "rds-db";
const RDS_EXPIRES_IN: u16 = 900; // 15 minutes, matching the AWS CLI

pub fn generate_db_auth_token(
    credentials: AWScredentials,
    region: String,
    host: &str,
    port: u16,
    db_user: &str,
) -> String {
    let options = GetSignedUrlOptions::for_service(
        region,
        RDS_SERVICE,
        RDS_EXPIRES_IN,
        credentials.AccessKeyId,
        credentials.SecretAccessKey,
        credentials.SessionToken,
    );

    // The signed host is the DB endpoint with its port; only `host` is signed.
    let host_value = format!("{host}:{port}");
    let mut params = sigv4::standard_query_params(&options, "host");
    params.insert("Action".to_string(), "connect".to_string());
    params.insert("DBUser".to_string(), db_user.to_string());
    let query = sigv4::build_url_search_params(params);

    let canonical =
        sigv4::canonical_request("GET", "/", &query, &host_value, &[], EMPTY_SHA256_HASH);
    let string_to_sign = sigv4::get_signature_payload(&options, canonical);
    let key = sigv4::get_signature_key(&options);
    let signature = sigv4::hmac_sha_256_hex(&key, &string_to_sign);

    let url = format!("https://{host_value}/?{query}&X-Amz-Signature={signature}");
    // The RDS token is the presigned URL without the scheme.
    url.strip_prefix("https://").unwrap_or(&url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> AWScredentials {
        serde_json::from_str(
            r#"{
                "Version": 1,
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "SessionToken": "token123",
                "Expiration": "2099-01-01T00:00:00Z"
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn test_token_shape() {
        let token = generate_db_auth_token(
            creds(),
            "us-east-1".to_string(),
            "mydb.abc123.us-east-1.rds.amazonaws.com",
            5432,
            "appuser",
        );
        // No scheme, host:port present, connect action + db user, and a signature.
        assert!(!token.starts_with("https://"));
        assert!(token.starts_with("mydb.abc123.us-east-1.rds.amazonaws.com:5432/?"));
        assert!(token.contains("Action=connect"));
        assert!(token.contains("DBUser=appuser"));
        assert!(token.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(token.contains("X-Amz-Security-Token="));
        assert!(token.contains("X-Amz-Signature="));
        assert!(token.contains("X-Amz-Expires=900"));
    }

    #[test]
    fn test_query_is_sorted() {
        let token = generate_db_auth_token(
            creds(),
            "eu-west-1".to_string(),
            "db.example.com",
            3306,
            "u",
        );
        let query = token.split_once("/?").unwrap().1;
        // strip the appended signature param for the ordering check
        let query = query.rsplit_once("&X-Amz-Signature=").unwrap().0;
        let keys: Vec<&str> = query
            .split('&')
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_by_key(|k| k.to_lowercase());
        assert_eq!(keys, sorted);
    }
}
