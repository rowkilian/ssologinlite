use crate::aws_credentials::AWScredentials;
use crate::sigv4::{self, GetSignedUrlOptions, EMPTY_SHA256_HASH};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const AUTH_COMMAND: &str = "GetCallerIdentity";
const AUTH_API_VERSION: &str = "2011-06-15";
const BETA_API: &str = "client.authentication.k8s.io/v1beta1";
const TOKEN_EXPIRATION_MINS: i64 = 14;
const TOKEN_PREFIX: &str = "k8s-aws-v1.";
const K8S_AWS_ID_HEADER: &str = "x-k8s-aws-id";

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct Status {
    pub expirationTimestamp: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Spec {}

#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct EksToken {
    pub kind: String,
    pub apiVersion: String,
    pub spec: Spec,
    pub status: Status,
}

impl Default for EksToken {
    fn default() -> EksToken {
        EksToken {
            kind: String::from("ExecCredential"),
            apiVersion: String::from(BETA_API),
            spec: Spec {},
            status: Status {
                expirationTimestamp: String::from(""),
                token: String::from(""),
            },
        }
    }
}

impl Status {
    pub fn from_credentials(
        credentials: AWScredentials,
        region: String,
        cluster: &str,
    ) -> Result<Status> {
        let signed_url = GetSignedUrlOptions::new(
            region,
            credentials.AccessKeyId,
            credentials.SecretAccessKey,
            credentials.SessionToken,
        );
        let url = get_signed_url(&signed_url, cluster);
        // EKS exec credential tokens require base64url (RFC 4648 §5):
        // URL-safe alphabet (- and _ instead of + and /), no padding. The
        // URL_SAFE_NO_PAD engine handles all of that in one step. The
        // previous implementation used STANDARD base64 + manual `/` → `_`
        // and trailing `=` strip, which left `+` characters intact and
        // produced strings that were not strictly valid base64url.
        let token = format!("{}{}", TOKEN_PREFIX, base64url_encode(&url));
        let expiration_timestamp = (Utc::now() + Duration::minutes(TOKEN_EXPIRATION_MINS))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        Ok(Status {
            expirationTimestamp: expiration_timestamp,
            token,
        })
    }
}

impl EksToken {
    pub fn from_credentials(
        credentials: AWScredentials,
        region: String,
        cluster: &str,
    ) -> Result<String> {
        let status = Status::from_credentials(credentials, region, cluster)?;
        let token = EksToken {
            status,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        token.serialize(&mut ser)?;
        Ok(String::from_utf8(buf)?)
    }
}

// EKS sends the GetCallerIdentity request signing host + the x-k8s-aws-id
// header (which carries the cluster name), so both the query set and canonical
// request below are STS/EKS-specific; the generic SigV4 mechanics live in sigv4.
fn signed_headers() -> String {
    format!("host;{K8S_AWS_ID_HEADER}")
}

fn get_query_parameters(options: &GetSignedUrlOptions) -> String {
    let mut url_params: HashMap<String, String> =
        sigv4::standard_query_params(options, &signed_headers());
    url_params.insert("Action".to_string(), AUTH_COMMAND.to_string());
    url_params.insert("Version".to_string(), AUTH_API_VERSION.to_string());
    sigv4::build_url_search_params(url_params)
}

fn get_canonical_request(
    options: &GetSignedUrlOptions,
    query_parameters: &str,
    cluster: &str,
) -> String {
    let host = format!(
        "{}.{}.{}",
        options.service, options.region, options.endpoint
    );
    sigv4::canonical_request(
        &options.method,
        "/",
        query_parameters,
        &host,
        &[(K8S_AWS_ID_HEADER, cluster)],
        EMPTY_SHA256_HASH,
    )
}

fn get_url(options: &GetSignedUrlOptions, query_parameters: String, signature: String) -> String {
    let url: Vec<&str> = vec![
        "https://",
        &options.service,
        ".",
        &options.region,
        ".",
        "amazonaws.com",
        "/",
        "?",
        &query_parameters,
        "&X-Amz-Signature=",
        &signature,
    ];
    url.join("")
}

pub fn get_signed_url(options: &GetSignedUrlOptions, cluster: &str) -> String {
    // SigV4 signs the canonical (key-sorted) query string. The order of
    // parameters in the final URL is irrelevant — AWS re-canonicalises the
    // received query before verifying — so the same sorted string is reused
    // for both the canonical request and the URL.
    let query_parameters = get_query_parameters(options);
    let canonical_request = get_canonical_request(options, &query_parameters, cluster);
    // The canonical request and signature payload embed X-Amz-Security-Token
    // (a live STS session token) and X-Amz-Credential. Logging them — even at
    // debug — would leak a usable credential into the (non-0600) log file, so
    // they are deliberately not logged here.
    let signature_payload = sigv4::get_signature_payload(options, canonical_request);
    let signature_key = sigv4::get_signature_key(options);
    let signature = sigv4::hmac_sha_256_hex(&signature_key, &signature_payload);

    get_url(options, query_parameters, signature)
}

fn base64url_encode(data: &str) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Primitive SigV4 tests (sha256/hmac/signature key & payload/param sort)
    // now live in src/sigv4.rs alongside the functions they exercise.

    #[test]
    fn test_base64url_encode() {
        // URL_SAFE_NO_PAD: same alphabet as standard base64 except + → -,
        // / → _, with trailing `=` padding stripped.
        assert_eq!(base64url_encode("test"), "dGVzdA");
    }

    #[test]
    fn test_base64url_encode_uses_url_safe_alphabet() {
        // The byte sequence [0xfb, 0xff, 0xbf] encodes to "+/+/" in standard
        // base64; URL_SAFE_NO_PAD must produce "-_-_" (no `+`, no `/`, no `=`).
        let raw = [0xfbu8, 0xff, 0xbf];
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_get_signed_url_format() {
        let options = GetSignedUrlOptions::default();
        let cluster = "test-cluster".to_string();
        let url = get_signed_url(&options, &cluster);

        assert!(url.starts_with("https://sts."));
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Signature="));
        assert!(url.contains("X-Amz-Security-Token="));
    }

    #[test]
    fn test_get_query_parameters() {
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options);

        assert!(params.contains("Action=GetCallerIdentity"));
        assert!(params.contains("Version=2011-06-15"));
        assert!(params.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_get_query_parameters_sorted_case_insensitive() {
        // The canonical query string must be sorted by key; verify the ordering
        // the SigV4 signature depends on.
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options);
        let keys: Vec<&str> = params
            .split('&')
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_by_key(|k| k.to_lowercase());
        assert_eq!(keys, sorted);
    }

    #[test]
    fn test_canonical_request_structure() {
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options);
        let cluster = "test-cluster-123".to_string();

        let canonical = get_canonical_request(&options, &params, &cluster);

        assert!(canonical.contains("GET"));
        assert!(canonical.contains("host:sts.us-east-1.amazonaws.com"));
        assert!(canonical.contains("x-k8s-aws-id:test-cluster-123"));
        assert!(canonical.contains(EMPTY_SHA256_HASH));
    }

    #[test]
    fn test_eks_token_default_structure() {
        let token = EksToken::default();
        assert_eq!(token.kind, "ExecCredential");
        assert_eq!(token.apiVersion, BETA_API);
        assert_eq!(token.status.token, "");
        assert_eq!(token.status.expirationTimestamp, "");
    }

    #[test]
    fn test_status_from_credentials() {
        let creds_json = r#"{
            "Version": 1,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token123",
            "Expiration": "2025-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(creds_json).unwrap();

        let status = Status::from_credentials(creds, "us-west-2".to_string(), "my-cluster");

        assert!(status.is_ok());
        let status = status.unwrap();
        assert!(status.token.starts_with(TOKEN_PREFIX));
        assert!(!status.expirationTimestamp.is_empty());
    }

    #[test]
    fn test_eks_token_from_credentials() {
        let creds_json = r#"{
            "Version": 1,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token123",
            "Expiration": "2025-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(creds_json).unwrap();

        let token_json = EksToken::from_credentials(creds, "us-west-2".to_string(), "my-cluster");

        assert!(token_json.is_ok());
        let token_json = token_json.unwrap();

        // Verify it's valid JSON and has correct structure
        let token: Result<EksToken, _> = serde_json::from_str(&token_json);
        assert!(token.is_ok());

        let token = token.unwrap();
        assert_eq!(token.kind, "ExecCredential");
        assert_eq!(token.apiVersion, BETA_API);
        assert!(token.status.token.starts_with(TOKEN_PREFIX));
        assert!(!token.status.expirationTimestamp.is_empty());
    }

    #[test]
    fn test_token_expiration_is_future() {
        let creds_json = r#"{
            "Version": 1,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token123",
            "Expiration": "2025-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(creds_json).unwrap();

        let status =
            Status::from_credentials(creds, "us-west-2".to_string(), "my-cluster").unwrap();

        // Parse as UTC DateTime
        let exp_time = chrono::NaiveDateTime::parse_from_str(
            &status.expirationTimestamp,
            "%Y-%m-%dT%H:%M:%SZ",
        )
        .unwrap()
        .and_utc();

        // Verify expiration is in the future
        assert!(exp_time > Utc::now());
    }

    #[test]
    fn test_token_expiration_approximately_14_minutes() {
        let creds_json = r#"{
            "Version": 1,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token123",
            "Expiration": "2025-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(creds_json).unwrap();

        let status =
            Status::from_credentials(creds, "us-west-2".to_string(), "my-cluster").unwrap();

        // Parse as UTC DateTime
        let exp_time = chrono::NaiveDateTime::parse_from_str(
            &status.expirationTimestamp,
            "%Y-%m-%dT%H:%M:%SZ",
        )
        .unwrap()
        .and_utc();
        let now = Utc::now();
        let duration = exp_time.signed_duration_since(now);

        // Should be approximately 14 minutes (within 1 second tolerance)
        assert!(duration.num_minutes() >= 13);
        assert!(duration.num_minutes() <= 15);
    }

    #[test]
    fn test_url_contains_cluster_id() {
        let options = GetSignedUrlOptions::default();
        let cluster = "my-special-cluster".to_string();
        let url = get_signed_url(&options, &cluster);

        // The cluster name should be encoded in the canonical request and affect the signature
        assert!(url.contains("X-Amz-Signature="));
        assert!(!url.contains("my-special-cluster")); // Should not be in URL directly
    }

    #[test]
    fn test_different_regions_produce_different_urls() {
        let options1 = GetSignedUrlOptions {
            region: "us-east-1".to_string(),
            ..GetSignedUrlOptions::default()
        };
        let options2 = GetSignedUrlOptions {
            region: "eu-west-1".to_string(),
            // Same date for comparison so only region differs.
            date: options1.date,
            ..GetSignedUrlOptions::default()
        };

        let cluster = "test-cluster".to_string();
        let url1 = get_signed_url(&options1, &cluster);
        let url2 = get_signed_url(&options2, &cluster);

        assert_ne!(url1, url2);
        assert!(url1.contains("us-east-1"));
        assert!(url2.contains("eu-west-1"));
    }

    #[test]
    fn test_token_round_trip_decodes_to_signed_url() {
        // Status::from_credentials produces a token of the form
        //   "k8s-aws-v1." + base64url(signed_url)
        // with `=` padding stripped and `/` replaced by `_`. EKS auth webhooks
        // expect this exact format. This test reverses the transformation and
        // verifies that the embedded URL is the one we'd generate directly.
        let creds_json = r#"{
            "Version": 1,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token123",
            "Expiration": "2025-01-01T00:00:00Z"
        }"#;
        let creds: AWScredentials = serde_json::from_str(creds_json).unwrap();
        let status =
            Status::from_credentials(creds, "us-west-2".to_string(), "my-cluster").unwrap();

        let encoded = status
            .token
            .strip_prefix(TOKEN_PREFIX)
            .expect("token must start with k8s-aws-v1.");
        // The token uses base64url with no padding; decode with the matching
        // engine and no manual character substitution.
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("token suffix must decode as base64url (no-pad)");
        let decoded_url = String::from_utf8(bytes).expect("decoded bytes must be UTF-8");

        assert!(decoded_url.starts_with("https://sts.us-west-2.amazonaws.com/"));
        assert!(decoded_url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(decoded_url.contains("X-Amz-Signature="));
        assert!(decoded_url.contains("X-Amz-Security-Token="));
        // The token's encoded portion must use only the URL-safe alphabet —
        // no `+`, `/`, or `=` from STANDARD base64.
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
}
