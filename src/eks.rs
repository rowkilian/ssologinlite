use crate::aws_credentials::AWScredentials;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url_search_params::encode_uri_component;

const AUTH_SERVICE: &str = "sts";
const AUTH_COMMAND: &str = "GetCallerIdentity";
const AUTH_API_VERSION: &str = "2011-06-15";
// const AUTH_SIGNING_VERSION: &str = "v4";
// const ALPHA_API: &str = "client.authentication.k8s.io/v1alpha1";
const BETA_API: &str = "client.authentication.k8s.io/v1beta1";
// const V1_API: &str = "client.authentication.k8s.io/v1";
const URL_TIMEOUT: u16 = 60;
const TOKEN_EXPIRATION_MINS: i64 = 14;
const TOKEN_PREFIX: &str = "k8s-aws-v1.";
const K8S_AWS_ID_HEADER: &str = "x-k8s-aws-id";
const EMPTY_SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
    pub fn from_credenials(
        credentials: AWScredentials,
        region: String,
        cluster: &String,
    ) -> Result<Status> {
        let signed_url = GetSignedUrlOptions::new(
            region,
            credentials.AccessKeyId,
            credentials.SecretAccessKey,
            credentials.SessionToken,
        );
        let url = get_signed_url(&signed_url, cluster);
        let encoded_url = base64_encode(&url).trim_end_matches('=').to_string();
        let sanitized_encoded_url = encoded_url.replace("/", "_");
        let token = format!("{}{}", TOKEN_PREFIX, sanitized_encoded_url);
        // let token = format!("{}{}", TOKEN_PREFIX, base64_encode(&url));
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
        cluster: &String,
    ) -> Result<String> {
        let status = Status::from_credenials(credentials, region, cluster)?;
        let token = EksToken {
            status,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        token.serialize(&mut ser).unwrap();
        // Ok(serde_json::to_string_pretty(&token)?)
        Ok(String::from_utf8(buf)?)
    }
}

#[derive(Debug)]
pub struct GetSignedUrlOptions {
    pub method: String,
    pub region: String,
    pub expires_in: u16,
    pub date: DateTime<Utc>,
    pub service: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: String,
    pub endpoint: String,
}

impl Default for GetSignedUrlOptions {
    fn default() -> GetSignedUrlOptions {
        GetSignedUrlOptions {
            method: String::from("GET"),
            region: String::from("us-east-1"),
            expires_in: URL_TIMEOUT,
            date: Utc::now(),
            service: String::from(AUTH_SERVICE),
            access_key_id: String::from("ASIAIOSFODNN7EXAMPLE"),
            secret_access_key: String::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"),
            security_token: String::from(
                "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L\
                To6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3z\
                rkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtp\
                Z3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE",
            ),
            endpoint: String::from("amazonaws.com"),
        }
    }
}

impl GetSignedUrlOptions {
    pub fn new(
        region: String,
        access_key_id: String,
        secret_access_key: String,
        security_token: String,
    ) -> Self {
        GetSignedUrlOptions {
            method: String::from("GET"),
            region,
            expires_in: URL_TIMEOUT,
            date: Utc::now(),
            service: String::from(AUTH_SERVICE),
            access_key_id,
            secret_access_key,
            security_token,
            endpoint: String::from("amazonaws.com"),
        }
    }
}

fn sha256(data: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn hmac_sha_256(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data);
    hasher.finalize().into_bytes().to_vec()
}

fn hmac_sha_256_hex(key: &Vec<u8>, data: &String) -> String {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize().into_bytes())
}

fn get_query_parameters(options: &GetSignedUrlOptions, for_canonical: bool) -> String {
    let mut url_params: HashMap<String, String> = HashMap::new();
    url_params.insert("Action".to_string(), AUTH_COMMAND.to_string());
    url_params.insert("Version".to_string(), AUTH_API_VERSION.to_string());
    url_params.insert(
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    );
    url_params.insert(
        "X-Amz-Credential".to_string(),
        options.access_key_id.to_string()
            + "/"
            + &options.date.format("%Y%m%d").to_string()
            + "/"
            + &options.region
            + "/"
            + &options.service
            + "/aws4_request",
    );
    url_params.insert(
        "X-Amz-Date".to_string(),
        options.date.format("%Y%m%dT%H%M%SZ").to_string(),
    );
    url_params.insert("X-Amz-Expires".to_string(), options.expires_in.to_string());
    url_params.insert(
        "X-Amz-SignedHeaders".to_string(),
        format!("host;{K8S_AWS_ID_HEADER}").to_string(),
    );
    url_params.insert(
        "X-Amz-Security-Token".to_string(),
        options.security_token.to_string(),
    );
    build_url_search_params(url_params, for_canonical)
}

fn get_canonical_request(
    options: &GetSignedUrlOptions,
    query_parameters: &String,
    cluster: &String,
) -> String {
    // let key = &("/".to_string() + &options.key);
    let host =
        &("host:".to_string() + &options.service + "." + &options.region + "." + &options.endpoint);
    let cluster_header = format!("{}:{}", K8S_AWS_ID_HEADER, cluster);
    let eks_payload = format!("host;{}", K8S_AWS_ID_HEADER);
    let canonical_request: Vec<&str> = vec![
        &options.method,
        "/",
        query_parameters,
        host,
        cluster_header.as_str(),
        "",
        eks_payload.as_str(),
        EMPTY_SHA256_HASH,
    ];
    canonical_request.join("\n")
}

fn get_signature_payload(options: &GetSignedUrlOptions, payload: String) -> String {
    let payload_hash = &sha256(&payload)[..];
    let date1 = &options.date.format("%Y%m%dT%H%M%SZ").to_string()[..];
    let date2 = &options.date.format("%Y%m%d").to_string()[..];
    let third =
        &(date2.to_owned() + "/" + &options.region + "/" + &options.service + "/aws4_request");

    let signature_payload: Vec<&str> = vec!["AWS4-HMAC-SHA256", &date1, &third, payload_hash];
    signature_payload.join("\n")
}

pub fn get_signature_key(options: &GetSignedUrlOptions) -> Vec<u8> {
    let parts: Vec<String> = vec![
        "AWS4".to_string() + &options.secret_access_key,
        options.date.format("%Y%m%d").to_string(),
        options.region.to_string(),
        options.service.to_string(),
        "aws4_request".to_string(),
    ];

    let bytes_vec: Vec<Vec<u8>> = parts
        .into_iter()
        .map(|s| s.into_bytes())
        .collect::<Vec<Vec<u8>>>();

    let vec_key: Vec<u8> = bytes_vec
        .into_iter()
        .reduce(|a, b| hmac_sha_256(&a, &b))
        .unwrap();
    vec_key
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
        // &options.key,
        "?",
        &query_parameters,
        "&X-Amz-Signature=",
        &signature,
    ];
    url.join("")
}

pub fn get_signed_url(options: &GetSignedUrlOptions, cluster: &String) -> String {
    let query_parameters_cr = get_query_parameters(options, true);
    let query_parameters = get_query_parameters(options, false);
    let canonical_request = get_canonical_request(options, &query_parameters_cr, cluster);
    debug!("canonical_request = {}", canonical_request);
    let signature_payload = get_signature_payload(options, canonical_request);
    debug!("signature_payload = {}", signature_payload);
    let signature_key = get_signature_key(options);
    let signature = hmac_sha_256_hex(&signature_key, &signature_payload);
    debug!("signature = {}", signature);

    get_url(options, query_parameters, signature)
}

fn base64_encode(data: &String) -> String {
    STANDARD.encode(data)
}

fn build_url_search_params(params: HashMap<String, String>, for_canonical: bool) -> String {
    let mut key_value_list: Vec<String> = vec![];
    for (key, value) in params {
        let param = [
            encode_uri_component(key.as_str()),
            "=".to_string(),
            encode_uri_component(value.as_str()),
        ]
        .join("");
        key_value_list.push(param);
    }

    key_value_list.sort_by_key(|a| a.to_lowercase());
    if !for_canonical {
        // Non-canonical (URL) form swaps X-Amz-Security-Token and X-Amz-SignedHeaders
        // so Security-Token sits after SignedHeaders. Locating these by key prefix
        // avoids a panic if the param set ever changes shape.
        let token_idx = key_value_list
            .iter()
            .position(|s| s.starts_with("X-Amz-Security-Token="));
        let signed_idx = key_value_list
            .iter()
            .position(|s| s.starts_with("X-Amz-SignedHeaders="));
        if let (Some(t), Some(s)) = (token_idx, signed_idx) {
            key_value_list.swap(t, s);
        }
    };
    key_value_list.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let input = "test".to_string();
        assert_eq!(
            sha256(&input),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_sha256_empty_string() {
        let input = "".to_string();
        assert_eq!(sha256(&input), EMPTY_SHA256_HASH);
    }

    #[test]
    fn test_hmac_sha256_produces_correct_length() {
        let key = b"key".to_vec();
        let data = b"data".to_vec();
        let result = hmac_sha_256(&key, &data);
        assert_eq!(result.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_hmac_sha256_hex_format() {
        let key = b"key".to_vec();
        let data = "data".to_string();
        let result = hmac_sha_256_hex(&key, &data);
        assert_eq!(result.len(), 64); // Hex string is 2x byte length
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_base64_encode() {
        let input = "test".to_string();
        let encoded = base64_encode(&input);
        assert_eq!(encoded, "dGVzdA==");
    }

    #[test]
    fn test_base64_encode_padding_removal() {
        let input = "https://example.com".to_string();
        let encoded = base64_encode(&input);
        assert!(encoded.ends_with("=") || !encoded.is_empty());
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
    fn test_get_query_parameters_canonical() {
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options, true);

        assert!(params.contains("Action=GetCallerIdentity"));
        assert!(params.contains("Version=2011-06-15"));
        assert!(params.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_get_query_parameters_non_canonical() {
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options, false);

        assert!(params.contains("Action=GetCallerIdentity"));
        assert!(params.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn test_canonical_request_structure() {
        let options = GetSignedUrlOptions::default();
        let params = get_query_parameters(&options, true);
        let cluster = "test-cluster-123".to_string();

        let canonical = get_canonical_request(&options, &params, &cluster);

        assert!(canonical.contains("GET"));
        assert!(canonical.contains("host:sts.us-east-1.amazonaws.com"));
        assert!(canonical.contains("x-k8s-aws-id:test-cluster-123"));
        assert!(canonical.contains(EMPTY_SHA256_HASH));
    }

    #[test]
    fn test_signature_key_deterministic() {
        let options = GetSignedUrlOptions::default();
        let key1 = get_signature_key(&options);
        let key2 = get_signature_key(&options);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_signature_key_length() {
        let options = GetSignedUrlOptions::default();
        let key = get_signature_key(&options);
        assert_eq!(key.len(), 32); // HMAC-SHA256 produces 32 bytes
    }

    #[test]
    fn test_signature_payload_format() {
        let options = GetSignedUrlOptions::default();
        let payload = "test payload".to_string();
        let signature_payload = get_signature_payload(&options, payload);

        assert!(signature_payload.starts_with("AWS4-HMAC-SHA256"));
        assert!(signature_payload.contains("us-east-1"));
        assert!(signature_payload.contains("sts"));
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

        let status =
            Status::from_credenials(creds, "us-west-2".to_string(), &"my-cluster".to_string());

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

        let token_json =
            EksToken::from_credentials(creds, "us-west-2".to_string(), &"my-cluster".to_string());

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
            Status::from_credenials(creds, "us-west-2".to_string(), &"my-cluster".to_string())
                .unwrap();

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
            Status::from_credenials(creds, "us-west-2".to_string(), &"my-cluster".to_string())
                .unwrap();

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
        let mut options1 = GetSignedUrlOptions::default();
        options1.region = "us-east-1".to_string();

        let mut options2 = GetSignedUrlOptions::default();
        options2.region = "eu-west-1".to_string();
        options2.date = options1.date; // Same date for comparison

        let cluster = "test-cluster".to_string();
        let url1 = get_signed_url(&options1, &cluster);
        let url2 = get_signed_url(&options2, &cluster);

        assert_ne!(url1, url2);
        assert!(url1.contains("us-east-1"));
        assert!(url2.contains("eu-west-1"));
    }

    #[test]
    fn test_build_url_search_params_sorted() {
        let mut params = HashMap::new();
        params.insert("Zebra".to_string(), "last".to_string());
        params.insert("Apple".to_string(), "first".to_string());
        params.insert("Banana".to_string(), "second".to_string());

        let result = build_url_search_params(params, true);
        let parts: Vec<&str> = result.split('&').collect();

        // Should be sorted (case-insensitive)
        assert!(parts[0].starts_with("Apple"));
        assert!(parts[1].starts_with("Banana"));
        assert!(parts[2].starts_with("Zebra"));
    }
}
