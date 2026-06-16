// Generic AWS Signature Version 4 query-presigning primitives, shared by the
// EKS (`eks.rs`) and RDS IAM (`rds.rs`) token builders. Nothing in here is
// service-specific: callers supply the host, the service-specific query
// parameters, and any extra signed headers, and get back the pieces needed to
// assemble a presigned URL.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url_search_params::encode_uri_component;

// SHA-256 of the empty string — the payload hash for an unsigned-body GET.
pub(crate) const EMPTY_SHA256_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Defaults match the original EKS/STS usage so GetSignedUrlOptions::new keeps
// behaving as before; RDS overrides them via `for_service`.
const DEFAULT_SERVICE: &str = "sts";
const DEFAULT_EXPIRES_IN: u16 = 60;

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
            expires_in: DEFAULT_EXPIRES_IN,
            date: Utc::now(),
            service: String::from(DEFAULT_SERVICE),
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
    // STS/EKS-flavored constructor (service `sts`, 60s expiry).
    pub fn new(
        region: String,
        access_key_id: String,
        secret_access_key: String,
        security_token: String,
    ) -> Self {
        GetSignedUrlOptions {
            method: String::from("GET"),
            region,
            expires_in: DEFAULT_EXPIRES_IN,
            date: Utc::now(),
            service: String::from(DEFAULT_SERVICE),
            access_key_id,
            secret_access_key,
            security_token,
            endpoint: String::from("amazonaws.com"),
        }
    }

    // Generic constructor for non-STS services (e.g. `rds-db` with a 900s
    // expiry). `endpoint` is unused for services whose host is supplied
    // directly to the signer, so it defaults to amazonaws.com.
    pub fn for_service(
        region: String,
        service: &str,
        expires_in: u16,
        access_key_id: String,
        secret_access_key: String,
        security_token: String,
    ) -> Self {
        GetSignedUrlOptions {
            method: String::from("GET"),
            region,
            expires_in,
            date: Utc::now(),
            service: service.to_string(),
            access_key_id,
            secret_access_key,
            security_token,
            endpoint: String::from("amazonaws.com"),
        }
    }
}

pub(crate) fn sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub(crate) fn hmac_sha_256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data);
    hasher.finalize().into_bytes().to_vec()
}

pub(crate) fn hmac_sha_256_hex(key: &[u8], data: &str) -> String {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize().into_bytes())
}

// The six standard SigV4 query parameters common to every presigned request.
// `signed_headers` is the `;`-joined list the request will sign (e.g. "host"
// or "host;x-k8s-aws-id"). Callers add their service-specific params (Action,
// etc.) to the returned map before calling build_url_search_params.
pub(crate) fn standard_query_params(
    options: &GetSignedUrlOptions,
    signed_headers: &str,
) -> HashMap<String, String> {
    let mut p: HashMap<String, String> = HashMap::new();
    p.insert(
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    );
    p.insert(
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
    p.insert(
        "X-Amz-Date".to_string(),
        options.date.format("%Y%m%dT%H%M%SZ").to_string(),
    );
    p.insert("X-Amz-Expires".to_string(), options.expires_in.to_string());
    p.insert(
        "X-Amz-SignedHeaders".to_string(),
        signed_headers.to_string(),
    );
    p.insert(
        "X-Amz-Security-Token".to_string(),
        options.security_token.to_string(),
    );
    p
}

// Build the canonical request. `extra_headers` are signed headers beyond the
// mandatory `host` (name, value); the canonical header block and the
// SignedHeaders list are derived from the full set, sorted by lowercase name
// as SigV4 requires.
pub(crate) fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    host_value: &str,
    extra_headers: &[(&str, &str)],
    payload_hash: &str,
) -> String {
    let mut headers: Vec<(String, String)> = vec![("host".to_string(), host_value.to_string())];
    for (name, value) in extra_headers {
        headers.push((name.to_lowercase(), value.to_string()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers = headers
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>()
        .join(";");

    let mut parts: Vec<String> = vec![
        method.to_string(),
        canonical_uri.to_string(),
        canonical_query.to_string(),
    ];
    for (n, v) in &headers {
        parts.push(format!("{n}:{v}"));
    }
    parts.push(String::new()); // blank line separating headers from signed list
    parts.push(signed_headers);
    parts.push(payload_hash.to_string());
    parts.join("\n")
}

// The string-to-sign: "AWS4-HMAC-SHA256\n<amzdate>\n<scope>\n<sha256(canonical)>".
pub(crate) fn get_signature_payload(options: &GetSignedUrlOptions, payload: String) -> String {
    let payload_hash = &sha256(&payload)[..];
    let date1 = &options.date.format("%Y%m%dT%H%M%SZ").to_string()[..];
    let date2 = &options.date.format("%Y%m%d").to_string()[..];
    let third =
        &(date2.to_owned() + "/" + &options.region + "/" + &options.service + "/aws4_request");

    let signature_payload: Vec<&str> = vec!["AWS4-HMAC-SHA256", date1, third, payload_hash];
    signature_payload.join("\n")
}

// Derive the SigV4 signing key from the secret, date, region, and service.
pub(crate) fn get_signature_key(options: &GetSignedUrlOptions) -> Vec<u8> {
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

    bytes_vec
        .into_iter()
        .reduce(|a, b| hmac_sha_256(&a, &b))
        .unwrap()
}

// URI-encode and sort the query parameters into the canonical `k=v&k=v` query
// string. SigV4 requires sorting by the encoded parameter name in byte order,
// then by encoded value. Sorting the (key, value) tuple does exactly that;
// sorting the joined "key=value" string would be subtly wrong when one key is a
// prefix of another (the '=' separator, 0x3D, sorts after digits), and a
// case-insensitive sort is not byte order at all.
pub(crate) fn build_url_search_params(params: HashMap<String, String>) -> String {
    let mut pairs: Vec<(String, String)> = params
        .into_iter()
        .map(|(k, v)| {
            (
                encode_uri_component(k.as_str()),
                encode_uri_component(v.as_str()),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let input = "test";
        assert_eq!(
            sha256(input),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_sha256_empty_string() {
        assert_eq!(sha256(""), EMPTY_SHA256_HASH);
    }

    #[test]
    fn test_hmac_sha256_produces_correct_length() {
        let result = hmac_sha_256(b"key", b"data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_hex_format() {
        let result = hmac_sha_256_hex(b"key", "data");
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_signature_key_deterministic() {
        let options = GetSignedUrlOptions::default();
        assert_eq!(get_signature_key(&options), get_signature_key(&options));
    }

    #[test]
    fn test_signature_key_matches_aws_reference_vector() {
        // Known-answer test against AWS's documented SigV4 "derive a signing
        // key" example: secret + 20120215 / us-east-1 / iam must produce this
        // exact key. Validates the HMAC chain cryptographically, not just its
        // shape.
        use chrono::TimeZone;
        let options = GetSignedUrlOptions {
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            region: "us-east-1".to_string(),
            service: "iam".to_string(),
            date: Utc.with_ymd_and_hms(2012, 2, 15, 0, 0, 0).unwrap(),
            ..Default::default()
        };
        let key_hex: String = get_signature_key(&options)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            key_hex,
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn test_signature_key_length() {
        let options = GetSignedUrlOptions::default();
        assert_eq!(get_signature_key(&options).len(), 32);
    }

    #[test]
    fn test_signature_payload_format() {
        let options = GetSignedUrlOptions::default();
        let sp = get_signature_payload(&options, "test payload".to_string());
        assert!(sp.starts_with("AWS4-HMAC-SHA256"));
        assert!(sp.contains("us-east-1"));
        assert!(sp.contains("sts"));
    }

    #[test]
    fn test_build_url_search_params_sorted() {
        let mut params = HashMap::new();
        params.insert("Zebra".to_string(), "last".to_string());
        params.insert("Apple".to_string(), "first".to_string());
        params.insert("Banana".to_string(), "second".to_string());
        let result = build_url_search_params(params);
        let parts: Vec<&str> = result.split('&').collect();
        assert!(parts[0].starts_with("Apple"));
        assert!(parts[1].starts_with("Banana"));
        assert!(parts[2].starts_with("Zebra"));
    }

    #[test]
    fn test_build_url_search_params_is_byte_order_not_case_insensitive() {
        // SigV4 sorts by byte order: uppercase (0x41..) precedes lowercase
        // (0x61..), so "Zebra" must come before "apple". A case-insensitive
        // sort would (wrongly) put "apple" first.
        let mut params = HashMap::new();
        params.insert("apple".to_string(), "1".to_string());
        params.insert("Zebra".to_string(), "2".to_string());
        let result = build_url_search_params(params);
        assert_eq!(result, "Zebra=2&apple=1");
    }

    #[test]
    fn test_canonical_request_sorts_headers_and_derives_signed_list() {
        let cr = canonical_request(
            "GET",
            "/",
            "Action=connect",
            "db.example.com:5432",
            &[("x-extra", "v")],
            EMPTY_SHA256_HASH,
        );
        let lines: Vec<&str> = cr.split('\n').collect();
        assert_eq!(lines[0], "GET");
        assert_eq!(lines[1], "/");
        assert_eq!(lines[2], "Action=connect");
        // host sorts before x-extra
        assert_eq!(lines[3], "host:db.example.com:5432");
        assert_eq!(lines[4], "x-extra:v");
        assert_eq!(lines[5], "");
        assert_eq!(lines[6], "host;x-extra");
        assert_eq!(lines[7], EMPTY_SHA256_HASH);
    }

    #[test]
    fn test_standard_query_params_has_six_keys() {
        let options = GetSignedUrlOptions::default();
        let p = standard_query_params(&options, "host");
        assert_eq!(p.len(), 6);
        assert_eq!(p.get("X-Amz-SignedHeaders").unwrap(), "host");
        assert_eq!(p.get("X-Amz-Algorithm").unwrap(), "AWS4-HMAC-SHA256");
    }
}
