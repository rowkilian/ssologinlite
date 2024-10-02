use crate::aws_credentials::AWScredentials;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url_search_params::build_url_search_params;

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
    pub fn from_credenials(credentials: AWScredentials, region: String) -> Result<Status> {
        let signed_url = GetSignedUrlOptions::new(
            region,
            credentials.AccessKeyId,
            credentials.SecretAccessKey,
            credentials.SessionToken,
        );
        let url = get_signed_url(&signed_url);
        let token = format!("{}{}", TOKEN_PREFIX, base64_encode(&url));
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
    pub fn from_credenials(credentials: AWScredentials, region: String) -> Result<String> {
        let status = Status::from_credenials(credentials, region)?;
        let token = EksToken {
            status,
            ..Default::default()
        };
        Ok(serde_json::to_string(&token)?)
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
    return format!("{:x}", hasher.finalize());
}

fn hmac_sha_256(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data);
    return hasher.finalize().into_bytes().to_vec();
}

fn hmac_sha_256_hex(key: &Vec<u8>, data: &String) -> String {
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    hasher.update(data.as_bytes());
    return format!("{:x}", hasher.finalize().into_bytes());
}

fn get_query_parameters(options: &GetSignedUrlOptions) -> String {
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
    return build_url_search_params(url_params);
}

fn get_canonical_request(options: &GetSignedUrlOptions, query_parameters: &String) -> String {
    // let key = &("/".to_string() + &options.key);
    let host = &("host:".to_string() + &options.service + "." + &options.endpoint);

    let canonical_request: Vec<&str> = vec![
        &options.method,
        "/",
        query_parameters,
        host,
        "",
        "host",
        "UNSIGNED-PAYLOAD",
    ];
    return canonical_request.join("\n");
}

fn get_signature_payload(options: &GetSignedUrlOptions, payload: String) -> String {
    let payload_hash = &sha256(&payload)[..];
    let date1 = &options.date.format("%Y%m%dT%H%M%SZ").to_string()[..];
    let date2 = &options.date.format("%Y%m%d").to_string()[..];
    let third =
        &(date2.to_owned() + "/" + &options.region + "/" + &options.service + "/aws4_request");

    let signature_payload: Vec<&str> = vec!["AWS4-HMAC-SHA256", &date1, &third, payload_hash];
    return signature_payload.join("\n");
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
    return vec_key;
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
    return url.join("");
}

pub fn get_signed_url(options: &GetSignedUrlOptions) -> String {
    let signature_key = get_signature_key(&options);

    let query_parameters = get_query_parameters(&options);
    let canonical_request = get_canonical_request(&options, &query_parameters);
    let signature_payload = get_signature_payload(&options, canonical_request);
    let signature = hmac_sha_256_hex(&signature_key, &signature_payload);
    let url = get_url(&options, query_parameters, signature);
    return url;
}

fn base64_encode(data: &String) -> String {
    return STANDARD.encode(data);
}
