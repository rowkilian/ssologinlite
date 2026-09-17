// EC2 instance-role credentials via IMDSv2.
//
// Unlike every other credential source in this crate, this one needs no SSO
// profile, no browser step, and no user-provided identifiers at all: it reads
// whatever IAM role is attached to the EC2 instance ssologinlite is running
// on. It exists for the `imds` subcommand, so ssologinlite can be used as a
// `credential_process` on a host that only has an instance profile.
//
// The actual IMDSv2 token/handshake/retry logic is not reimplemented here —
// `aws_config::imds::credentials::ImdsCredentialsProvider` already does this
// (it's a transitive dependency of `aws-config`, already used elsewhere in
// this crate for SSO). This module is a thin adapter: build that provider,
// convert its `aws_credential_types::Credentials` into this crate's
// `AWScredentials` shape, and translate its errors into clearer messages.
use crate::aws_credentials::AWScredentials;
use anyhow::{anyhow, Result};
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_credential_types::provider::{error::CredentialsError, ProvideCredentials};
use chrono::{DateTime as CDateTime, Utc};
use log::{debug, error};

pub async fn get_instance_role_credentials_from_aws() -> Result<AWScredentials> {
    debug!("imds_credentials.get_instance_role_credentials_from_aws: querying IMDSv2");
    // No explicit endpoint/config is passed here on purpose: the provider
    // resolves AWS_EC2_METADATA_SERVICE_ENDPOINT / AWS_EC2_METADATA_DISABLED /
    // ~/.aws/config itself, which is also what lets tests redirect it at a
    // local mock server purely via environment variable.
    let provider = ImdsCredentialsProvider::builder().build();
    let creds = provider.provide_credentials().await.map_err(|e| {
        error!(
            "imds_credentials.get_instance_role_credentials_from_aws: {}",
            e
        );
        anyhow!(classify_error(&e))
    })?;

    let session_token = creds.session_token().ok_or_else(|| {
        error!(
            "imds_credentials.get_instance_role_credentials_from_aws: IMDS response had no session token"
        );
        anyhow!(MyErrors::Unhandled(
            "IMDS credentials response had no session token".to_string()
        ))
    })?;

    let expiration = creds.expiry().ok_or_else(|| {
        error!(
            "imds_credentials.get_instance_role_credentials_from_aws: IMDS response had no expiration"
        );
        anyhow!(MyErrors::Unhandled(
            "IMDS credentials response had no expiration".to_string()
        ))
    })?;
    let string_expiration = CDateTime::<Utc>::from(expiration)
        .format("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    Ok(AWScredentials::from_parts(
        creds.access_key_id().to_string(),
        creds.secret_access_key().to_string(),
        session_token.to_string(),
        string_expiration,
    ))
}

// Translate the SDK's (non-exhaustive) CredentialsError into one of our own
// variants, keeping the underlying message for detail. CredentialsNotLoaded
// covers both "no instance profile attached" (404 from IMDS) and "disabled
// via AWS_EC2_METADATA_DISABLED" — the SDK collapses both into the same
// variant, distinguishable only by the message text it happens to carry, so
// we deliberately don't try to split them further here.
fn classify_error(e: &CredentialsError) -> MyErrors {
    let detail = error_chain(e);
    match e {
        CredentialsError::CredentialsNotLoaded(_) => MyErrors::NoInstanceRoleCredentials(detail),
        CredentialsError::ProviderTimedOut(_) => MyErrors::TimedOut(detail),
        CredentialsError::InvalidConfiguration(_) => MyErrors::InvalidConfiguration(detail),
        _ => MyErrors::Unhandled(detail),
    }
}

// Some CredentialsError variants (notably Unhandled) have a generic top-level
// Display ("unexpected credentials error") and put the actually useful detail
// in their `source()` chain instead. Walk it so our error messages carry that
// detail rather than a message that says nothing.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

#[derive(Debug)]
enum MyErrors {
    // Not running on EC2, no IAM role attached to the instance, or IMDS was
    // explicitly disabled via AWS_EC2_METADATA_DISABLED.
    NoInstanceRoleCredentials(String),
    TimedOut(String),
    InvalidConfiguration(String),
    Unhandled(String),
}

impl std::fmt::Display for MyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInstanceRoleCredentials(msg) => write!(
                f,
                "no IMDSv2 instance-role credentials available (not running on \
                 EC2, no IAM role attached, or IMDS disabled): {}",
                msg
            ),
            Self::TimedOut(msg) => write!(f, "timed out reaching IMDS: {}", msg),
            Self::InvalidConfiguration(msg) => write!(f, "invalid IMDS configuration: {}", msg),
            Self::Unhandled(msg) => write!(f, "error retrieving IMDS credentials: {}", msg),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    // --- Minimal hand-rolled fake IMDSv2 server ---
    //
    // Deliberately not a general-purpose HTTP mock: this only needs to
    // distinguish `PUT /latest/api/token` from
    // `GET /latest/meta-data/iam/security-credentials/[<role>]` and return a
    // canned status/body for each, driven entirely via
    // AWS_EC2_METADATA_SERVICE_ENDPOINT. A real mocking crate would pull in
    // dependencies that risk breaking this project's 1.77.2 MSRV (CI runs
    // `cargo test`/`clippy` at MSRV across all targets, dev-deps included).
    //
    // Shared with aws_credentials.rs's caching integration test, which is why
    // this lives in its own `pub(crate)` module rather than nested in `tests`.
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Clone)]
    pub(crate) struct ImdsScript {
        pub(crate) token_status: u16,
        pub(crate) token_body: String,
        pub(crate) listing_status: u16,
        pub(crate) listing_body: String,
        pub(crate) role_status: u16,
        pub(crate) role_body: String,
    }

    impl Default for ImdsScript {
        fn default() -> Self {
            ImdsScript {
                token_status: 200,
                token_body: "FAKE-TOKEN".to_string(),
                listing_status: 200,
                listing_body: "test-role".to_string(),
                role_status: 200,
                role_body: r#"{"Code":"Success","AccessKeyId":"ASIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Token":"FwoGZXIvYXdzEA...","Expiration":"2099-01-01T00:00:00Z"}"#.to_string(),
            }
        }
    }

    pub(crate) struct FakeImdsServer {
        addr: SocketAddr,
        connection_count: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl FakeImdsServer {
        pub(crate) async fn start(script: ImdsScript) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connection_count = Arc::new(AtomicUsize::new(0));
            let counter = connection_count.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let script = script.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(&mut socket, &script).await;
                    });
                }
            });
            FakeImdsServer {
                addr,
                connection_count,
                handle,
            }
        }

        pub(crate) fn endpoint(&self) -> String {
            format!("http://{}", self.addr)
        }

        pub(crate) fn connections(&self) -> usize {
            self.connection_count.load(Ordering::SeqCst)
        }
    }

    impl Drop for FakeImdsServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn handle_connection(socket: &mut TcpStream, script: &ImdsScript) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buf);
        let first_line = request.lines().next().unwrap_or("");
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        // Real IMDS echoes the requested TTL back on the token response; the
        // client rejects a token response that's missing it (TokenErrorKind::NoTtl).
        let requested_ttl = request
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("x-aws-ec2-metadata-token-ttl-seconds:")
                    .map(|v| v.trim().to_string())
            })
            .unwrap_or_else(|| "21600".to_string());

        let (status, body, extra_header) = if method == "PUT" && path == "/latest/api/token" {
            (
                script.token_status,
                script.token_body.clone(),
                Some(format!(
                    "x-aws-ec2-metadata-token-ttl-seconds: {}\r\n",
                    requested_ttl
                )),
            )
        } else if method == "GET" && path == "/latest/meta-data/iam/security-credentials/" {
            (script.listing_status, script.listing_body.clone(), None)
        } else if method == "GET" && path.starts_with("/latest/meta-data/iam/security-credentials/")
        {
            (script.role_status, script.role_body.clone(), None)
        } else {
            (404, "not found".to_string(), None)
        };

        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            _ => "Error",
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
            status,
            reason,
            body.len(),
            extra_header.unwrap_or_default(),
            body
        );
        socket.write_all(response.as_bytes()).await?;
        socket.shutdown().await?;
        Ok(())
    }

    // Bind a listener just to reserve a free loopback port, then drop it so
    // nothing is listening there anymore — connecting to it should fail fast
    // with "connection refused" rather than hanging.
    pub(crate) async fn unused_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    // Guards AWS_EC2_METADATA_SERVICE_ENDPOINT / AWS_EC2_METADATA_DISABLED,
    // restoring/removing them on drop so tests don't leak env state into
    // each other even on panic (tests are still serialized via
    // #[serial(env_vars)], matching the pattern in config.rs).
    pub(crate) struct EnvGuard {
        keys: Vec<&'static str>,
    }

    impl EnvGuard {
        pub(crate) fn set(pairs: &[(&'static str, &str)]) -> Self {
            let mut keys = Vec::new();
            for (k, v) in pairs {
                std::env::set_var(k, v);
                keys.push(*k);
            }
            EnvGuard { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                std::env::remove_var(k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{unused_addr, EnvGuard, FakeImdsServer, ImdsScript};
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_success_path_returns_expected_credentials() {
        let server = FakeImdsServer::start(ImdsScript::default()).await;
        let _guard = EnvGuard::set(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.endpoint())]);

        let creds = get_instance_role_credentials_from_aws().await.unwrap();

        assert_eq!(creds.AccessKeyId, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.SecretAccessKey,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(creds.SessionToken, "FwoGZXIvYXdzEA...");
    }

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_expiration_is_formatted_like_other_credential_sources() {
        let server = FakeImdsServer::start(ImdsScript::default()).await;
        let _guard = EnvGuard::set(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.endpoint())]);

        let creds = get_instance_role_credentials_from_aws().await.unwrap();

        // Golden assertion: the mocked "2099-01-01T00:00:00Z" expiration must
        // map to exactly this format, matching the SSO/assume-role paths.
        assert_eq!(creds.Expiration, "2099-01-01T00:00:00+00:00");
    }

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_no_instance_profile_attached_gives_clear_error() {
        let script = ImdsScript {
            listing_status: 404,
            listing_body: "".to_string(),
            ..Default::default()
        };
        let server = FakeImdsServer::start(script).await;
        let _guard = EnvGuard::set(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.endpoint())]);

        let err = get_instance_role_credentials_from_aws().await.unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("no IAM role attached") || msg.contains("not running on"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_imds_disabled_makes_no_network_call() {
        // Point at a real server so a stray network call would be observable,
        // but disable IMDS — the provider must short-circuit before ever
        // opening a connection.
        let server = FakeImdsServer::start(ImdsScript::default()).await;
        let _guard = EnvGuard::set(&[
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.endpoint()),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ]);

        let err = get_instance_role_credentials_from_aws().await.unwrap_err();

        assert!(err.to_string().contains("IMDS disabled"));
        assert_eq!(
            server.connections(),
            0,
            "IMDS disabled must not make any network calls"
        );
    }

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_malformed_credentials_json_gives_clear_error() {
        let script = ImdsScript {
            // Missing required "SecretAccessKey" field.
            role_body: r#"{"Code":"Success","AccessKeyId":"AK","Token":"T","Expiration":"2099-01-01T00:00:00Z"}"#
                .to_string(),
            ..Default::default()
        };
        let server = FakeImdsServer::start(script).await;
        let _guard = EnvGuard::set(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &server.endpoint())]);

        let err = get_instance_role_credentials_from_aws().await.unwrap_err();

        assert!(
            err.to_string().contains("SecretAccessKey"),
            "unexpected error message: {}",
            err
        );
    }

    #[tokio::test]
    #[serial(env_vars)]
    async fn test_unreachable_imds_gives_clear_error_instead_of_hanging() {
        let addr = unused_addr().await;
        let _guard = EnvGuard::set(&[(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
            &format!("http://{}", addr),
        )]);

        let err = get_instance_role_credentials_from_aws().await.unwrap_err();

        // Whichever variant the SDK settles on for a refused connection, it
        // must surface as one of our classified error messages, not a panic
        // or an indefinite hang.
        let msg = err.to_string();
        assert!(
            msg.contains("IMDS") || msg.contains("timed out"),
            "unexpected error message: {msg}"
        );
    }
}
