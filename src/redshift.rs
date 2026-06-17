// Redshift temporary database credentials, the equivalent of
// `aws redshift get-cluster-credentials`. Emits JSON with DbUser, DbPassword,
// and Expiration so the caller can feed it to a DB client.

use crate::aws_credentials::AWScredentials;
use anyhow::{anyhow, Result};
use aws_smithy_types_convert::date_time::DateTimeExt;
use aws_types::region::Region;
use log::error;
use serde::Serialize;

#[derive(Serialize)]
#[allow(non_snake_case)]
struct ClusterCredentials {
    DbUser: String,
    DbPassword: String,
    Expiration: Option<String>,
}

pub async fn get_cluster_credentials(
    credentials: AWScredentials,
    region: String,
    cluster_id: &str,
    db_user: &str,
    db_name: Option<String>,
    auto_create: bool,
) -> Result<String> {
    let config = aws_sdk_redshift::Config::builder()
        .behavior_version(aws_sdk_redshift::config::BehaviorVersion::latest())
        .region(Region::new(region))
        .credentials_provider(credentials.credentials_provider())
        .build();
    let client = aws_sdk_redshift::Client::from_conf(config);

    let mut request = client
        .get_cluster_credentials()
        .cluster_identifier(cluster_id)
        .db_user(db_user)
        .auto_create(auto_create);
    if let Some(db) = db_name {
        request = request.db_name(db);
    }

    let output = request.send().await.map_err(|e| {
        error!("redshift.get_cluster_credentials: {}", e);
        anyhow!("error getting Redshift cluster credentials")
    })?;

    let db_user = output
        .db_user()
        .ok_or_else(|| anyhow!("Redshift returned no DbUser"))?
        .to_string();
    let db_password = output
        .db_password()
        .ok_or_else(|| anyhow!("Redshift returned no DbPassword"))?
        .to_string();
    let expiration = output
        .expiration()
        .and_then(|dt| dt.to_chrono_utc().ok())
        .map(|dt| dt.to_rfc3339());

    let creds = ClusterCredentials {
        DbUser: db_user,
        DbPassword: db_password,
        Expiration: expiration,
    };
    Ok(serde_json::to_string_pretty(&creds)?)
}
