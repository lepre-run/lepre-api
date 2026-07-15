//! DynamoDB persistence for Strava connections, browser sessions and
//! short-lived webhook events. Workout data is deliberately not stored here.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use sha2::{Digest, Sha256};

use crate::crypto::EncryptedToken;

const PK: &str = "pk";
const SK: &str = "sk";
const CONNECTION_SK: &str = "CONNECTION";
const SESSION_SK: &str = "SESSION";

#[derive(Clone)]
pub struct Store {
    client: Client,
    table: String,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub athlete_id: i64,
    pub access_token: EncryptedToken,
    pub refresh_token: EncryptedToken,
    pub key_version: i32,
    pub token_version: i64,
    pub token_expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub object_id: i64,
    pub aspect_type: String,
}

impl Store {
    pub fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }

    pub async fn put_connection(&self, connection: &Connection) -> Result<(), anyhow::Error> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(connection_item(connection)))
            .send()
            .await
            .context("dynamodb put connection failed")?;
        Ok(())
    }

    pub async fn get_connection(
        &self,
        athlete_id: i64,
    ) -> Result<Option<Connection>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(athlete_pk(athlete_id)))
            .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get connection failed")?;
        response.item().map(parse_connection).transpose()
    }

    pub async fn replace_tokens(
        &self,
        connection: &Connection,
        expected_version: i64,
    ) -> Result<bool, anyhow::Error> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(connection_item(connection)))
            .condition_expression("token_version = :expected")
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).context("dynamodb token update failed"),
        }
    }

    pub async fn delete_connection(&self, athlete_id: i64) -> Result<(), anyhow::Error> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(athlete_pk(athlete_id)))
            .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .send()
            .await
            .context("dynamodb delete connection failed")?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        raw_session: &str,
        athlete_id: i64,
        expires_at: i64,
    ) -> Result<(), anyhow::Error> {
        self.client
            .put_item()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(session_pk(raw_session)))
            .item(SK, AttributeValue::S(SESSION_SK.to_owned()))
            .item("athlete_id", AttributeValue::N(athlete_id.to_string()))
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .send()
            .await
            .context("dynamodb put session failed")?;
        Ok(())
    }

    pub async fn athlete_for_session(
        &self,
        raw_session: &str,
        now: i64,
    ) -> Result<Option<i64>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(session_pk(raw_session)))
            .key(SK, AttributeValue::S(SESSION_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get session failed")?;
        let Some(item) = response.item() else {
            return Ok(None);
        };
        let expires = n(item, "expires_at")?;
        if expires <= now {
            return Ok(None);
        }
        Ok(Some(n(item, "athlete_id")?))
    }

    pub async fn delete_session(&self, raw_session: &str) -> Result<(), anyhow::Error> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(session_pk(raw_session)))
            .key(SK, AttributeValue::S(SESSION_SK.to_owned()))
            .send()
            .await
            .context("dynamodb delete session failed")?;
        Ok(())
    }

    pub async fn put_webhook_event(
        &self,
        athlete_id: i64,
        object_id: i64,
        aspect_type: &str,
        received_at_ms: i64,
    ) -> Result<(), anyhow::Error> {
        let suffix = uuid::Uuid::new_v4();
        self.client
            .put_item()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(athlete_pk(athlete_id)))
            .item(
                SK,
                AttributeValue::S(format!("EVENT#{received_at_ms:020}#{suffix}")),
            )
            .item("object_id", AttributeValue::N(object_id.to_string()))
            .item("aspect_type", AttributeValue::S(aspect_type.to_owned()))
            .item(
                "expires_at",
                AttributeValue::N((received_at_ms / 1000 + 2_592_000).to_string()),
            )
            .send()
            .await
            .context("dynamodb put webhook event failed")?;
        Ok(())
    }

    pub async fn webhook_events(
        &self,
        athlete_id: i64,
        after_ms: i64,
        through_ms: i64,
    ) -> Result<Vec<WebhookEvent>, anyhow::Error> {
        let response = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("pk = :pk AND sk BETWEEN :after AND :through")
            .expression_attribute_values(":pk", AttributeValue::S(athlete_pk(athlete_id)))
            .expression_attribute_values(
                ":after",
                AttributeValue::S(format!("EVENT#{after_ms:020}")),
            )
            .expression_attribute_values(
                ":through",
                AttributeValue::S(format!("EVENT#{through_ms:020}~")),
            )
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb query webhook events failed")?;
        response
            .items()
            .iter()
            .map(|item| {
                Ok(WebhookEvent {
                    object_id: n(item, "object_id")?,
                    aspect_type: s(item, "aspect_type")?.to_owned(),
                })
            })
            .collect()
    }
}

fn athlete_pk(athlete_id: i64) -> String {
    format!("ATHLETE#{athlete_id}")
}

fn session_pk(raw_session: &str) -> String {
    let digest = Sha256::digest(raw_session.as_bytes());
    format!("SESSION#{digest:x}")
}

fn connection_item(connection: &Connection) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            PK.to_owned(),
            AttributeValue::S(athlete_pk(connection.athlete_id)),
        ),
        (SK.to_owned(), AttributeValue::S(CONNECTION_SK.to_owned())),
        (
            "athlete_id".to_owned(),
            AttributeValue::N(connection.athlete_id.to_string()),
        ),
        (
            "access_ciphertext".to_owned(),
            AttributeValue::B(Blob::new(connection.access_token.ciphertext.clone())),
        ),
        (
            "access_nonce".to_owned(),
            AttributeValue::B(Blob::new(connection.access_token.nonce)),
        ),
        (
            "refresh_ciphertext".to_owned(),
            AttributeValue::B(Blob::new(connection.refresh_token.ciphertext.clone())),
        ),
        (
            "refresh_nonce".to_owned(),
            AttributeValue::B(Blob::new(connection.refresh_token.nonce)),
        ),
        (
            "key_version".to_owned(),
            AttributeValue::N(connection.key_version.to_string()),
        ),
        (
            "token_version".to_owned(),
            AttributeValue::N(connection.token_version.to_string()),
        ),
        (
            "token_expires_at".to_owned(),
            AttributeValue::N(connection.token_expires_at.to_string()),
        ),
    ])
}

fn parse_connection(item: &HashMap<String, AttributeValue>) -> Result<Connection, anyhow::Error> {
    Ok(Connection {
        athlete_id: n(item, "athlete_id")?,
        access_token: encrypted(item, "access_ciphertext", "access_nonce")?,
        refresh_token: encrypted(item, "refresh_ciphertext", "refresh_nonce")?,
        key_version: n(item, "key_version")? as i32,
        token_version: n(item, "token_version")?,
        token_expires_at: n(item, "token_expires_at")?,
    })
}

fn encrypted(
    item: &HashMap<String, AttributeValue>,
    ciphertext: &str,
    nonce: &str,
) -> Result<EncryptedToken, anyhow::Error> {
    let ciphertext = item
        .get(ciphertext)
        .and_then(|v| v.as_b().ok())
        .ok_or_else(|| anyhow!("missing ciphertext"))?
        .as_ref()
        .to_vec();
    let nonce_vec = item
        .get(nonce)
        .and_then(|v| v.as_b().ok())
        .ok_or_else(|| anyhow!("missing nonce"))?
        .as_ref()
        .to_vec();
    let nonce = nonce_vec.try_into().map_err(|_| anyhow!("invalid nonce"))?;
    Ok(EncryptedToken { ciphertext, nonce })
}

fn s<'a>(item: &'a HashMap<String, AttributeValue>, key: &str) -> Result<&'a str, anyhow::Error> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing string field {key}"))
}

fn n(item: &HashMap<String, AttributeValue>, key: &str) -> Result<i64, anyhow::Error> {
    item.get(key)
        .and_then(|value| value.as_n().ok())
        .ok_or_else(|| anyhow!("missing numeric field {key}"))?
        .parse()
        .with_context(|| format!("invalid numeric field {key}"))
}
