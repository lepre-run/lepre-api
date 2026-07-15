//! DynamoDB adapter for application persistence ports.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;
use sha2::{Digest, Sha256};

use crate::application::{
    ProviderCredentials, ProviderEvent, Repository, StoredProviderConnection,
};
use crate::crypto::{EncryptedToken, TokenKind, decrypt, encrypt};
use crate::domain::{ConnectionId, ExternalAccountId, ProviderConnection, ProviderId, UserId};

const PK: &str = "pk";
const SK: &str = "sk";
const CONNECTION_SK: &str = "CONNECTION";
const SESSION_SK: &str = "SESSION";

#[derive(Clone)]
pub struct Store {
    client: Client,
    table: String,
    encryption_key: [u8; 32],
    key_version: i32,
}

impl Store {
    pub fn new(client: Client, table: String, encryption_key: [u8; 32], key_version: i32) -> Self {
        Self {
            client,
            table,
            encryption_key,
            key_version,
        }
    }

    async fn raw_connection(
        &self,
        user_id: &UserId,
    ) -> Result<Option<HashMap<String, AttributeValue>>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get provider connection failed")?;
        Ok(response.item)
    }

    fn connection_item(
        &self,
        record: &StoredProviderConnection,
    ) -> Result<HashMap<String, AttributeValue>, anyhow::Error> {
        let connection_id = record.connection.id.as_str();
        let access = encrypt(
            record.credentials.access_token.as_bytes(),
            connection_id,
            TokenKind::Access,
            self.key_version,
            &self.encryption_key,
        )?;
        let refresh = encrypt(
            record.credentials.refresh_token.as_bytes(),
            connection_id,
            TokenKind::Refresh,
            self.key_version,
            &self.encryption_key,
        )?;
        Ok(HashMap::from([
            (PK.to_owned(), AttributeValue::S(user_pk(&record.user_id))),
            (SK.to_owned(), AttributeValue::S(CONNECTION_SK.to_owned())),
            (
                "user_id".to_owned(),
                AttributeValue::S(record.user_id.to_string()),
            ),
            (
                "connection_id".to_owned(),
                AttributeValue::S(record.connection.id.to_string()),
            ),
            (
                "provider".to_owned(),
                AttributeValue::S(record.connection.provider.as_str().to_owned()),
            ),
            (
                "external_account_id".to_owned(),
                AttributeValue::S(record.connection.external_account_id.to_string()),
            ),
            (
                "access_ciphertext".to_owned(),
                AttributeValue::B(Blob::new(access.ciphertext)),
            ),
            (
                "access_nonce".to_owned(),
                AttributeValue::B(Blob::new(access.nonce)),
            ),
            (
                "refresh_ciphertext".to_owned(),
                AttributeValue::B(Blob::new(refresh.ciphertext)),
            ),
            (
                "refresh_nonce".to_owned(),
                AttributeValue::B(Blob::new(refresh.nonce)),
            ),
            (
                "key_version".to_owned(),
                AttributeValue::N(self.key_version.to_string()),
            ),
            (
                "token_version".to_owned(),
                AttributeValue::N(record.token_version.to_string()),
            ),
            (
                "token_expires_at".to_owned(),
                AttributeValue::N(record.credentials.expires_at.to_string()),
            ),
        ]))
    }

    fn parse_connection(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<StoredProviderConnection, anyhow::Error> {
        let user_id = UserId::new(s(item, "user_id")?)?;
        let connection_id = ConnectionId::new(s(item, "connection_id")?)?;
        let provider = match s(item, "provider")? {
            "strava" => ProviderId::Strava,
            other => return Err(anyhow!("unknown provider {other}")),
        };
        let external_account_id = ExternalAccountId::new(s(item, "external_account_id")?)?;
        let key_version = n(item, "key_version")? as i32;
        let access = encrypted(item, "access_ciphertext", "access_nonce")?;
        let refresh = encrypted(item, "refresh_ciphertext", "refresh_nonce")?;
        let access_token = String::from_utf8(decrypt(
            &access,
            connection_id.as_str(),
            TokenKind::Access,
            key_version,
            &self.encryption_key,
        )?)?;
        let refresh_token = String::from_utf8(decrypt(
            &refresh,
            connection_id.as_str(),
            TokenKind::Refresh,
            key_version,
            &self.encryption_key,
        )?)?;
        Ok(StoredProviderConnection {
            user_id,
            connection: ProviderConnection {
                id: connection_id,
                provider,
                external_account_id,
            },
            credentials: ProviderCredentials {
                access_token,
                refresh_token,
                expires_at: n(item, "token_expires_at")?,
            },
            token_version: n(item, "token_version")?,
        })
    }
}

#[async_trait]
impl Repository for Store {
    async fn connection_for_external(
        &self,
        provider: ProviderId,
        external_account_id: &ExternalAccountId,
    ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(
                PK,
                AttributeValue::S(external_pk(provider, external_account_id)),
            )
            .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get external account lookup failed")?;
        let Some(item) = response.item else {
            return Ok(None);
        };
        let user_id = UserId::new(s(&item, "user_id")?)?;
        self.connection_for_user(&user_id).await
    }

    async fn connection_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
        self.raw_connection(user_id)
            .await?
            .as_ref()
            .map(|item| self.parse_connection(item))
            .transpose()
    }

    async fn save_connection(
        &self,
        connection: &StoredProviderConnection,
    ) -> Result<(), anyhow::Error> {
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(self.connection_item(connection)?))
            .send()
            .await
            .context("dynamodb put provider connection failed")?;
        self.client
            .put_item()
            .table_name(&self.table)
            .item(
                PK,
                AttributeValue::S(external_pk(
                    connection.connection.provider,
                    &connection.connection.external_account_id,
                )),
            )
            .item(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .item("user_id", AttributeValue::S(connection.user_id.to_string()))
            .send()
            .await
            .context("dynamodb put external account lookup failed")?;
        Ok(())
    }

    async fn replace_credentials(
        &self,
        connection: &StoredProviderConnection,
        expected_version: i64,
    ) -> Result<bool, anyhow::Error> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(self.connection_item(connection)?))
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
                    .is_some_and(|value| value.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).context("dynamodb replace provider credentials failed"),
        }
    }

    async fn delete_connection(&self, user_id: &UserId) -> Result<(), anyhow::Error> {
        let existing = self.connection_for_user(user_id).await?;
        self.client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
            .send()
            .await
            .context("dynamodb delete provider connection failed")?;
        if let Some(existing) = existing {
            self.client
                .delete_item()
                .table_name(&self.table)
                .key(
                    PK,
                    AttributeValue::S(external_pk(
                        existing.connection.provider,
                        &existing.connection.external_account_id,
                    )),
                )
                .key(SK, AttributeValue::S(CONNECTION_SK.to_owned()))
                .send()
                .await
                .context("dynamodb delete external account lookup failed")?;
        }
        Ok(())
    }

    async fn create_session(
        &self,
        raw_session: &str,
        user_id: &UserId,
        expires_at: i64,
    ) -> Result<(), anyhow::Error> {
        self.client
            .put_item()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(session_pk(raw_session)))
            .item(SK, AttributeValue::S(SESSION_SK.to_owned()))
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .send()
            .await
            .context("dynamodb put session failed")?;
        Ok(())
    }

    async fn user_for_session(
        &self,
        raw_session: &str,
        now_seconds: i64,
    ) -> Result<Option<UserId>, anyhow::Error> {
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
        let Some(item) = response.item else {
            return Ok(None);
        };
        if n(&item, "expires_at")? <= now_seconds {
            return Ok(None);
        }
        Ok(Some(UserId::new(s(&item, "user_id")?)?))
    }

    async fn delete_session(&self, raw_session: &str) -> Result<(), anyhow::Error> {
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

    async fn put_event(
        &self,
        user_id: &UserId,
        event: &ProviderEvent,
        received_at_millis: i64,
    ) -> Result<(), anyhow::Error> {
        self.client
            .put_item()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(user_pk(user_id)))
            .item(
                SK,
                AttributeValue::S(format!(
                    "EVENT#{received_at_millis:020}#{}",
                    uuid::Uuid::new_v4()
                )),
            )
            .item(
                "external_workout_id",
                AttributeValue::N(event.external_workout_id.to_string()),
            )
            .item("aspect", AttributeValue::S(event.aspect.clone()))
            .item(
                "expires_at",
                AttributeValue::N((received_at_millis / 1000 + 2_592_000).to_string()),
            )
            .send()
            .await
            .context("dynamodb put provider event failed")?;
        Ok(())
    }

    async fn events(
        &self,
        user_id: &UserId,
        after_millis: i64,
        through_millis: i64,
    ) -> Result<Vec<ProviderEvent>, anyhow::Error> {
        let response = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("pk = :pk AND sk BETWEEN :after AND :through")
            .expression_attribute_values(":pk", AttributeValue::S(user_pk(user_id)))
            .expression_attribute_values(
                ":after",
                AttributeValue::S(format!("EVENT#{after_millis:020}")),
            )
            .expression_attribute_values(
                ":through",
                AttributeValue::S(format!("EVENT#{through_millis:020}~")),
            )
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb query provider events failed")?;
        response
            .items()
            .iter()
            .map(|item| {
                Ok(ProviderEvent {
                    external_workout_id: n(item, "external_workout_id")?,
                    aspect: s(item, "aspect")?.to_owned(),
                })
            })
            .collect()
    }
}

fn user_pk(user_id: &UserId) -> String {
    format!("USER#{user_id}")
}

fn external_pk(provider: ProviderId, external_account_id: &ExternalAccountId) -> String {
    format!("EXTERNAL#{}#{external_account_id}", provider.as_str())
}

fn session_pk(raw_session: &str) -> String {
    let digest = Sha256::digest(raw_session.as_bytes());
    format!("SESSION#{digest:x}")
}

fn encrypted(
    item: &HashMap<String, AttributeValue>,
    ciphertext: &str,
    nonce: &str,
) -> Result<EncryptedToken, anyhow::Error> {
    let ciphertext = item
        .get(ciphertext)
        .and_then(|value| value.as_b().ok())
        .ok_or_else(|| anyhow!("missing ciphertext"))?
        .as_ref()
        .to_vec();
    let nonce = item
        .get(nonce)
        .and_then(|value| value.as_b().ok())
        .ok_or_else(|| anyhow!("missing nonce"))?
        .as_ref()
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("invalid nonce"))?;
    Ok(EncryptedToken { ciphertext, nonce })
}

fn s<'a>(item: &'a HashMap<String, AttributeValue>, key: &str) -> Result<&'a str, anyhow::Error> {
    item.get(key)
        .and_then(|value| value.as_s().ok())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_provider_independent() {
        let user = UserId::new("user-1").unwrap();
        let external = ExternalAccountId::new("athlete-1").unwrap();
        assert_eq!(user_pk(&user), "USER#user-1");
        assert_eq!(
            external_pk(ProviderId::Strava, &external),
            "EXTERNAL#strava#athlete-1"
        );
    }

    #[test]
    fn raw_session_is_hashed() {
        assert!(!session_pk("secret-session").contains("secret-session"));
    }
}
