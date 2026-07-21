//! DynamoDB adapter for application persistence ports.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, Delete as TransactDelete, Put as TransactPut, TransactWriteItem,
    Update as TransactUpdate,
};
use sha2::{Digest, Sha256};

use crate::application::{
    ProviderCredentials, ProviderEvent, Repository, SYNC_BATCH_REQUEST_COST,
    StoredProviderConnection, SyncGateConfig, SyncTurn,
};
use crate::crypto::{EncryptedToken, TokenKind, decrypt, encrypt};
use crate::domain::{ConnectionId, ExternalAccountId, ProviderConnection, ProviderId, UserId};

const PK: &str = "pk";
const SK: &str = "sk";
const CONNECTION_SK: &str = "CONNECTION";
const SESSION_SK: &str = "SESSION";
const SYNC_QUEUE_PK: &str = "SYNC_QUEUE";
const SYNC_QUEUE_MARKER_SK: &str = "SYNC_QUEUE";
const STRAVA_QUOTA_PK: &str = "STRAVA_QUOTA";

struct QueueMarker {
    queue_sk: String,
    expires_at_millis: i64,
}

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
                "first_name".to_owned(),
                AttributeValue::S(record.first_name.clone()),
            ),
            (
                "last_name".to_owned(),
                AttributeValue::S(record.last_name.clone()),
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
            first_name: optional_s(item, "first_name")
                .unwrap_or("Strava")
                .to_owned(),
            last_name: optional_s(item, "last_name")
                .unwrap_or("Athlete")
                .to_owned(),
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

    async fn queue_marker(&self, user_id: &UserId) -> Result<Option<QueueMarker>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(SYNC_QUEUE_MARKER_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get synchronization queue marker failed")?;
        response
            .item
            .as_ref()
            .map(|item| {
                Ok(QueueMarker {
                    queue_sk: s(item, "queue_sk")?.to_owned(),
                    expires_at_millis: n(item, "expires_at_millis")?,
                })
            })
            .transpose()
    }

    async fn delete_expired_queue_entry(
        &self,
        queue_sk: &str,
        user_id: &UserId,
        now_millis: i64,
    ) -> Result<(), anyhow::Error> {
        let _ = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(SYNC_QUEUE_PK.to_owned()))
            .key(SK, AttributeValue::S(queue_sk.to_owned()))
            .condition_expression("expires_at_millis <= :now")
            .expression_attribute_values(":now", AttributeValue::N(now_millis.to_string()))
            .send()
            .await;
        let _ = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(SYNC_QUEUE_MARKER_SK.to_owned()))
            .condition_expression("queue_sk = :queue_sk AND expires_at_millis <= :now")
            .expression_attribute_values(":queue_sk", AttributeValue::S(queue_sk.to_owned()))
            .expression_attribute_values(":now", AttributeValue::N(now_millis.to_string()))
            .send()
            .await;
        Ok(())
    }

    async fn touch_queue_entry(
        &self,
        marker: &QueueMarker,
        user_id: &UserId,
        expires_at_millis: i64,
    ) -> Result<(), anyhow::Error> {
        let expires_at = expires_at_millis / 1_000 + 1;
        self.client
            .update_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(SYNC_QUEUE_PK.to_owned()))
            .key(SK, AttributeValue::S(marker.queue_sk.clone()))
            .update_expression("SET expires_at_millis = :expires_millis, expires_at = :expires")
            .condition_expression("user_id = :user_id")
            .expression_attribute_values(
                ":expires_millis",
                AttributeValue::N(expires_at_millis.to_string()),
            )
            .expression_attribute_values(":expires", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .context("dynamodb refresh synchronization queue entry failed")?;
        self.client
            .update_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(SYNC_QUEUE_MARKER_SK.to_owned()))
            .update_expression("SET expires_at_millis = :expires_millis, expires_at = :expires")
            .condition_expression("queue_sk = :queue_sk")
            .expression_attribute_values(
                ":expires_millis",
                AttributeValue::N(expires_at_millis.to_string()),
            )
            .expression_attribute_values(":expires", AttributeValue::N(expires_at.to_string()))
            .expression_attribute_values(":queue_sk", AttributeValue::S(marker.queue_sk.clone()))
            .send()
            .await
            .context("dynamodb refresh synchronization queue marker failed")?;
        Ok(())
    }

    async fn enqueue_sync(
        &self,
        user_id: &UserId,
        now_millis: i64,
        lease_seconds: i64,
    ) -> Result<QueueMarker, anyhow::Error> {
        if let Some(marker) = self.queue_marker(user_id).await? {
            if marker.expires_at_millis > now_millis {
                self.touch_queue_entry(&marker, user_id, now_millis + lease_seconds * 1_000)
                    .await?;
                return Ok(marker);
            }
            self.delete_expired_queue_entry(&marker.queue_sk, user_id, now_millis)
                .await?;
        }

        let queue_sk = format!("TURN#{now_millis:020}#{}", uuid::Uuid::new_v4());
        let expires_at_millis = now_millis + lease_seconds * 1_000;
        let expires_at = expires_at_millis / 1_000 + 1;
        let queue_put = TransactPut::builder()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(SYNC_QUEUE_PK.to_owned()))
            .item(SK, AttributeValue::S(queue_sk.clone()))
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item(
                "expires_at_millis",
                AttributeValue::N(expires_at_millis.to_string()),
            )
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(pk)")
            .build()?;
        let marker_put = TransactPut::builder()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(user_pk(user_id)))
            .item(SK, AttributeValue::S(SYNC_QUEUE_MARKER_SK.to_owned()))
            .item("queue_sk", AttributeValue::S(queue_sk.clone()))
            .item(
                "expires_at_millis",
                AttributeValue::N(expires_at_millis.to_string()),
            )
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(pk)")
            .build()?;
        let result = self
            .client
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(queue_put).build())
            .transact_items(TransactWriteItem::builder().put(marker_put).build())
            .send()
            .await;
        match result {
            Ok(_) => Ok(QueueMarker {
                queue_sk,
                expires_at_millis,
            }),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.is_transaction_canceled_exception()) =>
            {
                self.queue_marker(user_id)
                    .await?
                    .ok_or_else(|| anyhow!("synchronization queue enqueue raced without marker"))
            }
            Err(error) => Err(error).context("dynamodb enqueue synchronization failed"),
        }
    }

    async fn queue_head(&self) -> Result<Option<HashMap<String, AttributeValue>>, anyhow::Error> {
        let response = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("pk = :pk AND begins_with(sk, :turn)")
            .expression_attribute_values(":pk", AttributeValue::S(SYNC_QUEUE_PK.to_owned()))
            .expression_attribute_values(":turn", AttributeValue::S("TURN#".to_owned()))
            .scan_index_forward(true)
            .consistent_read(true)
            .limit(1)
            .send()
            .await
            .context("dynamodb read synchronization queue head failed")?;
        Ok(response.items.and_then(|mut items| items.pop()))
    }

    async fn quota_reserved(&self, quota_sk: &str) -> Result<i64, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(STRAVA_QUOTA_PK.to_owned()))
            .key(SK, AttributeValue::S(quota_sk.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb read Strava quota reservation failed")?;
        response
            .item
            .as_ref()
            .map_or(Ok(0), |item| n(item, "reserved"))
    }

    async fn reserve_sync_turn(
        &self,
        marker: &QueueMarker,
        user_id: &UserId,
        now_seconds: i64,
        config: &SyncGateConfig,
    ) -> Result<SyncTurn, anyhow::Error> {
        let window_start = now_seconds.div_euclid(15 * 60) * 15 * 60;
        let day_start = now_seconds.div_euclid(24 * 60 * 60) * 24 * 60 * 60;
        let window_sk = format!("READ#15M#{window_start:020}");
        let day_sk = format!("READ#DAY#{day_start:020}");
        let reserved_15 = self.quota_reserved(&window_sk).await?;
        let reserved_daily = self.quota_reserved(&day_sk).await?;
        let limit_15 = config.safe_limit_15_minutes();
        let limit_daily = config.safe_limit_daily();
        let window_blocked = reserved_15 + SYNC_BATCH_REQUEST_COST > limit_15;
        let day_blocked = reserved_daily + SYNC_BATCH_REQUEST_COST > limit_daily;
        if window_blocked || day_blocked {
            let mut retry_after_seconds = config.poll_seconds;
            if window_blocked {
                retry_after_seconds =
                    retry_after_seconds.max((window_start + 15 * 60 - now_seconds).max(1) as u64);
            }
            if day_blocked {
                retry_after_seconds =
                    retry_after_seconds.max((day_start + 24 * 60 * 60 - now_seconds).max(1) as u64);
            }
            let queue_keepalive_seconds = config
                .poll_seconds
                .max((config.queue_lease_seconds / 2).max(1) as u64);
            return Ok(SyncTurn::Queued {
                retry_after_seconds: retry_after_seconds.min(queue_keepalive_seconds),
            });
        }

        let quota_update = |quota_sk: &str, limit: i64, expires_at: i64| {
            TransactUpdate::builder()
                .table_name(&self.table)
                .key(PK, AttributeValue::S(STRAVA_QUOTA_PK.to_owned()))
                .key(SK, AttributeValue::S(quota_sk.to_owned()))
                .update_expression(
                    "SET reserved = if_not_exists(reserved, :zero) + :cost, expires_at = :expires",
                )
                .condition_expression("attribute_not_exists(reserved) OR reserved <= :maximum")
                .expression_attribute_values(":zero", AttributeValue::N("0".to_owned()))
                .expression_attribute_values(
                    ":cost",
                    AttributeValue::N(SYNC_BATCH_REQUEST_COST.to_string()),
                )
                .expression_attribute_values(
                    ":maximum",
                    AttributeValue::N((limit - SYNC_BATCH_REQUEST_COST).to_string()),
                )
                .expression_attribute_values(":expires", AttributeValue::N(expires_at.to_string()))
                .build()
        };
        let queue_delete = TransactDelete::builder()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(SYNC_QUEUE_PK.to_owned()))
            .key(SK, AttributeValue::S(marker.queue_sk.clone()))
            .condition_expression("user_id = :user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .build()?;
        let marker_delete = TransactDelete::builder()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(SYNC_QUEUE_MARKER_SK.to_owned()))
            .condition_expression("queue_sk = :queue_sk")
            .expression_attribute_values(":queue_sk", AttributeValue::S(marker.queue_sk.clone()))
            .build()?;
        let result = self
            .client
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .update(quota_update(
                        &window_sk,
                        limit_15,
                        window_start + 2 * 24 * 60 * 60,
                    )?)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .update(quota_update(
                        &day_sk,
                        limit_daily,
                        day_start + 3 * 24 * 60 * 60,
                    )?)
                    .build(),
            )
            .transact_items(TransactWriteItem::builder().delete(queue_delete).build())
            .transact_items(TransactWriteItem::builder().delete(marker_delete).build())
            .send()
            .await;
        match result {
            Ok(_) => {
                tracing::info!(
                    event = "strava_sync_turn_granted",
                    request_cost = SYNC_BATCH_REQUEST_COST,
                    reserved_15_minutes = reserved_15 + SYNC_BATCH_REQUEST_COST,
                    reserved_daily = reserved_daily + SYNC_BATCH_REQUEST_COST,
                    "granted a fair Strava synchronization turn"
                );
                Ok(SyncTurn::Granted)
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.is_transaction_canceled_exception()) =>
            {
                Ok(SyncTurn::Queued {
                    retry_after_seconds: config.poll_seconds,
                })
            }
            Err(error) => Err(error).context("dynamodb reserve synchronization turn failed"),
        }
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

    async fn acquire_sync_turn(
        &self,
        user_id: &UserId,
        now_millis: i64,
        config: &SyncGateConfig,
    ) -> Result<SyncTurn, anyhow::Error> {
        for _ in 0..4 {
            let marker = self
                .enqueue_sync(user_id, now_millis, config.queue_lease_seconds)
                .await?;
            let Some(head) = self.queue_head().await? else {
                return Ok(SyncTurn::Queued {
                    retry_after_seconds: config.poll_seconds,
                });
            };
            let head_queue_sk = s(&head, SK)?.to_owned();
            let head_user_id = UserId::new(s(&head, "user_id")?)?;
            let head_expires_at_millis = n(&head, "expires_at_millis")?;
            if head_expires_at_millis <= now_millis {
                self.delete_expired_queue_entry(&head_queue_sk, &head_user_id, now_millis)
                    .await?;
                continue;
            }
            if head_user_id != *user_id {
                return Ok(SyncTurn::Queued {
                    retry_after_seconds: config.poll_seconds,
                });
            }
            return self
                .reserve_sync_turn(&marker, user_id, now_millis / 1_000, config)
                .await;
        }

        Ok(SyncTurn::Queued {
            retry_after_seconds: config.poll_seconds,
        })
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

fn optional_s<'a>(item: &'a HashMap<String, AttributeValue>, key: &str) -> Option<&'a str> {
    item.get(key)
        .and_then(|value| value.as_s().ok())
        .map(String::as_str)
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

    #[test]
    fn optional_strings_allow_legacy_connection_records() {
        let item = HashMap::new();
        assert_eq!(optional_s(&item, "first_name"), None);
    }
}
