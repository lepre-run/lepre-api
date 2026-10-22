//! DynamoDB adapter for application persistence ports.

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, Delete as TransactDelete, KeysAndAttributes, Put as TransactPut,
    TransactWriteItem, Update as TransactUpdate,
};
use sha2::{Digest, Sha256};

use crate::application::{
    HistoryRepository, ImportState, ImportStatus, PendingImport, ProviderCredentials,
    ProviderEvent, Repository, SYNC_BATCH_REQUEST_COST, StoredProviderConnection, SyncGateConfig,
    SyncTurn,
};
use crate::crypto::{EncryptedToken, TokenKind, decrypt, encrypt};
use crate::domain::{
    ConnectionId, ExternalAccountId, ProviderConnection, ProviderId, UserId, Workout, WorkoutId,
};
use crate::history::{
    ChangeSet, MonthState, StoredWorkoutState, WorkoutRecord, affected_months, plan_changes,
};

const PK: &str = "pk";
const SK: &str = "sk";
const CONNECTION_SK: &str = "CONNECTION";
const SESSION_SK: &str = "SESSION";
const SYNC_QUEUE_PK: &str = "SYNC_QUEUE";
const SYNC_QUEUE_MARKER_SK: &str = "SYNC_QUEUE";
const STRAVA_QUOTA_PK: &str = "STRAVA_QUOTA";
const HISTORY_PENDING_PK: &str = "HISTORY_PENDING";
const HISTORY_IMPORT_SK: &str = "HISTORY_IMPORT";
const WORKOUT_SK_PREFIX: &str = "WORKOUT#";
const MONTH_SK_PREFIX: &str = "MONTH#";
const MAX_BATCH_GET_KEYS: usize = 100;
const MAX_TRANSACTION_ITEMS: usize = 100;
const MAX_CHANGE_ATTEMPTS: usize = 3;

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
        let mut events = Vec::new();
        let mut exclusive_start_key = None;
        loop {
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
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .context("dynamodb query provider events failed")?;
            for item in response.items() {
                events.push(ProviderEvent {
                    external_workout_id: n(item, "external_workout_id")?,
                    aspect: s(item, "aspect")?.to_owned(),
                    received_at_millis: event_received_at(s(item, SK)?)?,
                });
            }
            // Query stops at 1MB per page; keep reading until DynamoDB returns no continuation key.
            match response.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => return Ok(events),
            }
        }
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

#[async_trait]
impl HistoryRepository for Store {
    async fn mark_pending(&self, user_id: &UserId, now_millis: i64) -> Result<(), anyhow::Error> {
        self.client
            .update_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(HISTORY_PENDING_PK.to_owned()))
            .key(SK, AttributeValue::S(user_pk(user_id)))
            .update_expression(
                "SET user_id = :user_id, touched_at_millis = :now, \
                 last_turn_millis = if_not_exists(last_turn_millis, :zero), \
                 retry_at_millis = if_not_exists(retry_at_millis, :zero), \
                 failures = if_not_exists(failures, :zero)",
            )
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(now_millis.to_string()))
            .expression_attribute_values(":zero", AttributeValue::N("0".to_owned()))
            .send()
            .await
            .context("dynamodb mark history import pending failed")?;
        Ok(())
    }

    async fn pending_imports(&self) -> Result<Vec<PendingImport>, anyhow::Error> {
        let mut pending = Vec::new();
        let mut exclusive_start_key = None;
        loop {
            let response = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(
                    ":pk",
                    AttributeValue::S(HISTORY_PENDING_PK.to_owned()),
                )
                .consistent_read(true)
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .context("dynamodb query pending history imports failed")?;
            for item in response.items() {
                pending.push(PendingImport {
                    user_id: UserId::new(s(item, "user_id")?)?,
                    touched_at_millis: n(item, "touched_at_millis")?,
                    last_turn_millis: n(item, "last_turn_millis")?,
                    retry_at_millis: n(item, "retry_at_millis")?,
                    failures: optional_n(item, "failures")?.unwrap_or(0),
                });
            }
            match response.last_evaluated_key {
                Some(key) if !key.is_empty() => exclusive_start_key = Some(key),
                _ => return Ok(pending),
            }
        }
    }

    async fn record_turn(
        &self,
        user_id: &UserId,
        now_millis: i64,
        retry_at_millis: i64,
        failures: i64,
    ) -> Result<(), anyhow::Error> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(HISTORY_PENDING_PK.to_owned()))
            .key(SK, AttributeValue::S(user_pk(user_id)))
            .update_expression(
                "SET last_turn_millis = :now, retry_at_millis = :retry, failures = :failures",
            )
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":now", AttributeValue::N(now_millis.to_string()))
            .expression_attribute_values(":retry", AttributeValue::N(retry_at_millis.to_string()))
            .expression_attribute_values(":failures", AttributeValue::N(failures.to_string()))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(error) => Err(error).context("dynamodb record history import turn failed"),
        }
    }

    async fn clear_pending(&self, pending: &PendingImport) -> Result<(), anyhow::Error> {
        let result = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(HISTORY_PENDING_PK.to_owned()))
            .key(SK, AttributeValue::S(user_pk(&pending.user_id)))
            .condition_expression("touched_at_millis = :seen")
            .expression_attribute_values(
                ":seen",
                AttributeValue::N(pending.touched_at_millis.to_string()),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(error) => Err(error).context("dynamodb clear pending history import failed"),
        }
    }

    async fn import_state(&self, user_id: &UserId) -> Result<Option<ImportState>, anyhow::Error> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(PK, AttributeValue::S(user_pk(user_id)))
            .key(SK, AttributeValue::S(HISTORY_IMPORT_SK.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .context("dynamodb get history import state failed")?;
        response
            .item
            .as_ref()
            .map(|item| {
                Ok(ImportState {
                    status: match s(item, "import_status")? {
                        "in_progress" => ImportStatus::InProgress,
                        "complete" => ImportStatus::Complete,
                        "failed" => ImportStatus::Failed,
                        other => return Err(anyhow!("unknown history import status {other}")),
                    },
                    before_seconds: n(item, "before_seconds")?,
                    event_cursor_millis: n(item, "event_cursor_millis")?,
                    imported_count: n(item, "imported_count")?,
                    started_at_millis: n(item, "started_at_millis")?,
                })
            })
            .transpose()
    }

    async fn save_import_state(
        &self,
        user_id: &UserId,
        state: &ImportState,
    ) -> Result<(), anyhow::Error> {
        let status = match state.status {
            ImportStatus::InProgress => "in_progress",
            ImportStatus::Complete => "complete",
            ImportStatus::Failed => "failed",
        };
        self.client
            .put_item()
            .table_name(&self.table)
            .item(PK, AttributeValue::S(user_pk(user_id)))
            .item(SK, AttributeValue::S(HISTORY_IMPORT_SK.to_owned()))
            .item("import_status", AttributeValue::S(status.to_owned()))
            .item(
                "before_seconds",
                AttributeValue::N(state.before_seconds.to_string()),
            )
            .item(
                "event_cursor_millis",
                AttributeValue::N(state.event_cursor_millis.to_string()),
            )
            .item(
                "imported_count",
                AttributeValue::N(state.imported_count.to_string()),
            )
            .item(
                "started_at_millis",
                AttributeValue::N(state.started_at_millis.to_string()),
            )
            .send()
            .await
            .context("dynamodb save history import state failed")?;
        Ok(())
    }

    async fn apply_workout_changes(
        &self,
        user_id: &UserId,
        upserts: Vec<Workout>,
        removals: Vec<WorkoutId>,
    ) -> Result<(), anyhow::Error> {
        let records: Vec<WorkoutRecord> = upserts
            .into_iter()
            .filter_map(|workout| {
                let id = workout.id.to_string();
                let record = WorkoutRecord::new(workout);
                if record.is_none() {
                    tracing::warn!(
                        event = "history_workout_skipped",
                        workout_id = id,
                        "workout start time has no month bucket"
                    );
                }
                record
            })
            .collect();
        let removals: Vec<String> = removals.iter().map(ToString::to_string).collect();
        if records.is_empty() && removals.is_empty() {
            return Ok(());
        }
        let ids: BTreeSet<String> = records
            .iter()
            .map(|record| record.id.clone())
            .chain(removals.iter().cloned())
            .collect();
        for _ in 0..MAX_CHANGE_ATTEMPTS {
            let existing = self.stored_workouts(user_id, &ids).await?;
            let months = self
                .stored_months(user_id, &affected_months(&existing, &records))
                .await?;
            let changes = plan_changes(&existing, &months, records.clone(), &removals, || {
                uuid::Uuid::new_v4().to_string()
            });
            if changes.is_empty() || self.commit_changes(user_id, &changes).await? {
                return Ok(());
            }
        }
        Err(anyhow!(
            "history changes kept conflicting with concurrent writes"
        ))
    }
}

impl Store {
    async fn batch_get(
        &self,
        keys: Vec<HashMap<String, AttributeValue>>,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, anyhow::Error> {
        let mut items = Vec::new();
        for chunk in keys.chunks(MAX_BATCH_GET_KEYS) {
            let mut request = Some(
                KeysAndAttributes::builder()
                    .set_keys(Some(chunk.to_vec()))
                    .consistent_read(true)
                    .build()?,
            );
            while let Some(keys) = request.take() {
                let response = self
                    .client
                    .batch_get_item()
                    .request_items(&self.table, keys)
                    .send()
                    .await
                    .context("dynamodb batch get history items failed")?;
                if let Some(found) = response
                    .responses
                    .and_then(|mut tables| tables.remove(&self.table))
                {
                    items.extend(found);
                }
                request = response
                    .unprocessed_keys
                    .and_then(|mut tables| tables.remove(&self.table))
                    .filter(|keys| !keys.keys().is_empty());
            }
        }
        Ok(items)
    }

    async fn stored_workouts(
        &self,
        user_id: &UserId,
        ids: &BTreeSet<String>,
    ) -> Result<HashMap<String, StoredWorkoutState>, anyhow::Error> {
        let keys = ids
            .iter()
            .map(|id| history_key(user_id, format!("{WORKOUT_SK_PREFIX}{id}")))
            .collect();
        self.batch_get(keys)
            .await?
            .iter()
            .map(|item| {
                let id = s(item, SK)?
                    .strip_prefix(WORKOUT_SK_PREFIX)
                    .ok_or_else(|| anyhow!("workout item has an unexpected sort key"))?;
                Ok((
                    id.to_owned(),
                    StoredWorkoutState {
                        month: s(item, "month")?.to_owned(),
                        sync_version: s(item, "sync_version")?.to_owned(),
                        fingerprint: s(item, "fingerprint")?.to_owned(),
                    },
                ))
            })
            .collect()
    }

    async fn stored_months(
        &self,
        user_id: &UserId,
        months: &BTreeSet<String>,
    ) -> Result<HashMap<String, MonthState>, anyhow::Error> {
        let keys = months
            .iter()
            .map(|month| history_key(user_id, format!("{MONTH_SK_PREFIX}{month}")))
            .collect();
        self.batch_get(keys)
            .await?
            .iter()
            .map(|item| {
                let members = item
                    .get("members")
                    .and_then(|value| value.as_m().ok())
                    .ok_or_else(|| anyhow!("month item has no members"))?
                    .iter()
                    .map(|(id, version)| {
                        version
                            .as_s()
                            .map(|version| (id.clone(), version.clone()))
                            .map_err(|_| anyhow!("month member version is not a string"))
                    })
                    .collect::<Result<_, anyhow::Error>>()?;
                Ok((
                    s(item, "month")?.to_owned(),
                    MonthState {
                        members,
                        rev: n(item, "rev")?,
                    },
                ))
            })
            .collect()
    }

    /// Write a change set atomically. `Ok(false)` means a concurrent writer
    /// changed an affected month first and the caller should re-plan.
    async fn commit_changes(
        &self,
        user_id: &UserId,
        changes: &ChangeSet,
    ) -> Result<bool, anyhow::Error> {
        let mut items = Vec::new();
        for write in &changes.workout_writes {
            let put = TransactPut::builder()
                .table_name(&self.table)
                .set_item(Some(HashMap::from([
                    (PK.to_owned(), AttributeValue::S(user_pk(user_id))),
                    (
                        SK.to_owned(),
                        AttributeValue::S(format!("{WORKOUT_SK_PREFIX}{}", write.record.id)),
                    ),
                    (
                        "month".to_owned(),
                        AttributeValue::S(write.record.month.clone()),
                    ),
                    (
                        "sync_version".to_owned(),
                        AttributeValue::S(write.sync_version.clone()),
                    ),
                    (
                        "fingerprint".to_owned(),
                        AttributeValue::S(write.record.fingerprint.clone()),
                    ),
                    (
                        "payload".to_owned(),
                        AttributeValue::S(write.record.payload.clone()),
                    ),
                ])))
                .build()?;
            items.push(TransactWriteItem::builder().put(put).build());
        }
        for id in &changes.workout_deletes {
            let delete = TransactDelete::builder()
                .table_name(&self.table)
                .set_key(Some(history_key(
                    user_id,
                    format!("{WORKOUT_SK_PREFIX}{id}"),
                )))
                .build()?;
            items.push(TransactWriteItem::builder().delete(delete).build());
        }
        for month in &changes.month_writes {
            let key = history_key(user_id, format!("{MONTH_SK_PREFIX}{}", month.month));
            match (month.expected_rev, month.members.is_empty()) {
                (None, true) => {}
                (Some(rev), true) => {
                    let delete = TransactDelete::builder()
                        .table_name(&self.table)
                        .set_key(Some(key))
                        .condition_expression("#rev = :rev")
                        .expression_attribute_names("#rev", "rev")
                        .expression_attribute_values(":rev", AttributeValue::N(rev.to_string()))
                        .build()?;
                    items.push(TransactWriteItem::builder().delete(delete).build());
                }
                (expected_rev, false) => {
                    let mut item = key;
                    item.insert("month".to_owned(), AttributeValue::S(month.month.clone()));
                    item.insert(
                        "members".to_owned(),
                        AttributeValue::M(
                            month
                                .members
                                .iter()
                                .map(|(id, version)| {
                                    (id.clone(), AttributeValue::S(version.clone()))
                                })
                                .collect(),
                        ),
                    );
                    item.insert("digest".to_owned(), AttributeValue::S(month.digest()));
                    item.insert(
                        "workout_count".to_owned(),
                        AttributeValue::N(month.members.len().to_string()),
                    );
                    item.insert(
                        "rev".to_owned(),
                        AttributeValue::N((expected_rev.unwrap_or(0) + 1).to_string()),
                    );
                    let put = TransactPut::builder()
                        .table_name(&self.table)
                        .set_item(Some(item))
                        .expression_attribute_names("#rev", "rev");
                    let put = match expected_rev {
                        Some(rev) => put
                            .condition_expression("#rev = :rev")
                            .expression_attribute_values(
                                ":rev",
                                AttributeValue::N(rev.to_string()),
                            ),
                        None => put.condition_expression("attribute_not_exists(#rev)"),
                    };
                    items.push(TransactWriteItem::builder().put(put.build()?).build());
                }
            }
        }
        if items.len() > MAX_TRANSACTION_ITEMS {
            anyhow::bail!("history change set exceeds one DynamoDB transaction");
        }
        let result = self
            .client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.is_transaction_canceled_exception()) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).context("dynamodb commit history changes failed"),
        }
    }
}

fn history_key(user_id: &UserId, sk: String) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (PK.to_owned(), AttributeValue::S(user_pk(user_id))),
        (SK.to_owned(), AttributeValue::S(sk)),
    ])
}

/// Receive time encoded in an `EVENT#{millis:020}#{uuid}` sort key.
fn event_received_at(sk: &str) -> Result<i64, anyhow::Error> {
    sk.strip_prefix("EVENT#")
        .and_then(|rest| rest.get(..20))
        .and_then(|millis| millis.parse().ok())
        .ok_or_else(|| anyhow!("event item has an unexpected sort key"))
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

fn optional_n(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<i64>, anyhow::Error> {
    item.get(key).map(|_| n(item, key)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
    use wiremock::matchers::{body_string_contains, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[tokio::test]
    async fn events_follow_pagination_past_the_first_page() {
        let server = MockServer::start().await;
        let last_key = r#"{"pk":{"S":"USER#user-1"},"sk":{"S":"EVENT#00000000000000000002#b"}}"#;
        let page = |items: &str, last: Option<&str>| {
            let body = match last {
                Some(key) => format!(r#"{{"Items":[{items}],"LastEvaluatedKey":{key}}}"#),
                None => format!(r#"{{"Items":[{items}]}}"#),
            };
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/x-amz-json-1.0")
                .set_body_string(body)
        };
        Mock::given(method("POST"))
            .and(body_string_contains("ExclusiveStartKey"))
            .respond_with(page(
                r#"{"sk":{"S":"EVENT#00000000000000000007#c"},"external_workout_id":{"N":"3"},"aspect":{"S":"delete"}}"#,
                None,
            ))
            .expect(1)
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(page(
                r#"{"sk":{"S":"EVENT#00000000000000000001#a"},"external_workout_id":{"N":"1"},"aspect":{"S":"create"}},{"sk":{"S":"EVENT#00000000000000000002#b"},"external_workout_id":{"N":"2"},"aspect":{"S":"update"}}"#,
                Some(last_key),
            ))
            .expect(1)
            .up_to_n_times(1)
            .with_priority(2)
            .mount(&server)
            .await;
        let store = test_store(&server);

        let events = store
            .events(&UserId::new("user-1").unwrap(), 0, 10)
            .await
            .unwrap();

        let ids: Vec<_> = events
            .iter()
            .map(|event| {
                (
                    event.external_workout_id,
                    event.aspect.as_str(),
                    event.received_at_millis,
                )
            })
            .collect();
        assert_eq!(ids, [(1, "create", 1), (2, "update", 2), (3, "delete", 7)]);
    }

    fn test_store(server: &MockServer) -> Store {
        let config = aws_sdk_dynamodb::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::for_tests())
            .endpoint_url(server.uri())
            .build();
        Store::new(Client::from_conf(config), "table".into(), [0; 32], 1)
    }

    fn dynamodb_json(status: u16, body: &str) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .insert_header("content-type", "application/x-amz-json-1.0")
            .set_body_string(body.to_owned())
    }

    fn operation(name: &str) -> wiremock::matchers::HeaderExactMatcher {
        header("x-amz-target", format!("DynamoDB_20120810.{name}").as_str())
    }

    fn easy_run() -> Workout {
        use crate::domain::{RunSport, WorkoutData, WorkoutType};
        Workout::new(WorkoutData {
            id: WorkoutId::new("strava:1").unwrap(),
            performed_at: "2026-10-10T08:00:00Z".to_owned(),
            name: "Easy".to_owned(),
            description: String::new(),
            workout_type: WorkoutType::Workout,
            sport: RunSport::Run,
            duration_seconds: 1_800,
            elapsed_duration_seconds: 1_800,
            distance_meters: 5_000.0,
            average_heart_rate_bpm: None,
            max_heart_rate_bpm: None,
            laps: Vec::new(),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn new_workout_is_written_with_its_month_in_one_transaction() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(operation("BatchGetItem"))
            .respond_with(dynamodb_json(200, r#"{"Responses":{"table":[]}}"#))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(operation("TransactWriteItems"))
            .respond_with(dynamodb_json(200, "{}"))
            .expect(1)
            .mount(&server)
            .await;

        test_store(&server)
            .apply_workout_changes(
                &UserId::new("user-1").unwrap(),
                vec![easy_run()],
                Vec::new(),
            )
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let transaction = String::from_utf8(requests[2].body.clone()).unwrap();
        assert!(transaction.contains(r#""S":"WORKOUT#strava:1""#));
        assert!(transaction.contains(r#""S":"MONTH#2026-10""#));
        assert!(transaction.contains("attribute_not_exists(#rev)"));
        assert!(transaction.contains(r#""rev":{"N":"1"}"#));
    }

    #[tokio::test]
    async fn conflicting_month_write_is_replanned() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(operation("BatchGetItem"))
            .respond_with(dynamodb_json(200, r#"{"Responses":{"table":[]}}"#))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(operation("TransactWriteItems"))
            .respond_with(dynamodb_json(
                400,
                r#"{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"Transaction cancelled","CancellationReasons":[{"Code":"ConditionalCheckFailed"}]}"#,
            ))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(operation("TransactWriteItems"))
            .respond_with(dynamodb_json(200, "{}"))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        test_store(&server)
            .apply_workout_changes(
                &UserId::new("user-1").unwrap(),
                vec![easy_run()],
                Vec::new(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn clearing_pending_keeps_an_entry_touched_after_it_was_read() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(operation("DeleteItem"))
            .and(body_string_contains("touched_at_millis = :seen"))
            .respond_with(dynamodb_json(
                400,
                r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed"}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;

        test_store(&server)
            .clear_pending(&PendingImport {
                user_id: UserId::new("user-1").unwrap(),
                touched_at_millis: 5,
                last_turn_millis: 0,
                retry_at_millis: 0,
                failures: 0,
            })
            .await
            .unwrap();
    }
}
