//! Provider-independent application use cases and their outbound ports.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use rand::Rng;
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{
    ConnectionId, ExternalAccountId, ProviderConnection, ProviderId, User, UserId, Workout,
    WorkoutId,
};

const SESSION_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_SYNC_PAGES: i64 = 1_000;

#[derive(Debug, Clone)]
pub struct ProviderCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredProviderConnection {
    pub user_id: UserId,
    pub first_name: String,
    pub last_name: String,
    pub connection: ProviderConnection,
    pub credentials: ProviderCredentials,
    pub token_version: i64,
}

#[derive(Debug)]
pub struct AuthorizedProviderAccount {
    pub external_account_id: ExternalAccountId,
    pub first_name: String,
    pub last_name: String,
    pub credentials: ProviderCredentials,
}

#[derive(Debug)]
pub struct ProviderWorkoutPage {
    pub workouts: Vec<Workout>,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct ProviderEvent {
    pub external_workout_id: i64,
    pub aspect: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    pub after_seconds: i64,
    pub event_cursor_millis: i64,
    pub snapshot_millis: i64,
    pub page: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCheckpoint {
    pub after_seconds: i64,
    pub event_cursor_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncContinuation {
    More(SyncRequest),
    Complete(SyncCheckpoint),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncBatch {
    pub upserted: Vec<Workout>,
    pub removed: Vec<WorkoutId>,
    pub continuation: SyncContinuation,
}

#[derive(Debug, Clone)]
pub enum WebhookEvent {
    AuthorizationRevoked {
        external_account_id: ExternalAccountId,
    },
    WorkoutChanged {
        external_account_id: ExternalAccountId,
        external_workout_id: i64,
        aspect: String,
        received_at_millis: i64,
    },
}

#[async_trait]
pub trait Repository: Send + Sync {
    async fn connection_for_external(
        &self,
        provider: ProviderId,
        external_account_id: &ExternalAccountId,
    ) -> Result<Option<StoredProviderConnection>, anyhow::Error>;
    async fn connection_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Option<StoredProviderConnection>, anyhow::Error>;
    async fn save_connection(
        &self,
        connection: &StoredProviderConnection,
    ) -> Result<(), anyhow::Error>;
    async fn replace_credentials(
        &self,
        connection: &StoredProviderConnection,
        expected_version: i64,
    ) -> Result<bool, anyhow::Error>;
    async fn delete_connection(&self, user_id: &UserId) -> Result<(), anyhow::Error>;
    async fn create_session(
        &self,
        raw_session: &str,
        user_id: &UserId,
        expires_at: i64,
    ) -> Result<(), anyhow::Error>;
    async fn user_for_session(
        &self,
        raw_session: &str,
        now_seconds: i64,
    ) -> Result<Option<UserId>, anyhow::Error>;
    async fn delete_session(&self, raw_session: &str) -> Result<(), anyhow::Error>;
    async fn put_event(
        &self,
        user_id: &UserId,
        event: &ProviderEvent,
        received_at_millis: i64,
    ) -> Result<(), anyhow::Error>;
    async fn events(
        &self,
        user_id: &UserId,
        after_millis: i64,
        through_millis: i64,
    ) -> Result<Vec<ProviderEvent>, anyhow::Error>;
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn authorization_url(&self, state: &str) -> String;
    fn scopes_sufficient(&self, scopes: &str) -> bool;
    async fn authorize(&self, code: &str) -> Result<AuthorizedProviderAccount, anyhow::Error>;
    async fn refresh(&self, refresh_token: &str) -> Result<ProviderCredentials, anyhow::Error>;
    async fn workouts(
        &self,
        access_token: &str,
        after: i64,
        before: i64,
        page: i64,
    ) -> Result<ProviderWorkoutPage, anyhow::Error>;
    async fn workout(
        &self,
        access_token: &str,
        external_workout_id: i64,
    ) -> Result<Option<Workout>, anyhow::Error>;
    async fn deauthorize(&self, access_token: &str) -> Result<(), anyhow::Error>;
}

#[derive(Debug, Error)]
#[error("provider rate limited; retry after {retry_after_seconds} seconds")]
pub struct ProviderRateLimited {
    pub retry_after_seconds: u64,
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("no authenticated user")]
    Unauthorized,
    #[error("invalid synchronization request")]
    InvalidSynchronization,
    #[error("provider operation failed: {0}")]
    Provider(#[source] anyhow::Error),
    #[error("provider rate limited; retry after {retry_after_seconds} seconds")]
    ProviderRateLimited { retry_after_seconds: u64 },
    #[error("persistence operation failed: {0}")]
    Persistence(#[source] anyhow::Error),
    #[error("domain operation failed: {0}")]
    Domain(#[from] crate::domain::DomainError),
}

#[derive(Clone)]
pub struct Application {
    repository: Arc<dyn Repository>,
    provider: Arc<dyn Provider>,
}

impl Application {
    pub fn new(repository: Arc<dyn Repository>, provider: Arc<dyn Provider>) -> Self {
        Self {
            repository,
            provider,
        }
    }

    pub fn authorization_url(&self, state: &str) -> String {
        self.provider.authorization_url(state)
    }

    pub fn scopes_sufficient(&self, scopes: &str) -> bool {
        self.provider.scopes_sufficient(scopes)
    }

    pub async fn connect(&self, code: &str, now_seconds: i64) -> Result<String, ApplicationError> {
        let authorized = self
            .provider
            .authorize(code)
            .await
            .map_err(provider_error)?;
        let existing = self
            .repository
            .connection_for_external(ProviderId::Strava, &authorized.external_account_id)
            .await
            .map_err(ApplicationError::Persistence)?;
        let (user_id, connection_id, token_version) = match existing {
            Some(existing) => (
                existing.user_id,
                existing.connection.id,
                existing.token_version + 1,
            ),
            None => (
                UserId::new(Uuid::new_v4().to_string())?,
                ConnectionId::new(Uuid::new_v4().to_string())?,
                1,
            ),
        };
        let connection = StoredProviderConnection {
            user_id: user_id.clone(),
            first_name: authorized.first_name,
            last_name: authorized.last_name,
            connection: ProviderConnection {
                id: connection_id,
                provider: ProviderId::Strava,
                external_account_id: authorized.external_account_id,
            },
            credentials: authorized.credentials,
            token_version,
        };
        self.repository
            .save_connection(&connection)
            .await
            .map_err(ApplicationError::Persistence)?;
        let session = new_session();
        self.repository
            .create_session(&session, &user_id, now_seconds + SESSION_SECONDS)
            .await
            .map_err(ApplicationError::Persistence)?;
        Ok(session)
    }

    pub async fn current_user(
        &self,
        raw_session: &str,
        now_seconds: i64,
    ) -> Result<Option<User>, ApplicationError> {
        let Some(user_id) = self.authenticate(raw_session, now_seconds).await? else {
            return Ok(None);
        };
        let connection = self.connection(&user_id).await?;
        Ok(Some(User::new(
            user_id,
            connection.first_name,
            connection.last_name,
            connection.connection,
        )?))
    }

    pub async fn synchronize(
        &self,
        raw_session: &str,
        request: SyncRequest,
        now_seconds: i64,
    ) -> Result<SyncBatch, ApplicationError> {
        if !(1..=MAX_SYNC_PAGES).contains(&request.page)
            || request.after_seconds < 0
            || request.event_cursor_millis < 0
            || request.snapshot_millis < 1
        {
            return Err(ApplicationError::InvalidSynchronization);
        }
        let user_id = self
            .authenticate(raw_session, now_seconds)
            .await?
            .ok_or(ApplicationError::Unauthorized)?;
        let connection = self.connection(&user_id).await?;
        let access_token = self.valid_access_token(connection, now_seconds).await?;
        let before = request.snapshot_millis / 1000 + 1;
        let page = self
            .provider
            .workouts(&access_token, request.after_seconds, before, request.page)
            .await
            .map_err(provider_error)?;
        let mut workouts = page.workouts;
        let has_more = page.has_more;
        if has_more && request.page == MAX_SYNC_PAGES {
            return Err(ApplicationError::InvalidSynchronization);
        }
        let events = if has_more {
            Vec::new()
        } else {
            self.repository
                .events(
                    &user_id,
                    request.event_cursor_millis,
                    request.snapshot_millis,
                )
                .await
                .map_err(ApplicationError::Persistence)?
        };
        let mut removed = HashSet::new();
        let present: HashSet<String> = workouts
            .iter()
            .map(|workout| workout.id.as_str().to_owned())
            .collect();
        for event in events {
            let workout_id = WorkoutId::new(format!("strava:{}", event.external_workout_id))?;
            if event.aspect == "delete" {
                removed.insert(workout_id);
            } else if !present.contains(workout_id.as_str()) {
                match self
                    .provider
                    .workout(&access_token, event.external_workout_id)
                    .await
                    .map_err(provider_error)?
                {
                    Some(workout) => workouts.push(workout),
                    None => {
                        removed.insert(workout_id);
                    }
                }
            }
        }
        workouts.retain(|workout| !removed.contains(&workout.id));
        workouts.sort_by(|left, right| right.performed_at.cmp(&left.performed_at));
        let continuation = if has_more {
            SyncContinuation::More(SyncRequest {
                page: request.page + 1,
                ..request
            })
        } else {
            SyncContinuation::Complete(SyncCheckpoint {
                after_seconds: request.snapshot_millis / 1000,
                event_cursor_millis: request.snapshot_millis,
            })
        };
        Ok(SyncBatch {
            upserted: workouts,
            removed: removed.into_iter().collect(),
            continuation,
        })
    }

    pub async fn disconnect(
        &self,
        raw_session: &str,
        now_seconds: i64,
    ) -> Result<(), ApplicationError> {
        let Some(user_id) = self.authenticate(raw_session, now_seconds).await? else {
            return Ok(());
        };
        let connection = self.connection(&user_id).await?;
        if let Ok(access) = self.valid_access_token(connection, now_seconds).await {
            let _ = self.provider.deauthorize(&access).await;
        }
        self.repository
            .delete_connection(&user_id)
            .await
            .map_err(ApplicationError::Persistence)?;
        self.repository
            .delete_session(raw_session)
            .await
            .map_err(ApplicationError::Persistence)
    }

    pub async fn record_webhook(&self, event: WebhookEvent) -> Result<(), ApplicationError> {
        match event {
            WebhookEvent::AuthorizationRevoked {
                external_account_id,
            } => {
                if let Some(connection) = self
                    .repository
                    .connection_for_external(ProviderId::Strava, &external_account_id)
                    .await
                    .map_err(ApplicationError::Persistence)?
                {
                    self.repository
                        .delete_connection(&connection.user_id)
                        .await
                        .map_err(ApplicationError::Persistence)?;
                }
            }
            WebhookEvent::WorkoutChanged {
                external_account_id,
                external_workout_id,
                aspect,
                received_at_millis,
            } => {
                if let Some(connection) = self
                    .repository
                    .connection_for_external(ProviderId::Strava, &external_account_id)
                    .await
                    .map_err(ApplicationError::Persistence)?
                {
                    self.repository
                        .put_event(
                            &connection.user_id,
                            &ProviderEvent {
                                external_workout_id,
                                aspect,
                            },
                            received_at_millis,
                        )
                        .await
                        .map_err(ApplicationError::Persistence)?;
                }
            }
        }
        Ok(())
    }

    async fn authenticate(
        &self,
        raw_session: &str,
        now_seconds: i64,
    ) -> Result<Option<UserId>, ApplicationError> {
        self.repository
            .user_for_session(raw_session, now_seconds)
            .await
            .map_err(ApplicationError::Persistence)
    }

    async fn connection(
        &self,
        user_id: &UserId,
    ) -> Result<StoredProviderConnection, ApplicationError> {
        self.repository
            .connection_for_user(user_id)
            .await
            .map_err(ApplicationError::Persistence)?
            .ok_or(ApplicationError::Unauthorized)
    }

    async fn valid_access_token(
        &self,
        mut connection: StoredProviderConnection,
        now_seconds: i64,
    ) -> Result<String, ApplicationError> {
        for _ in 0..2 {
            if connection.credentials.expires_at > now_seconds + 60 {
                return Ok(connection.credentials.access_token);
            }
            let refreshed = self
                .provider
                .refresh(&connection.credentials.refresh_token)
                .await
                .map_err(provider_error)?;
            let replacement = StoredProviderConnection {
                credentials: refreshed.clone(),
                token_version: connection.token_version + 1,
                ..connection.clone()
            };
            if self
                .repository
                .replace_credentials(&replacement, connection.token_version)
                .await
                .map_err(ApplicationError::Persistence)?
            {
                return Ok(refreshed.access_token);
            }
            connection = self.connection(&connection.user_id).await?;
        }
        Err(ApplicationError::Provider(anyhow::anyhow!(
            "concurrent token refresh did not settle"
        )))
    }
}

fn provider_error(error: anyhow::Error) -> ApplicationError {
    match error.downcast_ref::<ProviderRateLimited>() {
        Some(rate_limit) => ApplicationError::ProviderRateLimited {
            retry_after_seconds: rate_limit.retry_after_seconds,
        },
        None => ApplicationError::Provider(error),
    }
}

fn new_session() -> String {
    use base64::Engine as _;
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
