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
const MAX_SYNC_EVENT_BATCH: usize = 10;
/// Wait after a failed import turn so one broken account cannot spend the
/// shared Strava budget every minute.
const FAILED_TURN_BACKOFF_MILLIS: i64 = 15 * 60 * 1_000;
pub const SYNC_BATCH_REQUEST_COST: i64 = 21;

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

/// One page of history, newest first, listed strictly before a cursor.
#[derive(Debug)]
pub struct ProviderHistoryPage {
    pub workouts: Vec<Workout>,
    /// Start time of the oldest listed activity of any sport; `None` when the
    /// page is empty and the history walk is done.
    pub oldest_start_seconds: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ProviderEvent {
    pub external_workout_id: i64,
    pub aspect: String,
    pub received_at_millis: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportStatus {
    InProgress,
    Complete,
}

/// Progress of one user's Strava → DynamoDB import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportState {
    pub status: ImportStatus,
    /// The next history page lists activities that started before this time.
    pub before_seconds: i64,
    /// Webhook events received at or after this time are not processed yet.
    pub event_cursor_millis: i64,
    pub imported_count: i64,
    pub started_at_millis: i64,
}

impl ImportState {
    fn started(now_millis: i64) -> Self {
        Self {
            status: ImportStatus::InProgress,
            before_seconds: now_millis / 1_000,
            event_cursor_millis: now_millis,
            imported_count: 0,
            started_at_millis: now_millis,
        }
    }
}

/// A user with import work outstanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingImport {
    pub user_id: UserId,
    /// Last time something added work; clearing is conditional on it.
    pub touched_at_millis: i64,
    pub last_turn_millis: i64,
    /// No turn is taken for this user before this time.
    pub retry_at_millis: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportTickReport {
    pub turns: usize,
    pub completed: usize,
    pub failed: usize,
    pub stopped_by_quota: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    pub after_seconds: i64,
    pub event_cursor_millis: i64,
    pub snapshot_millis: i64,
    pub phase: SyncPhase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    Activities { page: i64 },
    Events { offset: usize },
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
pub struct SyncGateConfig {
    pub read_limit_15_minutes: i64,
    pub read_limit_daily: i64,
    pub safety_percent: i64,
    pub queue_lease_seconds: i64,
    pub poll_seconds: u64,
}

impl SyncGateConfig {
    pub fn safe_limit_15_minutes(&self) -> i64 {
        self.read_limit_15_minutes * self.safety_percent / 100
    }

    pub fn safe_limit_daily(&self) -> i64 {
        self.read_limit_daily * self.safety_percent / 100
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncTurn {
    Granted,
    Queued { retry_after_seconds: u64 },
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
    async fn acquire_sync_turn(
        &self,
        user_id: &UserId,
        now_millis: i64,
        config: &SyncGateConfig,
    ) -> Result<SyncTurn, anyhow::Error>;
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
    async fn history_page(
        &self,
        access_token: &str,
        before_seconds: i64,
    ) -> Result<ProviderHistoryPage, anyhow::Error>;
    async fn deauthorize(&self, access_token: &str) -> Result<(), anyhow::Error>;
}

/// Durable per-user workout history and its import bookkeeping.
#[async_trait]
pub trait HistoryRepository: Send + Sync {
    async fn mark_pending(&self, user_id: &UserId, now_millis: i64) -> Result<(), anyhow::Error>;
    async fn pending_imports(&self) -> Result<Vec<PendingImport>, anyhow::Error>;
    async fn record_turn(
        &self,
        user_id: &UserId,
        now_millis: i64,
        retry_at_millis: i64,
    ) -> Result<(), anyhow::Error>;
    /// Remove the entry unless it was touched after `pending` was read.
    async fn clear_pending(&self, pending: &PendingImport) -> Result<(), anyhow::Error>;
    async fn import_state(&self, user_id: &UserId) -> Result<Option<ImportState>, anyhow::Error>;
    async fn save_import_state(
        &self,
        user_id: &UserId,
        state: &ImportState,
    ) -> Result<(), anyhow::Error>;
    async fn apply_workout_changes(
        &self,
        user_id: &UserId,
        upserts: Vec<Workout>,
        removals: Vec<WorkoutId>,
    ) -> Result<(), anyhow::Error>;
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
    #[error("synchronization queued; retry after {retry_after_seconds} seconds")]
    SynchronizationQueued { retry_after_seconds: u64 },
    #[error("persistence operation failed: {0}")]
    Persistence(#[source] anyhow::Error),
    #[error("domain operation failed: {0}")]
    Domain(#[from] crate::domain::DomainError),
}

#[derive(Clone)]
pub struct Application {
    repository: Arc<dyn Repository>,
    history: Arc<dyn HistoryRepository>,
    provider: Arc<dyn Provider>,
    sync_gate: SyncGateConfig,
}

enum TurnOutcome {
    Finished,
    MoreWork,
    Disconnected,
}

impl Application {
    pub fn new(
        repository: Arc<dyn Repository>,
        history: Arc<dyn HistoryRepository>,
        provider: Arc<dyn Provider>,
        sync_gate: SyncGateConfig,
    ) -> Self {
        Self {
            repository,
            history,
            provider,
            sync_gate,
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
        now_millis: i64,
    ) -> Result<SyncBatch, ApplicationError> {
        let valid_phase = match &request.phase {
            SyncPhase::Activities { page } => (1..=MAX_SYNC_PAGES).contains(page),
            SyncPhase::Events { offset } => *offset <= MAX_SYNC_PAGES as usize * 1_000,
        };
        if !valid_phase
            || request.after_seconds < 0
            || request.event_cursor_millis < 0
            || request.snapshot_millis < 1
        {
            return Err(ApplicationError::InvalidSynchronization);
        }
        let now_seconds = now_millis / 1_000;
        let user_id = self
            .authenticate(raw_session, now_seconds)
            .await?
            .ok_or(ApplicationError::Unauthorized)?;
        match self
            .repository
            .acquire_sync_turn(&user_id, now_millis, &self.sync_gate)
            .await
            .map_err(ApplicationError::Persistence)?
        {
            SyncTurn::Granted => {}
            SyncTurn::Queued {
                retry_after_seconds,
            } => {
                return Err(ApplicationError::SynchronizationQueued {
                    retry_after_seconds,
                });
            }
        }
        let connection = self.connection(&user_id).await?;
        let access_token = self.valid_access_token(connection, now_seconds).await?;
        let before = request.snapshot_millis / 1000 + 1;
        let (mut workouts, event_offset) = match request.phase.clone() {
            SyncPhase::Activities { page } => {
                let provider_page = self
                    .provider
                    .workouts(&access_token, request.after_seconds, before, page)
                    .await
                    .map_err(provider_error)?;
                if provider_page.has_more && page == MAX_SYNC_PAGES {
                    return Err(ApplicationError::InvalidSynchronization);
                }
                if provider_page.has_more {
                    return Ok(SyncBatch {
                        upserted: provider_page.workouts,
                        removed: Vec::new(),
                        continuation: SyncContinuation::More(SyncRequest {
                            phase: SyncPhase::Activities { page: page + 1 },
                            ..request
                        }),
                    });
                }
                (provider_page.workouts, 0)
            }
            SyncPhase::Events { offset } => (Vec::new(), offset),
        };
        let events = coalesce_events(
            self.repository
                .events(
                    &user_id,
                    request.event_cursor_millis,
                    request.snapshot_millis,
                )
                .await
                .map_err(ApplicationError::Persistence)?,
        );
        let mut removed = HashSet::new();
        let present: HashSet<String> = workouts
            .iter()
            .map(|workout| workout.id.as_str().to_owned())
            .collect();
        let event_batch = events.iter().skip(event_offset).take(MAX_SYNC_EVENT_BATCH);
        for event in event_batch {
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
        let next_event_offset = event_offset.saturating_add(MAX_SYNC_EVENT_BATCH);
        let continuation = if next_event_offset < events.len() {
            SyncContinuation::More(SyncRequest {
                phase: SyncPhase::Events {
                    offset: next_event_offset,
                },
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
                                received_at_millis,
                            },
                            received_at_millis,
                        )
                        .await
                        .map_err(ApplicationError::Persistence)?;
                    self.history
                        .mark_pending(&connection.user_id, received_at_millis)
                        .await
                        .map_err(ApplicationError::Persistence)?;
                }
            }
        }
        Ok(())
    }

    /// Run up to `max_turns` import turns across pending users.
    ///
    /// Users take turns round-robin, least recently served first. Every turn
    /// goes through the shared Strava quota gate; the tick stops as soon as
    /// the gate or Strava asks to wait.
    pub async fn import_tick(
        &self,
        now_millis: i64,
        max_turns: usize,
    ) -> Result<ImportTickReport, ApplicationError> {
        let mut pending = self
            .history
            .pending_imports()
            .await
            .map_err(ApplicationError::Persistence)?;
        pending.retain(|entry| entry.retry_at_millis <= now_millis);
        pending.sort_by_key(|entry| (entry.last_turn_millis, entry.touched_at_millis));
        let mut report = ImportTickReport::default();
        while !pending.is_empty() {
            let mut next_round = Vec::new();
            for entry in pending {
                if report.turns >= max_turns {
                    return Ok(report);
                }
                let turn = self
                    .repository
                    .acquire_sync_turn(&entry.user_id, now_millis, &self.sync_gate)
                    .await
                    .map_err(ApplicationError::Persistence)?;
                if let SyncTurn::Queued { .. } = turn {
                    report.stopped_by_quota = true;
                    return Ok(report);
                }
                report.turns += 1;
                match self.import_turn(&entry.user_id, now_millis).await {
                    Ok(TurnOutcome::Finished) => {
                        report.completed += 1;
                        self.history
                            .clear_pending(&entry)
                            .await
                            .map_err(ApplicationError::Persistence)?;
                    }
                    Ok(TurnOutcome::Disconnected) => self
                        .history
                        .clear_pending(&entry)
                        .await
                        .map_err(ApplicationError::Persistence)?,
                    Ok(TurnOutcome::MoreWork) => {
                        self.history
                            .record_turn(&entry.user_id, now_millis, now_millis)
                            .await
                            .map_err(ApplicationError::Persistence)?;
                        next_round.push(entry);
                    }
                    Err(ApplicationError::ProviderRateLimited { .. }) => {
                        report.stopped_by_quota = true;
                        return Ok(report);
                    }
                    Err(error) => {
                        tracing::warn!(
                            event = "history_import_turn_failed",
                            error = %error,
                            "history import turn failed; retrying on a later tick"
                        );
                        report.failed += 1;
                        self.history
                            .record_turn(
                                &entry.user_id,
                                now_millis,
                                now_millis + FAILED_TURN_BACKOFF_MILLIS,
                            )
                            .await
                            .map_err(ApplicationError::Persistence)?;
                    }
                }
            }
            pending = next_round;
        }
        Ok(report)
    }

    /// One quota turn for one user: pending webhook events first, then the
    /// next page of history.
    async fn import_turn(
        &self,
        user_id: &UserId,
        now_millis: i64,
    ) -> Result<TurnOutcome, ApplicationError> {
        let Some(connection) = self
            .repository
            .connection_for_user(user_id)
            .await
            .map_err(ApplicationError::Persistence)?
        else {
            return Ok(TurnOutcome::Disconnected);
        };
        let access_token = self
            .valid_access_token(connection, now_millis / 1_000)
            .await?;
        let mut state = self
            .history
            .import_state(user_id)
            .await
            .map_err(ApplicationError::Persistence)?
            .unwrap_or_else(|| ImportState::started(now_millis));

        let events = self
            .repository
            .events(user_id, state.event_cursor_millis, now_millis)
            .await
            .map_err(ApplicationError::Persistence)?;
        let (batch, more_events) = event_batch(events, MAX_SYNC_EVENT_BATCH);
        if let Some(last) = batch.last() {
            state.event_cursor_millis = last.received_at_millis + 1;
        }
        let mut upserts = Vec::new();
        let mut removals = Vec::new();
        for event in coalesce_events(batch) {
            let workout_id = WorkoutId::new(format!("strava:{}", event.external_workout_id))?;
            if event.aspect == "delete" {
                removals.push(workout_id);
                continue;
            }
            match self
                .provider
                .workout(&access_token, event.external_workout_id)
                .await
                .map_err(provider_error)?
            {
                Some(workout) => upserts.push(workout),
                None => removals.push(workout_id),
            }
        }
        self.history
            .apply_workout_changes(user_id, upserts, removals)
            .await
            .map_err(ApplicationError::Persistence)?;

        if state.status == ImportStatus::InProgress {
            let page = self
                .provider
                .history_page(&access_token, state.before_seconds)
                .await
                .map_err(provider_error)?;
            match page.oldest_start_seconds {
                Some(oldest) if oldest < state.before_seconds => {
                    state.imported_count += page.workouts.len() as i64;
                    self.history
                        .apply_workout_changes(user_id, page.workouts, Vec::new())
                        .await
                        .map_err(ApplicationError::Persistence)?;
                    state.before_seconds = oldest;
                }
                Some(_) => {
                    tracing::warn!(
                        event = "history_import_cursor_stalled",
                        "history page did not move the cursor back; ending the import"
                    );
                    state.status = ImportStatus::Complete;
                }
                None => state.status = ImportStatus::Complete,
            }
        }
        self.history
            .save_import_state(user_id, &state)
            .await
            .map_err(ApplicationError::Persistence)?;
        Ok(if state.status == ImportStatus::Complete && !more_events {
            TurnOutcome::Finished
        } else {
            TurnOutcome::MoreWork
        })
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

fn coalesce_events(events: Vec<ProviderEvent>) -> Vec<ProviderEvent> {
    let mut coalesced: Vec<ProviderEvent> = Vec::new();
    for event in events {
        if let Some(existing) = coalesced
            .iter_mut()
            .find(|existing| existing.external_workout_id == event.external_workout_id)
        {
            *existing = event;
        } else {
            coalesced.push(event);
        }
    }
    coalesced
}

/// Take the oldest events, whole milliseconds at a time, until the batch
/// would touch more than `max_workouts` distinct workouts. Always takes at
/// least the first millisecond so the cursor makes progress. Returns the batch
/// and whether events remain.
fn event_batch(events: Vec<ProviderEvent>, max_workouts: usize) -> (Vec<ProviderEvent>, bool) {
    let mut events = events;
    events.sort_by_key(|event| event.received_at_millis);
    let mut workouts = HashSet::new();
    let mut taken = 0;
    while taken < events.len() {
        let millis = events[taken].received_at_millis;
        let group_end = events[taken..]
            .iter()
            .position(|event| event.received_at_millis != millis)
            .map_or(events.len(), |offset| taken + offset);
        let mut grown = workouts.clone();
        grown.extend(
            events[taken..group_end]
                .iter()
                .map(|event| event.external_workout_id),
        );
        if taken > 0 && grown.len() > max_workouts {
            break;
        }
        workouts = grown;
        taken = group_end;
    }
    let more = taken < events.len();
    events.truncate(taken);
    (events, more)
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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{RunSport, WorkoutData, WorkoutType};
    use crate::history::{
        MonthState, StoredWorkoutState, WorkoutRecord, affected_months, plan_changes,
    };

    const NOW_MILLIS: i64 = 1_800_000_000_000;

    fn user(id: &str) -> UserId {
        UserId::new(id).unwrap()
    }

    fn workout(id: i64, performed_at: &str) -> Workout {
        Workout::new(WorkoutData {
            id: WorkoutId::new(format!("strava:{id}")).unwrap(),
            performed_at: performed_at.to_owned(),
            name: format!("Run {id}"),
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

    fn connection(user_id: &str, athlete: &str) -> StoredProviderConnection {
        StoredProviderConnection {
            user_id: user(user_id),
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            connection: ProviderConnection {
                id: ConnectionId::new(format!("conn-{user_id}")).unwrap(),
                provider: ProviderId::Strava,
                external_account_id: ExternalAccountId::new(athlete).unwrap(),
            },
            credentials: ProviderCredentials {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
                expires_at: i64::MAX,
            },
            token_version: 1,
        }
    }

    fn event(id: i64, aspect: &str, received_at_millis: i64) -> ProviderEvent {
        ProviderEvent {
            external_workout_id: id,
            aspect: aspect.to_owned(),
            received_at_millis,
        }
    }

    fn sync_gate() -> SyncGateConfig {
        SyncGateConfig {
            read_limit_15_minutes: 100,
            read_limit_daily: 1_000,
            safety_percent: 90,
            queue_lease_seconds: 30,
            poll_seconds: 2,
        }
    }

    struct FakeRepository {
        connections: Vec<StoredProviderConnection>,
        events: Mutex<Vec<ProviderEvent>>,
        grants_left: Mutex<usize>,
        turn_requests: Mutex<Vec<UserId>>,
    }

    impl FakeRepository {
        fn new(connections: Vec<StoredProviderConnection>, grants: usize) -> Self {
            Self {
                connections,
                events: Mutex::new(Vec::new()),
                grants_left: Mutex::new(grants),
                turn_requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Repository for FakeRepository {
        async fn connection_for_external(
            &self,
            _provider: ProviderId,
            external_account_id: &ExternalAccountId,
        ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
            Ok(self
                .connections
                .iter()
                .find(|stored| stored.connection.external_account_id == *external_account_id)
                .cloned())
        }

        async fn connection_for_user(
            &self,
            user_id: &UserId,
        ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
            Ok(self
                .connections
                .iter()
                .find(|stored| stored.user_id == *user_id)
                .cloned())
        }

        async fn save_connection(
            &self,
            _connection: &StoredProviderConnection,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("save_connection unused in import tests")
        }

        async fn replace_credentials(
            &self,
            _connection: &StoredProviderConnection,
            _expected_version: i64,
        ) -> Result<bool, anyhow::Error> {
            unimplemented!("replace_credentials unused in import tests")
        }

        async fn delete_connection(&self, _user_id: &UserId) -> Result<(), anyhow::Error> {
            unimplemented!("delete_connection unused in import tests")
        }

        async fn create_session(
            &self,
            _raw_session: &str,
            _user_id: &UserId,
            _expires_at: i64,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("create_session unused in import tests")
        }

        async fn user_for_session(
            &self,
            _raw_session: &str,
            _now_seconds: i64,
        ) -> Result<Option<UserId>, anyhow::Error> {
            unimplemented!("user_for_session unused in import tests")
        }

        async fn delete_session(&self, _raw_session: &str) -> Result<(), anyhow::Error> {
            unimplemented!("delete_session unused in import tests")
        }

        async fn put_event(
            &self,
            _user_id: &UserId,
            event: &ProviderEvent,
            _received_at_millis: i64,
        ) -> Result<(), anyhow::Error> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }

        async fn events(
            &self,
            _user_id: &UserId,
            after_millis: i64,
            through_millis: i64,
        ) -> Result<Vec<ProviderEvent>, anyhow::Error> {
            Ok(self
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| (after_millis..=through_millis).contains(&event.received_at_millis))
                .cloned()
                .collect())
        }

        async fn acquire_sync_turn(
            &self,
            user_id: &UserId,
            _now_millis: i64,
            _config: &SyncGateConfig,
        ) -> Result<SyncTurn, anyhow::Error> {
            self.turn_requests.lock().unwrap().push(user_id.clone());
            let mut grants_left = self.grants_left.lock().unwrap();
            if *grants_left == 0 {
                return Ok(SyncTurn::Queued {
                    retry_after_seconds: 60,
                });
            }
            *grants_left -= 1;
            Ok(SyncTurn::Granted)
        }
    }

    #[derive(Default)]
    struct FakeHistory {
        pending: Mutex<HashMap<String, PendingImport>>,
        states: Mutex<HashMap<String, ImportState>>,
        workouts: Mutex<HashMap<String, StoredWorkoutState>>,
        months: Mutex<HashMap<String, MonthState>>,
        next_version: Mutex<u64>,
    }

    impl FakeHistory {
        fn with_pending(entries: &[(&str, i64)]) -> Self {
            let history = Self::default();
            for (user_id, last_turn_millis) in entries {
                history.pending.lock().unwrap().insert(
                    (*user_id).to_owned(),
                    PendingImport {
                        user_id: user(user_id),
                        touched_at_millis: 1,
                        last_turn_millis: *last_turn_millis,
                        retry_at_millis: 0,
                    },
                );
            }
            history
        }

        fn stored_ids(&self) -> Vec<String> {
            let mut ids: Vec<_> = self.workouts.lock().unwrap().keys().cloned().collect();
            ids.sort();
            ids
        }

        fn state(&self, user_id: &str) -> Option<ImportState> {
            self.states.lock().unwrap().get(user_id).cloned()
        }

        fn is_pending(&self, user_id: &str) -> bool {
            self.pending.lock().unwrap().contains_key(user_id)
        }
    }

    #[async_trait]
    impl HistoryRepository for FakeHistory {
        async fn mark_pending(
            &self,
            user_id: &UserId,
            now_millis: i64,
        ) -> Result<(), anyhow::Error> {
            let mut pending = self.pending.lock().unwrap();
            let (last_turn_millis, retry_at_millis) =
                pending.get(user_id.as_str()).map_or((0, 0), |entry| {
                    (entry.last_turn_millis, entry.retry_at_millis)
                });
            pending.insert(
                user_id.to_string(),
                PendingImport {
                    user_id: user_id.clone(),
                    touched_at_millis: now_millis,
                    last_turn_millis,
                    retry_at_millis,
                },
            );
            Ok(())
        }

        async fn pending_imports(&self) -> Result<Vec<PendingImport>, anyhow::Error> {
            Ok(self.pending.lock().unwrap().values().cloned().collect())
        }

        async fn record_turn(
            &self,
            user_id: &UserId,
            now_millis: i64,
            retry_at_millis: i64,
        ) -> Result<(), anyhow::Error> {
            if let Some(entry) = self.pending.lock().unwrap().get_mut(user_id.as_str()) {
                entry.last_turn_millis = now_millis;
                entry.retry_at_millis = retry_at_millis;
            }
            Ok(())
        }

        async fn clear_pending(&self, seen: &PendingImport) -> Result<(), anyhow::Error> {
            let mut pending = self.pending.lock().unwrap();
            if pending
                .get(seen.user_id.as_str())
                .is_some_and(|entry| entry.touched_at_millis == seen.touched_at_millis)
            {
                pending.remove(seen.user_id.as_str());
            }
            Ok(())
        }

        async fn import_state(
            &self,
            user_id: &UserId,
        ) -> Result<Option<ImportState>, anyhow::Error> {
            Ok(self.states.lock().unwrap().get(user_id.as_str()).cloned())
        }

        async fn save_import_state(
            &self,
            user_id: &UserId,
            state: &ImportState,
        ) -> Result<(), anyhow::Error> {
            self.states
                .lock()
                .unwrap()
                .insert(user_id.to_string(), state.clone());
            Ok(())
        }

        async fn apply_workout_changes(
            &self,
            _user_id: &UserId,
            upserts: Vec<Workout>,
            removals: Vec<WorkoutId>,
        ) -> Result<(), anyhow::Error> {
            let records: Vec<_> = upserts.into_iter().filter_map(WorkoutRecord::new).collect();
            let removals: Vec<_> = removals.iter().map(ToString::to_string).collect();
            let mut workouts = self.workouts.lock().unwrap();
            let mut months = self.months.lock().unwrap();
            let existing: HashMap<_, _> = records
                .iter()
                .map(|record| &record.id)
                .chain(&removals)
                .filter_map(|id| workouts.get(id).map(|state| (id.clone(), state.clone())))
                .collect();
            let wanted = affected_months(&existing, &records);
            let current: HashMap<_, _> = months
                .iter()
                .filter(|(name, _)| wanted.contains(*name))
                .map(|(name, state)| (name.clone(), state.clone()))
                .collect();
            let changes = plan_changes(&existing, &current, records, &removals, || {
                let mut next = self.next_version.lock().unwrap();
                *next += 1;
                format!("v{next}")
            });
            for write in changes.workout_writes {
                workouts.insert(
                    write.record.id.clone(),
                    StoredWorkoutState {
                        month: write.record.month,
                        sync_version: write.sync_version,
                        fingerprint: write.record.fingerprint,
                    },
                );
            }
            for id in changes.workout_deletes {
                workouts.remove(&id);
            }
            for write in changes.month_writes {
                if write.members.is_empty() {
                    months.remove(&write.month);
                } else {
                    months.insert(
                        write.month,
                        MonthState {
                            members: write.members,
                            rev: write.expected_rev.unwrap_or(0) + 1,
                        },
                    );
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeProvider {
        pages: Mutex<VecDeque<Result<ProviderHistoryPage, anyhow::Error>>>,
        details: HashMap<i64, Workout>,
        page_cursors: Mutex<Vec<i64>>,
        detail_requests: Mutex<Vec<i64>>,
    }

    impl FakeProvider {
        fn with_pages(pages: Vec<ProviderHistoryPage>) -> Self {
            Self {
                pages: Mutex::new(pages.into_iter().map(Ok).collect()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl Provider for FakeProvider {
        fn authorization_url(&self, _state: &str) -> String {
            unimplemented!("authorization_url unused in import tests")
        }

        fn scopes_sufficient(&self, _scopes: &str) -> bool {
            unimplemented!("scopes_sufficient unused in import tests")
        }

        async fn authorize(&self, _code: &str) -> Result<AuthorizedProviderAccount, anyhow::Error> {
            unimplemented!("authorize unused in import tests")
        }

        async fn refresh(
            &self,
            _refresh_token: &str,
        ) -> Result<ProviderCredentials, anyhow::Error> {
            unimplemented!("refresh unused in import tests")
        }

        async fn workouts(
            &self,
            _access_token: &str,
            _after: i64,
            _before: i64,
            _page: i64,
        ) -> Result<ProviderWorkoutPage, anyhow::Error> {
            unimplemented!("workouts unused in import tests")
        }

        async fn workout(
            &self,
            _access_token: &str,
            external_workout_id: i64,
        ) -> Result<Option<Workout>, anyhow::Error> {
            self.detail_requests
                .lock()
                .unwrap()
                .push(external_workout_id);
            Ok(self.details.get(&external_workout_id).cloned())
        }

        async fn history_page(
            &self,
            _access_token: &str,
            before_seconds: i64,
        ) -> Result<ProviderHistoryPage, anyhow::Error> {
            self.page_cursors.lock().unwrap().push(before_seconds);
            self.pages.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(ProviderHistoryPage {
                    workouts: Vec::new(),
                    oldest_start_seconds: None,
                })
            })
        }

        async fn deauthorize(&self, _access_token: &str) -> Result<(), anyhow::Error> {
            unimplemented!("deauthorize unused in import tests")
        }
    }

    fn application(
        repository: &Arc<FakeRepository>,
        history: &Arc<FakeHistory>,
        provider: &Arc<FakeProvider>,
    ) -> Application {
        Application::new(
            repository.clone(),
            history.clone(),
            provider.clone(),
            sync_gate(),
        )
    }

    #[tokio::test]
    async fn import_walks_history_backwards_until_strava_runs_out() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 10));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 0)]));
        let provider = Arc::new(FakeProvider::with_pages(vec![
            ProviderHistoryPage {
                workouts: vec![
                    workout(3, "2026-10-02T06:00:00Z"),
                    workout(2, "2026-09-20T06:00:00Z"),
                ],
                oldest_start_seconds: Some(1_789_000_000),
            },
            ProviderHistoryPage {
                workouts: vec![workout(1, "2025-01-05T06:00:00Z")],
                oldest_start_seconds: Some(1_736_000_000),
            },
        ]));

        let report = application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 10)
            .await
            .unwrap();

        assert_eq!(
            *provider.page_cursors.lock().unwrap(),
            [NOW_MILLIS / 1_000, 1_789_000_000, 1_736_000_000]
        );
        assert_eq!(history.stored_ids(), ["strava:1", "strava:2", "strava:3"]);
        let state = history.state("u1").unwrap();
        assert_eq!(state.status, ImportStatus::Complete);
        assert_eq!(state.imported_count, 3);
        assert!(!history.is_pending("u1"));
        assert_eq!(report.turns, 3);
        assert_eq!(report.completed, 1);
    }

    #[tokio::test]
    async fn webhook_events_update_stored_history() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 10));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 0)]));
        history
            .apply_workout_changes(
                &user("u1"),
                vec![
                    workout(1, "2026-10-01T06:00:00Z"),
                    workout(6, "2026-10-03T06:00:00Z"),
                ],
                Vec::new(),
            )
            .await
            .unwrap();
        history.states.lock().unwrap().insert(
            "u1".into(),
            ImportState {
                status: ImportStatus::Complete,
                before_seconds: 0,
                event_cursor_millis: 1_000,
                imported_count: 2,
                started_at_millis: 1_000,
            },
        );
        repository.events.lock().unwrap().extend([
            event(1, "delete", 999),
            event(5, "create", 2_000),
            event(6, "update", 2_001),
            event(1, "delete", 2_002),
        ]);
        let provider = Arc::new(FakeProvider {
            details: HashMap::from([(5, workout(5, "2026-10-05T06:00:00Z"))]),
            ..FakeProvider::default()
        });

        application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 10)
            .await
            .unwrap();

        assert_eq!(history.stored_ids(), ["strava:5"]);
        assert_eq!(*provider.detail_requests.lock().unwrap(), [5, 6]);
        assert!(provider.page_cursors.lock().unwrap().is_empty());
        assert_eq!(history.state("u1").unwrap().event_cursor_millis, 2_003);
        assert!(!history.is_pending("u1"));
    }

    #[test]
    fn event_batches_never_split_a_millisecond() {
        let events = vec![
            event(1, "create", 10),
            event(2, "create", 10),
            event(3, "create", 11),
            event(4, "create", 11),
            event(5, "create", 12),
        ];
        let (batch, more) = event_batch(events.clone(), 3);
        let ids: Vec<_> = batch
            .iter()
            .map(|event| event.external_workout_id)
            .collect();
        assert_eq!(ids, [1, 2]);
        assert!(more);

        let crowded: Vec<_> = (1..=5).map(|id| event(id, "create", 7)).collect();
        let (batch, more) = event_batch(crowded, 3);
        assert_eq!(batch.len(), 5);
        assert!(!more);
    }

    #[tokio::test]
    async fn quota_gate_stops_the_tick_before_calling_strava() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 0));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 0)]));
        let provider = Arc::new(FakeProvider::default());

        let report = application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 10)
            .await
            .unwrap();

        assert!(report.stopped_by_quota);
        assert_eq!(report.turns, 0);
        assert!(provider.page_cursors.lock().unwrap().is_empty());
        assert!(history.is_pending("u1"));
    }

    #[tokio::test]
    async fn strava_rate_limit_stops_the_tick_and_keeps_the_user_pending() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 10));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 0)]));
        let provider = Arc::new(FakeProvider {
            pages: Mutex::new(VecDeque::from([Err(ProviderRateLimited {
                retry_after_seconds: 60,
            }
            .into())])),
            ..FakeProvider::default()
        });

        let report = application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 10)
            .await
            .unwrap();

        assert!(report.stopped_by_quota);
        assert_eq!(report.turns, 1);
        assert!(history.state("u1").is_none());
        assert!(history.is_pending("u1"));
    }

    #[tokio::test]
    async fn failing_user_backs_off_instead_of_spending_quota_every_tick() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 10));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 0)]));
        let provider = Arc::new(FakeProvider {
            pages: Mutex::new(VecDeque::from([Err(anyhow::anyhow!(
                "Strava returned 500"
            ))])),
            ..FakeProvider::default()
        });
        let application = application(&repository, &history, &provider);

        let report = application.import_tick(NOW_MILLIS, 10).await.unwrap();
        assert_eq!(report.failed, 1);
        assert!(history.is_pending("u1"));

        let report = application
            .import_tick(NOW_MILLIS + 60_000, 10)
            .await
            .unwrap();
        assert_eq!(report.turns, 0);
        assert_eq!(repository.turn_requests.lock().unwrap().len(), 1);

        let report = application
            .import_tick(NOW_MILLIS + FAILED_TURN_BACKOFF_MILLIS, 10)
            .await
            .unwrap();
        assert_eq!(report.turns, 1);
    }

    #[tokio::test]
    async fn least_recently_served_user_goes_first() {
        let repository = Arc::new(FakeRepository::new(
            vec![connection("u1", "41"), connection("u2", "42")],
            10,
        ));
        let history = Arc::new(FakeHistory::with_pending(&[("u1", 500), ("u2", 100)]));
        let provider = Arc::new(FakeProvider::default());

        let report = application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 1)
            .await
            .unwrap();

        assert_eq!(report.turns, 1);
        assert_eq!(*repository.turn_requests.lock().unwrap(), [user("u2")]);
    }

    #[tokio::test]
    async fn disconnected_user_leaves_the_pending_list() {
        let repository = Arc::new(FakeRepository::new(Vec::new(), 10));
        let history = Arc::new(FakeHistory::with_pending(&[("gone", 0)]));
        let provider = Arc::new(FakeProvider::default());

        application(&repository, &history, &provider)
            .import_tick(NOW_MILLIS, 10)
            .await
            .unwrap();

        assert!(!history.is_pending("gone"));
        assert!(provider.page_cursors.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_marks_the_user_pending() {
        let repository = Arc::new(FakeRepository::new(vec![connection("u1", "42")], 10));
        let history = Arc::new(FakeHistory::default());
        let provider = Arc::new(FakeProvider::default());

        application(&repository, &history, &provider)
            .record_webhook(WebhookEvent::WorkoutChanged {
                external_account_id: ExternalAccountId::new("42").unwrap(),
                external_workout_id: 7,
                aspect: "create".into(),
                received_at_millis: 5_000,
            })
            .await
            .unwrap();

        assert!(history.is_pending("u1"));
        assert_eq!(
            history.pending.lock().unwrap()["u1"].touched_at_millis,
            5_000
        );
    }
}
