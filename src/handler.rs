//! HTTP inbound adapter for Lambda/API Gateway.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{CONTENT_TYPE, COOKIE, LOCATION, RETRY_AFTER, SET_COOKIE};
use http::{Method, StatusCode};
use lambda_http::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::application::{
    Application, ApplicationError, SyncContinuation, SyncPhase, SyncRequest, WebhookEvent,
};
use crate::config::Config;
use crate::cookie::{
    clear_session_cookie, mint_state, read_session_cookie, read_state_cookie, set_state_cookie,
};
use crate::domain::{ExternalAccountId, User};
use crate::history::WorkoutPayload;
use crate::{headers, redirect};

const APP_ORIGIN: &str = "https://lepre.run";
const DEFAULT_HISTORY_DAYS: i64 = 365;
const MAX_HISTORY_DAYS: i64 = 3_650;

const STRAVA_WEBHOOK_PREFIX: &str = "/v1/webhooks/strava/";
const WEBHOOK_ASPECT_CREATE: &str = "create";
const WEBHOOK_ASPECT_UPDATE: &str = "update";
const WEBHOOK_ASPECT_DELETE: &str = "delete";
const WEBHOOK_RATE_WINDOW_MS: i64 = 60_000;

/// Process-local rolling window for authenticated webhook POSTs.
///
/// Caps DynamoDB/event work if the path secret leaks. Not shared across
/// Lambda instances; combine with API Gateway stage throttling in production.
pub struct WebhookRateLimit {
    window_start_ms: AtomicI64,
    count: AtomicU64,
    max_per_window: u64,
}

impl WebhookRateLimit {
    pub fn new(max_per_window: u64) -> Self {
        Self {
            window_start_ms: AtomicI64::new(0),
            count: AtomicU64::new(0),
            max_per_window,
        }
    }

    /// Returns `true` when the request is admitted.
    pub fn admit(&self, now_ms: i64) -> bool {
        let window_start = self.window_start_ms.load(Ordering::Relaxed);
        if now_ms - window_start >= WEBHOOK_RATE_WINDOW_MS {
            self.window_start_ms.store(now_ms, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            return true;
        }
        let prior = self.count.fetch_add(1, Ordering::Relaxed);
        prior < self.max_per_window
    }
}

pub struct Ctx {
    pub config: Config,
    pub application: Application,
    pub webhook_rate_limit: WebhookRateLimit,
}

pub async fn route(req: Request, ctx: Arc<Ctx>) -> Result<Response<Body>, lambda_http::Error> {
    let method = req.method().clone();
    let path = req.uri().path();
    let response = match (&method, path) {
        (&Method::OPTIONS, _) => empty(StatusCode::NO_CONTENT),
        (&Method::GET, "/v1/healthz") => json(StatusCode::OK, &serde_json::json!({"ok": true})),
        (&Method::GET, "/v1/auth/strava/start") => provider_start(&ctx),
        (&Method::GET, "/v1/auth/strava/callback") => provider_callback(&req, &ctx).await,
        (&Method::GET, "/v1/session") => session(&req, &ctx).await,
        (&Method::GET, "/v1/workouts") => workouts(&req, &ctx).await,
        (&Method::POST, "/v1/disconnect") => disconnect(&req, &ctx).await,
        (&Method::GET, path) if is_strava_webhook_path(path) => {
            verify_webhook(&req, &ctx.config, path)
        }
        (&Method::POST, path) if is_strava_webhook_path(path) => {
            receive_webhook(&req, &ctx, path).await
        }
        _ => json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error":"not_found","code":404}),
        ),
    };
    Ok(response)
}

fn provider_start(ctx: &Ctx) -> Response<Body> {
    if !ctx.config.strava_configured() {
        return redirect::to_connect_failed("strava_not_configured");
    }
    let state = mint_state();
    headers::apply(http::Response::builder())
        .status(StatusCode::FOUND)
        .header(LOCATION, ctx.application.authorization_url(&state))
        .header(SET_COOKIE, set_state_cookie(&state))
        .body(Body::Empty)
        .expect("valid provider authorization redirect")
}

async fn provider_callback(req: &Request, ctx: &Ctx) -> Response<Body> {
    if !ctx.config.strava_configured() {
        return redirect::to_connect_failed("strava_not_configured");
    }
    let query: CallbackQuery =
        serde_urlencoded::from_str(req.uri().query().unwrap_or("")).unwrap_or_default();
    if query.error.is_some() {
        return redirect::to_connect_failed("user_denied");
    }
    let cookie_state = req
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(read_state_cookie);
    let valid_state = match (&cookie_state, &query.state) {
        (Some(cookie), Some(query)) => bool::from(cookie.as_bytes().ct_eq(query.as_bytes())),
        _ => false,
    };
    if !valid_state {
        return redirect::to_connect_failed("state_invalid");
    }
    let Some(code) = query.code.as_deref() else {
        return redirect::to_connect_failed("missing_code");
    };
    let Some(scopes) = query.scope.as_deref() else {
        return redirect::to_connect_failed("scope_insufficient");
    };
    if !ctx.application.scopes_sufficient(scopes) {
        return redirect::to_connect_failed("scope_insufficient");
    }
    match ctx.application.connect(code, now_seconds()).await {
        Ok(session) => redirect::to_connected_with_session(&session),
        Err(error) => {
            tracing::error!(%error, "provider connection failed");
            let reason = match error {
                ApplicationError::Provider(_) => "strava_exchange_failed",
                ApplicationError::Persistence(_) => "db_failure",
                _ => "unknown",
            };
            redirect::to_connect_failed(reason)
        }
    }
}

async fn session(req: &Request, ctx: &Ctx) -> Response<Body> {
    let Some(raw_session) = session_cookie(req) else {
        return json(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"error":"unauthorized"}),
        );
    };
    match ctx
        .application
        .current_user(&raw_session, now_seconds())
        .await
    {
        Ok(Some(user)) => json(StatusCode::OK, &UserResponse::from(&user)),
        Ok(None) | Err(ApplicationError::Unauthorized) => json(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"error":"unauthorized"}),
        ),
        Err(error) => application_error(error),
    }
}

async fn workouts(req: &Request, ctx: &Ctx) -> Response<Body> {
    let Some(raw_session) = session_cookie(req) else {
        return json(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"error":"unauthorized"}),
        );
    };
    let request = match sync_request(req.uri().query().unwrap_or(""), now_millis()) {
        Ok(request) => request,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error":"invalid_synchronization"}),
            );
        }
    };
    match ctx
        .application
        .synchronize(&raw_session, request, now_millis())
        .await
    {
        Ok(batch) => json(StatusCode::OK, &SyncResponse::from(batch)),
        Err(error) => application_error(error),
    }
}

async fn disconnect(req: &Request, ctx: &Ctx) -> Response<Body> {
    let result = match session_cookie(req) {
        Some(session) => ctx.application.disconnect(&session, now_seconds()).await,
        None => Ok(()),
    };
    match result {
        Ok(()) | Err(ApplicationError::Unauthorized) => {
            clear_session(empty(StatusCode::NO_CONTENT))
        }
        Err(error) => application_error(error),
    }
}

#[derive(Deserialize)]
struct WebhookVerification {
    #[serde(rename = "hub.mode")]
    mode: String,
    #[serde(rename = "hub.verify_token")]
    verify_token: String,
    #[serde(rename = "hub.challenge")]
    challenge: String,
}

fn verify_webhook(req: &Request, config: &Config, path: &str) -> Response<Body> {
    if !webhook_path_authorized(path, &config.webhook_path_secret) {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error":"not_found","code":404}),
        );
    }
    let query: WebhookVerification =
        match serde_urlencoded::from_str(req.uri().query().unwrap_or("")) {
            Ok(query) => query,
            Err(_) => {
                return json(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({"error":"invalid_verification"}),
                );
            }
        };
    let token_ok = bool::from(
        query
            .verify_token
            .as_bytes()
            .ct_eq(config.webhook_verify_token.as_bytes()),
    );
    if query.mode != "subscribe" || !token_ok {
        return json(
            StatusCode::FORBIDDEN,
            &serde_json::json!({"error":"verification_failed"}),
        );
    }
    json(
        StatusCode::OK,
        &serde_json::json!({"hub.challenge":query.challenge}),
    )
}

#[derive(Deserialize)]
struct WebhookPayload {
    object_type: String,
    object_id: i64,
    aspect_type: String,
    owner_id: i64,
    #[serde(default)]
    updates: HashMap<String, serde_json::Value>,
}

async fn receive_webhook(req: &Request, ctx: &Ctx, path: &str) -> Response<Body> {
    if !webhook_path_authorized(path, &ctx.config.webhook_path_secret) {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error":"not_found","code":404}),
        );
    }
    let now = now_millis();
    if !ctx.webhook_rate_limit.admit(now) {
        tracing::warn!("webhook rate limit exceeded");
        let mut response = json(
            StatusCode::TOO_MANY_REQUESTS,
            &serde_json::json!({
                "error":"webhook_rate_limited",
                "retryAfterSeconds":60
            }),
        );
        response
            .headers_mut()
            .insert(RETRY_AFTER, "60".parse().expect("valid retry-after header"));
        return response;
    }
    let payload: WebhookPayload = match serde_json::from_slice(body_bytes(req)) {
        Ok(payload) => payload,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error":"invalid_payload"}),
            );
        }
    };
    let Some(event) = webhook_event_from_payload(payload, now) else {
        return json(StatusCode::OK, &serde_json::json!({}));
    };
    match ctx.application.record_webhook(event).await {
        Ok(()) => json(StatusCode::OK, &serde_json::json!({})),
        Err(error) => application_error(error),
    }
}

fn is_strava_webhook_path(path: &str) -> bool {
    path.starts_with(STRAVA_WEBHOOK_PREFIX)
}

fn webhook_path_secret(path: &str) -> Option<&str> {
    let secret = path.strip_prefix(STRAVA_WEBHOOK_PREFIX)?;
    if secret.is_empty() || secret.contains('/') {
        return None;
    }
    Some(secret)
}

fn webhook_path_authorized(path: &str, expected: &str) -> bool {
    match webhook_path_secret(path) {
        Some(provided) => bool::from(provided.as_bytes().ct_eq(expected.as_bytes())),
        None => false,
    }
}

fn known_activity_aspect(aspect: &str) -> bool {
    matches!(
        aspect,
        WEBHOOK_ASPECT_CREATE | WEBHOOK_ASPECT_UPDATE | WEBHOOK_ASPECT_DELETE
    )
}

fn webhook_event_from_payload(
    payload: WebhookPayload,
    received_at_millis: i64,
) -> Option<WebhookEvent> {
    let external_account_id = ExternalAccountId::new(payload.owner_id.to_string()).ok()?;
    if payload.object_type == "athlete"
        && payload
            .updates
            .get("authorized")
            .and_then(|value| value.as_str())
            == Some("false")
    {
        return Some(WebhookEvent::AuthorizationRevoked {
            external_account_id,
        });
    }
    if payload.object_type == "activity" && known_activity_aspect(&payload.aspect_type) {
        return Some(WebhookEvent::WorkoutChanged {
            external_account_id,
            external_workout_id: payload.object_id,
            aspect: payload.aspect_type,
            received_at_millis,
        });
    }
    None
}

#[derive(Default, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncQuery {
    checkpoint: Option<String>,
    continuation: Option<String>,
    history_days: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointToken {
    after_seconds: i64,
    event_cursor_millis: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinuationToken {
    after_seconds: i64,
    event_cursor_millis: i64,
    snapshot_millis: i64,
    phase: ContinuationPhase,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ContinuationPhase {
    Activities { page: i64 },
    Events { offset: usize },
}

impl From<ContinuationPhase> for SyncPhase {
    fn from(value: ContinuationPhase) -> Self {
        match value {
            ContinuationPhase::Activities { page } => Self::Activities { page },
            ContinuationPhase::Events { offset } => Self::Events { offset },
        }
    }
}

impl From<SyncPhase> for ContinuationPhase {
    fn from(value: SyncPhase) -> Self {
        match value {
            SyncPhase::Activities { page } => Self::Activities { page },
            SyncPhase::Events { offset } => Self::Events { offset },
        }
    }
}

fn sync_request(query: &str, snapshot_millis: i64) -> Result<SyncRequest, anyhow::Error> {
    let query: SyncQuery = serde_urlencoded::from_str(query)?;
    let history_days = query.history_days.unwrap_or(DEFAULT_HISTORY_DAYS);
    if !(1..=MAX_HISTORY_DAYS).contains(&history_days) {
        anyhow::bail!("invalid history window");
    }
    match (query.checkpoint, query.continuation) {
        (Some(_), Some(_)) => anyhow::bail!("checkpoint and continuation are mutually exclusive"),
        (_, Some(value)) => {
            let token: ContinuationToken = decode_token(&value)?;
            Ok(SyncRequest {
                after_seconds: token.after_seconds,
                event_cursor_millis: token.event_cursor_millis,
                snapshot_millis: token.snapshot_millis,
                phase: token.phase.into(),
            })
        }
        (Some(value), None) => {
            let checkpoint: CheckpointToken = decode_token(&value)?;
            Ok(SyncRequest {
                after_seconds: checkpoint.after_seconds,
                event_cursor_millis: checkpoint.event_cursor_millis,
                snapshot_millis,
                phase: SyncPhase::Activities { page: 1 },
            })
        }
        (None, None) => Ok(SyncRequest {
            after_seconds: (snapshot_millis / 1000)
                .saturating_sub(history_days * 24 * 60 * 60)
                .max(0),
            event_cursor_millis: 0,
            snapshot_millis,
            phase: SyncPhase::Activities { page: 1 },
        }),
    }
}

fn encode_token(value: &impl Serialize) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serializable sync token"))
}

fn decode_token<Value: for<'de> Deserialize<'de>>(value: &str) -> Result<Value, anyhow::Error> {
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value)?)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionResponse<'a> {
    id: &'a str,
    provider: &'static str,
    external_account_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserResponse<'a> {
    id: &'a str,
    first_name: &'a str,
    last_name: &'a str,
    connection: ConnectionResponse<'a>,
}

impl<'a> From<&'a User> for UserResponse<'a> {
    fn from(user: &'a User) -> Self {
        Self {
            id: user.id.as_str(),
            first_name: &user.first_name,
            last_name: &user.last_name,
            connection: ConnectionResponse {
                id: user.connection.id.as_str(),
                provider: user.connection.provider.as_str(),
                external_account_id: user.connection.external_account_id.as_str(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum ContinuationResponse {
    More { token: String },
    Complete { checkpoint: String },
}

#[derive(Serialize)]
struct SyncResponse {
    upserted: Vec<WorkoutPayload>,
    removed: Vec<String>,
    continuation: ContinuationResponse,
}

impl From<crate::application::SyncBatch> for SyncResponse {
    fn from(batch: crate::application::SyncBatch) -> Self {
        let continuation = match batch.continuation {
            SyncContinuation::More(request) => ContinuationResponse::More {
                token: encode_token(&ContinuationToken {
                    after_seconds: request.after_seconds,
                    event_cursor_millis: request.event_cursor_millis,
                    snapshot_millis: request.snapshot_millis,
                    phase: request.phase.into(),
                }),
            },
            SyncContinuation::Complete(checkpoint) => ContinuationResponse::Complete {
                checkpoint: encode_token(&CheckpointToken {
                    after_seconds: checkpoint.after_seconds,
                    event_cursor_millis: checkpoint.event_cursor_millis,
                }),
            },
        };
        Self {
            upserted: batch.upserted.into_iter().map(Into::into).collect(),
            removed: batch.removed.into_iter().map(|id| id.to_string()).collect(),
            continuation,
        }
    }
}

fn session_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(read_session_cookie)
}

fn body_bytes(req: &Request) -> &[u8] {
    match req.body() {
        Body::Empty => &[],
        Body::Text(text) => text.as_bytes(),
        Body::Binary(bytes) => bytes,
    }
}

fn now_seconds() -> i64 {
    now_millis() / 1000
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as i64
}

fn json(status: StatusCode, value: &impl Serialize) -> Response<Body> {
    let body = serde_json::to_string(value).expect("serializable response");
    cors(headers::apply(http::Response::builder()))
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::Text(body))
        .expect("valid JSON response")
}

fn empty(status: StatusCode) -> Response<Body> {
    cors(headers::apply(http::Response::builder()))
        .status(status)
        .body(Body::Empty)
        .expect("valid empty response")
}

fn cors(builder: http::response::Builder) -> http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", APP_ORIGIN)
        .header("Access-Control-Allow-Credentials", "true")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        .header("Access-Control-Expose-Headers", "Retry-After")
        .header("Vary", "Origin")
}

fn application_error(error: ApplicationError) -> Response<Body> {
    match error {
        ApplicationError::Unauthorized => json(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"error":"unauthorized"}),
        ),
        ApplicationError::InvalidSynchronization => json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error":"invalid_synchronization"}),
        ),
        ApplicationError::Provider(error) => {
            tracing::error!(%error, "provider operation failed");
            json(
                StatusCode::BAD_GATEWAY,
                &serde_json::json!({"error":"provider_unavailable"}),
            )
        }
        ApplicationError::ProviderRateLimited {
            retry_after_seconds,
        } => {
            tracing::warn!(retry_after_seconds, "provider rate limited");
            let mut response = json(
                StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({
                    "error":"provider_rate_limited",
                    "retryAfterSeconds":retry_after_seconds
                }),
            );
            response.headers_mut().insert(
                RETRY_AFTER,
                retry_after_seconds
                    .to_string()
                    .parse()
                    .expect("valid retry-after header"),
            );
            response
        }
        ApplicationError::SynchronizationQueued {
            retry_after_seconds,
        } => {
            tracing::info!(
                event = "strava_sync_queued",
                retry_after_seconds,
                "synchronization is waiting for a fair Strava turn"
            );
            let mut response = json(
                StatusCode::ACCEPTED,
                &serde_json::json!({
                    "status":"queued",
                    "retryAfterSeconds":retry_after_seconds
                }),
            );
            response.headers_mut().insert(
                RETRY_AFTER,
                retry_after_seconds
                    .to_string()
                    .parse()
                    .expect("valid retry-after header"),
            );
            response
        }
        error => {
            tracing::error!(%error, "application operation failed");
            json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error":"internal_error"}),
            )
        }
    }
}

fn clear_session(mut response: Response<Body>) -> Response<Body> {
    response.headers_mut().append(
        SET_COOKIE,
        clear_session_cookie().parse().expect("valid cookie"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::application::{
        HistoryRepository, ImportState, PendingImport, Provider, ProviderCredentials,
        ProviderEvent, ProviderHistoryPage, ProviderWorkoutPage, Repository,
        StoredProviderConnection, SyncBatch, SyncGateConfig, SyncTurn,
    };
    use crate::domain::{
        ConnectionId, ProviderConnection, ProviderId, UserId, Workout, WorkoutData, WorkoutId,
    };

    #[test]
    fn synchronization_tokens_roundtrip_without_nullable_fields() {
        let checkpoint = CheckpointToken {
            after_seconds: 123,
            event_cursor_millis: 456,
        };
        let encoded = encode_token(&checkpoint);
        let decoded: CheckpointToken = decode_token(&encoded).unwrap();
        assert_eq!(decoded.after_seconds, 123);
        assert_eq!(decoded.event_cursor_millis, 456);
    }

    #[test]
    fn initial_synchronization_has_explicit_defaults() {
        assert_eq!(
            sync_request("", 40_000_000_000).unwrap(),
            SyncRequest {
                after_seconds: 8_464_000,
                event_cursor_millis: 0,
                snapshot_millis: 40_000_000_000,
                phase: SyncPhase::Activities { page: 1 },
            }
        );
    }

    #[test]
    fn workout_contract_contains_seconds_and_meters() {
        let response = SyncResponse::from(SyncBatch {
            upserted: vec![
                Workout::new(WorkoutData {
                    id: WorkoutId::new("strava:7").unwrap(),
                    performed_at: "2026-07-15T06:00:00Z".to_owned(),
                    name: "Morning Run".to_owned(),
                    description: "Track session".to_owned(),
                    workout_type: crate::domain::WorkoutType::Workout,
                    sport: crate::domain::RunSport::Run,
                    duration_seconds: 3600,
                    elapsed_duration_seconds: 3700,
                    distance_meters: 10_050.5,
                    average_heart_rate_bpm: Some(148.2),
                    max_heart_rate_bpm: Some(176.0),
                    laps: vec![
                        crate::domain::Lap::new(
                            1,
                            "Lap 1",
                            3600,
                            3700,
                            10_050.5,
                            Some(148.2),
                            Some(176.0),
                        )
                        .unwrap(),
                    ],
                })
                .unwrap(),
            ],
            removed: Vec::new(),
            continuation: SyncContinuation::Complete(crate::application::SyncCheckpoint {
                after_seconds: 123,
                event_cursor_millis: 456,
            }),
        });
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["upserted"][0]["id"], "strava:7");
        assert_eq!(value["upserted"][0]["durationSeconds"], 3600);
        assert_eq!(value["upserted"][0]["distanceMeters"], 10_050.5);
        assert_eq!(value["upserted"][0]["description"], "Track session");
        assert_eq!(value["upserted"][0]["type"], "workout");
        assert_eq!(value["upserted"][0]["averageHeartRateBpm"], 148.2);
        assert_eq!(value["upserted"][0]["maxHeartRateBpm"], 176.0);
        assert_eq!(value["upserted"][0]["laps"][0]["index"], 1);
        assert_eq!(
            value["upserted"][0]["laps"][0]["averageHeartRateBpm"],
            148.2
        );
        assert_eq!(value["continuation"]["kind"], "complete");
        assert!(value["continuation"]["checkpoint"].is_string());
    }

    #[test]
    fn provider_rate_limit_is_an_explicit_retryable_response() {
        let response = application_error(ApplicationError::ProviderRateLimited {
            retry_after_seconds: 120,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "120");
        let Body::Text(body) = response.body() else {
            panic!("expected JSON body");
        };
        assert!(body.contains("provider_rate_limited"));
        assert!(body.contains("retryAfterSeconds"));
    }

    #[test]
    fn fair_queue_wait_is_an_explicit_retryable_response() {
        let response = application_error(ApplicationError::SynchronizationQueued {
            retry_after_seconds: 5,
        });
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[RETRY_AFTER], "5");
        let Body::Text(body) = response.body() else {
            panic!("expected JSON body");
        };
        assert!(body.contains("queued"));
        assert!(body.contains("retryAfterSeconds"));
    }

    #[test]
    fn webhook_path_secret_requires_single_segment() {
        assert_eq!(webhook_path_secret("/v1/webhooks/strava/abc"), Some("abc"));
        assert_eq!(webhook_path_secret("/v1/webhooks/strava/"), None);
        assert_eq!(webhook_path_secret("/v1/webhooks/strava"), None);
        assert_eq!(webhook_path_secret("/v1/webhooks/strava/a/b"), None);
        assert!(webhook_path_authorized(
            "/v1/webhooks/strava/expected",
            "expected"
        ));
        assert!(!webhook_path_authorized(
            "/v1/webhooks/strava/wrong",
            "expected"
        ));
    }

    #[test]
    fn unknown_activity_aspects_are_dropped() {
        let payload = WebhookPayload {
            object_type: "activity".into(),
            object_id: 9,
            aspect_type: "comment".into(),
            owner_id: 42,
            updates: HashMap::new(),
        };
        assert!(webhook_event_from_payload(payload, 1).is_none());
    }

    #[test]
    fn known_activity_aspects_are_accepted() {
        for aspect in ["create", "update", "delete"] {
            let payload = WebhookPayload {
                object_type: "activity".into(),
                object_id: 9,
                aspect_type: aspect.into(),
                owner_id: 42,
                updates: HashMap::new(),
            };
            let event = webhook_event_from_payload(payload, 7).unwrap();
            match event {
                WebhookEvent::WorkoutChanged {
                    external_workout_id,
                    aspect: got,
                    received_at_millis,
                    ..
                } => {
                    assert_eq!(external_workout_id, 9);
                    assert_eq!(got, aspect);
                    assert_eq!(received_at_millis, 7);
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn reject_unauth_revoke_without_path_secret() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 120);
        let body = serde_json::json!({
            "object_type": "athlete",
            "object_id": 42,
            "aspect_type": "update",
            "owner_id": 42,
            "updates": {"authorized": "false"}
        });
        let req = http::Request::builder()
            .method(Method::POST)
            .uri("/v1/webhooks/strava")
            .body(Body::Text(body.to_string()))
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(repo.deleted.lock().unwrap().is_empty());
        assert!(repo.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reject_unauth_revoke_with_wrong_path_secret() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 120);
        let body = serde_json::json!({
            "object_type": "athlete",
            "object_id": 42,
            "aspect_type": "update",
            "owner_id": 42,
            "updates": {"authorized": "false"}
        });
        let req = http::Request::builder()
            .method(Method::POST)
            .uri("/v1/webhooks/strava/wrong-secret")
            .body(Body::Text(body.to_string()))
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(repo.deleted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn allow_valid_path_revoke() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 120);
        let body = serde_json::json!({
            "object_type": "athlete",
            "object_id": 42,
            "aspect_type": "update",
            "owner_id": 42,
            "updates": {"authorized": "false"}
        });
        let req = http::Request::builder()
            .method(Method::POST)
            .uri("/v1/webhooks/strava/path-secret")
            .body(Body::Text(body.to_string()))
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(repo.deleted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn allow_valid_path_activity_event() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 120);
        let body = serde_json::json!({
            "object_type": "activity",
            "object_id": 99,
            "aspect_type": "create",
            "owner_id": 42,
            "updates": {}
        });
        let req = http::Request::builder()
            .method(Method::POST)
            .uri("/v1/webhooks/strava/path-secret")
            .body(Body::Text(body.to_string()))
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(repo.events.lock().unwrap().len(), 1);
        assert_eq!(repo.events.lock().unwrap()[0].external_workout_id, 99);
        assert_eq!(repo.events.lock().unwrap()[0].aspect, "create");
    }

    #[tokio::test]
    async fn unauthenticated_event_flood_for_arbitrary_owner_is_blocked() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 120);
        let body = serde_json::json!({
            "object_type": "activity",
            "object_id": 1,
            "aspect_type": "create",
            "owner_id": 42,
            "updates": {}
        });
        for _ in 0..5 {
            let req = http::Request::builder()
                .method(Method::POST)
                .uri("/v1/webhooks/strava/attacker")
                .body(Body::Text(body.to_string()))
                .unwrap();
            let response = route(req, Arc::clone(&ctx)).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        assert!(repo.events.lock().unwrap().is_empty());
        assert_eq!(*repo.lookups.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn authenticated_event_flood_is_rate_limited() {
        let repo = Arc::new(MockRepository::with_connection(sample_connection()));
        let ctx = test_ctx(Arc::clone(&repo), 2);
        let body = serde_json::json!({
            "object_type": "activity",
            "object_id": 1,
            "aspect_type": "create",
            "owner_id": 42,
            "updates": {}
        });
        for expected in [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let req = http::Request::builder()
                .method(Method::POST)
                .uri("/v1/webhooks/strava/path-secret")
                .body(Body::Text(body.to_string()))
                .unwrap();
            let response = route(req, Arc::clone(&ctx)).await.unwrap();
            assert_eq!(response.status(), expected);
        }
        assert_eq!(repo.events.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn verify_challenge_works_with_secret_path_and_token() {
        let repo = Arc::new(MockRepository::default());
        let ctx = test_ctx(repo, 120);
        let req = http::Request::builder()
            .method(Method::GET)
            .uri(
                "/v1/webhooks/strava/path-secret?hub.mode=subscribe&hub.verify_token=verify&hub.challenge=abc123",
            )
            .body(Body::Empty)
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let Body::Text(body) = response.body() else {
            panic!("expected JSON body");
        };
        assert!(body.contains("abc123"));
    }

    #[tokio::test]
    async fn verify_challenge_rejects_wrong_path_secret() {
        let repo = Arc::new(MockRepository::default());
        let ctx = test_ctx(repo, 120);
        let req = http::Request::builder()
            .method(Method::GET)
            .uri(
                "/v1/webhooks/strava/wrong?hub.mode=subscribe&hub.verify_token=verify&hub.challenge=abc123",
            )
            .body(Body::Empty)
            .unwrap();
        let response = route(req, ctx).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn test_ctx(repo: Arc<MockRepository>, rate_limit: u64) -> Arc<Ctx> {
        let config = Config {
            strava_client_id: "clid".into(),
            strava_client_secret: "csec".into(),
            webhook_verify_token: "verify".into(),
            webhook_path_secret: "path-secret".into(),
            table_name: "lepre".into(),
            token_encryption_key: [7u8; 32],
            key_version: 1,
            sync_gate: SyncGateConfig {
                read_limit_15_minutes: 100,
                read_limit_daily: 1_000,
                safety_percent: 90,
                queue_lease_seconds: 30,
                poll_seconds: 2,
            },
            webhook_rate_limit_per_minute: rate_limit,
        };
        let application = Application::new(
            repo,
            Arc::new(MockHistory::default()),
            Arc::new(MockProvider),
            config.sync_gate.clone(),
        );
        Arc::new(Ctx {
            config,
            application,
            webhook_rate_limit: WebhookRateLimit::new(rate_limit),
        })
    }

    fn sample_connection() -> StoredProviderConnection {
        StoredProviderConnection {
            user_id: UserId::new("user-1").unwrap(),
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            connection: ProviderConnection {
                id: ConnectionId::new("conn-1").unwrap(),
                provider: ProviderId::Strava,
                external_account_id: ExternalAccountId::new("42").unwrap(),
            },
            credentials: ProviderCredentials {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
                expires_at: 9_999_999_999,
            },
            token_version: 1,
        }
    }

    #[derive(Default)]
    struct MockRepository {
        connection: Mutex<Option<StoredProviderConnection>>,
        deleted: Mutex<Vec<UserId>>,
        events: Mutex<Vec<ProviderEvent>>,
        lookups: Mutex<u64>,
    }

    impl MockRepository {
        fn with_connection(connection: StoredProviderConnection) -> Self {
            Self {
                connection: Mutex::new(Some(connection)),
                deleted: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                lookups: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl Repository for MockRepository {
        async fn connection_for_external(
            &self,
            _provider: ProviderId,
            external_account_id: &ExternalAccountId,
        ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
            *self.lookups.lock().unwrap() += 1;
            Ok(self
                .connection
                .lock()
                .unwrap()
                .as_ref()
                .filter(|connection| {
                    connection.connection.external_account_id == *external_account_id
                })
                .cloned())
        }

        async fn connection_for_user(
            &self,
            user_id: &UserId,
        ) -> Result<Option<StoredProviderConnection>, anyhow::Error> {
            Ok(self
                .connection
                .lock()
                .unwrap()
                .as_ref()
                .filter(|connection| connection.user_id == *user_id)
                .cloned())
        }

        async fn save_connection(
            &self,
            connection: &StoredProviderConnection,
        ) -> Result<(), anyhow::Error> {
            *self.connection.lock().unwrap() = Some(connection.clone());
            Ok(())
        }

        async fn replace_credentials(
            &self,
            connection: &StoredProviderConnection,
            _expected_version: i64,
        ) -> Result<bool, anyhow::Error> {
            *self.connection.lock().unwrap() = Some(connection.clone());
            Ok(true)
        }

        async fn delete_connection(&self, user_id: &UserId) -> Result<(), anyhow::Error> {
            self.deleted.lock().unwrap().push(user_id.clone());
            *self.connection.lock().unwrap() = None;
            Ok(())
        }

        async fn create_session(
            &self,
            _raw_session: &str,
            _user_id: &UserId,
            _expires_at: i64,
        ) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn user_for_session(
            &self,
            _raw_session: &str,
            _now_seconds: i64,
        ) -> Result<Option<UserId>, anyhow::Error> {
            Ok(None)
        }

        async fn delete_session(&self, _raw_session: &str) -> Result<(), anyhow::Error> {
            Ok(())
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
            _after_millis: i64,
            _through_millis: i64,
        ) -> Result<Vec<ProviderEvent>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn acquire_sync_turn(
            &self,
            _user_id: &UserId,
            _now_millis: i64,
            _config: &SyncGateConfig,
        ) -> Result<SyncTurn, anyhow::Error> {
            Ok(SyncTurn::Granted)
        }
    }

    struct MockProvider;

    #[async_trait]
    impl Provider for MockProvider {
        fn authorization_url(&self, _state: &str) -> String {
            "https://example.test/oauth".into()
        }

        fn scopes_sufficient(&self, _scopes: &str) -> bool {
            true
        }

        async fn authorize(
            &self,
            _code: &str,
        ) -> Result<crate::application::AuthorizedProviderAccount, anyhow::Error> {
            unimplemented!("authorize unused in webhook tests")
        }

        async fn refresh(
            &self,
            _refresh_token: &str,
        ) -> Result<ProviderCredentials, anyhow::Error> {
            unimplemented!("refresh unused in webhook tests")
        }

        async fn workouts(
            &self,
            _access_token: &str,
            _after: i64,
            _before: i64,
            _page: i64,
        ) -> Result<ProviderWorkoutPage, anyhow::Error> {
            unimplemented!("workouts unused in webhook tests")
        }

        async fn workout(
            &self,
            _access_token: &str,
            _external_workout_id: i64,
        ) -> Result<Option<Workout>, anyhow::Error> {
            unimplemented!("workout unused in webhook tests")
        }

        async fn history_page(
            &self,
            _access_token: &str,
            _before_seconds: i64,
        ) -> Result<ProviderHistoryPage, anyhow::Error> {
            unimplemented!("history_page unused in webhook tests")
        }

        async fn deauthorize(&self, _access_token: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockHistory {
        pending: Mutex<Vec<UserId>>,
    }

    #[async_trait]
    impl HistoryRepository for MockHistory {
        async fn mark_pending(
            &self,
            user_id: &UserId,
            _now_millis: i64,
        ) -> Result<(), anyhow::Error> {
            self.pending.lock().unwrap().push(user_id.clone());
            Ok(())
        }

        async fn pending_imports(&self) -> Result<Vec<PendingImport>, anyhow::Error> {
            unimplemented!("pending_imports unused in webhook tests")
        }

        async fn record_turn(
            &self,
            _user_id: &UserId,
            _now_millis: i64,
            _retry_at_millis: i64,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("record_turn unused in webhook tests")
        }

        async fn clear_pending(&self, _pending: &PendingImport) -> Result<(), anyhow::Error> {
            unimplemented!("clear_pending unused in webhook tests")
        }

        async fn import_state(
            &self,
            _user_id: &UserId,
        ) -> Result<Option<ImportState>, anyhow::Error> {
            unimplemented!("import_state unused in webhook tests")
        }

        async fn save_import_state(
            &self,
            _user_id: &UserId,
            _state: &ImportState,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("save_import_state unused in webhook tests")
        }

        async fn apply_workout_changes(
            &self,
            _user_id: &UserId,
            _upserts: Vec<Workout>,
            _removals: Vec<WorkoutId>,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("apply_workout_changes unused in webhook tests")
        }
    }
}
