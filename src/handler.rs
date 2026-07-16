//! HTTP inbound adapter for Lambda/API Gateway.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{CONTENT_TYPE, COOKIE, LOCATION, RETRY_AFTER, SET_COOKIE};
use http::{Method, StatusCode};
use lambda_http::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::application::{
    Application, ApplicationError, SyncContinuation, SyncRequest, WebhookEvent,
};
use crate::config::Config;
use crate::cookie::{
    clear_session_cookie, mint_state, read_session_cookie, read_state_cookie, set_state_cookie,
};
use crate::domain::{ExternalAccountId, User, Workout};
use crate::{headers, redirect};

const APP_ORIGIN: &str = "https://lepre.run";
const DEFAULT_HISTORY_DAYS: i64 = 365;
const MAX_HISTORY_DAYS: i64 = 3_650;

pub struct Ctx {
    pub config: Config,
    pub application: Application,
}

pub async fn route(req: Request, ctx: Arc<Ctx>) -> Result<Response<Body>, lambda_http::Error> {
    let method = req.method().clone();
    let response = match (&method, req.uri().path()) {
        (&Method::OPTIONS, _) => empty(StatusCode::NO_CONTENT),
        (&Method::GET, "/v1/healthz") => json(StatusCode::OK, &serde_json::json!({"ok": true})),
        (&Method::GET, "/v1/auth/strava/start") => provider_start(&ctx),
        (&Method::GET, "/v1/auth/strava/callback") => provider_callback(&req, &ctx).await,
        (&Method::GET, "/v1/session") => session(&req, &ctx).await,
        (&Method::GET, "/v1/workouts") => workouts(&req, &ctx).await,
        (&Method::POST, "/v1/disconnect") => disconnect(&req, &ctx).await,
        (&Method::GET, "/v1/webhooks/strava") => verify_webhook(&req, &ctx.config),
        (&Method::POST, "/v1/webhooks/strava") => receive_webhook(&req, &ctx).await,
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
        .synchronize(&raw_session, request, now_seconds())
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

fn verify_webhook(req: &Request, config: &Config) -> Response<Body> {
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
    if query.mode != "subscribe" || query.verify_token != config.webhook_verify_token {
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

async fn receive_webhook(req: &Request, ctx: &Ctx) -> Response<Body> {
    let payload: WebhookPayload = match serde_json::from_slice(body_bytes(req)) {
        Ok(payload) => payload,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error":"invalid_payload"}),
            );
        }
    };
    let external_account_id = match ExternalAccountId::new(payload.owner_id.to_string()) {
        Ok(value) => value,
        Err(error) => return application_error(ApplicationError::Domain(error)),
    };
    let event = if payload.object_type == "athlete"
        && payload
            .updates
            .get("authorized")
            .and_then(|value| value.as_str())
            == Some("false")
    {
        WebhookEvent::AuthorizationRevoked {
            external_account_id,
        }
    } else if payload.object_type == "activity" {
        WebhookEvent::WorkoutChanged {
            external_account_id,
            external_workout_id: payload.object_id,
            aspect: payload.aspect_type,
            received_at_millis: now_millis(),
        }
    } else {
        return json(StatusCode::OK, &serde_json::json!({}));
    };
    match ctx.application.record_webhook(event).await {
        Ok(()) => json(StatusCode::OK, &serde_json::json!({})),
        Err(error) => application_error(error),
    }
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
    page: i64,
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
                page: token.page,
            })
        }
        (Some(value), None) => {
            let checkpoint: CheckpointToken = decode_token(&value)?;
            Ok(SyncRequest {
                after_seconds: checkpoint.after_seconds,
                event_cursor_millis: checkpoint.event_cursor_millis,
                snapshot_millis,
                page: 1,
            })
        }
        (None, None) => Ok(SyncRequest {
            after_seconds: (snapshot_millis / 1000)
                .saturating_sub(history_days * 24 * 60 * 60)
                .max(0),
            event_cursor_millis: 0,
            snapshot_millis,
            page: 1,
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
#[serde(rename_all = "camelCase")]
struct WorkoutResponse {
    id: String,
    performed_at: String,
    name: String,
    description: String,
    sport: &'static str,
    duration_seconds: i64,
    elapsed_duration_seconds: i64,
    distance_meters: f64,
    laps: Vec<LapResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LapResponse {
    index: i64,
    name: String,
    moving_duration_seconds: i64,
    elapsed_duration_seconds: i64,
    distance_meters: f64,
}

impl From<Workout> for WorkoutResponse {
    fn from(workout: Workout) -> Self {
        Self {
            id: workout.id.to_string(),
            performed_at: workout.performed_at,
            name: workout.name,
            description: workout.description,
            sport: workout.sport.as_str(),
            duration_seconds: workout.duration_seconds,
            elapsed_duration_seconds: workout.elapsed_duration_seconds,
            distance_meters: workout.distance_meters,
            laps: workout
                .laps
                .into_iter()
                .map(|lap| LapResponse {
                    index: lap.index,
                    name: lap.name,
                    moving_duration_seconds: lap.moving_duration_seconds,
                    elapsed_duration_seconds: lap.elapsed_duration_seconds,
                    distance_meters: lap.distance_meters,
                })
                .collect(),
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
    upserted: Vec<WorkoutResponse>,
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
                    page: request.page,
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
    use crate::application::SyncBatch;
    use crate::domain::{WorkoutData, WorkoutId};

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
                page: 1,
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
                    sport: crate::domain::RunSport::Run,
                    duration_seconds: 3600,
                    elapsed_duration_seconds: 3700,
                    distance_meters: 10_050.5,
                    laps: vec![crate::domain::Lap::new(1, "Lap 1", 3600, 3700, 10_050.5).unwrap()],
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
        assert_eq!(value["upserted"][0]["laps"][0]["index"], 1);
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
}
