//! Lambda routes for OAuth, authenticated workout sync and Strava webhooks.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use http::{Method, StatusCode};
use lambda_http::{Body, Request, Response};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::cookie::{
    clear_session_cookie, mint_state, read_session_cookie, read_state_cookie, set_state_cookie,
};
use crate::crypto::{TokenKind, decrypt, encrypt};
use crate::db::{Connection, Store};
use crate::{headers, redirect, strava};

const AUTHORIZE_URL: &str = "https://www.strava.com/oauth/authorize";
const REDIRECT_URI: &str = "https://api.lepre.run/v1/auth/strava/callback";
const REQUIRED_SCOPES: &[&str] = &["read", "activity:read_all"];
const SESSION_SECONDS: i64 = 30 * 24 * 60 * 60;
const APP_ORIGIN: &str = "https://lepre.run";

pub struct Ctx {
    pub config: Config,
    pub store: Store,
    pub http_client: reqwest::Client,
}

pub async fn route(req: Request, ctx: Arc<Ctx>) -> Result<Response<Body>, lambda_http::Error> {
    let method = req.method().clone();
    let path = req.uri().path();
    let response = match (&method, path) {
        (&Method::OPTIONS, _) => empty(StatusCode::NO_CONTENT),
        (&Method::GET, "/v1/healthz") => json(StatusCode::OK, &serde_json::json!({"ok": true})),
        (&Method::GET, "/v1/auth/strava/start") => strava_start(&ctx.config),
        (&Method::GET, "/v1/auth/strava/callback") => strava_callback(&req, &ctx).await,
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

fn strava_start(config: &Config) -> Response<Body> {
    if !config.strava_configured() {
        return redirect::to_connect_failed("strava_not_configured");
    }
    let state = mint_state();
    let query = serde_urlencoded::to_string(AuthorizeParams {
        client_id: &config.strava_client_id,
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: &REQUIRED_SCOPES.join(","),
        state: &state,
    })
    .expect("static authorization parameters");
    headers::apply(http::Response::builder())
        .status(StatusCode::FOUND)
        .header(LOCATION, format!("{AUTHORIZE_URL}?{query}"))
        .header(SET_COOKIE, set_state_cookie(&state))
        .body(Body::Empty)
        .expect("valid redirect")
}

async fn strava_callback(req: &Request, ctx: &Ctx) -> Response<Body> {
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
        .and_then(|v| v.to_str().ok())
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

    let token = match strava::exchange_code(
        &ctx.http_client,
        strava::token_url(),
        &ctx.config.strava_client_id,
        &ctx.config.strava_client_secret,
        code,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "Strava token exchange failed");
            return redirect::to_connect_failed("strava_exchange_failed");
        }
    };
    if !scope_sufficient(query.scope.as_deref()) {
        let _ = strava::deauthorize(
            &ctx.http_client,
            strava::deauthorize_url(),
            &token.access_token,
        )
        .await;
        return redirect::to_connect_failed("scope_insufficient");
    }

    let connection = match encrypted_connection(
        &ctx.config,
        token.athlete.id,
        &token.access_token,
        &token.refresh_token,
        token.expires_at,
        1,
    ) {
        Ok(connection) => connection,
        Err(error) => {
            tracing::error!(%error, "token encryption failed");
            return redirect::to_connect_failed("unknown");
        }
    };
    let session = new_session();
    if let Err(error) = ctx.store.put_connection(&connection).await {
        tracing::error!(%error, "connection persistence failed");
        return redirect::to_connect_failed("db_failure");
    }
    if let Err(error) = ctx
        .store
        .create_session(&session, token.athlete.id, now_seconds() + SESSION_SECONDS)
        .await
    {
        tracing::error!(%error, "session persistence failed");
        return redirect::to_connect_failed("db_failure");
    }
    redirect::to_connected_with_session(&session)
}

async fn session(req: &Request, ctx: &Ctx) -> Response<Body> {
    match authenticate(req, ctx).await {
        Ok(Some(athlete_id)) => json(
            StatusCode::OK,
            &serde_json::json!({"authenticated":true,"athleteId":athlete_id}),
        ),
        Ok(None) => json(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"authenticated":false}),
        ),
        Err(error) => internal(error),
    }
}

#[derive(Default, Deserialize)]
struct SyncQuery {
    after: Option<i64>,
    cursor: Option<i64>,
    snapshot: Option<i64>,
    page: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    workouts: Vec<strava::Workout>,
    deleted_ids: Vec<i64>,
    synced_at: i64,
    cursor: i64,
    snapshot: i64,
    next_page: Option<i64>,
}

async fn workouts(req: &Request, ctx: &Ctx) -> Response<Body> {
    let athlete_id = match authenticate(req, ctx).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return json(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({"error":"unauthorized"}),
            );
        }
        Err(error) => return internal(error),
    };
    let query: SyncQuery =
        serde_urlencoded::from_str(req.uri().query().unwrap_or("")).unwrap_or_default();
    let Some(page) = query.page else {
        return json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error":"paged_sync_required"}),
        );
    };
    if !(1..=30).contains(&page) {
        return json(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error":"invalid_sync_page"}),
        );
    }
    let after = query.after.unwrap_or(0).max(0);
    let event_cursor = query.cursor.unwrap_or(0).max(0);
    let snapshot_ms = query.snapshot.unwrap_or_else(now_millis).max(1);
    // Strava's `before` parameter is in seconds. Adding one keeps activities
    // created during the snapshot second inside this stable import window.
    let before = snapshot_ms / 1000 + 1;
    let access_token = match valid_access_token(ctx, athlete_id).await {
        Ok(token) => token,
        Err(error) => return internal(error),
    };
    let mut workouts = match strava::activities_page(
        &ctx.http_client,
        strava::activities_url(),
        &access_token,
        after,
        before,
        page,
    )
    .await
    {
        Ok(workouts) => workouts,
        Err(error) => return upstream(error),
    };
    let has_more = workouts.len() == 200;
    if has_more && page == 30 {
        return upstream(anyhow::anyhow!("activity import exceeded 6000 activities"));
    }
    let events = if has_more {
        Vec::new()
    } else {
        match ctx
            .store
            .webhook_events(athlete_id, event_cursor, snapshot_ms)
            .await
        {
            Ok(events) => events,
            Err(error) => return internal(error),
        }
    };
    let mut deleted = HashSet::new();
    let present: HashSet<i64> = workouts.iter().map(|workout| workout.id).collect();
    for event in events {
        if event.aspect_type == "delete" {
            deleted.insert(event.object_id);
        } else if !present.contains(&event.object_id) {
            match strava::activity(
                &ctx.http_client,
                strava::activity_url(),
                &access_token,
                event.object_id,
            )
            .await
            {
                Ok(Some(workout)) => workouts.push(workout),
                Ok(None) => {
                    deleted.insert(event.object_id);
                }
                Err(error) => {
                    tracing::warn!(%error, activity_id = event.object_id, "could not fetch webhook activity")
                }
            }
        }
    }
    workouts.retain(|workout| !deleted.contains(&workout.id));
    workouts.sort_by(|a, b| b.date.cmp(&a.date));
    json(
        StatusCode::OK,
        &SyncResponse {
            workouts,
            deleted_ids: deleted.into_iter().collect(),
            synced_at: snapshot_ms / 1000,
            cursor: snapshot_ms,
            snapshot: snapshot_ms,
            next_page: has_more.then_some(page + 1),
        },
    )
}

async fn disconnect(req: &Request, ctx: &Ctx) -> Response<Body> {
    let raw_session = session_cookie(req);
    let athlete_id = match authenticate(req, ctx).await {
        Ok(Some(id)) => id,
        Ok(None) => return clear_session(json(StatusCode::NO_CONTENT, &serde_json::json!({}))),
        Err(error) => return internal(error),
    };
    if let Ok(access) = valid_access_token(ctx, athlete_id).await
        && let Err(error) =
            strava::deauthorize(&ctx.http_client, strava::deauthorize_url(), &access).await
    {
        tracing::warn!(%error, "Strava deauthorization failed");
    }
    if let Err(error) = ctx.store.delete_connection(athlete_id).await {
        return internal(error);
    }
    if let Some(session) = raw_session
        && let Err(error) = ctx.store.delete_session(&session).await
    {
        return internal(error);
    }
    clear_session(empty(StatusCode::NO_CONTENT))
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
    if payload.object_type == "athlete"
        && payload.updates.get("authorized").and_then(|v| v.as_str()) == Some("false")
    {
        if let Err(error) = ctx.store.delete_connection(payload.owner_id).await {
            return internal(error);
        }
    } else if payload.object_type == "activity"
        && let Err(error) = ctx
            .store
            .put_webhook_event(
                payload.owner_id,
                payload.object_id,
                &payload.aspect_type,
                now_millis(),
            )
            .await
    {
        return internal(error);
    }
    json(StatusCode::OK, &serde_json::json!({}))
}

async fn authenticate(req: &Request, ctx: &Ctx) -> Result<Option<i64>, anyhow::Error> {
    let Some(session) = session_cookie(req) else {
        return Ok(None);
    };
    ctx.store.athlete_for_session(&session, now_seconds()).await
}

fn session_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(read_session_cookie)
}

async fn valid_access_token(ctx: &Ctx, athlete_id: i64) -> Result<String, anyhow::Error> {
    for _ in 0..2 {
        let connection = ctx
            .store
            .get_connection(athlete_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Strava connection not found"))?;
        if connection.token_expires_at > now_seconds() + 60 {
            return token_plaintext(&ctx.config, &connection, TokenKind::Access);
        }
        let refresh = token_plaintext(&ctx.config, &connection, TokenKind::Refresh)?;
        let refreshed = strava::refresh_token(
            &ctx.http_client,
            strava::token_url(),
            &ctx.config.strava_client_id,
            &ctx.config.strava_client_secret,
            &refresh,
        )
        .await?;
        let replacement = encrypted_connection(
            &ctx.config,
            athlete_id,
            &refreshed.access_token,
            &refreshed.refresh_token,
            refreshed.expires_at,
            connection.token_version + 1,
        )?;
        if ctx
            .store
            .replace_tokens(&replacement, connection.token_version)
            .await?
        {
            return Ok(refreshed.access_token);
        }
    }
    anyhow::bail!("concurrent token refresh did not settle")
}

fn token_plaintext(
    config: &Config,
    connection: &Connection,
    kind: TokenKind,
) -> Result<String, anyhow::Error> {
    let encrypted = match kind {
        TokenKind::Access => &connection.access_token,
        TokenKind::Refresh => &connection.refresh_token,
    };
    let bytes = decrypt(
        encrypted,
        connection.athlete_id,
        kind,
        connection.key_version,
        &config.token_encryption_key,
    )?;
    String::from_utf8(bytes).map_err(Into::into)
}

fn encrypted_connection(
    config: &Config,
    athlete_id: i64,
    access: &str,
    refresh: &str,
    expires_at: i64,
    token_version: i64,
) -> Result<Connection, anyhow::Error> {
    Ok(Connection {
        athlete_id,
        access_token: encrypt(
            access.as_bytes(),
            athlete_id,
            TokenKind::Access,
            config.key_version,
            &config.token_encryption_key,
        )?,
        refresh_token: encrypt(
            refresh.as_bytes(),
            athlete_id,
            TokenKind::Refresh,
            config.key_version,
            &config.token_encryption_key,
        )?,
        key_version: config.key_version,
        token_version,
        token_expires_at: expires_at,
    })
}

#[derive(Serialize)]
struct AuthorizeParams<'a> {
    client_id: &'a str,
    response_type: &'static str,
    redirect_uri: &'a str,
    scope: &'a str,
    state: &'a str,
}

#[derive(Default, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

fn scope_sufficient(scopes: Option<&str>) -> bool {
    let Some(scopes) = scopes else { return false };
    let granted: HashSet<_> = scopes.split(',').map(str::trim).collect();
    REQUIRED_SCOPES.iter().all(|scope| granted.contains(scope))
}

fn new_session() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
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
        .header("Vary", "Origin")
}

fn internal(error: anyhow::Error) -> Response<Body> {
    tracing::error!(%error, "internal API error");
    json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &serde_json::json!({"error":"internal_error"}),
    )
}

fn upstream(error: anyhow::Error) -> Response<Body> {
    tracing::error!(%error, "Strava API error");
    json(
        StatusCode::BAD_GATEWAY,
        &serde_json::json!({"error":"strava_unavailable"}),
    )
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

    #[test]
    fn scopes_are_least_privilege_and_include_private_activities() {
        assert!(scope_sufficient(Some("read,activity:read_all")));
        assert!(!scope_sufficient(Some("read")));
        assert_eq!(REQUIRED_SCOPES, &["read", "activity:read_all"]);
    }

    #[test]
    fn session_tokens_are_random_and_url_safe() {
        let first = new_session();
        let second = new_session();
        assert_eq!(first.len(), 43);
        assert_ne!(first, second);
        assert!(!first.contains('='));
    }
}
