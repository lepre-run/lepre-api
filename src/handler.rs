//! Route dispatch + per-route handlers (ADR 001 §1, §2).
//!
//! Three routes plus a 404 fallback. The dispatcher is a flat `match` —
//! three routes don't justify a router framework.

use std::sync::Arc;

use chrono::Utc;
use http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use http::{Method, StatusCode};
use lambda_http::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::config::Config;
use crate::cookie::{mint_state, read_state_cookie, set_state_cookie};
use crate::crypto::{TokenKind, encrypt};
use crate::db::{self, ConnectionUpsert};
use crate::headers;
use crate::redirect;
use crate::strava;

const STRAVA_AUTHORIZE_URL: &str = "https://www.strava.com/oauth/authorize";
const REDIRECT_URI: &str = "https://api.lepre.run/v1/auth/strava/callback";
const REQUIRED_SCOPES: &[&str] = &["read", "activity:read_all", "profile:read_all"];

/// Per-Lambda-container context shared across invocations.
pub struct Ctx {
    pub config: Config,
    pub mongo_client: mongodb::Client,
    pub http_client: reqwest::Client,
}

/// Strava endpoints (overridable for tests so the integration test can
/// point at a wiremock server).
pub struct StravaEndpoints {
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub deauthorize_url: &'static str,
    pub redirect_uri: &'static str,
}

impl Default for StravaEndpoints {
    fn default() -> Self {
        Self {
            authorize_url: STRAVA_AUTHORIZE_URL,
            token_url: strava::token_url(),
            deauthorize_url: strava::deauthorize_url(),
            redirect_uri: REDIRECT_URI,
        }
    }
}

pub async fn route(req: Request, ctx: Arc<Ctx>) -> Result<Response<Body>, lambda_http::Error> {
    let endpoints = StravaEndpoints::default();
    Ok(route_with_endpoints(req, ctx, &endpoints).await)
}

pub async fn route_with_endpoints(
    req: Request,
    ctx: Arc<Ctx>,
    endpoints: &StravaEndpoints,
) -> Response<Body> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    match (&method, path.as_str()) {
        (&Method::GET, "/v1/healthz") => healthz(),
        (&Method::GET, "/v1/auth/strava/start") => strava_start(&ctx.config, endpoints),
        (&Method::GET, "/v1/auth/strava/callback") => strava_callback(&req, &ctx, endpoints).await,
        _ => not_found(),
    }
}

// --- routes ---------------------------------------------------------------

fn healthz() -> Response<Body> {
    headers::apply(http::Response::builder())
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::Text("{\"ok\":true}".into()))
        .expect("static response shape valid")
}

fn not_found() -> Response<Body> {
    headers::apply(http::Response::builder())
        .status(StatusCode::NOT_FOUND)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::Text("{\"error\":\"not_found\",\"code\":404}".into()))
        .expect("static response shape valid")
}

fn strava_start(config: &Config, endpoints: &StravaEndpoints) -> Response<Body> {
    let state = mint_state();
    let location = build_authorize_url(
        endpoints.authorize_url,
        &config.strava_client_id,
        endpoints.redirect_uri,
        &state,
    );

    headers::apply(http::Response::builder())
        .status(StatusCode::FOUND)
        .header(LOCATION, location)
        .header(SET_COOKIE, set_state_cookie(&state))
        .body(Body::Empty)
        .expect("static response shape valid")
}

async fn strava_callback(req: &Request, ctx: &Ctx, endpoints: &StravaEndpoints) -> Response<Body> {
    let query = parse_query(req.uri().query().unwrap_or(""));

    if query.error.is_some() {
        return redirect::to_connect_failed("user_denied");
    }

    let cookie_header = req
        .headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_state = read_state_cookie(cookie_header);

    let state_ok = match (&cookie_state, &query.state) {
        (Some(c), Some(q)) => c.as_bytes().ct_eq(q.as_bytes()).into(),
        _ => false,
    };
    if !state_ok {
        return redirect::to_connect_failed("state_invalid");
    }

    let Some(code) = query.code.as_deref() else {
        return redirect::to_connect_failed("missing_code");
    };

    let correlation_id = Uuid::new_v4().to_string();

    let token = match strava::exchange_code(
        &ctx.http_client,
        endpoints.token_url,
        &ctx.config.strava_client_id,
        &ctx.config.strava_client_secret,
        code,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                correlation_id = %correlation_id,
                error = %e,
                "strava token exchange failed"
            );
            return redirect::to_connect_failed_with_id("strava_exchange_failed", &correlation_id);
        }
    };

    if !scope_sufficient(query.scope.as_deref()) {
        let _ = strava::deauthorize(
            &ctx.http_client,
            endpoints.deauthorize_url,
            &token.access_token,
        )
        .await;
        return redirect::to_connect_failed("scope_insufficient");
    }

    let attempt_id = Uuid::new_v4().to_string();

    let athlete_id = token.athlete.id;
    let key_version = ctx.config.key_version;
    let key = &ctx.config.token_encryption_key;

    let access_ct = match encrypt(
        token.access_token.as_bytes(),
        athlete_id,
        TokenKind::Access,
        key_version,
        key,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "encrypt access_token failed");
            return redirect::to_connect_failed("unknown");
        }
    };
    let refresh_ct = match encrypt(
        token.refresh_token.as_bytes(),
        athlete_id,
        TokenKind::Refresh,
        key_version,
        key,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "encrypt refresh_token failed");
            return redirect::to_connect_failed("unknown");
        }
    };

    let upsert = ConnectionUpsert {
        strava_athlete_id: athlete_id,
        connection_attempt_id: attempt_id.clone(),
        access_token: access_ct,
        refresh_token: refresh_ct,
        key_version,
        expires_at_epoch_seconds: token.expires_at,
    };

    if let Err(e) = db::upsert_connection(&ctx.mongo_client, &upsert, Utc::now()).await {
        tracing::error!(
            correlation_id = %correlation_id,
            attempt_id = %attempt_id,
            error = %e,
            "mongo upsert failed"
        );
        // Best-effort cleanup of any partially-written doc.
        if let Err(cleanup) = db::delete_attempt(&ctx.mongo_client, &attempt_id).await {
            tracing::error!(
                correlation_id = %correlation_id,
                error = %cleanup,
                "mongo cleanup delete also failed"
            );
        }
        // Best-effort revoke the Strava grant so the user's Strava settings
        // don't show a dangling app authorization.
        if let Err(d) = strava::deauthorize(
            &ctx.http_client,
            endpoints.deauthorize_url,
            &token.access_token,
        )
        .await
        {
            tracing::error!(
                correlation_id = %correlation_id,
                error = %d,
                "strava deauthorize after mongo failure also failed"
            );
        }
        return redirect::to_connect_failed_with_id("db_failure", &correlation_id);
    }

    redirect::to_connected()
}

// --- helpers --------------------------------------------------------------

#[derive(Default, Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    error: Option<String>,
}

fn parse_query(raw: &str) -> CallbackQuery {
    serde_urlencoded::from_str(raw).unwrap_or_default()
}

#[derive(Serialize)]
struct AuthorizeParams<'a> {
    client_id: &'a str,
    response_type: &'static str,
    redirect_uri: &'a str,
    scope: &'a str,
    state: &'a str,
}

fn build_authorize_url(base: &str, client_id: &str, redirect_uri: &str, state: &str) -> String {
    let scope = REQUIRED_SCOPES.join(",");
    let params = AuthorizeParams {
        client_id,
        response_type: "code",
        redirect_uri,
        scope: &scope,
        state,
    };
    let q = serde_urlencoded::to_string(&params)
        .expect("AuthorizeParams serialization is infallible for &str fields");
    format!("{base}?{q}")
}

fn scope_sufficient(returned: Option<&str>) -> bool {
    let Some(s) = returned else {
        return false;
    };
    let granted: std::collections::HashSet<&str> = s.split(',').map(str::trim).collect();
    REQUIRED_SCOPES.iter().all(|r| granted.contains(*r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_authorize_url_carries_required_params() {
        let url = build_authorize_url(
            "https://www.strava.com/oauth/authorize",
            "12345",
            "https://api.lepre.run/v1/auth/strava/callback",
            "abc",
        );
        assert!(url.contains("client_id=12345"));
        assert!(url.contains("response_type=code"));
        assert!(
            url.contains(
                "redirect_uri=https%3A%2F%2Fapi.lepre.run%2Fv1%2Fauth%2Fstrava%2Fcallback"
            ),
            "got: {url}"
        );
        assert!(
            url.contains("scope=read%2Cactivity%3Aread_all%2Cprofile%3Aread_all"),
            "got: {url}"
        );
        assert!(url.contains("state=abc"));
    }

    #[test]
    fn scope_sufficient_accepts_full_grant() {
        assert!(scope_sufficient(Some(
            "read,activity:read_all,profile:read_all"
        )));
        // Order is irrelevant.
        assert!(scope_sufficient(Some(
            "profile:read_all,read,activity:read_all"
        )));
    }

    #[test]
    fn scope_sufficient_rejects_partial_grant() {
        assert!(!scope_sufficient(Some("read")));
        assert!(!scope_sufficient(Some("read,activity:read_all")));
        assert!(!scope_sufficient(Some(
            "activity:read_all,profile:read_all"
        )));
    }

    #[test]
    fn scope_sufficient_rejects_missing() {
        assert!(!scope_sufficient(None));
    }

    #[test]
    fn parse_query_extracts_oauth_params() {
        let q = parse_query("code=abc&state=xyz&scope=read%2Cactivity%3Aread_all");
        assert_eq!(q.code.as_deref(), Some("abc"));
        assert_eq!(q.state.as_deref(), Some("xyz"));
        assert_eq!(q.scope.as_deref(), Some("read,activity:read_all"));
        assert_eq!(q.error, None);
    }

    #[test]
    fn parse_query_extracts_error_param() {
        let q = parse_query("error=access_denied");
        assert_eq!(q.error.as_deref(), Some("access_denied"));
    }

    #[test]
    fn healthz_returns_200_json_with_security_headers() {
        let r = healthz();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        assert!(r.headers().contains_key("strict-transport-security"));
    }

    #[test]
    fn not_found_returns_404_with_node_backend_error_shape() {
        let r = not_found();
        assert_eq!(r.status(), 404);
        let body = match r.into_body() {
            Body::Text(s) => s,
            _ => panic!("expected text body"),
        };
        assert!(body.contains("\"error\":\"not_found\""));
        assert!(body.contains("\"code\":404"));
    }

    fn fake_config() -> Config {
        Config {
            strava_client_id: "cid".into(),
            strava_client_secret: "csec".into(),
            mongodb_uri: "mongodb://test".into(),
            token_encryption_key: [0u8; 32],
            key_version: 1,
        }
    }

    #[test]
    fn strava_start_sets_cookie_and_carries_state_in_redirect() {
        let cfg = fake_config();
        let endpoints = StravaEndpoints::default();
        let r = strava_start(&cfg, &endpoints);
        assert_eq!(r.status(), 302);

        let location = r.headers().get(LOCATION).unwrap().to_str().unwrap();
        let cookie = r.headers().get(SET_COOKIE).unwrap().to_str().unwrap();

        // Extract `state=...` from the redirect.
        let state_from_url = location
            .split('&')
            .find_map(|kv| kv.strip_prefix("state="))
            .or_else(|| {
                location
                    .split('?')
                    .nth(1)?
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("state="))
            })
            .expect("state param in redirect");
        let state_from_cookie = cookie
            .split(';')
            .find_map(|p| p.trim().strip_prefix("lepre_oauth_state="))
            .expect("state cookie value");

        assert_eq!(state_from_url, state_from_cookie);
        assert_eq!(state_from_url.len(), 43);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/v1/auth/strava"));
        assert!(!cookie.contains("Domain="));
        assert!(location.starts_with("https://www.strava.com/oauth/authorize"));
        assert!(location.contains("client_id=cid"));
    }

    #[test]
    fn state_cookie_path_constant_matches_set_attribute() {
        // Belt-and-braces: the redirect helper uses the same path string;
        // if these ever diverge, the cookie deletion silently fails.
        use crate::cookie::STATE_COOKIE_PATH;
        let cookie = set_state_cookie("v");
        let clear = crate::cookie::clear_state_cookie();
        assert!(cookie.contains(STATE_COOKIE_PATH));
        assert!(clear.contains(STATE_COOKIE_PATH));
    }
}
