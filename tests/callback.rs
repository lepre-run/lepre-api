//! Integration tests for `GET /v1/auth/strava/callback` — full handler path
//! through `lambda_http::Request`, with `wiremock` standing in for Strava
//! and `testcontainers` running real MongoDB.

use std::sync::Arc;

use http::header::COOKIE;
use lambda_http::{Body, Request};
use mongodb::bson::doc;
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lepre_api::config::Config;
use lepre_api::handler::{Ctx, StravaEndpoints, route_with_endpoints};
use lepre_api::{db, strava};

const STATE: &str = "test-state-value";
const CODE: &str = "test-auth-code";
const ATHLETE_ID: i64 = 999_001;

fn fake_config(mongodb_uri: &str) -> Config {
    Config {
        strava_client_id: "cid".into(),
        strava_client_secret: "csec".into(),
        mongodb_uri: mongodb_uri.into(),
        token_encryption_key: [9u8; 32],
        key_version: 1,
    }
}

fn endpoints(strava_uri: &str) -> StravaEndpoints {
    // Leak short-lived strings to satisfy the &'static str fields in
    // StravaEndpoints. These are integration-test-scoped — leaking is
    // acceptable.
    let token = format!("{strava_uri}/oauth/token");
    let deauth = format!("{strava_uri}/oauth/deauthorize");
    StravaEndpoints {
        authorize_url: Box::leak(format!("{strava_uri}/oauth/authorize").into_boxed_str()),
        token_url: Box::leak(token.into_boxed_str()),
        deauthorize_url: Box::leak(deauth.into_boxed_str()),
        redirect_uri: "https://api.lepre.run/v1/auth/strava/callback",
    }
}

fn callback_request(state_cookie: &str, query: &str) -> Request {
    let cookie_header = format!("lepre_oauth_state={state_cookie}");
    http::Request::builder()
        .method("GET")
        .uri(format!(
            "https://api.lepre.run/v1/auth/strava/callback?{query}"
        ))
        .header(COOKIE, cookie_header)
        .body(Body::Empty)
        .unwrap()
}

#[tokio::test]
async fn happy_path_writes_encrypted_doc_with_aad() {
    let mongo = Mongo::default()
        .start()
        .await
        .expect("start mongo container");
    let port = mongo.get_host_port_ipv4(27017).await.unwrap();
    let mongodb_uri = format!("mongodb://127.0.0.1:{port}");

    let strava = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "atk-secret",
            "refresh_token": "rtk-secret",
            "expires_at": 1_900_000_000_i64,
            "athlete": { "id": ATHLETE_ID },
        })))
        .expect(1)
        .mount(&strava)
        .await;

    let config = fake_config(&mongodb_uri);
    let mongo_client = db::connect(&config.mongodb_uri).await.unwrap();
    let http_client = strava::http_client().unwrap();
    let endpoints = endpoints(&strava.uri());

    let ctx = Arc::new(Ctx {
        config,
        mongo_client: mongo_client.clone(),
        http_client,
    });

    let req = callback_request(
        STATE,
        &format!("code={CODE}&state={STATE}&scope=read,activity:read_all,profile:read_all"),
    );
    let resp = route_with_endpoints(req, ctx, &endpoints).await;

    assert_eq!(resp.status(), 302);
    let location = resp.headers().get(http::header::LOCATION).unwrap();
    assert_eq!(location, "https://lepre.run/connected");
    let cookie = resp.headers().get(http::header::SET_COOKIE).unwrap();
    assert!(cookie.to_str().unwrap().contains("Max-Age=0"));

    // Mongo state.
    let coll = mongo_client
        .database("lepre")
        .collection::<mongodb::bson::Document>("connections");
    let doc = coll
        .find_one(doc! { "strava_athlete_id": ATHLETE_ID })
        .await
        .unwrap()
        .expect("doc not found");
    assert_eq!(doc.get_i64("strava_athlete_id").unwrap(), ATHLETE_ID);
    assert_eq!(doc.get_i32("key_version").unwrap(), 1);
    assert!(doc.get_binary_generic("access_token_ciphertext").is_ok());
    assert!(doc.get_binary_generic("access_token_nonce").is_ok());
    assert!(doc.get_binary_generic("refresh_token_ciphertext").is_ok());
    assert!(doc.get_binary_generic("refresh_token_nonce").is_ok());
    assert!(doc.contains_key("connected_at"));
    assert!(doc.contains_key("updated_at"));
    assert!(doc.contains_key("connection_attempt_id"));
}

#[tokio::test]
async fn repeat_callback_upserts_single_doc() {
    let mongo = Mongo::default().start().await.unwrap();
    let port = mongo.get_host_port_ipv4(27017).await.unwrap();
    let mongodb_uri = format!("mongodb://127.0.0.1:{port}");

    let strava = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "atk-1",
            "refresh_token": "rtk-1",
            "expires_at": 1_900_000_000_i64,
            "athlete": { "id": ATHLETE_ID },
        })))
        .mount(&strava)
        .await;

    let config = fake_config(&mongodb_uri);
    let mongo_client = db::connect(&config.mongodb_uri).await.unwrap();
    let http_client = strava::http_client().unwrap();
    let endpoints = endpoints(&strava.uri());

    let ctx = Arc::new(Ctx {
        config,
        mongo_client: mongo_client.clone(),
        http_client,
    });

    let make_req = || {
        callback_request(
            STATE,
            &format!("code={CODE}&state={STATE}&scope=read,activity:read_all,profile:read_all"),
        )
    };

    let r1 = route_with_endpoints(make_req(), Arc::clone(&ctx), &endpoints).await;
    assert_eq!(r1.status(), 302);
    let r2 = route_with_endpoints(make_req(), Arc::clone(&ctx), &endpoints).await;
    assert_eq!(r2.status(), 302);

    let coll = mongo_client
        .database("lepre")
        .collection::<mongodb::bson::Document>("connections");
    let count = coll.count_documents(doc! {}).await.unwrap();
    assert_eq!(count, 1, "expected one upserted doc, got {count}");
}

#[tokio::test]
async fn mongo_failure_redirects_and_deauthorizes() {
    // Deliberately broken Mongo URI — no testcontainer, no kill-mid-test.
    let bad_mongodb_uri = "mongodb://127.0.0.1:1/lepre?serverSelectionTimeoutMS=200";

    let strava = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "atk-secret",
            "refresh_token": "rtk-secret",
            "expires_at": 1_900_000_000_i64,
            "athlete": { "id": ATHLETE_ID },
        })))
        .mount(&strava)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/deauthorize"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer atk-secret",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&strava)
        .await;

    let config = fake_config(bad_mongodb_uri);
    let mongo_client = db::connect(&config.mongodb_uri).await.unwrap();
    let http_client = strava::http_client().unwrap();
    let endpoints = endpoints(&strava.uri());

    let ctx = Arc::new(Ctx {
        config,
        mongo_client,
        http_client,
    });

    let req = callback_request(
        STATE,
        &format!("code={CODE}&state={STATE}&scope=read,activity:read_all,profile:read_all"),
    );
    let resp = route_with_endpoints(req, ctx, &endpoints).await;

    assert_eq!(resp.status(), 302);
    let location = resp
        .headers()
        .get(http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("https://lepre.run/connect-failed?reason=db_failure&id="),
        "got: {location}"
    );
}

#[tokio::test]
async fn partial_scope_redirects_to_connect_failed_scope_insufficient() {
    let mongo = Mongo::default().start().await.unwrap();
    let port = mongo.get_host_port_ipv4(27017).await.unwrap();
    let mongodb_uri = format!("mongodb://127.0.0.1:{port}");

    let strava = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "atk-secret",
            "refresh_token": "rtk-secret",
            "expires_at": 1_900_000_000_i64,
            "athlete": { "id": ATHLETE_ID },
        })))
        .mount(&strava)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/deauthorize"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer atk-secret",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&strava)
        .await;

    let config = fake_config(&mongodb_uri);
    let mongo_client = db::connect(&config.mongodb_uri).await.unwrap();
    let http_client = strava::http_client().unwrap();
    let endpoints = endpoints(&strava.uri());

    let ctx = Arc::new(Ctx {
        config,
        mongo_client: mongo_client.clone(),
        http_client,
    });

    // Only `read` granted — partial scope.
    let req = callback_request(STATE, &format!("code={CODE}&state={STATE}&scope=read"));
    let resp = route_with_endpoints(req, ctx, &endpoints).await;

    assert_eq!(resp.status(), 302);
    let location = resp.headers().get(http::header::LOCATION).unwrap();
    assert_eq!(
        location,
        "https://lepre.run/connect-failed?reason=scope_insufficient"
    );

    // Nothing written to Mongo.
    let coll = mongo_client
        .database("lepre")
        .collection::<mongodb::bson::Document>("connections");
    assert_eq!(coll.count_documents(doc! {}).await.unwrap(), 0);
}
