//! `lepre-api` Lambda entrypoint.
//!
//! Three routes (per ADR 001 §1):
//! - `GET /v1/healthz`
//! - `GET /v1/auth/strava/start`
//! - `GET /v1/auth/strava/callback`
//!
//! Anything else → `404 not_found`.

use std::sync::Arc;

use lambda_http::{Error, service_fn};
use lepre_api::{config, db, handler, strava};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mongodb=warn,reqwest=warn,hyper=warn,h2=warn".into()),
        )
        .with_target(false)
        .with_current_span(false)
        .init();

    let config = config::Config::load_from_ssm().await?;
    let mongo_client = db::connect(&config.mongodb_uri).await?;
    db::ensure_indexes(&mongo_client).await?;
    let http_client = strava::http_client()?;

    let ctx = Arc::new(handler::Ctx {
        config,
        mongo_client,
        http_client,
    });

    lambda_http::run(service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { handler::route(req, ctx).await }
    }))
    .await
}
