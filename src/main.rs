//! `lepre-api` Lambda entrypoint.
//!
//! Lambda entry point for the local-first application's thin backend.

use std::sync::Arc;

use lambda_http::{Error, service_fn};
use lepre_api::application::Application;
use lepre_api::{config, db, handler, strava};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,aws_sdk=warn,reqwest=warn,hyper=warn,h2=warn".into()),
        )
        .with_target(false)
        .with_current_span(false)
        .init();

    let config = config::Config::load_from_ssm().await?;
    let aws = aws_config::load_from_env().await;
    let store = db::Store::new(
        aws_sdk_dynamodb::Client::new(&aws),
        config.table_name.clone(),
        config.token_encryption_key,
        config.key_version,
    );
    let http_client = strava::http_client()?;
    let provider = strava::StravaProvider::new(
        http_client,
        config.strava_client_id.clone(),
        config.strava_client_secret.clone(),
    );
    let application = Application::new(Arc::new(store), Arc::new(provider));

    let ctx = Arc::new(handler::Ctx {
        config,
        application,
    });

    lambda_http::run(service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { handler::route(req, ctx).await }
    }))
    .await
}
