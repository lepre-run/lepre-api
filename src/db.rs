//! MongoDB Atlas access (ADR 001 §4): connection setup + the upsert / cleanup
//! used by the OAuth callback.
//!
//! The Lambda holds one `mongodb::Client` per warm container; it is
//! constructed in `main.rs` (cold start) and reused for every invocation.
//! Calls take a `&Client` rather than touching a global, which keeps tests
//! injectable.

use anyhow::Context;
use bson::{Binary, Bson, doc, spec::BinarySubtype};
use chrono::{DateTime, TimeZone, Utc};
use mongodb::Client;
use mongodb::options::ClientOptions;

use crate::crypto::EncryptedToken;

const DATABASE: &str = "lepre";
const COLLECTION: &str = "connections";
const POOL_SIZE: u32 = 5;

/// Document fields written by `upsert_connection`. Public so integration
/// tests can read them back.
pub mod fields {
    pub const STRAVA_ATHLETE_ID: &str = "strava_athlete_id";
    pub const CONNECTION_ATTEMPT_ID: &str = "connection_attempt_id";
    pub const ACCESS_TOKEN_CIPHERTEXT: &str = "access_token_ciphertext";
    pub const ACCESS_TOKEN_NONCE: &str = "access_token_nonce";
    pub const REFRESH_TOKEN_CIPHERTEXT: &str = "refresh_token_ciphertext";
    pub const REFRESH_TOKEN_NONCE: &str = "refresh_token_nonce";
    pub const KEY_VERSION: &str = "key_version";
    pub const EXPIRES_AT: &str = "expires_at";
    pub const CONNECTED_AT: &str = "connected_at";
    pub const UPDATED_AT: &str = "updated_at";
}

/// Build a Mongo client with the project-wide pool ceiling.
pub async fn connect(uri: &str) -> Result<Client, anyhow::Error> {
    let mut opts = ClientOptions::parse(uri)
        .await
        .context("invalid mongodb uri")?;
    opts.app_name = Some("lepre-api".into());
    opts.max_pool_size = Some(POOL_SIZE);
    Ok(Client::with_options(opts)?)
}

/// What the OAuth callback needs to store.
pub struct ConnectionUpsert {
    pub strava_athlete_id: i64,
    pub connection_attempt_id: String,
    pub access_token: EncryptedToken,
    pub refresh_token: EncryptedToken,
    pub key_version: i32,
    pub expires_at_epoch_seconds: i64,
}

/// Idempotent upsert keyed by `strava_athlete_id`.
///
/// First successful connection inserts; a subsequent connection by the same
/// athlete replaces the encrypted token fields. `connected_at` is preserved
/// across re-connections; `updated_at` is set to `now` every time.
pub async fn upsert_connection(
    client: &Client,
    upsert: &ConnectionUpsert,
    now: DateTime<Utc>,
) -> Result<(), anyhow::Error> {
    let coll = client
        .database(DATABASE)
        .collection::<bson::Document>(COLLECTION);

    let expires_at = Utc
        .timestamp_opt(upsert.expires_at_epoch_seconds, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("invalid expires_at epoch"))?;

    let set_doc = doc! {
        fields::STRAVA_ATHLETE_ID: upsert.strava_athlete_id,
        fields::CONNECTION_ATTEMPT_ID: &upsert.connection_attempt_id,
        fields::ACCESS_TOKEN_CIPHERTEXT: bin(&upsert.access_token.ciphertext),
        fields::ACCESS_TOKEN_NONCE: bin(&upsert.access_token.nonce),
        fields::REFRESH_TOKEN_CIPHERTEXT: bin(&upsert.refresh_token.ciphertext),
        fields::REFRESH_TOKEN_NONCE: bin(&upsert.refresh_token.nonce),
        fields::KEY_VERSION: upsert.key_version,
        fields::EXPIRES_AT: bson::DateTime::from_chrono(expires_at),
        fields::UPDATED_AT: bson::DateTime::from_chrono(now),
    };
    let on_insert_doc = doc! {
        fields::CONNECTED_AT: bson::DateTime::from_chrono(now),
    };

    coll.update_one(
        doc! { fields::STRAVA_ATHLETE_ID: upsert.strava_athlete_id },
        doc! { "$set": set_doc, "$setOnInsert": on_insert_doc },
    )
    .upsert(true)
    .await
    .context("mongo upsert failed")?;

    Ok(())
}

/// Cleanup any partial document written under `connection_attempt_id` —
/// used after a write failure where `replace_one` may have succeeded
/// server-side before the client saw the error.
pub async fn delete_attempt(
    client: &Client,
    connection_attempt_id: &str,
) -> Result<(), anyhow::Error> {
    let coll = client
        .database(DATABASE)
        .collection::<bson::Document>(COLLECTION);
    coll.delete_one(doc! { fields::CONNECTION_ATTEMPT_ID: connection_attempt_id })
        .await
        .context("mongo cleanup delete failed")?;
    Ok(())
}

/// Ensure the unique index on `{ strava_athlete_id: 1 }` exists. Called once
/// at cold start; idempotent.
pub async fn ensure_indexes(client: &Client) -> Result<(), anyhow::Error> {
    use mongodb::IndexModel;
    use mongodb::options::IndexOptions;

    let index = IndexModel::builder()
        .keys(doc! { fields::STRAVA_ATHLETE_ID: 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();

    client
        .database(DATABASE)
        .collection::<bson::Document>(COLLECTION)
        .create_index(index)
        .await
        .context("mongo create_index failed")?;
    Ok(())
}

fn bin(bytes: &[u8]) -> Bson {
    Bson::Binary(Binary {
        subtype: BinarySubtype::Generic,
        bytes: bytes.to_vec(),
    })
}
