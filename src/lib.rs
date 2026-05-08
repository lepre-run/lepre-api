//! `lepre-api` library: shared modules used by both the Lambda binary
//! (`src/main.rs`) and the integration test (`tests/callback.rs`).

pub mod config;
pub mod cookie;
pub mod crypto;
pub mod db;
pub mod handler;
pub mod headers;
pub mod redirect;
pub mod strava;
