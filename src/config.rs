//! Lambda runtime configuration loaded once on cold start (ADR 001 §5).
//!
//! Secrets live under `/lepre/api/*` in SSM SecureString. A single
//! `GetParameters` batch call populates the struct; subsequent invocations
//! of the warm Lambda re-use the cached values without further SSM
//! round-trips.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use base64::Engine as _;

use crate::application::{SYNC_BATCH_REQUEST_COST, SyncGateConfig};

const SSM_NAMES: &[&str] = &[
    "/lepre/api/strava_client_id",
    "/lepre/api/strava_client_secret",
    "/lepre/api/token_encryption_key",
    "/lepre/api/webhook_verify_token",
    "/lepre/api/webhook_path_secret",
];

/// Resolved configuration values. Constructed once; never mutated.
#[derive(Clone, Debug)]
pub struct Config {
    pub strava_client_id: String,
    pub strava_client_secret: String,
    pub webhook_verify_token: String,
    /// URL path segment shared with Strava when registering the subscription
    /// callback (`/v1/webhooks/strava/{webhook_path_secret}`). Required on
    /// every webhook GET/POST because Strava does not sign event bodies.
    pub webhook_path_secret: String,
    pub table_name: String,
    /// 32-byte AES-256 key, decoded from the base64 SSM value.
    pub token_encryption_key: [u8; 32],
    pub key_version: i32,
    pub sync_gate: SyncGateConfig,
    /// Process-local cap on authenticated webhook POSTs per rolling window.
    pub webhook_rate_limit_per_minute: u64,
}

impl Config {
    /// Read all four parameters via one `ssm:GetParameters` call.
    pub async fn load_from_ssm() -> Result<Self, anyhow::Error> {
        let aws = aws_config::load_from_env().await;
        let client = aws_sdk_ssm::Client::new(&aws);

        let resp = client
            .get_parameters()
            .set_names(Some(SSM_NAMES.iter().map(|&s| s.to_owned()).collect()))
            .with_decryption(true)
            .send()
            .await
            .context("ssm:GetParameters failed")?;

        if let Some(invalid) = resp.invalid_parameters().iter().find(|name| {
            name.as_str() != "/lepre/api/strava_client_id"
                && name.as_str() != "/lepre/api/strava_client_secret"
        }) {
            return Err(anyhow!(
                "ssm parameter not found: {invalid} (expected one of: {names})",
                names = SSM_NAMES.join(", "),
            ));
        }

        let mut found: HashMap<String, String> = resp
            .parameters()
            .iter()
            .filter_map(|p| {
                let name = p.name()?.to_owned();
                let value = p.value()?.to_owned();
                Some((name, value))
            })
            .collect();

        Self::from_values(&mut found)
    }

    fn from_values(values: &mut HashMap<String, String>) -> Result<Self, anyhow::Error> {
        let strava_client_id = values
            .remove("/lepre/api/strava_client_id")
            .unwrap_or_default();
        let strava_client_secret = values
            .remove("/lepre/api/strava_client_secret")
            .unwrap_or_default();

        let mut take = |k: &str| -> Result<String, anyhow::Error> {
            values
                .remove(k)
                .ok_or_else(|| anyhow!("missing ssm parameter: {k}"))
        };

        let webhook_verify_token = take("/lepre/api/webhook_verify_token")?;
        let webhook_path_secret = take("/lepre/api/webhook_path_secret")?;
        if webhook_path_secret.is_empty()
            || webhook_path_secret.contains('/')
            || webhook_path_secret.contains('?')
            || webhook_path_secret.contains('#')
        {
            return Err(anyhow!(
                "webhook_path_secret must be a non-empty single URL path segment"
            ));
        }
        let key_b64 = take("/lepre/api/token_encryption_key")?;

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .context("token_encryption_key is not valid base64")?;
        let token_encryption_key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("token_encryption_key must decode to exactly 32 bytes"))?;

        let sync_gate = SyncGateConfig {
            read_limit_15_minutes: environment_integer("STRAVA_READ_LIMIT_15_MINUTES", 100)?,
            read_limit_daily: environment_integer("STRAVA_READ_LIMIT_DAILY", 1_000)?,
            safety_percent: environment_integer("STRAVA_QUOTA_SAFETY_PERCENT", 90)?,
            queue_lease_seconds: environment_integer("SYNC_QUEUE_LEASE_SECONDS", 30)?,
            poll_seconds: environment_integer("SYNC_QUEUE_POLL_SECONDS", 2)? as u64,
        };
        if !(50..=100).contains(&sync_gate.safety_percent)
            || sync_gate.queue_lease_seconds < 10
            || sync_gate.poll_seconds == 0
            || sync_gate.safe_limit_15_minutes() < SYNC_BATCH_REQUEST_COST
            || sync_gate.safe_limit_daily() < SYNC_BATCH_REQUEST_COST
        {
            return Err(anyhow!("invalid synchronization gate configuration"));
        }

        let webhook_rate_limit_per_minute =
            environment_integer("WEBHOOK_RATE_LIMIT_PER_MINUTE", 120)? as u64;
        if webhook_rate_limit_per_minute == 0 {
            return Err(anyhow!("WEBHOOK_RATE_LIMIT_PER_MINUTE must be >= 1"));
        }

        Ok(Self {
            strava_client_id,
            strava_client_secret,
            webhook_verify_token,
            webhook_path_secret,
            table_name: std::env::var("LEPRE_TABLE_NAME").unwrap_or_else(|_| "lepre".to_owned()),
            token_encryption_key,
            key_version: 1,
            sync_gate,
            webhook_rate_limit_per_minute,
        })
    }

    pub fn strava_configured(&self) -> bool {
        !self.strava_client_id.is_empty() && !self.strava_client_secret.is_empty()
    }
}

fn environment_integer(name: &str, default: i64) -> Result<i64, anyhow::Error> {
    std::env::var(name)
        .map_or_else(|_| Ok(default), |value| value.parse())
        .with_context(|| format!("{name} must be an integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64_32() -> String {
        let raw = [7u8; 32];
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    #[test]
    fn from_values_constructs_config_when_all_present() {
        let mut h = HashMap::new();
        h.insert("/lepre/api/strava_client_id".into(), "clid".into());
        h.insert("/lepre/api/strava_client_secret".into(), "csec".into());
        h.insert("/lepre/api/token_encryption_key".into(), b64_32());
        h.insert("/lepre/api/webhook_verify_token".into(), "verify".into());
        h.insert(
            "/lepre/api/webhook_path_secret".into(),
            "path-secret".into(),
        );

        let cfg = Config::from_values(&mut h).unwrap();
        assert_eq!(cfg.strava_client_id, "clid");
        assert_eq!(cfg.strava_client_secret, "csec");
        assert_eq!(cfg.webhook_verify_token, "verify");
        assert_eq!(cfg.webhook_path_secret, "path-secret");
        assert_eq!(cfg.token_encryption_key, [7u8; 32]);
        assert_eq!(cfg.key_version, 1);
        assert_eq!(cfg.webhook_rate_limit_per_minute, 120);
    }

    #[test]
    fn from_values_errors_on_missing_parameter() {
        let mut h = HashMap::new();
        h.insert("/lepre/api/strava_client_id".into(), "clid".into());
        let err = Config::from_values(&mut h).unwrap_err();
        assert!(
            err.to_string().contains("missing ssm parameter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_values_errors_on_short_key() {
        let mut h = HashMap::new();
        h.insert("/lepre/api/strava_client_id".into(), "x".into());
        h.insert("/lepre/api/strava_client_secret".into(), "x".into());
        h.insert("/lepre/api/mongodb_uri".into(), "x".into());
        h.insert(
            "/lepre/api/token_encryption_key".into(),
            base64::engine::general_purpose::STANDARD.encode([1u8; 16]),
        );
        h.insert("/lepre/api/webhook_verify_token".into(), "verify".into());
        h.insert(
            "/lepre/api/webhook_path_secret".into(),
            "path-secret".into(),
        );
        let err = Config::from_values(&mut h).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_values_errors_on_invalid_webhook_path_secret() {
        let mut h = HashMap::new();
        h.insert("/lepre/api/strava_client_id".into(), "clid".into());
        h.insert("/lepre/api/strava_client_secret".into(), "csec".into());
        h.insert("/lepre/api/token_encryption_key".into(), b64_32());
        h.insert("/lepre/api/webhook_verify_token".into(), "verify".into());
        h.insert("/lepre/api/webhook_path_secret".into(), "bad/secret".into());
        let err = Config::from_values(&mut h).unwrap_err();
        assert!(
            err.to_string().contains("webhook_path_secret"),
            "unexpected error: {err}"
        );
    }
}
