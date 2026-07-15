//! Lambda runtime configuration loaded once on cold start (ADR 001 §5).
//!
//! Secrets live under `/lepre/api/*` in SSM SecureString. A single
//! `GetParameters` batch call populates the struct; subsequent invocations
//! of the warm Lambda re-use the cached values without further SSM
//! round-trips.

use std::collections::HashMap;

use anyhow::{Context, anyhow};
use base64::Engine as _;

const SSM_NAMES: &[&str] = &[
    "/lepre/api/strava_client_id",
    "/lepre/api/strava_client_secret",
    "/lepre/api/token_encryption_key",
    "/lepre/api/webhook_verify_token",
];

/// Resolved configuration values. Constructed once; never mutated.
#[derive(Clone, Debug)]
pub struct Config {
    pub strava_client_id: String,
    pub strava_client_secret: String,
    pub webhook_verify_token: String,
    pub table_name: String,
    /// 32-byte AES-256 key, decoded from the base64 SSM value.
    pub token_encryption_key: [u8; 32],
    pub key_version: i32,
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
        let key_b64 = take("/lepre/api/token_encryption_key")?;

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .context("token_encryption_key is not valid base64")?;
        let token_encryption_key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("token_encryption_key must decode to exactly 32 bytes"))?;

        Ok(Self {
            strava_client_id,
            strava_client_secret,
            webhook_verify_token,
            table_name: std::env::var("LEPRE_TABLE_NAME").unwrap_or_else(|_| "lepre".to_owned()),
            token_encryption_key,
            key_version: 1,
        })
    }

    pub fn strava_configured(&self) -> bool {
        !self.strava_client_id.is_empty() && !self.strava_client_secret.is_empty()
    }
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

        let cfg = Config::from_values(&mut h).unwrap();
        assert_eq!(cfg.strava_client_id, "clid");
        assert_eq!(cfg.strava_client_secret, "csec");
        assert_eq!(cfg.webhook_verify_token, "verify");
        assert_eq!(cfg.token_encryption_key, [7u8; 32]);
        assert_eq!(cfg.key_version, 1);
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
        let err = Config::from_values(&mut h).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }
}
