//! AES-256-GCM token encryption with AAD-bound to athlete + token kind +
//! key version (ADR 001 §4).
//!
//! The AAD prevents ciphertext copy-paste attacks: a row whose ciphertext is
//! moved to another athlete, swapped between `access`/`refresh`, or read with
//! the wrong key version will fail the AEAD check rather than silently
//! decrypt to the original value.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::Rng;

/// Which token a ciphertext represents — bound into the AAD so an attacker
/// cannot swap an access-token ciphertext into a refresh-token slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Refresh,
}

impl TokenKind {
    fn as_aad_str(self) -> &'static str {
        match self {
            TokenKind::Access => "access",
            TokenKind::Refresh => "refresh",
        }
    }
}

/// Output of one encrypt call: ciphertext + per-encryption nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedToken {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

/// Build the AAD bound to a particular row + field.
///
/// Format: `strava|athlete={athlete_id}|kind={access|refresh}|key={version}`.
fn build_aad(athlete_id: i64, kind: TokenKind, key_version: i32) -> String {
    format!(
        "strava|athlete={athlete_id}|kind={kind}|key={key_version}",
        kind = kind.as_aad_str(),
    )
}

/// Encrypt `plaintext` under `key`, with AAD bound to athlete + kind + version.
///
/// A fresh 12-byte nonce is drawn from the OS CSPRNG for every call.
pub fn encrypt(
    plaintext: &[u8],
    athlete_id: i64,
    kind: TokenKind,
    key_version: i32,
    key: &[u8; 32],
) -> Result<EncryptedToken, anyhow::Error> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = rand::rng().random();
    let nonce = Nonce::from(nonce_bytes);
    let aad = build_aad(athlete_id, kind, key_version);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("aes-gcm encryption failed"))?;

    Ok(EncryptedToken {
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt `et`. Returns an opaque error on tag mismatch / wrong key /
/// wrong AAD — the caller is never told *why* decryption failed.
///
/// Slice 1 only encrypts (no token refresh, no read-back); decryption is
/// here for symmetry and tests, and so slice 2 has a stable surface to call.
#[allow(
    dead_code,
    reason = "slice 1 writes only; slice 2 will read for token refresh"
)]
pub fn decrypt(
    et: &EncryptedToken,
    athlete_id: i64,
    kind: TokenKind,
    key_version: i32,
    key: &[u8; 32],
) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(et.nonce);
    let aad = build_aad(athlete_id, kind, key_version);

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &et.ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("aes-gcm decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const KEY: &[u8; 32] = b"01234567890123456789012345678901";
    const ATHLETE: i64 = 12345;

    #[test]
    fn token_encryption_roundtrip() {
        let plaintext = b"strava-access-token-abc123";
        let et = encrypt(plaintext, ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        assert_ne!(et.ciphertext, plaintext);
        let got = decrypt(&et, ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_athlete_id() {
        let et = encrypt(b"secret", ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        let err = decrypt(&et, ATHLETE + 1, TokenKind::Access, 1, KEY).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn decrypt_fails_with_wrong_token_kind() {
        let et = encrypt(b"access-tok", ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        decrypt(&et, ATHLETE, TokenKind::Refresh, 1, KEY).unwrap_err();
    }

    #[test]
    fn decrypt_fails_with_wrong_key_version() {
        let et = encrypt(b"tok", ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        decrypt(&et, ATHLETE, TokenKind::Access, 2, KEY).unwrap_err();
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let alt_key: &[u8; 32] = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let et = encrypt(b"tok", ATHLETE, TokenKind::Access, 1, KEY).unwrap();
        decrypt(&et, ATHLETE, TokenKind::Access, 1, alt_key).unwrap_err();
    }

    #[test]
    fn nonce_unique_per_encryption() {
        let mut nonces = HashSet::with_capacity(1_000);
        for _ in 0..1_000 {
            let et = encrypt(b"same payload", ATHLETE, TokenKind::Access, 1, KEY).unwrap();
            nonces.insert(et.nonce);
        }
        assert_eq!(nonces.len(), 1_000, "nonce collision detected");
    }
}
