//! State-cookie helpers for the OAuth flow (ADR 001 §2).
//!
//! The state cookie is host-only on `api.lepre.run` (no `Domain=` attribute,
//! so it is bound to the exact host and not its subdomains), scoped by
//! `Path=/v1/auth/strava` so it is not sent on `/v1/healthz` or any other
//! route.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;

/// Cookie name used for the OAuth CSRF state.
pub const STATE_COOKIE_NAME: &str = "lepre_oauth_state";

/// `Path` attribute used for set + delete (must match for the deletion to take).
pub const STATE_COOKIE_PATH: &str = "/v1/auth/strava";
pub const SESSION_COOKIE_NAME: &str = "lepre_session";

const STATE_COOKIE_MAX_AGE_SECONDS: u32 = 600;

/// Mint a 32-byte random state value, base64url-encoded (no padding).
///
/// Uses `rand::rng()`, which is seeded from the OS CSPRNG.
pub fn mint_state() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `Set-Cookie` header value for the *initial* state cookie set by `/start`.
pub fn set_state_cookie(state: &str) -> String {
    format!(
        "{name}={state}; Path={path}; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax",
        name = STATE_COOKIE_NAME,
        path = STATE_COOKIE_PATH,
        max_age = STATE_COOKIE_MAX_AGE_SECONDS,
    )
}

/// `Set-Cookie` header value for *clearing* the state cookie.
///
/// Path must match the original; omitting `Domain=` for both set and clear
/// keeps the cookie host-only.
pub fn clear_state_cookie() -> &'static str {
    concat!(
        "lepre_oauth_state=; Path=/v1/auth/strava; Max-Age=0; ",
        "Secure; HttpOnly; SameSite=Lax",
    )
}

/// Read the value of `lepre_oauth_state` from a `Cookie:` header value, if present.
pub fn read_state_cookie(cookie_header: &str) -> Option<String> {
    read_cookie(cookie_header, STATE_COOKIE_NAME)
}

pub fn read_session_cookie(cookie_header: &str) -> Option<String> {
    read_cookie(cookie_header, SESSION_COOKIE_NAME)
}

fn read_cookie(cookie_header: &str, name: &str) -> Option<String> {
    cookie_header.split(';').map(str::trim).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == name { Some(v.to_owned()) } else { None }
    })
}

pub fn set_session_cookie(session: &str) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={session}; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Lax"
    )
}

pub fn clear_session_cookie() -> &'static str {
    "lepre_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_state_is_base64url_no_padding() {
        let s = mint_state();
        assert!(!s.contains('='), "no padding expected: {s}");
        assert!(!s.contains('+'), "url-safe alphabet expected: {s}");
        assert!(!s.contains('/'), "url-safe alphabet expected: {s}");
        // 32 bytes -> 43 base64url chars unpadded.
        assert_eq!(s.len(), 43);
    }

    #[test]
    fn mint_state_is_unique_across_calls() {
        let a = mint_state();
        let b = mint_state();
        assert_ne!(a, b);
    }

    #[test]
    fn set_state_cookie_omits_domain_attribute() {
        let header = set_state_cookie("xyz");
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/v1/auth/strava"));
        assert!(header.contains("Max-Age=600"));
        assert!(
            !header.contains("Domain="),
            "host-only — no Domain= allowed"
        );
    }

    #[test]
    fn clear_state_cookie_matches_set_path_and_zeroes_max_age() {
        let header = clear_state_cookie();
        assert!(header.contains("Path=/v1/auth/strava"));
        assert!(header.contains("Max-Age=0"));
        assert!(!header.contains("Domain="));
    }

    #[test]
    fn read_state_cookie_extracts_value_among_multiple_cookies() {
        let h = "foo=bar; lepre_oauth_state=abc123; baz=qux";
        assert_eq!(read_state_cookie(h), Some("abc123".to_owned()));
    }

    #[test]
    fn read_state_cookie_returns_none_when_absent() {
        assert_eq!(read_state_cookie("foo=bar; baz=qux"), None);
        assert_eq!(read_state_cookie(""), None);
    }
}
