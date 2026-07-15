//! Callback exit helper (ADR 001 §2): every callback response is built here
//! so that the state cookie is *always* cleared with the matching `Path`.

use http::header::{LOCATION, SET_COOKIE};
use lambda_http::Body;
use lambda_http::Response;

use crate::cookie::{clear_state_cookie, set_session_cookie};
use crate::headers;

const APP_BASE: &str = "https://lepre.run";

/// Build a 302 to the given app path (e.g. `/connected` or
/// `/connect-failed?reason=...`), always sending `Set-Cookie` to clear the
/// state cookie.
pub fn redirect_with_cookie_clear(path_with_query: &str) -> Response<Body> {
    let location = format!("{APP_BASE}{path_with_query}");
    headers::apply(http::Response::builder())
        .status(302)
        .header(LOCATION, location)
        .header(SET_COOKIE, clear_state_cookie())
        .body(Body::Empty)
        .expect("static response builder shape always valid")
}

/// Sugar for the success path.
pub fn to_connected() -> Response<Body> {
    redirect_with_cookie_clear("/connected")
}

pub fn to_connected_with_session(session: &str) -> Response<Body> {
    let mut response = redirect_with_cookie_clear("/connected");
    response.headers_mut().append(
        SET_COOKIE,
        set_session_cookie(session)
            .parse()
            .expect("valid session cookie"),
    );
    response
}

/// Sugar for failure paths.
pub fn to_connect_failed(reason: &str) -> Response<Body> {
    redirect_with_cookie_clear(&format!("/connect-failed?reason={reason}"))
}

/// Failure with a correlation id (used for `db_failure`,
/// `strava_exchange_failed`).
pub fn to_connect_failed_with_id(reason: &str, id: &str) -> Response<Body> {
    redirect_with_cookie_clear(&format!("/connect-failed?reason={reason}&id={id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_value(resp: &Response<Body>) -> String {
        resp.headers()
            .get(SET_COOKIE)
            .expect("Set-Cookie missing")
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn location_value(resp: &Response<Body>) -> String {
        resp.headers()
            .get(LOCATION)
            .expect("Location missing")
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn to_connected_clears_cookie_and_points_at_app() {
        let r = to_connected();
        assert_eq!(r.status(), 302);
        assert_eq!(location_value(&r), "https://lepre.run/connected");
        let c = cookie_value(&r);
        assert!(c.contains("lepre_oauth_state="));
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("Path=/v1/auth/strava"));
    }

    #[test]
    fn to_connect_failed_carries_reason_and_clears_cookie() {
        let r = to_connect_failed("user_denied");
        assert_eq!(r.status(), 302);
        assert_eq!(
            location_value(&r),
            "https://lepre.run/connect-failed?reason=user_denied"
        );
        let c = cookie_value(&r);
        assert!(c.contains("Max-Age=0"));
    }

    #[test]
    fn to_connect_failed_with_id_appends_id_param() {
        let r = to_connect_failed_with_id("db_failure", "abc-123");
        assert_eq!(
            location_value(&r),
            "https://lepre.run/connect-failed?reason=db_failure&id=abc-123"
        );
    }

    #[test]
    fn redirect_carries_security_headers() {
        let r = to_connected();
        assert!(r.headers().contains_key("strict-transport-security"));
        assert!(r.headers().contains_key("x-content-type-options"));
        assert!(r.headers().contains_key("referrer-policy"));
    }

    #[test]
    fn every_failure_reason_clears_cookie_table_driven() {
        let reasons = [
            "user_denied",
            "state_invalid",
            "missing_code",
            "scope_insufficient",
            "unknown",
        ];
        for r in reasons {
            let resp = to_connect_failed(r);
            let c = cookie_value(&resp);
            assert!(
                c.contains("Max-Age=0"),
                "{r}: expected cookie cleared, got {c}"
            );
        }
    }
}
