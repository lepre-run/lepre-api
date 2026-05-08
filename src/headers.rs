//! Security headers added to every Lambda response (ADR 001 §2).
//!
//! Three headers, applied uniformly:
//! - `Strict-Transport-Security` — long-lived HTTPS enforcement.
//! - `X-Content-Type-Options: nosniff` — disables MIME sniffing.
//! - `Referrer-Policy: strict-origin-when-cross-origin` — strips path/query
//!   on cross-origin requests; normalises across browsers (Safari's
//!   default differs from Chrome/Firefox).

use http::header::{HeaderName, HeaderValue};
use http::response::Builder;

const HSTS: (HeaderName, &str) = (
    http::header::STRICT_TRANSPORT_SECURITY,
    "max-age=63072000; includeSubDomains; preload",
);
const X_CONTENT_TYPE_OPTIONS: (HeaderName, &str) =
    (HeaderName::from_static("x-content-type-options"), "nosniff");
const REFERRER_POLICY: (HeaderName, &str) = (
    HeaderName::from_static("referrer-policy"),
    "strict-origin-when-cross-origin",
);

/// Apply the standard security headers to a response builder.
pub fn apply(builder: Builder) -> Builder {
    builder
        .header(HSTS.0.clone(), HeaderValue::from_static(HSTS.1))
        .header(
            X_CONTENT_TYPE_OPTIONS.0.clone(),
            HeaderValue::from_static(X_CONTENT_TYPE_OPTIONS.1),
        )
        .header(
            REFERRER_POLICY.0.clone(),
            HeaderValue::from_static(REFERRER_POLICY.1),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_sets_all_three_security_headers() {
        let resp = apply(http::Response::builder())
            .status(200)
            .body(())
            .unwrap();

        assert_eq!(
            resp.headers()
                .get(http::header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            "max-age=63072000; includeSubDomains; preload"
        );
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get("referrer-policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }
}
