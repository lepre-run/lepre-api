//! Strava OAuth client (ADR 001 §2): token exchange and best-effort
//! deauthorize. Both calls use an explicit short timeout and no automatic
//! retry — the OAuth `code` is single-use, so retrying on a network blip
//! risks an unrecoverable state.

use std::time::Duration;

use serde::Deserialize;

const STRAVA_TOKEN_URL: &str = "https://www.strava.com/oauth/token";
const STRAVA_DEAUTHORIZE_URL: &str = "https://www.strava.com/oauth/deauthorize";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the shared HTTP client with the project-wide timeout.
pub fn http_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(HTTP_TIMEOUT)
        .build()?)
}

/// Body posted to `https://www.strava.com/oauth/token`.
#[derive(serde::Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    grant_type: &'static str,
}

/// Subset of Strava's token response we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Token expiry as Unix epoch seconds.
    pub expires_at: i64,
    pub athlete: Athlete,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Athlete {
    pub id: i64,
}

/// Exchange a single-use authorization `code` for tokens.
///
/// Caller-supplied `base_url` enables wiremock'd integration tests; the real
/// runtime uses the constant.
pub async fn exchange_code(
    client: &reqwest::Client,
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<TokenResponse, anyhow::Error> {
    let body = TokenRequest {
        client_id,
        client_secret,
        code,
        grant_type: "authorization_code",
    };

    let resp = client.post(base_url).form(&body).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("strava /oauth/token returned {status}: {body_text}");
    }
    Ok(resp.json::<TokenResponse>().await?)
}

/// Best-effort `POST /oauth/deauthorize`. Errors are logged and swallowed by
/// the caller — failure to deauthorize must not block the user's
/// failure-page redirect.
pub async fn deauthorize(
    client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<(), anyhow::Error> {
    let resp = client
        .post(base_url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("strava /oauth/deauthorize returned {status}");
    }
    Ok(())
}

/// Public token endpoint URL (used by `main.rs`; tests override).
pub fn token_url() -> &'static str {
    STRAVA_TOKEN_URL
}

/// Public deauthorize endpoint URL (used by `main.rs`; tests override).
pub fn deauthorize_url() -> &'static str {
    STRAVA_DEAUTHORIZE_URL
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exchange_code_posts_form_body_with_required_fields() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("client_id=cid"))
            .and(body_string_contains("client_secret=csec"))
            .and(body_string_contains("code=abc"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "atk",
                "refresh_token": "rtk",
                "expires_at": 1_900_000_000_i64,
                "athlete": { "id": 42 },
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = http_client().unwrap();
        let r = exchange_code(&client, &server.uri(), "cid", "csec", "abc")
            .await
            .unwrap();
        assert_eq!(r.access_token, "atk");
        assert_eq!(r.refresh_token, "rtk");
        assert_eq!(r.expires_at, 1_900_000_000);
        assert_eq!(r.athlete.id, 42);
    }

    #[tokio::test]
    async fn exchange_code_errors_on_non_2xx() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&server)
            .await;

        let client = http_client().unwrap();
        let err = exchange_code(&client, &server.uri(), "cid", "csec", "abc")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("400"));
    }

    #[tokio::test]
    async fn exchange_code_errors_on_timeout() {
        use std::time::Instant;

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(8)))
            .mount(&server)
            .await;

        let client = http_client().unwrap();
        let start = Instant::now();
        let _err = exchange_code(&client, &server.uri(), "cid", "csec", "abc")
            .await
            .expect_err("expected a timeout error");
        let elapsed = start.elapsed();

        // 5 s timeout (HTTP_TIMEOUT) — fires before the 8 s wiremock delay.
        assert!(
            elapsed < Duration::from_secs(7),
            "exchange_code took {elapsed:?}, expected to fail within ~5s"
        );
    }

    #[tokio::test]
    async fn deauthorize_posts_bearer_authorization() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer atk-xyz",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = http_client().unwrap();
        deauthorize(&client, &server.uri(), "atk-xyz")
            .await
            .unwrap();
    }
}
