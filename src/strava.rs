//! Minimal Strava client. Only activity id, date and name leave this module.

use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

const TOKEN_URL: &str = "https://www.strava.com/oauth/token";
const DEAUTHORIZE_URL: &str = "https://www.strava.com/oauth/deauthorize";
const ACTIVITIES_URL: &str = "https://www.strava.com/api/v3/athlete/activities";
const ACTIVITY_URL: &str = "https://www.strava.com/api/v3/activities";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn http_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .build()?)
}

#[derive(serde::Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    grant_type: &'static str,
}

#[derive(serde::Serialize)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    refresh_token: &'a str,
    grant_type: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub athlete: Athlete,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshedToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Athlete {
    pub id: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Workout {
    pub id: i64,
    pub name: String,
    #[serde(rename(deserialize = "start_date"))]
    pub date: String,
}

pub async fn exchange_code(
    client: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<TokenResponse, anyhow::Error> {
    checked_json(
        client
            .post(token_url)
            .form(&TokenRequest {
                client_id,
                client_secret,
                code,
                grant_type: "authorization_code",
            })
            .send()
            .await?,
    )
    .await
}

pub async fn refresh_token(
    client: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<RefreshedToken, anyhow::Error> {
    checked_json(
        client
            .post(token_url)
            .form(&RefreshRequest {
                client_id,
                client_secret,
                refresh_token,
                grant_type: "refresh_token",
            })
            .send()
            .await?,
    )
    .await
}

pub async fn activities(
    client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
    after: i64,
) -> Result<Vec<Workout>, anyhow::Error> {
    let mut workouts = Vec::new();
    for page in 1..=30 {
        let response = client
            .get(base_url)
            .bearer_auth(access_token)
            .query(&[("after", after), ("page", page), ("per_page", 200)])
            .send()
            .await?;
        let batch: Vec<Workout> = checked_json(response).await?;
        let done = batch.len() < 200;
        workouts.extend(batch);
        if done {
            return Ok(workouts);
        }
    }
    anyhow::bail!("activity import exceeded 6000 activities")
}

pub async fn activity(
    client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
    id: i64,
) -> Result<Option<Workout>, anyhow::Error> {
    let response = client
        .get(format!("{base_url}/{id}"))
        .bearer_auth(access_token)
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(checked_json(response).await?))
}

pub async fn deauthorize(
    client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<(), anyhow::Error> {
    let response = client
        .post(base_url)
        .bearer_auth(access_token)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("strava deauthorize returned {}", response.status())
    }
    Ok(())
}

async fn checked_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, anyhow::Error> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("strava returned {status}: {body}")
    }
    response.json().await.context("invalid Strava response")
}

pub fn token_url() -> &'static str {
    TOKEN_URL
}
pub fn deauthorize_url() -> &'static str {
    DEAUTHORIZE_URL
}
pub fn activities_url() -> &'static str {
    ACTIVITIES_URL
}
pub fn activity_url() -> &'static str {
    ACTIVITY_URL
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exchange_and_refresh_use_expected_grants() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token":"a", "refresh_token":"r", "expires_at":9, "athlete":{"id":42}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let token = exchange_code(&http_client().unwrap(), &server.uri(), "c", "s", "code")
            .await
            .unwrap();
        assert_eq!(token.athlete.id, 42);

        server.reset().await;
        Mock::given(method("POST"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token":"a2", "refresh_token":"r2", "expires_at":10
            })))
            .expect(1)
            .mount(&server)
            .await;
        let token = refresh_token(&http_client().unwrap(), &server.uri(), "c", "s", "r")
            .await
            .unwrap();
        assert_eq!(token.refresh_token, "r2");
    }

    #[tokio::test]
    async fn activities_keep_only_minimum_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/activities"))
            .and(query_param("after", "0")).and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "id":7, "name":"Morning Run", "start_date":"2026-07-15T06:00:00Z", "distance":12000
            }]))).mount(&server).await;
        let got = activities(
            &http_client().unwrap(),
            &format!("{}/activities", server.uri()),
            "token",
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            vec![Workout {
                id: 7,
                name: "Morning Run".into(),
                date: "2026-07-15T06:00:00Z".into()
            }]
        );
    }
}
