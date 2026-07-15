//! Strava outbound adapter. Strava DTOs never leave this module.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::application::{
    AuthorizedProviderAccount, Provider, ProviderCredentials, ProviderProfile,
};
use crate::domain::{ExternalAccountId, Workout, WorkoutId};

const AUTHORIZE_URL: &str = "https://www.strava.com/oauth/authorize";
const TOKEN_URL: &str = "https://www.strava.com/oauth/token";
const DEAUTHORIZE_URL: &str = "https://www.strava.com/oauth/deauthorize";
const ATHLETE_URL: &str = "https://www.strava.com/api/v3/athlete";
const ACTIVITIES_URL: &str = "https://www.strava.com/api/v3/athlete/activities";
const ACTIVITY_URL: &str = "https://www.strava.com/api/v3/activities";
const REDIRECT_URI: &str = "https://api.lepre.run/v1/auth/strava/callback";
const REQUIRED_SCOPES: &[&str] = &["read", "activity:read_all"];
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct StravaProvider {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    endpoints: Endpoints,
}

#[derive(Clone)]
struct Endpoints {
    authorize: String,
    token: String,
    deauthorize: String,
    athlete: String,
    activities: String,
    activity: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            authorize: AUTHORIZE_URL.to_owned(),
            token: TOKEN_URL.to_owned(),
            deauthorize: DEAUTHORIZE_URL.to_owned(),
            athlete: ATHLETE_URL.to_owned(),
            activities: ACTIVITIES_URL.to_owned(),
            activity: ACTIVITY_URL.to_owned(),
        }
    }
}

impl StravaProvider {
    pub fn new(
        client: reqwest::Client,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            client,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            endpoints: Endpoints::default(),
        }
    }

    #[cfg(test)]
    fn with_base_url(base_url: &str) -> Self {
        Self {
            client: http_client().unwrap(),
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
            endpoints: Endpoints {
                authorize: format!("{base_url}/authorize"),
                token: format!("{base_url}/token"),
                deauthorize: format!("{base_url}/deauthorize"),
                athlete: format!("{base_url}/athlete"),
                activities: format!("{base_url}/activities"),
                activity: format!("{base_url}/activity"),
            },
        }
    }
}

pub fn http_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .build()?)
}

#[derive(Serialize)]
struct AuthorizeParams<'a> {
    client_id: &'a str,
    response_type: &'static str,
    redirect_uri: &'static str,
    scope: String,
    state: &'a str,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    grant_type: &'static str,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    refresh_token: &'a str,
    grant_type: &'static str,
}

#[derive(Deserialize)]
struct TokenResponseDto {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
    athlete: AthleteDto,
}

#[derive(Deserialize)]
struct RefreshedTokenDto {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct AthleteDto {
    id: i64,
    firstname: String,
    lastname: String,
}

#[derive(Deserialize)]
struct ActivityDto {
    id: i64,
    name: String,
    start_date: String,
    moving_time: i64,
    distance: f64,
}

impl ActivityDto {
    fn into_domain(self) -> Result<Workout, anyhow::Error> {
        Ok(Workout::new(
            WorkoutId::new(format!("strava:{}", self.id))?,
            self.start_date,
            self.name,
            self.moving_time,
            self.distance,
        )?)
    }
}

#[async_trait]
impl Provider for StravaProvider {
    fn authorization_url(&self, state: &str) -> String {
        let query = serde_urlencoded::to_string(AuthorizeParams {
            client_id: &self.client_id,
            response_type: "code",
            redirect_uri: REDIRECT_URI,
            scope: REQUIRED_SCOPES.join(","),
            state,
        })
        .expect("static authorization parameters");
        format!("{}?{query}", self.endpoints.authorize)
    }

    fn scopes_sufficient(&self, scopes: &str) -> bool {
        let granted: HashSet<_> = scopes.split(',').map(str::trim).collect();
        REQUIRED_SCOPES.iter().all(|scope| granted.contains(scope))
    }

    async fn authorize(&self, code: &str) -> Result<AuthorizedProviderAccount, anyhow::Error> {
        let response: TokenResponseDto = checked_json(
            self.client
                .post(&self.endpoints.token)
                .form(&TokenRequest {
                    client_id: &self.client_id,
                    client_secret: &self.client_secret,
                    code,
                    grant_type: "authorization_code",
                })
                .send()
                .await?,
        )
        .await?;
        Ok(AuthorizedProviderAccount {
            external_account_id: ExternalAccountId::new(response.athlete.id.to_string())?,
            first_name: response.athlete.firstname,
            last_name: response.athlete.lastname,
            credentials: ProviderCredentials {
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: response.expires_at,
            },
        })
    }

    async fn refresh(&self, refresh_token: &str) -> Result<ProviderCredentials, anyhow::Error> {
        let response: RefreshedTokenDto = checked_json(
            self.client
                .post(&self.endpoints.token)
                .form(&RefreshRequest {
                    client_id: &self.client_id,
                    client_secret: &self.client_secret,
                    refresh_token,
                    grant_type: "refresh_token",
                })
                .send()
                .await?,
        )
        .await?;
        Ok(ProviderCredentials {
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            expires_at: response.expires_at,
        })
    }

    async fn profile(&self, access_token: &str) -> Result<ProviderProfile, anyhow::Error> {
        let athlete: AthleteDto = checked_json(
            self.client
                .get(&self.endpoints.athlete)
                .bearer_auth(access_token)
                .send()
                .await?,
        )
        .await?;
        Ok(ProviderProfile {
            first_name: athlete.firstname,
            last_name: athlete.lastname,
        })
    }

    async fn workouts(
        &self,
        access_token: &str,
        after: i64,
        before: i64,
        page: i64,
    ) -> Result<Vec<Workout>, anyhow::Error> {
        let activities: Vec<ActivityDto> = checked_json(
            self.client
                .get(&self.endpoints.activities)
                .bearer_auth(access_token)
                .query(&[
                    ("after", after),
                    ("before", before),
                    ("page", page),
                    ("per_page", 200),
                ])
                .send()
                .await?,
        )
        .await?;
        activities
            .into_iter()
            .map(ActivityDto::into_domain)
            .collect()
    }

    async fn workout(
        &self,
        access_token: &str,
        external_workout_id: i64,
    ) -> Result<Option<Workout>, anyhow::Error> {
        let response = self
            .client
            .get(format!("{}/{external_workout_id}", self.endpoints.activity))
            .bearer_auth(access_token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let activity: ActivityDto = checked_json(response).await?;
        Ok(Some(activity.into_domain()?))
    }

    async fn deauthorize(&self, access_token: &str) -> Result<(), anyhow::Error> {
        let response = self
            .client
            .post(&self.endpoints.deauthorize)
            .bearer_auth(access_token)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("Strava deauthorization returned {}", response.status())
        }
        Ok(())
    }
}

async fn checked_json<Value: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<Value, anyhow::Error> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Strava returned {status}: {body}")
    }
    response.json().await.context("invalid Strava response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn authorization_is_least_privilege_and_supports_private_activities() {
        let provider = StravaProvider::new(http_client().unwrap(), "client", "secret");
        let url = provider.authorization_url("state");
        assert!(url.contains("scope=read%2Cactivity%3Aread_all"));
        assert!(!url.contains("profile%3Awrite"));
    }

    #[tokio::test]
    async fn authorization_maps_provider_profile_and_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token":"access", "refresh_token":"refresh", "expires_at":9,
                "athlete":{"id":42,"firstname":"Francesco","lastname":"Barbera"}
            })))
            .mount(&server)
            .await;
        let account = StravaProvider::with_base_url(&server.uri())
            .authorize("code")
            .await
            .unwrap();
        assert_eq!(account.external_account_id.as_str(), "42");
        assert_eq!(account.first_name, "Francesco");
    }

    #[tokio::test]
    async fn activities_map_seconds_and_meters_into_domain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .and(query_param("after", "0"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id":7, "name":"Morning Run", "start_date":"2026-07-15T06:00:00Z",
                    "moving_time":3600, "distance":10050.5
                }])),
            )
            .mount(&server)
            .await;
        let workouts = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert_eq!(workouts[0].id.as_str(), "strava:7");
        assert_eq!(workouts[0].duration_seconds, 3600);
        assert_eq!(workouts[0].distance_meters, 10050.5);
    }
}
