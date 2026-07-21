//! Strava outbound adapter. Strava DTOs never leave this module.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt, stream};
use reqwest::header::RETRY_AFTER;
use serde::{Deserialize, Serialize};

use crate::application::{
    AuthorizedProviderAccount, Provider, ProviderCredentials, ProviderRateLimited,
    ProviderWorkoutPage,
};
use crate::domain::{
    ExternalAccountId, Lap, RunSport, Workout, WorkoutData, WorkoutId, WorkoutType,
};

const AUTHORIZE_URL: &str = "https://www.strava.com/oauth/authorize";
const TOKEN_URL: &str = "https://www.strava.com/oauth/token";
const DEAUTHORIZE_URL: &str = "https://www.strava.com/oauth/deauthorize";
const ACTIVITIES_URL: &str = "https://www.strava.com/api/v3/athlete/activities";
const ACTIVITY_URL: &str = "https://www.strava.com/api/v3/activities";
const REDIRECT_URI: &str = "https://api.lepre.run/v1/auth/strava/callback";
const REQUIRED_SCOPES: &[&str] = &["read", "activity:read_all"];
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const ACTIVITY_PAGE_SIZE: i64 = 10;
const DETAIL_CONCURRENCY: usize = 4;
const DEFAULT_RATE_LIMIT_RETRY_SECONDS: u64 = 15 * 60;

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
    activities: String,
    activity: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            authorize: AUTHORIZE_URL.to_owned(),
            token: TOKEN_URL.to_owned(),
            deauthorize: DEAUTHORIZE_URL.to_owned(),
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
struct SummaryActivityDto {
    id: i64,
    sport_type: String,
}

#[derive(Deserialize)]
struct DetailedActivityDto {
    id: i64,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    workout_type: Option<i64>,
    sport_type: String,
    start_date: String,
    moving_time: i64,
    elapsed_time: i64,
    distance: f64,
    #[serde(default)]
    average_heartrate: Option<f64>,
    #[serde(default)]
    max_heartrate: Option<f64>,
    #[serde(default)]
    laps: Vec<LapDto>,
}

#[derive(Deserialize)]
struct LapDto {
    lap_index: i64,
    name: String,
    moving_time: i64,
    elapsed_time: i64,
    distance: f64,
    #[serde(default)]
    average_heartrate: Option<f64>,
    #[serde(default)]
    max_heartrate: Option<f64>,
}

fn run_sport(value: &str) -> Option<RunSport> {
    match value {
        "Run" => Some(RunSport::Run),
        "TrailRun" => Some(RunSport::TrailRun),
        "VirtualRun" => Some(RunSport::VirtualRun),
        _ => None,
    }
}

fn run_workout_type(value: Option<i64>) -> WorkoutType {
    match value {
        Some(1) => WorkoutType::Race,
        _ => WorkoutType::Workout,
    }
}

impl DetailedActivityDto {
    fn into_domain(self) -> Result<Option<Workout>, anyhow::Error> {
        let Some(sport) = run_sport(&self.sport_type) else {
            return Ok(None);
        };
        let laps = self
            .laps
            .into_iter()
            .map(|lap| {
                Lap::new(
                    lap.lap_index,
                    lap.name,
                    lap.moving_time,
                    lap.elapsed_time,
                    lap.distance,
                    lap.average_heartrate,
                    lap.max_heartrate,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Workout::new(WorkoutData {
            id: WorkoutId::new(format!("strava:{}", self.id))?,
            performed_at: self.start_date,
            name: self.name,
            description: self.description.unwrap_or_default(),
            workout_type: run_workout_type(self.workout_type),
            sport,
            duration_seconds: self.moving_time,
            elapsed_duration_seconds: self.elapsed_time,
            distance_meters: self.distance,
            average_heart_rate_bpm: self.average_heartrate,
            max_heart_rate_bpm: self.max_heartrate,
            laps,
        })?
        .into())
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

    async fn workouts(
        &self,
        access_token: &str,
        after: i64,
        before: i64,
        page: i64,
    ) -> Result<ProviderWorkoutPage, anyhow::Error> {
        let activities: Vec<SummaryActivityDto> = checked_json(
            self.client
                .get(&self.endpoints.activities)
                .bearer_auth(access_token)
                .query(&[
                    ("after", after),
                    ("before", before),
                    ("page", page),
                    ("per_page", ACTIVITY_PAGE_SIZE),
                ])
                .send()
                .await?,
        )
        .await?;
        let has_more = activities.len() == ACTIVITY_PAGE_SIZE as usize;
        let ids = activities
            .into_iter()
            .filter(|activity| run_sport(&activity.sport_type).is_some())
            .map(|activity| activity.id);
        let workouts = stream::iter(ids)
            .map(|id| async move { self.detailed_workout(access_token, id).await })
            .buffered(DETAIL_CONCURRENCY)
            .try_collect::<Vec<Option<Workout>>>()
            .await?
            .into_iter()
            .flatten()
            .collect();
        Ok(ProviderWorkoutPage { workouts, has_more })
    }

    async fn workout(
        &self,
        access_token: &str,
        external_workout_id: i64,
    ) -> Result<Option<Workout>, anyhow::Error> {
        self.detailed_workout(access_token, external_workout_id)
            .await
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

impl StravaProvider {
    async fn detailed_workout(
        &self,
        access_token: &str,
        external_workout_id: i64,
    ) -> Result<Option<Workout>, anyhow::Error> {
        let response = self
            .client
            .get(format!("{}/{external_workout_id}", self.endpoints.activity))
            .bearer_auth(access_token)
            .query(&[("include_all_efforts", false)])
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let activity: DetailedActivityDto = checked_json(response).await?;
        activity.into_domain()
    }
}

async fn checked_json<Value: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<Value, anyhow::Error> {
    let status = response.status();
    if !status.is_success() {
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after_seconds = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT_RATE_LIMIT_RETRY_SECONDS);
            return Err(ProviderRateLimited {
                retry_after_seconds,
            }
            .into());
        }
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
    async fn running_activities_include_descriptions_and_laps() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .and(query_param("after", "0"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id":7, "sport_type":"Run"
                }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":7, "name":"Morning Run", "description":"Track session",
                "workout_type":1, "sport_type":"Run", "start_date":"2026-07-15T06:00:00Z",
                "moving_time":3600, "elapsed_time":3700, "distance":10050.5,
                "average_heartrate":148.2, "max_heartrate":176.0,
                "laps":[{
                    "lap_index":1, "name":"Lap 1", "moving_time":3600,
                    "elapsed_time":3700, "distance":10050.5,
                    "average_heartrate":148.2, "max_heartrate":176.0
                }]
            })))
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        let workouts = page.workouts;
        assert_eq!(workouts[0].id.as_str(), "strava:7");
        assert_eq!(workouts[0].duration_seconds, 3600);
        assert_eq!(workouts[0].distance_meters, 10050.5);
        assert_eq!(workouts[0].description, "Track session");
        assert_eq!(workouts[0].workout_type, WorkoutType::Race);
        assert_eq!(workouts[0].average_heart_rate_bpm, Some(148.2));
        assert_eq!(workouts[0].max_heart_rate_bpm, Some(176.0));
        assert_eq!(workouts[0].laps[0].index, 1);
        assert_eq!(workouts[0].laps[0].average_heart_rate_bpm, Some(148.2));
        assert!(!page.has_more);
    }

    #[test]
    fn only_strava_races_are_normalized_as_races() {
        assert_eq!(run_workout_type(Some(1)), WorkoutType::Race);
        assert_eq!(run_workout_type(None), WorkoutType::Workout);
        assert_eq!(run_workout_type(Some(0)), WorkoutType::Workout);
        assert_eq!(run_workout_type(Some(2)), WorkoutType::Workout);
        assert_eq!(run_workout_type(Some(3)), WorkoutType::Workout);
        assert_eq!(run_workout_type(Some(99)), WorkoutType::Workout);
    }

    #[tokio::test]
    async fn non_running_activities_are_not_detailed_or_returned() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id":8, "sport_type":"Ride"
                }])),
            )
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert!(page.workouts.is_empty());
    }

    #[tokio::test]
    async fn rate_limits_are_reported_explicitly() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "120")
                    .set_body_json(serde_json::json!({"message":"Rate Limit Exceeded"})),
            )
            .mount(&server)
            .await;

        let error = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap_err();
        let rate_limit = error.downcast_ref::<ProviderRateLimited>().unwrap();
        assert_eq!(rate_limit.retry_after_seconds, 120);
    }
}
