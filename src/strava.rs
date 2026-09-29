//! Strava outbound adapter. Strava DTOs never leave this module.

use std::collections::HashSet;
use std::time::{Duration, Instant};

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
    DomainError, ExternalAccountId, Lap, RunSport, Workout, WorkoutData, WorkoutId, WorkoutType,
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
    #[serde(default)]
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
    #[serde(default)]
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
    /// Map a Strava detailed activity into a domain workout.
    ///
    /// Empty optional string fields from Strava (`name`, lap `name`) are
    /// normalized to safe defaults with a WARN that names the field only.
    /// Empty `start_date`, `lap_index < 1`, and invalid measurements skip the
    /// activity (WARN with field/reason) instead of failing the whole sync page.
    fn into_domain(self) -> Result<Option<Workout>, anyhow::Error> {
        let Some(sport) = run_sport(&self.sport_type) else {
            return Ok(None);
        };
        let performed_at = self.start_date.trim().to_owned();
        if performed_at.is_empty() {
            return skip_activity(self.id, "start_date", "empty_value");
        }
        if self.laps.iter().any(|lap| lap.lap_index < 1) {
            return skip_activity(self.id, "laps[].lap_index", "lap_index_lt_1");
        }
        let name = nonempty_or_default(self.name, "name", self.id, "Untitled");
        let laps = match self
            .laps
            .into_iter()
            .map(|lap| {
                let index = lap.lap_index;
                let lap_name =
                    nonempty_or_default(lap.name, "laps[].name", self.id, format!("Lap {index}"));
                Lap::new(
                    index,
                    lap_name,
                    lap.moving_time,
                    lap.elapsed_time,
                    lap.distance,
                    lap.average_heartrate,
                    lap.max_heartrate,
                )
            })
            .collect::<Result<Vec<_>, DomainError>>()
        {
            Ok(laps) => laps,
            Err(DomainError::EmptyValue) => {
                return skip_activity(self.id, "laps", "empty_value");
            }
            Err(DomainError::InvalidMeasurement) => {
                return skip_activity(self.id, "laps", "invalid_measurement");
            }
        };
        match Workout::new(WorkoutData {
            id: WorkoutId::new(format!("strava:{}", self.id))?,
            performed_at,
            name,
            description: self.description.unwrap_or_default(),
            workout_type: run_workout_type(self.workout_type),
            sport,
            duration_seconds: self.moving_time,
            elapsed_duration_seconds: self.elapsed_time,
            distance_meters: self.distance,
            average_heart_rate_bpm: self.average_heartrate,
            max_heart_rate_bpm: self.max_heartrate,
            laps,
        }) {
            Ok(workout) => Ok(Some(workout)),
            Err(DomainError::EmptyValue) => skip_activity(self.id, "activity", "empty_value"),
            Err(DomainError::InvalidMeasurement) => {
                skip_activity(self.id, "measurement", "invalid_measurement")
            }
        }
    }
}

/// Skip one activity after a domain reject; WARN with field/reason only (no PII).
fn skip_activity(
    activity_id: i64,
    field: &'static str,
    reason: &'static str,
) -> Result<Option<Workout>, anyhow::Error> {
    tracing::warn!(
        event = "strava_activity_skipped",
        field,
        reason,
        activity_id,
        "skipping Strava activity rejected by domain mapping"
    );
    Ok(None)
}

/// Trim `value`; if empty, WARN with the Strava field name and return `default`.
fn nonempty_or_default(
    value: impl Into<String>,
    field: &'static str,
    activity_id: i64,
    default: impl Into<String>,
) -> String {
    let trimmed = value.into().trim().to_owned();
    if trimmed.is_empty() {
        tracing::warn!(
            event = "strava_empty_optional_field",
            field,
            activity_id,
            "empty Strava optional field; using default"
        );
        default.into()
    } else {
        trimmed
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
        let started = Instant::now();
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
            "authorize",
            started,
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
        let started = Instant::now();
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
            "refresh_token",
            started,
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
        let started = Instant::now();
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
            "list_activities",
            started,
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
        let started = Instant::now();
        let response = self
            .client
            .post(&self.endpoints.deauthorize)
            .bearer_auth(access_token)
            .send()
            .await?;
        record_response(&response, "deauthorize", started);
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
        let started = Instant::now();
        let response = self
            .client
            .get(format!("{}/{external_workout_id}", self.endpoints.activity))
            .bearer_auth(access_token)
            .query(&[("include_all_efforts", false)])
            .send()
            .await?;
        record_response(&response, "activity_detail", started);
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let activity: DetailedActivityDto = checked_json_body(response).await?;
        activity.into_domain()
    }
}

async fn checked_json<Value: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    endpoint: &'static str,
    started: Instant,
) -> Result<Value, anyhow::Error> {
    record_response(&response, endpoint, started);
    checked_json_body(response).await
}

async fn checked_json_body<Value: for<'de> Deserialize<'de>>(
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

fn record_response(response: &reqwest::Response, endpoint: &'static str, started: Instant) {
    let (overall_limit_15_minutes, overall_limit_daily) =
        rate_limit_pair(response, "x-ratelimit-limit");
    let (overall_usage_15_minutes, overall_usage_daily) =
        rate_limit_pair(response, "x-ratelimit-usage");
    let (read_limit_15_minutes, read_limit_daily) =
        rate_limit_pair(response, "x-readratelimit-limit");
    let (read_usage_15_minutes, read_usage_daily) =
        rate_limit_pair(response, "x-readratelimit-usage");
    tracing::info!(
        event = "strava_api_call",
        endpoint,
        status = response.status().as_u16(),
        latency_ms = started.elapsed().as_millis() as u64,
        overall_limit_15_minutes,
        overall_limit_daily,
        overall_usage_15_minutes,
        overall_usage_daily,
        read_limit_15_minutes,
        read_limit_daily,
        read_usage_15_minutes,
        read_usage_daily,
        "received a Strava API response"
    );
}

fn rate_limit_pair(response: &reqwest::Response, header: &str) -> (i64, i64) {
    let mut values = response
        .headers()
        .get(header)
        .and_then(|value| value.to_str().ok())
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.trim().parse::<i64>().ok());
    (values.next().unwrap_or(-1), values.next().unwrap_or(-1))
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
    async fn empty_optional_activity_and_lap_names_use_defaults() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id":9, "sport_type":"Run"
                }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/9"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":9, "name":"  ", "description":null,
                "workout_type":0, "sport_type":"Run", "start_date":"2026-09-01T07:00:00Z",
                "moving_time":1800, "elapsed_time":1900, "distance":5000.0,
                "laps":[{
                    "lap_index":1, "name":"", "moving_time":1800,
                    "elapsed_time":1900, "distance":5000.0
                }]
            })))
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert_eq!(page.workouts.len(), 1);
        assert_eq!(page.workouts[0].id.as_str(), "strava:9");
        assert_eq!(page.workouts[0].name, "Untitled");
        assert_eq!(page.workouts[0].description, "");
        assert_eq!(page.workouts[0].laps[0].name, "Lap 1");
    }

    #[tokio::test]
    async fn empty_start_date_skips_activity_instead_of_failing_sync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id":10, "sport_type":"Run"
                }])),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":10, "name":"Ghost Run", "sport_type":"Run", "start_date":"   ",
                "moving_time":600, "elapsed_time":600, "distance":1000.0,
                "laps":[]
            })))
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert!(page.workouts.is_empty());
    }

    #[tokio::test]
    async fn omitted_activity_name_field_deserializes_empty_and_defaults() {
        // Omitted `name` deserializes via #[serde(default)] then defaults to Untitled.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activity/11"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":11, "sport_type":"TrailRun",
                "start_date":"2026-09-02T08:00:00Z",
                "moving_time":900, "elapsed_time":950, "distance":3000.0,
                "laps":[]
            })))
            .mount(&server)
            .await;
        let workout = StravaProvider::with_base_url(&server.uri())
            .workout("token", 11)
            .await
            .unwrap()
            .expect("mapped workout");
        assert_eq!(workout.name, "Untitled");
        assert_eq!(workout.sport, RunSport::TrailRun);
    }

    #[tokio::test]
    async fn lap_index_below_one_skips_activity_instead_of_failing_sync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id":12, "sport_type":"Run"},
                {"id":13, "sport_type":"Run"}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/12"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":12, "name":"Bad Lap Index", "sport_type":"Run",
                "start_date":"2026-09-03T07:00:00Z",
                "moving_time":600, "elapsed_time":600, "distance":1000.0,
                "laps":[{
                    "lap_index":0, "name":"Lap 0", "moving_time":600,
                    "elapsed_time":600, "distance":1000.0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/13"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":13, "name":"Good Run", "sport_type":"Run",
                "start_date":"2026-09-03T08:00:00Z",
                "moving_time":900, "elapsed_time":900, "distance":2000.0,
                "laps":[{
                    "lap_index":1, "name":"Lap 1", "moving_time":900,
                    "elapsed_time":900, "distance":2000.0
                }]
            })))
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert_eq!(page.workouts.len(), 1);
        assert_eq!(page.workouts[0].id.as_str(), "strava:13");
    }

    #[tokio::test]
    async fn invalid_measurement_skips_activity_instead_of_failing_sync() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/activities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id":14, "sport_type":"Run"},
                {"id":15, "sport_type":"Run"},
                {"id":16, "sport_type":"Run"}
            ])))
            .mount(&server)
            .await;
        // Activity-level InvalidMeasurement (negative duration).
        Mock::given(method("GET"))
            .and(path("/activity/14"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":14, "name":"Negative Duration", "sport_type":"Run",
                "start_date":"2026-09-04T07:00:00Z",
                "moving_time":-1, "elapsed_time":600, "distance":1000.0,
                "laps":[]
            })))
            .mount(&server)
            .await;
        // Lap-level InvalidMeasurement (negative lap moving_time).
        Mock::given(method("GET"))
            .and(path("/activity/15"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":15, "name":"Bad Lap Measurement", "sport_type":"Run",
                "start_date":"2026-09-04T08:00:00Z",
                "moving_time":1200, "elapsed_time":1200, "distance":4000.0,
                "laps":[{
                    "lap_index":1, "name":"Lap 1", "moving_time":-1,
                    "elapsed_time":1200, "distance":4000.0
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/activity/16"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":16, "name":"Valid Sibling", "sport_type":"Run",
                "start_date":"2026-09-04T09:00:00Z",
                "moving_time":300, "elapsed_time":300, "distance":800.0,
                "laps":[]
            })))
            .mount(&server)
            .await;
        let page = StravaProvider::with_base_url(&server.uri())
            .workouts("token", 0, 1_800_000_000, 1)
            .await
            .unwrap();
        assert_eq!(page.workouts.len(), 1);
        assert_eq!(page.workouts[0].id.as_str(), "strava:16");
        assert_eq!(page.workouts[0].name, "Valid Sibling");
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
