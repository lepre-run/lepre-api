//! Provider-independent entities and value objects.

use std::fmt;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("domain value cannot be empty")]
    EmptyValue,
    #[error("workout duration or distance is invalid")]
    InvalidMeasurement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunSport {
    Run,
    TrailRun,
    VirtualRun,
}

impl RunSport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::TrailRun => "TrailRun",
            Self::VirtualRun => "VirtualRun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkoutType {
    Workout,
    Race,
}

impl WorkoutType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workout => "workout",
            Self::Race => "race",
        }
    }
}

macro_rules! string_value {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into().trim().to_owned();
                if value.is_empty() {
                    return Err(DomainError::EmptyValue);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

string_value!(UserId);
string_value!(ConnectionId);
string_value!(ExternalAccountId);
string_value!(WorkoutId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderId {
    Strava,
}

impl ProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strava => "strava",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConnection {
    pub id: ConnectionId,
    pub provider: ProviderId,
    pub external_account_id: ExternalAccountId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub first_name: String,
    pub last_name: String,
    pub connection: ProviderConnection,
}

impl User {
    pub fn new(
        id: UserId,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
        connection: ProviderConnection,
    ) -> Result<Self, DomainError> {
        let first_name = first_name.into().trim().to_owned();
        let last_name = last_name.into().trim().to_owned();
        if first_name.is_empty() || last_name.is_empty() {
            return Err(DomainError::EmptyValue);
        }
        Ok(Self {
            id,
            first_name,
            last_name,
            connection,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Lap {
    pub index: i64,
    pub name: String,
    pub moving_duration_seconds: i64,
    pub elapsed_duration_seconds: i64,
    pub distance_meters: f64,
}

impl Lap {
    pub fn new(
        index: i64,
        name: impl Into<String>,
        moving_duration_seconds: i64,
        elapsed_duration_seconds: i64,
        distance_meters: f64,
    ) -> Result<Self, DomainError> {
        let name = name.into();
        if index < 1 || name.trim().is_empty() {
            return Err(DomainError::EmptyValue);
        }
        if moving_duration_seconds < 0
            || elapsed_duration_seconds < 0
            || !distance_meters.is_finite()
            || distance_meters < 0.0
        {
            return Err(DomainError::InvalidMeasurement);
        }
        Ok(Self {
            index,
            name,
            moving_duration_seconds,
            elapsed_duration_seconds,
            distance_meters,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Workout {
    pub id: WorkoutId,
    pub performed_at: String,
    pub name: String,
    pub description: String,
    pub workout_type: WorkoutType,
    pub sport: RunSport,
    pub duration_seconds: i64,
    pub elapsed_duration_seconds: i64,
    pub distance_meters: f64,
    pub laps: Vec<Lap>,
}

pub struct WorkoutData {
    pub id: WorkoutId,
    pub performed_at: String,
    pub name: String,
    pub description: String,
    pub workout_type: WorkoutType,
    pub sport: RunSport,
    pub duration_seconds: i64,
    pub elapsed_duration_seconds: i64,
    pub distance_meters: f64,
    pub laps: Vec<Lap>,
}

impl Workout {
    pub fn new(data: WorkoutData) -> Result<Self, DomainError> {
        if data.performed_at.trim().is_empty() || data.name.trim().is_empty() {
            return Err(DomainError::EmptyValue);
        }
        if data.duration_seconds < 0
            || data.elapsed_duration_seconds < 0
            || !data.distance_meters.is_finite()
            || data.distance_meters < 0.0
        {
            return Err(DomainError::InvalidMeasurement);
        }
        Ok(Self {
            id: data.id,
            performed_at: data.performed_at,
            name: data.name,
            description: data.description,
            workout_type: data.workout_type,
            sport: data.sport,
            duration_seconds: data.duration_seconds,
            elapsed_duration_seconds: data.elapsed_duration_seconds,
            distance_meters: data.distance_meters,
            laps: data.laps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workout_contains_only_agreed_content_and_identity() {
        let workout = Workout::new(WorkoutData {
            id: WorkoutId::new("strava:7").unwrap(),
            performed_at: "2026-07-15T06:00:00Z".to_owned(),
            name: "Morning Run".to_owned(),
            description: "Track session".to_owned(),
            workout_type: WorkoutType::Workout,
            sport: RunSport::Run,
            duration_seconds: 3600,
            elapsed_duration_seconds: 3700,
            distance_meters: 10_000.0,
            laps: vec![Lap::new(1, "Lap 1", 3600, 3700, 10_000.0).unwrap()],
        })
        .unwrap();
        assert_eq!(workout.duration_seconds, 3600);
        assert_eq!(workout.distance_meters, 10_000.0);
    }

    #[test]
    fn invalid_measurements_cannot_enter_domain() {
        let result = Workout::new(WorkoutData {
            id: WorkoutId::new("strava:7").unwrap(),
            performed_at: "2026-07-15T06:00:00Z".to_owned(),
            name: "Morning Run".to_owned(),
            description: String::new(),
            workout_type: WorkoutType::Workout,
            sport: RunSport::Run,
            duration_seconds: -1,
            elapsed_duration_seconds: -1,
            distance_meters: f64::NAN,
            laps: Vec::new(),
        });
        assert_eq!(result.unwrap_err(), DomainError::InvalidMeasurement);
    }
}
