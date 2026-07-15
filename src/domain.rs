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
pub struct Workout {
    pub id: WorkoutId,
    pub performed_at: String,
    pub name: String,
    pub duration_seconds: i64,
    pub distance_meters: f64,
}

impl Workout {
    pub fn new(
        id: WorkoutId,
        performed_at: impl Into<String>,
        name: impl Into<String>,
        duration_seconds: i64,
        distance_meters: f64,
    ) -> Result<Self, DomainError> {
        let performed_at = performed_at.into().trim().to_owned();
        let name = name.into().trim().to_owned();
        if performed_at.is_empty() || name.is_empty() {
            return Err(DomainError::EmptyValue);
        }
        if duration_seconds < 0 || !distance_meters.is_finite() || distance_meters < 0.0 {
            return Err(DomainError::InvalidMeasurement);
        }
        Ok(Self {
            id,
            performed_at,
            name,
            duration_seconds,
            distance_meters,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workout_contains_only_agreed_content_and_identity() {
        let workout = Workout::new(
            WorkoutId::new("strava:7").unwrap(),
            "2026-07-15T06:00:00Z",
            "Morning Run",
            3600,
            10_000.0,
        )
        .unwrap();
        assert_eq!(workout.duration_seconds, 3600);
        assert_eq!(workout.distance_meters, 10_000.0);
    }

    #[test]
    fn invalid_measurements_cannot_enter_domain() {
        let result = Workout::new(
            WorkoutId::new("strava:7").unwrap(),
            "2026-07-15T06:00:00Z",
            "Morning Run",
            -1,
            f64::NAN,
        );
        assert_eq!(result.unwrap_err(), DomainError::InvalidMeasurement);
    }
}
