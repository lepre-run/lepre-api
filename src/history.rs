//! Durable workout history: month buckets, digests and change planning.
//!
//! Every stored workout belongs to the month bucket of its UTC start time.
//! Clients compare one digest per month with the server and replace whole
//! months that differ, so the digest format here must stay byte-identical to
//! the web client's implementation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::Workout;

/// Hex characters of the SHA-256 kept for a month digest (64 bits).
const DIGEST_HEX_CHARS: usize = 16;

/// Wire and storage shape of one workout.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkoutPayload {
    pub id: String,
    pub performed_at: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub workout_type: String,
    pub sport: String,
    pub duration_seconds: i64,
    pub elapsed_duration_seconds: i64,
    pub distance_meters: f64,
    pub average_heart_rate_bpm: Option<f64>,
    pub max_heart_rate_bpm: Option<f64>,
    pub laps: Vec<LapPayload>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LapPayload {
    pub index: i64,
    pub name: String,
    pub moving_duration_seconds: i64,
    pub elapsed_duration_seconds: i64,
    pub distance_meters: f64,
    pub average_heart_rate_bpm: Option<f64>,
    pub max_heart_rate_bpm: Option<f64>,
}

impl From<Workout> for WorkoutPayload {
    fn from(workout: Workout) -> Self {
        Self {
            id: workout.id.to_string(),
            performed_at: workout.performed_at,
            name: workout.name,
            description: workout.description,
            workout_type: workout.workout_type.as_str().to_owned(),
            sport: workout.sport.as_str().to_owned(),
            duration_seconds: workout.duration_seconds,
            elapsed_duration_seconds: workout.elapsed_duration_seconds,
            distance_meters: workout.distance_meters,
            average_heart_rate_bpm: workout.average_heart_rate_bpm,
            max_heart_rate_bpm: workout.max_heart_rate_bpm,
            laps: workout
                .laps
                .into_iter()
                .map(|lap| LapPayload {
                    index: lap.index,
                    name: lap.name,
                    moving_duration_seconds: lap.moving_duration_seconds,
                    elapsed_duration_seconds: lap.elapsed_duration_seconds,
                    distance_meters: lap.distance_meters,
                    average_heart_rate_bpm: lap.average_heart_rate_bpm,
                    max_heart_rate_bpm: lap.max_heart_rate_bpm,
                })
                .collect(),
        }
    }
}

/// A workout ready to store: its bucket, serialized payload and content fingerprint.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkoutRecord {
    pub id: String,
    pub month: String,
    pub payload: String,
    pub fingerprint: String,
}

impl WorkoutRecord {
    /// Build the record, or `None` when the start time has no usable month.
    pub fn new(workout: Workout) -> Option<Self> {
        let month = month_of(&workout.performed_at)?;
        let payload = WorkoutPayload::from(workout);
        let id = payload.id.clone();
        let payload = serde_json::to_string(&payload).expect("serializable workout payload");
        let fingerprint = hex(&Sha256::digest(payload.as_bytes()));
        Some(Self {
            id,
            month,
            payload,
            fingerprint,
        })
    }
}

/// What is already stored for one workout.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredWorkoutState {
    pub month: String,
    pub sync_version: String,
    pub fingerprint: String,
}

/// What is already stored for one month bucket.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MonthState {
    pub members: BTreeMap<String, String>,
    pub rev: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkoutWrite {
    pub record: WorkoutRecord,
    pub sync_version: String,
    /// The stored `sync_version` this write replaces; `None` for a workout
    /// that must not exist yet.
    pub expected_version: Option<String>,
}

/// Delete of a stored workout, only while it still has `expected_version`.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkoutDelete {
    pub id: String,
    pub expected_version: String,
}

/// New contents of a month bucket. `expected_rev` is `None` for a month that
/// did not exist yet; an empty `members` map deletes the month.
#[derive(Debug, Clone, PartialEq)]
pub struct MonthWrite {
    pub month: String,
    pub expected_rev: Option<i64>,
    pub members: BTreeMap<String, String>,
}

impl MonthWrite {
    pub fn digest(&self) -> String {
        month_digest(&self.members)
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChangeSet {
    pub workout_writes: Vec<WorkoutWrite>,
    pub workout_deletes: Vec<WorkoutDelete>,
    pub month_writes: Vec<MonthWrite>,
}

impl ChangeSet {
    pub fn is_empty(&self) -> bool {
        self.workout_writes.is_empty()
            && self.workout_deletes.is_empty()
            && self.month_writes.is_empty()
    }
}

/// Months whose current state `plan_changes` needs for these changes.
pub fn affected_months(
    existing: &HashMap<String, StoredWorkoutState>,
    upserts: &[WorkoutRecord],
) -> BTreeSet<String> {
    existing
        .values()
        .map(|state| state.month.clone())
        .chain(upserts.iter().map(|record| record.month.clone()))
        .collect()
}

/// Plan the writes that apply `upserts` and `removals` to stored history.
///
/// A workout keeps its `sync_version` while its content fingerprint is
/// unchanged, so re-importing identical data writes nothing and leaves every
/// month digest as it was.
pub fn plan_changes(
    existing: &HashMap<String, StoredWorkoutState>,
    months: &HashMap<String, MonthState>,
    upserts: Vec<WorkoutRecord>,
    removals: &[String],
    mut new_version: impl FnMut() -> String,
) -> ChangeSet {
    let month_members = |name: &str| {
        months
            .get(name)
            .map(|state| state.members.clone())
            .unwrap_or_default()
    };
    let mut dirty: BTreeSet<String> = BTreeSet::new();
    let mut updated: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut changes = ChangeSet::default();
    let removed: BTreeSet<&String> = removals.iter().collect();

    for id in removals {
        if let Some(state) = existing.get(id) {
            updated
                .entry(state.month.clone())
                .or_insert_with(|| month_members(&state.month))
                .remove(id);
            dirty.insert(state.month.clone());
            changes.workout_deletes.push(WorkoutDelete {
                id: id.clone(),
                expected_version: state.sync_version.clone(),
            });
        }
    }

    let latest: BTreeMap<String, WorkoutRecord> = upserts
        .into_iter()
        .filter(|record| !removed.contains(&record.id))
        .map(|record| (record.id.clone(), record))
        .collect();
    for (id, record) in latest {
        let previous = existing.get(&id);
        let unchanged = previous.is_some_and(|state| {
            state.fingerprint == record.fingerprint && state.month == record.month
        });
        let sync_version = match previous {
            Some(state) if unchanged => state.sync_version.clone(),
            _ => new_version(),
        };
        let target = updated
            .entry(record.month.clone())
            .or_insert_with(|| month_members(&record.month));
        if unchanged && target.get(&id) == Some(&sync_version) {
            continue;
        }
        target.insert(id.clone(), sync_version.clone());
        dirty.insert(record.month.clone());
        if let Some(state) = previous.filter(|state| state.month != record.month) {
            updated
                .entry(state.month.clone())
                .or_insert_with(|| month_members(&state.month))
                .remove(&id);
            dirty.insert(state.month.clone());
        }
        if !unchanged {
            changes.workout_writes.push(WorkoutWrite {
                record,
                sync_version,
                expected_version: previous.map(|state| state.sync_version.clone()),
            });
        }
    }

    for name in dirty {
        changes.month_writes.push(MonthWrite {
            expected_rev: months.get(&name).map(|stored| stored.rev),
            members: updated.remove(&name).unwrap_or_default(),
            month: name,
        });
    }
    changes
}

/// Digest of one month: the first 64 bits of
/// `sha256(concat("{id} {sync_version}\n"))` over members sorted by id.
pub fn month_digest(members: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (id, sync_version) in members {
        hasher.update(format!("{id} {sync_version}\n").as_bytes());
    }
    let mut digest = hex(&hasher.finalize());
    digest.truncate(DIGEST_HEX_CHARS);
    digest
}

/// `YYYY-MM` bucket of a UTC RFC 3339 timestamp such as `2026-10-10T08:12:00Z`.
pub fn month_of(timestamp: &str) -> Option<String> {
    utc_seconds(timestamp)?;
    Some(timestamp[..7].to_owned())
}

/// Seconds since the Unix epoch of a UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_seconds(timestamp: &str) -> Option<i64> {
    let bytes = timestamp.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let field = |range: std::ops::Range<usize>| -> Option<i64> {
        let text = timestamp.get(range)?;
        text.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| text.parse().ok())?
    };
    let (year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Lap, RunSport, WorkoutData, WorkoutId, WorkoutType};

    fn workout(id: &str, performed_at: &str, name: &str) -> Workout {
        Workout::new(WorkoutData {
            id: WorkoutId::new(id).unwrap(),
            performed_at: performed_at.to_owned(),
            name: name.to_owned(),
            description: String::new(),
            workout_type: WorkoutType::Workout,
            sport: RunSport::Run,
            duration_seconds: 1_800,
            elapsed_duration_seconds: 1_900,
            distance_meters: 5_000.0,
            average_heart_rate_bpm: None,
            max_heart_rate_bpm: None,
            laps: vec![Lap::new(1, "Lap 1", 1_800, 1_900, 5_000.0, None, None).unwrap()],
        })
        .unwrap()
    }

    fn record(id: &str, performed_at: &str, name: &str) -> WorkoutRecord {
        WorkoutRecord::new(workout(id, performed_at, name)).unwrap()
    }

    fn stored(record: &WorkoutRecord, sync_version: &str) -> StoredWorkoutState {
        StoredWorkoutState {
            month: record.month.clone(),
            sync_version: sync_version.to_owned(),
            fingerprint: record.fingerprint.clone(),
        }
    }

    fn versions() -> impl FnMut() -> String {
        let mut next = 0;
        move || {
            next += 1;
            format!("v{next}")
        }
    }

    #[test]
    fn utc_seconds_matches_known_instants() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(utc_seconds("2026-10-10T08:12:00Z"), Some(1_791_619_920));
        assert_eq!(utc_seconds("2024-02-29T23:59:59Z"), Some(1_709_251_199));
        assert_eq!(utc_seconds("2023-02-29T00:00:00Z"), None);
        assert_eq!(utc_seconds("2026-10-10T08:12:00+02:00"), None);
        assert_eq!(utc_seconds("2026-1a-10T08:12:00Z"), None);
        assert_eq!(utc_seconds(""), None);
    }

    #[test]
    fn month_buckets_use_the_utc_start_month() {
        assert_eq!(month_of("2026-10-31T23:30:00Z").as_deref(), Some("2026-10"));
        assert_eq!(month_of("not a date"), None);
    }

    #[test]
    fn month_digest_matches_shared_test_vectors() {
        assert_eq!(month_digest(&BTreeMap::new()), "e3b0c44298fc1c14");
        let members = BTreeMap::from([
            ("strava:2".to_owned(), "b".to_owned()),
            ("strava:1".to_owned(), "a".to_owned()),
        ]);
        assert_eq!(month_digest(&members), "5f5b14b3a85ffc07");
    }

    #[test]
    fn payload_keeps_the_existing_wire_shape() {
        let payload = WorkoutPayload::from(workout("strava:7", "2026-07-15T06:00:00Z", "Easy"));
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["type"], "workout");
        assert_eq!(json["performedAt"], "2026-07-15T06:00:00Z");
        assert_eq!(json["laps"][0]["movingDurationSeconds"], 1_800);
    }

    #[test]
    fn new_workout_creates_its_month() {
        let easy = record("strava:1", "2026-10-10T08:00:00Z", "Easy");
        let changes = plan_changes(
            &HashMap::new(),
            &HashMap::new(),
            vec![easy.clone()],
            &[],
            versions(),
        );
        assert_eq!(changes.workout_writes.len(), 1);
        assert_eq!(changes.workout_writes[0].sync_version, "v1");
        assert_eq!(changes.workout_writes[0].expected_version, None);
        assert_eq!(
            changes.month_writes,
            vec![MonthWrite {
                month: "2026-10".into(),
                expected_rev: None,
                members: BTreeMap::from([("strava:1".into(), "v1".into())]),
            }]
        );
    }

    #[test]
    fn identical_reimport_writes_nothing() {
        let easy = record("strava:1", "2026-10-10T08:00:00Z", "Easy");
        let existing = HashMap::from([("strava:1".to_owned(), stored(&easy, "old"))]);
        let months = HashMap::from([(
            "2026-10".to_owned(),
            MonthState {
                members: BTreeMap::from([("strava:1".into(), "old".into())]),
                rev: 3,
            },
        )]);
        let changes = plan_changes(&existing, &months, vec![easy], &[], versions());
        assert!(changes.is_empty());
    }

    #[test]
    fn edited_workout_gets_a_new_version() {
        let before = record("strava:1", "2026-10-10T08:00:00Z", "Easy");
        let after = record("strava:1", "2026-10-10T08:00:00Z", "Tempo");
        let existing = HashMap::from([("strava:1".to_owned(), stored(&before, "old"))]);
        let months = HashMap::from([(
            "2026-10".to_owned(),
            MonthState {
                members: BTreeMap::from([("strava:1".into(), "old".into())]),
                rev: 3,
            },
        )]);
        let changes = plan_changes(&existing, &months, vec![after], &[], versions());
        assert_eq!(changes.workout_writes[0].sync_version, "v1");
        assert_eq!(
            changes.workout_writes[0].expected_version.as_deref(),
            Some("old")
        );
        assert_eq!(changes.month_writes[0].expected_rev, Some(3));
        assert_eq!(changes.month_writes[0].members["strava:1"], "v1");
    }

    #[test]
    fn start_date_edit_moves_the_workout_between_months() {
        let before = record("strava:1", "2026-09-30T23:00:00Z", "Easy");
        let after = record("strava:1", "2026-10-01T06:00:00Z", "Easy");
        let existing = HashMap::from([("strava:1".to_owned(), stored(&before, "old"))]);
        let months = HashMap::from([(
            "2026-09".to_owned(),
            MonthState {
                members: BTreeMap::from([("strava:1".into(), "old".into())]),
                rev: 1,
            },
        )]);
        let changes = plan_changes(&existing, &months, vec![after], &[], versions());
        let names: Vec<_> = changes
            .month_writes
            .iter()
            .map(|m| m.month.as_str())
            .collect();
        assert_eq!(names, ["2026-09", "2026-10"]);
        assert!(changes.month_writes[0].members.is_empty());
        assert_eq!(changes.month_writes[1].members["strava:1"], "v1");
    }

    #[test]
    fn removal_drops_the_workout_and_ignores_unknown_ids() {
        let easy = record("strava:1", "2026-10-10T08:00:00Z", "Easy");
        let other = record("strava:2", "2026-10-11T08:00:00Z", "Long");
        let existing = HashMap::from([("strava:1".to_owned(), stored(&easy, "a"))]);
        let months = HashMap::from([(
            "2026-10".to_owned(),
            MonthState {
                members: BTreeMap::from([
                    ("strava:1".into(), "a".into()),
                    ("strava:2".into(), "b".into()),
                ]),
                rev: 5,
            },
        )]);
        let changes = plan_changes(
            &existing,
            &months,
            vec![other],
            &["strava:1".to_owned(), "strava:9".to_owned()],
            versions(),
        );
        assert_eq!(
            changes.workout_deletes,
            [WorkoutDelete {
                id: "strava:1".into(),
                expected_version: "a".into(),
            }]
        );
        assert_eq!(
            changes.month_writes[0].members,
            BTreeMap::from([("strava:2".into(), "v1".into())])
        );
    }
}
