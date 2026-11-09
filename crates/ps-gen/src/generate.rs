//! Build a labeled dataset from [`GenerateOptions`].

use crate::catalog::{ATTACK_PLACE, PLACES, Place};
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use ps_core::{DeviceFingerprint, EventId, LoginEvent, TenantId, UserId, haversine_km};
use ps_enrich::GeoFixture;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// Why dataset generation was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenerateError {
    /// `users` was zero or above the documentation-range budget.
    #[error("users must be between 1 and {max}")]
    UsersOutOfRange {
        /// Largest accepted population.
        max: usize,
    },
    /// `days` was zero.
    #[error("days must be at least 1")]
    NoDays,
    /// The tenant id was empty or too long.
    #[error("invalid tenant id: {0}")]
    Tenant(String),
    /// The city catalog cannot stage an intercontinental hop.
    #[error("no catalog city is far enough from {city} to inject impossible travel")]
    NoDistantPlace {
        /// Home city that had no far partner.
        city: String,
    },
}

/// Knobs for [`generate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateOptions {
    /// Mixer seed. The same seed and options always yield the same file.
    pub seed: u64,
    /// Tenant stamped on every event.
    pub tenant_id: String,
    /// Home users. Each gets a unique documentation address.
    pub users: usize,
    /// Days of ordinary traffic before the stuffing burst.
    pub days: u16,
    /// UTC midnight of the first day.
    pub start: DateTime<Utc>,
    /// How many home users get an impossible-travel login after their last
    /// ordinary one. Clamped to `users`.
    pub impossible_travel_users: usize,
    /// Attempts in the stuffing burst.
    pub stuffing_attempts: usize,
    /// Distinct victim accounts in the stuffing burst.
    pub stuffing_accounts: usize,
    /// Coworkers who share one address and should not look like stuffing.
    pub office_users: usize,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            seed: 42,
            tenant_id: "demo".to_owned(),
            users: 20,
            days: 5,
            start: Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap(),
            impossible_travel_users: 2,
            stuffing_attempts: 30,
            stuffing_accounts: 20,
            office_users: 3,
        }
    }
}

impl GenerateOptions {
    fn validate(&self) -> Result<(), GenerateError> {
        if self.users == 0 || self.users > MAX_USERS {
            return Err(GenerateError::UsersOutOfRange { max: MAX_USERS });
        }
        if self.days == 0 {
            return Err(GenerateError::NoDays);
        }
        TenantId::new(&self.tenant_id).map_err(|err| GenerateError::Tenant(err.to_string()))?;
        Ok(())
    }
}

/// Largest home population that fits in `203.0.113.10`–`203.0.113.209`,
/// leaving `203.0.113.220` and up for travel destinations.
const MAX_USERS: usize = 200;

/// A label the generator attaches so a test can find injected attacks.
///
/// Labels are not an input to the scorer. They travel in the JSONL file and
/// are stripped before scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    /// This login is on a different continent minutes after the previous one.
    ImpossibleTravel,
    /// This login is part of the single-address stuffing burst.
    CredentialStuffing,
}

/// One generated login plus the labels that describe why it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedEvent {
    /// The event the scorer will see.
    pub event: LoginEvent,
    /// Empty for ordinary traffic.
    pub labels: Vec<Label>,
}

/// Counts a caller can print without scanning labels again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Total events.
    pub events: usize,
    /// Events labeled [`Label::ImpossibleTravel`].
    pub impossible_travel: usize,
    /// Events labeled [`Label::CredentialStuffing`].
    pub credential_stuffing: usize,
    /// Events with no label.
    pub ordinary: usize,
    /// Addresses described by the fixture.
    pub fixture_ips: usize,
}

/// A generated population.
#[derive(Debug, Clone, PartialEq)]
pub struct Dataset {
    /// Events in timestamp order, with ids assigned in that order.
    pub events: Vec<GeneratedEvent>,
    /// Coordinates and ASNs for every address the events use.
    pub fixture: GeoFixture,
}

impl Dataset {
    /// Serializes events as JSONL. Each line is a login plus a `labels` array.
    ///
    /// # Errors
    ///
    /// Returns a serde error if a value cannot be serialized. The built-in
    /// types do serialize; this is a `Result` so callers do not unwrap inside
    /// a library.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut out = String::new();
        for event in &self.events {
            let mut value = serde_json::to_value(&event.event)?;
            if let Some(map) = value.as_object_mut() {
                map.insert("labels".to_owned(), serde_json::to_value(&event.labels)?);
            }
            out.push_str(&serde_json::to_string(&value)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Pretty-printed fixture JSON.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the fixture cannot be serialized.
    pub fn fixture_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.fixture)
    }

    /// Label and size counts.
    #[must_use]
    pub fn summary(&self) -> Summary {
        let impossible_travel = self
            .events
            .iter()
            .filter(|event| event.labels.contains(&Label::ImpossibleTravel))
            .count();
        let credential_stuffing = self
            .events
            .iter()
            .filter(|event| event.labels.contains(&Label::CredentialStuffing))
            .count();
        Summary {
            events: self.events.len(),
            impossible_travel,
            credential_stuffing,
            ordinary: self.events.len() - impossible_travel - credential_stuffing,
            fixture_ips: self.fixture.ips.len(),
        }
    }
}

struct Person {
    id: UserId,
    place_index: usize,
    ip: IpAddr,
    fingerprint: DeviceFingerprint,
    user_agent: String,
    /// Shared-office users are ordinary traffic and are not used as travel subjects.
    office: bool,
}

struct Pending {
    event: LoginEvent,
    labels: Vec<Label>,
    seq: u64,
}

/// Builds a dataset.
///
/// # Errors
///
/// Returns [`GenerateError`] when the options are out of range or the catalog
/// cannot place an impossible-travel hop.
pub fn generate(options: &GenerateOptions) -> Result<Dataset, GenerateError> {
    options.validate()?;
    let tenant = TenantId::new(&options.tenant_id).expect("validate() accepted the tenant");
    let mut fixture = GeoFixture::default();
    let mut people = Vec::with_capacity(options.users + options.office_users);

    for index in 0..options.users {
        let place_index = index % PLACES.len();
        let ip = ipv4(203, 0, 113, octet(10, index));
        fixture.insert(ip, PLACES[place_index].fixture());
        people.push(person(index, place_index, ip, false));
    }

    let office_ip = ipv4(198, 51, 100, 10);
    fixture.insert(office_ip, PLACES[0].fixture());
    for index in 0..options.office_users {
        people.push(person(1_000 + index, 0, office_ip, true));
    }

    for (place_index, place) in PLACES.iter().enumerate() {
        let ip = ipv4(203, 0, 113, octet(220, place_index));
        fixture.insert(ip, place.fixture());
    }
    let attack_ip = ipv4(198, 51, 100, 50);
    let mut attack = ATTACK_PLACE.fixture();
    attack.network_type = ps_core::NetworkType::Hosting;
    fixture.insert(attack_ip, attack);

    let mut pending = Vec::new();
    let mut seq = 0_u64;
    let mut last_of_user: Vec<Option<usize>> = vec![None; people.len()];
    let slots = [(0_u32, 9_i32), (1, 13), (2, 19)];

    for (person_index, person) in people.iter().enumerate() {
        let place = &PLACES[person.place_index];
        for day in 0..i64::from(options.days) {
            for (slot, hour) in slots {
                let minute = (mix(&[
                    options.seed,
                    person_index as u64,
                    day as u64,
                    u64::from(slot),
                ]) % 20) as i32;
                let success = mix(&[
                    options.seed,
                    person_index as u64,
                    day as u64,
                    u64::from(slot),
                    7,
                ]) % 20
                    != 0;
                let timestamp =
                    login_time(options.start, day, hour, minute, place.utc_offset_hours);
                let event = login(
                    &tenant,
                    person,
                    timestamp,
                    person.ip,
                    success,
                    Some(person.fingerprint.clone()),
                    seq,
                );
                last_of_user[person_index] = Some(pending.len());
                pending.push(Pending {
                    event,
                    labels: Vec::new(),
                    seq,
                });
                seq += 1;
            }
        }
    }

    let travel_subjects = options.impossible_travel_users.min(options.users);
    for person_index in 0..travel_subjects {
        let person = &people[person_index];
        debug_assert!(!person.office, "travel subjects are home users");
        let home = &PLACES[person.place_index];
        let (dest_index, distance) = farthest_place(home);
        if distance < 2_000.0 {
            return Err(GenerateError::NoDistantPlace {
                city: home.city.to_owned(),
            });
        }
        let Some(last) = last_of_user[person_index] else {
            continue;
        };
        let timestamp = pending[last].event.timestamp + TimeDelta::minutes(8);
        let dest_ip = ipv4(203, 0, 113, octet(220, dest_index));
        let event = login(
            &tenant,
            person,
            timestamp,
            dest_ip,
            true,
            Some(person.fingerprint.clone()),
            seq,
        );
        pending.push(Pending {
            event,
            labels: vec![Label::ImpossibleTravel],
            seq,
        });
        seq += 1;
    }

    if options.stuffing_attempts > 0 && options.stuffing_accounts > 0 {
        let stuffing_start = options.start + TimeDelta::days(i64::from(options.days) + 1);
        for attempt in 0..options.stuffing_attempts {
            let victim_index = attempt % options.stuffing_accounts;
            let user = UserId::new(format!("victim-{victim_index:02}")).expect("victim id");
            let timestamp =
                stuffing_start + TimeDelta::seconds(i64::try_from(attempt).unwrap_or(0));
            let success = attempt % 5 == 4;
            let event = LoginEvent {
                event_id: EventId::new(format!("tmp-{seq}")).expect("tmp id"),
                user_id: user,
                tenant_id: tenant.clone(),
                timestamp,
                ip: attack_ip,
                user_agent: "python-requests/2.32".to_owned(),
                success,
                device_fingerprint: None,
            };
            pending.push(Pending {
                event,
                labels: vec![Label::CredentialStuffing],
                seq,
            });
            seq += 1;
        }
    }

    pending.sort_by(|left, right| {
        left.event
            .timestamp
            .cmp(&right.event.timestamp)
            .then(left.event.user_id.cmp(&right.event.user_id))
            .then(left.seq.cmp(&right.seq))
    });
    let events = pending
        .into_iter()
        .enumerate()
        .map(|(index, mut row)| {
            row.event.event_id = EventId::new(format!("evt-{index:06}")).expect("event id");
            GeneratedEvent {
                event: row.event,
                labels: row.labels,
            }
        })
        .collect();

    Ok(Dataset { events, fixture })
}

fn person(index: usize, place_index: usize, ip: IpAddr, office: bool) -> Person {
    let name = if office {
        format!("office-{index:03}")
    } else {
        format!("user-{index:03}")
    };
    let id = UserId::new(&name).expect("user id");
    Person {
        fingerprint: DeviceFingerprint::new(format!("fp-{name}")).expect("fingerprint"),
        user_agent: USER_AGENTS[index % USER_AGENTS.len()].to_owned(),
        id,
        place_index,
        ip,
        office,
    }
}

fn login(
    tenant: &TenantId,
    person: &Person,
    timestamp: DateTime<Utc>,
    ip: IpAddr,
    success: bool,
    fingerprint: Option<DeviceFingerprint>,
    seq: u64,
) -> LoginEvent {
    LoginEvent {
        event_id: EventId::new(format!("tmp-{seq}")).expect("tmp id"),
        user_id: person.id.clone(),
        tenant_id: tenant.clone(),
        timestamp,
        ip,
        user_agent: person.user_agent.clone(),
        success,
        device_fingerprint: fingerprint,
    }
}

fn login_time(
    start: DateTime<Utc>,
    day: i64,
    local_hour: i32,
    minute: i32,
    offset_hours: i32,
) -> DateTime<Utc> {
    let utc_hour = i64::from(local_hour - offset_hours);
    start
        + TimeDelta::days(day)
        + TimeDelta::hours(utc_hour)
        + TimeDelta::minutes(i64::from(minute))
}

fn farthest_place(home: &Place) -> (usize, f64) {
    PLACES
        .iter()
        .enumerate()
        .filter(|(_, place)| place.name != home.name)
        .map(|(index, place)| {
            (
                index,
                haversine_km(
                    home.latitude,
                    home.longitude,
                    place.latitude,
                    place.longitude,
                ),
            )
        })
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .unwrap_or((0, 0.0))
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn octet(base: u8, index: usize) -> u8 {
    let value = usize::from(base) + index;
    u8::try_from(value).expect("caller bounds the index")
}

/// Portable mixer. Same inputs, same output, on every platform.
fn mix(parts: &[u64]) -> u64 {
    let mut z = 0x9E37_79B9_7F4A_7C15_u64;
    for part in parts {
        z ^= part.wrapping_add(0xBF58_476D_1CE4_E5B9);
        z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
    }
    z
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixer_is_deterministic_and_seed_sensitive() {
        assert_eq!(mix(&[1, 2, 3]), mix(&[1, 2, 3]));
        assert_ne!(mix(&[1, 2, 3]), mix(&[2, 2, 3]));
    }

    #[test]
    fn same_seed_is_byte_identical_and_a_different_seed_is_not() {
        let first = generate(&GenerateOptions::default()).unwrap();
        let second = generate(&GenerateOptions::default()).unwrap();
        assert_eq!(first.to_jsonl().unwrap(), second.to_jsonl().unwrap());
        let other = GenerateOptions {
            seed: 99,
            ..GenerateOptions::default()
        };
        assert_ne!(
            first.to_jsonl().unwrap(),
            generate(&other).unwrap().to_jsonl().unwrap()
        );
    }

    #[test]
    fn injected_travel_is_fast_and_far() {
        let dataset = generate(&GenerateOptions::default()).unwrap();
        let travel: Vec<_> = dataset
            .events
            .iter()
            .filter(|event| event.labels.contains(&Label::ImpossibleTravel))
            .collect();
        assert_eq!(travel.len(), 2);
        for event in travel {
            let previous = dataset
                .events
                .iter()
                .rev()
                .find(|candidate| {
                    candidate.event.user_id == event.event.user_id
                        && candidate.event.timestamp < event.event.timestamp
                        && candidate.labels.is_empty()
                })
                .unwrap();
            let gap = event.event.timestamp - previous.event.timestamp;
            assert_eq!(gap.num_minutes(), 8);
            let from = dataset.fixture.get(previous.event.ip).unwrap();
            let to = dataset.fixture.get(event.event.ip).unwrap();
            let distance = haversine_km(from.latitude, from.longitude, to.latitude, to.longitude);
            assert!(distance > 5_000.0, "{distance}");
            assert_ne!(from.asn, to.asn);
        }
    }

    #[test]
    fn stuffing_is_one_address_many_accounts_mostly_failing() {
        let dataset = generate(&GenerateOptions::default()).unwrap();
        let stuffing: Vec<_> = dataset
            .events
            .iter()
            .filter(|event| event.labels.contains(&Label::CredentialStuffing))
            .collect();
        assert_eq!(stuffing.len(), 30);
        let ip = stuffing[0].event.ip;
        assert!(stuffing.iter().all(|event| event.event.ip == ip));
        let users: std::collections::BTreeSet<_> = stuffing
            .iter()
            .map(|event| event.event.user_id.as_str())
            .collect();
        assert!(users.len() >= 8);
        let failures = stuffing.iter().filter(|event| !event.event.success).count();
        assert!(failures >= 20, "{failures}");
        let span = stuffing.last().unwrap().event.timestamp - stuffing[0].event.timestamp;
        assert!(span.num_seconds() < 120);
    }

    #[test]
    fn office_shares_one_address_and_is_unlabeled() {
        let dataset = generate(&GenerateOptions::default()).unwrap();
        let office: Vec<_> = dataset
            .events
            .iter()
            .filter(|event| event.event.user_id.as_str().starts_with("office-"))
            .collect();
        assert!(!office.is_empty());
        let ip = office[0].event.ip;
        assert!(
            office
                .iter()
                .all(|event| event.event.ip == ip && event.labels.is_empty())
        );
        let users: std::collections::BTreeSet<_> = office
            .iter()
            .map(|event| event.event.user_id.as_str())
            .collect();
        assert_eq!(users.len(), 3);
    }

    #[test]
    fn rejects_an_empty_population() {
        let options = GenerateOptions {
            users: 0,
            ..GenerateOptions::default()
        };
        assert!(matches!(
            generate(&options),
            Err(GenerateError::UsersOutOfRange { .. })
        ));
    }
}
