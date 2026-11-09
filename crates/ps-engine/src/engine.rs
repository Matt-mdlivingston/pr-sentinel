//! Scores one event at a time against a [`RiskState`].

use crate::rules::{Rules, RulesError};
use crate::signals;
use crate::state::{Observation, RiskState};
use crate::{signal::EvalCtx, signal::Signal};
use chrono::{DateTime, Utc};
use ps_core::{IpInfo, LoginEvent, RiskScore, source_network};
use thiserror::Error;

/// Scores logins and then records them.
///
/// `S` is the history store. [`Engine::new`] uses the in-memory store sized by
/// the rules. A streaming deployment can pass a different [`RiskState`] as
/// long as it honors event time and the same query semantics.
pub struct Engine<S> {
    rules: Rules,
    state: S,
    signals: Vec<Box<dyn Signal>>,
    last_timestamp: Option<DateTime<Utc>>,
}

/// The event could not be scored.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    /// Events must be applied in non-decreasing timestamp order.
    ///
    /// Batch callers sort first. A stream that receives a late event has to
    /// decide whether to drop it; the engine refuses rather than rewriting
    /// history that was already scored.
    #[error("event at {event} is earlier than the previous event at {previous}")]
    OutOfOrder {
        /// Timestamp of the rejected event.
        event: DateTime<Utc>,
        /// Timestamp of the last accepted event.
        previous: DateTime<Utc>,
    },
}

impl Engine<crate::state::MemoryState> {
    /// Builds an engine with the in-memory store described by `rules`.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] when `rules` fails validation. [`Rules::from_toml`]
    /// already validates, so this only fails if a `Rules` value was assembled
    /// some other way. Today the TOML parser is the only constructor, and it
    /// validates, so this `Result` stays for the day a second constructor exists.
    pub fn new(rules: Rules) -> Result<Self, RulesError> {
        let state = rules.memory_state();
        Ok(Self::with_state(rules, state))
    }
}

impl<S: RiskState> Engine<S> {
    /// Builds an engine around an existing store.
    ///
    /// The store should be empty for a fresh batch. Seeding it is how a
    /// restarted stream would resume, once a durable store exists.
    #[must_use]
    pub fn with_state(rules: Rules, state: S) -> Self {
        Self {
            rules,
            state,
            signals: signals::builtin(),
            last_timestamp: None,
        }
    }

    /// Scores `event` using `info`, then records it.
    ///
    /// `info` must describe `event.ip`. The engine does not check that the
    /// addresses match; the caller owns enrichment.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::OutOfOrder`] when `event.timestamp` is earlier
    /// than the previous scored event. State is left unchanged in that case.
    pub fn score(&mut self, event: &LoginEvent, info: &IpInfo) -> Result<RiskScore, EngineError> {
        if let Some(previous) = self.last_timestamp {
            if event.timestamp < previous {
                return Err(EngineError::OutOfOrder {
                    event: event.timestamp,
                    previous,
                });
            }
        }
        let effective = self.rules.resolve(&event.tenant_id);
        let hits: Vec<_> = {
            let ctx = EvalCtx {
                event,
                ip: info,
                state: &self.state,
                rules: &effective,
            };
            self.signals
                .iter()
                .filter_map(|signal| signal.evaluate(&ctx))
                .collect()
        };
        let score = crate::score::attribute(effective.prior_log_odds, &hits);
        let observation = Observation::new(
            event.tenant_id.clone(),
            event.user_id.clone(),
            event.timestamp,
            event.ip,
            source_network(event.ip),
            event.success,
            info,
        );
        self.state.observe(&observation);
        self.last_timestamp = Some(event.timestamp);
        debug_assert_eq!(score.attributed_total(), i32::from(score.score));
        Ok(score)
    }

    /// Borrows the history store.
    #[must_use]
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Borrows the validated rules, including every tenant overlay.
    #[must_use]
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::default_rules;
    use chrono::{TimeDelta, TimeZone, Utc};
    use ps_core::{IpInfo, LoginEvent, SignalId, UserId};

    fn event(
        id: &str,
        user: &str,
        tenant: &str,
        second: i64,
        ip: &str,
        success: bool,
    ) -> LoginEvent {
        LoginEvent {
            event_id: ps_core::EventId::new(id).unwrap(),
            user_id: UserId::new(user).unwrap(),
            tenant_id: ps_core::TenantId::new(tenant).unwrap(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap()
                + TimeDelta::seconds(second),
            ip: ip.parse().unwrap(),
            user_agent: "ua".to_owned(),
            success,
            device_fingerprint: None,
        }
    }

    fn info(ip: &str, lat: f64, lon: f64, asn: u32) -> IpInfo {
        IpInfo {
            ip: ip.parse().unwrap(),
            latitude: Some(lat),
            longitude: Some(lon),
            accuracy_radius_km: Some(25.0),
            asn: Some(asn),
            asn_organization: Some(format!("AS{asn}")),
            network_type: ps_core::NetworkType::Residential,
            country_code: Some("US".to_owned()),
            city: Some("Test".to_owned()),
        }
    }

    #[test]
    fn out_of_order_event_does_not_change_state() {
        let mut engine = Engine::new(default_rules().unwrap()).unwrap();
        let first = event("a", "u", "demo", 100, "203.0.113.10", true);
        engine
            .score(&first, &info("203.0.113.10", 40.7, -74.0, 1))
            .unwrap();
        let late = event("b", "u", "demo", 50, "203.0.113.40", true);
        let err = engine
            .score(&late, &info("203.0.113.40", -33.8, 151.2, 2))
            .unwrap_err();
        assert!(matches!(err, EngineError::OutOfOrder { .. }));
        let again = event("c", "u", "demo", 100, "203.0.113.10", true);
        let score = engine
            .score(&again, &info("203.0.113.10", 40.7, -74.0, 1))
            .unwrap();
        assert!(score.contribution(SignalId::IMPOSSIBLE_TRAVEL).is_none());
    }

    #[test]
    fn travel_and_new_asn_attribute_exactly() {
        let mut engine = Engine::new(default_rules().unwrap()).unwrap();
        for second in [0, 10, 20] {
            let ev = event(
                &format!("e{second}"),
                "u",
                "demo",
                second,
                "203.0.113.10",
                true,
            );
            engine
                .score(&ev, &info("203.0.113.10", 40.7, -74.0, 7922))
                .unwrap();
        }
        let hop = event("hop", "u", "demo", 20 + 8 * 60, "203.0.113.40", true);
        let score = engine
            .score(&hop, &info("203.0.113.40", -33.8, 151.2, 1221))
            .unwrap();
        assert!(score.score >= 60, "score {}", score.score);
        assert!(score.contribution(SignalId::IMPOSSIBLE_TRAVEL).is_some());
        assert!(score.contribution(SignalId::NEW_ASN).is_some());
        assert_eq!(score.attributed_total(), i32::from(score.score));
    }

    #[test]
    fn replaying_twice_matches() {
        let rules = default_rules().unwrap();
        let events = [
            (
                event("1", "u", "demo", 0, "203.0.113.10", true),
                info("203.0.113.10", 40.7, -74.0, 1),
            ),
            (
                event("2", "u", "demo", 30, "203.0.113.10", false),
                info("203.0.113.10", 40.7, -74.0, 1),
            ),
            (
                event("3", "v", "demo", 40, "203.0.113.10", true),
                info("203.0.113.10", 40.7, -74.0, 1),
            ),
        ];
        let run = || {
            let mut engine = Engine::new(rules.clone()).unwrap();
            events
                .iter()
                .map(|(event, info)| engine.score(event, info).unwrap().score)
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
