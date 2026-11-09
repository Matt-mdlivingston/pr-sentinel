//! An autonomous system this user has not logged in from before.
//!
//! The first few logins establish a baseline and do not fire. After that, an
//! ASN absent from retained history is evidence of a new network: a VPN, a
//! travel network, or someone using the password from somewhere else. The
//! detector does not know which. It reports the fact and lets the weight
//! decide how loud it is. Impossible travel, when the coordinates also moved,
//! is a separate signal; the two are correlated, and the scoring docs call
//! that out instead of hiding it inside one detector.

use crate::signal::{EvalCtx, Signal};
use ps_core::{SignalHit, SignalId};

/// New-ASN detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct NewAsn;

impl Signal for NewAsn {
    fn id(&self) -> &'static str {
        SignalId::NEW_ASN
    }

    fn evaluate(&self, ctx: &EvalCtx<'_>) -> Option<SignalHit> {
        let params = &ctx.rules.new_asn;
        if !params.enabled {
            return None;
        }
        let asn = ctx.ip.asn?;
        let history = ctx
            .state
            .asn_history(&ctx.event.tenant_id, &ctx.event.user_id);
        if history.retained_observations < params.min_prior_observations {
            return None;
        }
        if history.asns.contains(&asn) {
            return None;
        }
        let log_odds = params.weight;
        if !log_odds.is_finite() || log_odds == 0.0 {
            return None;
        }
        let org = ctx
            .ip
            .asn_organization
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("unknown organization");
        let seen = if history.asns.is_empty() {
            "none".to_owned()
        } else {
            history
                .asns
                .iter()
                .map(|seen| format!("AS{seen}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Some(SignalHit {
            id: SignalId::new(SignalId::NEW_ASN),
            log_odds,
            reason: format!(
                "AS{asn} ({org}) does not appear in the previous {} logins for this user (previously {seen})",
                history.retained_observations
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::default_rules;
    use crate::signal::EvalCtx;
    use crate::state::{MemoryState, Observation, RiskState};
    use chrono::{TimeDelta, TimeZone, Utc};
    use ps_core::{IpInfo, LoginEvent, UserId};

    fn event(user: &str, tenant: &str, second: i64, ip: &str) -> LoginEvent {
        LoginEvent {
            event_id: ps_core::EventId::new(format!("evt-{second}")).unwrap(),
            user_id: UserId::new(user).unwrap(),
            tenant_id: ps_core::TenantId::new(tenant).unwrap(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap()
                + TimeDelta::seconds(second),
            ip: ip.parse().unwrap(),
            user_agent: "ua".to_owned(),
            success: true,
            device_fingerprint: None,
        }
    }

    fn info(ip: &str, asn: Option<u32>) -> IpInfo {
        let mut info = IpInfo::unknown(ip.parse().unwrap());
        info.asn = asn;
        info.asn_organization = asn.map(|n| format!("Org {n}"));
        info.latitude = Some(1.0);
        info.longitude = Some(2.0);
        info
    }

    fn push(state: &mut MemoryState, event: &LoginEvent, info: &IpInfo) {
        state.observe(&Observation::new(
            event.tenant_id.clone(),
            event.user_id.clone(),
            event.timestamp,
            event.ip,
            ps_core::source_network(event.ip),
            true,
            info,
        ));
    }

    fn eval(state: &MemoryState, event: &LoginEvent, info: &IpInfo) -> Option<SignalHit> {
        let rules = default_rules().unwrap();
        let effective = rules.resolve(&event.tenant_id);
        NewAsn.evaluate(&EvalCtx {
            event,
            ip: info,
            state,
            rules: &effective,
        })
    }

    #[test]
    fn baseline_logins_do_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for second in 0..2 {
            let event = event("u", "demo", second, "203.0.113.10");
            let seen = eval(&state, &event, &info("203.0.113.10", Some(7922)));
            assert!(seen.is_none());
            push(&mut state, &event, &info("203.0.113.10", Some(7922)));
        }
    }

    #[test]
    fn repeated_asn_does_not_fire_after_baseline() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for second in 0..3 {
            let event = event("u", "demo", second, "203.0.113.10");
            push(&mut state, &event, &info("203.0.113.10", Some(7922)));
        }
        let next = event("u", "demo", 10, "203.0.113.11");
        assert!(eval(&state, &next, &info("203.0.113.11", Some(7922))).is_none());
    }

    #[test]
    fn unseen_asn_fires_after_baseline() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for second in 0..3 {
            let event = event("u", "demo", second, "203.0.113.10");
            push(&mut state, &event, &info("203.0.113.10", Some(7922)));
        }
        let next = event("u", "demo", 10, "198.51.100.8");
        let hit = eval(&state, &next, &info("198.51.100.8", Some(14061))).unwrap();
        assert!(hit.reason.contains("AS14061"));
        assert!(hit.reason.contains("AS7922"));
        assert!(hit.log_odds > 0.0);
    }

    #[test]
    fn missing_asn_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for second in 0..3 {
            let event = event("u", "demo", second, "203.0.113.10");
            push(&mut state, &event, &info("203.0.113.10", Some(7922)));
        }
        let next = event("u", "demo", 10, "198.51.100.8");
        assert!(eval(&state, &next, &info("198.51.100.8", None)).is_none());
    }

    #[test]
    fn other_tenant_history_is_not_this_users_baseline() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for second in 0..3 {
            let event = event("u", "other", second, "203.0.113.10");
            push(&mut state, &event, &info("203.0.113.10", Some(7922)));
        }
        let next = event("u", "demo", 10, "198.51.100.8");
        assert!(eval(&state, &next, &info("198.51.100.8", Some(14061))).is_none());
    }
}
