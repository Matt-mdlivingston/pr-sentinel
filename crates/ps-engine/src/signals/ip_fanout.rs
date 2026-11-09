//! One source touching many accounts inside a sliding window.
//!
//! Credential stuffing shows up as one address (or one IPv6 `/64`) trying
//! many accounts and failing most of them. The detector has two dimensions:
//!
//! * distinct accounts, which catches a source spraying a user list
//! * failures, which catches the spray actually being rejected
//!
//! A dimension contributes strength `1 + (observed - threshold) / threshold`
//! once it has crossed its threshold, and nothing before that. Strength of
//! the signal is the mean of the dimensions that fired, capped by
//! `strength_cap`. Log-odds are `weight * strength`. At the threshold,
//! strength is 1, so the weight alone is the log-odds of "this just became
//! an alert". Further excess makes the same signal louder without a second
//! detector.
//!
//! Failures only count when at least `min_accounts_for_failure_burst`
//! distinct accounts are in the window. One person mistyping a password is
//! not stuffing.
//!
//! The current attempt is included. Earlier attempts are whatever the state
//! retained. The window is measured from the event's own timestamp.

use crate::signal::{EvalCtx, Signal};
use crate::state::IpWindowQuery;
use chrono::{DateTime, TimeDelta, Utc};
use ps_core::{SignalHit, SignalId, source_network};

/// IP fan-out detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct IpFanout;

impl Signal for IpFanout {
    fn id(&self) -> &'static str {
        SignalId::IP_FANOUT
    }

    fn evaluate(&self, ctx: &EvalCtx<'_>) -> Option<SignalHit> {
        let params = &ctx.rules.ip_fanout;
        if !params.enabled || params.window_secs == 0 {
            return None;
        }
        let network = source_network(ctx.event.ip);
        let since = window_start(ctx.event.timestamp, params.window_secs);
        let stats = ctx.state.ip_window(IpWindowQuery {
            tenant: &ctx.event.tenant_id,
            network: &network,
            since,
            until: ctx.event.timestamp,
            user: &ctx.event.user_id,
        });
        let distinct = stats.distinct_users + usize::from(!stats.contains_user);
        let failures = stats.failures + usize::from(!ctx.event.success);
        let accounts_hit = distinct >= params.min_distinct_accounts as usize;
        let failures_hit = failures >= params.min_failures as usize
            && distinct >= params.min_accounts_for_failure_burst as usize;
        if !accounts_hit && !failures_hit {
            return None;
        }
        let mut parts = Vec::new();
        if accounts_hit {
            parts.push(dimension_strength(
                distinct,
                params.min_distinct_accounts as usize,
            ));
        }
        if failures_hit {
            parts.push(dimension_strength(failures, params.min_failures as usize));
        }
        let mean = parts.iter().sum::<f64>() / parts.len() as f64;
        let strength = mean.min(params.strength_cap).max(0.0);
        let log_odds = params.weight * strength;
        if !log_odds.is_finite() || log_odds == 0.0 {
            return None;
        }
        let label = match ctx.event.ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("{ip} (counted as {network})"),
        };
        Some(SignalHit {
            id: SignalId::new(SignalId::IP_FANOUT),
            log_odds,
            reason: format!(
                "{label} reached {distinct} distinct accounts and {failures} failures in {}s (thresholds {} accounts, {} failures)",
                params.window_secs, params.min_distinct_accounts, params.min_failures,
            ),
        })
    }
}

/// Strength of one dimension that has already crossed `minimum`.
///
/// Returns 1 at the threshold and grows toward infinity as `observed`
/// increases. The caller caps the mean.
fn dimension_strength(observed: usize, minimum: usize) -> f64 {
    if minimum == 0 || observed < minimum {
        return 0.0;
    }
    let overshoot = (observed - minimum) as f64 / minimum as f64;
    1.0 + overshoot
}

fn window_start(timestamp: DateTime<Utc>, window_secs: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(window_secs).unwrap_or(i64::MAX);
    let delta = TimeDelta::try_seconds(seconds).unwrap_or_else(TimeDelta::zero);
    timestamp
        .checked_sub_signed(delta)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::default_rules;
    use crate::signal::EvalCtx;
    use crate::state::{MemoryState, Observation, RiskState};
    use chrono::{TimeDelta, TimeZone, Utc};
    use ps_core::{IpInfo, LoginEvent, UserId};

    fn at(second: i64, user: &str, ip: &str, success: bool) -> (LoginEvent, IpInfo) {
        let event = LoginEvent {
            event_id: ps_core::EventId::new(format!("evt-{second}-{user}")).unwrap(),
            user_id: UserId::new(user).unwrap(),
            tenant_id: ps_core::TenantId::new("demo").unwrap(),
            timestamp: Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap()
                + TimeDelta::seconds(second),
            ip: ip.parse().unwrap(),
            user_agent: "ua".to_owned(),
            success,
            device_fingerprint: None,
        };
        let info = IpInfo::unknown(event.ip);
        (event, info)
    }

    fn push(state: &mut MemoryState, event: &LoginEvent, info: &IpInfo) {
        state.observe(&Observation::new(
            event.tenant_id.clone(),
            event.user_id.clone(),
            event.timestamp,
            event.ip,
            source_network(event.ip),
            event.success,
            info,
        ));
    }

    fn eval(state: &MemoryState, event: &LoginEvent, info: &IpInfo) -> Option<SignalHit> {
        let rules = default_rules().unwrap();
        let effective = rules.resolve(&event.tenant_id);
        IpFanout.evaluate(&EvalCtx {
            event,
            ip: info,
            state,
            rules: &effective,
        })
    }

    #[test]
    fn a_handful_of_accounts_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for i in 0..3 {
            let (event, info) = at(i, &format!("user-{i}"), "203.0.113.50", true);
            assert!(eval(&state, &event, &info).is_none(), "user {i}");
            push(&mut state, &event, &info);
        }
    }

    #[test]
    fn many_accounts_from_one_ip_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let mut last = None;
        for i in 0..8 {
            let (event, info) = at(i, &format!("user-{i}"), "203.0.113.50", true);
            last = eval(&state, &event, &info);
            push(&mut state, &event, &info);
        }
        let hit = last.expect("the 8th distinct account crosses the threshold");
        assert!(hit.reason.contains("8 distinct accounts"));
        assert!(hit.log_odds > 0.0);
    }

    #[test]
    fn one_user_failing_repeatedly_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for i in 0..25 {
            let (event, info) = at(i, "user-0", "203.0.113.50", false);
            assert!(eval(&state, &event, &info).is_none());
            push(&mut state, &event, &info);
        }
    }

    #[test]
    fn failure_burst_across_accounts_fires() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let mut fired = false;
        for i in 0..20 {
            let user = format!("user-{}", i % 4);
            let (event, info) = at(i, &user, "203.0.113.50", false);
            if eval(&state, &event, &info).is_some() {
                fired = true;
            }
            push(&mut state, &event, &info);
        }
        assert!(fired);
    }

    #[test]
    fn attempts_outside_the_window_do_not_count() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for i in 0..7 {
            let (event, info) = at(i, &format!("user-{i}"), "203.0.113.50", false);
            push(&mut state, &event, &info);
        }
        let (event, info) = at(10_000, "user-new", "203.0.113.50", false);
        assert!(eval(&state, &event, &info).is_none());
    }

    #[test]
    fn ipv6_privacy_addresses_in_one_prefix_count_together() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let mut last = None;
        for i in 0..8 {
            let ip = format!("2001:db8:abcd::{i}");
            let (event, info) = at(i, &format!("user-{i}"), &ip, true);
            last = eval(&state, &event, &info);
            push(&mut state, &event, &info);
        }
        let hit = last.expect("one /64 spraying accounts");
        assert!(hit.reason.contains("counted as"));
    }

    #[test]
    fn different_ipv6_prefixes_do_not_merge() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        for i in 0..8 {
            let ip = format!("2001:db8:{i:x}::1");
            let (event, info) = at(i, &format!("user-{i}"), &ip, false);
            assert!(eval(&state, &event, &info).is_none());
            push(&mut state, &event, &info);
        }
    }

    #[test]
    fn strength_is_one_at_the_threshold_and_grows_after() {
        assert!((dimension_strength(8, 8) - 1.0).abs() < 1e-9);
        assert!(dimension_strength(16, 8) > 1.0);
        assert_eq!(dimension_strength(7, 8), 0.0);
    }
}
