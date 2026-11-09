//! Generate a seeded population and check that the injected attacks are the
//! events that score high.

use ps_core::{IpLookup, SignalId};
use ps_engine::{Engine, default_rules};
use ps_enrich::FixtureLookup;
use ps_gen::{GenerateOptions, Label, generate};
use std::collections::BTreeSet;

/// Alert bar for the default rules. This is a detection requirement, not a
/// measured benchmark: the prior alone displays as 5, and a signal at its
/// configured weight is what pushes an event across this line.
const ALERT_SCORE: u8 = 60;
/// Ordinary events should land under this. The prior is about 5.
const QUIET_SCORE: u8 = 30;

#[test]
fn seeded_attacks_outrank_ordinary_logins() {
    let options = GenerateOptions::default();
    let dataset = generate(&options).expect("dataset");
    let rules = default_rules().expect("rules");
    let fanout = rules.signals.ip_fanout;
    let lookup = FixtureLookup::from_fixture(&dataset.fixture).expect("fixture");
    let mut engine = Engine::new(rules).expect("engine");

    let mut ordinary = 0_usize;
    let mut quiet = 0_usize;
    let mut travel = 0_usize;
    let mut stuffing_established = 0_usize;
    let mut stuffing_users = BTreeSet::new();
    let mut stuffing_failures = 0_usize;

    for generated in &dataset.events {
        let info = lookup.lookup(generated.event.ip);
        let scored = engine.score(&generated.event, &info).expect("ordered");
        assert_eq!(
            scored.attributed_total(),
            i32::from(scored.score),
            "attribution drifted on {}",
            generated.event.event_id
        );

        let is_travel = generated.labels.contains(&Label::ImpossibleTravel);
        let is_stuffing = generated.labels.contains(&Label::CredentialStuffing);

        if is_travel {
            travel += 1;
            assert!(
                scored.score >= ALERT_SCORE,
                "{} scored {}",
                generated.event.event_id,
                scored.score
            );
            let hit = scored
                .contribution(SignalId::IMPOSSIBLE_TRAVEL)
                .expect("travel signal");
            assert!(!hit.reason.is_empty());
        }

        if is_stuffing {
            stuffing_users.insert(generated.event.user_id.as_str());
            if !generated.event.success {
                stuffing_failures += 1;
            }
            let accounts = stuffing_users.len() >= fanout.min_distinct_accounts as usize;
            let failures = stuffing_failures >= fanout.min_failures as usize
                && stuffing_users.len() >= fanout.min_accounts_for_failure_burst as usize;
            if accounts || failures {
                stuffing_established += 1;
                assert!(
                    scored.score >= ALERT_SCORE,
                    "{} scored {} ({:?})",
                    generated.event.event_id,
                    scored.score,
                    scored
                        .contributions
                        .iter()
                        .map(|contribution| contribution.id.as_str())
                        .collect::<Vec<_>>()
                );
                assert!(scored.contribution(SignalId::IP_FANOUT).is_some());
            }
        }

        if !is_travel && !is_stuffing {
            ordinary += 1;
            assert!(
                scored.contribution(SignalId::IMPOSSIBLE_TRAVEL).is_none(),
                "ordinary {} looked like travel: {}",
                generated.event.event_id,
                scored
                    .contribution(SignalId::IMPOSSIBLE_TRAVEL)
                    .map(|hit| hit.reason.as_str())
                    .unwrap_or("")
            );
            assert!(scored.contribution(SignalId::IP_FANOUT).is_none());
            if scored.score < QUIET_SCORE {
                quiet += 1;
            }
        }
    }

    assert!(travel >= 1);
    assert!(stuffing_established >= 1);
    let quiet_ratio = quiet as f64 / ordinary as f64;
    assert!(
        quiet_ratio >= 0.95,
        "{quiet} of {ordinary} ordinary events scored under {QUIET_SCORE} ({quiet_ratio:.3})"
    );
}
