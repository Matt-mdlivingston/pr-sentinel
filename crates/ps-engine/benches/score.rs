//! Scoring microbenchmark stub.
//!
//! Milestone 3 replaces this with a Criterion suite over realistic batch
//! sizes. This file only keeps the harness compiling. It does not record or
//! assert any timing number.

#![allow(missing_docs)]

use chrono::{TimeDelta, TimeZone, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use ps_core::IpInfo;
use ps_core::{LoginEvent, UserId};
use ps_engine::{Engine, default_rules};

fn sample() -> Vec<(LoginEvent, IpInfo)> {
    let start = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
    (0..32)
        .map(|i| {
            let event = LoginEvent {
                event_id: ps_core::EventId::new(format!("evt-{i}")).unwrap(),
                user_id: UserId::new(format!("user-{}", i % 8)).unwrap(),
                tenant_id: ps_core::TenantId::new("demo").unwrap(),
                timestamp: start + TimeDelta::seconds(i),
                ip: format!("203.0.113.{}", 10 + (i % 8)).parse().unwrap(),
                user_agent: "bench".to_owned(),
                success: true,
                device_fingerprint: None,
            };
            let info = IpInfo {
                ip: event.ip,
                latitude: Some(40.7),
                longitude: Some(-74.0),
                accuracy_radius_km: Some(25.0),
                asn: Some(7922),
                asn_organization: Some("bench".to_owned()),
                network_type: ps_core::NetworkType::Unknown,
                country_code: Some("US".to_owned()),
                city: Some("Bench".to_owned()),
            };
            (event, info)
        })
        .collect()
}

fn score_batch(c: &mut Criterion) {
    let rules = default_rules().expect("default rules");
    let events = sample();
    c.bench_function("score_32_events", |b| {
        b.iter(|| {
            let mut engine = Engine::new(rules.clone()).expect("engine");
            for (event, info) in &events {
                let scored = engine.score(event, info).expect("in order");
                std::hint::black_box(scored.score);
            }
        });
    });
}

criterion_group!(benches, score_batch);
criterion_main!(benches);
