//! Velocity between a user's consecutive logins.
//!
//! The distance that matters is the minimum plausible distance: the
//! great-circle distance minus each endpoint's accuracy radius. A free
//! geolocation database is often only accurate to a city, and two lookups of
//! the same neighborhood can land tens of kilometers apart. Subtracting the
//! radii keeps that from looking like travel. DB-IP City Lite does not publish
//! a radius, so a missing radius uses `default_accuracy_radius_km` from the
//! rules rather than zero.
//!
//! The comparison is against the immediately previous retained login. If that
//! login has no coordinates, the detector stays quiet. Skipping back to an
//! older located login would accuse the user of flying across a gap we cannot
//! actually measure.

use crate::rules::ImpossibleTravelConfig;
use crate::signal::{EvalCtx, Signal};
use crate::state::PreviousLogin;
use ps_core::{SignalHit, SignalId, coordinates_are_valid, haversine_km};

/// Impossible-travel detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImpossibleTravel;

impl Signal for ImpossibleTravel {
    fn id(&self) -> &'static str {
        SignalId::IMPOSSIBLE_TRAVEL
    }

    fn evaluate(&self, ctx: &EvalCtx<'_>) -> Option<SignalHit> {
        let params = &ctx.rules.impossible_travel;
        if !params.enabled {
            return None;
        }
        let (lat, lon) = located(ctx.ip.latitude, ctx.ip.longitude)?;
        let previous = ctx
            .state
            .previous_login(&ctx.event.tenant_id, &ctx.event.user_id)?;
        evaluate_pair(
            params,
            ctx.event.timestamp,
            lat,
            lon,
            ctx.ip.accuracy_radius_km,
            &previous,
        )
    }
}

fn located(latitude: Option<f64>, longitude: Option<f64>) -> Option<(f64, f64)> {
    match (latitude, longitude) {
        (Some(lat), Some(lon)) if coordinates_are_valid(lat, lon) => Some((lat, lon)),
        _ => None,
    }
}

fn evaluate_pair(
    params: &ImpossibleTravelConfig,
    timestamp: chrono::DateTime<chrono::Utc>,
    latitude: f64,
    longitude: f64,
    accuracy_radius_km: Option<f64>,
    previous: &PreviousLogin,
) -> Option<SignalHit> {
    let (prev_lat, prev_lon) = located(previous.latitude, previous.longitude)?;
    let elapsed = timestamp.signed_duration_since(previous.timestamp);
    let seconds = elapsed.num_seconds();
    if seconds <= 0 {
        return None;
    }
    let distance = haversine_km(prev_lat, prev_lon, latitude, longitude);
    if !distance.is_finite() {
        return None;
    }
    let prev_radius = radius(
        previous.accuracy_radius_km,
        params.default_accuracy_radius_km,
    );
    let curr_radius = radius(accuracy_radius_km, params.default_accuracy_radius_km);
    let effective = (distance - prev_radius - curr_radius).max(0.0);
    if effective <= params.min_effective_distance_km {
        return None;
    }
    let hours = seconds as f64 / 3600.0;
    let speed = effective / hours;
    if !speed.is_finite() || speed <= params.max_plausible_speed_kmh {
        return None;
    }
    let log_odds = params.weight;
    if !log_odds.is_finite() || log_odds == 0.0 {
        return None;
    }
    let minutes = seconds as f64 / 60.0;
    Some(SignalHit {
        id: SignalId::new(SignalId::IMPOSSIBLE_TRAVEL),
        log_odds,
        reason: format!(
            "{effective:.0} km in {minutes:.1} min implies {speed:.0} km/h after subtracting {prev_radius:.0} km and {curr_radius:.0} km accuracy radii (limit {limit:.0} km/h)",
            limit = params.max_plausible_speed_kmh,
        ),
    })
}

fn radius(explicit: Option<f64>, default_km: f64) -> f64 {
    explicit.unwrap_or(default_km).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Rules, default_rules};
    use crate::state::{MemoryState, Observation, RiskState};
    use chrono::{TimeZone, Utc};
    use proptest::prelude::*;
    use ps_core::{IpInfo, LoginEvent, TenantId, UserId};
    fn ts(h: u32, m: u32, s: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 5, h, m, s).unwrap()
    }

    fn event_at(seconds_from_base: i64, ip: &str) -> LoginEvent {
        LoginEvent {
            event_id: ps_core::EventId::new("evt").unwrap(),
            user_id: UserId::new("user").unwrap(),
            tenant_id: TenantId::new("demo").unwrap(),
            timestamp: ts(12, 0, 0) + chrono::TimeDelta::seconds(seconds_from_base),
            ip: ip.parse().unwrap(),
            user_agent: "ua".to_owned(),
            success: true,
            device_fingerprint: None,
        }
    }

    fn located_info(ip: &str, lat: f64, lon: f64, radius_km: Option<f64>) -> IpInfo {
        IpInfo {
            ip: ip.parse().unwrap(),
            latitude: Some(lat),
            longitude: Some(lon),
            accuracy_radius_km: radius_km,
            asn: Some(1),
            asn_organization: None,
            network_type: ps_core::NetworkType::Unknown,
            country_code: None,
            city: None,
        }
    }

    fn observe(state: &mut MemoryState, event: &LoginEvent, info: &IpInfo) {
        state.observe(&Observation::new(
            event.tenant_id.clone(),
            event.user_id.clone(),
            event.timestamp,
            event.ip,
            ps_core::source_network(event.ip),
            event.success,
            info,
        ));
    }

    fn eval(
        state: &MemoryState,
        event: &LoginEvent,
        info: &IpInfo,
        rules: &Rules,
    ) -> Option<SignalHit> {
        let effective = rules.resolve(&event.tenant_id);
        let ctx = EvalCtx {
            event,
            ip: info,
            state,
            rules: &effective,
        };
        ImpossibleTravel.evaluate(&ctx)
    }

    #[test]
    fn same_location_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        let home = located_info("203.0.113.10", 40.71, -74.00, Some(50.0));
        observe(&mut state, &first, &home);
        let second = event_at(60, "203.0.113.11");
        let again = located_info("203.0.113.11", 40.71, -74.00, Some(50.0));
        assert!(eval(&state, &second, &again, &rules).is_none());
    }

    #[test]
    fn nearby_points_inside_accuracy_radii_do_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        observe(
            &mut state,
            &first,
            &located_info("203.0.113.10", 40.71, -74.00, Some(40.0)),
        );
        // About 30 km north, swallowed by 40 km + 40 km of radius.
        let second = event_at(60, "203.0.113.11");
        let hit = eval(
            &state,
            &second,
            &located_info("203.0.113.11", 40.98, -74.00, Some(40.0)),
            &rules,
        );
        assert!(hit.is_none());
    }

    #[test]
    fn fast_intercontinental_hop_fires() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        observe(
            &mut state,
            &first,
            &located_info("203.0.113.10", 40.71, -74.00, Some(50.0)),
        );
        let second = event_at(8 * 60, "203.0.113.40");
        let hit = eval(
            &state,
            &second,
            &located_info("203.0.113.40", -33.87, 151.21, Some(50.0)),
            &rules,
        )
        .expect("sydney 8 minutes after new york");
        assert_eq!(hit.id.as_str(), SignalId::IMPOSSIBLE_TRAVEL);
        assert!(hit.reason.contains("km/h"));
        assert!(hit.log_odds > 0.0);
    }

    #[test]
    fn plausible_flight_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        observe(
            &mut state,
            &first,
            &located_info("203.0.113.10", 40.71, -74.00, Some(0.0)),
        );
        // New York to Chicago is roughly 1,150 km. Ten hours is under 900 km/h
        // even before the minimum-distance floor.
        let second = event_at(10 * 3600, "203.0.113.70");
        assert!(
            eval(
                &state,
                &second,
                &located_info("203.0.113.70", 41.88, -87.63, Some(0.0)),
                &rules
            )
            .is_none()
        );
    }

    #[test]
    fn short_hop_under_minimum_distance_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        observe(
            &mut state,
            &first,
            &located_info("203.0.113.10", 40.71, -74.00, Some(0.0)),
        );
        // ~80 km in one minute would be a huge speed, but it is inside the
        // minimum effective distance, so imprecise city pairs stay quiet.
        let second = event_at(60, "203.0.113.11");
        assert!(
            eval(
                &state,
                &second,
                &located_info("203.0.113.11", 41.40, -74.00, Some(0.0)),
                &rules
            )
            .is_none()
        );
    }

    #[test]
    fn missing_geo_or_history_does_not_fire() {
        let rules = default_rules().unwrap();
        let state = rules.memory_state();
        let event = event_at(0, "203.0.113.10");
        assert!(
            eval(
                &state,
                &event,
                &located_info("203.0.113.10", 40.71, -74.00, None),
                &rules
            )
            .is_none()
        );

        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        let mut unlocated = IpInfo::unknown(first.ip);
        unlocated.asn = Some(1);
        observe(&mut state, &first, &unlocated);
        let second = event_at(60, "198.51.100.10");
        assert!(
            eval(
                &state,
                &second,
                &located_info("198.51.100.10", 35.6, 139.6, None),
                &rules
            )
            .is_none()
        );
    }

    #[test]
    fn same_timestamp_does_not_fire() {
        let rules = default_rules().unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        observe(
            &mut state,
            &first,
            &located_info("203.0.113.10", 40.71, -74.00, Some(0.0)),
        );
        let second = event_at(0, "203.0.113.40");
        assert!(
            eval(
                &state,
                &second,
                &located_info("203.0.113.40", -33.87, 151.21, Some(0.0)),
                &rules
            )
            .is_none()
        );
    }

    #[test]
    fn tenant_speed_limit_changes_the_decision() {
        let rules = Rules::from_toml(&format!(
            "{}\n[tenants.strict.signals.impossible_travel]\nmax_plausible_speed_kmh = 200\n",
            crate::rules::DEFAULT_RULES_TOML
        ))
        .unwrap();
        let mut state = rules.memory_state();
        let first = event_at(0, "203.0.113.10");
        let mut strict_first = first.clone();
        strict_first.tenant_id = TenantId::new("strict").unwrap();
        let mut demo_first = first.clone();
        demo_first.tenant_id = TenantId::new("demo").unwrap();
        let nyc = located_info("203.0.113.10", 40.71, -74.00, Some(0.0));
        observe(&mut state, &strict_first, &nyc);
        observe(&mut state, &demo_first, &nyc);
        // London is roughly 5,500 km away. In one hour that is far above
        // 200 km/h and far above 900 km/h too. Use a slower gap: 500 km in
        // one hour sits between the two limits. Chicago is ~1,150 km, so
        // use two hours: ~575 km/h.
        let mut strict_event = event_at(2 * 3600, "203.0.113.70");
        strict_event.tenant_id = TenantId::new("strict").unwrap();
        let mut demo_event = strict_event.clone();
        demo_event.tenant_id = TenantId::new("demo").unwrap();
        let chicago = located_info("203.0.113.70", 41.88, -87.63, Some(0.0));
        assert!(eval(&state, &strict_event, &chicago, &rules).is_some());
        assert!(eval(&state, &demo_event, &chicago, &rules).is_none());
    }

    proptest! {
        #[test]
        fn same_coordinates_never_fire(
            lat in -90.0..90.0,
            lon in -180.0..180.0,
            radius_km in 0.0..500.0f64,
            gap_secs in 1i64..86_400,
        ) {
            let rules = default_rules().unwrap();
            let mut state = rules.memory_state();
            let first = event_at(0, "203.0.113.10");
            let info = located_info("203.0.113.10", lat, lon, Some(radius_km));
            observe(&mut state, &first, &info);
            let second = event_at(gap_secs, "203.0.113.11");
            let next = located_info("203.0.113.11", lat, lon, Some(radius_km));
            prop_assert!(eval(&state, &second, &next, &rules).is_none());
        }
    }
}
