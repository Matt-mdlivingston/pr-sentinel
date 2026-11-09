//! Geography helpers and the enrichment facts a signal is allowed to see.
//!
//! The haversine distance is a spherical approximation (mean Earth radius
//! 6371.0088 km). It is the right model for a velocity check at city scale:
//! the error against the WGS84 ellipsoid is well under one percent, which is
//! smaller than the accuracy radius of a free IP geolocation database.

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

/// Mean Earth radius used by [`haversine_km`].
pub const EARTH_RADIUS_KM: f64 = 6371.0088;

/// Great-circle distance in kilometers.
///
/// Latitudes are degrees in `-90..=90`. Longitudes are degrees in
/// `-180..=180`. Values outside that range, or non-finite values, produce
/// `NaN`.
#[must_use]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    if !coordinates_are_valid(lat1, lon1) || !coordinates_are_valid(lat2, lon2) {
        return f64::NAN;
    }
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_phi = (lat2 - lat1).to_radians();
    let d_lambda = (lon2 - lon1).to_radians();
    let a = (d_phi / 2.0).sin().powi(2) + phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_KM * c
}

/// Reports whether a latitude/longitude pair is finite and in range.
#[must_use]
pub fn coordinates_are_valid(latitude: f64, longitude: f64) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

/// Network identity used when an IP is a key rather than a location.
///
/// IPv4 is kept at `/32`. Collapsing IPv4 into a `/24` would merge unrelated
/// customers behind carrier NAT and manufacture fan-out alerts.
///
/// IPv6 is collapsed to `/64`. Temporary privacy addresses rotate inside the
/// customer's `/64`, so treating each address as a distinct source splits one
/// laptop into many and hides a `/64` that is stuffing accounts. IPv4-mapped
/// IPv6 addresses are unwrapped first so they share a key with the embedded
/// IPv4 address.
///
/// # Panics
///
/// Panics only if `ipnetwork` rejects a `/32` or `/64`, which it does not for
/// any address those prefixes can represent.
#[must_use]
pub fn source_network(ip: IpAddr) -> IpNetwork {
    let normalized = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match normalized {
        IpAddr::V4(v4) => {
            IpNetwork::new(IpAddr::V4(v4), 32).expect("IPv4/32 is a valid prefix for every address")
        }
        IpAddr::V6(v6) => {
            // ipnetwork 0.21 compares the full address, not the masked
            // network, so privacy addresses only collide if we mask first.
            let masked = Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64));
            IpNetwork::new(IpAddr::V6(masked), 64)
                .expect("IPv6/64 is a valid prefix for every address")
        }
    }
}

/// Coarse network class. Milestone 1's free databases do not populate this.
///
/// The variant is part of [`IpInfo`] so a later hosting/Tor/VPN list can fill
/// it without changing the scoring API. The DB-IP Lite reader leaves it as
/// [`NetworkType::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    /// No network-class evidence.
    #[default]
    Unknown,
    /// Consumer ISP, as classified by a future data source.
    Residential,
    /// Mobile carrier CGNAT or cellular range.
    Mobile,
    /// Cloud, hosting, or proxy range.
    Hosting,
    /// Corporate or enterprise range.
    Corporate,
}

/// Facts known about an IP at scoring time.
///
/// Every field except [`IpInfo::ip`] is optional because enrichment fails
/// open: an unknown address produces an otherwise empty record, and signals
/// decline to fire rather than inventing a location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpInfo {
    /// Address these facts describe.
    pub ip: IpAddr,
    /// WGS84 latitude in degrees, when the database has one.
    pub latitude: Option<f64>,
    /// WGS84 longitude in degrees, when the database has one.
    pub longitude: Option<f64>,
    /// Radius of uncertainty in kilometers, when the database publishes one.
    ///
    /// DB-IP City Lite does not. Callers that want a tolerance anyway supply a
    /// default from the rules file; this field stays `None` so the default is
    /// visible as a policy choice rather than a property of the database.
    pub accuracy_radius_km: Option<f64>,
    /// Autonomous system number, when known.
    pub asn: Option<u32>,
    /// Organization name for [`IpInfo::asn`], when known.
    pub asn_organization: Option<String>,
    /// Coarse network class. See [`NetworkType`].
    pub network_type: NetworkType,
    /// ISO 3166-1 alpha-2 country code, when known.
    pub country_code: Option<String>,
    /// City name in English, when known.
    pub city: Option<String>,
}

impl IpInfo {
    /// An enrichment miss. Signals treat this as "no evidence", not as a
    /// location at (0, 0).
    #[must_use]
    pub fn unknown(ip: IpAddr) -> Self {
        Self {
            ip,
            latitude: None,
            longitude: None,
            accuracy_radius_km: None,
            asn: None,
            asn_organization: None,
            network_type: NetworkType::Unknown,
            country_code: None,
            city: None,
        }
    }

    /// Whether both coordinates are present and in range.
    #[must_use]
    pub fn is_located(&self) -> bool {
        match (self.latitude, self.longitude) {
            (Some(lat), Some(lon)) => coordinates_are_valid(lat, lon),
            _ => false,
        }
    }

    /// Whether a lookup learned a location or an ASN.
    ///
    /// Used by the fallback enricher to decide that the primary database
    /// missed and a fixture should be consulted.
    #[must_use]
    pub fn has_network_evidence(&self) -> bool {
        self.is_located() || self.asn.is_some()
    }
}

/// Turns an IP into [`IpInfo`].
///
/// Implementations must not do I/O that can fail for an individual address:
/// a miss is an [`IpInfo::unknown`] record. Opening a database is allowed to
/// fail at construction time.
pub trait IpLookup {
    /// Looks up `ip`.
    fn lookup(&self, ip: IpAddr) -> IpInfo;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn same_point_is_zero() {
        let d = haversine_km(51.5074, -0.1278, 51.5074, -0.1278);
        assert!(d.abs() < 1e-6, "{d}");
    }

    #[test]
    fn london_to_paris_is_about_343_km() {
        let d = haversine_km(51.5074, -0.1278, 48.8566, 2.3522);
        assert!((330.0..360.0).contains(&d), "{d}");
    }

    #[test]
    fn equator_half_circumference() {
        let d = haversine_km(0.0, 0.0, 0.0, 180.0);
        let expected = std::f64::consts::PI * EARTH_RADIUS_KM;
        assert!((d - expected).abs() < 1.0, "{d} vs {expected}");
    }

    #[test]
    fn rejects_out_of_range_coordinates() {
        assert!(haversine_km(91.0, 0.0, 0.0, 0.0).is_nan());
    }

    #[test]
    fn ipv6_privacy_addresses_share_a_slash_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::abcd".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_network(a), source_network(b));
        assert_ne!(source_network(a), source_network(c));
        assert_eq!(source_network(a).prefix(), 64);
        assert_eq!(
            source_network(a).ip(),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv4_is_a_host_route() {
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let network = source_network(ip);
        assert_eq!(network.prefix(), 32);
        assert_eq!(network.ip(), ip);
    }

    #[test]
    fn ipv4_mapped_ipv6_collapses_to_the_v4_host() {
        let v4: IpAddr = "203.0.113.10".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.10".parse().unwrap();
        assert_eq!(source_network(v4), source_network(mapped));
    }

    proptest! {
        #[test]
        fn haversine_is_symmetric(
            lat1 in -90.0..90.0,
            lon1 in -180.0..180.0,
            lat2 in -90.0..90.0,
            lon2 in -180.0..180.0,
        ) {
            let d1 = haversine_km(lat1, lon1, lat2, lon2);
            let d2 = haversine_km(lat2, lon2, lat1, lon1);
            prop_assert!(d1.is_finite());
            prop_assert!((d1 - d2).abs() < 1e-6);
            prop_assert!(d1 >= 0.0);
            prop_assert!(d1 <= std::f64::consts::PI * EARTH_RADIUS_KM + 1e-6);
        }

        #[test]
        fn haversine_same_location_is_zero(lat in -90.0..90.0, lon in -180.0..180.0) {
            let d = haversine_km(lat, lon, lat, lon);
            prop_assert!(d.abs() < 1e-6);
        }
    }
}
