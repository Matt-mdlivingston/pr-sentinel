//! Primary lookup with a secondary used only on a complete miss.

use ps_core::{IpInfo, IpLookup};
use std::net::IpAddr;

/// Tries `primary` and, when that lookup has neither coordinates nor an ASN,
/// tries `secondary`.
///
/// A partial primary hit is kept. Mixing a database city with a fixture ASN
/// would hide which source a score came from.
#[derive(Debug, Clone)]
pub struct FallbackLookup<P, S> {
    /// Consulted first.
    pub primary: P,
    /// Consulted when the primary has no network evidence.
    pub secondary: S,
}

impl<P, S> FallbackLookup<P, S> {
    /// Builds a fallback chain.
    pub fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P: IpLookup, S: IpLookup> IpLookup for FallbackLookup<P, S> {
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        let primary = self.primary.lookup(ip);
        if primary.has_network_evidence() {
            return primary;
        }
        let secondary = self.secondary.lookup(ip);
        if secondary.has_network_evidence() {
            secondary
        } else {
            primary
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::NetworkType;

    struct Fixed {
        info: IpInfo,
    }

    impl IpLookup for Fixed {
        fn lookup(&self, ip: IpAddr) -> IpInfo {
            if self.info.ip == ip {
                self.info.clone()
            } else {
                IpInfo::unknown(ip)
            }
        }
    }

    #[test]
    fn secondary_fills_a_primary_miss_and_does_not_override_a_hit() {
        let known: IpAddr = "8.8.8.8".parse().unwrap();
        let synthetic: IpAddr = "203.0.113.10".parse().unwrap();
        let primary = Fixed {
            info: IpInfo {
                ip: known,
                latitude: Some(37.4),
                longitude: Some(-122.0),
                accuracy_radius_km: None,
                asn: Some(15169),
                asn_organization: Some("Google LLC".to_owned()),
                network_type: NetworkType::Unknown,
                country_code: Some("US".to_owned()),
                city: Some("Mountain View".to_owned()),
            },
        };
        let secondary = Fixed {
            info: IpInfo {
                ip: synthetic,
                latitude: Some(40.7),
                longitude: Some(-74.0),
                accuracy_radius_km: Some(50.0),
                asn: Some(6167),
                asn_organization: Some("Example".to_owned()),
                network_type: NetworkType::Residential,
                country_code: Some("US".to_owned()),
                city: Some("New York".to_owned()),
            },
        };
        let lookup = FallbackLookup::new(primary, secondary);
        assert_eq!(lookup.lookup(known).asn, Some(15169));
        assert_eq!(lookup.lookup(synthetic).asn, Some(6167));
        assert!(
            !lookup
                .lookup("198.51.100.9".parse().unwrap())
                .has_network_evidence()
        );
    }
}
