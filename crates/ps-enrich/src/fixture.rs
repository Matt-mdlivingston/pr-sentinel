//! JSON geo fixture for synthetic addresses and tests.

use ps_core::{IpInfo, IpLookup, NetworkType, coordinates_are_valid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::IpAddr;
use thiserror::Error;

/// A map from IP address to enrichment facts.
///
/// Keys are stored as strings so the file is diffable and ordered. The
/// generator writes one of these next to every synthetic event file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GeoFixture {
    /// Address → facts. The key is the textual IP.
    pub ips: BTreeMap<String, FixtureIp>,
}

/// One address in a [`GeoFixture`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixtureIp {
    /// Latitude in degrees.
    pub latitude: f64,
    /// Longitude in degrees.
    pub longitude: f64,
    /// Accuracy radius in kilometers, when the scenario wants one.
    #[serde(default)]
    pub accuracy_radius_km: Option<f64>,
    /// Autonomous system number.
    #[serde(default)]
    pub asn: Option<u32>,
    /// Organization name for the ASN.
    #[serde(default)]
    pub asn_organization: Option<String>,
    /// Coarse network class. Defaults to unknown.
    #[serde(default)]
    pub network_type: NetworkType,
    /// City name.
    #[serde(default)]
    pub city: Option<String>,
    /// ISO country code.
    #[serde(default)]
    pub country_code: Option<String>,
}

/// A fixture could not be parsed or contained an illegal entry.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// The fixture could not be read.
    #[error("failed to read geo fixture: {0}")]
    Read(#[from] std::io::Error),
    /// JSON did not match [`GeoFixture`].
    #[error("geo fixture is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A map key was not an IP address.
    #[error("geo fixture key `{key}` is not an IP address")]
    BadIp {
        /// The offending key.
        key: String,
    },
    /// Coordinates were missing, infinite, or out of range.
    #[error("geo fixture entry {ip} has invalid coordinates")]
    BadCoordinates {
        /// Address whose coordinates were rejected.
        ip: String,
    },
}

impl GeoFixture {
    /// Parses a fixture from any reader.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureError`] when the JSON is invalid. Coordinate and IP
    /// checks happen in [`FixtureLookup::from_fixture`], so a file can be
    /// parsed and then rejected for a bad entry.
    pub fn from_reader(mut reader: impl Read) -> Result<Self, FixtureError> {
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Inserts or replaces the facts for `ip`.
    pub fn insert(&mut self, ip: IpAddr, record: FixtureIp) {
        self.ips.insert(ip.to_string(), record);
    }

    /// Looks up a record without converting it to [`IpInfo`].
    #[must_use]
    pub fn get(&self, ip: IpAddr) -> Option<&FixtureIp> {
        self.ips.get(&ip.to_string())
    }
}

impl FixtureIp {
    /// Converts this record into the domain type for `ip`.
    #[must_use]
    pub fn to_info(&self, ip: IpAddr) -> IpInfo {
        IpInfo {
            ip,
            latitude: Some(self.latitude),
            longitude: Some(self.longitude),
            accuracy_radius_km: self.accuracy_radius_km,
            asn: self.asn,
            asn_organization: self.asn_organization.clone(),
            network_type: self.network_type,
            country_code: self.country_code.clone(),
            city: self.city.clone(),
        }
    }
}

/// [`IpLookup`] backed by a [`GeoFixture`].
///
/// Addresses that are not in the map return [`IpInfo::unknown`].
#[derive(Debug, Clone)]
pub struct FixtureLookup {
    by_ip: HashMap<IpAddr, IpInfo>,
}

impl FixtureLookup {
    /// Builds a lookup table, checking every entry.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureError`] when a key is not an IP or coordinates are
    /// out of range.
    pub fn from_fixture(fixture: &GeoFixture) -> Result<Self, FixtureError> {
        let mut by_ip = HashMap::with_capacity(fixture.ips.len());
        for (key, record) in &fixture.ips {
            let ip: IpAddr = key
                .parse()
                .map_err(|_| FixtureError::BadIp { key: key.clone() })?;
            if !coordinates_are_valid(record.latitude, record.longitude) {
                return Err(FixtureError::BadCoordinates { ip: key.clone() });
            }
            by_ip.insert(ip, record.to_info(ip));
        }
        Ok(Self { by_ip })
    }
}

impl IpLookup for FixtureLookup {
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        self.by_ip
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| IpInfo::unknown(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_address_round_trips_and_unknown_address_is_empty() {
        let mut fixture = GeoFixture::default();
        fixture.insert(
            "203.0.113.10".parse().unwrap(),
            FixtureIp {
                latitude: 40.71,
                longitude: -74.0,
                accuracy_radius_km: Some(25.0),
                asn: Some(6167),
                asn_organization: Some("Example ISP".to_owned()),
                network_type: NetworkType::Residential,
                city: Some("New York".to_owned()),
                country_code: Some("US".to_owned()),
            },
        );
        let lookup = FixtureLookup::from_fixture(&fixture).unwrap();
        let info = lookup.lookup("203.0.113.10".parse().unwrap());
        assert_eq!(info.asn, Some(6167));
        assert_eq!(info.city.as_deref(), Some("New York"));
        assert!(
            !lookup
                .lookup("198.51.100.1".parse().unwrap())
                .has_network_evidence()
        );
    }

    #[test]
    fn bad_key_and_bad_coordinates_fail() {
        let mut fixture = GeoFixture::default();
        fixture.ips.insert(
            "not-an-ip".to_owned(),
            FixtureIp {
                latitude: 0.0,
                longitude: 0.0,
                accuracy_radius_km: None,
                asn: None,
                asn_organization: None,
                network_type: NetworkType::Unknown,
                city: None,
                country_code: None,
            },
        );
        assert!(matches!(
            FixtureLookup::from_fixture(&fixture),
            Err(FixtureError::BadIp { .. })
        ));

        let mut fixture = GeoFixture::default();
        fixture.insert(
            "203.0.113.10".parse().unwrap(),
            FixtureIp {
                latitude: 120.0,
                longitude: 0.0,
                accuracy_radius_km: None,
                asn: None,
                asn_organization: None,
                network_type: NetworkType::Unknown,
                city: None,
                country_code: None,
            },
        );
        assert!(matches!(
            FixtureLookup::from_fixture(&fixture),
            Err(FixtureError::BadCoordinates { .. })
        ));
    }
}
