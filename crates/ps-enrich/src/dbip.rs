//! DB-IP Lite readers.
//!
//! The City Lite and ASN Lite files follow the MaxMind DB specification and
//! are close to the GeoLite2 schema, but they are not GeoLite2. City Lite
//! publishes coordinates and omits `location.accuracy_radius`. ASN Lite
//! publishes `autonomous_system_number` and `autonomous_system_organization`
//! at the top of the record. The structs below name only the fields we use;
//! unknown fields are ignored so a later DB-IP revision can add keys without
//! breaking the reader.

use maxminddb::{MaxMindDbError, Reader};
use ps_core::{IpInfo, IpLookup, NetworkType};
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

/// A City Lite database and an ASN Lite database opened together.
#[derive(Debug)]
pub struct DbIpEnricher {
    city: Reader<Vec<u8>>,
    asn: Reader<Vec<u8>>,
}

/// Opening a DB-IP file failed.
#[derive(Debug, Error)]
pub enum EnrichError {
    /// The file could not be read or is not a MaxMind DB.
    #[error("failed to open {kind} database at {path}: {source}")]
    Open {
        /// Which database was requested.
        kind: &'static str,
        /// Path that failed.
        path: std::path::PathBuf,
        /// Reader error.
        #[source]
        source: MaxMindDbError,
    },
}

#[derive(Debug, Deserialize)]
struct CityRecord {
    city: Option<NamedPlace>,
    country: Option<Country>,
    location: Option<Location>,
}

#[derive(Debug, Deserialize)]
struct NamedPlace {
    names: Option<LocalizedName>,
}

#[derive(Debug, Deserialize)]
struct Country {
    iso_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LocalizedName {
    en: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Location {
    latitude: Option<f64>,
    longitude: Option<f64>,
    #[serde(default)]
    accuracy_radius: Option<FlexUint>,
}

#[derive(Debug, Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

/// DB-IP and MaxMind both use an integer radius, but a custom database might
/// write a float. Accept either.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexUint {
    Int(u64),
    Float(f64),
}

impl FlexUint {
    fn as_f64(&self) -> Option<f64> {
        let value = match self {
            #[allow(clippy::cast_precision_loss)]
            Self::Int(value) => *value as f64,
            Self::Float(value) => *value,
        };
        value.is_finite().then_some(value)
    }
}

impl DbIpEnricher {
    /// Loads both databases into memory.
    ///
    /// Memory mapping is available in `maxminddb` and is a better fit for a
    /// long-running process. The CLI scores a file and exits, so a plain read
    /// keeps the dependency set smaller.
    ///
    /// # Errors
    ///
    /// Returns [`EnrichError::Open`] when a path is missing or not a MaxMind DB.
    pub fn open(city_db: impl AsRef<Path>, asn_db: impl AsRef<Path>) -> Result<Self, EnrichError> {
        Ok(Self {
            city: open_reader(city_db.as_ref(), "city")?,
            asn: open_reader(asn_db.as_ref(), "asn")?,
        })
    }

    /// Database type strings from the two MMDB headers.
    ///
    /// Useful for logs. DB-IP City Lite reports `DBIP-City-Lite`.
    #[must_use]
    pub fn database_types(&self) -> (&str, &str) {
        (
            self.city.metadata().database_type.as_str(),
            self.asn.metadata().database_type.as_str(),
        )
    }
}

fn open_reader(path: &Path, kind: &'static str) -> Result<Reader<Vec<u8>>, EnrichError> {
    Reader::open_readfile(path).map_err(|source| EnrichError::Open {
        kind,
        path: path.to_path_buf(),
        source,
    })
}

impl IpLookup for DbIpEnricher {
    fn lookup(&self, ip: IpAddr) -> IpInfo {
        let mut info = IpInfo::unknown(ip);
        if let Ok(result) = self.city.lookup(ip) {
            if let Ok(Some(record)) = result.decode::<CityRecord>() {
                apply_city(&mut info, record);
            }
        }
        if let Ok(result) = self.asn.lookup(ip) {
            if let Ok(Some(record)) = result.decode::<AsnRecord>() {
                info.asn = record.autonomous_system_number;
                info.asn_organization = record
                    .autonomous_system_organization
                    .filter(|name| !name.is_empty());
            }
        }
        // Free DB-IP Lite has no connection-type or hosting flag. Leaving this
        // unknown is deliberate: guessing from an ASN name would be a hidden
        // heuristic. Milestone 3 can fill it from a maintained list.
        info.network_type = NetworkType::Unknown;
        info
    }
}

fn apply_city(info: &mut IpInfo, record: CityRecord) {
    if let Some(city) = record
        .city
        .and_then(|place| place.names)
        .and_then(|names| names.en)
    {
        if !city.is_empty() {
            info.city = Some(city);
        }
    }
    if let Some(country) = record.country {
        info.country_code = country.iso_code.filter(|code| !code.is_empty());
    }
    if let Some(location) = record.location {
        info.latitude = location.latitude.filter(|value| value.is_finite());
        info.longitude = location.longitude.filter(|value| value.is_finite());
        info.accuracy_radius_km = location.accuracy_radius.and_then(|radius| radius.as_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn data_file(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("data")
            .join(name)
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = DbIpEnricher::open("/no/such/city.mmdb", "/no/such/asn.mmdb").unwrap_err();
        assert!(matches!(err, EnrichError::Open { kind: "city", .. }));
    }

    #[test]
    fn reads_dbip_lite_when_the_files_are_present() {
        let city = data_file("dbip-city-lite.mmdb");
        let asn = data_file("dbip-asn-lite.mmdb");
        if !city.exists() || !asn.exists() {
            eprintln!(
                "skipping DB-IP reader test; run `cargo xtask download-geodb` (looked in {})",
                city.display()
            );
            return;
        }
        let enricher = DbIpEnricher::open(&city, &asn).unwrap();
        let (city_type, asn_type) = enricher.database_types();
        assert!(
            city_type.contains("DBIP") || city_type.contains("City"),
            "{city_type}"
        );
        assert!(
            asn_type.contains("ASN") || asn_type.contains("DBIP"),
            "{asn_type}"
        );

        let info = enricher.lookup("8.8.8.8".parse().unwrap());
        assert_eq!(info.country_code.as_deref(), Some("US"));
        assert!(info.city.is_some());
        assert!(info.latitude.is_some() && info.longitude.is_some());
        assert!(info.asn.is_some());
        assert!(info.asn_organization.is_some());
        // City Lite's published schema has no accuracy radius. A future file
        // that adds one should fail this assertion so we notice and keep the
        // "radius if available" path honest.
        assert!(info.accuracy_radius_km.is_none());
        assert_eq!(info.network_type, NetworkType::Unknown);

        let reserved = enricher.lookup("203.0.113.10".parse().unwrap());
        assert!(!reserved.has_network_evidence());
    }
}
