//! Fixed cities the synthetic population lives in.
//!
//! Coordinates are ordinary city centers, not lookups from a geolocation
//! database. The ASN numbers are real, well-known networks so a fixture is
//! readable, but the IP addresses that point at them are documentation
//! addresses. Nothing here is a claim about where those ASNs geolocate.

use ps_enrich::FixtureIp;

pub(crate) struct Place {
    pub name: &'static str,
    pub city: &'static str,
    pub country_code: &'static str,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_radius_km: f64,
    pub asn: u32,
    pub asn_organization: &'static str,
    pub utc_offset_hours: i32,
}

impl Place {
    pub(crate) fn fixture(&self) -> FixtureIp {
        FixtureIp {
            latitude: self.latitude,
            longitude: self.longitude,
            accuracy_radius_km: Some(self.accuracy_radius_km),
            asn: Some(self.asn),
            asn_organization: Some(self.asn_organization.to_owned()),
            network_type: ps_core::NetworkType::Residential,
            city: Some(self.city.to_owned()),
            country_code: Some(self.country_code.to_owned()),
        }
    }
}

pub(crate) const PLACES: &[Place] = &[
    Place {
        name: "new_york",
        city: "New York",
        country_code: "US",
        latitude: 40.7128,
        longitude: -74.0060,
        accuracy_radius_km: 50.0,
        asn: 6167,
        asn_organization: "Verizon Business",
        utc_offset_hours: -5,
    },
    Place {
        name: "chicago",
        city: "Chicago",
        country_code: "US",
        latitude: 41.8781,
        longitude: -87.6298,
        accuracy_radius_km: 50.0,
        asn: 7922,
        asn_organization: "Comcast",
        utc_offset_hours: -6,
    },
    Place {
        name: "london",
        city: "London",
        country_code: "GB",
        latitude: 51.5074,
        longitude: -0.1278,
        accuracy_radius_km: 50.0,
        asn: 2856,
        asn_organization: "British Telecommunications",
        utc_offset_hours: 0,
    },
    Place {
        name: "paris",
        city: "Paris",
        country_code: "FR",
        latitude: 48.8566,
        longitude: 2.3522,
        accuracy_radius_km: 50.0,
        asn: 3215,
        asn_organization: "Orange",
        utc_offset_hours: 1,
    },
    Place {
        name: "berlin",
        city: "Berlin",
        country_code: "DE",
        latitude: 52.5200,
        longitude: 13.4050,
        accuracy_radius_km: 50.0,
        asn: 3320,
        asn_organization: "Deutsche Telekom",
        utc_offset_hours: 1,
    },
    Place {
        name: "tokyo",
        city: "Tokyo",
        country_code: "JP",
        latitude: 35.6762,
        longitude: 139.6503,
        accuracy_radius_km: 50.0,
        asn: 2516,
        asn_organization: "KDDI",
        utc_offset_hours: 9,
    },
    Place {
        name: "sydney",
        city: "Sydney",
        country_code: "AU",
        latitude: -33.8688,
        longitude: 151.2093,
        accuracy_radius_km: 50.0,
        asn: 1221,
        asn_organization: "Telstra",
        utc_offset_hours: 11,
    },
    Place {
        name: "sao_paulo",
        city: "Sao Paulo",
        country_code: "BR",
        latitude: -23.5558,
        longitude: -46.6396,
        accuracy_radius_km: 50.0,
        asn: 28573,
        asn_organization: "Claro",
        utc_offset_hours: -3,
    },
];

/// Where the credential-stuffing source sits. It is not a home.
pub(crate) const ATTACK_PLACE: Place = Place {
    name: "amsterdam",
    city: "Amsterdam",
    country_code: "NL",
    latitude: 52.3676,
    longitude: 4.9041,
    accuracy_radius_km: 25.0,
    asn: 14061,
    asn_organization: "Example Hosting",
    utc_offset_hours: 1,
};
