//! IP enrichment for pr-sentinel.
//!
//! [`ps_core::IpLookup`] is the only thing the rest of the pipeline needs.
//! This crate provides three implementations:
//!
//! * [`DbIpEnricher`] reads the free [DB-IP](https://db-ip.com) City Lite and
//!   ASN Lite MMDB files (CC BY 4.0). Those files are downloaded by
//!   `cargo xtask download-geodb` and are not committed.
//! * [`FixtureLookup`] answers from a JSON map, which is how the synthetic
//!   generator and the unit tests supply coordinates for documentation-range
//!   addresses that no public database contains.
//! * [`FallbackLookup`] tries a primary lookup and, on a complete miss, a
//!   secondary one. The CLI uses this so a real database is consulted first
//!   and the synthetic fixture fills in `203.0.113.0/24` and `198.51.100.0/24`.
//!
//! Source identity (IPv4 `/32`, IPv6 `/64`) lives in [`ps_core::source_network`]
//! because it is a scoring decision, not a property of the database.
//!
//! DB-IP City Lite does not publish an accuracy radius or a network-class
//! field. The reader leaves [`ps_core::IpInfo::accuracy_radius_km`] empty and
//! [`ps_core::NetworkType`] as [`ps_core::NetworkType::Unknown`]. The travel
//! detector applies the rules file's default radius only when the radius is
//! empty, so a database that does publish one (a commercial MMDB, for
//! example) takes precedence without a code change.

#![forbid(unsafe_code)]

mod dbip;
mod fallback;
mod fixture;

pub use dbip::{DbIpEnricher, EnrichError};
pub use fallback::FallbackLookup;
pub use fixture::{FixtureError, FixtureIp, FixtureLookup, GeoFixture};
