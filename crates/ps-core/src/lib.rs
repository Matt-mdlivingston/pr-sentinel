//! Domain types for [pr-sentinel](https://github.com/Matt-mdlivingston/pr-sentinel).
//!
//! This crate is pure data and math. It does not read files, open sockets, or
//! look at the clock. Login events come in, enrichment facts are attached by a
//! caller, and risk scores go out with one contribution per signal.
//!
//! IP addresses are a weak identity (carrier NAT, VPNs, proxies, IPv6 privacy
//! addresses, DHCP churn). Nothing in this crate treats an IP as a person.
//! [`source_network`] documents the only subnet collapse we do apply: IPv6
//! addresses are keyed at `/64` so temporary privacy addresses from one
//! network do not look like many sources.

#![forbid(unsafe_code)]

mod event;
mod geo;
mod id;
mod score;

pub use event::{EventError, LoginEvent};
pub use geo::{IpInfo, IpLookup, NetworkType, coordinates_are_valid, haversine_km, source_network};
pub use id::{DeviceFingerprint, EventId, IdError, TenantId, UserId};
pub use score::{RiskScore, SignalContribution, SignalHit, SignalId};
