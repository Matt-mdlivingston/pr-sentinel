//! Seeded synthetic login traffic for pr-sentinel.
//!
//! The generator builds a small population of users who mostly sign in from
//! home, on a stable device, during local daytime, and then injects two
//! labeled attacks:
//!
//! * impossible travel — a user appears on another continent minutes after a
//!   home login
//! * credential stuffing — one address tries many fresh accounts and fails
//!   most of the attempts
//!
//! Addresses are taken from the IPv4 documentation ranges in RFC 5737
//! (`203.0.113.0/24`, `198.51.100.0/24`). They are not real users and they are
//! not in DB-IP. Every address used in the file is described by a
//! [`ps_enrich::GeoFixture`] written next to the events, so scoring does not
//! depend on a geolocation database and the same seed produces the same
//! labels on every platform.
//!
//! The random-looking jitter is a tiny portable mixer, not `rand`'s
//! `StdRng`. `StdRng` is explicitly allowed to change output across versions
//! and platforms, which would make a seeded regression test lie.

#![forbid(unsafe_code)]

mod catalog;
mod generate;

pub use generate::{
    Dataset, GenerateError, GenerateOptions, GeneratedEvent, Label, Summary, generate,
};
