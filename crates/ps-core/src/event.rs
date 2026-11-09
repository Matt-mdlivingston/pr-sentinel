//! A single login attempt, as the scorer sees it.

use crate::{DeviceFingerprint, EventId, IdError, TenantId, UserId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

/// One authentication attempt.
///
/// The struct is the contract between producers (a log pipeline, the synthetic
/// generator) and the scoring engine. It deliberately has no geolocation:
/// coordinates come from enrichment and can be replayed with a different
/// database without rewriting the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginEvent {
    /// Unique id within the batch being scored.
    pub event_id: EventId,
    /// Account that was presented.
    pub user_id: UserId,
    /// Customer or organization that owns the account.
    pub tenant_id: TenantId,
    /// When the attempt happened, in UTC. Scoring uses this clock, never wall time.
    pub timestamp: DateTime<Utc>,
    /// Client address. Not a user identity; see the crate docs.
    pub ip: IpAddr,
    /// Raw user-agent string. Empty when the source system did not record one.
    pub user_agent: String,
    /// Whether the identity provider accepted the credentials.
    pub success: bool,
    /// Optional caller-supplied device id. Unused by milestone 1 signals.
    pub device_fingerprint: Option<DeviceFingerprint>,
}

/// A login event failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EventError {
    /// An identifier on the event was empty or too long.
    #[error(transparent)]
    Id(#[from] IdError),
}

impl LoginEvent {
    /// Checks invariants that deserialization cannot express.
    ///
    /// Identifiers are already validated by their types. This method exists so
    /// callers have one place to extend event checks later (for example a
    /// required user-agent) without changing the engine.
    ///
    /// # Errors
    ///
    /// Reserved for future field checks. The current implementation always
    /// returns `Ok(())` for a successfully constructed event.
    pub fn validate(&self) -> Result<(), EventError> {
        let _ = self.event_id.as_str();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_keeps_optional_fingerprint_absent() {
        let event = LoginEvent {
            event_id: EventId::new("evt-1").unwrap(),
            user_id: UserId::new("user-1").unwrap(),
            tenant_id: TenantId::new("demo").unwrap(),
            timestamp: "2026-01-05T15:04:05Z".parse().unwrap(),
            ip: "203.0.113.10".parse().unwrap(),
            user_agent: "ua".to_owned(),
            success: true,
            device_fingerprint: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LoginEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
        assert!(back.device_fingerprint.is_none());
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let json = r#"{
            "event_id": "evt-1",
            "user_id": "user-1",
            "tenant_id": "demo",
            "timestamp": "2026-01-05T15:04:05Z",
            "ip": "203.0.113.10",
            "user_agent": "ua",
            "success": true,
            "device_fingerprint": null,
            "labels": ["nope"]
        }"#;
        assert!(serde_json::from_str::<LoginEvent>(json).is_err());
    }
}
