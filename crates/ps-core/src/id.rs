//! Owned identifiers carried on a [`LoginEvent`](crate::LoginEvent).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const MAX_LEN: usize = 256;

/// Why an identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// The value was an empty string.
    #[error("{field} must not be empty")]
    Empty {
        /// Which identifier failed.
        field: &'static str,
    },
    /// The value was longer than the allowed byte length.
    #[error("{field} exceeds {max} bytes")]
    TooLong {
        /// Which identifier failed.
        field: &'static str,
        /// Maximum accepted length in bytes.
        max: usize,
    },
}

fn parse_id(field: &'static str, value: String) -> Result<String, IdError> {
    if value.is_empty() {
        return Err(IdError::Empty { field });
    }
    if value.len() > MAX_LEN {
        return Err(IdError::TooLong {
            field,
            max: MAX_LEN,
        });
    }
    Ok(value)
}

macro_rules! string_id {
    ($(#[$attr:meta])* $name:ident, $field:literal) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an id, rejecting empty and oversized values.
            ///
            /// # Errors
            ///
            /// Returns [`IdError`] when `value` is empty or longer than 256 bytes.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                Ok(Self(parse_id($field, value.into())?))
            }

            /// Returns the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

string_id!(
    /// Tenant that owns the user and the rules overlay.
    ///
    /// State and rules are always scoped by tenant so two customers who happen
    /// to use the same user id never share history.
    TenantId,
    "tenant_id"
);
string_id!(
    /// Account the login attempt was for.
    UserId,
    "user_id"
);
string_id!(
    /// Caller-supplied id for one login attempt.
    ///
    /// Batch replay orders events by timestamp and then by this id, so it
    /// should be unique inside a file.
    EventId,
    "event_id"
);
string_id!(
    /// Stable device identifier supplied by the caller.
    ///
    /// Milestone 1 stores the value and does not score it. Later milestones
    /// use it as a fingerprint signal.
    DeviceFingerprint,
    "device_fingerprint"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_ids() {
        assert!(matches!(
            UserId::new(""),
            Err(IdError::Empty { field: "user_id" })
        ));
        let too_long = "x".repeat(MAX_LEN + 1);
        assert!(matches!(
            TenantId::new(too_long),
            Err(IdError::TooLong { max: MAX_LEN, .. })
        ));
    }

    #[test]
    fn round_trips_through_json_as_a_string() {
        let id = EventId::new("evt-000001").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"evt-000001\"");
        let back: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
