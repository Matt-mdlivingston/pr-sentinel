//! Risk score types.
//!
//! The numbers inside these types are produced by `ps-engine`. They live here
//! so a CLI, an API, or a test can pass a score around without depending on
//! the detectors.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable name of a detector, for example `impossible_travel`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignalId(String);

impl SignalId {
    /// Signal id for impossible travel.
    pub const IMPOSSIBLE_TRAVEL: &'static str = "impossible_travel";
    /// Signal id for an ASN this user has not used before.
    pub const NEW_ASN: &'static str = "new_asn";
    /// Signal id for one source touching many accounts.
    pub const IP_FANOUT: &'static str = "ip_fanout";

    /// Creates an id from any non-empty string.
    ///
    /// Empty ids are replaced with `unknown` so a score can still be printed.
    /// Built-in detectors use the constants on this type instead.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        if id.is_empty() {
            Self("unknown".to_owned())
        } else {
            Self(id)
        }
    }

    /// Returns the id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SignalId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Evidence emitted by one detector, before it is turned into points.
///
/// `log_odds` is a natural-log likelihood ratio. Independent signals add in
/// this space. The human-readable [`SignalHit::reason`] describes the evidence
/// (a speed, a count), not the weight, so an operator can retune weights
/// without changing what the detector claims to have seen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalHit {
    /// Detector that produced the hit.
    pub id: SignalId,
    /// Signed log-likelihood ratio added to the prior.
    pub log_odds: f64,
    /// What was observed, in plain language.
    pub reason: String,
}

/// One detector's share of a [`RiskScore`].
///
/// `points` is an integer on the same 0–100 scale as [`RiskScore::score`].
/// Across the score, `prior_points + sum(points)` equals `score` exactly.
/// See the engine scoring docs for why this is an apportionment of a
/// non-linear probability and not a second copy of `log_odds`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalContribution {
    /// Detector that produced the contribution.
    pub id: SignalId,
    /// Log-odds added by this detector. Additive with the other contributions.
    pub log_odds: f64,
    /// Integer points attributed to this detector on the 0–100 scale.
    pub points: i16,
    /// The detector's explanation, copied from [`SignalHit::reason`].
    pub reason: String,
}

/// A 0–100 risk score and the evidence behind it.
///
/// `score` is `round(100 * sigmoid(total_log_odds))`. The probability is a
/// calibrated-looking number only to the extent the weights are; milestone 1
/// treats weights as operator policy, not as a fitted model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Display score in `0..=100`.
    pub score: u8,
    /// Log-odds of the base rate, before evidence.
    pub prior_log_odds: f64,
    /// Prior plus every contribution's log-odds.
    pub total_log_odds: f64,
    /// `sigmoid(total_log_odds)`, in `0.0..=1.0` for finite inputs.
    pub probability: f64,
    /// Points attributed to the base rate.
    ///
    /// Together with each [`SignalContribution::points`], these sum to
    /// [`RiskScore::score`].
    pub prior_points: u8,
    /// One entry per signal that returned evidence, in detector order.
    pub contributions: Vec<SignalContribution>,
}

impl RiskScore {
    /// Finds the contribution from `id`, if that signal fired.
    #[must_use]
    pub fn contribution(&self, id: &str) -> Option<&SignalContribution> {
        self.contributions.iter().find(|c| c.id.as_str() == id)
    }

    /// `prior_points + sum(contribution points)`.
    ///
    /// Equals [`RiskScore::score`] when the scorer built this value. Exposed
    /// so tests can state the attribution invariant without reimplementing it.
    #[must_use]
    pub fn attributed_total(&self) -> i32 {
        i32::from(self.prior_points)
            + self
                .contributions
                .iter()
                .map(|c| i32::from(c.points))
                .sum::<i32>()
    }
}
