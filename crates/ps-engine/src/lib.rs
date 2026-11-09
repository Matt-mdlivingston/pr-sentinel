//! Login risk scoring for pr-sentinel.
//!
//! The engine is pure once a [`Rules`] table and a [`RiskState`] are in hand.
//! It does not read the geolocation database and it does not call the clock.
//! Callers enrich each [`LoginEvent`](ps_core::LoginEvent) and then pass
//! events in non-decreasing timestamp order. That single rule is what lets
//! the same code replay a file and, later, score a stream.
//!
//! # Scoring
//!
//! Evidence is a log-likelihood ratio. A prior log-odds `L0` (the base rate)
//! plus each signal's log-odds `L_i` gives
//!
//! ```text
//! L = L0 + Σ L_i
//! score = round(100 * σ(L))
//! ```
//!
//! where `σ` is the logistic function. Log-odds are the space where
//! independent evidence adds, so attribution of `L` is exact: each signal's
//! `log_odds` field is its whole contribution, and the sum of those fields
//! plus the prior equals `total_log_odds`.
//!
//! The 0–100 score is not additive, because `σ` is not linear. A signal that
//! adds 2.0 log-odds moves the score a lot when the running total is near
//! zero and barely at all when the total is already large. To still show a
//! point breakdown that adds up, the engine apportions `score - score(L0)`
//! across the signals by the largest-remainder method, weighted by their
//! log-odds. `prior_points + Σ points == score` holds exactly. The points are
//! an explanation of the displayed number. The log-odds are the model.
//!
//! Weights are policy, loaded from TOML, with per-tenant overrides. They are
//! not a fitted probability model.

#![forbid(unsafe_code)]

mod engine;
pub mod rules;
pub mod score;
pub mod signal;
mod signals;
pub mod state;

pub use engine::{Engine, EngineError};
pub use rules::{Rules, RulesError, default_rules};
pub use score::{attribute, sigmoid};
pub use signal::{EvalCtx, Signal};
pub use state::{
    AsnHistory, IpWindowQuery, IpWindowStats, MemoryState, Observation, PreviousLogin, RiskState,
    RiskView,
};
