//! The detector interface.
//!
//! A signal looks at one event, the enrichment for its IP, and the history of
//! events that have already been scored. It returns at most one [`SignalHit`].
//! It does not update state. The engine observes the event only after every
//! signal has run, so detectors share a consistent "past" for this event.

use crate::rules::EffectiveRules;
use crate::state::RiskView;
use ps_core::{IpInfo, LoginEvent, SignalHit};

/// Context for one detector invocation.
#[derive(Clone, Copy)]
pub struct EvalCtx<'a> {
    /// The login being scored.
    pub event: &'a LoginEvent,
    /// Enrichment for [`LoginEvent::ip`](ps_core::LoginEvent::ip).
    pub ip: &'a IpInfo,
    /// History strictly before this event.
    pub state: &'a dyn RiskView,
    /// Rules after the tenant overlay.
    pub rules: &'a EffectiveRules,
}

/// One detector.
///
/// Implementations are stateless. Per-user memory lives in [`RiskView`], and
/// per-tenant thresholds live in [`EffectiveRules`], so the same detector
/// value can score every event.
pub trait Signal: Send + Sync {
    /// Stable id, matching [`ps_core::SignalId`] constants for built-in detectors.
    fn id(&self) -> &'static str;

    /// Evidence for this event, or `None` when the detector does not fire.
    fn evaluate(&self, ctx: &EvalCtx<'_>) -> Option<SignalHit>;
}
