//! Milestone 1 detectors.

mod impossible_travel;
mod ip_fanout;
mod new_asn;

pub use impossible_travel::ImpossibleTravel;
pub use ip_fanout::IpFanout;
pub use new_asn::NewAsn;

use crate::signal::Signal;

/// The built-in detectors, in the order their contributions are reported.
#[must_use]
pub fn builtin() -> Vec<Box<dyn Signal>> {
    vec![
        Box::new(ImpossibleTravel),
        Box::new(NewAsn),
        Box::new(IpFanout),
    ]
}
