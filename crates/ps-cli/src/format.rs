//! Text rendering of a score. JSON rendering lives in `main`.

use chrono::SecondsFormat;
use ps_core::{LoginEvent, RiskScore};
use std::fmt::Write;

pub fn text(event: &LoginEvent, score: &RiskScore) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  {}  {}  {}  {}  success={}",
        event.event_id,
        event.user_id,
        event.tenant_id,
        event.ip,
        event.timestamp.to_rfc3339_opts(SecondsFormat::Secs, true),
        event.success,
    );
    let _ = writeln!(
        out,
        "  score {}/100  probability {:.3}  log-odds {:+.2} -> {:+.2}",
        score.score, score.probability, score.prior_log_odds, score.total_log_odds,
    );
    let _ = writeln!(
        out,
        "  {:<22} {:>4} pts  log-odds {:+.2}  base rate before evidence",
        "prior", score.prior_points, score.prior_log_odds,
    );
    for contribution in &score.contributions {
        let _ = writeln!(
            out,
            "  {:<22} {:>+4} pts  log-odds {:+.2}  {}",
            contribution.id, contribution.points, contribution.log_odds, contribution.reason,
        );
    }
    let _ = writeln!(out);
    out
}
