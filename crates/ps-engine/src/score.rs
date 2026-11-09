//! Log-odds scoring and exact integer attribution of the 0–100 score.

use ps_core::{RiskScore, SignalContribution, SignalHit};

/// Logistic function, stable for large positive and negative inputs.
#[must_use]
pub fn sigmoid(log_odds: f64) -> f64 {
    if !log_odds.is_finite() {
        return if log_odds.is_sign_negative() {
            0.0
        } else {
            1.0
        };
    }
    if log_odds >= 0.0 {
        let z = (-log_odds).exp();
        1.0 / (1.0 + z)
    } else {
        let z = log_odds.exp();
        z / (1.0 + z)
    }
}

fn probability_to_score(probability: f64) -> u8 {
    if !probability.is_finite() {
        return 0;
    }
    let scaled = (probability.clamp(0.0, 1.0) * 100.0).round();
    if scaled >= 100.0 {
        100
    } else if scaled <= 0.0 {
        0
    } else {
        // `scaled` is a finite value in (0, 100) that was produced by `round`.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            scaled as u8
        }
    }
}

/// Turns a prior and detector hits into a [`RiskScore`].
///
/// Non-finite hits are dropped. Hits whose log-odds are exactly zero are
/// dropped too: they carry no evidence, and a zero weight would otherwise be
/// able to receive a leftover point when fractional parts tie.
///
/// The returned score satisfies `score.attributed_total() == i32::from(score.score)`.
#[must_use]
pub fn attribute(prior_log_odds: f64, hits: &[SignalHit]) -> RiskScore {
    let prior_log_odds = if prior_log_odds.is_finite() {
        prior_log_odds
    } else {
        0.0
    };
    let hits: Vec<&SignalHit> = hits
        .iter()
        .filter(|hit| hit.log_odds.is_finite() && hit.log_odds != 0.0)
        .collect();
    let signal_log_odds: f64 = hits.iter().map(|hit| hit.log_odds).sum();
    let total_log_odds = prior_log_odds + signal_log_odds;
    let probability = sigmoid(total_log_odds);
    let score = probability_to_score(probability);
    let prior_score = probability_to_score(sigmoid(prior_log_odds));
    let delta = i32::from(score) - i32::from(prior_score);
    let weights: Vec<f64> = hits.iter().map(|hit| hit.log_odds).collect();
    let points = apportion(delta, &weights);
    let contributions = hits
        .iter()
        .zip(points.iter().copied())
        .map(|(hit, pts)| SignalContribution {
            id: hit.id.clone(),
            log_odds: hit.log_odds,
            points: i16::try_from(pts).unwrap_or(if pts.is_negative() {
                i16::MIN
            } else {
                i16::MAX
            }),
            reason: hit.reason.clone(),
        })
        .collect();
    RiskScore {
        score,
        prior_log_odds,
        total_log_odds,
        probability,
        prior_points: prior_score,
        contributions,
    }
}

/// Largest-remainder apportionment of `total` across `weights`.
///
/// The returned integers sum to `total` when the weights are finite and their
/// sum is finite and non-zero. Otherwise every share is zero and the caller
/// keeps `total` on the prior.
fn apportion(total: i32, weights: &[f64]) -> Vec<i32> {
    let n = weights.len();
    if n == 0 || total == 0 {
        return vec![0; n];
    }
    if weights.iter().any(|w| !w.is_finite()) {
        return vec![0; n];
    }
    let sum_w: f64 = weights.iter().sum();
    if sum_w == 0.0 || !sum_w.is_finite() {
        return vec![0; n];
    }
    let raw: Vec<f64> = weights
        .iter()
        .map(|w| f64::from(total) * w / sum_w)
        .collect();
    if raw.iter().any(|r| !r.is_finite()) {
        return vec![0; n];
    }
    let mut base: Vec<i32> = raw.iter().copied().map(floor_i32).collect();
    let assigned: i32 = base.iter().sum();
    let mut leftover = total - assigned;
    if leftover < 0 {
        // Floor can only undershoot a finite sum. A negative leftover means
        // the conversion saturated; hand the whole total to the largest weight.
        let mut out = vec![0; n];
        if let Some((idx, _)) = weights
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1).then(b.0.cmp(&a.0)))
        {
            out[idx] = total;
        }
        return out;
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&i, &j| {
        let fi = raw[i] - f64::from(base[i]);
        let fj = raw[j] - f64::from(base[j]);
        fj.total_cmp(&fi).then(i.cmp(&j))
    });
    let mut cursor = 0;
    while leftover > 0 {
        base[order[cursor % n]] += 1;
        leftover -= 1;
        cursor += 1;
        if cursor > n.saturating_mul(4) {
            break;
        }
    }
    base
}

fn floor_i32(value: f64) -> i32 {
    let floored = value.floor();
    if floored >= f64::from(i32::MAX) {
        i32::MAX
    } else if floored <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            floored as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::SignalId;

    fn hit(id: &str, log_odds: f64) -> SignalHit {
        SignalHit {
            id: SignalId::new(id),
            log_odds,
            reason: id.to_owned(),
        }
    }
    use proptest::prelude::*;

    #[test]
    fn sigmoid_of_zero_is_one_half() {
        let score = attribute(0.0, &[]);
        assert!((score.probability - 0.5).abs() < 1e-12);
        assert_eq!(score.score, 50);
        assert_eq!(score.prior_points, 50);
        assert!(score.contributions.is_empty());
        assert_eq!(score.attributed_total(), 50);
    }

    #[test]
    fn five_percent_prior_displays_as_five() {
        let prior = 0.05_f64.ln() - 0.95_f64.ln();
        let score = attribute(prior, &[]);
        assert_eq!(score.score, 5, "probability {}", score.probability);
        assert_eq!(score.attributed_total(), i32::from(score.score));
    }

    #[test]
    fn known_split_sums_and_favors_the_larger_signal() {
        let score = attribute(-2.944_438_879, &[hit("a", 4.0), hit("b", 2.0)]);
        assert_eq!(score.attributed_total(), i32::from(score.score));
        let a = score.contribution("a").unwrap().points;
        let b = score.contribution("b").unwrap().points;
        assert!(a > b, "a={a} b={b}");
        assert!(a > 0 && b > 0);
    }

    #[test]
    fn zero_log_odds_are_not_given_points() {
        let score = attribute(0.0, &[hit("mute", 0.0), hit("real", 1.0)]);
        assert!(score.contribution("mute").is_none());
        assert_eq!(score.attributed_total(), i32::from(score.score));
    }

    #[test]
    fn negative_evidence_lowers_the_score() {
        let base = attribute(1.0, &[]);
        let lowered = attribute(1.0, &[hit("familiar", -1.5)]);
        assert!(lowered.score < base.score);
        assert_eq!(lowered.attributed_total(), i32::from(lowered.score));
        assert!(lowered.contribution("familiar").unwrap().points <= 0);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn attribution_is_exact_and_score_is_bounded(
            prior in -8.0..2.0,
            weights in proptest::collection::vec(-4.0..6.0f64, 0..6usize),
        ) {
            let hits: Vec<SignalHit> = weights.iter().enumerate().map(|(i, w)| {
                hit(&format!("s{i}"), *w)
            }).collect();
            let score = attribute(prior, &hits);
            prop_assert_eq!(score.attributed_total(), i32::from(score.score));
            prop_assert!(score.score <= 100);
            let sum_lo: f64 = score.contributions.iter().map(|c| c.log_odds).sum();
            prop_assert!((score.prior_log_odds + sum_lo - score.total_log_odds).abs() < 1e-9);
        }

        #[test]
        fn score_is_monotonic_in_a_contribution(
            prior in -6.0..1.0,
            left in 0.0..5.0f64,
            right in 0.0..5.0f64,
            bump in 0.0..4.0f64,
        ) {
            let before = attribute(prior, &[hit("a", left), hit("b", right)]).score;
            let after = attribute(prior, &[hit("a", left + bump), hit("b", right)]).score;
            prop_assert!(after >= before);
        }
    }
}
