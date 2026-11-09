//! TOML rules: global defaults plus a sparse per-tenant overlay.
//!
//! A tenant override replaces individual fields. Unset fields keep the global
//! value. The merged view is what a signal evaluates; the file on disk stays
//! the source of truth.

use crate::state::MemoryState;
use chrono::TimeDelta;
use ps_core::TenantId;
use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

/// Embedded copy of `rules/default.toml`.
pub const DEFAULT_RULES_TOML: &str = include_str!("../../../rules/default.toml");

/// Loads and validates the built-in rules.
///
/// # Errors
///
/// Returns an error if the embedded file ever fails validation. That is a
/// programming bug, so callers that only want the defaults can surface it
/// during startup.
pub fn default_rules() -> Result<Rules, RulesError> {
    Rules::from_toml(DEFAULT_RULES_TOML)
}

/// Validated scoring policy.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Base-rate and any future global scoring knobs.
    pub scoring: ScoringConfig,
    /// Bounds for in-memory history.
    pub state: StateConfig,
    /// Built-in detectors.
    pub signals: SignalConfigs,
    /// Sparse overrides keyed by tenant id.
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantOverride>,
}

/// Global scoring knobs.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoringConfig {
    /// Log-odds of the base rate, before evidence.
    #[serde(deserialize_with = "flex_f64")]
    pub prior_log_odds: f64,
}

/// How much history the in-memory state retains.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Maximum retained logins per tenant and user.
    pub max_user_observations: usize,
    /// IP hits older than this many seconds before the event being applied
    /// are discarded. Must cover every fan-out window.
    pub ip_retention_secs: u64,
}

/// The three milestone 1 detectors.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalConfigs {
    /// Velocity between consecutive logins.
    pub impossible_travel: ImpossibleTravelConfig,
    /// ASN not present in the user's retained history.
    pub new_asn: NewAsnConfig,
    /// One source, many accounts, inside a sliding window.
    pub ip_fanout: IpFanoutConfig,
}

/// Impossible-travel parameters.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpossibleTravelConfig {
    /// When false, the detector returns no evidence.
    pub enabled: bool,
    /// Log-odds added when the detector fires. Strength is 1.
    #[serde(deserialize_with = "flex_f64")]
    pub weight: f64,
    /// Speeds at or below this, in km/h, are plausible.
    #[serde(deserialize_with = "flex_f64")]
    pub max_plausible_speed_kmh: f64,
    /// Effective distance at or below this never fires, even at high speed.
    #[serde(deserialize_with = "flex_f64")]
    pub min_effective_distance_km: f64,
    /// Accuracy radius used when enrichment did not supply one.
    #[serde(deserialize_with = "flex_f64")]
    pub default_accuracy_radius_km: f64,
}

/// New-ASN parameters.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAsnConfig {
    /// When false, the detector returns no evidence.
    pub enabled: bool,
    /// Log-odds added when the detector fires.
    #[serde(deserialize_with = "flex_f64")]
    pub weight: f64,
    /// Minimum retained logins before an unseen ASN is evidence.
    pub min_prior_observations: usize,
}

/// IP fan-out parameters.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpFanoutConfig {
    /// When false, the detector returns no evidence.
    pub enabled: bool,
    /// Multiplied by strength to produce log-odds.
    #[serde(deserialize_with = "flex_f64")]
    pub weight: f64,
    /// Sliding window length in seconds.
    pub window_secs: u64,
    /// Distinct accounts at which the account dimension fires.
    pub min_distinct_accounts: u32,
    /// Failures at which the failure dimension fires.
    pub min_failures: u32,
    /// Failure bursts with fewer distinct accounts than this are ignored.
    pub min_accounts_for_failure_burst: u32,
    /// Upper bound on strength. Strength is 1 at a threshold.
    #[serde(deserialize_with = "flex_f64")]
    pub strength_cap: f64,
}

/// Optional replacement fields for one tenant.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TenantOverride {
    /// Scoring fields to replace.
    pub scoring: ScoringOverride,
    /// Signal fields to replace.
    pub signals: SignalOverrideSet,
}

/// Optional scoring replacements.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ScoringOverride {
    /// Replacement prior, when set.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub prior_log_odds: Option<f64>,
}

/// Optional per-signal replacements.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SignalOverrideSet {
    /// Impossible-travel replacements.
    pub impossible_travel: ImpossibleTravelOverride,
    /// New-ASN replacements.
    pub new_asn: NewAsnOverride,
    /// Fan-out replacements.
    pub ip_fanout: IpFanoutOverride,
}

/// Optional impossible-travel replacements.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ImpossibleTravelOverride {
    /// Replacement for `enabled`.
    pub enabled: Option<bool>,
    /// Replacement weight.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub weight: Option<f64>,
    /// Replacement speed limit.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub max_plausible_speed_kmh: Option<f64>,
    /// Replacement minimum distance.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub min_effective_distance_km: Option<f64>,
    /// Replacement default accuracy radius.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub default_accuracy_radius_km: Option<f64>,
}

/// Optional new-ASN replacements.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct NewAsnOverride {
    /// Replacement for `enabled`.
    pub enabled: Option<bool>,
    /// Replacement weight.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub weight: Option<f64>,
    /// Replacement history requirement.
    pub min_prior_observations: Option<usize>,
}

/// Optional fan-out replacements.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct IpFanoutOverride {
    /// Replacement for `enabled`.
    pub enabled: Option<bool>,
    /// Replacement weight.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub weight: Option<f64>,
    /// Replacement window.
    pub window_secs: Option<u64>,
    /// Replacement account threshold.
    pub min_distinct_accounts: Option<u32>,
    /// Replacement failure threshold.
    pub min_failures: Option<u32>,
    /// Replacement minimum accounts for a failure burst.
    pub min_accounts_for_failure_burst: Option<u32>,
    /// Replacement strength cap.
    #[serde(default, deserialize_with = "flex_f64_opt")]
    pub strength_cap: Option<f64>,
}

/// Policy for one event after tenant overrides are applied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EffectiveRules {
    /// Prior log-odds for this tenant.
    pub prior_log_odds: f64,
    /// Impossible-travel parameters.
    pub impossible_travel: ImpossibleTravelConfig,
    /// New-ASN parameters.
    pub new_asn: NewAsnConfig,
    /// Fan-out parameters.
    pub ip_fanout: IpFanoutConfig,
}

/// A rules file was unreadable or failed validation.
#[derive(Debug, Error)]
pub enum RulesError {
    /// TOML did not match the schema.
    #[error("rules could not be parsed: {0}")]
    Parse(#[from] toml::de::Error),
    /// A numeric field was NaN or infinite.
    #[error("{field} must be finite")]
    NotFinite {
        /// Dotted field path.
        field: String,
    },
    /// A numeric field was below an inclusive minimum.
    #[error("{field} must be >= {min}")]
    BelowMinimum {
        /// Dotted field path.
        field: String,
        /// Inclusive minimum.
        min: f64,
    },
    /// A numeric field was not strictly positive.
    #[error("{field} must be > 0")]
    NotPositive {
        /// Dotted field path.
        field: String,
    },
    /// IP retention does not cover a fan-out window, so a replay would forget
    /// events the detector still needs.
    #[error(
        "state.ip_retention_secs ({retention}) is shorter than the {signal} window ({window}s){where_}"
    )]
    RetentionShorterThanWindow {
        /// Configured retention.
        retention: u64,
        /// Signal whose window does not fit.
        signal: &'static str,
        /// Window that did not fit.
        window: u64,
        /// Tenant suffix, or empty for the global window.
        where_: String,
    },
}

fn flex_f64<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        I(i64),
        F(f64),
    }
    match Num::deserialize(deserializer)? {
        // Rules files use small integers. `as f64` is exact for every value
        // that fits in the mantissa, which covers any threshold an operator
        // would write.
        #[allow(clippy::cast_precision_loss)]
        Num::I(value) => Ok(value as f64),
        Num::F(value) => Ok(value),
    }
}

fn flex_f64_opt<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = flex_f64(deserializer)?;
    Ok(Some(value))
}

impl Rules {
    /// Parses and validates a rules document.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError`] when the TOML is structurally invalid or a field
    /// is outside the accepted range.
    pub fn from_toml(text: &str) -> Result<Self, RulesError> {
        let rules: Self = toml::from_str(text)?;
        rules.validate()?;
        Ok(rules)
    }

    /// Builds the in-memory state configured by this document.
    #[must_use]
    pub fn memory_state(&self) -> MemoryState {
        let retention =
            TimeDelta::try_seconds(i64::try_from(self.state.ip_retention_secs).unwrap_or(i64::MAX))
                .unwrap_or_else(TimeDelta::zero);
        MemoryState::new(self.state.max_user_observations, retention)
    }

    /// Merges the tenant overlay for `tenant` onto the global rules.
    ///
    /// Unknown tenants get the global rules unchanged.
    #[must_use]
    pub fn resolve(&self, tenant: &TenantId) -> EffectiveRules {
        let mut effective = EffectiveRules {
            prior_log_odds: self.scoring.prior_log_odds,
            impossible_travel: self.signals.impossible_travel,
            new_asn: self.signals.new_asn,
            ip_fanout: self.signals.ip_fanout,
        };
        let Some(over) = self.tenants.get(tenant.as_str()) else {
            return effective;
        };
        if let Some(prior) = over.scoring.prior_log_odds {
            effective.prior_log_odds = prior;
        }
        apply_travel(
            &mut effective.impossible_travel,
            &over.signals.impossible_travel,
        );
        apply_asn(&mut effective.new_asn, &over.signals.new_asn);
        apply_fanout(&mut effective.ip_fanout, &over.signals.ip_fanout);
        effective
    }

    fn validate(&self) -> Result<(), RulesError> {
        check_finite("scoring.prior_log_odds", self.scoring.prior_log_odds)?;
        if self.state.max_user_observations < 1 {
            return Err(RulesError::BelowMinimum {
                field: "state.max_user_observations".to_owned(),
                min: 1.0,
            });
        }
        check_positive(
            "state.ip_retention_secs",
            self.state.ip_retention_secs as f64,
        )?;
        validate_travel("signals.impossible_travel", &self.signals.impossible_travel)?;
        validate_asn("signals.new_asn", &self.signals.new_asn)?;
        validate_fanout("signals.ip_fanout", &self.signals.ip_fanout)?;
        ensure_retention(
            self.state.ip_retention_secs,
            self.signals.ip_fanout.window_secs,
            "",
        )?;
        for (tenant, over) in &self.tenants {
            let where_ = format!(" for tenant {tenant}");
            if let Some(prior) = over.scoring.prior_log_odds {
                check_finite(&format!("tenants.{tenant}.scoring.prior_log_odds"), prior)?;
            }
            let travel = merged_travel(
                &self.signals.impossible_travel,
                &over.signals.impossible_travel,
            );
            validate_travel(
                &format!("tenants.{tenant}.signals.impossible_travel"),
                &travel,
            )?;
            let asn = merged_asn(&self.signals.new_asn, &over.signals.new_asn);
            validate_asn(&format!("tenants.{tenant}.signals.new_asn"), &asn)?;
            let fanout = merged_fanout(&self.signals.ip_fanout, &over.signals.ip_fanout);
            validate_fanout(&format!("tenants.{tenant}.signals.ip_fanout"), &fanout)?;
            ensure_retention(self.state.ip_retention_secs, fanout.window_secs, &where_)?;
        }
        Ok(())
    }
}

fn apply_travel(target: &mut ImpossibleTravelConfig, over: &ImpossibleTravelOverride) {
    if let Some(value) = over.enabled {
        target.enabled = value;
    }
    if let Some(value) = over.weight {
        target.weight = value;
    }
    if let Some(value) = over.max_plausible_speed_kmh {
        target.max_plausible_speed_kmh = value;
    }
    if let Some(value) = over.min_effective_distance_km {
        target.min_effective_distance_km = value;
    }
    if let Some(value) = over.default_accuracy_radius_km {
        target.default_accuracy_radius_km = value;
    }
}

fn apply_asn(target: &mut NewAsnConfig, over: &NewAsnOverride) {
    if let Some(value) = over.enabled {
        target.enabled = value;
    }
    if let Some(value) = over.weight {
        target.weight = value;
    }
    if let Some(value) = over.min_prior_observations {
        target.min_prior_observations = value;
    }
}

fn apply_fanout(target: &mut IpFanoutConfig, over: &IpFanoutOverride) {
    if let Some(value) = over.enabled {
        target.enabled = value;
    }
    if let Some(value) = over.weight {
        target.weight = value;
    }
    if let Some(value) = over.window_secs {
        target.window_secs = value;
    }
    if let Some(value) = over.min_distinct_accounts {
        target.min_distinct_accounts = value;
    }
    if let Some(value) = over.min_failures {
        target.min_failures = value;
    }
    if let Some(value) = over.min_accounts_for_failure_burst {
        target.min_accounts_for_failure_burst = value;
    }
    if let Some(value) = over.strength_cap {
        target.strength_cap = value;
    }
}

fn merged_travel(
    base: &ImpossibleTravelConfig,
    over: &ImpossibleTravelOverride,
) -> ImpossibleTravelConfig {
    let mut merged = *base;
    apply_travel(&mut merged, over);
    merged
}

fn merged_asn(base: &NewAsnConfig, over: &NewAsnOverride) -> NewAsnConfig {
    let mut merged = *base;
    apply_asn(&mut merged, over);
    merged
}

fn merged_fanout(base: &IpFanoutConfig, over: &IpFanoutOverride) -> IpFanoutConfig {
    let mut merged = *base;
    apply_fanout(&mut merged, over);
    merged
}

fn validate_travel(prefix: &str, cfg: &ImpossibleTravelConfig) -> Result<(), RulesError> {
    check_non_negative(&format!("{prefix}.weight"), cfg.weight)?;
    check_positive(
        &format!("{prefix}.max_plausible_speed_kmh"),
        cfg.max_plausible_speed_kmh,
    )?;
    check_non_negative(
        &format!("{prefix}.min_effective_distance_km"),
        cfg.min_effective_distance_km,
    )?;
    check_non_negative(
        &format!("{prefix}.default_accuracy_radius_km"),
        cfg.default_accuracy_radius_km,
    )?;
    Ok(())
}

fn validate_asn(prefix: &str, cfg: &NewAsnConfig) -> Result<(), RulesError> {
    check_non_negative(&format!("{prefix}.weight"), cfg.weight)?;
    if cfg.min_prior_observations < 1 {
        return Err(RulesError::BelowMinimum {
            field: format!("{prefix}.min_prior_observations"),
            min: 1.0,
        });
    }
    Ok(())
}

fn validate_fanout(prefix: &str, cfg: &IpFanoutConfig) -> Result<(), RulesError> {
    check_non_negative(&format!("{prefix}.weight"), cfg.weight)?;
    check_positive(&format!("{prefix}.window_secs"), cfg.window_secs as f64)?;
    check_at_least(
        &format!("{prefix}.min_distinct_accounts"),
        f64::from(cfg.min_distinct_accounts),
        1.0,
    )?;
    check_at_least(
        &format!("{prefix}.min_failures"),
        f64::from(cfg.min_failures),
        1.0,
    )?;
    check_at_least(
        &format!("{prefix}.min_accounts_for_failure_burst"),
        f64::from(cfg.min_accounts_for_failure_burst),
        1.0,
    )?;
    check_positive(&format!("{prefix}.strength_cap"), cfg.strength_cap)?;
    Ok(())
}

fn ensure_retention(retention: u64, window: u64, where_: &str) -> Result<(), RulesError> {
    if retention < window {
        Err(RulesError::RetentionShorterThanWindow {
            retention,
            signal: "ip_fanout",
            window,
            where_: where_.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn check_finite(field: &str, value: f64) -> Result<(), RulesError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(RulesError::NotFinite {
            field: field.to_owned(),
        })
    }
}

fn check_non_negative(field: &str, value: f64) -> Result<(), RulesError> {
    check_finite(field, value)?;
    check_at_least(field, value, 0.0)
}

fn check_positive(field: &str, value: f64) -> Result<(), RulesError> {
    check_finite(field, value)?;
    if value > 0.0 {
        Ok(())
    } else {
        Err(RulesError::NotPositive {
            field: field.to_owned(),
        })
    }
}

fn check_at_least(field: &str, value: f64, min: f64) -> Result<(), RulesError> {
    if value >= min {
        Ok(())
    } else {
        Err(RulesError::BelowMinimum {
            field: field.to_owned(),
            min,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_load() {
        let rules = default_rules().unwrap();
        assert!(rules.scoring.prior_log_odds < 0.0);
        assert!(rules.signals.impossible_travel.enabled);
        assert!(rules.signals.new_asn.enabled);
        assert!(rules.signals.ip_fanout.enabled);
        assert!(rules.tenants.is_empty());
    }

    #[test]
    fn integer_weights_are_accepted() {
        let rules = Rules::from_toml(
            r#"
            [scoring]
            prior_log_odds = -3
            [state]
            max_user_observations = 8
            ip_retention_secs = 3600
            [signals.impossible_travel]
            enabled = true
            weight = 4
            max_plausible_speed_kmh = 900
            min_effective_distance_km = 100
            default_accuracy_radius_km = 50
            [signals.new_asn]
            enabled = true
            weight = 2
            min_prior_observations = 3
            [signals.ip_fanout]
            enabled = true
            weight = 3
            window_secs = 600
            min_distinct_accounts = 8
            min_failures = 20
            min_accounts_for_failure_burst = 4
            strength_cap = 2
            "#,
        )
        .unwrap();
        assert_eq!(rules.signals.impossible_travel.weight, 4.0);
        assert_eq!(rules.scoring.prior_log_odds, -3.0);
    }

    #[test]
    fn tenant_override_replaces_only_the_given_field() {
        let extra = r#"
            [tenants.acme.signals.impossible_travel]
            max_plausible_speed_kmh = 400
        "#;
        let text = format!("{DEFAULT_RULES_TOML}\n{extra}");
        let rules = Rules::from_toml(&text).unwrap();
        let acme = rules.resolve(&TenantId::new("acme").unwrap());
        let other = rules.resolve(&TenantId::new("other").unwrap());
        assert_eq!(acme.impossible_travel.max_plausible_speed_kmh, 400.0);
        assert_eq!(
            acme.impossible_travel.weight,
            other.impossible_travel.weight
        );
        assert_eq!(
            other.impossible_travel.max_plausible_speed_kmh,
            rules.signals.impossible_travel.max_plausible_speed_kmh
        );
    }

    #[test]
    fn unknown_field_and_short_retention_fail() {
        let unknown = r#"
            [scoring]
            prior_log_odds = -1.0
            mystery = 1
            [state]
            max_user_observations = 4
            ip_retention_secs = 10
            [signals.impossible_travel]
            enabled = true
            weight = 1.0
            max_plausible_speed_kmh = 900.0
            min_effective_distance_km = 1.0
            default_accuracy_radius_km = 1.0
            [signals.new_asn]
            enabled = true
            weight = 1.0
            min_prior_observations = 1
            [signals.ip_fanout]
            enabled = true
            weight = 1.0
            window_secs = 50
            min_distinct_accounts = 2
            min_failures = 2
            min_accounts_for_failure_burst = 2
            strength_cap = 1.0
        "#;
        assert!(Rules::from_toml(unknown).is_err());

        let short = unknown.replace("mystery = 1\n", "");
        assert!(matches!(
            Rules::from_toml(&short),
            Err(RulesError::RetentionShorterThanWindow { .. })
        ));
    }
}
