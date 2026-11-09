//! Per-user and per-source history.
//!
//! [`RiskView`] is the read API every detector uses. [`RiskState::observe`] is
//! the write API. A batch replay and a future streaming service both call
//! them in non-decreasing event-time order; neither consults the wall clock.
//! The in-memory implementation is the milestone 1 store. A Postgres
//! implementation can answer the same three queries without changing a signal.

use chrono::{DateTime, TimeDelta, Utc};
use ipnetwork::IpNetwork;
use ps_core::{IpInfo, TenantId, UserId};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// The most recent login recorded for a user, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct PreviousLogin {
    /// When that login happened.
    pub timestamp: DateTime<Utc>,
    /// Latitude, if enrichment had one.
    pub latitude: Option<f64>,
    /// Longitude, if enrichment had one.
    pub longitude: Option<f64>,
    /// Database accuracy radius in kilometers, if the database published one.
    pub accuracy_radius_km: Option<f64>,
    /// ASN observed on that login, if known.
    pub asn: Option<u32>,
    /// Address of that login.
    pub ip: IpAddr,
}

/// ASNs present in a user's retained history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnHistory {
    /// How many logins are still retained for the user.
    pub retained_observations: usize,
    /// Sorted unique ASNs among those logins. Missing ASNs are not listed.
    pub asns: Vec<u32>,
}

/// What one source has done inside a half-open time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpWindowStats {
    /// Attempts whose timestamp is inside the window.
    pub attempts: usize,
    /// How many of those attempts failed.
    pub failures: usize,
    /// Distinct accounts among those attempts.
    pub distinct_users: usize,
    /// Whether `query.user` is already one of those accounts.
    ///
    /// The current event is not in the store yet. Detectors add it themselves
    /// so an event is never treated as corroborating evidence of itself
    /// except where the detector explicitly says so (fan-out counts the
    /// attempt under evaluation).
    pub contains_user: bool,
}

/// Bounds for an [`RiskView::ip_window`] query.
#[derive(Debug, Clone, Copy)]
pub struct IpWindowQuery<'a> {
    /// Tenant to query.
    pub tenant: &'a TenantId,
    /// Source key from [`ps_core::source_network`].
    pub network: &'a IpNetwork,
    /// Inclusive start.
    pub since: DateTime<Utc>,
    /// Inclusive end. Scoring passes the current event's timestamp.
    pub until: DateTime<Utc>,
    /// Account on the event being scored.
    pub user: &'a UserId,
}

/// Read-only history queries. Object-safe so signals do not each grow a type parameter.
pub trait RiskView {
    /// The latest retained login for this user, or nothing if they are new.
    fn previous_login(&self, tenant: &TenantId, user: &UserId) -> Option<PreviousLogin>;

    /// ASNs seen in this user's retained logins.
    fn asn_history(&self, tenant: &TenantId, user: &UserId) -> AsnHistory;

    /// Activity for one source between `since` and `until`, inclusive.
    fn ip_window(&self, query: IpWindowQuery<'_>) -> IpWindowStats;
}

/// A store a scorer can both query and append to.
pub trait RiskState: RiskView {
    /// Records one login. Called only after that login has been scored.
    fn observe(&mut self, observation: &Observation);
}

/// One scored login, flattened for storage.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    /// Tenant that owns the account.
    pub tenant_id: TenantId,
    /// Account that was presented.
    pub user_id: UserId,
    /// Event time. This is the store's only clock.
    pub timestamp: DateTime<Utc>,
    /// Client address.
    pub ip: IpAddr,
    /// [`ps_core::source_network`] of `ip`, computed by the caller so the
    /// store does not disagree with the detector about identity.
    pub network: IpNetwork,
    /// Whether the attempt succeeded.
    pub success: bool,
    /// Latitude, if enrichment had one.
    pub latitude: Option<f64>,
    /// Longitude, if enrichment had one.
    pub longitude: Option<f64>,
    /// Accuracy radius from the database, not the rules default.
    pub accuracy_radius_km: Option<f64>,
    /// ASN, if enrichment had one.
    pub asn: Option<u32>,
}

impl Observation {
    /// Builds a record from the event fields the store actually keeps.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        user_id: UserId,
        timestamp: DateTime<Utc>,
        ip: IpAddr,
        network: IpNetwork,
        success: bool,
        info: &IpInfo,
    ) -> Self {
        Self {
            tenant_id,
            user_id,
            timestamp,
            ip,
            network,
            success,
            latitude: info.latitude,
            longitude: info.longitude,
            accuracy_radius_km: info.accuracy_radius_km,
            asn: info.asn,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UserKey {
    tenant: TenantId,
    user: UserId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IpKey {
    tenant: TenantId,
    network: IpNetwork,
}

#[derive(Debug, Clone)]
struct UserHit {
    timestamp: DateTime<Utc>,
    ip: IpAddr,
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius_km: Option<f64>,
    asn: Option<u32>,
}

#[derive(Debug, Clone)]
struct IpHit {
    timestamp: DateTime<Utc>,
    user_id: UserId,
    success: bool,
}

/// In-memory history bounded by a per-user cap and an IP retention window.
///
/// Both bounds are applied using event time. Replaying the same sequence
/// produces the same state whether or not the process waited between events.
#[derive(Debug, Clone)]
pub struct MemoryState {
    users: HashMap<UserKey, VecDeque<UserHit>>,
    ips: HashMap<IpKey, VecDeque<IpHit>>,
    max_user_observations: usize,
    ip_retention: TimeDelta,
}

impl MemoryState {
    /// Creates an empty store.
    ///
    /// `max_user_observations` of zero is treated as one so a misconfigured
    /// caller still retains the login needed for the next comparison. The
    /// rules validator rejects zero before this constructor is used.
    #[must_use]
    pub fn new(max_user_observations: usize, ip_retention: TimeDelta) -> Self {
        Self {
            users: HashMap::new(),
            ips: HashMap::new(),
            max_user_observations: max_user_observations.max(1),
            ip_retention,
        }
    }
}

impl RiskView for MemoryState {
    fn previous_login(&self, tenant: &TenantId, user: &UserId) -> Option<PreviousLogin> {
        let key = UserKey {
            tenant: tenant.clone(),
            user: user.clone(),
        };
        self.users
            .get(&key)
            .and_then(|hits| hits.back())
            .map(|hit| PreviousLogin {
                timestamp: hit.timestamp,
                latitude: hit.latitude,
                longitude: hit.longitude,
                accuracy_radius_km: hit.accuracy_radius_km,
                asn: hit.asn,
                ip: hit.ip,
            })
    }

    fn asn_history(&self, tenant: &TenantId, user: &UserId) -> AsnHistory {
        let key = UserKey {
            tenant: tenant.clone(),
            user: user.clone(),
        };
        let Some(hits) = self.users.get(&key) else {
            return AsnHistory {
                retained_observations: 0,
                asns: Vec::new(),
            };
        };
        let mut asns: Vec<u32> = hits.iter().filter_map(|hit| hit.asn).collect();
        asns.sort_unstable();
        asns.dedup();
        AsnHistory {
            retained_observations: hits.len(),
            asns,
        }
    }

    fn ip_window(&self, query: IpWindowQuery<'_>) -> IpWindowStats {
        let key = IpKey {
            tenant: query.tenant.clone(),
            network: *query.network,
        };
        let Some(hits) = self.ips.get(&key) else {
            return IpWindowStats {
                attempts: 0,
                failures: 0,
                distinct_users: 0,
                contains_user: false,
            };
        };
        let mut users = HashSet::new();
        let mut attempts = 0;
        let mut failures = 0;
        for hit in hits {
            if hit.timestamp < query.since || hit.timestamp > query.until {
                continue;
            }
            attempts += 1;
            if !hit.success {
                failures += 1;
            }
            users.insert(hit.user_id.clone());
        }
        let contains_user = users.contains(query.user);
        IpWindowStats {
            attempts,
            failures,
            distinct_users: users.len(),
            contains_user,
        }
    }
}

impl RiskState for MemoryState {
    fn observe(&mut self, observation: &Observation) {
        let user_key = UserKey {
            tenant: observation.tenant_id.clone(),
            user: observation.user_id.clone(),
        };
        let user_hits = self.users.entry(user_key).or_default();
        user_hits.push_back(UserHit {
            timestamp: observation.timestamp,
            ip: observation.ip,
            latitude: observation.latitude,
            longitude: observation.longitude,
            accuracy_radius_km: observation.accuracy_radius_km,
            asn: observation.asn,
        });
        while user_hits.len() > self.max_user_observations {
            user_hits.pop_front();
        }

        let ip_key = IpKey {
            tenant: observation.tenant_id.clone(),
            network: observation.network,
        };
        let ip_hits = self.ips.entry(ip_key).or_default();
        ip_hits.push_back(IpHit {
            timestamp: observation.timestamp,
            user_id: observation.user_id.clone(),
            success: observation.success,
        });
        let retain_after = observation
            .timestamp
            .checked_sub_signed(self.ip_retention)
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        while ip_hits
            .front()
            .is_some_and(|hit| hit.timestamp < retain_after)
        {
            ip_hits.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeDelta, Utc};
    use ps_core::IpInfo;

    fn ts(seconds: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(seconds)
    }

    fn obs(
        tenant: &str,
        user: &str,
        seconds: i64,
        ip: &str,
        success: bool,
        asn: Option<u32>,
    ) -> Observation {
        let ip: IpAddr = ip.parse().unwrap();
        let mut info = IpInfo::unknown(ip);
        info.asn = asn;
        info.latitude = Some(0.0);
        info.longitude = Some(0.0);
        Observation::new(
            TenantId::new(tenant).unwrap(),
            UserId::new(user).unwrap(),
            ts(seconds),
            ip,
            ps_core::source_network(ip),
            success,
            &info,
        )
    }

    #[test]
    fn user_cap_drops_the_oldest_login() {
        let mut state = MemoryState::new(2, TimeDelta::seconds(10_000));
        state.observe(&obs("t", "u", 1, "203.0.113.1", true, Some(1)));
        state.observe(&obs("t", "u", 2, "203.0.113.2", true, Some(2)));
        state.observe(&obs("t", "u", 3, "203.0.113.3", true, Some(3)));
        let history = state.asn_history(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap());
        assert_eq!(history.retained_observations, 2);
        assert_eq!(history.asns, vec![2, 3]);
        let previous = state
            .previous_login(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
            .unwrap();
        assert_eq!(previous.asn, Some(3));
    }

    #[test]
    fn ip_retention_uses_event_time() {
        let mut state = MemoryState::new(8, TimeDelta::seconds(100));
        state.observe(&obs("t", "old", 0, "203.0.113.9", false, None));
        state.observe(&obs("t", "new", 150, "203.0.113.9", true, None));
        let network = ps_core::source_network("203.0.113.9".parse().unwrap());
        let stats = state.ip_window(IpWindowQuery {
            tenant: &TenantId::new("t").unwrap(),
            network: &network,
            since: ts(0),
            until: ts(150),
            user: &UserId::new("new").unwrap(),
        });
        assert_eq!(stats.attempts, 1);
        assert!(stats.contains_user);
        assert_eq!(stats.distinct_users, 1);
    }

    #[test]
    fn tenants_do_not_share_history() {
        let mut state = MemoryState::new(8, TimeDelta::seconds(1000));
        state.observe(&obs("a", "u", 10, "203.0.113.9", false, Some(1)));
        let history = state.asn_history(&TenantId::new("b").unwrap(), &UserId::new("u").unwrap());
        assert_eq!(history.retained_observations, 0);
    }
}
