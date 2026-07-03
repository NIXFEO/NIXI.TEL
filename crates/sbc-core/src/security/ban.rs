//! Fail2ban-style SIP banning: sliding-window failure counter per source
//! IP, escalating ban duration for repeat offenders, hot-path check is a
//! single DashMap read.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BanConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Strikes within `window_secs` that trigger a ban.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    #[serde(default = "default_window")]
    pub window_secs: u64,
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
    /// Each repeat offense multiplies the duration (capped at max_ban_secs).
    #[serde(default = "default_multiplier")]
    pub repeat_offender_multiplier: u32,
    #[serde(default = "default_max_ban")]
    pub max_ban_secs: u64,
    /// true: drop packets silently; false: answer 403.
    #[serde(default = "default_enabled")]
    pub silent_drop: bool,
    /// IPs/CIDRs never banned (loopback is always whitelisted).
    #[serde(default)]
    pub whitelist: Vec<String>,
}

fn default_enabled() -> bool { true }
fn default_max_failures() -> u32 { 5 }
fn default_window() -> u64 { 60 }
fn default_ban_duration() -> u64 { 3600 }
fn default_multiplier() -> u32 { 4 }
fn default_max_ban() -> u64 { 86400 }

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failures: default_max_failures(),
            window_secs: default_window(),
            ban_duration_secs: default_ban_duration(),
            repeat_offender_multiplier: default_multiplier(),
            max_ban_secs: default_max_ban(),
            silent_drop: true,
            whitelist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BanEntry {
    pub ip: IpAddr,
    pub reason: String,
    /// SystemTime so bans survive persist/restore across restarts.
    pub banned_at: SystemTime,
    pub expires_at: SystemTime,
    pub failures: u32,
    pub manual: bool,
    pub offense_count: u32,
}

impl BanEntry {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    pub fn remaining_secs(&self) -> u64 {
        self.expires_at
            .duration_since(SystemTime::now())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn ts_rfc_secs(t: SystemTime) -> u64 {
        t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

pub struct BanManager {
    config: std::sync::RwLock<BanConfig>,
    /// Failure timestamps per IP (pruned to the window on insert).
    failures: DashMap<IpAddr, VecDeque<Instant>>,
    bans: DashMap<IpAddr, BanEntry>,
    /// Past offense counts (for repeat-offender escalation), kept after expiry.
    offenses: DashMap<IpAddr, u32>,
}

impl BanManager {
    pub fn new(config: BanConfig) -> Self {
        Self {
            config: std::sync::RwLock::new(config),
            failures: DashMap::new(),
            bans: DashMap::new(),
            offenses: DashMap::new(),
        }
    }

    pub fn config(&self) -> BanConfig {
        self.config.read().unwrap().clone()
    }

    pub fn set_config(&self, config: BanConfig) {
        *self.config.write().unwrap() = config;
    }

    fn is_whitelisted(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let config = self.config.read().unwrap();
        config.whitelist.iter().any(|w| {
            if let Ok(net) = w.parse::<ipnetwork::IpNetwork>() {
                net.contains(ip)
            } else {
                w == &ip.to_string()
            }
        })
    }

    /// Hot path: is this source banned right now?
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        // NOTE: the Ref guard from get() MUST be dropped before remove() —
        // removing while holding a same-shard guard deadlocks DashMap.
        let expired = match self.bans.get(&ip) {
            Some(entry) if !entry.is_expired() => return true,
            Some(_) => true,
            None => false,
        };
        if expired {
            self.bans.remove(&ip);
        }
        false
    }

    /// Whether banned traffic should be dropped silently (vs 403).
    pub fn silent_drop(&self) -> bool {
        self.config.read().unwrap().silent_drop
    }

    /// Record a failure strike; returns the new ban when the threshold is hit.
    pub fn record_failure(&self, ip: IpAddr, reason: &str) -> Option<BanEntry> {
        let config = self.config.read().unwrap().clone();
        if !config.enabled || self.is_whitelisted(ip) || self.is_banned(ip) {
            return None;
        }

        let now = Instant::now();
        let window = Duration::from_secs(config.window_secs);
        let mut strikes = self.failures.entry(ip).or_default();
        while strikes.front().map_or(false, |t| now.duration_since(*t) > window) {
            strikes.pop_front();
        }
        strikes.push_back(now);
        let count = strikes.len() as u32;
        drop(strikes);

        if count < config.max_failures {
            return None;
        }

        self.failures.remove(&ip);
        let offense = self.offenses.entry(ip).or_insert(0).value() + 1;
        self.offenses.insert(ip, offense);

        let factor = config
            .repeat_offender_multiplier
            .saturating_pow(offense.saturating_sub(1))
            .max(1) as u64;
        let duration = (config.ban_duration_secs.saturating_mul(factor))
            .min(config.max_ban_secs);

        let entry = BanEntry {
            ip,
            reason: reason.to_string(),
            banned_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(duration),
            failures: count,
            manual: false,
            offense_count: offense,
        };
        warn!(
            target: "security",
            "BAN issued: {} for {}s (offense #{}, {} failures: {})",
            ip, duration, offense, count, reason
        );
        self.bans.insert(ip, entry.clone());
        Some(entry)
    }

    /// Manual/administrative ban.
    pub fn ban(&self, ip: IpAddr, duration: Duration, reason: &str) -> BanEntry {
        let entry = BanEntry {
            ip,
            reason: reason.to_string(),
            banned_at: SystemTime::now(),
            expires_at: SystemTime::now() + duration,
            failures: 0,
            manual: true,
            offense_count: self.offenses.get(&ip).map(|o| *o).unwrap_or(0) + 1,
        };
        info!(target: "security", "Manual ban: {} for {:?} ({})", ip, duration, reason);
        self.bans.insert(ip, entry.clone());
        entry
    }

    pub fn unban(&self, ip: IpAddr) -> bool {
        let removed = self.bans.remove(&ip).is_some();
        if removed {
            info!(target: "security", "Ban lifted: {}", ip);
        }
        removed
    }

    pub fn list(&self) -> Vec<BanEntry> {
        self.bans
            .iter()
            .filter(|e| !e.is_expired())
            .map(|e| e.clone())
            .collect()
    }

    /// Remove expired bans (periodic maintenance). Returns removed count.
    pub fn cleanup_expired(&self) -> usize {
        let expired: Vec<IpAddr> = self
            .bans
            .iter()
            .filter(|e| e.is_expired())
            .map(|e| *e.key())
            .collect();
        for ip in &expired {
            self.bans.remove(ip);
        }
        expired.len()
    }

    /// Restore a persisted ban (startup).
    pub fn restore(&self, entry: BanEntry) {
        if !entry.is_expired() {
            self.offenses.insert(entry.ip, entry.offense_count);
            self.bans.insert(entry.ip, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(max_failures: u32, window: u64) -> BanManager {
        BanManager::new(BanConfig {
            max_failures,
            window_secs: window,
            ban_duration_secs: 3600,
            ..Default::default()
        })
    }

    fn ip(last: u8) -> IpAddr {
        format!("198.51.100.{}", last).parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_within_window() {
        let mgr = manager(3, 60);
        assert!(mgr.record_failure(ip(1), "auth").is_none());
        assert!(mgr.record_failure(ip(1), "auth").is_none());
        let ban = mgr.record_failure(ip(1), "auth");
        assert!(ban.is_some());
        assert!(mgr.is_banned(ip(1)));
        assert!(!mgr.is_banned(ip(2)));
    }

    #[test]
    fn loopback_and_whitelist_never_banned() {
        let mgr = BanManager::new(BanConfig {
            max_failures: 1,
            whitelist: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        });
        assert!(mgr.record_failure("127.0.0.1".parse().unwrap(), "x").is_none());
        assert!(mgr.record_failure("10.1.2.3".parse().unwrap(), "x").is_none());
        assert!(mgr.record_failure(ip(9), "x").is_some());
    }

    #[test]
    fn repeat_offender_escalates() {
        let mgr = manager(1, 60);
        let first = mgr.record_failure(ip(3), "auth").unwrap();
        mgr.unban(ip(3));
        let second = mgr.record_failure(ip(3), "auth").unwrap();
        assert_eq!(second.offense_count, 2);
        assert!(second.remaining_secs() > first.remaining_secs());
    }

    #[test]
    fn manual_ban_unban_and_list() {
        let mgr = manager(5, 60);
        mgr.ban(ip(4), Duration::from_secs(600), "manual");
        assert!(mgr.is_banned(ip(4)));
        assert_eq!(mgr.list().len(), 1);
        assert!(mgr.unban(ip(4)));
        assert!(!mgr.is_banned(ip(4)));
        assert!(!mgr.unban(ip(4)));
    }

    #[test]
    fn expired_ban_auto_clears() {
        let mgr = manager(1, 60);
        let mut entry = mgr.record_failure(ip(5), "auth").unwrap();
        entry.expires_at = SystemTime::now() - Duration::from_secs(1);
        mgr.bans.insert(ip(5), entry);
        assert!(!mgr.is_banned(ip(5)));
        assert_eq!(mgr.cleanup_expired(), 0); // already removed by is_banned
    }

    #[test]
    fn restore_skips_expired() {
        let mgr = manager(5, 60);
        mgr.restore(BanEntry {
            ip: ip(6),
            reason: "old".into(),
            banned_at: SystemTime::now() - Duration::from_secs(7200),
            expires_at: SystemTime::now() - Duration::from_secs(3600),
            failures: 5,
            manual: false,
            offense_count: 1,
        });
        assert!(!mgr.is_banned(ip(6)));
        mgr.restore(BanEntry {
            ip: ip(7),
            reason: "active".into(),
            banned_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            failures: 5,
            manual: false,
            offense_count: 2,
        });
        assert!(mgr.is_banned(ip(7)));
    }
}
