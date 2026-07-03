//! Per-user call limits: max concurrent calls (derived from the live
//! B2buaManager — no shadow counter to drift) and call-setup rate
//! (sliding 60s window kept here).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserLimitsConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 0 = unlimited.
    #[serde(default = "default_concurrent")]
    pub default_max_concurrent_calls: u32,
    /// Call attempts per minute; 0 = unlimited.
    #[serde(default = "default_cpm")]
    pub default_max_calls_per_minute: u32,
    #[serde(default)]
    pub overrides: Vec<UserLimitOverride>,
}

fn default_enabled() -> bool { true }
fn default_concurrent() -> u32 { 4 }
fn default_cpm() -> u32 { 10 }

impl Default for UserLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_max_concurrent_calls: default_concurrent(),
            default_max_calls_per_minute: default_cpm(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserLimitOverride {
    pub user: String,
    pub max_concurrent_calls: Option<u32>,
    pub max_calls_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UserLimits {
    pub max_concurrent_calls: Option<u32>,
    pub max_calls_per_minute: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LimitDecision {
    Allowed,
    ConcurrentExceeded { current: u32, limit: u32 },
    RateExceeded { current: u32, limit: u32, retry_after_secs: u64 },
}

pub struct UserLimitsManager {
    enabled: RwLock<bool>,
    defaults: RwLock<(u32, u32)>, // (max_concurrent, max_cpm); 0 = unlimited
    overrides: DashMap<String, UserLimits>,
    rate_windows: DashMap<String, VecDeque<Instant>>,
}

impl UserLimitsManager {
    pub fn new(config: UserLimitsConfig) -> Self {
        let mgr = Self {
            enabled: RwLock::new(config.enabled),
            defaults: RwLock::new((
                config.default_max_concurrent_calls,
                config.default_max_calls_per_minute,
            )),
            overrides: DashMap::new(),
            rate_windows: DashMap::new(),
        };
        for o in config.overrides {
            mgr.overrides.insert(
                o.user.clone(),
                UserLimits {
                    max_concurrent_calls: o.max_concurrent_calls,
                    max_calls_per_minute: o.max_calls_per_minute,
                },
            );
        }
        mgr
    }

    pub fn limits_for(&self, user: &str) -> (u32, u32) {
        let (dc, dr) = *self.defaults.read().unwrap();
        match self.overrides.get(user) {
            Some(o) => (
                o.max_concurrent_calls.unwrap_or(dc),
                o.max_calls_per_minute.unwrap_or(dr),
            ),
            None => (dc, dr),
        }
    }

    pub fn set_override(&self, user: &str, limits: UserLimits) {
        self.overrides.insert(user.to_string(), limits);
    }

    pub fn remove_override(&self, user: &str) -> bool {
        self.overrides.remove(user).is_some()
    }

    pub fn set_defaults(&self, max_concurrent: u32, max_cpm: u32) {
        *self.defaults.write().unwrap() = (max_concurrent, max_cpm);
    }

    pub fn defaults(&self) -> (u32, u32) {
        *self.defaults.read().unwrap()
    }

    pub fn overrides(&self) -> Vec<(String, UserLimits)> {
        self.overrides
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    }

    /// Check limits for a new call attempt from `user` and record the
    /// attempt in the rate window when allowed.
    /// `current_concurrent` comes from the live B2buaManager.
    pub fn check_and_record(&self, user: &str, current_concurrent: u32) -> LimitDecision {
        if !*self.enabled.read().unwrap() {
            return LimitDecision::Allowed;
        }
        let (max_concurrent, max_cpm) = self.limits_for(user);

        if max_concurrent > 0 && current_concurrent >= max_concurrent {
            return LimitDecision::ConcurrentExceeded {
                current: current_concurrent,
                limit: max_concurrent,
            };
        }

        if max_cpm > 0 {
            let now = Instant::now();
            let window = Duration::from_secs(60);
            let mut attempts = self.rate_windows.entry(user.to_string()).or_default();
            while attempts.front().map_or(false, |t| now.duration_since(*t) > window) {
                attempts.pop_front();
            }
            if attempts.len() as u32 >= max_cpm {
                let retry_after = attempts
                    .front()
                    .map(|t| 60u64.saturating_sub(now.duration_since(*t).as_secs()))
                    .unwrap_or(60);
                return LimitDecision::RateExceeded {
                    current: attempts.len() as u32,
                    limit: max_cpm,
                    retry_after_secs: retry_after.max(1),
                };
            }
            attempts.push_back(now);
        }

        LimitDecision::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(concurrent: u32, cpm: u32) -> UserLimitsManager {
        UserLimitsManager::new(UserLimitsConfig {
            enabled: true,
            default_max_concurrent_calls: concurrent,
            default_max_calls_per_minute: cpm,
            overrides: vec![],
        })
    }

    #[test]
    fn concurrent_cap() {
        let mgr = manager(2, 0);
        assert_eq!(mgr.check_and_record("alice", 0), LimitDecision::Allowed);
        assert_eq!(mgr.check_and_record("alice", 1), LimitDecision::Allowed);
        assert!(matches!(
            mgr.check_and_record("alice", 2),
            LimitDecision::ConcurrentExceeded { current: 2, limit: 2 }
        ));
    }

    #[test]
    fn rate_window() {
        let mgr = manager(0, 3);
        for _ in 0..3 {
            assert_eq!(mgr.check_and_record("bob", 0), LimitDecision::Allowed);
        }
        match mgr.check_and_record("bob", 0) {
            LimitDecision::RateExceeded { current, limit, retry_after_secs } => {
                assert_eq!((current, limit), (3, 3));
                assert!(retry_after_secs >= 1 && retry_after_secs <= 60);
            }
            other => panic!("expected RateExceeded, got {:?}", other),
        }
        // Other users unaffected
        assert_eq!(mgr.check_and_record("carol", 0), LimitDecision::Allowed);
    }

    #[test]
    fn zero_means_unlimited_and_overrides_beat_defaults() {
        let mgr = manager(1, 1);
        mgr.set_override("pbx", UserLimits {
            max_concurrent_calls: Some(0),
            max_calls_per_minute: Some(0),
        });
        for _ in 0..10 {
            assert_eq!(mgr.check_and_record("pbx", 100), LimitDecision::Allowed);
        }
        assert!(matches!(
            mgr.check_and_record("normal", 1),
            LimitDecision::ConcurrentExceeded { .. }
        ));
    }

    #[test]
    fn disabled_allows_everything() {
        let mgr = UserLimitsManager::new(UserLimitsConfig {
            enabled: false,
            default_max_concurrent_calls: 1,
            default_max_calls_per_minute: 1,
            overrides: vec![],
        });
        for _ in 0..5 {
            assert_eq!(mgr.check_and_record("x", 99), LimitDecision::Allowed);
        }
    }
}
