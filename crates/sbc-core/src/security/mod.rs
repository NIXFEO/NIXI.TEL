//! Security & anti-fraud: fail2ban-style SIP banning, destination
//! (anti-IRSF) blocking, and per-user call limits.
//!
//! Pipeline position: **Ban → ACL → DoS → dispatch** (ban check is one
//! DashMap read on the hot path). Everything is configurable via TOML and
//! manageable at runtime through the REST API; bans persist to the SQLite
//! store so a restart does not amnesty offenders.

pub mod ban;
pub mod destination;
pub mod user_limits;

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;

pub use ban::{BanConfig, BanEntry, BanManager};
pub use destination::{DestinationDecision, DestinationPolicy, DestinationRule, DestinationsConfig};
pub use user_limits::{LimitDecision, UserLimits, UserLimitsConfig, UserLimitsManager};

/// TOML: `[security.ban]`, `[security.destinations]`, `[security.user_limits]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecurityFeaturesConfig {
    #[serde(default)]
    pub ban: BanConfig,
    #[serde(default)]
    pub destinations: DestinationsConfig,
    #[serde(default)]
    pub user_limits: UserLimitsConfig,
}

/// A security enforcement event, kept in a ring buffer for
/// `GET /api/v1/security/status` and published on the SSE bus.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecurityEvent {
    BanIssued {
        ip: String,
        reason: String,
        duration_secs: u64,
        failures: u32,
        manual: bool,
        ts: u64,
    },
    BanLifted {
        ip: String,
        manual: bool,
        ts: u64,
    },
    AuthFailure {
        ip: String,
        username: Option<String>,
        method: String,
        ts: u64,
    },
    DestinationBlocked {
        user: Option<String>,
        destination: String,
        rule: String,
        ts: u64,
    },
    UserLimitHit {
        user: String,
        kind: String, // "concurrent" | "rate"
        current: u32,
        limit: u32,
        ts: u64,
    },
}

pub struct SecurityManager {
    pub bans: BanManager,
    pub destinations: DestinationPolicy,
    pub user_limits: UserLimitsManager,
    /// Last 100 enforcement events.
    recent_events: Mutex<VecDeque<SecurityEvent>>,
    /// SSE bus (wired at boot).
    event_bus: std::sync::RwLock<Option<crate::events::EventBus>>,
}

impl SecurityManager {
    pub fn new(config: SecurityFeaturesConfig) -> Self {
        Self {
            bans: BanManager::new(config.ban),
            destinations: DestinationPolicy::new(config.destinations),
            user_limits: UserLimitsManager::new(config.user_limits),
            recent_events: Mutex::new(VecDeque::with_capacity(100)),
            event_bus: std::sync::RwLock::new(None),
        }
    }

    pub fn set_event_bus(&self, bus: crate::events::EventBus) {
        *self.event_bus.write().unwrap() = Some(bus);
    }

    pub fn emit(&self, event: SecurityEvent) {
        if let Ok(bus) = self.event_bus.read() {
            if let Some(bus) = bus.as_ref() {
                let (kind, detail) = match &event {
                    SecurityEvent::BanIssued { ip, reason, .. } => {
                        ("ban_issued", format!("{} ({})", ip, reason))
                    }
                    SecurityEvent::BanLifted { ip, .. } => ("ban_lifted", ip.clone()),
                    SecurityEvent::AuthFailure { ip, .. } => ("auth_failure", ip.clone()),
                    SecurityEvent::DestinationBlocked { destination, rule, .. } => {
                        ("destination_blocked", format!("{} (rule {})", destination, rule))
                    }
                    SecurityEvent::UserLimitHit { user, kind, .. } => {
                        ("user_limit", format!("{} ({})", user, kind))
                    }
                };
                bus.publish(crate::events::SbcEvent::Alert {
                    level: "warning".to_string(),
                    kind: kind.to_string(),
                    detail,
                    ts: crate::events::event_ts(),
                });
            }
        }
        if let Ok(mut ring) = self.recent_events.lock() {
            if ring.len() >= 100 {
                ring.pop_front();
            }
            ring.push_back(event);
        }
    }

    /// Record a real authentication failure (nonce-stale retries excluded by
    /// the caller!). Returns the ban entry when this failure triggered one.
    pub fn record_auth_failure(
        &self,
        ip: IpAddr,
        username: Option<&str>,
        method: &str,
    ) -> Option<BanEntry> {
        self.emit(SecurityEvent::AuthFailure {
            ip: ip.to_string(),
            username: username.map(str::to_string),
            method: method.to_string(),
            ts: crate::events::event_ts(),
        });
        let banned = self.bans.record_failure(ip, &format!("{} auth failures", method));
        if let Some(entry) = &banned {
            self.emit(SecurityEvent::BanIssued {
                ip: entry.ip.to_string(),
                reason: entry.reason.clone(),
                duration_secs: entry.remaining_secs(),
                failures: entry.failures,
                manual: false,
                ts: crate::events::event_ts(),
            });
        }
        banned
    }

    pub fn recent_events(&self) -> Vec<SecurityEvent> {
        self.recent_events
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default()
    }
}
