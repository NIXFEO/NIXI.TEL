//! Dynamic ACL — IP Access Control Lists
//!
//! Provides runtime-configurable IP filtering with:
//!   - CIDR-based rules (e.g. 10.0.0.0/8, 2001:db8::/32)
//!   - Named rule sets ("trusted_trunks", "blocked_ranges", …)
//!   - Three actions: Allow, Deny, Log
//!   - Priority ordering (higher priority evaluated first)
//!   - Hot-reload from config/database without restart
//!   - Separate inbound / outbound rule chains
//!   - IPv4 and IPv6 support via `ipnetwork`
//!
//! # Rule evaluation
//! Rules are evaluated in priority order (highest first).
//! First match wins.  If no rule matches, the default action applies.
//!
//! # Thread safety
//! All mutations go through `RwLock`, safe for concurrent access.

use crate::{Error, Result};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Rule types
// ─────────────────────────────────────────────────────────────────────────────

/// What to do when a rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAction {
    /// Allow traffic from this IP/range
    Allow,
    /// Deny (drop silently)
    Deny,
    /// Allow but log a warning
    Log,
}

impl fmt::Display for AclAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny  => write!(f, "deny"),
            Self::Log   => write!(f, "log"),
        }
    }
}

impl FromStr for AclAction {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "allow" | "permit" | "accept" => Ok(Self::Allow),
            "deny"  | "drop"   | "block"  => Ok(Self::Deny),
            "log"   | "warn"              => Ok(Self::Log),
            other => Err(Error::Config(format!("unknown ACL action: '{}'", other))),
        }
    }
}

/// Direction of traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

/// A single ACL rule
#[derive(Debug, Clone)]
pub struct AclRule {
    /// Unique rule ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// CIDR block to match (e.g. "10.0.0.0/8", "192.168.1.5/32")
    pub cidr: IpNetwork,
    /// Action if matched
    pub action: AclAction,
    /// Evaluation priority (higher = evaluated first)
    pub priority: i32,
    /// Direction this rule applies to
    pub direction: Direction,
    /// Whether this rule is active
    pub enabled: bool,
    /// Optional description / comment
    pub comment: Option<String>,
    /// UNIX timestamp when rule was created/modified
    pub updated_at: u64,
}

impl AclRule {
    pub fn new(
        id: &str,
        name: &str,
        cidr: &str,
        action: AclAction,
        priority: i32,
    ) -> Result<Self> {
        let cidr = cidr.parse::<IpNetwork>()
            .map_err(|e| Error::Config(format!("invalid CIDR '{}': {}", cidr, e)))?;
        Ok(Self {
            id: id.to_string(),
            name: name.to_string(),
            cidr,
            action,
            priority,
            direction: Direction::Both,
            enabled: true,
            comment: None,
            updated_at: unix_now(),
        })
    }

    /// Check if a given IP matches this rule's CIDR
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.enabled && self.cidr.contains(ip)
    }

    /// Apply a direction filter
    pub fn applies_to(&self, dir: Direction) -> bool {
        matches!(self.direction, Direction::Both)
            || self.direction == dir
    }

    pub fn with_direction(mut self, dir: Direction) -> Self {
        self.direction = dir;
        self
    }

    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Result of ACL evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// The result of evaluating an IP against the ACL
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclResult {
    /// Traffic allowed
    Allowed { rule_id: Option<String> },
    /// Traffic denied
    Denied  { rule_id: String, reason: String },
    /// Traffic allowed but logged
    Logged  { rule_id: String },
    /// No rule matched — default policy applied
    Default { allowed: bool },
}

impl AclResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. } | Self::Logged { .. }
            | Self::Default { allowed: true })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ACL engine
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the ACL engine
#[derive(Debug, Clone)]
pub struct AclConfig {
    /// Default action when no rule matches
    pub default_action: AclAction,
    /// Whether to log all denied traffic
    pub log_denied: bool,
    /// Whether to log all allowed traffic (verbose)
    pub log_allowed: bool,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            default_action: AclAction::Allow,  // permissive by default
            log_denied: true,
            log_allowed: false,
        }
    }
}

impl AclConfig {
    /// Deny-by-default (whitelist mode)
    pub fn deny_default() -> Self {
        Self { default_action: AclAction::Deny, ..Default::default() }
    }
}

/// ACL statistics
#[derive(Debug, Clone, Default)]
pub struct AclStats {
    pub total_checked: u64,
    pub allowed: u64,
    pub denied: u64,
    pub logged: u64,
    pub default_applied: u64,
    pub rule_count: usize,
}

/// Dynamic ACL manager
///
/// Rules can be added, removed, or modified at runtime without restart.
pub struct AclManager {
    config: Arc<RwLock<AclConfig>>,
    /// Rules indexed by ID
    rules: Arc<RwLock<HashMap<String, AclRule>>>,
    /// Statistics
    stats: Arc<RwLock<AclStats>>,
}

impl AclManager {
    pub fn new(config: AclConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            rules: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AclStats::default())),
        }
    }

    pub fn new_permissive() -> Self {
        Self::new(AclConfig::default())
    }

    pub fn new_restrictive() -> Self {
        Self::new(AclConfig::deny_default())
    }

    /// Add or update a rule
    pub async fn add_rule(&self, rule: AclRule) -> Result<()> {
        let id = rule.id.clone();
        let cidr = rule.cidr.to_string();
        let action = rule.action;
        let mut rules = self.rules.write().await;
        rules.insert(id.clone(), rule);
        info!("ACL: added rule '{}' ({} → {})", id, cidr, action);
        Ok(())
    }

    /// Remove a rule by ID
    pub async fn remove_rule(&self, id: &str) -> Result<()> {
        let mut rules = self.rules.write().await;
        if rules.remove(id).is_some() {
            info!("ACL: removed rule '{}'", id);
            Ok(())
        } else {
            Err(Error::Config(format!("ACL rule '{}' not found", id)))
        }
    }

    /// Replace the whole rule set atomically (SQLite hydration path).
    pub async fn replace_rules(&self, new_rules: Vec<AclRule>) -> usize {
        let mut rules = self.rules.write().await;
        rules.clear();
        for rule in new_rules {
            rules.insert(rule.id.clone(), rule);
        }
        rules.len()
    }

    /// Current default action.
    pub async fn default_action(&self) -> AclAction {
        self.config.read().await.default_action
    }

    /// Enable or disable a rule without removing it
    pub async fn set_rule_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let mut rules = self.rules.write().await;
        let rule = rules.get_mut(id)
            .ok_or_else(|| Error::Config(format!("ACL rule '{}' not found", id)))?;
        rule.enabled = enabled;
        rule.updated_at = unix_now();
        info!("ACL: rule '{}' {}", id, if enabled { "enabled" } else { "disabled" });
        Ok(())
    }

    /// Evaluate an IP address against all rules
    pub async fn check(&self, ip: IpAddr, direction: Direction) -> AclResult {
        let rules = self.rules.read().await;
        let config = self.config.read().await;

        // Sort rules by priority (descending — higher priority first)
        let mut sorted: Vec<&AclRule> = rules.values()
            .filter(|r| r.applies_to(direction))
            .collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Evaluate first match
        for rule in sorted {
            if rule.matches(ip) {
                let result = match rule.action {
                    AclAction::Allow => {
                        if config.log_allowed {
                            debug!("ACL: {} ALLOWED by rule '{}'", ip, rule.id);
                        }
                        AclResult::Allowed { rule_id: Some(rule.id.clone()) }
                    }
                    AclAction::Deny => {
                        if config.log_denied {
                            warn!("ACL: {} DENIED by rule '{}' ({})", ip, rule.id, rule.name);
                        }
                        AclResult::Denied {
                            rule_id: rule.id.clone(),
                            reason: rule.comment.clone()
                                .unwrap_or_else(|| rule.name.clone()),
                        }
                    }
                    AclAction::Log => {
                        warn!("ACL: {} matched LOG rule '{}' ({})", ip, rule.id, rule.name);
                        AclResult::Logged { rule_id: rule.id.clone() }
                    }
                };

                // Update stats
                drop(rules);
                drop(config);
                let mut stats = self.stats.write().await;
                stats.total_checked += 1;
                match &result {
                    AclResult::Allowed { .. } => stats.allowed += 1,
                    AclResult::Denied  { .. } => stats.denied  += 1,
                    AclResult::Logged  { .. } => stats.logged  += 1,
                    _ => {}
                }
                return result;
            }
        }

        // No match → default
        let allowed = config.default_action != AclAction::Deny;
        if !allowed && config.log_denied {
            debug!("ACL: {} DENIED by default policy", ip);
        }

        drop(rules);
        drop(config);
        let mut stats = self.stats.write().await;
        stats.total_checked += 1;
        stats.default_applied += 1;
        if allowed { stats.allowed += 1; } else { stats.denied += 1; }

        AclResult::Default { allowed }
    }

    /// Convenience wrapper for SocketAddr
    pub async fn check_addr(&self, addr: SocketAddr, direction: Direction) -> AclResult {
        self.check(addr.ip(), direction).await
    }

    /// Get all rules sorted by priority
    pub async fn rules(&self) -> Vec<AclRule> {
        let rules = self.rules.read().await;
        let mut sorted: Vec<AclRule> = rules.values().cloned().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        sorted
    }

    /// Get rule count
    pub async fn rule_count(&self) -> usize {
        self.rules.read().await.len()
    }

    /// Get statistics
    pub async fn stats(&self) -> AclStats {
        let mut stats = self.stats.read().await.clone();
        stats.rule_count = self.rules.read().await.len();
        stats
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        *self.stats.write().await = AclStats::default();
    }

    /// Load rules from a simple TOML-like configuration string.
    ///
    /// Format (each line):
    /// ```text
    /// <id>|<name>|<cidr>|<action>|<priority>
    /// ```
    pub async fn load_from_text(&self, text: &str) -> Result<u32> {
        let mut count = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() < 5 {
                warn!("ACL: skipping malformed rule: {}", line);
                continue;
            }
            let (id, name, cidr, action_str, prio_str) =
                (parts[0], parts[1], parts[2], parts[3], parts[4]);

            let action = action_str.parse::<AclAction>()?;
            let priority = prio_str.trim().parse::<i32>()
                .map_err(|_| Error::Config(format!("invalid priority: {}", prio_str)))?;

            let rule = AclRule::new(id.trim(), name.trim(), cidr.trim(), action, priority)?;
            self.add_rule(rule).await?;
            count += 1;
        }
        info!("ACL: loaded {} rules from text", count);
        Ok(count)
    }

    /// Export rules as text (for persistence)
    pub async fn export_to_text(&self) -> String {
        let rules = self.rules.read().await;
        let mut sorted: Vec<&AclRule> = rules.values().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
        sorted.iter().map(|r| {
            format!("{}|{}|{}|{}|{}", r.id, r.name, r.cidr, r.action, r.priority)
        }).collect::<Vec<_>>().join("\n")
    }

    /// Update the default action at runtime
    pub async fn set_default_action(&self, action: AclAction) {
        self.config.write().await.default_action = action;
        info!("ACL: default action changed to {}", action);
    }

    /// Add a block for a single IP (shorthand)
    pub async fn block_ip(&self, ip: IpAddr, reason: &str) -> Result<()> {
        let cidr = format!("{}/128", ip);
        // Try /128 for IPv6, fall back to /32 for IPv4
        let cidr = cidr.parse::<IpNetwork>()
            .or_else(|_| format!("{}/32", ip).parse::<IpNetwork>())
            .map_err(|e| Error::Config(format!("invalid IP {}: {}", ip, e)))?;

        let id = format!("block-{}", ip);
        let mut rule = AclRule::new(&id, reason, &cidr.to_string(), AclAction::Deny, 1000)?;
        rule.comment = Some(reason.to_string());
        self.add_rule(rule).await
    }

    /// Remove a block for a single IP
    pub async fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
        let id = format!("block-{}", ip);
        self.remove_rule(&id).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_rule(id: &str, cidr: &str, prio: i32) -> AclRule {
        AclRule::new(id, id, cidr, AclAction::Allow, prio).unwrap()
    }

    fn deny_rule(id: &str, cidr: &str, prio: i32) -> AclRule {
        AclRule::new(id, id, cidr, AclAction::Deny, prio).unwrap()
    }

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    // ── AclRule ───────────────────────────────────────────────────────────────

    #[test]
    fn test_rule_matches_cidr() {
        let rule = allow_rule("r1", "192.168.1.0/24", 100);
        assert!(rule.matches(ip("192.168.1.1")));
        assert!(rule.matches(ip("192.168.1.254")));
        assert!(!rule.matches(ip("192.168.2.1")));
        assert!(!rule.matches(ip("10.0.0.1")));
    }

    #[test]
    fn test_rule_matches_exact_ip() {
        let rule = deny_rule("r2", "10.0.0.5/32", 200);
        assert!(rule.matches(ip("10.0.0.5")));
        assert!(!rule.matches(ip("10.0.0.6")));
    }

    #[test]
    fn test_rule_disabled_does_not_match() {
        let mut rule = allow_rule("r3", "0.0.0.0/0", 50);
        rule.enabled = false;
        assert!(!rule.matches(ip("1.2.3.4")));
    }

    #[test]
    fn test_action_from_str() {
        assert_eq!("allow".parse::<AclAction>().unwrap(), AclAction::Allow);
        assert_eq!("deny".parse::<AclAction>().unwrap(),  AclAction::Deny);
        assert_eq!("block".parse::<AclAction>().unwrap(), AclAction::Deny);
        assert_eq!("log".parse::<AclAction>().unwrap(),   AclAction::Log);
        assert!("invalid".parse::<AclAction>().is_err());
    }

    #[test]
    fn test_invalid_cidr_fails() {
        let result = AclRule::new("r", "name", "not-a-cidr", AclAction::Allow, 100);
        assert!(result.is_err());
    }

    // ── AclManager — basic ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_default_allow() {
        let acl = AclManager::new_permissive();
        let result = acl.check(ip("1.2.3.4"), Direction::Inbound).await;
        assert!(result.is_allowed());
        assert!(matches!(result, AclResult::Default { allowed: true }));
    }

    #[tokio::test]
    async fn test_default_deny() {
        let acl = AclManager::new_restrictive();
        let result = acl.check(ip("1.2.3.4"), Direction::Inbound).await;
        assert!(!result.is_allowed());
        assert!(matches!(result, AclResult::Default { allowed: false }));
    }

    #[tokio::test]
    async fn test_allow_rule_matches() {
        let acl = AclManager::new_restrictive(); // default deny
        acl.add_rule(allow_rule("trusted", "192.168.0.0/16", 100)).await.unwrap();

        let r = acl.check(ip("192.168.5.10"), Direction::Inbound).await;
        assert!(r.is_allowed(), "should match allow rule");
        assert!(matches!(r, AclResult::Allowed { .. }));
    }

    #[tokio::test]
    async fn test_deny_rule_matches() {
        let acl = AclManager::new_permissive(); // default allow
        acl.add_rule(deny_rule("blocked", "10.10.0.0/16", 100)).await.unwrap();

        let r = acl.check(ip("10.10.5.5"), Direction::Inbound).await;
        assert!(!r.is_allowed(), "should match deny rule");
        assert!(matches!(r, AclResult::Denied { .. }));
    }

    // ── Priority ordering ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_higher_priority_wins() {
        let acl = AclManager::new_permissive();
        // Deny the whole /16 at low priority
        acl.add_rule(deny_rule("deny-range", "10.0.0.0/16", 50)).await.unwrap();
        // Allow a specific /32 at higher priority
        acl.add_rule(allow_rule("allow-host", "10.0.0.5/32", 200)).await.unwrap();

        // The specific host should be allowed despite the /16 deny
        let r = acl.check(ip("10.0.0.5"), Direction::Inbound).await;
        assert!(r.is_allowed(), "higher priority allow should win");

        // Other IPs in the range should still be denied
        let r2 = acl.check(ip("10.0.0.10"), Direction::Inbound).await;
        assert!(!r2.is_allowed(), "lower priority deny should apply to other IPs");
    }

    // ── Rule management ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_rule() {
        let acl = AclManager::new_permissive();
        acl.add_rule(deny_rule("r1", "5.5.5.0/24", 100)).await.unwrap();
        assert_eq!(acl.rule_count().await, 1);

        acl.remove_rule("r1").await.unwrap();
        assert_eq!(acl.rule_count().await, 0);

        // After removal, default allow should apply
        let r = acl.check(ip("5.5.5.5"), Direction::Inbound).await;
        assert!(r.is_allowed());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_rule_fails() {
        let acl = AclManager::new_permissive();
        assert!(acl.remove_rule("does-not-exist").await.is_err());
    }

    #[tokio::test]
    async fn test_disable_rule() {
        let acl = AclManager::new_permissive();
        acl.add_rule(deny_rule("r1", "7.7.7.0/24", 100)).await.unwrap();

        // Rule active → denied
        let r = acl.check(ip("7.7.7.7"), Direction::Inbound).await;
        assert!(!r.is_allowed());

        // Disable rule → default allow applies
        acl.set_rule_enabled("r1", false).await.unwrap();
        let r2 = acl.check(ip("7.7.7.7"), Direction::Inbound).await;
        assert!(r2.is_allowed());
    }

    // ── Block/unblock shortcuts ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_block_unblock_ip() {
        let acl = AclManager::new_permissive();
        let target = ip("8.8.8.8");

        acl.block_ip(target, "suspicious host").await.unwrap();
        let r = acl.check(target, Direction::Inbound).await;
        assert!(!r.is_allowed(), "blocked IP should be denied");

        acl.unblock_ip(target).await.unwrap();
        let r2 = acl.check(target, Direction::Inbound).await;
        assert!(r2.is_allowed(), "unblocked IP should be allowed");
    }

    // ── Text import/export ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_load_from_text() {
        let acl = AclManager::new_permissive();
        let text = "# Comment line\n\
r1|trusted_lans|10.0.0.0/8|allow|100\n\
r2|blocked_china|1.2.3.0/24|deny|200\n\
\n\
r3|warn_zone|172.16.0.0/12|log|50\n";

        let count = acl.load_from_text(text).await.unwrap();
        assert_eq!(count, 3);
        assert_eq!(acl.rule_count().await, 3);
    }

    #[tokio::test]
    async fn test_export_to_text() {
        let acl = AclManager::new_permissive();
        acl.add_rule(allow_rule("r1", "10.0.0.0/8", 100)).await.unwrap();
        acl.add_rule(deny_rule("r2", "1.2.3.4/32", 200)).await.unwrap();

        let text = acl.export_to_text().await;
        assert!(text.contains("r1"), "export should contain r1");
        assert!(text.contains("r2"), "export should contain r2");
        assert!(text.contains("10.0.0.0/8"), "export should contain CIDR");
    }

    #[tokio::test]
    async fn test_load_and_export_roundtrip() {
        let acl1 = AclManager::new_permissive();
        let text = "r1|allow_private|192.168.0.0/16|allow|100\nr2|deny_bad|5.5.5.0/24|deny|200\n";
        acl1.load_from_text(text).await.unwrap();

        let exported = acl1.export_to_text().await;

        let acl2 = AclManager::new_permissive();
        acl2.load_from_text(&exported).await.unwrap();
        assert_eq!(acl2.rule_count().await, 2);
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_stats_counting() {
        let acl = AclManager::new_permissive();
        acl.add_rule(deny_rule("deny", "9.9.9.0/24", 100)).await.unwrap();

        acl.check(ip("1.1.1.1"), Direction::Inbound).await; // allowed (default)
        acl.check(ip("9.9.9.9"), Direction::Inbound).await; // denied (rule)
        acl.check(ip("2.2.2.2"), Direction::Inbound).await; // allowed (default)

        let stats = acl.stats().await;
        assert_eq!(stats.total_checked, 3);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.denied, 1);
    }

    #[tokio::test]
    async fn test_stats_reset() {
        let acl = AclManager::new_permissive();
        acl.check(ip("1.2.3.4"), Direction::Inbound).await;
        acl.reset_stats().await;
        let stats = acl.stats().await;
        assert_eq!(stats.total_checked, 0);
    }

    // ── Direction filtering ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_direction_filtering() {
        let acl = AclManager::new_permissive();
        let mut rule = deny_rule("inbound-only", "3.3.3.0/24", 100);
        rule.direction = Direction::Inbound;
        acl.add_rule(rule).await.unwrap();

        // Should be denied inbound
        let r_in = acl.check(ip("3.3.3.3"), Direction::Inbound).await;
        assert!(!r_in.is_allowed());

        // Should be allowed outbound (rule doesn't apply)
        let r_out = acl.check(ip("3.3.3.3"), Direction::Outbound).await;
        assert!(r_out.is_allowed());
    }

    // ── IPv6 support ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ipv6_rule() {
        let acl = AclManager::new_permissive();
        acl.add_rule(
            AclRule::new("v6-block", "v6 block", "2001:db8::/32", AclAction::Deny, 100).unwrap()
        ).await.unwrap();

        let r = acl.check(ip("2001:db8::1"), Direction::Inbound).await;
        assert!(!r.is_allowed());

        let r2 = acl.check(ip("2001:db9::1"), Direction::Inbound).await;
        assert!(r2.is_allowed());
    }

    // ── change default policy at runtime ─────────────────────────────────────

    #[tokio::test]
    async fn test_change_default_action() {
        let acl = AclManager::new_permissive();
        let r = acl.check(ip("1.2.3.4"), Direction::Both).await;
        assert!(r.is_allowed());

        acl.set_default_action(AclAction::Deny).await;
        let r2 = acl.check(ip("1.2.3.4"), Direction::Both).await;
        assert!(!r2.is_allowed());
    }
}
