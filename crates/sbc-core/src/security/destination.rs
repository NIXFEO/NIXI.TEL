//! Destination (anti-IRSF) blocking: longest-prefix rules on canonicalized
//! dialed numbers, per-user or global, checked before trunk selection —
//! blocked calls never allocate a trunk.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::warn;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DestinationsConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// "allow" (blocklist mode) or "deny" (allowlist mode).
    #[serde(default = "default_action")]
    pub default_action: String,
    /// Country code used to canonicalize national numbers ("33" → +33…).
    #[serde(default = "default_cc")]
    pub default_country_code: String,
    #[serde(default)]
    pub rules: Vec<DestinationRuleToml>,
    /// Seed the unambiguous IRSF satellite/premium ranges (+881/+882/+883/+979)
    /// when no deny rules are configured.
    #[serde(default = "default_enabled")]
    pub seed_irsf_rules: bool,
}

fn default_enabled() -> bool { true }
fn default_action() -> String { "allow".to_string() }
fn default_cc() -> String { "33".to_string() }

impl Default for DestinationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: default_action(),
            default_country_code: default_cc(),
            rules: Vec::new(),
            seed_irsf_rules: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DestinationRuleToml {
    pub prefix: String,
    /// "allow" | "deny"
    pub action: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DestinationRule {
    pub id: String,
    pub prefix: String,
    pub deny: bool,
    /// None = global rule.
    pub user: Option<String>,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DestinationDecision {
    Allowed,
    Blocked { rule_id: String, description: String },
}

pub struct DestinationPolicy {
    rules: RwLock<Vec<DestinationRule>>,
    default_deny: RwLock<bool>,
    default_cc: RwLock<String>,
    enabled: RwLock<bool>,
    pub blocked_total: AtomicU64,
}

/// Unambiguous international premium/satellite ranges (IRSF magnets).
const IRSF_SEED: &[(&str, &str)] = &[
    ("+881", "Global Mobile Satellite System"),
    ("+882", "International Networks"),
    ("+883", "International Networks"),
    ("+979", "International Premium Rate"),
];

impl DestinationPolicy {
    pub fn new(config: DestinationsConfig) -> Self {
        let mut rules: Vec<DestinationRule> = config
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| DestinationRule {
                id: format!("cfg-{}", i),
                prefix: r.prefix.clone(),
                deny: r.action.eq_ignore_ascii_case("deny"),
                user: r.user.clone(),
                description: r.description.clone(),
                enabled: true,
            })
            .collect();

        if config.seed_irsf_rules && !rules.iter().any(|r| r.deny) {
            for (prefix, desc) in IRSF_SEED {
                rules.push(DestinationRule {
                    id: format!("irsf{}", prefix),
                    prefix: prefix.to_string(),
                    deny: true,
                    user: None,
                    description: desc.to_string(),
                    enabled: true,
                });
            }
        }

        Self {
            rules: RwLock::new(rules),
            default_deny: RwLock::new(config.default_action.eq_ignore_ascii_case("deny")),
            default_cc: RwLock::new(config.default_country_code),
            enabled: RwLock::new(config.enabled),
            blocked_total: AtomicU64::new(0),
        }
    }

    /// Canonicalize a dialed string: "00xx…" → "+xx…", "0x…" → "+<cc>x…",
    /// "+…" passthrough; non-numeric strings returned as-is (matched
    /// literally, so rules like "08" still work on raw dial strings).
    pub fn canonicalize(&self, dialed: &str) -> String {
        let digits: String = dialed.chars().filter(|c| !matches!(c, ' ' | '-' | '.')).collect();
        if digits.starts_with('+') {
            return digits;
        }
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return dialed.to_string();
        }
        if let Some(rest) = digits.strip_prefix("00") {
            return format!("+{}", rest);
        }
        if let Some(rest) = digits.strip_prefix('0') {
            let cc = self.default_cc.read().unwrap().clone();
            return format!("+{}{}", cc, rest);
        }
        digits
    }

    /// Longest-prefix decision. Per-user rules beat global ones; among equal
    /// scope the longest prefix wins; exact tie → deny wins. Both the
    /// canonical and the raw dialed forms are matched.
    pub fn check(&self, dialed: &str, user: Option<&str>) -> DestinationDecision {
        if !*self.enabled.read().unwrap() {
            return DestinationDecision::Allowed;
        }
        let canonical = self.canonicalize(dialed);
        let rules = self.rules.read().unwrap();

        let best = rules
            .iter()
            .filter(|r| r.enabled)
            .filter(|r| r.user.is_none() || r.user.as_deref() == user)
            .filter(|r| canonical.starts_with(&r.prefix) || dialed.starts_with(&r.prefix))
            .max_by_key(|r| {
                (
                    r.user.is_some() as u8, // user-scoped beats global
                    r.prefix.len(),
                    r.deny as u8, // tie → deny wins
                )
            });

        match best {
            Some(rule) if rule.deny => {
                self.blocked_total.fetch_add(1, Ordering::Relaxed);
                warn!(
                    target: "security",
                    "Destination blocked: {} (canonical {}) by rule {} ({})",
                    dialed, canonical, rule.id, rule.description
                );
                DestinationDecision::Blocked {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                }
            }
            Some(_) => DestinationDecision::Allowed,
            None => {
                if *self.default_deny.read().unwrap() {
                    self.blocked_total.fetch_add(1, Ordering::Relaxed);
                    DestinationDecision::Blocked {
                        rule_id: "default".to_string(),
                        description: "default deny".to_string(),
                    }
                } else {
                    DestinationDecision::Allowed
                }
            }
        }
    }

    pub fn list_rules(&self) -> Vec<DestinationRule> {
        self.rules.read().unwrap().clone()
    }

    pub fn add_rule(&self, rule: DestinationRule) {
        self.rules.write().unwrap().push(rule);
    }

    pub fn remove_rule(&self, id: &str) -> bool {
        let mut rules = self.rules.write().unwrap();
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < before
    }

    pub fn set_default_action(&self, deny: bool) {
        *self.default_deny.write().unwrap() = deny;
    }

    pub fn default_action_deny(&self) -> bool {
        *self.default_deny.read().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DestinationPolicy {
        DestinationPolicy::new(DestinationsConfig::default())
    }

    #[test]
    fn canonicalization_table() {
        let p = policy();
        assert_eq!(p.canonicalize("+33612345678"), "+33612345678");
        assert_eq!(p.canonicalize("0612345678"), "+33612345678");
        assert_eq!(p.canonicalize("0088216311111"), "+88216311111");
        assert_eq!(p.canonicalize("06 12-34.56 78"), "+33612345678");
        assert_eq!(p.canonicalize("alice"), "alice");
    }

    #[test]
    fn irsf_seed_blocks_satellite_ranges() {
        let p = policy();
        assert!(matches!(
            p.check("0088216311111", None),
            DestinationDecision::Blocked { .. }
        ));
        assert!(matches!(
            p.check("+97912345", None),
            DestinationDecision::Blocked { .. }
        ));
        assert_eq!(p.check("0612345678", None), DestinationDecision::Allowed);
        assert_eq!(p.blocked_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn longest_prefix_and_user_scope_win() {
        let p = policy();
        // Global deny on +33899 premium, but allow a longer carve-out prefix
        p.add_rule(DestinationRule {
            id: "deny899".into(), prefix: "+33899".into(), deny: true,
            user: None, description: "premium".into(), enabled: true,
        });
        p.add_rule(DestinationRule {
            id: "allow8991".into(), prefix: "+338991".into(), deny: false,
            user: None, description: "carve-out".into(), enabled: true,
        });
        assert!(matches!(p.check("0899000000", None), DestinationDecision::Blocked { .. }));
        assert_eq!(p.check("0899100000", None), DestinationDecision::Allowed);

        // Per-user deny beats global allow
        p.add_rule(DestinationRule {
            id: "alice-no-intl".into(), prefix: "+1".into(), deny: true,
            user: Some("alice".into()), description: "no US for alice".into(), enabled: true,
        });
        assert!(matches!(
            p.check("+12125551234", Some("alice")),
            DestinationDecision::Blocked { .. }
        ));
        assert_eq!(p.check("+12125551234", Some("bob")), DestinationDecision::Allowed);
    }

    #[test]
    fn default_deny_mode() {
        let p = policy();
        p.set_default_action(true);
        p.add_rule(DestinationRule {
            id: "fr".into(), prefix: "+33".into(), deny: false,
            user: None, description: "France ok".into(), enabled: true,
        });
        assert_eq!(p.check("0612345678", None), DestinationDecision::Allowed);
        assert!(matches!(p.check("+4912345", None), DestinationDecision::Blocked { .. }));
    }

    #[test]
    fn disabled_rule_ignored() {
        let p = policy();
        p.add_rule(DestinationRule {
            id: "off".into(), prefix: "+33".into(), deny: true,
            user: None, description: "disabled".into(), enabled: false,
        });
        assert_eq!(p.check("0612345678", None), DestinationDecision::Allowed);
    }
}
