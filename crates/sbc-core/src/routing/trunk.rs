//! Trunk Management
//!
//! Handles configuration and state for SIP trunks.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Unique identifier for a trunk
pub type TrunkId = Uuid;

/// Transport type for trunk
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl TransportType {
    /// Convert to rsip Transport type
    pub fn to_rsip_transport(&self) -> rsip::Transport {
        match self {
            TransportType::Udp => rsip::Transport::Udp,
            TransportType::Tcp => rsip::Transport::Tcp,
            TransportType::Tls => rsip::Transport::Tls,
            TransportType::Ws => rsip::Transport::Ws,
            TransportType::Wss => rsip::Transport::Wss,
        }
    }

    /// Create from rsip Transport type
    pub fn from_rsip_transport(transport: rsip::Transport) -> Self {
        match transport {
            rsip::Transport::Udp => TransportType::Udp,
            rsip::Transport::Tcp => TransportType::Tcp,
            rsip::Transport::Tls => TransportType::Tls,
            rsip::Transport::Ws => TransportType::Ws,
            rsip::Transport::Wss => TransportType::Wss,
            _ => TransportType::Udp, // Default fallback
        }
    }
}

/// Number format expected by a trunk
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NumberFormat {
    /// E.164 international: +33612345678 (keep as-is)
    E164,
    /// National format: 0612345678 (strip country code, add national prefix)
    National,
    /// Local format: 612345678 (strip country code and national prefix)
    Local,
}

impl Default for NumberFormat {
    fn default() -> Self { NumberFormat::E164 }
}

/// Trunk configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrunkConfig {
    pub id: TrunkId,
    pub name: String,
    pub enabled: bool,

    // Network
    pub transport: TransportType,
    pub host: String,
    pub port: u16,
    /// Pre-resolved IP address (DNS lookup at load time for hostnames)
    #[serde(skip)]
    pub resolved_addr: Option<SocketAddr>,

    // Authentication (outbound — credentials TO send to trunk)
    pub auth_required: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,

    // Codecs
    pub allowed_codecs: Vec<String>,
    pub transcoding_enabled: bool,

    // Limits
    pub max_concurrent_calls: u32,
    pub calls_per_second: u32,

    // ACL
    pub allowed_ips: Vec<String>, // CIDR notation

    // SIP settings
    pub register_with_trunk: bool,
    pub registration_interval: Duration,

    // LCR (Least Cost Routing)
    /// Cost per minute in millicents (e.g. 150 = 1.50 cents/min)
    pub cost_per_minute: u32,

    /// Priority (lower = higher priority; 0 = highest)
    pub priority: u32,

    /// Weight for load balancing among same-priority trunks (0–100)
    pub weight: u32,

    /// Prefix patterns this trunk can route (e.g. ["+33", "+44", "+1"])
    /// Empty = routes everything
    pub prefix_patterns: Vec<String>,

    // Number normalization (callee — Request-URI)
    pub number_format: NumberFormat,
    pub country_code: Option<String>,
    pub national_prefix: Option<String>,

    // Caller ID manipulation (From header / P-Asserted-Identity)
    /// Format for caller number in From header (same options as callee)
    pub caller_number_format: Option<NumberFormat>,
    /// Override caller number (e.g. trunk-specific CLI)
    pub caller_number_override: Option<String>,
    /// Override caller display name
    pub caller_display_name: Option<String>,

    // ── Outbound TLS (transport = TLS) ──────────────────────────────
    /// SNI / expected certificate hostname (default: trunk host).
    pub tls_sni: Option<String>,
    /// Custom CA bundle path (PEM); None = system roots.
    pub tls_ca_cert: Option<String>,
    /// Verify the server certificate (default true).
    pub tls_verify: bool,
    /// Client cert/key paths (PEM) — both set = mTLS.
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
}

impl TrunkConfig {
    /// Create a new trunk configuration
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            enabled: true,
            transport: TransportType::Udp,
            host: String::new(),
            port: 5060,
            resolved_addr: None,
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            allowed_codecs: vec!["PCMU".to_string(), "PCMA".to_string()],
            transcoding_enabled: false,
            max_concurrent_calls: 100,
            calls_per_second: 10,
            allowed_ips: Vec::new(),
            register_with_trunk: false,
            registration_interval: Duration::from_secs(300),
            cost_per_minute: 0,
            priority: 100,
            weight: 100,
            prefix_patterns: Vec::new(),
            number_format: NumberFormat::E164,
            country_code: None,
            national_prefix: None,
            caller_number_format: None,
            caller_number_override: None,
            caller_display_name: None,
            tls_sni: None,
            tls_ca_cert: None,
            tls_verify: true,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    /// Get the trunk's destination address.
    /// Uses pre-resolved address if available (for hostnames), otherwise tries direct parse.
    pub fn destination(&self) -> Option<SocketAddr> {
        if let Some(addr) = self.resolved_addr {
            return Some(addr);
        }
        format!("{}:{}", self.host, self.port).parse().ok()
    }

    /// Resolve the trunk's hostname to an IP address via DNS.
    /// Must be called at startup for trunks with hostnames (e.g. trunk.example.com).
    pub async fn resolve_destination(&mut self) -> Option<SocketAddr> {
        // If it's already a valid SocketAddr, use it directly
        if let Ok(addr) = format!("{}:{}", self.host, self.port).parse::<SocketAddr>() {
            self.resolved_addr = Some(addr);
            return Some(addr);
        }
        // DNS lookup for hostnames
        match tokio::net::lookup_host(format!("{}:{}", self.host, self.port)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    self.resolved_addr = Some(addr);
                    Some(addr)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check if a codec is allowed for this trunk
    pub fn is_codec_allowed(&self, codec: &str) -> bool {
        self.allowed_codecs.iter().any(|c| c.eq_ignore_ascii_case(codec))
    }

    /// Check if this trunk can route a given phone number (prefix matching)
    pub fn matches_prefix(&self, number: &str) -> bool {
        if self.prefix_patterns.is_empty() {
            return true; // Empty patterns = routes everything
        }
        self.prefix_patterns.iter().any(|p| number.starts_with(p))
    }

    /// LCR sort key: (priority, cost_per_minute) — lower is better
    pub fn lcr_sort_key(&self) -> (u32, u32) {
        (self.priority, self.cost_per_minute)
    }

    /// Normalize the CALLER number for this trunk.
    /// Returns (number, display_name) — either rewritten or original.
    pub fn normalize_caller(&self, number: &str, display_name: Option<&str>) -> (String, Option<String>) {
        // Override takes highest priority
        if let Some(ref override_num) = self.caller_number_override {
            let dn = self.caller_display_name.clone().or_else(|| display_name.map(|s| s.to_string()));
            return (override_num.clone(), dn);
        }
        // Apply format conversion if configured
        let new_number = if let Some(fmt) = self.caller_number_format {
            match fmt {
                NumberFormat::E164 => {
                    if number.starts_with('+') {
                        number.to_string()
                    } else if number.starts_with('0') {
                        if let Some(ref cc) = self.country_code {
                            format!("+{}{}", cc, &number[1..])
                        } else {
                            number.to_string()
                        }
                    } else {
                        number.to_string()
                    }
                }
                NumberFormat::National => {
                    if let Some(ref cc) = self.country_code {
                        let prefix = format!("+{}", cc);
                        if number.starts_with(&prefix) {
                            let np = self.national_prefix.as_deref().unwrap_or("0");
                            format!("{}{}", np, &number[prefix.len()..])
                        } else {
                            number.to_string()
                        }
                    } else {
                        number.to_string()
                    }
                }
                NumberFormat::Local => {
                    if let Some(ref cc) = self.country_code {
                        let prefix = format!("+{}", cc);
                        if number.starts_with(&prefix) {
                            number[prefix.len()..].to_string()
                        } else {
                            number.to_string()
                        }
                    } else {
                        number.to_string()
                    }
                }
            }
        } else {
            number.to_string()
        };
        let dn = self.caller_display_name.clone().or_else(|| display_name.map(|s| s.to_string()));
        (new_number, dn)
    }

    /// Normalize a phone number for this trunk's expected format.
    /// Input may be E.164 (+33612345678) or national (0612345678).
    pub fn normalize_number(&self, number: &str) -> String {
        match self.number_format {
            NumberFormat::E164 => {
                if number.starts_with('+') {
                    number.to_string()
                } else if number.starts_with('0') {
                    if let Some(ref cc) = self.country_code {
                        format!("+{}{}", cc, &number[1..])
                    } else {
                        number.to_string()
                    }
                } else {
                    number.to_string()
                }
            }
            NumberFormat::National => {
                if let Some(ref cc) = self.country_code {
                    let prefix = format!("+{}", cc);
                    if number.starts_with(&prefix) {
                        let national_prefix = self.national_prefix.as_deref().unwrap_or("0");
                        format!("{}{}", national_prefix, &number[prefix.len()..])
                    } else if number.starts_with('+') {
                        // Different country code — pass through
                        number.to_string()
                    } else {
                        // Already national format
                        number.to_string()
                    }
                } else {
                    number.to_string()
                }
            }
            NumberFormat::Local => {
                if let Some(ref cc) = self.country_code {
                    let prefix = format!("+{}", cc);
                    if number.starts_with(&prefix) {
                        number[prefix.len()..].to_string()
                    } else {
                        number.to_string()
                    }
                } else {
                    number.to_string()
                }
            }
        }
    }
}

/// Trunk state and statistics
#[derive(Debug, Clone)]
pub struct TrunkState {
    pub trunk_id: TrunkId,
    pub active_calls: u32,
    pub total_calls: u64,
    pub failed_calls: u64,
    pub registered: bool,
    /// Consecutive failures (reset on success)
    pub consecutive_failures: u32,
    /// Temporarily disabled until this time (for health-based cooldown)
    pub disabled_until: Option<std::time::Instant>,
}

impl TrunkState {
    pub fn new(trunk_id: TrunkId) -> Self {
        Self {
            trunk_id,
            active_calls: 0,
            total_calls: 0,
            failed_calls: 0,
            registered: false,
            consecutive_failures: 0,
            disabled_until: None,
        }
    }

    /// Check if trunk can accept a new call (capacity + health check)
    pub fn can_accept_call(&self, config: &TrunkConfig) -> bool {
        // Check health cooldown
        if let Some(until) = self.disabled_until {
            if std::time::Instant::now() < until {
                return false; // Still in cooldown
            }
        }
        self.active_calls < config.max_concurrent_calls
    }

    /// Record a successful call (reset consecutive failures)
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.disabled_until = None;
    }

    /// Record a trunk failure and apply cooldown if too many consecutive failures
    pub fn record_trunk_failure(&mut self) {
        self.failed_calls += 1;
        self.consecutive_failures += 1;
        // After 3 consecutive failures, disable for 30 seconds
        // After 6, disable for 2 minutes; after 10, disable for 5 minutes
        let cooldown_secs = match self.consecutive_failures {
            0..=2 => 0,
            3..=5 => 30,
            6..=9 => 120,
            _ => 300,
        };
        if cooldown_secs > 0 {
            self.disabled_until = Some(
                std::time::Instant::now() + std::time::Duration::from_secs(cooldown_secs)
            );
        }
    }

    /// Increment active call count
    pub fn increment_calls(&mut self) {
        self.active_calls += 1;
        self.total_calls += 1;
    }

    /// Decrement active call count
    pub fn decrement_calls(&mut self) {
        if self.active_calls > 0 {
            self.active_calls -= 1;
        }
    }

    /// Record a failed call
    pub fn record_failure(&mut self) {
        self.failed_calls += 1;
    }
}

/// Trunk manager
pub struct TrunkManager {
    trunks: Arc<DashMap<TrunkId, TrunkConfig>>,
    states: Arc<DashMap<TrunkId, TrunkState>>,
}

impl TrunkManager {
    /// Create a new trunk manager
    pub fn new() -> Self {
        Self {
            trunks: Arc::new(DashMap::new()),
            states: Arc::new(DashMap::new()),
        }
    }

    /// Add a trunk
    pub fn add_trunk(&self, config: TrunkConfig) -> TrunkId {
        let id = config.id;
        self.trunks.insert(id, config);
        self.states.insert(id, TrunkState::new(id));
        id
    }

    /// Get a trunk configuration
    pub fn get_trunk(&self, id: &TrunkId) -> Option<TrunkConfig> {
        self.trunks.get(id).map(|entry| entry.clone())
    }

    /// Get a trunk state
    pub fn get_state(&self, id: &TrunkId) -> Option<TrunkState> {
        self.states.get(id).map(|entry| entry.clone())
    }

    /// Update trunk state
    pub fn update_state<F>(&self, id: &TrunkId, update_fn: F)
    where
        F: FnOnce(&mut TrunkState),
    {
        if let Some(mut entry) = self.states.get_mut(id) {
            update_fn(&mut entry);
        }
    }

    /// Remove a trunk
    pub fn remove_trunk(&self, id: &TrunkId) -> bool {
        self.trunks.remove(id).is_some() && self.states.remove(id).is_some()
    }

    /// List all trunks
    pub fn list_trunks(&self) -> Vec<TrunkConfig> {
        self.trunks.iter().map(|entry| entry.clone()).collect()
    }

    /// Find trunk by name
    pub fn find_by_name(&self, name: &str) -> Option<TrunkConfig> {
        self.trunks
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.clone())
    }

    /// Update an existing trunk by name, preserving its id (and its resolved
    /// address when the destination is unchanged, so active calls are safe).
    /// Returns false when no trunk has that name.
    pub fn update_trunk_by_name(&self, name: &str, mut new_config: TrunkConfig) -> bool {
        let existing = match self.find_by_name(name) {
            Some(t) => t,
            None => return false,
        };
        new_config.id = existing.id;
        if new_config.host == existing.host && new_config.port == existing.port {
            new_config.resolved_addr = existing.resolved_addr;
        }
        self.trunks.insert(existing.id, new_config);
        true
    }

    /// Remove a trunk by name. Returns false when no trunk has that name.
    pub fn remove_by_name(&self, name: &str) -> bool {
        match self.find_by_name(name) {
            Some(t) => self.remove_trunk(&t.id),
            None => false,
        }
    }

    /// Enable a trunk
    pub fn enable_trunk(&self, id: &TrunkId) -> bool {
        if let Some(mut entry) = self.trunks.get_mut(id) {
            entry.enabled = true;
            true
        } else {
            false
        }
    }

    /// Disable a trunk
    pub fn disable_trunk(&self, id: &TrunkId) -> bool {
        if let Some(mut entry) = self.trunks.get_mut(id) {
            entry.enabled = false;
            true
        } else {
            false
        }
    }

    /// Get statistics for all trunks
    pub fn get_stats(&self) -> Vec<(TrunkConfig, TrunkState)> {
        self.trunks
            .iter()
            .filter_map(|entry| {
                let config = entry.clone();
                self.states
                    .get(&config.id)
                    .map(|state| (config, state.clone()))
            })
            .collect()
    }

    /// Count total active calls across all trunks
    pub fn total_active_calls(&self) -> u32 {
        self.states
            .iter()
            .map(|entry| entry.active_calls)
            .sum()
    }
}

impl Default for TrunkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trunk_config_creation() {
        let config = TrunkConfig::new("TestTrunk".to_string());
        assert_eq!(config.name, "TestTrunk");
        assert!(config.enabled);
        assert!(!config.auth_required);
    }

    #[test]
    fn test_trunk_codec_allowed() {
        let mut config = TrunkConfig::new("TestTrunk".to_string());
        config.allowed_codecs = vec!["PCMU".to_string(), "Opus".to_string()];

        assert!(config.is_codec_allowed("PCMU"));
        assert!(config.is_codec_allowed("pcmu")); // Case-insensitive
        assert!(config.is_codec_allowed("Opus"));
        assert!(!config.is_codec_allowed("G729"));
    }

    #[test]
    fn test_trunk_manager() {
        let manager = TrunkManager::new();

        let config = TrunkConfig::new("Trunk1".to_string());
        let id = manager.add_trunk(config.clone());

        assert!(manager.get_trunk(&id).is_some());
        assert_eq!(manager.get_trunk(&id).unwrap().name, "Trunk1");

        assert_eq!(manager.list_trunks().len(), 1);
        assert_eq!(manager.total_active_calls(), 0);
    }

    #[test]
    fn test_trunk_state() {
        let id = Uuid::new_v4();
        let mut state = TrunkState::new(id);

        let mut config = TrunkConfig::new("Test".to_string());
        config.max_concurrent_calls = 2;

        assert!(state.can_accept_call(&config));

        state.increment_calls();
        assert_eq!(state.active_calls, 1);
        assert!(state.can_accept_call(&config));

        state.increment_calls();
        assert_eq!(state.active_calls, 2);
        assert!(!state.can_accept_call(&config)); // At limit

        state.decrement_calls();
        assert_eq!(state.active_calls, 1);
        assert!(state.can_accept_call(&config));
    }

    #[test]
    fn test_trunk_manager_enable_disable() {
        let manager = TrunkManager::new();
        let config = TrunkConfig::new("Trunk1".to_string());
        let id = manager.add_trunk(config);

        assert!(manager.get_trunk(&id).unwrap().enabled);

        manager.disable_trunk(&id);
        assert!(!manager.get_trunk(&id).unwrap().enabled);

        manager.enable_trunk(&id);
        assert!(manager.get_trunk(&id).unwrap().enabled);
    }

    // ── Number normalization tests ────────────────────────────────────

    #[test]
    fn test_normalize_e164_to_national() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::National;
        trunk.country_code = Some("33".into());
        trunk.national_prefix = Some("0".into());

        assert_eq!(trunk.normalize_number("+33612345678"), "0612345678");
        assert_eq!(trunk.normalize_number("0612345678"), "0612345678"); // already national
        assert_eq!(trunk.normalize_number("+44123456789"), "+44123456789"); // foreign: pass through
    }

    #[test]
    fn test_normalize_national_to_e164() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::E164;
        trunk.country_code = Some("33".into());

        assert_eq!(trunk.normalize_number("0612345678"), "+33612345678");
        assert_eq!(trunk.normalize_number("+33612345678"), "+33612345678"); // already e164
    }

    #[test]
    fn test_normalize_e164_to_local() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::Local;
        trunk.country_code = Some("33".into());

        assert_eq!(trunk.normalize_number("+33612345678"), "612345678");
        assert_eq!(trunk.normalize_number("612345678"), "612345678"); // already local
    }

    #[test]
    fn test_normalize_no_country_code() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::National;
        // No country_code set — pass through

        assert_eq!(trunk.normalize_number("+33612345678"), "+33612345678");
    }

    #[test]
    fn test_destination_with_resolved_addr() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.host = "trunk.example.com".into(); // hostname, can't parse as SocketAddr
        trunk.port = 5060;

        // Without resolved_addr, hostname won't parse
        assert!(trunk.destination().is_none());

        // With resolved_addr set (from DNS), it works
        trunk.resolved_addr = Some("1.2.3.4:5060".parse().unwrap());
        assert_eq!(trunk.destination().unwrap(), "1.2.3.4:5060".parse::<SocketAddr>().unwrap());
    }

    // ── matches_prefix tests ─────────────────────────────────────────

    #[test]
    fn test_matches_prefix_france() {
        let mut trunk = TrunkConfig::new("fr-trunk".into());
        trunk.prefix_patterns = vec!["+33".into(), "0".into()];

        assert!(trunk.matches_prefix("+33612345678"), "E.164 French number should match");
        assert!(trunk.matches_prefix("0612345678"), "National French number should match");
        assert!(!trunk.matches_prefix("+44123456789"), "UK number should not match French trunk");
        assert!(!trunk.matches_prefix("+1555123456"), "US number should not match French trunk");
    }

    #[test]
    fn test_matches_prefix_empty_routes_everything() {
        let trunk = TrunkConfig::new("catch-all".into());
        // prefix_patterns is empty by default

        assert!(trunk.matches_prefix("+33612345678"), "Empty prefix should match any number");
        assert!(trunk.matches_prefix("+1555123456"), "Empty prefix should match any number");
        assert!(trunk.matches_prefix("anything"), "Empty prefix should match anything");
    }

    #[test]
    fn test_matches_prefix_international() {
        let mut trunk = TrunkConfig::new("intl-trunk".into());
        trunk.prefix_patterns = vec!["+44".into(), "+1".into(), "+49".into()];

        assert!(trunk.matches_prefix("+44207123456"), "UK number should match");
        assert!(trunk.matches_prefix("+12125551234"), "US number should match");
        assert!(trunk.matches_prefix("+4930123456"), "German number should match");
        assert!(!trunk.matches_prefix("+33612345678"), "French number should not match");
    }

    // ── normalize_caller tests ───────────────────────────────────────

    #[test]
    fn test_normalize_caller_override() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.caller_number_override = Some("+33978370000".into());
        trunk.caller_display_name = Some("NIXI.TEL".into());

        let (num, dn) = trunk.normalize_caller("+33612345678", Some("Alice"));
        assert_eq!(num, "+33978370000", "Override should replace caller number");
        assert_eq!(dn, Some("NIXI.TEL".to_string()), "Override should replace display name");
    }

    #[test]
    fn test_normalize_caller_override_keeps_original_display_name() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.caller_number_override = Some("+33978370000".into());
        // No caller_display_name set — should keep original

        let (num, dn) = trunk.normalize_caller("+33612345678", Some("Alice"));
        assert_eq!(num, "+33978370000");
        assert_eq!(dn, Some("Alice".to_string()), "Should keep original display name when not overridden");
    }

    #[test]
    fn test_normalize_caller_format_national_to_e164() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.caller_number_format = Some(NumberFormat::E164);
        trunk.country_code = Some("33".into());

        let (num, dn) = trunk.normalize_caller("0612345678", None);
        assert_eq!(num, "+33612345678", "National caller should be converted to E.164");
        assert_eq!(dn, None);
    }

    #[test]
    fn test_normalize_caller_format_e164_to_national() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.caller_number_format = Some(NumberFormat::National);
        trunk.country_code = Some("33".into());
        trunk.national_prefix = Some("0".into());

        let (num, _dn) = trunk.normalize_caller("+33612345678", None);
        assert_eq!(num, "0612345678", "E.164 caller should be converted to national");
    }

    #[test]
    fn test_normalize_caller_no_format_passthrough() {
        let trunk = TrunkConfig::new("test".into());
        // No caller_number_format, no override

        let (num, dn) = trunk.normalize_caller("+33612345678", Some("Bob"));
        assert_eq!(num, "+33612345678", "No format → passthrough");
        assert_eq!(dn, Some("Bob".to_string()), "Display name preserved");
    }

    #[test]
    fn test_normalize_caller_format_to_local() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.caller_number_format = Some(NumberFormat::Local);
        trunk.country_code = Some("33".into());

        let (num, _dn) = trunk.normalize_caller("+33612345678", None);
        assert_eq!(num, "612345678", "E.164 caller should be stripped to local");
    }

    // ── normalize_number edge cases ──────────────────────────────────

    #[test]
    fn test_normalize_number_already_correct_format() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::E164;
        trunk.country_code = Some("33".into());

        assert_eq!(trunk.normalize_number("+33612345678"), "+33612345678", "Already E.164 → no change");
    }

    #[test]
    fn test_normalize_number_foreign_passthrough() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::National;
        trunk.country_code = Some("33".into());
        trunk.national_prefix = Some("0".into());

        assert_eq!(trunk.normalize_number("+44207123456"), "+44207123456",
            "Foreign E.164 should pass through on National trunk");
    }

    #[test]
    fn test_normalize_number_no_leading_zero() {
        let mut trunk = TrunkConfig::new("test".into());
        trunk.number_format = NumberFormat::E164;
        trunk.country_code = Some("33".into());

        assert_eq!(trunk.normalize_number("612345678"), "612345678",
            "Number without + or 0 prefix → passthrough (ambiguous)");
    }
}
