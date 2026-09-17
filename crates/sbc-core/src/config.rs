//! SBC Configuration
//!
//! This module defines all configuration structures for the SBC.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// Main SBC configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SbcConfig {
    pub general: GeneralConfig,
    pub network: NetworkConfig,
    pub media: MediaConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub management: ManagementConfig,
    pub metrics: MetricsConfig,
    /// SIP trunks for outbound PSTN routing (loaded from [[trunks]] sections)
    #[serde(default)]
    pub trunks: Vec<TrunkConfigToml>,
    /// Inbound DID → SIP user mapping (loaded from [[dids]] sections)
    #[serde(default)]
    pub dids: Vec<DidMapping>,
}

/// DID (Direct Inward Dialing) mapping: PSTN number → local SIP user
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DidMapping {
    /// The PSTN number (e.g. "0123456789" or "+33123456789")
    pub number: String,
    /// The local SIP username to route to (e.g. "user1")
    pub user: String,
    /// Optional display name for Caller-ID rewriting
    pub display_name: Option<String>,
}

/// Trunk configuration as loaded from TOML `[[trunks]]` sections.
/// Converted to `routing::TrunkConfig` at startup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrunkConfigToml {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub host: String,
    #[serde(default = "default_sip_port")]
    pub port: u16,
    #[serde(default = "default_udp")]
    pub transport: String, // "UDP", "TCP", "TLS"

    // Authentication (outbound — credentials TO send to trunk)
    #[serde(default)]
    pub auth_required: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,

    // Outbound registration (SBC registers TO the trunk)
    #[serde(default)]
    pub register_with_trunk: bool,
    #[serde(default = "default_reg_interval")]
    pub registration_interval: u64, // seconds

    // Routing / LCR
    #[serde(default)]
    pub prefix_patterns: Vec<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub cost_per_minute: u32,
    #[serde(default = "default_weight")]
    pub weight: u32,

    // Number normalization (callee)
    #[serde(default = "default_number_format")]
    pub number_format: String, // "e164", "national", "local"
    pub country_code: Option<String>,    // "33" for France
    pub national_prefix: Option<String>, // "0" for France

    // Caller ID manipulation
    /// Format for caller number (same as callee: "e164", "national", "local")
    pub caller_number_format: Option<String>,
    /// Override caller number entirely (e.g. trunk-specific CLI)
    pub caller_number_override: Option<String>,
    /// Override caller display name
    pub caller_display_name: Option<String>,

    // Codecs
    #[serde(default = "default_codecs")]
    pub allowed_codecs: Vec<String>,

    // Limits
    #[serde(default = "default_max_calls")]
    pub max_concurrent_calls: u32,
}

fn default_true() -> bool {
    true
}
fn default_sip_port() -> u16 {
    5060
}
fn default_udp() -> String {
    "UDP".to_string()
}
fn default_reg_interval() -> u64 {
    300
}
fn default_priority() -> u32 {
    100
}
fn default_weight() -> u32 {
    100
}
fn default_number_format() -> String {
    "e164".to_string()
}
fn default_codecs() -> Vec<String> {
    vec!["PCMU".to_string(), "PCMA".to_string()]
}
fn default_max_calls() -> u32 {
    100
}

/// General SBC settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// Path to CDR file (JSON-lines format). If set, enables persistent CDR storage.
    pub cdr_file: Option<String>,
    pub name: String,
    pub instance_id: String,
}

/// Network configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub listeners: Vec<ListenerConfig>,
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
}

/// Listener configuration (UDP, TCP, TLS, WSS)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenerConfig {
    pub transport: TransportType,
    pub bind_address: IpAddr,
    pub bind_port: u16,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

/// Transport types
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum TransportType {
    UDP,
    TCP,
    TLS,
    WS,
    WSS,
}

impl TransportType {
    /// Check if transport requires TLS
    pub fn is_secure(&self) -> bool {
        matches!(self, TransportType::TLS | TransportType::WSS)
    }

    /// Convert to rsip Transport type
    pub fn to_rsip_transport(&self) -> rsip::Transport {
        match self {
            TransportType::UDP => rsip::Transport::Udp,
            TransportType::TCP => rsip::Transport::Tcp,
            TransportType::TLS => rsip::Transport::Tls,
            TransportType::WS => rsip::Transport::Ws,
            TransportType::WSS => rsip::Transport::Wss,
        }
    }
}

/// Media configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediaConfig {
    pub rtp_port_range: (u16, u16),
    pub rtcp_enabled: bool,
    pub transcoding_threads: usize,
    pub codecs: Vec<String>,
    pub webrtc: WebRtcConfig,
}

/// WebRTC configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebRtcConfig {
    pub enabled: bool,
    pub stun_servers: Vec<String>,
    pub turn_enabled: bool,
}

/// Database configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Embedded SQLite store for dynamic config (users, DIDs, trunks, routes, ACL).
    /// Source of truth for everything managed via the REST API.
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
        }
    }
}

fn default_sqlite_path() -> String {
    "data/sbc.db".to_string()
}

/// Security configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub rate_limit_global: u32,
    pub rate_limit_per_ip: u32,
    pub auth_challenge_timeout: u64,
    /// SIP realm for Digest authentication (e.g. "sip.nixi.tel")
    #[serde(default = "default_sip_realm")]
    pub sip_realm: String,
    /// SIP users: username → plaintext password (for Digest auth)
    #[serde(default)]
    pub sip_users: HashMap<String, String>,
    /// Enable Digest 401 challenge for REGISTER (false = 200 OK direct)
    #[serde(default)]
    pub enable_digest_auth: bool,

    /// REGISTER authorization (RFC 3261 §10.3 step 5): the authenticated
    /// user may only bind its own AOR. `enforce` answers 403 on a user
    /// mismatch, `log` only reports it (upgrade fallback). The AOR host is
    /// checked too, but refused only once `served_domains` is set: until
    /// then a foreign host is reported (phones registered against a LAN IP
    /// or a DNS alias keep working).
    #[serde(default = "default_register_aor_check")]
    pub register_aor_check: String,

    /// Extra hosts accepted as the domain of an AOR or a local From, besides
    /// `sip_realm`, the SBC domain, its public IP and loopback. Setting it
    /// turns the AOR host check of `register_aor_check` into a refusal.
    #[serde(default)]
    pub served_domains: Vec<String>,

    /// An INVITE from a trunk whose From claims a local user: `allow`
    /// relays it (flagged, never attributed to that user), `reject` answers
    /// 403.
    #[serde(default = "default_trunk_local_from")]
    pub trunk_local_from: String,

    /// Maximum call duration in seconds (0 = unlimited, default 14400 = 4 hours)
    #[serde(default = "default_max_call_duration")]
    pub max_call_duration: u64,

    /// Call setup timeout in seconds (max time in Initiated/Proceeding, default 60)
    /// Seconds an INVITE may stay unanswered (no 200 OK) before the SBC
    /// CANCELs it toward the callee and answers 408 to the caller (CDR
    /// "setup-timeout"). Keep it above the longest ring time you expect.
    #[serde(default = "default_call_setup_timeout")]
    pub call_setup_timeout: u64,

    /// RTP inactivity timeout in seconds (default 90)
    #[serde(default = "default_rtp_timeout")]
    pub rtp_timeout: u64,

    /// Outbound INVITE answer timeout in seconds before trunk failover
    /// (no provisional >= 180 within this window → CANCEL + next trunk).
    #[serde(default = "default_invite_timeout")]
    pub invite_timeout: u64,

    /// RFC 4028 session timers: SBC refreshes the trunk leg with re-INVITEs
    /// so long calls survive intermediaries (trunk negotiates 4h expiry).
    #[serde(default)]
    pub session_timer_enabled: bool,

    /// Session-Expires interval offered on outbound INVITEs (seconds).
    #[serde(default = "default_session_expires")]
    pub session_expires: u64,

    /// Minimum acceptable Session-Expires (RFC 4028 Min-SE).
    #[serde(default = "default_min_se")]
    pub min_se: u64,

    /// Anti-fraud features: [security.ban], [security.destinations],
    /// [security.user_limits]. All have safe defaults.
    #[serde(flatten, default)]
    pub features: crate::security::SecurityFeaturesConfig,
}

fn default_max_call_duration() -> u64 {
    14400
}
fn default_register_aor_check() -> String {
    "enforce".to_string()
}
fn default_trunk_local_from() -> String {
    "allow".to_string()
}
fn default_call_setup_timeout() -> u64 {
    60
}
fn default_rtp_timeout() -> u64 {
    90
}
fn default_invite_timeout() -> u64 {
    5
}
fn default_session_expires() -> u64 {
    1800
}
fn default_min_se() -> u64 {
    90
}

fn default_sip_realm() -> String {
    "sbc.local".to_string()
}

/// Management API configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementConfig {
    pub api_enabled: bool,
    pub api_bind_address: IpAddr,
    pub api_port: u16,
    pub api_auth_token: Option<String>,
    /// CORS allowed origins for the management API.
    /// Empty = no CORS headers; `["*"]` = any origin.
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Explicit opt-in required to bind the management API to a non-loopback
    /// address. When false (default) and `api_bind_address` is not loopback,
    /// the SBC refuses to start — the management API must never be publicly
    /// exposed without deliberate operator intent (firewall + TLS assumed).
    #[serde(default)]
    pub allow_public_bind: bool,
    /// Per-source-IP request budget for the management API, in requests per
    /// minute. Requests over the budget are answered `429 Too Many Requests`.
    #[serde(default = "default_api_rate_limit_per_min")]
    pub api_rate_limit_per_min: u32,
    /// Reverse proxies whose `X-Real-IP` / `X-Forwarded-For` are believed
    /// for rate limiting, audit and bans (loopback by default, where the
    /// nginx of INSTALL.md lives). From any other peer the TCP address is
    /// the client, whatever headers it sends.
    /// An entry that is not an IP address is a config error at startup
    /// rather than a proxy silently not trusted.
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<IpAddr>,
    /// Failed bearer-token checks count toward fail2ban: a brute force on
    /// the token gets the offender's IP banned (SIP and API). Turn off when
    /// operators share a NAT with phones.
    #[serde(default = "default_ban_on_auth_failure")]
    pub ban_on_auth_failure: bool,
}

fn default_api_rate_limit_per_min() -> u32 {
    60
}
fn default_trusted_proxies() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ]
}
fn default_ban_on_auth_failure() -> bool {
    true
}

/// Resolve the effective management API bearer token.
///
/// Precedence: the `SBC_API_TOKEN` environment variable (when present and
/// non-empty) overrides the TOML `[management].api_auth_token`. Whitespace is
/// trimmed; an all-whitespace value counts as unset. Returns `None` when no
/// token is configured anywhere — callers MUST fail closed in that case.
pub fn resolve_api_token(toml_val: &Option<String>) -> Option<String> {
    resolve_api_token_from(std::env::var("SBC_API_TOKEN").ok(), toml_val)
}

/// Pure resolution logic (env value injected) for testability.
fn resolve_api_token_from(env_val: Option<String>, toml_val: &Option<String>) -> Option<String> {
    let non_empty = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    env_val
        .as_deref()
        .and_then(non_empty)
        .or_else(|| toml_val.as_deref().and_then(non_empty))
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub prometheus_enabled: bool,
    pub prometheus_bind_address: IpAddr,
    pub prometheus_port: u16,
}

impl SbcConfig {
    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read config file: {}", e)))?;

        let config: SbcConfig = toml::from_str(&content)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;

        Ok(config)
    }

    /// Validate configuration
    fn validate(&self) -> crate::Result<()> {
        // Validate port ranges
        if self.media.rtp_port_range.0 >= self.media.rtp_port_range.1 {
            return Err(crate::Error::Config("Invalid RTP port range".to_string()));
        }

        // Validate listeners have TLS config when needed
        for listener in &self.network.listeners {
            if listener.transport.is_secure()
                && (listener.cert_file.is_none() || listener.key_file.is_none())
            {
                return Err(crate::Error::Config(format!(
                    "TLS listener on port {} requires cert_file and key_file",
                    listener.bind_port
                )));
            }
        }

        // Fail closed: never expose the management API on a non-loopback
        // address without a deliberate opt-in. A publicly reachable, world-
        // writable config surface is exactly the incident this guards against.
        if self.management.api_enabled && !self.management.api_bind_address.is_loopback() {
            if !self.management.allow_public_bind {
                return Err(crate::Error::Config(format!(
                    "management API bound to non-loopback address {} without \
                     allow_public_bind=true — refusing to start. The management \
                     API must never be publicly exposed; bind to 127.0.0.1 and \
                     reverse-proxy it, or set [management].allow_public_bind=true \
                     only if it is firewalled and TLS-fronted.",
                    self.management.api_bind_address
                )));
            }
            tracing::warn!(
                addr = %self.management.api_bind_address,
                "management API bound to non-loopback address {} — ensure it is \
                 firewalled and never publicly exposed",
                self.management.api_bind_address
            );
        }

        Ok(())
    }
}

impl Default for SbcConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                name: "SBC-NIXI".to_string(),
                instance_id: "sbc-001".to_string(),
                cdr_file: None,
            },
            network: NetworkConfig {
                listeners: vec![ListenerConfig {
                    transport: TransportType::UDP,
                    bind_address: "0.0.0.0".parse().unwrap(),
                    bind_port: 5060,
                    cert_file: None,
                    key_file: None,
                }],
                public_ipv4: None,
                public_ipv6: None,
            },
            media: MediaConfig {
                rtp_port_range: (10000, 20000),
                rtcp_enabled: true,
                transcoding_threads: 4,
                codecs: vec!["PCMU".to_string(), "PCMA".to_string(), "Opus".to_string()],
                webrtc: WebRtcConfig {
                    enabled: false,
                    stun_servers: vec![],
                    turn_enabled: false,
                },
            },
            database: DatabaseConfig::default(),
            security: SecurityConfig {
                rate_limit_global: 1000,
                rate_limit_per_ip: 50,
                auth_challenge_timeout: 30,
                sip_realm: "sbc.local".to_string(),
                sip_users: HashMap::new(),
                enable_digest_auth: false,
                register_aor_check: "enforce".to_string(),
                served_domains: Vec::new(),
                trunk_local_from: "allow".to_string(),
                max_call_duration: 14400,
                call_setup_timeout: 60,
                rtp_timeout: 90,
                invite_timeout: 5,
                session_timer_enabled: false,
                session_expires: 1800,
                min_se: 90,
                features: Default::default(),
            },
            management: ManagementConfig {
                api_enabled: true,
                api_bind_address: "127.0.0.1".parse().unwrap(),
                api_port: 8080,
                api_auth_token: None,
                cors_allowed_origins: Vec::new(),
                allow_public_bind: false,
                api_rate_limit_per_min: default_api_rate_limit_per_min(),
                trusted_proxies: default_trusted_proxies(),
                ban_on_auth_failure: true,
            },
            metrics: MetricsConfig {
                prometheus_enabled: true,
                prometheus_bind_address: "0.0.0.0".parse().unwrap(),
                prometheus_port: 9090,
            },
            trunks: Vec::new(),
            dids: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SbcConfig::default();
        assert_eq!(config.general.name, "SBC-NIXI");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_rtp_port_range() {
        let mut config = SbcConfig::default();
        config.media.rtp_port_range = (20000, 10000); // Invalid: min > max
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tls_requires_certs() {
        let mut config = SbcConfig::default();
        config.network.listeners = vec![ListenerConfig {
            transport: TransportType::TLS,
            bind_address: "0.0.0.0".parse().unwrap(),
            bind_port: 5061,
            cert_file: None, // Missing cert
            key_file: None,  // Missing key
        }];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_public_management_bind_refused_without_optin() {
        let mut config = SbcConfig::default();
        config.management.api_bind_address = "0.0.0.0".parse().unwrap();
        config.management.allow_public_bind = false;
        assert!(
            config.validate().is_err(),
            "non-loopback management bind must fail closed"
        );
    }

    #[test]
    fn test_public_management_bind_allowed_with_optin() {
        let mut config = SbcConfig::default();
        config.management.api_bind_address = "0.0.0.0".parse().unwrap();
        config.management.allow_public_bind = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_public_bind_ignored_when_api_disabled() {
        let mut config = SbcConfig::default();
        config.management.api_enabled = false;
        config.management.api_bind_address = "0.0.0.0".parse().unwrap();
        config.management.allow_public_bind = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resolve_api_token_precedence() {
        // env wins over TOML
        assert_eq!(
            resolve_api_token_from(Some("env-tok".into()), &Some("toml-tok".into())),
            Some("env-tok".to_string())
        );
        // empty/whitespace env falls back to TOML
        assert_eq!(
            resolve_api_token_from(Some("   ".into()), &Some("toml-tok".into())),
            Some("toml-tok".to_string())
        );
        // no env → TOML
        assert_eq!(
            resolve_api_token_from(None, &Some("toml-tok".into())),
            Some("toml-tok".to_string())
        );
        // nothing configured → None (caller must fail closed)
        assert_eq!(resolve_api_token_from(None, &None), None);
        // whitespace-only TOML counts as unset
        assert_eq!(resolve_api_token_from(None, &Some("  ".into())), None);
        // env value is trimmed
        assert_eq!(
            resolve_api_token_from(Some("  spaced  ".into()), &None),
            Some("spaced".to_string())
        );
    }
}

#[cfg(test)]
mod example_config_tests {
    use super::*;

    /// The shipped example must always parse: every new key documented
    /// there is a key the binary accepts.
    #[test]
    fn example_config_parses_with_every_documented_key() {
        let raw = include_str!("../../../config/sbc.toml.example");
        let cfg: SbcConfig = toml::from_str(raw).expect("config/sbc.toml.example parses");
        assert_eq!(cfg.security.register_aor_check, "enforce");
        assert_eq!(cfg.security.trunk_local_from, "allow");
        assert_eq!(cfg.security.call_setup_timeout, 60);
        assert_eq!(cfg.security.rtp_timeout, 90);
        assert_eq!(
            cfg.management.trusted_proxies,
            vec![
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            ]
        );
        let broken = raw.replace(
            "trusted_proxies = [\"127.0.0.1\", \"::1\"]",
            "trusted_proxies = [\"nginx\"]",
        );
        assert_ne!(broken, raw, "the example documents trusted_proxies");
        assert!(
            toml::from_str::<SbcConfig>(&broken).is_err(),
            "a proxy that is not an IP is a config error at startup"
        );
        assert!(cfg.management.ban_on_auth_failure);
    }
}
