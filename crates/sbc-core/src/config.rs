//! SBC Configuration
//!
//! This module defines all configuration structures for the SBC.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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
    /// Timings of the per-trunk OPTIONS probes and REGISTER retries
    /// (`[trunk_health]`, boot-only).
    #[serde(default)]
    pub trunk_health: TrunkHealthConfig,
    /// `[logging]`: level and output format (boot-only).
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human lines for a terminal or journald (`call{uuid=… call_id=…}: msg`).
    #[default]
    Text,
    /// One JSON object per line for log shipping (`span` carries the call).
    Json,
}

/// `[logging]`, read once at boot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// A level or `tracing` EnvFilter directives ("info", "debug",
    /// "sbc_core::media=debug,info"). Precedence: `--verbose` > `RUST_LOG`
    /// > this key.
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Text,
        }
    }
}

/// `[trunk_health]`: OPTIONS health checks and outbound REGISTER retries.
/// Read at boot only (the tasks themselves follow the trunk table live).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrunkHealthConfig {
    /// Seconds between two OPTIONS probes of a trunk.
    #[serde(default = "default_options_interval")]
    pub options_interval: u64,
    /// Seconds to wait for the OPTIONS answer before counting a miss.
    #[serde(default = "default_options_timeout")]
    pub options_timeout: u64,
    /// Cap (seconds) of the exponential retry after a refused or unanswered
    /// outbound REGISTER (starts at 30 s, doubles, resets on success).
    #[serde(default = "default_register_backoff_max")]
    pub register_backoff_max: u64,
}

fn default_options_interval() -> u64 {
    30
}
fn default_options_timeout() -> u64 {
    5
}
fn default_register_backoff_max() -> u64 {
    900
}

impl Default for TrunkHealthConfig {
    fn default() -> Self {
        Self {
            options_interval: default_options_interval(),
            options_timeout: default_options_timeout(),
            register_backoff_max: default_register_backoff_max(),
        }
    }
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
    /// A store that cannot be opened or read at boot is fatal (the SBC
    /// would run with no users, trunks or DIDs). `true` restores the old
    /// behaviour: warn and run from the TOML seeds, `/ready` stays 503.
    #[serde(default)]
    pub allow_missing_store: bool,
    /// Where `POST /api/v1/backup` and the backup timer write
    /// `sbc-<timestamp>.db` copies; default `<dir of sqlite_path>/backups`.
    #[serde(default)]
    pub backup_dir: Option<String>,
    /// Hours between two automatic backups; 0 disables the timer.
    #[serde(default = "default_backup_interval_hours")]
    pub backup_interval_hours: u32,
    /// Newest backups kept after each backup; 0 = never prune.
    #[serde(default = "default_backup_keep")]
    pub backup_keep: u32,
}

fn default_backup_interval_hours() -> u32 {
    24
}
fn default_backup_keep() -> u32 {
    7
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
            allow_missing_store: false,
            backup_dir: None,
            backup_interval_hours: default_backup_interval_hours(),
            backup_keep: default_backup_keep(),
        }
    }
}

impl DatabaseConfig {
    /// The backup policy derived from this section.
    pub fn backup_policy(&self) -> crate::sbc::backup::BackupPolicy {
        let dir = match self.backup_dir.as_deref().map(str::trim) {
            Some(d) if !d.is_empty() => PathBuf::from(d),
            _ => Path::new(&self.sqlite_path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("backups"),
        };
        let interval = (self.backup_interval_hours > 0)
            .then(|| std::time::Duration::from_secs(u64::from(self.backup_interval_hours) * 3600));
        crate::sbc::backup::BackupPolicy {
            dir,
            interval,
            keep: self.backup_keep as usize,
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

    /// Registrar (RFC 3261 §10.3): a REGISTER asking less than this is
    /// answered 423 Interval Too Brief + Min-Expires.
    #[serde(default = "default_register_min_expires")]
    pub register_min_expires: u32,
    /// Granted interval cap (the phone reads it back in the 200's Contact).
    #[serde(default = "default_register_max_expires")]
    pub register_max_expires: u32,
    /// Granted when the REGISTER names no interval.
    #[serde(default = "default_register_default_expires")]
    pub register_default_expires: u32,

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
fn default_register_min_expires() -> u32 {
    60
}
fn default_register_max_expires() -> u32 {
    3600
}
fn default_register_default_expires() -> u32 {
    3600
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
        Self::from_toml_str(&content)
    }

    /// Parse and validate a TOML document (what `from_file` and a reload do).
    pub fn from_toml_str(content: &str) -> crate::Result<Self> {
        let config: SbcConfig = toml::from_str(content)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    /// True when the management API binds a non-loopback address (allowed
    /// by `allow_public_bind`): the binary warns once at boot.
    pub fn management_bind_is_public(&self) -> bool {
        self.management.api_enabled && !self.management.api_bind_address.is_loopback()
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
        if self.management_bind_is_public() && !self.management.allow_public_bind {
            return Err(crate::Error::Config(format!(
                "management API bound to non-loopback address {} without \
                 allow_public_bind=true — refusing to start. The management \
                 API must never be publicly exposed; bind to 127.0.0.1 and \
                 reverse-proxy it, or set [management].allow_public_bind=true \
                 only if it is firewalled and TLS-fronted.",
                self.management.api_bind_address
            )));
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
                register_min_expires: 60,
                register_max_expires: 3600,
                register_default_expires: 3600,
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
            trunk_health: TrunkHealthConfig::default(),
            logging: LoggingConfig::default(),
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
        assert_eq!(
            (
                cfg.trunk_health.options_interval,
                cfg.trunk_health.options_timeout,
                cfg.trunk_health.register_backoff_max
            ),
            (30, 5, 900)
        );
        assert_eq!(
            (
                cfg.security.register_min_expires,
                cfg.security.register_max_expires,
                cfg.security.register_default_expires
            ),
            (60, 3600, 3600)
        );
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert!(!cfg.database.allow_missing_store);
        assert_eq!(
            cfg.database.backup_dir.as_deref(),
            Some("/var/lib/sbc/backups")
        );
        assert_eq!(
            (cfg.database.backup_interval_hours, cfg.database.backup_keep),
            (24, 7)
        );
    }

    #[test]
    fn logging_section_is_optional_and_strict() {
        let raw = include_str!("../../../config/sbc.toml.example");
        let without: String = {
            let start = raw.find("\n[logging]\n").unwrap() + 1;
            let end = raw[start + 1..]
                .find("\n[")
                .map(|i| start + 1 + i)
                .unwrap_or(raw.len());
            format!("{}{}", &raw[..start], &raw[end..])
        };
        let cfg: SbcConfig = toml::from_str(&without).expect("no [logging] section");
        assert_eq!(cfg.logging, LoggingConfig::default());
        let bad = raw.replace("format = \"json\"", "format = \"yaml\"");
        assert_ne!(bad, raw);
        assert!(
            toml::from_str::<SbcConfig>(&bad).is_err(),
            "an unknown format is a config error"
        );
    }

    #[test]
    fn backup_policy_defaults_next_to_the_store() {
        let mut db = DatabaseConfig::default();
        let policy = db.backup_policy();
        assert_eq!(policy.dir, PathBuf::from("data/backups"));
        assert_eq!(
            policy.interval,
            Some(std::time::Duration::from_secs(24 * 3600))
        );
        assert_eq!(policy.keep, 7);
        db.backup_interval_hours = 0;
        db.backup_dir = Some("  ".into());
        db.sqlite_path = "/var/lib/sbc/sbc.db".into();
        let policy = db.backup_policy();
        assert!(policy.interval.is_none(), "0 disables the timer");
        assert_eq!(
            policy.dir,
            PathBuf::from("/var/lib/sbc/backups"),
            "blank dir falls back"
        );
        db.sqlite_path = "sbc.db".into();
        assert_eq!(db.backup_policy().dir, PathBuf::from("./backups"));
    }
}

// ── Key classes, diff, masking (GET /api/v1/config, reload reports) ──────────

/// What a change of a TOML key needs to take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyClass {
    /// Applied by SIGHUP / `POST /api/v1/reload`.
    Reload,
    /// Read once at boot.
    Restart,
    /// Imported once into the SQLite store at first boot, then ignored.
    Seed,
    /// Parsed for compatibility, read by nothing.
    Unused,
}

const RELOAD_KEYS: &[&str] = &[
    "security.max_call_duration",
    "security.call_setup_timeout",
    "security.rtp_timeout",
    "security.invite_timeout",
    "security.session_timer_enabled",
    "security.session_expires",
    "security.min_se",
    "security.register_aor_check",
    "security.served_domains",
    "security.trunk_local_from",
    "security.register_min_expires",
    "security.register_max_expires",
    "security.register_default_expires",
    "security.rate_limit_per_ip",
    "security.ban.",
    "security.destinations.enabled",
    "security.destinations.default_action",
    "security.destinations.default_country_code",
    "security.user_limits.enabled",
    "security.user_limits.default_max_concurrent_calls",
    "security.user_limits.default_max_calls_per_minute",
];
const RESTART_KEYS: &[&str] = &[
    "general.cdr_file",
    "network.listeners",
    "network.public_ipv4",
    "media.rtp_port_range",
    "database.",
    "security.sip_realm",
    "security.enable_digest_auth",
    "management.",
    "trunk_health.",
    "logging.",
];
const SEED_KEYS: &[&str] = &[
    "security.sip_users",
    "trunks",
    "dids",
    "security.destinations.rules",
    "security.destinations.seed_irsf_rules",
    "security.user_limits.overrides",
];

/// The class of a dotted key path (`security.ban.max_failures`); the
/// longest matching prefix wins, unknown keys are `Unused`.
pub fn classify_key(path: &str) -> KeyClass {
    let matches = |prefixes: &[&str]| -> usize {
        prefixes
            .iter()
            .filter(|p| {
                path == p.trim_end_matches('.')
                    || path.starts_with(*p)
                    || (!p.ends_with('.') && path.starts_with(&format!("{}.", p)))
            })
            .map(|p| p.len())
            .max()
            .unwrap_or(0)
    };
    let (reload, restart, seed) = (
        matches(RELOAD_KEYS),
        matches(RESTART_KEYS),
        matches(SEED_KEYS),
    );
    let best = reload.max(restart).max(seed);
    if best == 0 {
        KeyClass::Unused
    } else if best == reload {
        KeyClass::Reload
    } else if best == restart {
        KeyClass::Restart
    } else {
        KeyClass::Seed
    }
}

/// The prefix tables, for `GET /api/v1/config`.
pub fn key_classes() -> serde_json::Value {
    serde_json::json!({
        "reload": RELOAD_KEYS,
        "restart": RESTART_KEYS,
        "seed": SEED_KEYS,
        "unused": ["general.name", "general.instance_id", "network.public_ipv6",
                   "security.rate_limit_global", "security.auth_challenge_timeout",
                   "media.* (except rtp_port_range)", "metrics.*"],
    })
}

/// Keys that differ between two configs, by what applying them needs.
/// Paths only, never values (a token cannot leak through here).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigDiff {
    pub restart_required: Vec<String>,
    pub reload_pending: Vec<String>,
}

fn leaves(value: &serde_json::Value, prefix: &str, out: &mut Vec<(String, serde_json::Value)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                leaves(v, &path, out);
            }
        }
        other => out.push((prefix.to_string(), other.clone())),
    }
}

fn config_leaves(cfg: &SbcConfig) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut out = Vec::new();
    leaves(&serde_json::to_value(cfg).unwrap_or_default(), "", &mut out);
    out.into_iter().collect()
}

pub fn config_diff(running: &SbcConfig, candidate: &SbcConfig) -> ConfigDiff {
    let a = config_leaves(running);
    let b = config_leaves(candidate);
    let mut diff = ConfigDiff::default();
    let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    for key in keys {
        if a.get(key) == b.get(key) {
            continue;
        }
        match classify_key(key) {
            KeyClass::Reload => diff.reload_pending.push(key.clone()),
            KeyClass::Restart => diff.restart_required.push(key.clone()),
            KeyClass::Seed | KeyClass::Unused => {}
        }
    }
    diff
}

/// `effective` with every reload-class leaf taken from `loaded`: what
/// actually runs after a reload (restart-class keys keep their boot value).
pub fn overlay_reload_keys(effective: &SbcConfig, loaded: &SbcConfig) -> SbcConfig {
    let mut base = serde_json::to_value(effective).unwrap_or_default();
    let mut new_leaves = Vec::new();
    leaves(
        &serde_json::to_value(loaded).unwrap_or_default(),
        "",
        &mut new_leaves,
    );
    for (path, value) in new_leaves {
        if classify_key(&path) != KeyClass::Reload {
            continue;
        }
        let mut cursor = &mut base;
        let parts: Vec<&str> = path.split('.').collect();
        for part in &parts[..parts.len() - 1] {
            cursor = cursor
                .as_object_mut()
                .map(|m| m.entry(part.to_string()).or_insert(serde_json::json!({})))
                .expect("object path");
        }
        if let Some(m) = cursor.as_object_mut() {
            m.insert(parts[parts.len() - 1].to_string(), value);
        }
    }
    serde_json::from_value(base).unwrap_or_else(|_| effective.clone())
}

/// The config as JSON with every secret replaced by `"***"`.
pub fn masked_json(cfg: &SbcConfig) -> serde_json::Value {
    let mut v = serde_json::to_value(cfg).unwrap_or_default();
    if let Some(t) = v.pointer_mut("/management/api_auth_token") {
        if !t.is_null() {
            *t = serde_json::json!("***");
        }
    }
    if let Some(serde_json::Value::Object(users)) = v.pointer_mut("/security/sip_users") {
        for value in users.values_mut() {
            *value = serde_json::json!("***");
        }
    }
    if let Some(serde_json::Value::Array(trunks)) = v.pointer_mut("/trunks") {
        for t in trunks.iter_mut() {
            if let Some(p) = t.get_mut("password") {
                if !p.is_null() {
                    *p = serde_json::json!("***");
                }
            }
        }
    }
    v
}

#[cfg(test)]
mod key_class_tests {
    use super::*;

    #[test]
    fn keys_are_classified_by_longest_prefix() {
        assert_eq!(classify_key("security.ban.max_failures"), KeyClass::Reload);
        assert_eq!(classify_key("security.destinations.rules"), KeyClass::Seed);
        assert_eq!(
            classify_key("security.destinations.enabled"),
            KeyClass::Reload
        );
        assert_eq!(
            classify_key("security.user_limits.overrides"),
            KeyClass::Seed
        );
        assert_eq!(
            classify_key("security.user_limits.enabled"),
            KeyClass::Reload
        );
        assert_eq!(classify_key("security.sip_users.alice"), KeyClass::Seed);
        assert_eq!(classify_key("security.sip_realm"), KeyClass::Restart);
        assert_eq!(classify_key("network.listeners"), KeyClass::Restart);
        assert_eq!(classify_key("network.public_ipv6"), KeyClass::Unused);
        assert_eq!(classify_key("management.api_port"), KeyClass::Restart);
        assert_eq!(classify_key("trunks"), KeyClass::Seed);
        assert_eq!(classify_key("metrics.prometheus_port"), KeyClass::Unused);
        assert_eq!(classify_key("logging.format"), KeyClass::Restart);
        assert_eq!(classify_key("database.backup_keep"), KeyClass::Restart);
    }

    #[test]
    fn diff_classifies_paths_and_carries_no_values() {
        let a = SbcConfig::default();
        let mut b = a.clone();
        b.security.max_call_duration += 1;
        b.security.features.ban.max_failures += 1;
        b.management.api_port += 1;
        b.management.api_auth_token = Some("tok-secret-1".into());
        b.metrics.prometheus_port += 1;
        b.security.sip_users.insert("alice".into(), "pw".into());
        let d = config_diff(&a, &b);
        assert_eq!(
            d.reload_pending,
            vec!["security.ban.max_failures", "security.max_call_duration"]
        );
        assert_eq!(
            d.restart_required,
            vec!["management.api_auth_token", "management.api_port"]
        );
        assert!(!serde_json::to_string(&d).unwrap().contains("tok-secret"));
        assert_eq!(config_diff(&a, &a), ConfigDiff::default());
    }

    #[test]
    fn overlay_takes_reload_keys_only() {
        let boot = SbcConfig::default();
        let mut loaded = boot.clone();
        loaded.security.rtp_timeout = 45;
        loaded.security.features.ban.max_failures = 2;
        loaded.management.api_port = 9999;
        loaded.security.sip_realm = "other".into();
        let eff = overlay_reload_keys(&boot, &loaded);
        assert_eq!(eff.security.rtp_timeout, 45);
        assert_eq!(eff.security.features.ban.max_failures, 2);
        assert_eq!(eff.management.api_port, boot.management.api_port);
        assert_eq!(eff.security.sip_realm, boot.security.sip_realm);
    }

    #[test]
    fn masked_json_hides_every_secret() {
        let mut cfg = SbcConfig::default();
        cfg.management.api_auth_token = Some("tok-1".into());
        cfg.security.sip_users.insert("alice".into(), "pw-1".into());
        cfg.trunks.push(TrunkConfigToml {
            password: Some("pw-2".into()),
            ..toml::from_str("name = \"t\"\nhost = \"h\"\n").unwrap()
        });
        let v = masked_json(&cfg);
        assert_eq!(v["management"]["api_auth_token"], "***");
        assert_eq!(v["security"]["sip_users"]["alice"], "***");
        assert_eq!(v["trunks"][0]["password"], "***");
        let text = v.to_string();
        assert!(!text.contains("tok-1") && !text.contains("pw-1") && !text.contains("pw-2"));
        assert!(masked_json(&SbcConfig::default())["management"]["api_auth_token"].is_null());
    }
}
