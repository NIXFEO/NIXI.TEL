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

fn default_true() -> bool { true }
fn default_sip_port() -> u16 { 5060 }
fn default_udp() -> String { "UDP".to_string() }
fn default_reg_interval() -> u64 { 300 }
fn default_priority() -> u32 { 100 }
fn default_weight() -> u32 { 100 }
fn default_number_format() -> String { "e164".to_string() }
fn default_codecs() -> Vec<String> { vec!["PCMU".to_string(), "PCMA".to_string()] }
fn default_max_calls() -> u32 { 100 }

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
    /// Legacy/optional external databases — not required to run the SBC.
    #[serde(default)]
    pub postgres_url: Option<String>,
    #[serde(default = "default_pg_max_conns")]
    pub postgres_max_connections: u32,
    #[serde(default)]
    pub redis_url: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
            postgres_url: None,
            postgres_max_connections: default_pg_max_conns(),
            redis_url: None,
        }
    }
}

fn default_sqlite_path() -> String { "data/sbc.db".to_string() }
fn default_pg_max_conns() -> u32 { 5 }

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

    /// Maximum call duration in seconds (0 = unlimited, default 14400 = 4 hours)
    #[serde(default = "default_max_call_duration")]
    pub max_call_duration: u64,

    /// Call setup timeout in seconds (max time in Initiated/Proceeding, default 60)
    #[serde(default = "default_call_setup_timeout")]
    pub call_setup_timeout: u64,

    /// RTP inactivity timeout in seconds (default 90)
    #[serde(default = "default_rtp_timeout")]
    pub rtp_timeout: u64,

    /// Outbound INVITE answer timeout in seconds before trunk failover
    /// (no provisional >= 180 within this window → CANCEL + next trunk).
    #[serde(default = "default_invite_timeout")]
    pub invite_timeout: u64,
}

fn default_max_call_duration() -> u64 { 14400 }
fn default_call_setup_timeout() -> u64 { 60 }
fn default_rtp_timeout() -> u64 { 90 }
fn default_invite_timeout() -> u64 { 5 }

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
            return Err(crate::Error::Config(
                "Invalid RTP port range".to_string(),
            ));
        }

        // Validate listeners have TLS config when needed
        for listener in &self.network.listeners {
            if listener.transport.is_secure() {
                if listener.cert_file.is_none() || listener.key_file.is_none() {
                    return Err(crate::Error::Config(format!(
                        "TLS listener on port {} requires cert_file and key_file",
                        listener.bind_port
                    )));
                }
            }
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
                max_call_duration: 14400,
                call_setup_timeout: 60,
                rtp_timeout: 90,
                invite_timeout: 5,
            },
            management: ManagementConfig {
                api_enabled: true,
                api_bind_address: "127.0.0.1".parse().unwrap(),
                api_port: 8080,
                api_auth_token: None,
                cors_allowed_origins: Vec::new(),
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
}
