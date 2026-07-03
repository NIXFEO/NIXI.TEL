//! Row DTOs for the dynamic-config SQLite store.
//!
//! These are plain data carriers: `sbc-core` converts them to its runtime
//! types (`TrunkConfig`, `DidMapping`, …) so this crate stays a leaf.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct UserRow {
    pub username: String,
    /// MD5(username:realm:password) — plaintext is never stored.
    pub ha1: String,
    pub realm: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub max_concurrent_calls: Option<i64>,
    pub max_calls_per_minute: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct DidRow {
    pub number: String,
    pub sip_user: String,
    pub display_name: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct TrunkRow {
    pub name: String,
    pub enabled: bool,
    pub host: String,
    pub port: i64,
    pub transport: String,
    pub auth_required: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
    pub register_with_trunk: bool,
    pub registration_interval: i64,
    /// JSON array of strings.
    pub prefix_patterns: String,
    pub priority: i64,
    pub weight: i64,
    pub cost_per_minute: i64,
    pub number_format: String,
    pub country_code: Option<String>,
    pub national_prefix: Option<String>,
    pub caller_number_format: Option<String>,
    pub caller_number_override: Option<String>,
    pub caller_display_name: Option<String>,
    /// JSON array of strings.
    pub allowed_codecs: String,
    pub max_concurrent_calls: i64,
    pub tls_sni: Option<String>,
    pub tls_ca_cert: Option<String>,
    pub tls_verify: bool,
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
}

impl TrunkRow {
    pub fn prefix_patterns_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.prefix_patterns).unwrap_or_default()
    }

    pub fn allowed_codecs_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_codecs).unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct RouteRow {
    /// 0 on insert — assigned by SQLite.
    #[serde(default)]
    pub id: i64,
    pub prefix: String,
    pub trunk_name: String,
    pub priority: i64,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct AclRuleRow {
    pub id: String,
    pub cidr: String,
    /// "allow" | "deny"
    pub action: String,
    /// "inbound" | "outbound" | "both"
    pub direction: String,
    pub priority: i64,
    pub enabled: bool,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow, Serialize, Deserialize)]
pub struct BanRow {
    pub ip: String,
    pub reason: String,
    /// RFC 3339 timestamps.
    pub banned_at: String,
    pub expires_at: String,
    pub failures: i64,
    pub manual: bool,
    pub offense_count: i64,
}
