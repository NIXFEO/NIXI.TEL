//! Row DTOs for the dynamic-config SQLite store.
//!
//! These are plain data carriers: `sbc-core` converts them to its runtime
//! types (`TrunkConfig`, `DidMapping`, …) so this crate stays a leaf.

use serde::{Deserialize, Serialize};

/// Keys of the `settings` table shared by the SBC core, the API and the
/// import, so every crate spells them the same way.
pub mod keys {
    /// `allow` | `deny` — the ACL default when no rule matches.
    pub const ACL_DEFAULT_ACTION: &str = "acl_default_action";
    /// API-set global per-user limits (decimal strings, both or neither).
    pub const USER_LIMITS_DEFAULT_CONCURRENT: &str = "user_limits.default_max_concurrent_calls";
    pub const USER_LIMITS_DEFAULT_CPM: &str = "user_limits.default_max_calls_per_minute";
    /// First-boot seed markers (RFC 3339). Once set, the store is the truth
    /// for that section and the TOML seeds are never applied again.
    pub const DESTINATION_RULES_SEEDED_AT: &str = "destination_rules_seeded_at";
    pub const USER_LIMITS_SEEDED_AT: &str = "user_limits_seeded_at";
}

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

/// Anti-IRSF destination rule (`destination_rules`, migration 0002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct DestinationRuleRow {
    pub id: String,
    pub prefix: String,
    /// "allow" | "deny"
    pub action: String,
    /// Restrict the rule to one user (NULL = everyone).
    pub user: Option<String>,
    pub description: String,
    pub enabled: bool,
}

/// One store backup written by `ConfigStore::backup_to` (`VACUUM INTO`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupInfo {
    pub path: std::path::PathBuf,
    pub bytes: u64,
    pub took_ms: u64,
}

/// One row of `cdrs` (migration 0003): the CDR v2 record as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct CdrRow {
    /// SQLite rowid (0 on insert; part of the paging cursor).
    #[serde(default)]
    pub rowid: i64,
    pub id: String,
    pub v: i64,
    pub uuid: String,
    pub call_id: String,
    pub direction: String,
    pub caller: String,
    pub callee: String,
    pub source_ip: String,
    pub trunk_id: Option<String>,
    pub codec: Option<String>,
    pub is_webrtc: bool,
    pub started_at: i64,
    pub answered_at: Option<i64>,
    pub ended_at: i64,
    pub duration_secs: i64,
    pub billable_secs: i64,
    pub sip_code: Option<i64>,
    pub disconnect_reason: String,
    pub reason: Option<String>,
    pub hangup_by: String,
}

/// `GET /api/v1/cdrs` filters; every field optional. Prefixes are
/// case-sensitive ranges on the indexed columns.
#[derive(Debug, Clone, Default)]
pub struct CdrFilter {
    /// `started_at >=`
    pub from: Option<i64>,
    /// `started_at <`
    pub to: Option<i64>,
    pub direction: Option<String>,
    pub trunk: Option<String>,
    pub caller_prefix: Option<String>,
    pub callee_prefix: Option<String>,
    pub sip_code: Option<i64>,
    pub answered: Option<bool>,
    pub uuid: Option<String>,
    pub call_id: Option<String>,
    /// Keyset cursor: rows strictly older than (started_at, rowid).
    pub before: Option<(i64, i64)>,
    pub offset: usize,
    pub limit: usize,
}
