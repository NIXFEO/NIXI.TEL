//! `ConfigStore` — SQLite-backed source of truth for dynamic SBC config.
//!
//! Opened once at boot; every REST mutation writes here first, then the
//! runtime is re-hydrated from it. WAL mode, foreign keys on, file 0600.

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use tracing::info;

use crate::models::{AclRuleRow, BanRow, DidRow, RouteRow, TrunkRow, UserRow};
use crate::{Error, Result};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub struct ConfigStore {
    pool: SqlitePool,
}

impl ConfigStore {
    /// Open (creating if missing) the store at `path` and run migrations.
    pub async fn open(path: &str) -> Result<Self> {
        if let Some(dir) = Path::new(path).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| Error::Database(format!("create {}: {}", dir.display(), e)))?;
            }
        }

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path))
            .map_err(|e| Error::Database(e.to_string()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| Error::Database(format!("open {}: {}", path, e)))?;

        // The DB holds trunk passwords — restrict to the service user.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

        let store = Self { pool };
        store.migrate().await?;
        info!("Config store ready at {}", path);
        Ok(store)
    }

    /// In-memory store for tests.
    pub async fn open_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| Error::Database(e.to_string()))?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("migrate: {}", e)))
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // ── users ────────────────────────────────────────────────────────────

    pub async fn list_users(&self) -> Result<Vec<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT username, ha1, realm, display_name, enabled,
                    max_concurrent_calls, max_calls_per_minute
             FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn get_user(&self, username: &str) -> Result<Option<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT username, ha1, realm, display_name, enabled,
                    max_concurrent_calls, max_calls_per_minute
             FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)
    }

    /// Returns `true` if the user was created (vs updated).
    pub async fn upsert_user(&self, row: &UserRow) -> Result<bool> {
        let existing = self.get_user(&row.username).await?;
        sqlx::query(
            "INSERT INTO users (username, ha1, realm, display_name, enabled,
                                max_concurrent_calls, max_calls_per_minute)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(username) DO UPDATE SET
                ha1 = excluded.ha1, realm = excluded.realm,
                display_name = excluded.display_name, enabled = excluded.enabled,
                max_concurrent_calls = excluded.max_concurrent_calls,
                max_calls_per_minute = excluded.max_calls_per_minute,
                updated_at = datetime('now')",
        )
        .bind(&row.username)
        .bind(&row.ha1)
        .bind(&row.realm)
        .bind(&row.display_name)
        .bind(row.enabled)
        .bind(row.max_concurrent_calls)
        .bind(row.max_calls_per_minute)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(existing.is_none())
    }

    pub async fn delete_user(&self, username: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── dids ─────────────────────────────────────────────────────────────

    pub async fn list_dids(&self) -> Result<Vec<DidRow>> {
        sqlx::query_as::<_, DidRow>(
            "SELECT number, sip_user, display_name, enabled FROM dids ORDER BY number",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn get_did(&self, number: &str) -> Result<Option<DidRow>> {
        sqlx::query_as::<_, DidRow>(
            "SELECT number, sip_user, display_name, enabled FROM dids WHERE number = ?",
        )
        .bind(number)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn upsert_did(&self, row: &DidRow) -> Result<bool> {
        let existing = self.get_did(&row.number).await?;
        sqlx::query(
            "INSERT INTO dids (number, sip_user, display_name, enabled)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(number) DO UPDATE SET
                sip_user = excluded.sip_user, display_name = excluded.display_name,
                enabled = excluded.enabled, updated_at = datetime('now')",
        )
        .bind(&row.number)
        .bind(&row.sip_user)
        .bind(&row.display_name)
        .bind(row.enabled)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(existing.is_none())
    }

    pub async fn delete_did(&self, number: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM dids WHERE number = ?")
            .bind(number)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── trunks ───────────────────────────────────────────────────────────

    pub async fn list_trunks(&self) -> Result<Vec<TrunkRow>> {
        sqlx::query_as::<_, TrunkRow>(&format!(
            "SELECT {} FROM trunks ORDER BY name",
            TRUNK_COLS
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn get_trunk(&self, name: &str) -> Result<Option<TrunkRow>> {
        sqlx::query_as::<_, TrunkRow>(&format!(
            "SELECT {} FROM trunks WHERE name = ?",
            TRUNK_COLS
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn upsert_trunk(&self, row: &TrunkRow) -> Result<bool> {
        let existing = self.get_trunk(&row.name).await?;
        sqlx::query(
            "INSERT INTO trunks (name, enabled, host, port, transport, auth_required,
                username, password, realm, register_with_trunk, registration_interval,
                prefix_patterns, priority, weight, cost_per_minute, number_format,
                country_code, national_prefix, caller_number_format,
                caller_number_override, caller_display_name, allowed_codecs,
                max_concurrent_calls, tls_sni, tls_ca_cert, tls_verify,
                tls_client_cert, tls_client_key)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET
                enabled = excluded.enabled, host = excluded.host, port = excluded.port,
                transport = excluded.transport, auth_required = excluded.auth_required,
                username = excluded.username, password = excluded.password,
                realm = excluded.realm, register_with_trunk = excluded.register_with_trunk,
                registration_interval = excluded.registration_interval,
                prefix_patterns = excluded.prefix_patterns, priority = excluded.priority,
                weight = excluded.weight, cost_per_minute = excluded.cost_per_minute,
                number_format = excluded.number_format, country_code = excluded.country_code,
                national_prefix = excluded.national_prefix,
                caller_number_format = excluded.caller_number_format,
                caller_number_override = excluded.caller_number_override,
                caller_display_name = excluded.caller_display_name,
                allowed_codecs = excluded.allowed_codecs,
                max_concurrent_calls = excluded.max_concurrent_calls,
                tls_sni = excluded.tls_sni, tls_ca_cert = excluded.tls_ca_cert,
                tls_verify = excluded.tls_verify, tls_client_cert = excluded.tls_client_cert,
                tls_client_key = excluded.tls_client_key,
                updated_at = datetime('now')",
        )
        .bind(&row.name)
        .bind(row.enabled)
        .bind(&row.host)
        .bind(row.port)
        .bind(&row.transport)
        .bind(row.auth_required)
        .bind(&row.username)
        .bind(&row.password)
        .bind(&row.realm)
        .bind(row.register_with_trunk)
        .bind(row.registration_interval)
        .bind(&row.prefix_patterns)
        .bind(row.priority)
        .bind(row.weight)
        .bind(row.cost_per_minute)
        .bind(&row.number_format)
        .bind(&row.country_code)
        .bind(&row.national_prefix)
        .bind(&row.caller_number_format)
        .bind(&row.caller_number_override)
        .bind(&row.caller_display_name)
        .bind(&row.allowed_codecs)
        .bind(row.max_concurrent_calls)
        .bind(&row.tls_sni)
        .bind(&row.tls_ca_cert)
        .bind(row.tls_verify)
        .bind(&row.tls_client_cert)
        .bind(&row.tls_client_key)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(existing.is_none())
    }

    pub async fn delete_trunk(&self, name: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM trunks WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── routes ───────────────────────────────────────────────────────────

    pub async fn list_routes(&self) -> Result<Vec<RouteRow>> {
        sqlx::query_as::<_, RouteRow>(
            "SELECT id, prefix, trunk_name, priority, enabled, description
             FROM routes ORDER BY priority, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn get_route(&self, id: i64) -> Result<Option<RouteRow>> {
        sqlx::query_as::<_, RouteRow>(
            "SELECT id, prefix, trunk_name, priority, enabled, description
             FROM routes WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)
    }

    /// Insert a route; returns the assigned id.
    pub async fn insert_route(&self, row: &RouteRow) -> Result<i64> {
        let res = sqlx::query(
            "INSERT INTO routes (prefix, trunk_name, priority, enabled, description)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&row.prefix)
        .bind(&row.trunk_name)
        .bind(row.priority)
        .bind(row.enabled)
        .bind(&row.description)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.last_insert_rowid())
    }

    pub async fn update_route(&self, row: &RouteRow) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE routes SET prefix = ?, trunk_name = ?, priority = ?,
                enabled = ?, description = ? WHERE id = ?",
        )
        .bind(&row.prefix)
        .bind(&row.trunk_name)
        .bind(row.priority)
        .bind(row.enabled)
        .bind(&row.description)
        .bind(row.id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn delete_route(&self, id: i64) -> Result<bool> {
        let res = sqlx::query("DELETE FROM routes WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── acl rules ────────────────────────────────────────────────────────

    pub async fn list_acl_rules(&self) -> Result<Vec<AclRuleRow>> {
        sqlx::query_as::<_, AclRuleRow>(
            "SELECT id, cidr, action, direction, priority, enabled, comment
             FROM acl_rules ORDER BY priority, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    pub async fn upsert_acl_rule(&self, row: &AclRuleRow) -> Result<bool> {
        let existing = sqlx::query("SELECT id FROM acl_rules WHERE id = ?")
            .bind(&row.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        sqlx::query(
            "INSERT INTO acl_rules (id, cidr, action, direction, priority, enabled, comment)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                cidr = excluded.cidr, action = excluded.action,
                direction = excluded.direction, priority = excluded.priority,
                enabled = excluded.enabled, comment = excluded.comment",
        )
        .bind(&row.id)
        .bind(&row.cidr)
        .bind(&row.action)
        .bind(&row.direction)
        .bind(row.priority)
        .bind(row.enabled)
        .bind(&row.comment)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(existing.is_none())
    }

    pub async fn delete_acl_rule(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM acl_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── bans ─────────────────────────────────────────────────────────────

    pub async fn save_ban(&self, row: &BanRow) -> Result<()> {
        sqlx::query(
            "INSERT INTO bans (ip, reason, banned_at, expires_at, failures, manual, offense_count)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(ip) DO UPDATE SET
                reason = excluded.reason, banned_at = excluded.banned_at,
                expires_at = excluded.expires_at, failures = excluded.failures,
                manual = excluded.manual, offense_count = excluded.offense_count",
        )
        .bind(&row.ip)
        .bind(&row.reason)
        .bind(&row.banned_at)
        .bind(&row.expires_at)
        .bind(row.failures)
        .bind(row.manual)
        .bind(row.offense_count)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    pub async fn delete_ban(&self, ip: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM bans WHERE ip = ?")
            .bind(ip)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    /// Bans whose expiry is still in the future (RFC 3339 comparison).
    pub async fn load_active_bans(&self, now_rfc3339: &str) -> Result<Vec<BanRow>> {
        sqlx::query_as::<_, BanRow>(
            "SELECT ip, reason, banned_at, expires_at, failures, manual, offense_count
             FROM bans WHERE expires_at > ?",
        )
        .bind(now_rfc3339)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    // ── settings / misc ──────────────────────────────────────────────────

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM settings WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    pub async fn table_is_empty(&self, table: Table) -> Result<bool> {
        let sql = match table {
            Table::Users => "SELECT COUNT(*) FROM users",
            Table::Dids => "SELECT COUNT(*) FROM dids",
            Table::Trunks => "SELECT COUNT(*) FROM trunks",
            Table::Routes => "SELECT COUNT(*) FROM routes",
            Table::AclRules => "SELECT COUNT(*) FROM acl_rules",
        };
        let (count,): (i64,) = sqlx::query_as(sql)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(count == 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Users,
    Dids,
    Trunks,
    Routes,
    AclRules,
}

const TRUNK_COLS: &str = "name, enabled, host, port, transport, auth_required, username, \
    password, realm, register_with_trunk, registration_interval, prefix_patterns, priority, \
    weight, cost_per_minute, number_format, country_code, national_prefix, \
    caller_number_format, caller_number_override, caller_display_name, allowed_codecs, \
    max_concurrent_calls, tls_sni, tls_ca_cert, tls_verify, tls_client_cert, tls_client_key";

fn db_err(e: sqlx::Error) -> Error {
    Error::Database(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> UserRow {
        UserRow {
            username: name.to_string(),
            ha1: "0123456789abcdef0123456789abcdef".to_string(),
            realm: "sip.example.com".to_string(),
            display_name: None,
            enabled: true,
            max_concurrent_calls: None,
            max_calls_per_minute: None,
        }
    }

    fn trunk(name: &str) -> TrunkRow {
        TrunkRow {
            name: name.to_string(),
            enabled: true,
            host: "trunk.example.com".to_string(),
            port: 5060,
            transport: "UDP".to_string(),
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            register_with_trunk: false,
            registration_interval: 300,
            prefix_patterns: r#"["+33","0"]"#.to_string(),
            priority: 100,
            weight: 100,
            cost_per_minute: 0,
            number_format: "e164".to_string(),
            country_code: Some("33".to_string()),
            national_prefix: Some("0".to_string()),
            caller_number_format: None,
            caller_number_override: None,
            caller_display_name: None,
            allowed_codecs: r#"["PCMU","PCMA"]"#.to_string(),
            max_concurrent_calls: 100,
            tls_sni: None,
            tls_ca_cert: None,
            tls_verify: true,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    #[tokio::test]
    async fn user_crud_roundtrip() {
        let store = ConfigStore::open_memory().await.unwrap();
        assert!(store.table_is_empty(Table::Users).await.unwrap());

        assert!(store.upsert_user(&user("alice")).await.unwrap());
        assert!(!store.upsert_user(&user("alice")).await.unwrap()); // update, not create
        assert!(!store.table_is_empty(Table::Users).await.unwrap());

        let got = store.get_user("alice").await.unwrap().unwrap();
        assert_eq!(got.realm, "sip.example.com");

        let all = store.list_users().await.unwrap();
        assert_eq!(all.len(), 1);

        assert!(store.delete_user("alice").await.unwrap());
        assert!(!store.delete_user("alice").await.unwrap());
    }

    #[tokio::test]
    async fn did_crud_roundtrip() {
        let store = ConfigStore::open_memory().await.unwrap();
        let did = DidRow {
            number: "+33123456789".to_string(),
            sip_user: "alice".to_string(),
            display_name: Some("Alice".to_string()),
            enabled: true,
        };
        assert!(store.upsert_did(&did).await.unwrap());
        let got = store.get_did("+33123456789").await.unwrap().unwrap();
        assert_eq!(got, did);
        assert!(store.delete_did("+33123456789").await.unwrap());
    }

    #[tokio::test]
    async fn trunk_crud_and_json_fields() {
        let store = ConfigStore::open_memory().await.unwrap();
        assert!(store.upsert_trunk(&trunk("pstn-1")).await.unwrap());

        let got = store.get_trunk("pstn-1").await.unwrap().unwrap();
        assert_eq!(got.prefix_patterns_vec(), vec!["+33", "0"]);
        assert_eq!(got.allowed_codecs_vec(), vec!["PCMU", "PCMA"]);
        assert_eq!(got, trunk("pstn-1"));

        let mut updated = trunk("pstn-1");
        updated.port = 5080;
        assert!(!store.upsert_trunk(&updated).await.unwrap());
        assert_eq!(store.get_trunk("pstn-1").await.unwrap().unwrap().port, 5080);

        assert!(store.delete_trunk("pstn-1").await.unwrap());
    }

    #[tokio::test]
    async fn route_crud_and_cascade() {
        let store = ConfigStore::open_memory().await.unwrap();
        store.upsert_trunk(&trunk("pstn-1")).await.unwrap();

        let id = store
            .insert_route(&RouteRow {
                id: 0,
                prefix: "+33".to_string(),
                trunk_name: "pstn-1".to_string(),
                priority: 10,
                enabled: true,
                description: None,
            })
            .await
            .unwrap();
        assert!(id > 0);

        // Unique (prefix, trunk_name)
        assert!(store
            .insert_route(&RouteRow {
                id: 0,
                prefix: "+33".to_string(),
                trunk_name: "pstn-1".to_string(),
                priority: 20,
                enabled: true,
                description: None,
            })
            .await
            .is_err());

        // Deleting the trunk cascades to its routes
        store.delete_trunk("pstn-1").await.unwrap();
        assert!(store.list_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn acl_rules_crud() {
        let store = ConfigStore::open_memory().await.unwrap();
        let rule = AclRuleRow {
            id: "r1".to_string(),
            cidr: "203.0.113.0/24".to_string(),
            action: "deny".to_string(),
            direction: "both".to_string(),
            priority: 100,
            enabled: true,
            comment: None,
        };
        assert!(store.upsert_acl_rule(&rule).await.unwrap());
        assert_eq!(store.list_acl_rules().await.unwrap().len(), 1);
        assert!(store.delete_acl_rule("r1").await.unwrap());
    }

    #[tokio::test]
    async fn ban_persistence_roundtrip() {
        let store = ConfigStore::open_memory().await.unwrap();
        let ban = BanRow {
            ip: "198.51.100.7".to_string(),
            reason: "auth failures".to_string(),
            banned_at: "2026-07-03T00:00:00Z".to_string(),
            expires_at: "2026-07-03T01:00:00Z".to_string(),
            failures: 5,
            manual: false,
            offense_count: 1,
        };
        store.save_ban(&ban).await.unwrap();

        let active = store.load_active_bans("2026-07-03T00:30:00Z").await.unwrap();
        assert_eq!(active.len(), 1);
        let expired = store.load_active_bans("2026-07-03T02:00:00Z").await.unwrap();
        assert!(expired.is_empty());

        assert!(store.delete_ban("198.51.100.7").await.unwrap());
    }

    #[tokio::test]
    async fn settings_roundtrip() {
        let store = ConfigStore::open_memory().await.unwrap();
        assert!(store.get_setting("k").await.unwrap().is_none());
        store.set_setting("k", "v1").await.unwrap();
        store.set_setting("k", "v2").await.unwrap();
        assert_eq!(store.get_setting("k").await.unwrap().unwrap(), "v2");
    }
}
