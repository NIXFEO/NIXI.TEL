//! `ConfigStore` — SQLite-backed source of truth for dynamic SBC config.
//!
//! Opened once at boot; every REST mutation writes here first, then the
//! runtime is re-hydrated from it. WAL mode, foreign keys on, file 0600.

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{SqliteConnection, SqlitePool};
use tracing::info;

use crate::models::{
    AclRuleRow, BackupInfo, BanRow, DestinationRuleRow, DidRow, RouteRow, TrunkRow, UserRow,
};
use crate::{Error, Result};

/// Embedded migrations. `ignore_missing` lets an older binary (rolled back
/// after an upgrade) open a store that already carries newer migrations
/// instead of refusing with VersionMissing and running TOML-only.
fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!("./migrations");
    m.set_ignore_missing(true);
    m
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    pub(crate) pool: SqlitePool,
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
        migrator()
            .run(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("migrate: {}", e)))
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// One pooled connection for the `*_on` variants below. The pool-based
    /// wrappers acquire it once, so they also work on a one-connection
    /// pool (`open_memory`).
    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>> {
        self.pool.acquire().await.map_err(db_err)
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
        let mut conn = self.conn().await?;
        Self::upsert_user_on(&mut conn, row).await
    }

    /// `upsert_user` on a caller-held connection (an open transaction's).
    /// Returns `true` when the row was inserted, `false` when updated.
    pub async fn upsert_user_on(conn: &mut SqliteConnection, row: &UserRow) -> Result<bool> {
        let existing = exists(
            conn,
            "SELECT 1 FROM users WHERE username = ?",
            &row.username,
        )
        .await?;
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
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(!existing)
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
        let mut conn = self.conn().await?;
        Self::upsert_did_on(&mut conn, row).await
    }

    /// `upsert_did` on a caller-held connection; `true` when inserted.
    pub async fn upsert_did_on(conn: &mut SqliteConnection, row: &DidRow) -> Result<bool> {
        let existing = exists(conn, "SELECT 1 FROM dids WHERE number = ?", &row.number).await?;
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
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(!existing)
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
        sqlx::query_as::<_, TrunkRow>(&format!("SELECT {} FROM trunks ORDER BY name", TRUNK_COLS))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)
    }

    pub async fn get_trunk(&self, name: &str) -> Result<Option<TrunkRow>> {
        sqlx::query_as::<_, TrunkRow>(&format!("SELECT {} FROM trunks WHERE name = ?", TRUNK_COLS))
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)
    }

    pub async fn upsert_trunk(&self, row: &TrunkRow) -> Result<bool> {
        let mut conn = self.conn().await?;
        Self::upsert_trunk_on(&mut conn, row).await
    }

    /// `upsert_trunk` on a caller-held connection; `true` when inserted.
    pub async fn upsert_trunk_on(conn: &mut SqliteConnection, row: &TrunkRow) -> Result<bool> {
        let existing = exists(conn, "SELECT 1 FROM trunks WHERE name = ?", &row.name).await?;
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
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(!existing)
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

    /// Insert or update the route identified by (`prefix`, `trunk_name`)
    /// — the natural key the `UNIQUE(prefix, trunk_name)` constraint
    /// enforces; `row.id` is ignored. `true` when inserted.
    pub async fn upsert_route_on(conn: &mut SqliteConnection, row: &RouteRow) -> Result<bool> {
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM routes WHERE prefix = ? AND trunk_name = ?")
                .bind(&row.prefix)
                .bind(&row.trunk_name)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db_err)?;
        sqlx::query(
            "INSERT INTO routes (prefix, trunk_name, priority, enabled, description)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(prefix, trunk_name) DO UPDATE SET
                priority = excluded.priority, enabled = excluded.enabled,
                description = excluded.description",
        )
        .bind(&row.prefix)
        .bind(&row.trunk_name)
        .bind(row.priority)
        .bind(row.enabled)
        .bind(&row.description)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(existing.is_none())
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
        let mut conn = self.conn().await?;
        Self::upsert_acl_rule_on(&mut conn, row).await
    }

    /// `upsert_acl_rule` on a caller-held connection; `true` when inserted.
    pub async fn upsert_acl_rule_on(conn: &mut SqliteConnection, row: &AclRuleRow) -> Result<bool> {
        let existing = exists(conn, "SELECT 1 FROM acl_rules WHERE id = ?", &row.id).await?;
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
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(!existing)
    }

    pub async fn delete_acl_rule(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM acl_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── destination rules (anti-IRSF) ─────────────────────────────────────

    pub async fn list_destination_rules(&self) -> Result<Vec<DestinationRuleRow>> {
        sqlx::query_as::<_, DestinationRuleRow>(
            "SELECT id, prefix, action, user, description, enabled
             FROM destination_rules ORDER BY user, prefix, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    /// Insert a rule only if its id is free; false (nothing written) when
    /// it exists — the API's create, which must not overwrite.
    pub async fn insert_destination_rule(&self, row: &DestinationRuleRow) -> Result<bool> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO destination_rules (id, prefix, action, user, description, enabled)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.prefix)
        .bind(&row.action)
        .bind(&row.user)
        .bind(&row.description)
        .bind(row.enabled)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    /// Insert or replace a rule (seeding, import); true when it did not
    /// exist yet.
    pub async fn upsert_destination_rule(&self, row: &DestinationRuleRow) -> Result<bool> {
        let mut conn = self.conn().await?;
        Self::upsert_destination_rule_on(&mut conn, row).await
    }

    /// `upsert_destination_rule` on a caller-held connection; `true` when
    /// inserted.
    pub async fn upsert_destination_rule_on(
        conn: &mut SqliteConnection,
        row: &DestinationRuleRow,
    ) -> Result<bool> {
        let existing = exists(
            conn,
            "SELECT 1 FROM destination_rules WHERE id = ?",
            &row.id,
        )
        .await?;
        sqlx::query(
            "INSERT INTO destination_rules (id, prefix, action, user, description, enabled)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                prefix = excluded.prefix, action = excluded.action, user = excluded.user,
                description = excluded.description, enabled = excluded.enabled",
        )
        .bind(&row.id)
        .bind(&row.prefix)
        .bind(&row.action)
        .bind(&row.user)
        .bind(&row.description)
        .bind(row.enabled)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(!existing)
    }

    pub async fn delete_destination_rule(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM destination_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    // ── per-user limits (columns of `users`) ──────────────────────────────

    /// Set (or clear, with None) a user's limit overrides. False when the
    /// user does not exist.
    pub async fn set_user_limits(
        &self,
        username: &str,
        max_concurrent_calls: Option<i64>,
        max_calls_per_minute: Option<i64>,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE users SET max_concurrent_calls = ?, max_calls_per_minute = ?,
                              updated_at = datetime('now')
             WHERE username = ?",
        )
        .bind(max_concurrent_calls)
        .bind(max_calls_per_minute)
        .bind(username)
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
        let mut conn = self.conn().await?;
        Self::get_setting_on(&mut conn, key).await
    }

    pub async fn get_setting_on(conn: &mut SqliteConnection, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_err)?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        Self::set_setting_on(&mut conn, key, value).await
    }

    pub async fn set_setting_on(conn: &mut SqliteConnection, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Remove a setting; `true` when it existed.
    pub async fn delete_setting(&self, key: &str) -> Result<bool> {
        let mut conn = self.conn().await?;
        Self::delete_setting_on(&mut conn, key).await
    }

    pub async fn delete_setting_on(conn: &mut SqliteConnection, key: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM settings WHERE key = ?")
            .bind(key)
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn table_is_empty(&self, table: Table) -> Result<bool> {
        let sql = match table {
            Table::Users => "SELECT COUNT(*) FROM users",
            Table::Dids => "SELECT COUNT(*) FROM dids",
            Table::Trunks => "SELECT COUNT(*) FROM trunks",
            Table::Routes => "SELECT COUNT(*) FROM routes",
            Table::AclRules => "SELECT COUNT(*) FROM acl_rules",
            Table::DestinationRules => "SELECT COUNT(*) FROM destination_rules",
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
    DestinationRules,
}

const TRUNK_COLS: &str = "name, enabled, host, port, transport, auth_required, username, \
    password, realm, register_with_trunk, registration_interval, prefix_patterns, priority, \
    weight, cost_per_minute, number_format, country_code, national_prefix, \
    caller_number_format, caller_number_override, caller_display_name, allowed_codecs, \
    max_concurrent_calls, tls_sni, tls_ca_cert, tls_verify, tls_client_cert, tls_client_key";

// ── Backups ──────────────────────────────────────────────────────────────────

/// `sbc-YYYYmmdd-HHMMSS[-n].db` → (timestamp, n), None for any other name.
fn backup_name_key(name: &str) -> Option<(String, u32)> {
    let rest = name.strip_prefix("sbc-")?.strip_suffix(".db")?;
    let (stamp, suffix) = match rest.split_at_checked(15) {
        Some((stamp, suffix)) => (stamp, suffix),
        None => return None,
    };
    let ok = stamp.len() == 15
        && stamp[..8].bytes().all(|b| b.is_ascii_digit())
        && &stamp[8..9] == "-"
        && stamp[9..].bytes().all(|b| b.is_ascii_digit());
    if !ok {
        return None;
    }
    let n = match suffix {
        "" => 0,
        s => s.strip_prefix('-')?.parse::<u32>().ok()?,
    };
    Some((stamp.to_string(), n))
}

impl ConfigStore {
    /// Write a consistent copy of the store into `dir` as
    /// `sbc-<YYYYmmdd-HHMMSS>.db` (`VACUUM INTO` on a temporary name,
    /// fsync, then rename). The directory is created 0700 when missing
    /// (an existing directory's mode is left alone), the file is 0600: it
    /// holds trunk passwords and user HA1s.
    pub async fn backup_to(&self, dir: &Path) -> Result<BackupInfo> {
        let started = std::time::Instant::now();
        let io = |what: &str, e: std::io::Error| Error::Database(format!("backup {}: {}", what, e));
        if tokio::fs::metadata(dir).await.is_err() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| io("create dir", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await;
            }
        }
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let mut final_path = dir.join(format!("sbc-{}.db", stamp));
        let mut n = 0;
        while tokio::fs::metadata(&final_path).await.is_ok() {
            n += 1;
            final_path = dir.join(format!("sbc-{}-{}.db", stamp, n));
        }
        let tmp = final_path.with_extension("db.tmp");
        let _ = tokio::fs::remove_file(&tmp).await; // VACUUM INTO refuses a non-empty target
        let target = tmp.to_string_lossy().into_owned();
        sqlx::query("VACUUM INTO ?1")
            .bind(&target)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(format!("backup into {}: {}", target, e)))?;
        let file = tokio::fs::File::open(&tmp)
            .await
            .map_err(|e| io("open copy", e))?;
        file.sync_all().await.map_err(|e| io("fsync", e))?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| io("chmod", e))?;
        }
        tokio::fs::rename(&tmp, &final_path)
            .await
            .map_err(|e| io("rename", e))?;
        let bytes = tokio::fs::metadata(&final_path)
            .await
            .map_err(|e| io("stat", e))?
            .len();
        Ok(BackupInfo {
            path: final_path,
            bytes,
            took_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// Delete the backups beyond the `keep` newest (`keep` 0 = keep all) and
/// any `.tmp` older than an hour (an interrupted `VACUUM INTO`). Returns
/// the removed paths. Runs on the blocking pool.
pub async fn prune_backups(dir: &Path, keep: usize) -> Result<Vec<std::path::PathBuf>> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<Vec<std::path::PathBuf>> {
        let mut removed = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
            Err(e) => return Err(Error::Database(format!("prune backups: {}", e))),
        };
        let mut backups: Vec<((String, u32), std::path::PathBuf)> = Vec::new();
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(key) = backup_name_key(name) {
                backups.push((key, path));
            } else if name.starts_with("sbc-") && name.ends_with(".db.tmp") {
                let stale = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .map(|m| m < hour_ago)
                    .unwrap_or(false);
                if stale && std::fs::remove_file(&path).is_ok() {
                    removed.push(path);
                }
            }
        }
        if keep > 0 {
            backups.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
            for (_, path) in backups.into_iter().skip(keep) {
                if std::fs::remove_file(&path).is_ok() {
                    removed.push(path);
                }
            }
        }
        Ok(removed)
    })
    .await
    .map_err(|e| Error::Database(format!("prune backups: {}", e)))?
}

/// The newest backup in `dir` by name, with its modification time.
pub fn newest_backup(dir: &Path) -> Option<(std::path::PathBuf, std::time::SystemTime)> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let key = backup_name_key(path.file_name()?.to_str()?)?;
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((key, path, mtime))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, path, mtime)| (path, mtime))
}

/// Map a driver error, telling schema-constraint violations (the caller's
/// data) apart from everything else (the database).
pub(crate) fn db_err(e: sqlx::Error) -> Error {
    if let sqlx::Error::Database(db) = &e {
        use sqlx::error::ErrorKind;
        if matches!(
            db.kind(),
            ErrorKind::UniqueViolation
                | ErrorKind::ForeignKeyViolation
                | ErrorKind::NotNullViolation
                | ErrorKind::CheckViolation
        ) {
            return Error::Constraint {
                table: String::new(),
                key: String::new(),
                detail: db.message().to_string(),
            };
        }
    }
    Error::Database(e.to_string())
}

/// `true` when `sql` (one `?` bound to `key`) returns a row.
async fn exists(conn: &mut SqliteConnection, sql: &str, key: &str) -> Result<bool> {
    let row: Option<(i64,)> = sqlx::query_as(sql)
        .bind(key)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(row.is_some())
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

        let active = store
            .load_active_bans("2026-07-03T00:30:00Z")
            .await
            .unwrap();
        assert_eq!(active.len(), 1);
        let expired = store
            .load_active_bans("2026-07-03T02:00:00Z")
            .await
            .unwrap();
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

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sbc-store-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn backup_names_are_recognised_and_ordered() {
        assert_eq!(
            backup_name_key("sbc-20260918-101500.db"),
            Some(("20260918-101500".into(), 0))
        );
        assert_eq!(
            backup_name_key("sbc-20260918-101500-2.db"),
            Some(("20260918-101500".into(), 2))
        );
        assert_eq!(
            backup_name_key("sbc-db-20260918-101500.db"),
            None,
            "deploy.sh copies"
        );
        assert_eq!(backup_name_key("sbc-20260918-101500.db.tmp"), None);
        assert_eq!(backup_name_key("sbc-2026091-101500.db"), None);
        assert!(
            backup_name_key("sbc-20260918-101500-1.db") > backup_name_key("sbc-20260918-101500.db")
        );
    }

    #[tokio::test]
    async fn backup_to_writes_a_consistent_copy_and_prune_keeps_the_newest() {
        let dir = temp_dir("backup");
        let store = ConfigStore::open(dir.join("live.db").to_str().unwrap())
            .await
            .unwrap();
        store
            .upsert_user(&UserRow {
                username: "alice".into(),
                ha1: "a".repeat(32),
                realm: "r".into(),
                display_name: None,
                enabled: true,
                max_concurrent_calls: None,
                max_calls_per_minute: None,
            })
            .await
            .unwrap();
        let backups = dir.join("backups");
        let first = store.backup_to(&backups).await.unwrap();
        assert!(first.bytes > 0);
        assert!(backup_name_key(first.path.file_name().unwrap().to_str().unwrap()).is_some());
        assert!(!backups
            .join(first.path.file_name().unwrap())
            .with_extension("db.tmp")
            .exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let copy = ConfigStore::open(first.path.to_str().unwrap())
            .await
            .unwrap();
        assert!(
            copy.get_user("alice").await.unwrap().is_some(),
            "the copy is a usable store"
        );

        // Same second: a suffix, no collision.
        let second = store.backup_to(&backups).await.unwrap();
        let third = store.backup_to(&backups).await.unwrap();
        assert_ne!(first.path, second.path);
        assert_ne!(second.path, third.path);
        let (path, _) = newest_backup(&backups).unwrap();
        assert_eq!(path, third.path, "newest by (timestamp, suffix)");

        // A stale tmp from an interrupted VACUUM, and prune to 2.
        let stale = backups.join("sbc-20200101-000000.db.tmp");
        std::fs::write(&stale, b"x").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        std::fs::File::open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let removed = prune_backups(&backups, 2).await.unwrap();
        assert!(removed.contains(&first.path), "{:?}", removed);
        assert!(removed.contains(&stale));
        assert!(second.path.exists() && third.path.exists());
        assert!(
            prune_backups(&backups, 0).await.unwrap().is_empty(),
            "keep 0 = keep all"
        );
        assert!(prune_backups(&dir.join("absent"), 2)
            .await
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
