//! Phase 5 Management REST API
//!
//! Endpoints:
//!   GET    /api/v1/users             — list SIP users from `auth_users` table
//!   POST   /api/v1/users             — create user (stores HA1 in DB)
//!   DELETE /api/v1/users/{username}  — remove user
//!   GET    /api/v1/dids              — list DID → SIP-user mappings
//!   POST   /api/v1/dids              — add DID mapping
//!   DELETE /api/v1/dids/{number}     — remove DID mapping
//!   POST   /api/v1/config/reload     — trigger SIGHUP hot-reload
//!
//! Auth is handled upstream by the HTTP server (Bearer token check on every
//! request before the router is called), so these handlers do not re-check it.
//!
//! # Required PostgreSQL schema
//! ```sql
//! CREATE TABLE IF NOT EXISTS auth_users (
//!     username   TEXT PRIMARY KEY,
//!     ha1        TEXT        NOT NULL,  -- MD5(username:realm:password)
//!     realm      TEXT        NOT NULL,
//!     created_at TIMESTAMPTZ NOT NULL DEFAULT now()
//! );
//!
//! CREATE TABLE IF NOT EXISTS dids (
//!     number       TEXT PRIMARY KEY,
//!     sip_user     TEXT        NOT NULL,
//!     display_name TEXT,
//!     created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
//! );
//! ```

use async_trait::async_trait;
use sbc_core::api::{ApiResponse, ContentType, ManagementHandler};
use sbc_core::auth::compute_ha1;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};

// ── Router ────────────────────────────────────────────────────────────────────

/// Phase 5 management handler — owns a Postgres connection pool and the SIP
/// realm used to compute HA1 password hashes.
pub struct ManagementRouter {
    pool:  PgPool,
    realm: String,
}

impl ManagementRouter {
    /// Connect to Postgres and return a ready-to-use router.
    ///
    /// Returns `Err` if the initial connection cannot be established.
    pub async fn new(db_url: &str, realm: impl Into<String>) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(db_url).await?;
        info!("Management API: Postgres pool connected");
        Ok(Self { pool, realm: realm.into() })
    }

    /// Create the required tables if they don't exist yet.
    /// Called on startup; failures are logged but not fatal.
    pub async fn ensure_schema(&self) {
        let sql = "
            CREATE TABLE IF NOT EXISTS auth_users (
                username   TEXT PRIMARY KEY,
                ha1        TEXT        NOT NULL,
                realm      TEXT        NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            CREATE TABLE IF NOT EXISTS dids (
                number       TEXT PRIMARY KEY,
                sip_user     TEXT        NOT NULL,
                display_name TEXT,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
            );
        ";
        match sqlx::query(sql).execute(&self.pool).await {
            Ok(_)  => info!("Management API: schema verified"),
            Err(e) => warn!("Management API: schema setup failed ({})", e),
        }
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    async fn list_users(&self) -> ApiResponse {
        let rows: Result<Vec<_>, _> = sqlx::query_as::<_, (String, String)>(
            "SELECT username, realm FROM auth_users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await;

        match rows {
            Ok(rows) => {
                let items: Vec<String> = rows
                    .iter()
                    .map(|(username, realm)| {
                        format!(r#"{{"username":"{username}","realm":"{realm}"}}"#)
                    })
                    .collect();
                ApiResponse::ok_json(format!("[{}]", items.join(",")))
            }
            Err(e) => {
                error!("list_users DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn create_user(&self, body: &str) -> ApiResponse {
        let username = extract_json_string(body, "username");
        let password = extract_json_string(body, "password");

        let (username, password) = match (username, password) {
            (Some(u), Some(p)) => (u, p),
            _ => {
                return ApiResponse {
                    status: 400,
                    content_type: ContentType::Json,
                    body: r#"{"error":"missing required fields: username, password"}"#.to_string(),
                }
            }
        };

        let ha1 = compute_ha1(&username, &self.realm, &password);

        let result = sqlx::query(
            "INSERT INTO auth_users (username, ha1, realm) \
             VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
        )
        .bind(&username)
        .bind(&ha1)
        .bind(&self.realm)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() == 0 => ApiResponse {
                status: 409,
                content_type: ContentType::Json,
                body: format!(r#"{{"error":"user '{}' already exists"}}"#, username),
            },
            Ok(_) => {
                info!("Management API: created user '{}'", username);
                ApiResponse {
                    status: 201,
                    content_type: ContentType::Json,
                    body: format!(
                        r#"{{"username":"{username}","realm":"{}","created":true}}"#,
                        self.realm
                    ),
                }
            }
            Err(e) => {
                error!("create_user DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn delete_user(&self, username: &str) -> ApiResponse {
        let result = sqlx::query("DELETE FROM auth_users WHERE username = $1")
            .bind(username)
            .execute(&self.pool)
            .await;

        match result {
            Ok(r) if r.rows_affected() == 0 => ApiResponse {
                status: 404,
                content_type: ContentType::Json,
                body: format!(r#"{{"error":"user '{}' not found"}}"#, username),
            },
            Ok(_) => {
                info!("Management API: deleted user '{}'", username);
                ApiResponse {
                    status: 200,
                    content_type: ContentType::Json,
                    body: format!(r#"{{"username":"{username}","deleted":true}}"#),
                }
            }
            Err(e) => {
                error!("delete_user DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    // ── DIDs ──────────────────────────────────────────────────────────────────

    async fn list_dids(&self) -> ApiResponse {
        let rows: Result<Vec<_>, _> = sqlx::query_as::<_, (String, String, Option<String>)>(
            "SELECT number, sip_user, display_name FROM dids ORDER BY number",
        )
        .fetch_all(&self.pool)
        .await;

        match rows {
            Ok(rows) => {
                let items: Vec<String> = rows
                    .iter()
                    .map(|(number, sip_user, display_name)| {
                        let dn = display_name
                            .as_deref()
                            .map(|d| format!(r#""{d}""#))
                            .unwrap_or_else(|| "null".to_string());
                        format!(
                            r#"{{"number":"{number}","sip_user":"{sip_user}","display_name":{dn}}}"#
                        )
                    })
                    .collect();
                ApiResponse::ok_json(format!("[{}]", items.join(",")))
            }
            Err(e) => {
                error!("list_dids DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn create_did(&self, body: &str) -> ApiResponse {
        let number       = extract_json_string(body, "number");
        let sip_user     = extract_json_string(body, "sip_user");
        let display_name = extract_json_string(body, "display_name");

        let (number, sip_user) = match (number, sip_user) {
            (Some(n), Some(u)) => (n, u),
            _ => {
                return ApiResponse {
                    status: 400,
                    content_type: ContentType::Json,
                    body: r#"{"error":"missing required fields: number, sip_user"}"#.to_string(),
                }
            }
        };

        let result = sqlx::query(
            "INSERT INTO dids (number, sip_user, display_name) \
             VALUES ($1, $2, $3) ON CONFLICT (number) DO NOTHING",
        )
        .bind(&number)
        .bind(&sip_user)
        .bind(&display_name)
        .execute(&self.pool)
        .await;

        match result {
            Ok(r) if r.rows_affected() == 0 => ApiResponse {
                status: 409,
                content_type: ContentType::Json,
                body: format!(r#"{{"error":"DID '{}' already exists"}}"#, number),
            },
            Ok(_) => {
                info!("Management API: created DID '{}' → '{}'", number, sip_user);
                ApiResponse {
                    status: 201,
                    content_type: ContentType::Json,
                    body: format!(
                        r#"{{"number":"{number}","sip_user":"{sip_user}","created":true}}"#
                    ),
                }
            }
            Err(e) => {
                error!("create_did DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn delete_did(&self, number: &str) -> ApiResponse {
        let result = sqlx::query("DELETE FROM dids WHERE number = $1")
            .bind(number)
            .execute(&self.pool)
            .await;

        match result {
            Ok(r) if r.rows_affected() == 0 => ApiResponse {
                status: 404,
                content_type: ContentType::Json,
                body: format!(r#"{{"error":"DID '{}' not found"}}"#, number),
            },
            Ok(_) => {
                info!("Management API: deleted DID '{}'", number);
                ApiResponse {
                    status: 200,
                    content_type: ContentType::Json,
                    body: format!(r#"{{"number":"{number}","deleted":true}}"#),
                }
            }
            Err(e) => {
                error!("delete_did DB error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    // ── Config reload ─────────────────────────────────────────────────────────

    async fn trigger_reload(&self) -> ApiResponse {
        #[cfg(unix)]
        {
            let pid = std::process::id();
            // SAFETY: kill() is async-signal-safe; we only send SIGHUP to ourselves.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
            info!("Management API: SIGHUP sent to PID {}", pid);
        }
        #[cfg(not(unix))]
        {
            warn!("Management API: config/reload not supported on this platform");
        }
        ApiResponse::ok_json(r#"{"status":"reload_triggered"}"#)
    }
}

// ── ManagementHandler impl ────────────────────────────────────────────────────

#[async_trait]
impl ManagementHandler for ManagementRouter {
    async fn handle_management(
        &self,
        method: &str,
        path:   &str,
        body:   &str,
    ) -> Option<ApiResponse> {
        match (method, path) {
            ("GET",  "/api/v1/users")          => Some(self.list_users().await),
            ("POST", "/api/v1/users")          => Some(self.create_user(body).await),
            ("GET",  "/api/v1/dids")           => Some(self.list_dids().await),
            ("POST", "/api/v1/dids")           => Some(self.create_did(body).await),
            ("POST", "/api/v1/config/reload")  => Some(self.trigger_reload().await),
            _ => {
                if method == "DELETE" {
                    if let Some(username) = path.strip_prefix("/api/v1/users/") {
                        if !username.is_empty() {
                            return Some(self.delete_user(username).await);
                        }
                    }
                    if let Some(number) = path.strip_prefix("/api/v1/dids/") {
                        if !number.is_empty() {
                            return Some(self.delete_did(number).await);
                        }
                    }
                }
                None // not a management route — let core router handle it
            }
        }
    }
}

// ── JSON helper ───────────────────────────────────────────────────────────────

/// Extract a string field from a minimal JSON object (no nested objects).
/// Mirrors the same helper in `sbc-core/src/api.rs`.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_string_basic() {
        let json = r#"{"username":"alice","password":"s3cret"}"#;
        assert_eq!(extract_json_string(json, "username"), Some("alice".into()));
        assert_eq!(extract_json_string(json, "password"), Some("s3cret".into()));
        assert_eq!(extract_json_string(json, "nope"),     None);
    }

    #[test]
    fn test_extract_json_string_missing() {
        let json = r#"{"foo":"bar"}"#;
        assert_eq!(extract_json_string(json, "baz"), None);
    }

    #[test]
    fn test_extract_json_string_did_fields() {
        let json = r#"{"number":"0123456789","sip_user":"alice","display_name":"Alice"}"#;
        assert_eq!(extract_json_string(json, "number"),       Some("0123456789".into()));
        assert_eq!(extract_json_string(json, "sip_user"),     Some("alice".into()));
        assert_eq!(extract_json_string(json, "display_name"), Some("Alice".into()));
    }
}
