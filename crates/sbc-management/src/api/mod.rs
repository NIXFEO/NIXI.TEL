//! Management REST API — SQLite-backed users/DIDs CRUD.
//!
//! Endpoints:
//!   GET    /api/v1/users             — list SIP users from the config store
//!   POST   /api/v1/users             — create user (stores HA1, never plaintext)
//!   PUT    /api/v1/users/{username}  — update user (password rotate / enable)
//!   DELETE /api/v1/users/{username}  — remove user
//!   GET    /api/v1/dids              — list DID → SIP-user mappings
//!   POST   /api/v1/dids              — add DID mapping
//!   DELETE /api/v1/dids/{number}     — remove DID mapping
//!   POST   /api/v1/config/reload     — trigger SIGHUP hot-reload
//!
//! Every mutation writes to the SQLite `ConfigStore` first, then re-hydrates
//! the live runtime (digest auth user map, DID routing table) so the change
//! is effective immediately — no restart, no reload round-trip.
//!
//! Auth is handled upstream by the HTTP server (Bearer token check on every
//! request before the router is called), so these handlers do not re-check it.

use async_trait::async_trait;
use sbc_core::api::{ApiResponse, ContentType, ManagementHandler};
use sbc_core::auth::compute_ha1;
use sbc_core::sbc::hydrate::{apply_dids, apply_users, RuntimeHandles};
use sbc_storage::{ConfigStore, DidRow, UserRow};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UserBody {
    username: Option<String>,
    password: Option<String>,
    /// Pre-hashed alternative to password: MD5(username:realm:password).
    ha1: Option<String>,
    display_name: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    max_concurrent_calls: Option<i64>,
    max_calls_per_minute: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DidBody {
    number: Option<String>,
    sip_user: Option<String>,
    display_name: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Management handler — owns the SQLite config store and the live runtime
/// handles used to apply mutations immediately.
pub struct ManagementRouter {
    store: Arc<ConfigStore>,
    realm: String,
    handles: RuntimeHandles,
}

impl ManagementRouter {
    pub fn new(store: Arc<ConfigStore>, realm: impl Into<String>, handles: RuntimeHandles) -> Self {
        Self {
            store,
            realm: realm.into(),
            handles,
        }
    }

    async fn rehydrate_users(&self) {
        if let Some(auth) = &self.handles.auth {
            if let Err(e) = apply_users(auth, &self.store).await {
                warn!("Management API: user hydration failed: {}", e);
            }
        }
    }

    async fn rehydrate_dids(&self) {
        if let Err(e) = apply_dids(&self.handles.dids, &self.store).await {
            warn!("Management API: DID hydration failed: {}", e);
        }
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    async fn list_users(&self) -> ApiResponse {
        match self.store.list_users().await {
            Ok(rows) => {
                let items: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|u| {
                        json!({
                            "username": u.username,
                            "realm": u.realm,
                            "display_name": u.display_name,
                            "enabled": u.enabled,
                            "max_concurrent_calls": u.max_concurrent_calls,
                            "max_calls_per_minute": u.max_calls_per_minute,
                        })
                    })
                    .collect();
                ApiResponse::ok_json(serde_json::Value::Array(items).to_string())
            }
            Err(e) => {
                error!("list_users store error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    fn user_row_from_body(&self, username: String, body: &UserBody) -> Result<UserRow, String> {
        let ha1 = match (&body.password, &body.ha1) {
            (Some(p), _) => compute_ha1(&username, &self.realm, p),
            (None, Some(h)) if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
                h.to_lowercase()
            }
            (None, Some(_)) => return Err("ha1 must be 32 hex chars".to_string()),
            (None, None) => return Err("missing required field: password (or ha1)".to_string()),
        };
        Ok(UserRow {
            username,
            ha1,
            realm: self.realm.clone(),
            display_name: body.display_name.clone(),
            enabled: body.enabled,
            max_concurrent_calls: body.max_concurrent_calls,
            max_calls_per_minute: body.max_calls_per_minute,
        })
    }

    async fn create_user(&self, body: &str) -> ApiResponse {
        let parsed: UserBody = match serde_json::from_str(body) {
            Ok(b) => b,
            Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
        };
        let username = match parsed.username.clone() {
            Some(u) if !u.is_empty() => u,
            _ => return bad_request("missing required field: username"),
        };

        // POST = create only (use PUT to update)
        match self.store.get_user(&username).await {
            Ok(Some(_)) => {
                return ApiResponse {
                    status: 409,
                    content_type: ContentType::Json,
                    body: json!({"error": format!("user '{}' already exists", username)})
                        .to_string(),
                }
            }
            Ok(None) => {}
            Err(e) => return ApiResponse::internal_error(e),
        }

        let row = match self.user_row_from_body(username.clone(), &parsed) {
            Ok(r) => r,
            Err(msg) => return bad_request(&msg),
        };

        match self.store.upsert_user(&row).await {
            Ok(_) => {
                self.rehydrate_users().await;
                info!("Management API: created user '{}'", username);
                ApiResponse {
                    status: 201,
                    content_type: ContentType::Json,
                    body: json!({"username": username, "realm": self.realm, "created": true})
                        .to_string(),
                }
            }
            Err(e) => {
                error!("create_user store error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn update_user(&self, username: &str, body: &str) -> ApiResponse {
        let parsed: UserBody = match serde_json::from_str(body) {
            Ok(b) => b,
            Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
        };

        let existing = match self.store.get_user(username).await {
            Ok(Some(u)) => u,
            Ok(None) => return not_found(&format!("user '{}' not found", username)),
            Err(e) => return ApiResponse::internal_error(e),
        };

        // Password/ha1 optional on update: keep the existing hash if absent.
        let row = if parsed.password.is_none() && parsed.ha1.is_none() {
            UserRow {
                username: username.to_string(),
                ha1: existing.ha1,
                realm: self.realm.clone(),
                display_name: parsed.display_name.clone(),
                enabled: parsed.enabled,
                max_concurrent_calls: parsed.max_concurrent_calls,
                max_calls_per_minute: parsed.max_calls_per_minute,
            }
        } else {
            match self.user_row_from_body(username.to_string(), &parsed) {
                Ok(r) => r,
                Err(msg) => return bad_request(&msg),
            }
        };

        match self.store.upsert_user(&row).await {
            Ok(_) => {
                self.rehydrate_users().await;
                info!("Management API: updated user '{}'", username);
                ApiResponse::ok_json(
                    json!({"username": username, "updated": true, "enabled": row.enabled})
                        .to_string(),
                )
            }
            Err(e) => ApiResponse::internal_error(e),
        }
    }

    async fn delete_user(&self, username: &str) -> ApiResponse {
        match self.store.delete_user(username).await {
            Ok(false) => not_found(&format!("user '{}' not found", username)),
            Ok(true) => {
                self.rehydrate_users().await;
                info!("Management API: deleted user '{}'", username);
                ApiResponse::ok_json(json!({"username": username, "deleted": true}).to_string())
            }
            Err(e) => {
                error!("delete_user store error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    // ── DIDs ──────────────────────────────────────────────────────────────────

    async fn list_dids(&self) -> ApiResponse {
        match self.store.list_dids().await {
            Ok(rows) => {
                let items: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|d| {
                        json!({
                            "number": d.number,
                            "sip_user": d.sip_user,
                            "display_name": d.display_name,
                            "enabled": d.enabled,
                        })
                    })
                    .collect();
                ApiResponse::ok_json(serde_json::Value::Array(items).to_string())
            }
            Err(e) => {
                error!("list_dids store error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn create_did(&self, body: &str) -> ApiResponse {
        let parsed: DidBody = match serde_json::from_str(body) {
            Ok(b) => b,
            Err(e) => return bad_request(&format!("invalid JSON: {}", e)),
        };
        let (number, sip_user) = match (parsed.number.clone(), parsed.sip_user.clone()) {
            (Some(n), Some(u)) if !n.is_empty() && !u.is_empty() => (n, u),
            _ => return bad_request("missing required fields: number, sip_user"),
        };

        match self.store.get_did(&number).await {
            Ok(Some(_)) => {
                return ApiResponse {
                    status: 409,
                    content_type: ContentType::Json,
                    body: json!({"error": format!("DID '{}' already exists", number)}).to_string(),
                }
            }
            Ok(None) => {}
            Err(e) => return ApiResponse::internal_error(e),
        }

        let row = DidRow {
            number: number.clone(),
            sip_user: sip_user.clone(),
            display_name: parsed.display_name.clone(),
            enabled: parsed.enabled,
        };

        match self.store.upsert_did(&row).await {
            Ok(_) => {
                self.rehydrate_dids().await;
                info!("Management API: created DID '{}' → '{}'", number, sip_user);
                ApiResponse {
                    status: 201,
                    content_type: ContentType::Json,
                    body: json!({"number": number, "sip_user": sip_user, "created": true})
                        .to_string(),
                }
            }
            Err(e) => {
                error!("create_did store error: {}", e);
                ApiResponse::internal_error(e)
            }
        }
    }

    async fn delete_did(&self, number: &str) -> ApiResponse {
        match self.store.delete_did(number).await {
            Ok(false) => not_found(&format!("DID '{}' not found", number)),
            Ok(true) => {
                self.rehydrate_dids().await;
                info!("Management API: deleted DID '{}'", number);
                ApiResponse::ok_json(json!({"number": number, "deleted": true}).to_string())
            }
            Err(e) => {
                error!("delete_did store error: {}", e);
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

fn bad_request(msg: &str) -> ApiResponse {
    ApiResponse {
        status: 400,
        content_type: ContentType::Json,
        body: json!({ "error": msg }).to_string(),
    }
}

fn not_found(msg: &str) -> ApiResponse {
    ApiResponse {
        status: 404,
        content_type: ContentType::Json,
        body: json!({ "error": msg }).to_string(),
    }
}

// ── ManagementHandler impl ────────────────────────────────────────────────────

#[async_trait]
impl ManagementHandler for ManagementRouter {
    async fn handle_management(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Option<ApiResponse> {
        match (method, path) {
            ("GET", "/api/v1/users") => Some(self.list_users().await),
            ("POST", "/api/v1/users") => Some(self.create_user(body).await),
            ("GET", "/api/v1/dids") => Some(self.list_dids().await),
            ("POST", "/api/v1/dids") => Some(self.create_did(body).await),
            ("POST", "/api/v1/config/reload") => Some(self.trigger_reload().await),
            _ => {
                if let Some(username) = path.strip_prefix("/api/v1/users/") {
                    if !username.is_empty() {
                        return match method {
                            "DELETE" => Some(self.delete_user(username).await),
                            "PUT" => Some(self.update_user(username, body).await),
                            _ => None,
                        };
                    }
                }
                if let Some(number) = path.strip_prefix("/api/v1/dids/") {
                    if !number.is_empty() && method == "DELETE" {
                        return Some(self.delete_did(number).await);
                    }
                }
                None // not a management route — let core router handle it
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sbc_core::acl::AclManager;
    use sbc_core::auth::DigestAuthenticator;
    use sbc_core::config::DidMapping;
    use sbc_core::routing::TrunkManager;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    async fn router() -> (ManagementRouter, Arc<DigestAuthenticator>) {
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let auth = Arc::new(DigestAuthenticator::new("sip.example.com", HashMap::new()));
        let handles = RuntimeHandles {
            auth: Some(auth.clone()),
            dids: Arc::new(RwLock::new(Vec::<DidMapping>::new())),
            trunks: Arc::new(TrunkManager::new()),
            acl: Arc::new(AclManager::new_permissive()),
        };
        (
            ManagementRouter::new(store, "sip.example.com", handles),
            auth,
        )
    }

    #[tokio::test]
    async fn create_user_applies_to_runtime_immediately() {
        let (router, auth) = router().await;
        let resp = router
            .handle_management(
                "POST",
                "/api/v1/users",
                r#"{"username":"alice","password":"s3cret"}"#,
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
        assert!(auth.user_exists("alice").await, "auth must see the user without reload");

        // Duplicate → 409
        let dup = router
            .handle_management(
                "POST",
                "/api/v1/users",
                r#"{"username":"alice","password":"other"}"#,
            )
            .await
            .unwrap();
        assert_eq!(dup.status, 409);
    }

    #[tokio::test]
    async fn delete_user_removes_from_runtime() {
        let (router, auth) = router().await;
        router
            .handle_management(
                "POST",
                "/api/v1/users",
                r#"{"username":"bob","password":"pw"}"#,
            )
            .await
            .unwrap();
        assert!(auth.user_exists("bob").await);

        let resp = router
            .handle_management("DELETE", "/api/v1/users/bob", "")
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert!(!auth.user_exists("bob").await);

        let missing = router
            .handle_management("DELETE", "/api/v1/users/bob", "")
            .await
            .unwrap();
        assert_eq!(missing.status, 404);
    }

    #[tokio::test]
    async fn update_user_disable_blocks_auth() {
        let (router, auth) = router().await;
        router
            .handle_management(
                "POST",
                "/api/v1/users",
                r#"{"username":"carol","password":"pw"}"#,
            )
            .await
            .unwrap();
        assert!(auth.user_exists("carol").await);

        let resp = router
            .handle_management("PUT", "/api/v1/users/carol", r#"{"enabled":false}"#)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert!(!auth.user_exists("carol").await, "disabled user must leave the auth map");
    }

    #[tokio::test]
    async fn did_crud_applies_to_runtime() {
        let (router, _) = router().await;
        let resp = router
            .handle_management(
                "POST",
                "/api/v1/dids",
                r#"{"number":"+33123456789","sip_user":"alice"}"#,
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(router.handles.dids.read().await.len(), 1);

        let del = router
            .handle_management("DELETE", "/api/v1/dids/+33123456789", "")
            .await
            .unwrap();
        assert_eq!(del.status, 200);
        assert!(router.handles.dids.read().await.is_empty());
    }

    #[tokio::test]
    async fn invalid_bodies_are_400() {
        let (router, _) = router().await;
        for (path, body) in [
            ("/api/v1/users", "not json"),
            ("/api/v1/users", r#"{"username":"x"}"#),
            ("/api/v1/dids", r#"{"number":"+331"}"#),
        ] {
            let resp = router.handle_management("POST", path, body).await.unwrap();
            assert_eq!(resp.status, 400, "path {} body {}", path, body);
        }
    }
}
