//! Users, DIDs and export — SQLite-backed, applied to the runtime immediately.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sbc_core::auth::compute_ha1;
use sbc_core::events::{event_ts, SbcEvent};
use sbc_core::sbc::hydrate::{apply_dids, apply_users};
use sbc_storage::{ConfigStore, DidRow, UserRow};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::{ApiError, ApiResult};
use crate::state::AppState;

fn store(state: &AppState) -> ApiResult<Arc<ConfigStore>> {
    state.store.clone().ok_or_else(ApiError::store_unavailable)
}

fn config_changed(state: &AppState, entity: &str, action: &str, id: &str) {
    state.events.publish(SbcEvent::ConfigChanged {
        entity: entity.to_string(),
        action: action.to_string(),
        id: id.to_string(),
        ts: event_ts(),
    });
}

async fn rehydrate_users(state: &AppState, store: &ConfigStore) {
    if let Some(auth) = &state.auth {
        let _ = apply_users(auth, store).await;
    }
}

// ── Users ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UserBody {
    pub username: Option<String>,
    pub password: Option<String>,
    /// Pre-hashed alternative: MD5(username:realm:password).
    pub ha1: Option<String>,
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub max_concurrent_calls: Option<i64>,
    pub max_calls_per_minute: Option<i64>,
}

fn default_true() -> bool {
    true
}

fn user_json(u: &UserRow) -> serde_json::Value {
    // ha1 is auth material — never returned.
    json!({
        "username": u.username,
        "realm": u.realm,
        "display_name": u.display_name,
        "enabled": u.enabled,
        "max_concurrent_calls": u.max_concurrent_calls,
        "max_calls_per_minute": u.max_calls_per_minute,
    })
}

fn resolve_ha1(realm: &str, username: &str, body: &UserBody) -> ApiResult<String> {
    match (&body.password, &body.ha1) {
        (Some(p), _) => Ok(compute_ha1(username, realm, p)),
        (None, Some(h)) if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(h.to_lowercase())
        }
        (None, Some(_)) => Err(ApiError::bad_request("ha1 must be 32 hex chars")),
        (None, None) => Err(ApiError::bad_request("missing required field: password (or ha1)")),
    }
}

pub async fn list_users(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let rows = store.list_users().await.map_err(ApiError::internal)?;
    Ok(Json(serde_json::Value::Array(
        rows.iter().map(user_json).collect(),
    )))
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<UserBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let store = store(&state)?;
    let username = body
        .username
        .clone()
        .filter(|u| !u.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing required field: username"))?;

    if store.get_user(&username).await.map_err(ApiError::internal)?.is_some() {
        return Err(ApiError::conflict(format!("user '{}' already exists", username)));
    }

    let row = UserRow {
        username: username.clone(),
        ha1: resolve_ha1(&state.realm, &username, &body)?,
        realm: state.realm.clone(),
        display_name: body.display_name.clone(),
        enabled: body.enabled,
        max_concurrent_calls: body.max_concurrent_calls,
        max_calls_per_minute: body.max_calls_per_minute,
    };
    store.upsert_user(&row).await.map_err(ApiError::internal)?;
    rehydrate_users(&state, &store).await;
    config_changed(&state, "user", "create", &username);
    info!("API: created user '{}'", username);
    Ok((StatusCode::CREATED, Json(user_json(&row))))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(body): Json<UserBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let existing = store
        .get_user(&username)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("user '{}' not found", username)))?;

    let ha1 = if body.password.is_none() && body.ha1.is_none() {
        existing.ha1
    } else {
        resolve_ha1(&state.realm, &username, &body)?
    };

    let row = UserRow {
        username: username.clone(),
        ha1,
        realm: state.realm.clone(),
        display_name: body.display_name.clone(),
        enabled: body.enabled,
        max_concurrent_calls: body.max_concurrent_calls,
        max_calls_per_minute: body.max_calls_per_minute,
    };
    store.upsert_user(&row).await.map_err(ApiError::internal)?;
    rehydrate_users(&state, &store).await;
    config_changed(&state, "user", "update", &username);
    Ok(Json(user_json(&row)))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if !store.delete_user(&username).await.map_err(ApiError::internal)? {
        return Err(ApiError::not_found(format!("user '{}' not found", username)));
    }
    rehydrate_users(&state, &store).await;
    config_changed(&state, "user", "delete", &username);
    info!("API: deleted user '{}'", username);
    Ok(Json(json!({ "username": username, "deleted": true })))
}

// ── DIDs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DidBody {
    pub number: Option<String>,
    pub sip_user: Option<String>,
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

pub async fn list_dids(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let rows = store.list_dids().await.map_err(ApiError::internal)?;
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
    Ok(Json(serde_json::Value::Array(items)))
}

pub async fn create_did(
    State(state): State<AppState>,
    Json(body): Json<DidBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let store = store(&state)?;
    let (number, sip_user) = match (body.number.clone(), body.sip_user.clone()) {
        (Some(n), Some(u)) if !n.is_empty() && !u.is_empty() => (n, u),
        _ => return Err(ApiError::bad_request("missing required fields: number, sip_user")),
    };

    if store.get_did(&number).await.map_err(ApiError::internal)?.is_some() {
        return Err(ApiError::conflict(format!("DID '{}' already exists", number)));
    }

    let row = DidRow {
        number: number.clone(),
        sip_user: sip_user.clone(),
        display_name: body.display_name.clone(),
        enabled: body.enabled,
    };
    store.upsert_did(&row).await.map_err(ApiError::internal)?;
    let _ = apply_dids(&state.dids, &store).await;
    config_changed(&state, "did", "create", &number);
    info!("API: created DID '{}' → '{}'", number, sip_user);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "number": number, "sip_user": sip_user, "created": true })),
    ))
}

pub async fn delete_did(
    State(state): State<AppState>,
    Path(number): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if !store.delete_did(&number).await.map_err(ApiError::internal)? {
        return Err(ApiError::not_found(format!("DID '{}' not found", number)));
    }
    let _ = apply_dids(&state.dids, &store).await;
    config_changed(&state, "did", "delete", &number);
    Ok(Json(json!({ "number": number, "deleted": true })))
}

// ── Export ────────────────────────────────────────────────────────────────────

/// GET /api/v1/export — full dynamic-config dump for backup/rollback.
/// Includes HA1 hashes and trunk credentials (token-gated admin endpoint);
/// a restore must be able to reproduce the exact state.
pub async fn export(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let users = store.list_users().await.map_err(ApiError::internal)?;
    let dids = store.list_dids().await.map_err(ApiError::internal)?;
    let trunks = store.list_trunks().await.map_err(ApiError::internal)?;
    let routes = store.list_routes().await.map_err(ApiError::internal)?;
    let acl = store.list_acl_rules().await.map_err(ApiError::internal)?;
    let acl_default = store
        .get_setting("acl_default_action")
        .await
        .map_err(ApiError::internal)?
        .unwrap_or_else(|| "allow".to_string());

    Ok(Json(json!({
        "version": 1,
        "exported_at": event_ts(),
        "users": users,
        "dids": dids,
        "trunks": trunks,
        "routes": routes,
        "acl_rules": acl,
        "acl_default_action": acl_default,
    })))
}
