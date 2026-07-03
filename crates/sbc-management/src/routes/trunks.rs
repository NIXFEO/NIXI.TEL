//! Trunk and route CRUD — SQLite-backed, hydrated into the TrunkManager
//! immediately (full field set; fixes the old volatile hardcoded-UDP stub).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sbc_core::events::{event_ts, SbcEvent};
use sbc_core::sbc::hydrate::apply_trunks_and_routes;
use sbc_storage::{ConfigStore, RouteRow, TrunkRow};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::info;

use super::{ApiError, ApiResult};
use crate::state::AppState;

fn store(state: &AppState) -> ApiResult<Arc<ConfigStore>> {
    state.store.clone().ok_or_else(ApiError::store_unavailable)
}

async fn apply_and_notify(state: &AppState, store: &ConfigStore, entity: &str, action: &str, id: &str) {
    let _ = apply_trunks_and_routes(&state.trunks, store).await;
    state.refresh_trunk_ips().await;
    state.events.publish(SbcEvent::ConfigChanged {
        entity: entity.to_string(),
        action: action.to_string(),
        id: id.to_string(),
        ts: event_ts(),
    });
}

// ── Trunks ────────────────────────────────────────────────────────────────────

/// Full trunk field set (everything TrunkConfigToml supports, plus TLS opts).
#[derive(Debug, Deserialize)]
pub struct TrunkBody {
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub host: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_udp")]
    pub transport: String,
    #[serde(default)]
    pub auth_required: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
    #[serde(default)]
    pub register_with_trunk: bool,
    #[serde(default = "default_reg_interval")]
    pub registration_interval: u64,
    #[serde(default)]
    pub prefix_patterns: Vec<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_priority")]
    pub weight: u32,
    #[serde(default)]
    pub cost_per_minute: u32,
    #[serde(default = "default_number_format")]
    pub number_format: String,
    pub country_code: Option<String>,
    pub national_prefix: Option<String>,
    pub caller_number_format: Option<String>,
    pub caller_number_override: Option<String>,
    pub caller_display_name: Option<String>,
    #[serde(default = "default_codecs")]
    pub allowed_codecs: Vec<String>,
    #[serde(default = "default_max_calls")]
    pub max_concurrent_calls: u32,
    pub tls_sni: Option<String>,
    pub tls_ca_cert: Option<String>,
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
}

fn default_true() -> bool { true }
fn default_port() -> u16 { 5060 }
fn default_udp() -> String { "UDP".to_string() }
fn default_reg_interval() -> u64 { 300 }
fn default_priority() -> u32 { 100 }
fn default_number_format() -> String { "e164".to_string() }
fn default_codecs() -> Vec<String> { vec!["PCMU".to_string(), "PCMA".to_string()] }
fn default_max_calls() -> u32 { 100 }

impl TrunkBody {
    fn into_row(self, name: String) -> ApiResult<TrunkRow> {
        let host = self
            .host
            .filter(|h| !h.is_empty())
            .ok_or_else(|| ApiError::bad_request("missing required field: host"))?;
        let transport = self.transport.to_uppercase();
        if !matches!(transport.as_str(), "UDP" | "TCP" | "TLS" | "WS" | "WSS") {
            return Err(ApiError::bad_request("transport must be UDP, TCP, TLS, WS or WSS"));
        }
        Ok(TrunkRow {
            name,
            enabled: self.enabled,
            host,
            port: self.port as i64,
            transport,
            auth_required: self.auth_required,
            username: self.username,
            password: self.password,
            realm: self.realm,
            register_with_trunk: self.register_with_trunk,
            registration_interval: self.registration_interval as i64,
            prefix_patterns: serde_json::to_string(&self.prefix_patterns)
                .unwrap_or_else(|_| "[]".to_string()),
            priority: self.priority as i64,
            weight: self.weight as i64,
            cost_per_minute: self.cost_per_minute as i64,
            number_format: self.number_format,
            country_code: self.country_code,
            national_prefix: self.national_prefix,
            caller_number_format: self.caller_number_format,
            caller_number_override: self.caller_number_override,
            caller_display_name: self.caller_display_name,
            allowed_codecs: serde_json::to_string(&self.allowed_codecs)
                .unwrap_or_else(|_| "[]".to_string()),
            max_concurrent_calls: self.max_concurrent_calls as i64,
            tls_sni: self.tls_sni,
            tls_ca_cert: self.tls_ca_cert,
            tls_verify: self.tls_verify,
            tls_client_cert: self.tls_client_cert,
            tls_client_key: self.tls_client_key,
        })
    }
}

/// Stored config + live health, password redacted.
fn trunk_json(state: &AppState, row: &TrunkRow) -> serde_json::Value {
    let live = state
        .trunks
        .get_stats()
        .into_iter()
        .find(|(t, _)| t.name == row.name);
    let (health, active, total, failed, consecutive) = match &live {
        Some((_, s)) => (
            if s.consecutive_failures == 0 {
                "up"
            } else if s.disabled_until.is_some() {
                "down"
            } else {
                "degraded"
            },
            s.active_calls,
            s.total_calls,
            s.failed_calls,
            s.consecutive_failures,
        ),
        None => ("unknown", 0, 0, 0, 0),
    };
    json!({
        "name": row.name,
        "enabled": row.enabled,
        "host": row.host,
        "port": row.port,
        "transport": row.transport,
        "auth_required": row.auth_required,
        "username": row.username,
        "password": row.password.as_ref().map(|_| "***"),
        "realm": row.realm,
        "register_with_trunk": row.register_with_trunk,
        "registration_interval": row.registration_interval,
        "prefix_patterns": row.prefix_patterns_vec(),
        "priority": row.priority,
        "weight": row.weight,
        "cost_per_minute": row.cost_per_minute,
        "number_format": row.number_format,
        "country_code": row.country_code,
        "national_prefix": row.national_prefix,
        "caller_number_override": row.caller_number_override,
        "allowed_codecs": row.allowed_codecs_vec(),
        "max_concurrent_calls": row.max_concurrent_calls,
        "tls": {
            "sni": row.tls_sni,
            "ca_cert": row.tls_ca_cert,
            "verify": row.tls_verify,
            "mtls": row.tls_client_cert.is_some(),
        },
        "health": health,
        "active_calls": active,
        "total_calls": total,
        "failed_calls": failed,
        "consecutive_failures": consecutive,
    })
}

pub async fn list_trunks(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    // Store-backed listing when available; fall back to live manager view
    // (matches the legacy /api/v1/trunks shape) otherwise.
    match state.store.clone() {
        Some(store) => {
            let rows = store.list_trunks().await.map_err(ApiError::internal)?;
            Ok(Json(serde_json::Value::Array(
                rows.iter().map(|r| trunk_json(&state, r)).collect(),
            )))
        }
        None => {
            let items: Vec<serde_json::Value> = state
                .trunks
                .get_stats()
                .iter()
                .map(|(t, s)| {
                    json!({
                        "id": t.id.to_string(),
                        "name": t.name,
                        "host": t.host,
                        "port": t.port,
                        "enabled": t.enabled,
                        "health": if s.consecutive_failures == 0 { "up" } else { "degraded" },
                        "active_calls": s.active_calls,
                        "total_calls": s.total_calls,
                        "failed_calls": s.failed_calls,
                        "consecutive_failures": s.consecutive_failures,
                    })
                })
                .collect();
            Ok(Json(serde_json::Value::Array(items)))
        }
    }
}

pub async fn get_trunk(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let row = store
        .get_trunk(&name)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("trunk '{}' not found", name)))?;
    Ok(Json(trunk_json(&state, &row)))
}

pub async fn create_trunk(
    State(state): State<AppState>,
    Json(body): Json<TrunkBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let store = store(&state)?;
    let name = body
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing required field: name"))?;

    if store.get_trunk(&name).await.map_err(ApiError::internal)?.is_some() {
        return Err(ApiError::conflict(format!("trunk '{}' already exists", name)));
    }

    let row = body.into_row(name.clone())?;
    store.upsert_trunk(&row).await.map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "trunk", "create", &name).await;
    info!("API: created trunk '{}' ({}:{})", name, row.host, row.port);
    Ok((StatusCode::CREATED, Json(trunk_json(&state, &row))))
}

pub async fn update_trunk(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<TrunkBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if store.get_trunk(&name).await.map_err(ApiError::internal)?.is_none() {
        return Err(ApiError::not_found(format!("trunk '{}' not found", name)));
    }
    let row = body.into_row(name.clone())?;
    store.upsert_trunk(&row).await.map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "trunk", "update", &name).await;
    Ok(Json(trunk_json(&state, &row)))
}

pub async fn delete_trunk(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;

    // Refuse while the trunk carries calls: disable instead.
    let has_active = state
        .trunks
        .get_stats()
        .iter()
        .any(|(t, s)| t.name == name && s.active_calls > 0);
    if has_active {
        return Err(ApiError::conflict(format!(
            "trunk '{}' has active calls — disable it first (POST /api/v1/trunks/{}/disable)",
            name, name
        )));
    }

    if !store.delete_trunk(&name).await.map_err(ApiError::internal)? {
        return Err(ApiError::not_found(format!("trunk '{}' not found", name)));
    }
    // Hydration disables manager entries missing from the store; remove outright.
    state.trunks.remove_by_name(&name);
    apply_and_notify(&state, &store, "trunk", "delete", &name).await;
    info!("API: deleted trunk '{}'", name);
    Ok(Json(json!({ "name": name, "deleted": true })))
}

async fn set_trunk_enabled(
    state: AppState,
    name: String,
    enabled: bool,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let mut row = store
        .get_trunk(&name)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("trunk '{}' not found", name)))?;
    row.enabled = enabled;
    store.upsert_trunk(&row).await.map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "trunk", if enabled { "enable" } else { "disable" }, &name)
        .await;
    Ok(Json(json!({ "name": name, "enabled": enabled })))
}

pub async fn enable_trunk(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    set_trunk_enabled(state, name, true).await
}

pub async fn disable_trunk(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    set_trunk_enabled(state, name, false).await
}

// ── Routes (prefix → trunk) ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RouteBody {
    pub prefix: Option<String>,
    pub trunk_name: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub description: Option<String>,
}

fn route_json(r: &RouteRow) -> serde_json::Value {
    json!({
        "id": r.id,
        "prefix": r.prefix,
        "trunk_name": r.trunk_name,
        "priority": r.priority,
        "enabled": r.enabled,
        "description": r.description,
    })
}

pub async fn list_routes(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let rows = store.list_routes().await.map_err(ApiError::internal)?;
    Ok(Json(serde_json::Value::Array(rows.iter().map(route_json).collect())))
}

pub async fn create_route(
    State(state): State<AppState>,
    Json(body): Json<RouteBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let store = store(&state)?;
    let (prefix, trunk_name) = match (body.prefix.clone(), body.trunk_name.clone()) {
        (Some(p), Some(t)) if !p.is_empty() && !t.is_empty() => (p, t),
        _ => return Err(ApiError::bad_request("missing required fields: prefix, trunk_name")),
    };
    if store.get_trunk(&trunk_name).await.map_err(ApiError::internal)?.is_none() {
        return Err(ApiError::bad_request(format!("unknown trunk '{}'", trunk_name)));
    }

    let mut row = RouteRow {
        id: 0,
        prefix,
        trunk_name,
        priority: body.priority as i64,
        enabled: body.enabled,
        description: body.description.clone(),
    };
    row.id = store
        .insert_route(&row)
        .await
        .map_err(|e| ApiError::conflict(format!("route insert failed: {}", e)))?;
    apply_and_notify(&state, &store, "route", "create", &row.id.to_string()).await;
    Ok((StatusCode::CREATED, Json(route_json(&row))))
}

pub async fn update_route(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<RouteBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let existing = store
        .get_route(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("route {} not found", id)))?;

    let row = RouteRow {
        id,
        prefix: body.prefix.unwrap_or(existing.prefix),
        trunk_name: body.trunk_name.unwrap_or(existing.trunk_name),
        priority: body.priority as i64,
        enabled: body.enabled,
        description: body.description.or(existing.description),
    };
    store.update_route(&row).await.map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "route", "update", &id.to_string()).await;
    Ok(Json(route_json(&row)))
}

pub async fn delete_route(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if !store.delete_route(id).await.map_err(ApiError::internal)? {
        return Err(ApiError::not_found(format!("route {} not found", id)));
    }
    apply_and_notify(&state, &store, "route", "delete", &id.to_string()).await;
    Ok(Json(json!({ "id": id, "deleted": true })))
}
