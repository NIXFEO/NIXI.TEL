//! ACL rules CRUD + default action — SQLite-backed, applied immediately.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sbc_core::events::{event_ts, SbcEvent};
use sbc_core::sbc::hydrate::apply_acl;
use sbc_storage::{AclRuleRow, ConfigStore};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use super::{ApiError, ApiResult};
use crate::state::AppState;

fn store(state: &AppState) -> ApiResult<Arc<ConfigStore>> {
    state.store.clone().ok_or_else(ApiError::store_unavailable)
}

async fn apply_and_notify(state: &AppState, store: &ConfigStore, action: &str, id: &str) {
    let _ = apply_acl(&state.acl, store).await;
    state.events.publish(SbcEvent::ConfigChanged {
        entity: "acl".to_string(),
        action: action.to_string(),
        id: id.to_string(),
        ts: event_ts(),
    });
}

#[derive(Debug, Deserialize)]
pub struct AclRuleBody {
    pub cidr: Option<String>,
    pub action: Option<String>,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub comment: Option<String>,
}

fn default_direction() -> String { "both".to_string() }
fn default_priority() -> u32 { 100 }
fn default_true() -> bool { true }

fn rule_json(r: &AclRuleRow) -> serde_json::Value {
    json!({
        "id": r.id,
        "cidr": r.cidr,
        "action": r.action,
        "direction": r.direction,
        "priority": r.priority,
        "enabled": r.enabled,
        "comment": r.comment,
    })
}

pub async fn list_rules(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let rows = store.list_acl_rules().await.map_err(ApiError::internal)?;
    Ok(Json(serde_json::Value::Array(rows.iter().map(rule_json).collect())))
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(body): Json<AclRuleBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let store = store(&state)?;
    let cidr = body
        .cidr
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing required field: cidr"))?;
    let action = match body.action.as_deref() {
        Some("allow") => "allow",
        Some("deny") => "deny",
        _ => return Err(ApiError::bad_request("action must be 'allow' or 'deny'")),
    };
    if !matches!(body.direction.as_str(), "inbound" | "outbound" | "both") {
        return Err(ApiError::bad_request("direction must be inbound, outbound or both"));
    }
    // Validate the CIDR before storing (single IPs accepted too).
    if cidr.parse::<std::net::IpAddr>().is_err() && !cidr.contains('/') {
        return Err(ApiError::bad_request(format!("invalid CIDR or IP: {}", cidr)));
    }

    let row = AclRuleRow {
        id: uuid::Uuid::new_v4().to_string(),
        cidr,
        action: action.to_string(),
        direction: body.direction.clone(),
        priority: body.priority as i64,
        enabled: body.enabled,
        comment: body.comment.clone(),
    };
    store.upsert_acl_rule(&row).await.map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "create", &row.id).await;
    Ok((StatusCode::CREATED, Json(rule_json(&row))))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if !store.delete_acl_rule(&id).await.map_err(ApiError::internal)? {
        return Err(ApiError::not_found(format!("ACL rule '{}' not found", id)));
    }
    apply_and_notify(&state, &store, "delete", &id).await;
    Ok(Json(json!({ "id": id, "deleted": true })))
}

#[derive(Debug, Deserialize)]
pub struct DefaultActionBody {
    pub action: String,
}

pub async fn get_default(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    let action = store
        .get_setting("acl_default_action")
        .await
        .map_err(ApiError::internal)?
        .unwrap_or_else(|| "allow".to_string());
    Ok(Json(json!({ "action": action })))
}

pub async fn set_default(
    State(state): State<AppState>,
    Json(body): Json<DefaultActionBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = store(&state)?;
    if !matches!(body.action.as_str(), "allow" | "deny") {
        return Err(ApiError::bad_request("action must be 'allow' or 'deny'"));
    }
    store
        .set_setting("acl_default_action", &body.action)
        .await
        .map_err(ApiError::internal)?;
    apply_and_notify(&state, &store, "set_default", &body.action).await;
    Ok(Json(json!({ "action": body.action })))
}
