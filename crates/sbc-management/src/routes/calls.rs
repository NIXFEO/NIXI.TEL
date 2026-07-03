//! Calls, registrations and CDR endpoints.

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiResult};
use crate::state::AppState;

pub async fn list_calls(State(state): State<AppState>) -> impl IntoResponse {
    let calls = state.b2bua.active_calls().await;
    let items: Vec<serde_json::Value> = calls
        .iter()
        .map(|c| {
            json!({
                "uuid": c.uuid,
                "state": c.state,
                "call_id": c.inbound_call_id,
                "caller": c.caller_addr,
                "callee": c.callee_addr,
                "duration_secs": c.duration_secs,
                "webrtc": c.is_webrtc,
                "media_session": c.media_session_id,
            })
        })
        .collect();
    Json(serde_json::Value::Array(items))
}

/// DELETE /api/v1/calls/{uuid} — administrative teardown.
pub async fn kick_call(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let active = state.b2bua.active_calls().await;
    if !active.iter().any(|c| c.uuid == uuid) {
        return Err(ApiError::not_found(format!("call '{}' not found", uuid)));
    }
    state.b2bua.terminate_call(&uuid).await;
    Ok(Json(json!({ "uuid": uuid, "terminated": true })))
}

pub async fn list_registrations(
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    let regs = state
        .registrar
        .all_registrations()
        .await
        .map_err(ApiError::internal)?;
    let items: Vec<serde_json::Value> = regs
        .iter()
        .map(|r| {
            json!({
                "aor": r.aor,
                "contact": r.contact,
                "expires_in": r.remaining_secs(),
                "transport": r.transport,
                "received_ip": r.received_ip,
                "received_port": r.received_port,
                "user_agent": r.user_agent,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(items)))
}

#[derive(Deserialize)]
pub struct CdrQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    100
}

pub async fn list_cdrs(
    State(state): State<AppState>,
    Query(q): Query<CdrQuery>,
) -> ApiResult<impl IntoResponse> {
    let limit = q.limit.min(1000);
    let (page, fetched) = state
        .cdr
        .get_page(limit, q.offset)
        .await
        .map_err(ApiError::internal)?;

    // CdrRecord serializes itself via to_json(); assemble raw to avoid
    // double-encoding.
    let items: Vec<String> = page.iter().map(|c| c.to_json()).collect();
    let body = format!(
        r#"{{"items":[{}],"count":{},"limit":{},"offset":{},"has_more":{}}}"#,
        items.join(","),
        items.len(),
        limit,
        q.offset,
        fetched == q.offset + limit,
    );
    Ok(([("content-type", "application/json")], body))
}
