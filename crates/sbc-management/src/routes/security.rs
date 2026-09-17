//! Security & anti-fraud API: bans, destination rules, user limits, status.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sbc_core::security::{BanEntry, DestinationRule, UserLimits};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

use sbc_core::events::{event_ts, SbcEvent};
use sbc_core::sbc::hydrate::{
    apply_destinations, apply_user_limits, SETTING_DEFAULT_CONCURRENT, SETTING_DEFAULT_CPM,
};
use sbc_storage::ConfigStore;
use tracing::warn;

use super::{ApiError, ApiResult};
use crate::state::AppState;

fn ban_json(b: &BanEntry) -> serde_json::Value {
    json!({
        "ip": b.ip.to_string(),
        "reason": b.reason,
        "banned_at": BanEntry::ts_rfc_secs(b.banned_at),
        "expires_in_secs": b.remaining_secs(),
        "failures": b.failures,
        "manual": b.manual,
        "offense_count": b.offense_count,
    })
}

// ── Bans ──────────────────────────────────────────────────────────────────────

pub async fn list_bans(State(state): State<AppState>) -> Json<serde_json::Value> {
    let bans: Vec<_> = state.security.bans.list().iter().map(ban_json).collect();
    Json(serde_json::Value::Array(bans))
}

#[derive(Deserialize)]
pub struct BanBody {
    pub ip: String,
    #[serde(default = "default_ban_secs")]
    pub duration_secs: u64,
    #[serde(default = "default_reason")]
    pub reason: String,
}

fn default_ban_secs() -> u64 {
    3600
}
fn default_reason() -> String {
    "manual".to_string()
}

pub async fn create_ban(
    State(state): State<AppState>,
    Json(body): Json<BanBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let ip: IpAddr = body
        .ip
        .parse()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {}", body.ip)))?;
    let entry = state.security.bans.ban(
        ip,
        Duration::from_secs(body.duration_secs.max(1)),
        &body.reason,
    );

    // Persist so restarts keep the ban
    if let Some(store) = &state.store {
        let row = sbc_storage::BanRow {
            ip: entry.ip.to_string(),
            reason: entry.reason.clone(),
            banned_at: rfc3339(entry.banned_at),
            expires_at: rfc3339(entry.expires_at),
            failures: entry.failures as i64,
            manual: true,
            offense_count: entry.offense_count as i64,
        };
        let _ = store.save_ban(&row).await;
    }
    Ok((StatusCode::CREATED, Json(ban_json(&entry))))
}

pub async fn delete_ban(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {}", ip)))?;
    if !state.security.bans.unban(addr) {
        return Err(ApiError::not_found(format!("{} is not banned", ip)));
    }
    if let Some(store) = &state.store {
        let _ = store.delete_ban(&ip).await;
    }
    Ok(Json(json!({ "ip": ip, "unbanned": true })))
}

// ── Destination rules ─────────────────────────────────────────────────────────

/// Re-hydrate the anti-fraud managers from the store and announce the change.
async fn apply_security(
    state: &AppState,
    store: &ConfigStore,
    entity: &str,
    action: &str,
    id: &str,
) {
    let _ = apply_destinations(&state.security, store).await;
    let _ = apply_user_limits(&state.security, store).await;
    state.events.publish(SbcEvent::ConfigChanged {
        entity: entity.to_string(),
        action: action.to_string(),
        id: id.to_string(),
        ts: event_ts(),
    });
}

pub async fn list_destination_rules(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "default_action": if state.security.destinations.default_action_deny() { "deny" } else { "allow" },
        "rules": state.security.destinations.list_rules(),
    }))
}

#[derive(Deserialize)]
pub struct DestinationRuleBody {
    /// Optional stable id (lets an export be replayed); a fresh uuid otherwise.
    pub id: Option<String>,
    pub prefix: String,
    pub action: String,
    pub user: Option<String>,
    #[serde(default)]
    pub description: String,
}

pub async fn create_destination_rule(
    State(state): State<AppState>,
    Json(body): Json<DestinationRuleBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if body.prefix.is_empty() {
        return Err(ApiError::bad_request("prefix must not be empty"));
    }
    let deny = match body.action.as_str() {
        "deny" => true,
        "allow" => false,
        _ => return Err(ApiError::bad_request("action must be 'allow' or 'deny'")),
    };
    let rule = DestinationRule {
        id: body
            .id
            .filter(|i| !i.is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        prefix: body.prefix,
        deny,
        user: body.user,
        description: body.description,
        enabled: true,
    };
    match &state.store {
        Some(store) => {
            let row = sbc_storage::DestinationRuleRow {
                id: rule.id.clone(),
                prefix: rule.prefix.clone(),
                action: if deny { "deny".into() } else { "allow".into() },
                user: rule.user.clone(),
                description: rule.description.clone(),
                enabled: true,
            };
            let created = store
                .upsert_destination_rule(&row)
                .await
                .map_err(ApiError::internal)?;
            if !created {
                return Err(ApiError::conflict(format!(
                    "destination rule '{}' already exists",
                    rule.id
                )));
            }
            apply_security(&state, store, "destination_rule", "create", &rule.id).await;
        }
        None => {
            warn!("Destination rule created in memory only (config store unavailable)");
            state.security.destinations.add_rule(rule.clone());
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&rule).unwrap_or_default()),
    ))
}

pub async fn delete_destination_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let in_memory = state.security.destinations.remove_rule(&id);
    let in_store = match &state.store {
        Some(store) => store
            .delete_destination_rule(&id)
            .await
            .map_err(ApiError::internal)?,
        None => false,
    };
    if !in_memory && !in_store {
        return Err(ApiError::not_found(format!("rule '{}' not found", id)));
    }
    if let Some(store) = &state.store {
        apply_security(&state, store, "destination_rule", "delete", &id).await;
    }
    Ok(Json(json!({ "id": id, "deleted": true })))
}

// ── User limits ───────────────────────────────────────────────────────────────

pub async fn get_user_limits(State(state): State<AppState>) -> Json<serde_json::Value> {
    let (concurrent, cpm) = state.security.user_limits.defaults();
    let overrides: Vec<_> = state
        .security
        .user_limits
        .overrides()
        .into_iter()
        .map(|(user, l)| {
            json!({
                "user": user,
                "max_concurrent_calls": l.max_concurrent_calls,
                "max_calls_per_minute": l.max_calls_per_minute,
            })
        })
        .collect();
    Json(json!({
        "default_max_concurrent_calls": concurrent,
        "default_max_calls_per_minute": cpm,
        "overrides": overrides,
    }))
}

#[derive(Deserialize)]
pub struct DefaultLimitsBody {
    pub default_max_concurrent_calls: u32,
    pub default_max_calls_per_minute: u32,
}

pub async fn set_default_limits(
    State(state): State<AppState>,
    Json(body): Json<DefaultLimitsBody>,
) -> ApiResult<Json<serde_json::Value>> {
    state.security.user_limits.set_defaults(
        body.default_max_concurrent_calls,
        body.default_max_calls_per_minute,
    );
    if let Some(store) = &state.store {
        store
            .set_setting(
                SETTING_DEFAULT_CONCURRENT,
                &body.default_max_concurrent_calls.to_string(),
            )
            .await
            .map_err(ApiError::internal)?;
        store
            .set_setting(
                SETTING_DEFAULT_CPM,
                &body.default_max_calls_per_minute.to_string(),
            )
            .await
            .map_err(ApiError::internal)?;
        apply_security(&state, store, "user_limits", "update", "defaults").await;
    }
    Ok(Json(json!({ "updated": true })))
}

#[derive(Deserialize)]
pub struct UserLimitBody {
    pub max_concurrent_calls: Option<u32>,
    pub max_calls_per_minute: Option<u32>,
}

/// Per-user overrides live on the user row (`users.max_*`): the user must
/// exist in the store. Without a store they stay in memory.
pub async fn set_user_limits(
    State(state): State<AppState>,
    Path(user): Path<String>,
    Json(body): Json<UserLimitBody>,
) -> ApiResult<Json<serde_json::Value>> {
    match &state.store {
        Some(store) => {
            let updated = store
                .set_user_limits(
                    &user,
                    body.max_concurrent_calls.map(i64::from),
                    body.max_calls_per_minute.map(i64::from),
                )
                .await
                .map_err(ApiError::internal)?;
            if !updated {
                return Err(ApiError::not_found(format!("user '{}' not found", user)));
            }
            apply_security(&state, store, "user_limits", "update", &user).await;
        }
        None => {
            warn!("User limit override set in memory only (config store unavailable)");
            state.security.user_limits.set_override(
                &user,
                UserLimits {
                    max_concurrent_calls: body.max_concurrent_calls,
                    max_calls_per_minute: body.max_calls_per_minute,
                },
            );
        }
    }
    Ok(Json(json!({ "user": user, "updated": true })))
}

pub async fn delete_user_limits(
    State(state): State<AppState>,
    Path(user): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    match &state.store {
        Some(store) => {
            let row = store
                .get_user(&user)
                .await
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::not_found(format!("user '{}' not found", user)))?;
            if row.max_concurrent_calls.is_none() && row.max_calls_per_minute.is_none() {
                return Err(ApiError::not_found(format!("no override for '{}'", user)));
            }
            store
                .set_user_limits(&user, None, None)
                .await
                .map_err(ApiError::internal)?;
            apply_security(&state, store, "user_limits", "delete", &user).await;
        }
        None => {
            if !state.security.user_limits.remove_override(&user) {
                return Err(ApiError::not_found(format!("no override for '{}'", user)));
            }
        }
    }
    Ok(Json(json!({ "user": user, "deleted": true })))
}

// ── Status ────────────────────────────────────────────────────────────────────

pub async fn status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let bans = state.security.bans.list();
    let (concurrent, cpm) = state.security.user_limits.defaults();
    Json(json!({
        "bans": {
            "active": bans.len(),
            "list": bans.iter().map(ban_json).collect::<Vec<_>>(),
        },
        "destinations": {
            "default_action": if state.security.destinations.default_action_deny() { "deny" } else { "allow" },
            "rules": state.security.destinations.list_rules().len(),
            "blocked_total": state.security.destinations.blocked_total.load(std::sync::atomic::Ordering::Relaxed),
        },
        "user_limits": {
            "default_max_concurrent_calls": concurrent,
            "default_max_calls_per_minute": cpm,
            "overrides": state.security.user_limits.overrides().len(),
        },
        "recent_events": state.security.recent_events(),
    }))
}

pub(crate) fn rfc3339(t: std::time::SystemTime) -> String {
    // Delegate to the epoch-seconds representation; consumers get a number
    // via ban_json — this string form is only for the persistence row.
    let secs = BanEntry::ts_rfc_secs(t);
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let (mut y, mut rem) = (1970u64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if rem < len {
            break;
        }
        rem -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_len = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while rem >= month_len[m] {
        rem -= month_len[m];
        m += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        rem + 1,
        rem_secs / 3600,
        (rem_secs % 3600) / 60,
        rem_secs % 60
    )
}
