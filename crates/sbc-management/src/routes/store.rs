//! Config store operations: `POST /api/v1/backup`.
use axum::extract::State;
use axum::Json;
use sbc_core::sbc::backup::{run_backup, BackupError};
use serde_json::json;
use tracing::info;

use super::{ApiError, ApiResult};
use crate::state::AppState;

/// Write a consistent copy of the store into the configured backup
/// directory and prune to the configured number of copies.
pub async fn backup(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let store = state
        .store
        .clone()
        .ok_or_else(ApiError::store_unavailable)?;
    match run_backup(
        &store,
        &state.backup,
        &state.metrics,
        &state.events,
        &state.backup_lock,
    )
    .await
    {
        Ok(report) => {
            info!(
                "API: store backup written: {} ({} bytes, {} ms)",
                report.info.path.display(),
                report.info.bytes,
                report.info.took_ms
            );
            Ok(Json(json!({
                "path": report.info.path,
                "bytes": report.info.bytes,
                "took_ms": report.info.took_ms,
                "pruned": report.pruned,
            })))
        }
        Err(BackupError::Busy) => Err(ApiError::conflict("backup already in progress")),
        Err(BackupError::Failed(e)) => Err(ApiError::internal(format!("backup failed: {}", e))),
    }
}

// ── Import ────────────────────────────────────────────────────────────────────

use axum::extract::Query;
use sbc_core::sbc::hydrate::hydrate_all;
use sbc_storage::{
    AclRuleRow, DestinationRuleRow, DidRow, ImportDoc, ImportMode, ImportUserLimits, RouteRow,
    TrunkRow, UserRow,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use tracing::warn;

/// Largest accepted import body. `server.rs` raises the route's limits to
/// it; the nginx in front needs `client_max_body_size` at least as large.
pub const IMPORT_BODY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

const KNOWN_KEYS: &[&str] = &[
    "version",
    "exported_at",
    "users",
    "dids",
    "trunks",
    "routes",
    "acl_rules",
    "acl_default_action",
    "destination_rules",
    "user_limits",
];

#[derive(Debug, Deserialize)]
pub struct ImportQuery {
    pub mode: Option<String>,
    pub dry_run: Option<bool>,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::bad_request(message).with_code("invalid_import")
}

/// POST /api/v1/import?mode=merge|replace&dry_run=true — load an export
/// document (`GET /api/v1/export`, version 1 or 2) into the store in one
/// transaction, then re-hydrate the runtime from the store.
pub async fn import(
    State(state): State<AppState>,
    Query(q): Query<ImportQuery>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let store = state
        .store
        .clone()
        .ok_or_else(ApiError::store_unavailable)?;
    let mode = match q.mode.as_deref() {
        None => ImportMode::Merge,
        Some(m) => ImportMode::parse(m)
            .ok_or_else(|| invalid(format!("mode must be 'merge' or 'replace', not '{}'", m)))?,
    };
    let dry_run = q.dry_run.unwrap_or(false);

    let doc = parse_document(&body, &state.realm)?;
    check_route_trunks(&doc, mode, &store).await?;
    if mode == ImportMode::Replace {
        refuse_if_busy(&state, &doc)?;
    }

    let report = store
        .import(&doc, mode, dry_run)
        .await
        .map_err(|e| match e {
            sbc_storage::Error::Constraint { .. } => invalid(e.to_string()),
            e => ApiError::internal(format!("import failed: {}", e)),
        })?;

    let mut warnings = Vec::new();
    let mut hydrated = false;
    if !dry_run {
        // Hydration only disables manager entries missing from the store;
        // a trunk the replace deleted goes away like DELETE /trunks does.
        for name in &report.deleted_trunks {
            state.trunks.remove_by_name(name);
            state.metrics.remove_trunk(name);
        }
        match hydrate_all(&state.runtime_handles(), &store).await {
            Ok(()) => hydrated = true,
            Err(e) => {
                warn!("API: import written but hydration failed: {}", e);
                warnings.push(format!(
                    "hydration failed: {} — POST /api/v1/reload to retry",
                    e
                ));
            }
        }
        state.refresh_trunk_ips().await;
        state.trunk_tasks.sync();
        state
            .events
            .publish(sbc_core::events::SbcEvent::ConfigChanged {
                entity: "import".to_string(),
                action: mode.as_str().to_string(),
                id: report.summary(),
                ts: sbc_core::events::event_ts(),
            });
        info!(
            "API: config import ({}): {}",
            mode.as_str(),
            report.summary()
        );
    }
    if doc.trunks.as_ref().is_some_and(|trunks| {
        trunks
            .iter()
            .any(|t| matches!(t.transport.as_str(), "TLS" | "WSS"))
    }) {
        warnings.push(
            "TLS/WSS trunks get their outbound TLS configuration at boot and on POST /api/v1/reload"
                .to_string(),
        );
    }

    Ok(Json(json!({
        "mode": mode.as_str(),
        "dry_run": dry_run,
        "users": report.users,
        "dids": report.dids,
        "trunks": report.trunks,
        "routes": report.routes,
        "acl_rules": report.acl_rules,
        "destination_rules": report.destination_rules,
        "settings": { "set": report.settings_set, "removed": report.settings_removed },
        "deleted_trunks": report.deleted_trunks,
        "hydrated": hydrated,
        "warnings": warnings,
    })))
}

/// The wire document → validated, normalised `ImportDoc`. Unknown keys,
/// an unsupported `version` and any malformed row are 400 `invalid_import`
/// naming the spot (`trunks[2] 'pstn': …`).
fn parse_document(body: &Value, realm: &str) -> ApiResult<ImportDoc> {
    let obj = body
        .as_object()
        .ok_or_else(|| invalid("body must be a JSON object (the GET /api/v1/export document)"))?;
    if let Some(k) = obj.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
        return Err(invalid(format!(
            "unknown key '{}' (known: {})",
            k,
            KNOWN_KEYS.join(", ")
        )));
    }
    match obj.get("version") {
        None | Some(Value::Null) => {}
        Some(v) if v.as_u64().is_some_and(|v| (1..=2).contains(&v)) => {}
        Some(v) => {
            return Err(invalid(format!(
                "unsupported version {} (this SBC exports version 2)",
                v
            )))
        }
    }

    let mut doc = ImportDoc {
        users: section::<UserRow>(obj, "users")?,
        dids: section::<DidRow>(obj, "dids")?,
        trunks: section::<TrunkRow>(obj, "trunks")?,
        routes: section::<RouteRow>(obj, "routes")?,
        acl_rules: section::<AclRuleRow>(obj, "acl_rules")?,
        acl_default_action: None,
        destination_rules: section::<DestinationRuleRow>(obj, "destination_rules")?,
        user_limits: None,
    };
    doc.acl_default_action = match obj.get("acl_default_action") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s == "allow" || s == "deny" => Some(s.clone()),
        Some(_) => return Err(invalid("acl_default_action must be 'allow' or 'deny'")),
    };
    doc.user_limits = match obj.get("user_limits") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let limits: ImportUserLimits = serde_json::from_value(v.clone())
                .map_err(|e| invalid(format!("user_limits: {}", e)))?;
            // The runtime applies the API-set defaults only as a pair (it
            // falls back to the TOML ones otherwise), so half a pair would
            // be stored and exported but never enforced.
            if limits.default_max_concurrent_calls.is_some()
                != limits.default_max_calls_per_minute.is_some()
            {
                return Err(invalid(
                    "user_limits: give both default_max_concurrent_calls and \
                     default_max_calls_per_minute, or neither (null clears both)",
                ));
            }
            Some(limits)
        }
    };
    validate(&mut doc, realm)?;
    Ok(doc)
}

fn section<T: DeserializeOwned>(obj: &Map<String, Value>, name: &str) -> ApiResult<Option<Vec<T>>> {
    match obj.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                if name == "users" && item.get("password").is_some() {
                    return Err(invalid(format!(
                        "users[{}]: 'password' is not accepted here — give 'ha1' = MD5(username:realm:password), or POST /api/v1/users",
                        i
                    )));
                }
                serde_json::from_value::<T>(item.clone())
                    .map_err(|e| invalid(format!("{}[{}]: {}", name, i, e)))
            })
            .collect::<ApiResult<Vec<T>>>()
            .map(Some),
        Some(_) => Err(invalid(format!("{} must be an array", name))),
    }
}

fn validate(doc: &mut ImportDoc, realm: &str) -> ApiResult<()> {
    fn non_empty(at: &str, field: &str, value: &str) -> ApiResult<()> {
        if value.trim().is_empty() {
            return Err(invalid(format!("{}: {} must not be empty", at, field)));
        }
        Ok(())
    }
    fn unique(seen: &mut HashSet<String>, at: &str, key: &str) -> ApiResult<()> {
        if !seen.insert(key.to_string()) {
            return Err(invalid(format!("{}: duplicate '{}'", at, key)));
        }
        Ok(())
    }
    fn allow_or_deny(at: &str, action: &str) -> ApiResult<()> {
        if !matches!(action, "allow" | "deny") {
            return Err(invalid(format!("{}: action must be 'allow' or 'deny'", at)));
        }
        Ok(())
    }
    fn json_string_list(at: &str, field: &str, value: &str) -> ApiResult<()> {
        serde_json::from_str::<Vec<String>>(value)
            .map(|_| ())
            .map_err(|_| {
                invalid(format!(
                    "{}: {} must be a JSON array of strings (as a string, e.g. \"[\\\"+33\\\"]\")",
                    at, field
                ))
            })
    }

    if let Some(users) = &mut doc.users {
        let mut seen = HashSet::new();
        for (i, u) in users.iter_mut().enumerate() {
            let at = format!("users[{}]", i);
            non_empty(&at, "username", &u.username)?;
            let at = format!("{} '{}'", at, u.username);
            unique(&mut seen, &at, &u.username)?;
            if u.ha1.len() != 32 || !u.ha1.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid(format!("{}: ha1 must be 32 hex chars", at)));
            }
            u.ha1 = u.ha1.to_lowercase();
            if u.realm != realm {
                return Err(invalid(format!(
                    "{}: realm '{}' is not this SBC's realm '{}' (the HA1 would never match)",
                    at, u.realm, realm
                )));
            }
        }
    }
    if let Some(dids) = &doc.dids {
        let mut seen = HashSet::new();
        for (i, d) in dids.iter().enumerate() {
            let at = format!("dids[{}]", i);
            non_empty(&at, "number", &d.number)?;
            non_empty(&at, "sip_user", &d.sip_user)?;
            unique(&mut seen, &at, &d.number)?;
        }
    }
    if let Some(trunks) = &mut doc.trunks {
        let mut seen = HashSet::new();
        for (i, t) in trunks.iter_mut().enumerate() {
            let at = format!("trunks[{}]", i);
            non_empty(&at, "name", &t.name)?;
            let at = format!("{} '{}'", at, t.name);
            unique(&mut seen, &at, &t.name)?;
            non_empty(&at, "host", &t.host)?;
            if t.password.as_deref() == Some(MASKED) {
                return Err(invalid(format!(
                    "{}: password is masked (\"{}\") — this is the GET shape, use GET /api/v1/export",
                    at, MASKED
                )));
            }
            t.transport = t.transport.to_uppercase();
            if !matches!(t.transport.as_str(), "UDP" | "TCP" | "TLS" | "WS" | "WSS") {
                return Err(invalid(format!(
                    "{}: transport must be UDP, TCP, TLS, WS or WSS",
                    at
                )));
            }
            if !(1..=65535).contains(&t.port) {
                return Err(invalid(format!("{}: port must be 1-65535", at)));
            }
            // Every one of these becomes a u32 in the runtime: a negative
            // value would wrap to a nonsensical limit.
            for (field, value) in [
                ("max_concurrent_calls", t.max_concurrent_calls),
                ("registration_interval", t.registration_interval),
                ("priority", t.priority),
                ("weight", t.weight),
                ("cost_per_minute", t.cost_per_minute),
            ] {
                if !(0..=i64::from(u32::MAX)).contains(&value) {
                    return Err(invalid(format!(
                        "{}: {} must be between 0 and {}",
                        at,
                        field,
                        u32::MAX
                    )));
                }
            }
            json_string_list(&at, "prefix_patterns", &t.prefix_patterns)?;
            json_string_list(&at, "allowed_codecs", &t.allowed_codecs)?;
        }
    }
    if let Some(routes) = &doc.routes {
        let mut seen = HashSet::new();
        for (i, r) in routes.iter().enumerate() {
            let at = format!("routes[{}]", i);
            non_empty(&at, "prefix", &r.prefix)?;
            non_empty(&at, "trunk_name", &r.trunk_name)?;
            unique(&mut seen, &at, &format!("{} → {}", r.prefix, r.trunk_name))?;
        }
    }
    if let Some(rules) = &doc.acl_rules {
        let mut seen = HashSet::new();
        for (i, r) in rules.iter().enumerate() {
            let at = format!("acl_rules[{}]", i);
            non_empty(&at, "id", &r.id)?;
            let at = format!("{} '{}'", at, r.id);
            unique(&mut seen, &at, &r.id)?;
            allow_or_deny(&at, &r.action)?;
            if !matches!(r.direction.as_str(), "inbound" | "outbound" | "both") {
                return Err(invalid(format!(
                    "{}: direction must be inbound, outbound or both",
                    at
                )));
            }
            // The parser hydration uses: a rule that only looks like a
            // CIDR would be stored, listed by the API and silently dropped
            // at hydration, so its deny would never be enforced.
            if let Err(e) = sbc_core::acl::parse_cidr(&r.cidr) {
                return Err(invalid(format!("{}: {}", at, e)));
            }
        }
    }
    if let Some(rules) = &doc.destination_rules {
        let mut seen = HashSet::new();
        for (i, r) in rules.iter().enumerate() {
            let at = format!("destination_rules[{}]", i);
            non_empty(&at, "id", &r.id)?;
            let at = format!("{} '{}'", at, r.id);
            unique(&mut seen, &at, &r.id)?;
            non_empty(&at, "prefix", &r.prefix)?;
            allow_or_deny(&at, &r.action)?;
        }
    }
    Ok(())
}

/// What `GET /api/v1/trunks` shows in place of a stored password.
const MASKED: &str = "***";

/// Every route must point at a trunk that will exist after the import:
/// the document's trunks (replace), those plus the store's (merge), or
/// the store's alone when the document carries no trunk section.
async fn check_route_trunks(
    doc: &ImportDoc,
    mode: ImportMode,
    store: &sbc_storage::ConfigStore,
) -> ApiResult<()> {
    let Some(routes) = &doc.routes else {
        return Ok(());
    };
    let mut known: HashSet<String> = match &doc.trunks {
        Some(trunks) => trunks.iter().map(|t| t.name.clone()).collect(),
        None => HashSet::new(),
    };
    if doc.trunks.is_none() || mode == ImportMode::Merge {
        let stored = store.list_trunks().await.map_err(ApiError::internal)?;
        known.extend(stored.into_iter().map(|t| t.name));
    }
    for (i, r) in routes.iter().enumerate() {
        if !known.contains(&r.trunk_name) {
            return Err(invalid(format!(
                "routes[{}] '{}': trunk '{}' is neither in the document nor in the store",
                i, r.prefix, r.trunk_name
            )));
        }
    }
    Ok(())
}

/// A replace would delete every trunk the document does not carry — same
/// rule as `DELETE /api/v1/trunks/{name}`: not while it carries calls.
fn refuse_if_busy(state: &AppState, doc: &ImportDoc) -> ApiResult<()> {
    let Some(trunks) = &doc.trunks else {
        return Ok(());
    };
    let wanted: HashSet<&str> = trunks.iter().map(|t| t.name.as_str()).collect();
    let busy: Vec<String> = state
        .trunks
        .get_stats()
        .iter()
        .filter(|(t, s)| s.active_calls > 0 && !wanted.contains(t.name.as_str()))
        .map(|(t, _)| t.name.clone())
        .collect();
    if busy.is_empty() {
        return Ok(());
    }
    Err(ApiError::conflict(format!(
        "replace would delete trunk(s) with active calls: {} — keep them in the document or disable them first",
        busy.join(", ")
    ))
    .with_code("trunk_busy"))
}
