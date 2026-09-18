//! Health, readiness, metrics, stats, alerts, reload.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sbc_core::metrics::HealthReport;
use serde_json::json;
use std::sync::atomic::Ordering;

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let report = HealthReport::from_metrics(&state.metrics);
    let status = if report.status.is_ok() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        [("content-type", "application/json")],
        report.to_json(),
    )
}

/// 200 once the store is open, the first hydration succeeded and the SIP
/// listeners are bound; 503 with the three flags otherwise. Public.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let r = &state.ready;
    let ready = r.is_ready();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if ready { "ready" } else { "not_ready" },
            "store": r.store_open(),
            "hydrated": r.hydrated(),
            "listening": r.listening(),
        })),
    )
}

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = state.metrics.render_prometheus();
    body.push_str(&sbc_core::metrics::render_trunk_availability(
        &state.trunks.get_stats(),
    ));
    ([("content-type", "text/plain; version=0.0.4")], body)
}

pub async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    let b2bua_stats = state.b2bua.stats().await;
    Json(json!({
        "active_calls": b2bua_stats.total_active,
        "connected": b2bua_stats.connected,
        "ringing": b2bua_stats.ringing,
        "webrtc_calls": b2bua_stats.webrtc_calls,
        "sip_requests_total": state.metrics.sip_requests_total.load(Ordering::Relaxed),
                "calls_total": state.metrics.calls_total.load(Ordering::Relaxed),
        "uptime_seconds": state.metrics.uptime_secs(),
        "cdr": {
            "backend": state.cdr.backend(),
            "queue": state.cdr.queue_len(),
            "written_total": state.metrics.cdrs_written_total.load(Ordering::Relaxed),
            "write_errors_total": state
                .metrics
                .cdr_write_errors
                .lock()
                .map(|m| m.values().sum::<u64>())
                .unwrap_or(0),
            "last_written_at": state.metrics.last_cdr_written_time.load(Ordering::Relaxed),
        },
    }))
}

pub async fn alerts(State(state): State<AppState>) -> impl IntoResponse {
    let mut alerts = Vec::new();

    let now = std::time::Instant::now();
    for (t, s) in &state.trunks.get_stats() {
        // Only while the router actually skips the trunk *because of its
        // health*: an expired cooldown is not an alert any more, and a
        // trunk the operator disabled is not an incident.
        if let Some(left) = s.unavailable_for(now).filter(|_| t.enabled) {
            let parked = s.health_label(now) == "parked";
            alerts.push(json!({
                "level": if parked { "warning" } else { "critical" },
                "type": if parked { "trunk_parked" } else { "trunk_down" },
                "trunk": t.name,
                "failures": s.consecutive_failures,
                "unavailable_for_secs": left.as_secs(),
            }));
        }
        if t.enabled
            && t.register_with_trunk
            && t.transport == sbc_core::routing::TransportType::Udp
            && !s.registered
        {
            alerts.push(json!({
                "level": "warning",
                "type": "trunk_unregistered",
                "trunk": t.name,
            }));
        }
    }

    if state.metrics.store_created_empty.load(Ordering::Relaxed) == 1 {
        alerts.push(json!({
            "level": "critical",
            "type": "store_created_empty",
            "detail": "the config store file was missing at boot and a new, empty one was created — restore it (docs/INSTALL.md §10)",
        }));
    }

    // Listener certificates: expired, or expiring within 14 days.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for cert in state.tls.statuses() {
        if let Some(not_after) = cert.info.not_after {
            let left = not_after as i64 - now_secs as i64;
            if left < 0 {
                alerts.push(json!({
                    "level": "critical",
                    "type": "tls_cert_expired",
                    "listener": cert.listener,
                    "bind": cert.bind,
                    "subject": cert.info.subject,
                }));
            } else if left < 14 * 86_400 {
                alerts.push(json!({
                    "level": "warning",
                    "type": "tls_cert_expiring",
                    "listener": cert.listener,
                    "bind": cert.bind,
                    "subject": cert.info.subject,
                    "days_left": left / 86_400,
                }));
            }
        }
    }

    let auth_failures = state.metrics.auth_failures_total.load(Ordering::Relaxed);
    let auth_challenges = state.metrics.auth_challenges_total.load(Ordering::Relaxed);
    if auth_challenges > 10 && auth_failures as f64 / auth_challenges as f64 > 0.5 {
        alerts.push(json!({
            "level": "warning",
            "type": "high_auth_failure_rate",
            "failures": auth_failures,
            "challenges": auth_challenges,
        }));
    }

    let calls_total = state.metrics.calls_total.load(Ordering::Relaxed);
    let calls_failed = state.metrics.calls_failed_total.load(Ordering::Relaxed);
    if calls_total > 5 && calls_failed as f64 / calls_total as f64 > 0.5 {
        alerts.push(json!({
            "level": "warning",
            "type": "high_call_failure_rate",
            "failed": calls_failed,
            "total": calls_total,
        }));
    }

    Json(serde_json::Value::Array(alerts))
}

/// POST /api/v1/reload — re-hydrate the runtime (store-backed when available).
/// How long `POST /api/v1/reload` waits for the engine's report.
const RELOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask the engine to reload and wait for its report: 200 with what was
/// applied and what needs a restart, 422 when the file is unusable
/// (nothing changed), 202 when the engine did not answer in time (busy
/// loop: check `GET /api/v1/config.last_reload`). Concurrent triggers
/// (SIGHUP, API) coalesce and may answer with the other's report.
pub async fn reload(State(state): State<AppState>) -> impl IntoResponse {
    let mut rx = state.runtime_config.subscribe();
    let before = *rx.borrow_and_update();
    state.reload.notify_one();
    let answered = tokio::time::timeout(RELOAD_WAIT, rx.wait_for(|g| *g > before)).await;
    match answered {
        Ok(Ok(_)) => match state.runtime_config.last_reload() {
            Some(r) if r.ok => (
                StatusCode::OK,
                Json(json!({
                    "status": "reloaded",
                    "source": r.source,
                    "applied": r.applied,
                    "restart_required": r.restart_required,
                    "hydrated": r.hydrated,
                    "ts": r.ts,
                })),
            )
                .into_response(),
            Some(r) => super::ApiError::unprocessable(
                "reload_failed",
                r.error.unwrap_or_else(|| "reload failed".into()),
            )
            .into_response(),
            None => (
                StatusCode::ACCEPTED,
                Json(json!({ "status": "reload_triggered" })),
            )
                .into_response(),
        },
        _ => (
            StatusCode::ACCEPTED,
            Json(json!({
                "status": "reload_triggered",
                "note": "engine did not answer within 5 s; check GET /api/v1/config",
            })),
        )
            .into_response(),
    }
}

/// The effective configuration (secrets masked), what a reload already
/// loaded but could not apply, and what the on-disk file would change.
pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    use sbc_core::config::{config_diff, key_classes, masked_json, SbcConfig};
    let snap = state.runtime_config.snapshot();
    let restart_required = config_diff(&snap.effective, &snap.last_loaded).restart_required;
    let file = match snap.path.as_deref() {
        None => serde_json::Value::Null,
        Some(path) => match tokio::fs::read_to_string(path).await {
            Err(e) => json!({ "readable": false, "error": e.to_string() }),
            Ok(raw) => match SbcConfig::from_toml_str(&raw) {
                Err(e) => json!({ "readable": true, "parse_error": e.to_string() }),
                Ok(on_disk) => {
                    let d = config_diff(&snap.effective, &on_disk);
                    json!({
                        "readable": true,
                        "parse_error": null,
                        "restart_required": d.restart_required,
                        "reload_pending": d.reload_pending,
                    })
                }
            },
        },
    };
    Json(json!({
        "path": snap.path,
        "loaded_at": snap.loaded_at,
        "loaded_by": snap.source,
        "store": state.store.is_some(),
        "running": masked_json(&snap.effective),
        "restart_required": restart_required,
        "file": file,
        "last_reload": snap.last_reload,
        "key_classes": key_classes(),
    }))
}
