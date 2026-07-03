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
    (status, [("content-type", "application/json")], report.to_json())
}

pub async fn ready() -> impl IntoResponse {
    Json(json!({ "status": "ready" }))
}

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render_prometheus(),
    )
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
    }))
}

pub async fn alerts(State(state): State<AppState>) -> impl IntoResponse {
    let mut alerts = Vec::new();

    for (t, s) in &state.trunks.get_stats() {
        if s.consecutive_failures >= 3 {
            alerts.push(json!({
                "level": "critical",
                "type": "trunk_down",
                "trunk": t.name,
                "failures": s.consecutive_failures,
            }));
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
pub async fn reload(State(state): State<AppState>) -> impl IntoResponse {
    state.reload.notify_one();
    Json(json!({ "status": "reload_triggered" }))
}
