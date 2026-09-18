//! Listener certificates: `GET /api/v1/tls/certificates`,
//! `POST /api/v1/tls/reload` (what a certbot deploy hook calls).
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sbc_core::events::{event_ts, SbcEvent};
use serde_json::json;
use tracing::info;

use crate::state::AppState;

pub async fn certificates(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.tls.statuses())
}

/// Re-read every TLS/WSS listener's cert/key files. 200 with one outcome
/// per listener; 422 `tls_reload_failed` when any listener could not
/// reload (its previous certificate stays in use). Empty when no secure
/// listener is configured.
pub async fn reload(State(state): State<AppState>) -> impl IntoResponse {
    let outcomes = state.tls.reload_all().await;
    state.tls.publish_expiry(&state.metrics);
    let ts = event_ts();
    for o in outcomes.iter().filter(|o| o.error.is_some()) {
        // Same SSE alert as the SIGHUP / POST /api/v1/reload path: a
        // certbot hook is the usual caller and nobody reads its output.
        state.events.publish(SbcEvent::Alert {
            level: "warning".into(),
            kind: "tls_reload_failed".into(),
            detail: format!(
                "{} {}: {}",
                o.listener,
                o.bind,
                o.error.as_deref().unwrap_or("unknown error")
            ),
            ts,
        });
    }
    let failed: Vec<&str> = outcomes
        .iter()
        .filter(|o| o.error.is_some())
        .map(|o| o.listener)
        .collect();
    info!(
        "API: TLS reload — {} listener(s), {} changed, {} failed",
        outcomes.len(),
        outcomes.iter().filter(|o| o.changed).count(),
        failed.len()
    );
    if failed.is_empty() {
        (
            StatusCode::OK,
            Json(json!({ "status": "ok", "listeners": outcomes })),
        )
    } else {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": format!("certificate reload failed for: {}", failed.join(", ")),
                "code": "tls_reload_failed",
                "listeners": outcomes,
            })),
        )
    }
}
