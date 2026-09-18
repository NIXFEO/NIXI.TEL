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
