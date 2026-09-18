//! Axum route handlers, grouped by resource.

pub mod acl;
pub mod calls;
pub mod config_api;
pub mod events;
pub mod security;
pub mod store;
pub mod system;
pub mod tls;
pub mod trunks;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Uniform error body: `{"error": "<message>", "code": "<machine_code>"}`.
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }
    /// 422 with a caller-chosen code (`reload_failed`…).
    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
        }
    }
    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.to_string(),
        }
    }
    /// Same status, a more specific machine code (`invalid_import`,
    /// `trunk_busy`…).
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    /// Config store unavailable — mutating endpoints cannot work.
    pub fn store_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "store_unavailable",
            message: "config store unavailable".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({ "error": self.message, "code": self.code })),
        )
            .into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// RFC 7396 JSON Merge Patch on a flat wire-shaped object: `null` removes
/// (→ `None`), anything else replaces. Keys the base does not know are an
/// error, so a client that PATCHes with the GET shape (`tls`, `health`,
/// `active_calls`…) learns about it instead of being silently ignored.
pub fn merge_patch(base: &mut serde_json::Value, patch: &serde_json::Value) -> ApiResult<()> {
    let Some(patch) = patch.as_object() else {
        return Err(ApiError::bad_request("PATCH body must be a JSON object"));
    };
    let Some(target) = base.as_object_mut() else {
        return Err(ApiError::internal("base is not an object"));
    };
    for (k, v) in patch {
        if !target.contains_key(k) {
            return Err(ApiError::bad_request(format!("unknown field '{}'", k)));
        }
        target.insert(k.clone(), v.clone());
    }
    Ok(())
}
