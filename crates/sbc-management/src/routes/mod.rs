//! Axum route handlers, grouped by resource.

pub mod acl;
pub mod calls;
pub mod config_api;
pub mod events;
pub mod security;
pub mod system;
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
        Self { status: StatusCode::BAD_REQUEST, code: "bad_request", message: message.into() }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_FOUND, code: "not_found", message: message.into() }
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self { status: StatusCode::CONFLICT, code: "conflict", message: message.into() }
    }
    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.to_string(),
        }
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
        (self.status, Json(json!({ "error": self.message, "code": self.code }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
