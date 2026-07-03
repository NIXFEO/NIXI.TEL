//! Axum management server — replaces the hand-rolled http_server.
//!
//! - proper HTTP/1.1 with keep-alive and body limits
//! - constant-time bearer-token auth (skips /health and /ready)
//! - configurable CORS
//! - SSE event stream at /api/v1/events

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use crate::routes;
use crate::state::AppState;

const BODY_LIMIT_BYTES: usize = 256 * 1024;

pub fn build_router(state: AppState, cors_allowed_origins: &[String]) -> Router {
    let mut app = Router::new()
        // Health & readiness (public)
        .route("/health", get(routes::system::health))
        .route("/ready", get(routes::system::ready))
        // Observability
        .route("/metrics", get(routes::system::metrics))
        .route("/api/v1/stats", get(routes::system::stats))
        .route("/api/v1/alerts", get(routes::system::alerts))
        .route("/api/v1/events", get(routes::events::sse_events))
        // Calls
        .route("/api/v1/calls", get(routes::calls::list_calls))
        .route("/api/v1/calls/:uuid", delete(routes::calls::kick_call))
        // Registrations
        .route("/api/v1/registrations", get(routes::calls::list_registrations))
        // CDRs
        .route("/api/v1/cdrs", get(routes::calls::list_cdrs))
        // Users / DIDs (SQLite-backed)
        .route(
            "/api/v1/users",
            get(routes::config_api::list_users).post(routes::config_api::create_user),
        )
        .route(
            "/api/v1/users/:username",
            put(routes::config_api::update_user).delete(routes::config_api::delete_user),
        )
        .route(
            "/api/v1/dids",
            get(routes::config_api::list_dids).post(routes::config_api::create_did),
        )
        .route(
            "/api/v1/dids/:number",
            delete(routes::config_api::delete_did),
        )
        // Trunks
        .route(
            "/api/v1/trunks",
            get(routes::trunks::list_trunks).post(routes::trunks::create_trunk),
        )
        .route(
            "/api/v1/trunks/:name",
            get(routes::trunks::get_trunk)
                .put(routes::trunks::update_trunk)
                .delete(routes::trunks::delete_trunk),
        )
        .route("/api/v1/trunks/:name/enable", post(routes::trunks::enable_trunk))
        .route("/api/v1/trunks/:name/disable", post(routes::trunks::disable_trunk))
        // Routes (prefix → trunk)
        .route(
            "/api/v1/routes",
            get(routes::trunks::list_routes).post(routes::trunks::create_route),
        )
        .route(
            "/api/v1/routes/:id",
            put(routes::trunks::update_route).delete(routes::trunks::delete_route),
        )
        // ACL
        .route(
            "/api/v1/acl/rules",
            get(routes::acl::list_rules).post(routes::acl::create_rule),
        )
        .route("/api/v1/acl/rules/:id", delete(routes::acl::delete_rule))
        .route(
            "/api/v1/acl/default",
            get(routes::acl::get_default).put(routes::acl::set_default),
        )
        // Config
        .route("/api/v1/reload", post(routes::system::reload))
        .route("/api/v1/config/reload", post(routes::system::reload))
        .route("/api/v1/export", get(routes::config_api::export))
        // Legacy aliases
        .route("/api/calls", get(routes::calls::list_calls))
        .route("/api/registrations", get(routes::calls::list_registrations))
        .route("/api/status", get(routes::system::stats))
        .route("/api/trunks", get(routes::trunks::list_trunks))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        .with_state(state);

    if let Some(cors) = build_cors(cors_allowed_origins) {
        app = app.layer(cors);
    }
    app
}

fn build_cors(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);
    let layer = if origins.iter().any(|o| o == "*") {
        layer.allow_origin(Any)
    } else {
        let parsed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        layer.allow_origin(AllowOrigin::list(parsed))
    };
    Some(layer)
}

/// Constant-time bearer-token check. Accepts `Authorization: Bearer <t>`,
/// `X-Api-Token: <t>`, or `?token=<t>` (for EventSource, which cannot set
/// headers). `/health` and `/ready` stay public.
async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/health" || path == "/ready" {
        return next.run(request).await;
    }

    let Some(expected) = state.api_token.as_deref() else {
        return next.run(request).await;
    };

    let presented = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::to_string)
        .or_else(|| {
            request
                .headers()
                .get("x-api-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .or_else(|| {
            request.uri().query().and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("token=").map(str::to_string))
            })
        });

    let authorized = presented
        .map(|p| p.as_bytes().ct_eq(expected.as_bytes()).into())
        .unwrap_or(false);

    if authorized {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [("content-type", "application/json")],
            r#"{"error":"unauthorized","code":"unauthorized"}"#,
        )
            .into_response()
    }
}

/// Bind and serve until the process exits.
pub async fn serve(
    addr: std::net::SocketAddr,
    state: AppState,
    cors_allowed_origins: Vec<String>,
) -> std::io::Result<()> {
    let app = build_router(state, &cors_allowed_origins);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Management API (axum) listening on http://{}", addr);
    if let Err(e) = axum::serve(listener, app).await {
        warn!("Management API server exited: {}", e);
    }
    Ok(())
}
