//! Axum management server — replaces the hand-rolled http_server.
//!
//! - proper HTTP/1.1 with keep-alive and body limits
//! - constant-time bearer-token auth (skips /health and /ready)
//! - configurable CORS
//! - SSE event stream at /api/v1/events

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use crate::rate_limit::{client_ip_with, RateLimiter};
use crate::routes;
use crate::state::AppState;

const BODY_LIMIT_BYTES: usize = 256 * 1024;

pub fn build_router(state: AppState, cors_allowed_origins: &[String]) -> Router {
    let rate_limiter = RateLimitState {
        limiter: RateLimiter::per_minute(state.api_rate_limit_per_min),
        trusted: state.trusted_proxies.clone(),
    };
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
        .route(
            "/api/v1/registrations",
            get(routes::calls::list_registrations),
        )
        // CDRs
        .route("/api/v1/cdrs", get(routes::calls::list_cdrs))
        // Users / DIDs (SQLite-backed)
        .route(
            "/api/v1/users",
            get(routes::config_api::list_users).post(routes::config_api::create_user),
        )
        .route(
            "/api/v1/users/:username",
            put(routes::config_api::update_user)
                .patch(routes::config_api::patch_user)
                .delete(routes::config_api::delete_user),
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
                .patch(routes::trunks::patch_trunk)
                .delete(routes::trunks::delete_trunk),
        )
        .route(
            "/api/v1/trunks/:name/enable",
            post(routes::trunks::enable_trunk),
        )
        .route(
            "/api/v1/trunks/:name/disable",
            post(routes::trunks::disable_trunk),
        )
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
        // Security / anti-fraud
        .route(
            "/api/v1/security/bans",
            get(routes::security::list_bans).post(routes::security::create_ban),
        )
        .route(
            "/api/v1/security/bans/:ip",
            delete(routes::security::delete_ban),
        )
        .route(
            "/api/v1/security/destination-rules",
            get(routes::security::list_destination_rules)
                .post(routes::security::create_destination_rule),
        )
        .route(
            "/api/v1/security/destination-rules/:id",
            delete(routes::security::delete_destination_rule),
        )
        .route(
            "/api/v1/security/user-limits",
            get(routes::security::get_user_limits).put(routes::security::set_default_limits),
        )
        .route(
            "/api/v1/security/user-limits/:user",
            put(routes::security::set_user_limits).delete(routes::security::delete_user_limits),
        )
        .route("/api/v1/security/status", get(routes::security::status))
        // Config
        .route("/api/v1/reload", post(routes::system::reload))
        .route("/api/v1/config/reload", post(routes::system::reload))
        .route("/api/v1/config", get(routes::system::get_config))
        .route("/api/v1/tls/certificates", get(routes::tls::certificates))
        .route("/api/v1/tls/reload", post(routes::tls::reload))
        .route("/api/v1/export", get(routes::config_api::export))
        .route("/api/v1/backup", post(routes::store::backup))
        // Legacy aliases
        .route("/api/calls", get(routes::calls::list_calls))
        .route("/api/registrations", get(routes::calls::list_registrations))
        .route("/api/status", get(routes::system::stats))
        .route("/api/trunks", get(routes::trunks::list_trunks))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        // The import takes a whole export document: its own, larger limit
        // (axum's 2 MB default on `Json` must be raised too).
        .merge(
            Router::new()
                .route("/api/v1/import", post(routes::store::import))
                .layer(DefaultBodyLimit::max(
                    routes::store::IMPORT_BODY_LIMIT_BYTES,
                ))
                .layer(RequestBodyLimitLayer::new(
                    routes::store::IMPORT_BODY_LIMIT_BYTES,
                )),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        // Rate-limit is outermost so it runs first, before auth and handlers.
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .with_state(state);

    if let Some(cors) = build_cors(cors_allowed_origins) {
        app = app.layer(cors);
    }
    app
}

/// Per-source-IP rate limit. Requests over budget get `429`, with the
/// offending IP logged at `warn`. `/health` and `/ready` are exempt so
/// liveness probes never trip it.
#[derive(Clone)]
struct RateLimitState {
    limiter: RateLimiter,
    trusted: Arc<Vec<std::net::IpAddr>>,
}

async fn rate_limit_middleware(
    State(rl): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/health" || path == "/ready" {
        return next.run(request).await;
    }

    let ip = client_ip_with(&request, &rl.trusted);
    if rl.limiter.check(ip) {
        next.run(request).await
    } else {
        warn!(
            source_ip = %ip,
            method = %request.method(),
            path = %request.uri().path(),
            "management API rate limit exceeded"
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("content-type", "application/json"), ("retry-after", "60")],
            r#"{"error":"rate limit exceeded","code":"too_many_requests","retry_after_secs":60}"#,
        )
            .into_response()
    }
}

fn build_cors(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers(Any);
    let layer = if origins.iter().any(|o| o == "*") {
        layer.allow_origin(Any)
    } else {
        let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        layer.allow_origin(AllowOrigin::list(parsed))
    };
    Some(layer)
}

/// Constant-time bearer-token check. Accepts `Authorization: Bearer <t>`,
/// `X-Api-Token: <t>`, or `?token=<t>` (for EventSource, which cannot set
/// headers). `/health` and `/ready` stay public.
async fn auth_middleware(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path == "/health" || path == "/ready" {
        return next.run(request).await;
    }

    let source_ip = client_ip_with(&request, &state.trusted_proxies);
    let method = request.method().clone();

    // fail2ban state of this IP (SIP or API abuse); applied AFTER the
    // token check: a valid token proves the caller is not the guesser, and
    // an operator whose office NAT got a SIP ban (a mis-provisioned phone,
    // or a spoofed-UDP attack) must still reach the API — it is the tool
    // that lifts bans. Unauthenticated requests from a banned IP get 403.
    let banned = !source_ip.is_unspecified() && state.security.bans.is_banned(source_ip);
    // Mutations get audited even on success; reads only when auth fails.
    let is_mutation = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );

    // Defense in depth: the binary refuses to start without a resolved token
    // (see sbc-bin/main.rs), so this arm should be unreachable in production.
    // If it is ever reached, fail CLOSED rather than fail open.
    let Some(expected) = state.api_token.as_deref() else {
        warn!(
            source_ip = %source_ip,
            method = %method,
            path = %path,
            auth = "denied",
            "management API request rejected: no api_token configured (fail-closed)"
        );
        return unauthorized();
    };

    let presented = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
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

    let path = path.to_string();
    if authorized {
        if banned {
            warn!(
                source_ip = %source_ip,
                method = %method,
                path = %path,
                auth = "ok_from_banned_ip",
                "management API request with a valid token from an IP fail2ban banned"
            );
        }
        if is_mutation {
            info!(
                source_ip = %source_ip,
                method = %method,
                path = %path,
                auth = "ok",
                "management API mutation"
            );
        }
        next.run(request).await
    } else {
        if banned {
            warn!(
                source_ip = %source_ip,
                method = %method,
                path = %path,
                auth = "banned",
                "management API request from a banned IP without a valid token"
            );
            return forbidden_banned();
        }
        warn!(
            source_ip = %source_ip,
            method = %method,
            path = %path,
            auth = "denied",
            "management API authentication failed"
        );
        // A brute force on the token is an attack like a SIP password
        // guess: same window, same ban (SIP and API).
        if state.ban_on_auth_failure && !source_ip.is_unspecified() {
            if let Some(entry) = state.security.record_auth_failure(source_ip, None, "API") {
                state.metrics.inc_security_ban();
                if let Some(store) = state.store.clone() {
                    let row = sbc_storage::BanRow {
                        ip: entry.ip.to_string(),
                        reason: entry.reason.clone(),
                        banned_at: crate::routes::security::rfc3339(entry.banned_at),
                        expires_at: crate::routes::security::rfc3339(entry.expires_at),
                        failures: entry.failures as i64,
                        manual: entry.manual,
                        offense_count: entry.offense_count as i64,
                    };
                    tokio::spawn(async move {
                        if let Err(e) = store.save_ban(&row).await {
                            warn!("Ban persistence failed for {}: {}", row.ip, e);
                        }
                    });
                }
            }
        }
        unauthorized()
    }
}

fn forbidden_banned() -> Response {
    (
        StatusCode::FORBIDDEN,
        [("content-type", "application/json")],
        r#"{"error":"banned","code":"forbidden"}"#,
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("content-type", "application/json")],
        r#"{"error":"unauthorized","code":"unauthorized"}"#,
    )
        .into_response()
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
    // `ConnectInfo` makes the TCP peer address available to the rate-limit and
    // audit middleware (used when no X-Real-IP / X-Forwarded-For is present).
    let make_service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    if let Err(e) = axum::serve(listener, make_service).await {
        warn!("Management API server exited: {}", e);
    }
    Ok(())
}
