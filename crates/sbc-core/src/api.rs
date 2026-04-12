//! REST API Management Interface
//!
//! HTTP endpoints for SBC management and monitoring.
//! Built with lightweight hand-rolled HTTP for zero extra deps (axum is in workspace
//! but only used in sbc-management crate). This module provides the route logic
//! that can be wired into any HTTP framework.

use crate::b2bua::{B2buaManager, CallSnapshot};
use crate::metrics::{HealthReport, SbcMetrics};
use crate::register::Registrar;
use crate::routing::trunk::TrunkManager;
use crate::storage::CdrManager;
use std::sync::Arc;
use tokio::sync::Notify;

/// Supported HTTP response content types
#[derive(Debug, Clone, Copy)]
pub enum ContentType {
    Json,
    PlainText,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json      => "application/json",
            Self::PlainText => "text/plain; version=0.0.4",
        }
    }
}

/// Minimal HTTP response (body + status + content-type)
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub content_type: ContentType,
    pub body: String,
}

impl ApiResponse {
    pub fn ok_json(body: impl Into<String>) -> Self {
        Self { status: 200, content_type: ContentType::Json, body: body.into() }
    }

    pub fn ok_text(body: impl Into<String>) -> Self {
        Self { status: 200, content_type: ContentType::PlainText, body: body.into() }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: ContentType::Json,
            body: r#"{"error": "Not found"}"#.to_string(),
        }
    }

    pub fn internal_error(msg: impl std::fmt::Display) -> Self {
        Self {
            status: 500,
            content_type: ContentType::Json,
            body: format!(r#"{{"error": "{}"}}"#, msg),
        }
    }
}

/// SBC API router
///
/// Holds references to all subsystems needed to serve API requests.
pub struct ApiRouter {
    metrics:       Arc<SbcMetrics>,
    b2bua:         Arc<B2buaManager>,
    trunks:        Arc<TrunkManager>,
    pub registrar: Option<Arc<dyn Registrar>>,
    pub reload_notify: Option<Arc<Notify>>,
    pub cdr: Option<Arc<CdrManager>>,
}

impl ApiRouter {
    pub fn new(
        metrics: Arc<SbcMetrics>,
        b2bua:   Arc<B2buaManager>,
        trunks:  Arc<TrunkManager>,
    ) -> Self {
        Self { metrics, b2bua, trunks, registrar: None, reload_notify: None, cdr: None }
    }

    pub fn with_reload_notify(mut self, notify: Arc<Notify>) -> Self {
        self.reload_notify = Some(notify);
        self
    }

    pub fn with_registrar(mut self, registrar: Arc<dyn Registrar>) -> Self {
        self.registrar = Some(registrar);
        self
    }

    /// Route an HTTP request and return a response
    ///
    /// `method` : "GET", "POST", "DELETE", …
    /// `path`   : "/health", "/metrics", "/api/v1/calls", …
    /// `body`   : request body (for POST/PUT)
    pub async fn handle(&self, method: &str, path: &str, body: &str) -> ApiResponse {
        match (method, path) {
            // Health & readiness
            ("GET",  "/health")                    => self.health().await,
            ("GET",  "/ready")                     => self.ready().await,
            ("GET",  "/metrics")                   => self.prometheus_metrics(),

            // API v1
            ("GET",  "/api/v1/calls")              => self.list_calls().await,
            ("GET",  "/api/v1/registrations")      => self.list_registrations().await,
            ("GET",  "/api/v1/stats")              => self.stats().await,
            ("GET",  "/api/v1/trunks")             => self.list_trunks().await,
            ("POST", "/api/v1/trunks")             => self.create_trunk(body).await,
            ("POST", "/api/v1/reload")             => self.reload_config().await,
            ("GET",  "/api/v1/cdrs")               => self.list_cdrs().await,
            ("GET",  "/api/v1/alerts")              => self.alerts().await,

            // Legacy routes (convenience aliases)
            ("GET",  "/api/calls")                 => self.list_calls().await,
            ("GET",  "/api/registrations")         => self.list_registrations().await,
            ("GET",  "/api/status")                => self.stats().await,
            ("GET",  "/api/trunks")                => self.list_trunks().await,

            _                                      => ApiResponse::not_found(),
        }
    }

    // ── Health / Readiness ─────────────────────────────────────────────────────

    async fn health(&self) -> ApiResponse {
        let report = HealthReport::from_metrics(&self.metrics);
        let status = if report.status.is_ok() { 200 } else { 503 };
        ApiResponse {
            status,
            content_type: ContentType::Json,
            body: report.to_json(),
        }
    }

    async fn ready(&self) -> ApiResponse {
        // Simple readiness: always ready if process is up
        ApiResponse::ok_json(r#"{"status": "ready"}"#)
    }

    // ── Prometheus metrics ─────────────────────────────────────────────────────

    fn prometheus_metrics(&self) -> ApiResponse {
        ApiResponse::ok_text(self.metrics.render_prometheus())
    }

    // ── Calls ──────────────────────────────────────────────────────────────────

    async fn list_calls(&self) -> ApiResponse {
        let calls = self.b2bua.active_calls().await;
        let json = calls_to_json(&calls);
        ApiResponse::ok_json(json)
    }

    // ── Registrations ────────────────────────────────────────────────────────

    async fn list_registrations(&self) -> ApiResponse {
        let registrar = match &self.registrar {
            Some(r) => r,
            None => return ApiResponse::ok_json(r#"{"error": "registrar not configured", "registrations": []}"#),
        };
        match registrar.all_registrations().await {
            Ok(regs) => {
                let items: Vec<String> = regs.iter().map(|r| {
                    format!(
                        r#"{{"aor": "{}", "contact": "{}", "expires_in": {}, "transport": "{}", "received_ip": "{}", "received_port": {}, "user_agent": {}}}"#,
                        r.aor,
                        r.contact,
                        r.remaining_secs(),
                        r.transport,
                        r.received_ip,
                        r.received_port,
                        r.user_agent.as_ref()
                            .map(|ua| format!("\"{}\"", ua))
                            .unwrap_or_else(|| "null".to_string()),
                    )
                }).collect();
                ApiResponse::ok_json(format!("[{}]", items.join(", ")))
            }
            Err(e) => ApiResponse::internal_error(e),
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    async fn stats(&self) -> ApiResponse {
        let b2bua_stats = self.b2bua.stats().await;
        let body = format!(
            r#"{{"active_calls": {}, "connected": {}, "ringing": {}, "webrtc_calls": {}, "sip_requests_total": {}, "calls_total": {}, "uptime_seconds": {}}}"#,
            b2bua_stats.total_active,
            b2bua_stats.connected,
            b2bua_stats.ringing,
            b2bua_stats.webrtc_calls,
            self.metrics.sip_requests_total.load(std::sync::atomic::Ordering::Relaxed),
            self.metrics.calls_total.load(std::sync::atomic::Ordering::Relaxed),
            self.metrics.uptime_secs(),
        );
        ApiResponse::ok_json(body)
    }

    // ── Reload ─────────────────────────────────────────────────────────────────

    async fn reload_config(&self) -> ApiResponse {
        match &self.reload_notify {
            Some(notify) => {
                notify.notify_one();
                ApiResponse::ok_json(r#"{"status": "reload_triggered"}"#)
            }
            None => ApiResponse::internal_error("reload not available"),
        }
    }

    // ── CDRs ───────────────────────────────────────────────────────────────────

    async fn list_cdrs(&self) -> ApiResponse {
        match &self.cdr {
            Some(cdr) => {
                let json = cdr.recent_to_json(100).await;
                ApiResponse::ok_json(json)
            }
            None => ApiResponse::ok_json("[]"),
        }
    }

    // ── Alerts ────────────────────────────────────────────────────────────────

    async fn alerts(&self) -> ApiResponse {
        let mut alerts: Vec<String> = Vec::new();

        // Check trunk health
        let stats = self.trunks.get_stats();
        for (t, s) in &stats {
            if s.consecutive_failures >= 3 {
                alerts.push(format!(
                    r#"{{"level":"critical","type":"trunk_down","trunk":"{}","failures":{}}}"#,
                    t.name, s.consecutive_failures
                ));
            }
        }

        // Check auth failure rate
        let auth_failures = self.metrics.auth_failures_total.load(std::sync::atomic::Ordering::Relaxed);
        let auth_challenges = self.metrics.auth_challenges_total.load(std::sync::atomic::Ordering::Relaxed);
        if auth_challenges > 10 && auth_failures as f64 / auth_challenges as f64 > 0.5 {
            alerts.push(format!(
                r#"{{"level":"warning","type":"high_auth_failure_rate","failures":{},"challenges":{}}}"#,
                auth_failures, auth_challenges
            ));
        }

        // Check call failure rate
        let calls_total = self.metrics.calls_total.load(std::sync::atomic::Ordering::Relaxed);
        let calls_failed = self.metrics.calls_failed_total.load(std::sync::atomic::Ordering::Relaxed);
        if calls_total > 5 && calls_failed as f64 / calls_total as f64 > 0.5 {
            alerts.push(format!(
                r#"{{"level":"warning","type":"high_call_failure_rate","failed":{},"total":{}}}"#,
                calls_failed, calls_total
            ));
        }

        ApiResponse::ok_json(format!("[{}]", alerts.join(",")))
    }

    // ── Trunks ─────────────────────────────────────────────────────────────────

    async fn list_trunks(&self) -> ApiResponse {
        let stats = self.trunks.get_stats();
        let items: Vec<String> = stats.iter().map(|(t, s)| {
            let health = if s.consecutive_failures == 0 {
                "up"
            } else if s.disabled_until.is_some() {
                "down"
            } else {
                "degraded"
            };
            format!(
                r#"{{"id": "{}", "name": "{}", "host": "{}", "port": {}, "enabled": {}, "health": "{}", "active_calls": {}, "total_calls": {}, "failed_calls": {}, "consecutive_failures": {}}}"#,
                t.id, t.name, t.host, t.port, t.enabled, health,
                s.active_calls, s.total_calls, s.failed_calls, s.consecutive_failures
            )
        }).collect();
        ApiResponse::ok_json(format!("[{}]", items.join(", ")))
    }

    async fn create_trunk(&self, body: &str) -> ApiResponse {
        // Very minimal JSON parsing (no external JSON parser to keep deps lean)
        // Expected: {"id":"trunk1","host":"1.2.3.4","port":5060}
        let id   = extract_json_string(body, "id");
        let host = extract_json_string(body, "host");
        let port = extract_json_number(body, "port").unwrap_or(5060);

        let (id, host) = match (id, host) {
            (Some(i), Some(h)) => (i, h),
            _ => return ApiResponse {
                status: 400,
                content_type: ContentType::Json,
                body: r#"{"error": "Missing required fields: id, host"}"#.to_string(),
            },
        };

        use crate::routing::trunk::{TrunkConfig, TransportType};
        use uuid::Uuid;
        let config = TrunkConfig {
            id: Uuid::new_v4(),
            name: id.clone(),
            host: host.clone(),
            port,
            transport: TransportType::Udp,
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            allowed_codecs: vec!["PCMU".to_string(), "PCMA".to_string()],
            transcoding_enabled: false,
            max_concurrent_calls: 100,
            calls_per_second: 10,
            allowed_ips: vec![],
            register_with_trunk: false,
            registration_interval: std::time::Duration::from_secs(60),
            enabled: true,
            cost_per_minute: 0,
            priority: 100,
            weight: 100,
            prefix_patterns: Vec::new(),
            resolved_addr: None,
            number_format: crate::routing::trunk::NumberFormat::E164,
            country_code: None,
            national_prefix: None,
            caller_number_format: None,
            caller_number_override: None,
            caller_display_name: None,
        };

        self.trunks.add_trunk(config);

        ApiResponse {
            status: 201,
            content_type: ContentType::Json,
            body: format!(r#"{{"id": "{}", "host": "{}", "port": {}, "created": true}}"#, id, host, port),
        }
    }
}

// ── JSON helpers ───────────────────────────────────────────────────────────────

/// Extract a string field from a minimal JSON object (no nested objects)
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

/// Extract a numeric field from a minimal JSON object
fn extract_json_number(json: &str, key: &str) -> Option<u16> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Serialize a list of CallSnapshots to JSON
fn calls_to_json(calls: &[CallSnapshot]) -> String {
    let items: Vec<String> = calls.iter().map(|c| {
        let callee = c.callee_addr.as_deref()
            .map(|a| format!("\"{}\"", a))
            .unwrap_or_else(|| "null".to_string());
        let media = c.media_session_id.as_deref()
            .map(|m| format!("\"{}\"", m))
            .unwrap_or_else(|| "null".to_string());
        format!(
            r#"{{"uuid": "{}", "state": "{}", "call_id": "{}", "caller": "{}", "callee": {}, "duration_secs": {}, "webrtc": {}, "media_session": {}}}"#,
            c.uuid, c.state, c.inbound_call_id, c.caller_addr,
            callee, c.duration_secs, c.is_webrtc, media
        )
    }).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::MediaManager;

    fn make_router() -> ApiRouter {
        let metrics = Arc::new(SbcMetrics::new());
        let media   = Arc::new(MediaManager::with_port_range(20000..30000, None));
        let b2bua   = Arc::new(B2buaManager::new(media));
        let trunks  = Arc::new(TrunkManager::new());
        ApiRouter::new(metrics, b2bua, trunks)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let router = make_router();
        let resp = router.handle("GET", "/health", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"status\""));
        assert!(resp.body.contains("healthy"));
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        let router = make_router();
        let resp = router.handle("GET", "/ready", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("ready"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let router = make_router();
        let resp = router.handle("GET", "/metrics", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("sbc_uptime_seconds"));
        assert!(resp.body.contains("sbc_active_calls"));
    }

    #[tokio::test]
    async fn test_list_calls_empty() {
        let router = make_router();
        let resp = router.handle("GET", "/api/v1/calls", "").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "[]");
    }

    #[tokio::test]
    async fn test_list_calls_with_active() {
        let router = make_router();
        let caller: std::net::SocketAddr = "192.168.1.1:5060".parse().unwrap();
        router.b2bua.create_call("cid-1".to_string(), "t".to_string(), caller, None, None, rsip::Transport::Udp).await.unwrap();

        let resp = router.handle("GET", "/api/v1/calls", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("cid-1"));
        assert!(resp.body.contains("proceeding"));
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let router = make_router();
        router.metrics.inc_sip_request("INVITE");
        router.metrics.inc_call_attempted();

        let resp = router.handle("GET", "/api/v1/stats", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"sip_requests_total\": 1"));
        assert!(resp.body.contains("\"calls_total\": 1"));
    }

    #[tokio::test]
    async fn test_list_trunks_empty() {
        let router = make_router();
        let resp = router.handle("GET", "/api/v1/trunks", "").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "[]");
    }

    #[tokio::test]
    async fn test_create_trunk() {
        let router = make_router();
        let body = r#"{"id": "trunk1", "host": "192.168.1.100", "port": 5060}"#;
        let resp = router.handle("POST", "/api/v1/trunks", body).await;
        assert_eq!(resp.status, 201);
        assert!(resp.body.contains("trunk1"));
        assert!(resp.body.contains("192.168.1.100"));

        // Trunk should now appear in list
        let list_resp = router.handle("GET", "/api/v1/trunks", "").await;
        assert!(list_resp.body.contains("trunk1"));
    }

    #[tokio::test]
    async fn test_create_trunk_missing_fields() {
        let router = make_router();
        let body = r#"{"id": "trunk-x"}"#; // missing host
        let resp = router.handle("POST", "/api/v1/trunks", body).await;
        assert_eq!(resp.status, 400);
        assert!(resp.body.contains("error"));
    }

    #[tokio::test]
    async fn test_not_found() {
        let router = make_router();
        let resp = router.handle("GET", "/api/v1/does-not-exist", "").await;
        assert_eq!(resp.status, 404);
    }

    // ── Registrations endpoint ───────────────────────────────────────

    fn make_router_with_registrar() -> ApiRouter {
        use crate::register::InMemoryRegistrar;
        let metrics = Arc::new(SbcMetrics::new());
        let media   = Arc::new(MediaManager::with_port_range(20000..30000, None));
        let b2bua   = Arc::new(B2buaManager::new(media));
        let trunks  = Arc::new(TrunkManager::new());
        let registrar: Arc<dyn crate::register::Registrar> = Arc::new(InMemoryRegistrar::new());
        ApiRouter::new(metrics, b2bua, trunks).with_registrar(registrar)
    }

    #[tokio::test]
    async fn test_registrations_empty() {
        let router = make_router_with_registrar();
        let resp = router.handle("GET", "/api/v1/registrations", "").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "[]");
    }

    #[tokio::test]
    async fn test_registrations_with_active() {
        use crate::register::{InMemoryRegistrar, Registration};
        let metrics = Arc::new(SbcMetrics::new());
        let media   = Arc::new(MediaManager::with_port_range(20000..30000, None));
        let b2bua   = Arc::new(B2buaManager::new(media));
        let trunks  = Arc::new(TrunkManager::new());
        let registrar = Arc::new(InMemoryRegistrar::new());

        // Register a user
        let reg = Registration::new(
            "sip:alice@sip.example.com".to_string(),
            "sip:alice@192.168.1.50:5060".to_string(),
            3600,
            "call-id-reg-1".to_string(),
            1,
            "192.168.1.50:5060".parse().unwrap(),
            "UDP",
        );
        registrar.register(reg).await.unwrap();

        let registrar_trait: Arc<dyn crate::register::Registrar> = registrar;
        let router = ApiRouter::new(metrics, b2bua, trunks).with_registrar(registrar_trait);

        let resp = router.handle("GET", "/api/v1/registrations", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("alice"), "Should contain registered user: {}", resp.body);
        assert!(resp.body.contains("192.168.1.50"), "Should contain contact IP");
        assert!(resp.body.contains("UDP"), "Should contain transport");
    }

    #[tokio::test]
    async fn test_registrations_no_registrar() {
        // Router without registrar should return graceful response
        let router = make_router();
        let resp = router.handle("GET", "/api/v1/registrations", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("not configured"));
    }

    // ── Legacy routes ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_legacy_route_calls() {
        let router = make_router();
        let resp = router.handle("GET", "/api/calls", "").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "[]");
    }

    #[tokio::test]
    async fn test_legacy_route_status() {
        let router = make_router();
        let resp = router.handle("GET", "/api/status", "").await;
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("active_calls"));
    }

    #[tokio::test]
    async fn test_legacy_route_registrations() {
        let router = make_router_with_registrar();
        let resp = router.handle("GET", "/api/registrations", "").await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "[]");
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"id": "abc", "host": "1.2.3.4"}"#;
        assert_eq!(extract_json_string(json, "id"),   Some("abc".to_string()));
        assert_eq!(extract_json_string(json, "host"), Some("1.2.3.4".to_string()));
        assert_eq!(extract_json_string(json, "nope"), None);
    }

    #[test]
    fn test_extract_json_number() {
        let json = r#"{"port": 5060, "other": 1234}"#;
        assert_eq!(extract_json_number(json, "port"),  Some(5060));
        assert_eq!(extract_json_number(json, "other"), Some(1234));
        assert_eq!(extract_json_number(json, "none"),  None);
    }
}
