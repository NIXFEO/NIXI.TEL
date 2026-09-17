//! Integration tests for the axum management API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sbc_core::acl::AclManager;
use sbc_core::auth::DigestAuthenticator;
use sbc_core::b2bua::B2buaManager;
use sbc_core::events::EventBus;
use sbc_core::media::MediaManager;
use sbc_core::metrics::SbcMetrics;
use sbc_core::register::InMemoryRegistrar;
use sbc_core::routing::TrunkManager;
use sbc_core::storage::CdrManager;
use sbc_management::server::build_router;
use sbc_management::state::AppState;
use sbc_storage::ConfigStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tower::ServiceExt;

const TOKEN: &str = "test-token-123";

async fn make_state() -> AppState {
    let media = Arc::new(MediaManager::with_port_range(20000..20100, None));
    AppState {
        metrics: Arc::new(SbcMetrics::new()),
        b2bua: Arc::new(B2buaManager::new(media)),
        trunks: Arc::new(TrunkManager::new()),
        registrar: Arc::new(InMemoryRegistrar::new()),
        cdr: Arc::new(CdrManager::new_memory()),
        acl: Arc::new(AclManager::new_permissive()),
        auth: Some(Arc::new(DigestAuthenticator::new(
            "sip.example.com",
            HashMap::new(),
        ))),
        dids: Arc::new(RwLock::new(Vec::new())),
        trunk_ips: Arc::new(RwLock::new(Vec::new())),
        store: Some(Arc::new(ConfigStore::open_memory().await.unwrap())),
        events: EventBus::new(),
        reload: Arc::new(Notify::new()),
        realm: "sip.example.com".to_string(),
        api_token: Some(TOKEN.to_string()),
        api_rate_limit_per_min: 0, // disabled for deterministic tests
        security: Arc::new(sbc_core::security::SecurityManager::new(Default::default())),
    }
}

fn req(method: &str, path: &str, body: Option<&str>, with_token: bool) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if with_token {
        builder = builder.header("authorization", format!("Bearer {}", TOKEN));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn health_is_public_and_stats_needs_token() {
    let app = build_router(make_state().await, &[]);

    let resp = app
        .clone()
        .oneshot(req("GET", "/health", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "/health must be public");

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/stats", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .oneshot(req("GET", "/api/v1/stats", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_via_query_param_works_for_sse_use_case() {
    let app = build_router(make_state().await, &[]);
    let resp = app
        .oneshot(req(
            "GET",
            &format!("/api/v1/stats?token={}", TOKEN),
            None,
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn no_token_configured_fails_closed() {
    // Defense in depth: even if the server were somehow started without a
    // token, every non-public route must be denied (never fail open).
    let mut state = make_state().await;
    state.api_token = None;
    let app = build_router(state, &[]);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/stats", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // /health stays public regardless.
    let resp = app
        .oneshot(req("GET", "/health", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limit_returns_429_over_budget() {
    let mut state = make_state().await;
    state.api_rate_limit_per_min = 3; // small budget; oneshot has no ConnectInfo → shared key
    let app = build_router(state, &[]);

    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(req("GET", "/api/v1/stats", None, true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    // 4th request exceeds the per-minute budget.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/stats", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Liveness probes are exempt from the limit.
    let resp = app
        .oneshot(req("GET", "/health", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let app = build_router(make_state().await, &[]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/stats")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_crud_roundtrip_applies_to_auth() {
    let state = make_state().await;
    let auth = state.auth.clone().unwrap();
    let app = build_router(state, &[]);

    // Create
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/users",
            Some(r#"{"username":"alice","password":"pw"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(
        auth.user_exists("alice").await,
        "runtime must see the user immediately"
    );

    // Response must never leak ha1
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/users", None, true))
        .await
        .unwrap();
    let body = body_json(resp).await.to_string();
    assert!(body.contains("alice") && !body.contains("ha1"));

    // Duplicate → 409
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/users",
            Some(r#"{"username":"alice","password":"pw"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Disable via PUT → user leaves auth map
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/users/alice",
            Some(r#"{"enabled":false}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!auth.user_exists("alice").await);

    // Delete
    let resp = app
        .clone()
        .oneshot(req("DELETE", "/api/v1/users/alice", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(req("DELETE", "/api/v1/users/alice", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn trunk_create_full_fields_and_hydration() {
    let state = make_state().await;
    let trunks = state.trunks.clone();
    let app = build_router(state, &[]);

    let body = r#"{
        "name": "pstn-1", "host": "192.0.2.10", "port": 5080, "transport": "TCP",
        "auth_required": true, "username": "u", "password": "p",
        "prefix_patterns": ["+33", "0"], "priority": 10,
        "allowed_codecs": ["PCMU"], "max_concurrent_calls": 42
    }"#;
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/trunks", Some(body), true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The live TrunkManager was hydrated with the full config
    let t = trunks.find_by_name("pstn-1").expect("trunk hydrated");
    assert_eq!(t.port, 5080);
    assert!(t.auth_required);
    assert_eq!(t.max_concurrent_calls, 42);
    assert!(t.prefix_patterns.contains(&"+33".to_string()));

    // Password must be redacted in the API response
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["password"], "***");

    // Invalid transport → 400
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/trunks",
            Some(r#"{"name":"bad","host":"h","transport":"SCTP"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Disable → hydrated
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/trunks/pstn-1/disable", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!trunks.find_by_name("pstn-1").unwrap().enabled);

    // Delete (no active calls) → gone from manager
    let resp = app
        .oneshot(req("DELETE", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(trunks.find_by_name("pstn-1").is_none());
}

#[tokio::test]
async fn routes_crud_merges_into_trunk_prefixes() {
    let state = make_state().await;
    let trunks = state.trunks.clone();
    let app = build_router(state, &[]);

    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/trunks",
            Some(r#"{"name":"t1","host":"192.0.2.20"}"#),
            true,
        ))
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/routes",
            Some(r#"{"prefix":"+1","trunk_name":"t1","priority":5}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["id"].as_i64().unwrap();

    assert!(trunks
        .find_by_name("t1")
        .unwrap()
        .prefix_patterns
        .contains(&"+1".to_string()));

    // Unknown trunk → 400
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/routes",
            Some(r#"{"prefix":"+44","trunk_name":"nope"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .oneshot(req("DELETE", &format!("/api/v1/routes/{}", id), None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn acl_rules_apply_immediately() {
    let state = make_state().await;
    let acl = state.acl.clone();
    let app = build_router(state, &[]);

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/acl/rules",
            Some(r#"{"cidr":"198.51.100.0/24","action":"deny","comment":"scanner"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let check = acl
        .check(
            "198.51.100.9".parse().unwrap(),
            sbc_core::acl::Direction::Inbound,
        )
        .await;
    assert!(!check.is_allowed(), "deny rule must be live immediately");

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/acl/rules/{}", id),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let check = acl
        .check(
            "198.51.100.9".parse().unwrap(),
            sbc_core::acl::Direction::Inbound,
        )
        .await;
    assert!(check.is_allowed(), "rule removal must be live immediately");
}

#[tokio::test]
async fn legacy_aliases_work() {
    let app = build_router(make_state().await, &[]);
    for path in [
        "/api/calls",
        "/api/registrations",
        "/api/status",
        "/api/trunks",
    ] {
        let resp = app
            .clone()
            .oneshot(req("GET", path, None, true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "legacy alias {}", path);
    }
}

#[tokio::test]
async fn export_returns_full_dump() {
    let app = build_router(make_state().await, &[]);
    app.clone()
        .oneshot(req(
            "POST",
            "/api/v1/users",
            Some(r#"{"username":"x","password":"y"}"#),
            true,
        ))
        .await
        .unwrap();

    let resp = app
        .oneshot(req("GET", "/api/v1/export", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["version"], 1);
    assert_eq!(json["users"].as_array().unwrap().len(), 1);
    assert!(json["trunks"].is_array());
}

#[tokio::test]
async fn events_endpoint_is_sse() {
    let state = make_state().await;
    let bus = state.events.clone();
    let app = build_router(state, &[]);

    // Publish after subscribing via the endpoint
    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        bus.publish(sbc_core::events::SbcEvent::CallAnswered {
            uuid: "u1".into(),
            ts: 1,
        });
    });

    let resp = app
        .oneshot(req("GET", "/api/v1/events", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/event-stream"), "content-type: {}", ct);

    // Read the first frame from the stream
    let mut body = resp.into_body().into_data_stream();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        futures_util_next(&mut body).await
    })
    .await
    .expect("first SSE frame within 2s");
    let text = String::from_utf8_lossy(&frame).to_string();
    assert!(
        text.contains("call_answered") || text.contains("keep-alive"),
        "frame: {}",
        text
    );
    handle.await.unwrap();
}

async fn futures_util_next(
    stream: &mut (impl tokio_stream::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
) -> axum::body::Bytes {
    use tokio_stream::StreamExt;
    stream.next().await.unwrap().unwrap()
}

// ── Security / anti-fraud ─────────────────────────────────────────────────────

#[tokio::test]
async fn security_bans_crud_applies_to_the_ban_manager() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/bans",
            Some(r#"{"ip":"not-an-ip"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/bans",
            Some(r#"{"ip":"198.51.100.7","duration_secs":120,"reason":"abuse"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["ip"], "198.51.100.7");
    assert_eq!(body["reason"], "abuse");
    assert_eq!(body["manual"], true);
    assert!(state.security.bans.is_banned(ip), "applied immediately");

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/security/bans", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().map(|a| a.len()), Some(1));
    assert_eq!(list[0]["ip"], "198.51.100.7");

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/security/status", None, true))
        .await
        .unwrap();
    let status = body_json(resp).await;
    assert_eq!(status["bans"]["active"], 1);

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/v1/security/bans/198.51.100.7",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["unbanned"], true);
    assert!(!state.security.bans.is_banned(ip));

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/v1/security/bans/198.51.100.7",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "already unbanned");
}

#[tokio::test]
async fn security_destination_rules_crud() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    // The policy ships with built-in premium-rate prefixes; count relative to them.
    let builtin = state.security.destinations.list_rules().len();

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/destination-rules",
            Some(r#"{"prefix":"+33899","action":"maybe"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "action must be allow|deny"
    );
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/destination-rules",
            Some(r#"{"prefix":"","action":"deny"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "prefix required");

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/destination-rules",
            Some(r#"{"prefix":"+33899","action":"deny","description":"premium rate"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let rule = body_json(resp).await;
    let id = rule["id"].as_str().expect("rule id").to_string();
    assert_eq!(rule["prefix"], "+33899");
    assert_eq!(rule["deny"], true);
    assert_eq!(state.security.destinations.list_rules().len(), builtin + 1);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/security/destination-rules", None, true))
        .await
        .unwrap();
    let list = body_json(resp).await;
    let rules = list["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), builtin + 1);
    let mine = rules
        .iter()
        .find(|r| r["id"] == id.as_str())
        .expect("the new rule is listed");
    assert_eq!(mine["description"], "premium rate");

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/security/destination-rules/{}", id),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(state.security.destinations.list_rules().len(), builtin);

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/security/destination-rules/{}", id),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn security_user_limits_defaults_and_overrides() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);

    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/security/user-limits",
            Some(r#"{"default_max_concurrent_calls":3,"default_max_calls_per_minute":10}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/security/user-limits/alice",
            Some(r#"{"max_concurrent_calls":1}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/security/user-limits", None, true))
        .await
        .unwrap();
    let limits = body_json(resp).await;
    assert_eq!(limits["default_max_concurrent_calls"], 3);
    assert_eq!(limits["default_max_calls_per_minute"], 10);
    let overrides = limits["overrides"].as_array().expect("overrides array");
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0]["user"], "alice");
    assert_eq!(overrides[0]["max_concurrent_calls"], 1);
    assert!(overrides[0]["max_calls_per_minute"].is_null());

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/v1/security/user-limits/alice",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.security.user_limits.overrides().is_empty());

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/v1/security/user-limits/alice",
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── DIDs ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn did_crud_persists_and_applies_to_the_runtime() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/dids",
            Some(r#"{"number":"+33123456789"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "sip_user required");

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/dids",
            Some(r#"{"number":"+33123456789","sip_user":"alice","display_name":"Alice"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(body_json(resp).await["created"], true);
    {
        let dids = state.dids.read().await;
        assert_eq!(dids.len(), 1, "applied to the live DID table");
        assert_eq!(dids[0].number, "+33123456789");
        assert_eq!(dids[0].user, "alice");
        assert_eq!(dids[0].display_name.as_deref(), Some("Alice"));
    }

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/dids",
            Some(r#"{"number":"+33123456789","sip_user":"bob"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "duplicate number");

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/dids", None, true))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert_eq!(list.as_array().map(|a| a.len()), Some(1));
    assert_eq!(list[0]["sip_user"], "alice");
    assert_eq!(list[0]["enabled"], true);

    let resp = app
        .clone()
        .oneshot(req("DELETE", "/api/v1/dids/+33123456789", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.dids.read().await.is_empty());

    let resp = app
        .clone()
        .oneshot(req("DELETE", "/api/v1/dids/+33123456789", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── CDRs and calls ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cdrs_are_paged_and_need_a_token() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    for n in 0..3 {
        state
            .cdr
            .record_call(
                &format!("cid-{}", n),
                "alice",
                "+33612345678",
                10 + n,
                false,
                Some("PCMU"),
                "normal-clearing",
            )
            .await
            .unwrap();
    }

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/cdrs", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/cdrs?limit=2&offset=0", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let page = body_json(resp).await;
    assert_eq!(page["count"], 2);
    assert_eq!(page["limit"], 2);
    assert_eq!(page["has_more"], true);
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["caller"], "alice");
    assert_eq!(items[0]["codec"], "PCMU");
    assert_eq!(items[0]["disconnect_reason"], "normal-clearing");
    assert!(items[0]["trunk_id"].is_null());

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/cdrs?limit=2&offset=2", None, true))
        .await
        .unwrap();
    let page = body_json(resp).await;
    assert_eq!(page["count"], 1);
    assert_eq!(page["has_more"], false);
}

#[tokio::test]
async fn delete_call_tears_it_down_and_releases_media() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    const SDP: &str =
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
    let uuid = state
        .b2bua
        .create_call(
            "cid-kick".to_string(),
            "tag-1".to_string(),
            "10.0.0.5:5060".parse().unwrap(),
            Some(SDP),
            None,
            sbc_core::rsip::Transport::Udp,
        )
        .await
        .unwrap();
    assert_eq!(state.b2bua.active_calls().await.len(), 1);

    let resp = app
        .clone()
        .oneshot(req("DELETE", "/api/v1/calls/does-not-exist", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/calls/{}", uuid),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["terminated"], true);
    assert!(state.b2bua.active_calls().await.is_empty());

    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/calls/{}", uuid),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "gone");
}
