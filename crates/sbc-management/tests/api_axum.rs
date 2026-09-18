//! Integration tests for the axum management API.

use axum::body::Body;
use axum::extract::ConnectInfo;
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
    let metrics = Arc::new(SbcMetrics::new());
    let trunks = Arc::new(TrunkManager::new());
    let events = EventBus::new();
    let trunk_tasks = Arc::new(sbc_core::trunk_tasks::TrunkTasks::new(
        trunks.clone(),
        Default::default(),
        metrics.clone(),
        events.clone(),
        Default::default(),
    ));
    AppState {
        metrics,
        b2bua: Arc::new(B2buaManager::new(media)),
        trunks,
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
        events,
        reload: Arc::new(Notify::new()),
        realm: "sip.example.com".to_string(),
        api_token: Some(TOKEN.to_string()),
        api_rate_limit_per_min: 0, // disabled for deterministic tests
        security: Arc::new(sbc_core::security::SecurityManager::new(Default::default())),
        kicks: Arc::new(sbc_core::sbc::AdminKicks::new()),
        trunk_tasks,
        ready: Arc::new(sbc_core::sbc::Readiness::new()),
        runtime_config: Arc::new(sbc_core::sbc::runtime_config::RuntimeConfig::new(
            sbc_core::config::SbcConfig::default(),
            None,
        )),
        backup: Arc::new(sbc_core::sbc::backup::BackupPolicy {
            dir: std::env::temp_dir().join(format!("sbc-api-backups-{}", uuid::Uuid::new_v4())),
            interval: None,
            keep: 2,
        }),
        backup_lock: Arc::new(tokio::sync::Mutex::new(())),
        trusted_proxies: Arc::new(sbc_management::rate_limit::default_trusted_proxies()),
        ban_on_auth_failure: true,
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
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("60"),
        "429 tells the client when to come back"
    );

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
    assert_eq!(json["version"], 2);
    assert!(json["destination_rules"].is_array());
    assert!(json["user_limits"].is_object());
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

    // Creating again with the same id is a conflict and does not overwrite.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/security/destination-rules",
            Some(&format!(
                r#"{{"id":"{}","prefix":"+1900","action":"allow"}}"#,
                id
            )),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let stored = state
        .store
        .as_ref()
        .unwrap()
        .list_destination_rules()
        .await
        .unwrap();
    let row = stored.iter().find(|r| r.id == id).expect("rule row");
    assert_eq!(
        (row.prefix.as_str(), row.action.as_str()),
        ("+33899", "deny")
    );
    // Persisted, and the runtime now mirrors the store (the built-in seeds
    // are written to the store at first boot in production; this test store
    // was never seeded, so the store's single rule is the whole policy).
    let stored = state
        .store
        .as_ref()
        .unwrap()
        .list_destination_rules()
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, id);
    assert_eq!(stored[0].action, "deny");
    let live = state.security.destinations.list_rules();
    assert_eq!(live.len(), 1, "store is the source of truth: {:?}", live);
    let _ = builtin;

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/security/destination-rules", None, true))
        .await
        .unwrap();
    let list = body_json(resp).await;
    let rules = list["rules"].as_array().expect("rules array");
    let fresh = sbc_core::security::SecurityManager::new(Default::default());
    sbc_core::sbc::hydrate::apply_destinations(&fresh, state.store.as_ref().unwrap())
        .await
        .unwrap();
    assert!(
        fresh.destinations.list_rules().iter().any(|r| r.id == id),
        "a fresh runtime hydrated from the store gets the rule back"
    );
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
    assert!(state
        .store
        .as_ref()
        .unwrap()
        .list_destination_rules()
        .await
        .unwrap()
        .is_empty());
    assert!(!state
        .security
        .destinations
        .list_rules()
        .iter()
        .any(|r| r.id == id));

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

    // Overrides live on the user row: an unknown user is 404.
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/security/user-limits/nobody",
            Some(r#"{"max_concurrent_calls":1}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
    let store = state.store.clone().unwrap();

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
    assert_eq!(
        store
            .get_setting(sbc_core::sbc::hydrate::SETTING_DEFAULT_CONCURRENT)
            .await
            .unwrap()
            .as_deref(),
        Some("3"),
        "defaults are persisted"
    );

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
    let row = store.get_user("alice").await.unwrap().unwrap();
    assert_eq!(row.max_concurrent_calls, None, "cleared on the user row");

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

    // Limits set through the user API are enforced too (same row, same
    // hydration), and a fresh runtime hydrated from the store sees them.
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/users/alice",
            Some(r#"{"password":"pw","max_calls_per_minute":4}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        state.security.user_limits.limits_for("alice"),
        (3, 4),
        "defaults from settings, cpm from the user row"
    );
    let fresh = sbc_core::security::SecurityManager::new(Default::default());
    sbc_core::sbc::hydrate::apply_user_limits(&fresh, &store)
        .await
        .unwrap();
    assert_eq!(fresh.user_limits.limits_for("alice"), (3, 4));
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
async fn delete_call_queues_an_admin_kick_for_the_engine() {
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
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(resp).await["terminating"], true);
    // The API has no SIP transport: the engine drains this queue and ends
    // the call on the wire (BYE both legs, CDR admin-kick).
    assert_eq!(state.kicks.pending(), vec![uuid.clone()]);
    assert_eq!(
        state.b2bua.active_calls().await.len(),
        1,
        "still present until the engine processes the kick"
    );

    // A second request is idempotent (queued once).
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
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(state.kicks.pending().len(), 1);
}

#[tokio::test]
async fn cdrs_expose_the_billing_window_newest_first() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let t0 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for (n, answered) in [(1u64, true), (2, false)] {
        let mut r = sbc_core::storage::CdrRecord::new(
            format!("cid-{}", n),
            "alice".into(),
            "+33612345678".into(),
        )
        .with_window(
            t0 + std::time::Duration::from_secs(n * 100),
            answered.then_some(t0 + std::time::Duration::from_secs(n * 100 + 5)),
            t0 + std::time::Duration::from_secs(n * 100 + 65),
        )
        .with_disconnect_reason(if answered {
            "normal-clearing"
        } else {
            "cancelled"
        });
        r.uuid = format!("u{}", n);
        r.direction = "outbound".into();
        r.sip_code = Some(if answered { 200 } else { 487 });
        r.source_ip = "10.0.0.9".into();
        state.cdr.insert(&r).await.unwrap();
    }

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/cdrs?limit=10", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_json(resp).await;
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["call_id"], "cid-2", "newest first");
    assert_eq!(items[0]["v"], 2);
    assert_eq!(items[0]["sip_code"], 487);
    assert!(items[0]["answered_at"].is_null());
    assert_eq!(items[0]["billable_secs"], 0);
    assert_eq!(items[0]["duration_secs"], 65);
    assert_eq!(items[1]["call_id"], "cid-1");
    assert_eq!(items[1]["answered_at"], 1_700_000_105u64);
    assert_eq!(items[1]["billable_secs"], 60);
    assert_eq!(items[1]["direction"], "outbound");
    assert_eq!(items[1]["uuid"], "u1");
    assert_eq!(items[1]["source_ip"], "10.0.0.9");
    assert_eq!(items[1]["disconnect_reason"], "normal-clearing");
}

#[tokio::test]
async fn trunk_patch_merges_and_the_masked_password_is_refused() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/trunks",
            Some(r#"{"name":"t1","host":"203.0.113.9","username":"u","password":"s3cret","auth_required":true}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let store = state.store.clone().unwrap();

    // GET masks the secret; writing that shape back is refused.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/t1", None, true))
        .await
        .unwrap();
    let shown = body_json(resp).await;
    assert_eq!(shown["password"], "***");
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            "/api/v1/trunks/t1",
            Some(&shown.to_string()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "masked password");
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/t1",
            Some(r#"{"password":"***"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        store
            .get_trunk("t1")
            .await
            .unwrap()
            .unwrap()
            .password
            .as_deref(),
        Some("s3cret"),
        "untouched"
    );

    // PATCH changes only what it names.
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/t1",
            Some(r#"{"port":5062,"priority":10}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = store.get_trunk("t1").await.unwrap().unwrap();
    assert_eq!(row.port, 5062);
    assert_eq!(row.priority, 10);
    assert_eq!(row.password.as_deref(), Some("s3cret"), "kept");
    assert_eq!(row.username.as_deref(), Some("u"));
    assert!(row.auth_required);

    // GET-only keys are refused rather than ignored.
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/t1",
            Some(r#"{"tls":{"verify":false}}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // null clears a nullable field (RFC 7396).
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/t1",
            Some(r#"{"username":null}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(store.get_trunk("t1").await.unwrap().unwrap().username, None);

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/nope",
            Some(r#"{"port":1}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn user_patch_keeps_the_password_and_the_other_fields() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/users",
            Some(r#"{"username":"alice","password":"pw","display_name":"Alice","max_concurrent_calls":2}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let store = state.store.clone().unwrap();
    let before = store.get_user("alice").await.unwrap().unwrap();

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/users/alice",
            Some(r#"{"enabled":false}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let after = store.get_user("alice").await.unwrap().unwrap();
    assert!(!after.enabled);
    assert_eq!(after.ha1, before.ha1, "password untouched");
    assert_eq!(after.display_name.as_deref(), Some("Alice"));
    assert_eq!(after.max_concurrent_calls, Some(2), "limits untouched");

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/users/alice",
            Some(r#"{"password":"new"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rotated = store.get_user("alice").await.unwrap().unwrap();
    assert_ne!(rotated.ha1, before.ha1, "password rotated");
    assert!(!rotated.enabled, "other fields still untouched");

    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/users/alice",
            Some(r#"{"realm":"x"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "realm is not settable"
    );
}

/// A brute force on the bearer token is treated like a SIP password guess:
/// the client's IP is banned (API and SIP) after the fail2ban threshold.
#[tokio::test]
async fn bearer_token_brute_force_bans_the_client_ip() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let attacker: std::net::SocketAddr = "198.51.100.7:45000".parse().unwrap();
    let from = |r: Request<Body>, peer: std::net::SocketAddr| {
        let mut r = r;
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    };

    let mut banned = false;
    for _ in 0..25 {
        let resp = app
            .clone()
            .oneshot(from(req("GET", "/api/v1/stats", None, false), attacker))
            .await
            .unwrap();
        if resp.status() == StatusCode::FORBIDDEN {
            banned = true;
            break;
        }
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(banned, "repeated token failures ban the IP");
    assert!(state.security.bans.is_banned(attacker.ip()));

    // A valid token is still served from the banned IP (the ban stops the
    // guessing, not the operator whose NAT got struck)…
    let resp = app
        .clone()
        .oneshot(from(req("GET", "/api/v1/stats", None, true), attacker))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid token is never locked out"
    );
    // …another IP is served, and the probes are public.
    let resp = app
        .clone()
        .oneshot(from(
            req("GET", "/api/v1/stats", None, true),
            "203.0.113.5:1".parse().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(from(req("GET", "/health", None, false), attacker))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "/health stays reachable");

    // Headers from an untrusted peer cannot shift the blame onto someone else.
    let mut spoof = req("GET", "/api/v1/stats", None, false);
    spoof
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.99".parse().unwrap());
    let spoof = from(spoof, attacker);
    let resp = app.clone().oneshot(spoof).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "still the attacker");
    assert!(!state
        .security
        .bans
        .is_banned("203.0.113.99".parse().unwrap()));
}

/// Every trunk write re-syncs the per-trunk OPTIONS / REGISTER tasks:
/// created → started, credentials changed → restarted, disabled → stopped,
/// deleted → gone. `registered` is exposed for trunks that register.
#[tokio::test]
async fn trunk_mutations_drive_the_task_registry() {
    let state = make_state().await;
    let tasks = state.trunk_tasks.clone();
    assert!(tasks.attach_socket(
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        None
    ));
    let app = build_router(state, &[]);

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/trunks",
            Some(r#"{"name":"pstn-1","host":"127.0.0.1","port":5999,"transport":"UDP"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let running = tasks.running();
    assert_eq!(running.len(), 1, "{:?}", running);
    assert_eq!(
        (running[0].name.as_str(), running[0].registers),
        ("pstn-1", false)
    );
    let g1 = running[0].generation;

    // No registration → `registered` is null.
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    assert!(body_json(resp).await["registered"].is_null());

    // Credentials + register flag: the tasks restart with a register loop.
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/pstn-1",
            Some(r#"{"username":"u","password":"p","register_with_trunk":true}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let running = tasks.running();
    assert_eq!(running.len(), 1);
    assert!(running[0].generation > g1, "restarted: {:?}", running);
    assert!(running[0].registers);
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["registered"], false);

    // A field outside the task spec does not restart them.
    let g2 = running[0].generation;
    let resp = app
        .clone()
        .oneshot(req(
            "PATCH",
            "/api/v1/trunks/pstn-1",
            Some(r#"{"priority":7}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(tasks.running()[0].generation, g2);

    // Disabled → stopped; enabled → started again; deleted → gone.
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/trunks/pstn-1/disable", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(tasks.running().is_empty());
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/trunks/pstn-1/enable", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(tasks.running().len(), 1);
    let resp = app
        .clone()
        .oneshot(req("DELETE", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(tasks.running().is_empty());
    tasks.shutdown().await;
}

/// `health` follows the router's view (parked / down only while it skips
/// the trunk), `/alerts` and `/metrics` expose availability, and a
/// re-enable forgives the park.
#[tokio::test]
async fn trunk_health_alerts_and_metrics_reflect_availability() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/trunks",
            Some(r#"{"name":"pstn-1","host":"127.0.0.1","port":5998,"transport":"UDP"}"#),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // The trunk answered 503 Retry-After: 120 → parked.
    assert!(state
        .trunks
        .update_state_by_name("pstn-1", |s| s.park_for(120)));
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["health"], "parked");
    assert!(json["unavailable_for_secs"].as_u64().unwrap() > 100);
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/alerts", None, true))
        .await
        .unwrap();
    assert!(body_json(resp).await.to_string().contains("trunk_parked"));
    let resp = app
        .clone()
        .oneshot(req("GET", "/metrics", None, true))
        .await
        .unwrap();
    let text = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        text.contains("sbc_trunk_enabled{trunk=\"pstn-1\"} 1\n"),
        "{}",
        text
    );
    assert!(
        text.contains("sbc_trunk_available{trunk=\"pstn-1\"} 0\n"),
        "{}",
        text
    );
    assert!(text.contains("# TYPE sbc_trunk_calls_total counter\n"));

    // Disable + enable: the park is forgiven.
    for action in ["disable", "enable"] {
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/trunks/pstn-1/{}", action),
                None,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/trunks/pstn-1", None, true))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["health"], "up");
    assert!(json["unavailable_for_secs"].is_null());
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/alerts", None, true))
        .await
        .unwrap();
    assert!(!body_json(resp).await.to_string().contains("trunk_parked"));
    state.trunk_tasks.shutdown().await;
}

/// `/ready` is public and answers 503 with the three flags until the store
/// is open, hydrated and the listeners are bound.
#[tokio::test]
async fn ready_is_503_until_store_hydrate_and_listeners() {
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);
    let resp = app
        .clone()
        .oneshot(req("GET", "/ready", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "not_ready");
    assert_eq!(json["store"], false);
    state.ready.set_store_open();
    state.ready.set_hydrated();
    let resp = app
        .clone()
        .oneshot(req("GET", "/ready", None, false))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "listeners not bound yet"
    );
    state.ready.set_listening();
    let resp = app
        .oneshot(req("GET", "/ready", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ready");
    assert!(json["store"] == true && json["hydrated"] == true && json["listening"] == true);
}

/// `POST /api/v1/backup` writes a copy, prunes to `keep`, needs the token,
/// refuses a concurrent run and 503s without a store.
#[tokio::test]
async fn backup_endpoint_writes_prunes_and_needs_a_token() {
    let mut state = make_state().await;
    // A file-backed store: VACUUM INTO needs a real database.
    let dir = state
        .backup
        .dir
        .parent()
        .unwrap()
        .join(format!("sbc-api-live-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    state.store = Some(Arc::new(
        ConfigStore::open(dir.join("live.db").to_str().unwrap())
            .await
            .unwrap(),
    ));
    let app = build_router(state.clone(), &[]);

    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/backup", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let mut paths = Vec::new();
    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(req("POST", "/api/v1/backup", None, true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["bytes"].as_u64().unwrap() > 0);
        assert!(json["took_ms"].is_u64());
        paths.push(json["path"].as_str().unwrap().to_string());
    }
    let files: Vec<_> = std::fs::read_dir(&state.backup.dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 2, "keep 2: {:?}", files);
    assert!(
        !std::path::Path::new(&paths[0]).exists(),
        "the oldest was pruned"
    );

    // A held lock (the timer is running) → 409.
    let guard = state.backup_lock.lock().await;
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/backup", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    drop(guard);

    // No store → 503.
    let mut no_store = state.clone();
    no_store.store = None;
    let resp = build_router(no_store, &[])
        .oneshot(req("POST", "/api/v1/backup", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&state.backup.dir);
}

// ── GET /api/v1/config, POST /api/v1/reload ──────────────────────────────────

#[tokio::test]
async fn config_endpoint_masks_secrets_and_needs_a_token() {
    let mut state = make_state().await;
    let mut cfg = sbc_core::config::SbcConfig::default();
    cfg.management.api_auth_token = Some("tok-secret-1".into());
    cfg.security
        .sip_users
        .insert("alice".into(), "pw-secret-1".into());
    cfg.trunks
        .push(toml::from_str("name = \"t\"\nhost = \"h\"\npassword = \"pw-secret-2\"\n").unwrap());
    state.runtime_config = Arc::new(sbc_core::sbc::runtime_config::RuntimeConfig::new(cfg, None));
    let app = build_router(state, &[]);
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/v1/config", None, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app
        .oneshot(req("GET", "/api/v1/config", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["running"]["management"]["api_auth_token"], "***");
    assert_eq!(json["running"]["security"]["sip_users"]["alice"], "***");
    assert_eq!(json["running"]["trunks"][0]["password"], "***");
    assert!(!json.to_string().contains("secret"));
    assert!(json["file"].is_null(), "no path set");
    assert_eq!(json["loaded_by"], "boot");
    assert!(json["key_classes"]["reload"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k == "security.ban."));
}

#[tokio::test]
async fn config_endpoint_diffs_the_file_against_the_running_values() {
    let state = make_state().await;
    let dir = std::env::temp_dir().join(format!("sbc-cfg-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sbc.toml");
    let mut on_disk = sbc_core::config::SbcConfig::default();
    on_disk.security.max_call_duration += 100;
    on_disk.management.api_port += 1;
    std::fs::write(&path, toml::to_string(&on_disk).unwrap()).unwrap();
    state
        .runtime_config
        .set_path(path.to_string_lossy().into_owned());
    let app = build_router(state, &[]);

    let json = body_json(
        app.clone()
            .oneshot(req("GET", "/api/v1/config", None, true))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(json["file"]["readable"], true);
    assert_eq!(
        json["file"]["reload_pending"],
        serde_json::json!(["security.max_call_duration"])
    );
    assert_eq!(
        json["file"]["restart_required"],
        serde_json::json!(["management.api_port"])
    );

    std::fs::write(&path, "this = is not [ toml").unwrap();
    let json = body_json(
        app.clone()
            .oneshot(req("GET", "/api/v1/config", None, true))
            .await
            .unwrap(),
    )
    .await;
    assert!(json["file"]["parse_error"].is_string());

    std::fs::remove_file(&path).unwrap();
    let json = body_json(
        app.oneshot(req("GET", "/api/v1/config", None, true))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(json["file"]["readable"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reload_returns_the_engine_report() {
    use sbc_core::sbc::runtime_config::{ReloadReport, ReloadSource};
    let state = make_state().await;
    let app = build_router(state.clone(), &[]);

    // A fake engine: on notify, record an ok report.
    let engine = state.clone();
    tokio::spawn(async move {
        engine.reload.notified().await;
        engine.runtime_config.record_reload(
            ReloadReport {
                ts: 1,
                source: ReloadSource::Api,
                ok: true,
                error: None,
                applied: vec!["security.rtp_timeout".into()],
                restart_required: vec![],
                hydrated: true,
            },
            Some(sbc_core::config::SbcConfig::default()),
        );
        engine.reload.notified().await;
        engine.runtime_config.record_reload(
            ReloadReport {
                ts: 2,
                source: ReloadSource::Api,
                ok: false,
                error: Some("Failed to parse config: boom".into()),
                applied: vec![],
                restart_required: vec![],
                hydrated: false,
            },
            None,
        );
    });
    let resp = app
        .clone()
        .oneshot(req("POST", "/api/v1/reload", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "reloaded");
    assert_eq!(json["applied"], serde_json::json!(["security.rtp_timeout"]));
    let resp = app
        .oneshot(req("POST", "/api/v1/config/reload", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = body_json(resp).await;
    assert_eq!(json["code"], "reload_failed");
    assert!(json["error"].as_str().unwrap().contains("boom"));
}

#[tokio::test]
async fn reload_without_an_engine_answers_202() {
    let state = make_state().await;
    let app = build_router(state, &[]);
    // Paused time: the 5 s wait for the engine elapses instantly.
    tokio::time::pause();
    let resp = app
        .oneshot(req("POST", "/api/v1/reload", None, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(resp).await["status"], "reload_triggered");
}
