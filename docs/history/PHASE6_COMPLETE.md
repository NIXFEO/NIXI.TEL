# Phase 6 — WebSocket, HTTP Server, CDR, DoS — COMPLETE

**Date** : 18 février 2026
**Serveur** : 51.158.117.229 (sip.nixi.tel)
**Tests** : 239/239 ✅ (+40 Phase 6)

---

## Résumé

Phase 6 ajoute la couche d'infrastructure réseau et de persistance :
- **WebSocket/WSS** — Transport SIP over WebSocket (RFC 7118) pour navigateurs WebRTC
- **HTTP Server** — Vrai serveur HTTP pour REST API et Prometheus (sans framework externe lourd)
- **CDR Storage** — Enregistrement des appels (en mémoire + structure PostgreSQL prête)
- **DoS Protection** — Token bucket par IP avec blacklist automatique

Total Phase 6 : **+40 tests** (6 ws + 12 http + 13 storage + 12 dos)
Total cumulatif : **239 tests, 0 échec**

---

## 1. WebSocket/WSS Transport (ws.rs) — 6 tests

### RFC 7118

SIP over WebSocket permet aux navigateurs web de se connecter directement au SBC sans plugin.

Sub-protocol IANA : `sip` (négocié via `Sec-WebSocket-Protocol: sip`)

### Architecture

```
Browser WebRTC ──WSS:8443──► WsListenerServer
                              │  accept_hdr_async (TLS first, then WS upgrade)
                              │  Sec-WebSocket-Protocol: sip ✓
                              ▼
                         process_ws_messages()
                              │  Text/Binary → parse SIP
                              │  Ping → Pong (keepalive)
                              │  Close → disconnect
                              ▼
                         ReceivedMessage → TransportManager channel
```

### API

```rust
pub struct WsListenerServer { ... }

impl WsListenerServer {
    pub async fn new_ws(bind_addr: SocketAddr) -> Result<Self>
    pub async fn new_wss(addr, cert_path, key_path) -> Result<Self>
    pub fn is_secure(&self) -> bool
    pub async fn listen(self, tx: mpsc::UnboundedSender<ReceivedMessage>) -> Result<()>
}
```

### Intégration TransportManager

```rust
// Avant (Phase 5) :
TransportType::WSS => {
    info!("WebSocket transport not yet implemented...");
}

// Après (Phase 6) :
TransportType::WS  => { self.start_ws_listener(config, false).await?; }
TransportType::WSS => { self.start_ws_listener(config, true).await?; }
```

### Démarrage confirmé sur nixi.tel

```
INFO WSS listener bound to 0.0.0.0:8443
INFO Started WSS listener on 0.0.0.0:8443
INFO Starting WSS listener on 0.0.0.0:8443
```

Port 8443 actif : `tcp LISTEN 0.0.0.0:8443` ✅

---

## 2. HTTP Server (http_server.rs) — 12 tests

### Design

Serveur HTTP/1.1 minimal sans dépendances lourdes (pas d'axum dans le runtime).
Écoute sur `127.0.0.1:8080` (non exposé publiquement).

### Fonctionnalités

- Parsing HTTP/1.1 brut (méthode, path, headers, body)
- Authentification par token (`Authorization:` ou `X-Api-Token:`)
- Délègue le routing à `ApiRouter` (Phase 5)
- CORS headers (`Access-Control-Allow-Origin: *`)
- Content-Type correct : `text/plain` pour `/metrics`, `application/json` sinon

### Configuration

```rust
pub struct HttpServerConfig {
    pub bind_address: SocketAddr,   // 127.0.0.1:8080
    pub auth_token: Option<String>, // token API optionnel
    pub cors_enabled: bool,
}

HttpServerConfig::new("127.0.0.1:8080".parse().unwrap())
    .with_token("my-secret-token".to_string())
```

### Utilisation

```rust
let server = HttpServer::new(config, metrics, b2bua, trunks);
server.start().await?;  // démarre en arrière-plan (tokio::spawn)
```

---

## 3. CDR Storage (storage.rs) — 13 tests

### Architecture trait-based

```rust
#[async_trait]
pub trait CdrStorage: Send + Sync {
    async fn insert_cdr(&self, record: &CdrRecord) -> Result<()>;
    async fn get_cdr(&self, call_id: &str) -> Result<Option<CdrRecord>>;
    async fn list_recent_cdrs(&self, limit: usize) -> Result<Vec<CdrRecord>>;
    async fn stats(&self) -> StorageStats;
}
```

Deux implémentations :
- `InMemoryCdrStorage` — pour dev/tests (pas de dépendance DB)
- `PostgresCdrStorage` — pour production (génère SQL correct, délègue à InMemory en attendant sqlx complet)

### CdrRecord

```rust
pub struct CdrRecord {
    pub id: String,             // UUID
    pub call_id: String,        // SIP Call-ID
    pub caller: String,         // From URI
    pub callee: String,         // To URI
    pub trunk_id: Option<String>,
    pub duration_secs: u64,
    pub codec: Option<String>,  // PCMU, PCMA, Opus...
    pub is_webrtc: bool,
    pub disconnect_reason: String,
    pub started_at: u64,        // Unix timestamp
    pub ended_at: u64,
}
```

### CdrManager

```rust
let mgr = CdrManager::new_memory();

// Enregistrer un appel terminé
mgr.record_call(
    "call-id-001",
    "sip:alice@nixi.tel",
    "sip:bob@example.com",
    duration_secs: 300,
    is_webrtc: false,
    codec: Some("PCMU"),
    reason: "normal",
).await?;

// Récupérer l'historique
let json = mgr.recent_to_json(100).await;
```

### SQL PostgreSQL généré

```sql
INSERT INTO cdr (id, call_id, caller, callee, duration_secs, is_webrtc,
                 disconnect_reason, started_at, ended_at)
VALUES ('uuid', 'call-001', 'alice', 'bob', 300, false, 'normal',
        to_timestamp(1737000000), to_timestamp(1737000300))
```

---

## 4. DoS Protection (dos.rs) — 12 tests

### Token Bucket Algorithm

```
Chaque IP a un "seau" de tokens :
- Capacité max = burst_size (ex: 100 tokens)
- Recharge = requests_per_second tokens/seconde
- Chaque requête consomme 1 token
- Si seau vide → violation
- N violations → blacklist temporaire
```

### Configuration prédéfinie

```rust
// Production (défaut)
RateLimitConfig::default()
// → 50 req/s, burst 100, blacklist 5min après 10 violations

// Strict (anti-DoS aggressif)
RateLimitConfig::strict()
// → 10 req/s, burst 20, blacklist 10min après 5 violations

// Permissif (dev/test)
RateLimitConfig::permissive()
// → 200 req/s, burst 500, blacklist 1min après 50 violations
```

### Usage

```rust
let protector = DosProtector::new(RateLimitConfig::default());

// Vérifier une IP
match protector.check_addr(peer_addr).await {
    RateLimitResult::Allowed => { /* process */ }
    RateLimitResult::Whitelisted => { /* always allow */ }
    RateLimitResult::RateLimited { violations } => {
        // Send 429 Too Many Requests
    }
    RateLimitResult::Blacklisted { remaining_secs } => {
        // Send 403 Forbidden
    }
}

// Blacklister manuellement
protector.blacklist_ip(ip, 3600).await;  // 1 heure

// Stats
let stats = protector.stats().await;
// DosStats { total_allowed: 1000, total_blocked: 5, blacklisted_ips: 1 }
```

### Whitelist

```rust
let trusted_ips = vec![
    "10.0.0.1".parse().unwrap(),  // réseau interne
    "192.168.1.1".parse().unwrap(), // gateway
];
let protector = DosProtector::new_with_whitelist(config, trusted_ips);
```

---

## Tests Phase 6 — 40/40 ✅

```
test transport::ws::tests::test_ws_listener_creation ... ok
test transport::ws::tests::test_ws_listener_port_allocated ... ok
test transport::ws::tests::test_ws_listener_not_secure ... ok
test transport::ws::tests::test_wss_needs_cert_files ... ok
test transport::ws::tests::test_parse_and_forward_valid_options ... ok
test transport::ws::tests::test_parse_and_forward_invalid_sip ... ok

test http_server::tests::test_http_response_format ... ok
test http_server::tests::test_http_response_content_length ... ok
test http_server::tests::test_extract_body_crlf ... ok
test http_server::tests::test_extract_body_lf ... ok
test http_server::tests::test_extract_body_empty ... ok
test http_server::tests::test_status_text_codes ... ok
test http_server::tests::test_http_server_config_default ... ok
test http_server::tests::test_http_server_config_with_token ... ok
test http_server::tests::test_http_server_binds ... ok
test http_server::tests::test_http_server_with_auth_config ... ok

test storage::tests::test_cdr_record_creation ... ok
test storage::tests::test_cdr_record_with_duration ... ok
test storage::tests::test_cdr_record_to_json ... ok
test storage::tests::test_in_memory_storage_insert_and_get ... ok
test storage::tests::test_in_memory_storage_not_found ... ok
test storage::tests::test_in_memory_storage_list_recent ... ok
test storage::tests::test_in_memory_storage_stats ... ok
test storage::tests::test_postgres_storage_invalid_url ... ok
test storage::tests::test_postgres_storage_valid_url ... ok
test storage::tests::test_mask_password ... ok
test storage::tests::test_cdr_manager_record_call ... ok
test storage::tests::test_cdr_manager_recent_json ... ok

test dos::tests::test_dos_allows_normal_traffic ... ok
test dos::tests::test_dos_blocks_excessive_traffic ... ok
test dos::tests::test_dos_blacklists_after_violations ... ok
test dos::tests::test_whitelist_always_allowed ... ok
test dos::tests::test_manual_blacklist ... ok
test dos::tests::test_manual_unblacklist ... ok
test dos::tests::test_different_ips_independent ... ok
test dos::tests::test_dos_stats ... ok
test dos::tests::test_blacklisted_ips_list ... ok
test dos::tests::test_check_addr_with_socket_addr ... ok
test dos::tests::test_rate_limit_config_strict ... ok
test dos::tests::test_rate_limit_config_permissive ... ok

test result: ok. 239 passed; 0 failed; 0 ignored
```

---

## Ports actifs en production (nixi.tel)

```
udp  0.0.0.0:5060   SIP UDP
tcp  0.0.0.0:5060   SIP TCP
tcp  0.0.0.0:5061   SIP TLS
tcp  0.0.0.0:8443   WebRTC WSS  ← NOUVEAU Phase 6
```

---

## Prochaine étape : Phase 7

| Composant | Description |
|-----------|-------------|
| Transcoding audio | Opus↔G.711 (PCMU/PCMA), G.729 |
| Topology hiding réel | Remplacement Via/Contact/Record-Route |
| Registration | REGISTER → base PostgreSQL |
| ACL IP dynamique | Règles firewall depuis la config |
| TLS client | Connexions sortantes vers trunks TLS |
| Clustering | Multiple instances SBC actif/actif |
