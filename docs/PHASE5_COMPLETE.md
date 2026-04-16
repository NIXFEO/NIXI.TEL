# Phase 5 — B2BUA, Auth, REST API, Métriques — COMPLETE

**Date** : 18 février 2026
**Serveur** : 51.158.117.229 (sip.nixi.tel)
**Tests** : 199/199 ✅

---

## Résumé

La Phase 5 implémente la couche de gestion complète du SBC :
- **B2BUA** — Back-to-Back User Agent avec state machine complète
- **SIP Digest Authentication** — RFC 7616, MD5 pur Rust sans dépendance externe
- **REST API** — Interface de gestion HTTP légère
- **Prometheus Metrics** — Export de métriques au format standard

Total Phase 5 : **+38 tests** (8 + 15 + 10 + 12)
Total cumulatif : **199 tests, 0 échec**

---

## 1. B2BUA (b2bua.rs) — 8 tests

### Concept

Le B2BUA (Back-to-Back User Agent) gère deux legs SIP indépendants :
- **Inbound** : Le SBC agit en tant que UAS (répond à l'appelant)
- **Outbound** : Le SBC agit en tant que UAC (appelle la destination)

Cette architecture permet la **topology hiding** (masquage de la topologie interne).

### State machine

```
Initiated → Proceeding → Ringing → Connected → Terminating → Terminated
```

### Structures principales

```rust
pub enum CallState {
    Initiated, Proceeding, Ringing, Connected, Terminating, Terminated
}

pub struct CallLeg {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: Option<String>,
    pub remote_addr: SocketAddr,
    pub cseq: u32,
    pub established: bool,
}

pub struct B2buaCall {
    pub uuid: CallUuid,
    pub inbound: CallLeg,
    pub outbound: Option<CallLeg>,
    pub state: CallState,
    pub caller_is_webrtc: bool,
    pub caller_sdp: Option<String>,
    pub callee_sdp: Option<String>,
    pub media_session_id: Option<String>,
    pub started_at: Instant,
}
```

### API publique

```rust
impl B2buaManager {
    pub async fn create_call(inbound_call_id, tag, addr, sdp) -> Result<CallUuid>
    pub async fn attach_outbound(uuid, call_id, tag, addr) -> Result<()>
    pub async fn handle_ringing(uuid) -> Result<()>          // 180 Ringing
    pub async fn handle_200_ok(uuid, tag, sdp) -> Result<()> // 200 OK
    pub async fn handle_ack(uuid) -> Result<()>              // ACK → Connected
    pub async fn handle_bye(uuid) -> Result<()>              // BYE → Terminating
    pub async fn terminate_call(uuid)                        // cleanup
    pub async fn find_by_inbound_call_id(call_id) -> Option<CallUuid>
    pub async fn stats() -> B2buaStats
    pub async fn active_calls() -> Vec<CallSnapshot>
}
```

### Tests (8/8)

| Test | Description |
|------|-------------|
| `test_create_call` | Création d'un appel B2BUA |
| `test_call_state_progression` | Transition Initiated→Proceeding→Ringing→Connected |
| `test_bye_terminates_call` | BYE → Terminating → cleanup |
| `test_find_by_inbound_call_id` | Lookup par Call-ID entrant |
| `test_multiple_concurrent_calls` | 5 appels simultanés |
| `test_webrtc_call_detected` | Détection WebRTC via SDP profile SAVPF |
| `test_active_calls_snapshot` | Snapshot des appels actifs |
| `test_call_duration` | Durée calculée depuis `started_at` |

**Correction appliquée** : deadlock tokio `Mutex` — le lock `calls` était maintenu lors de l'appel à `stats()` qui tentait de l'acquérir à nouveau. Fix : bloc `{}` pour libérer explicitement avant `stats()`.

---

## 2. SIP Digest Authentication (auth.rs) — 15 tests

### RFC 7616 / RFC 2617

Implémentation complète de l'authentification SIP Digest sans dépendance externe :
- MD5 pur Rust (RFC 1321) — tables S et K codées en dur
- HA1 = MD5(username:realm:password)
- HA2 = MD5(method:uri)
- response = MD5(HA1:nonce:HA2) ou MD5(HA1:nonce:nc:cnonce:qop:HA2)

### Fonctions cryptographiques

```rust
pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String
pub fn compute_ha2(method: &str, uri: &str) -> String
pub fn compute_response(ha1: &str, nonce: &str, ha2: &str) -> String
pub fn compute_response_auth(ha1, nonce, nc, cnonce, ha2) -> String
```

### Authenticator

```rust
pub struct DigestAuthenticator {
    pub realm: String,
    nonces: Arc<Mutex<HashMap<String, NonceRecord>>>,  // TTL 300s
    nonce_ttl: u64,
    users: Arc<HashMap<String, String>>,  // username → HA1 (pré-hashé)
}

impl DigestAuthenticator {
    // Génère: Digest realm="...", nonce="...", qop=auth, algorithm=MD5
    pub async fn generate_challenge(&self) -> String

    // Parse le header Authorization, vérifie nonce + response
    // Retourne Ok(username) ou Err(...)
    pub async fn verify(&self, auth_header: &str, method: &str) -> Result<String>

    pub async fn cleanup_nonces(&self)    // expire les nonces > TTL
    pub async fn active_nonces(&self) -> usize
}
```

### Tests (15/15)

| Test | Description |
|------|-------------|
| `test_md5_known_vectors` | Vecteurs RFC 1321 |
| `test_ha1_computation` | HA1 = MD5(user:realm:pass) |
| `test_ha2_computation` | HA2 = MD5(method:uri) |
| `test_response_computation` | response = MD5(HA1:nonce:HA2) |
| `test_response_with_qop` | response avec qop=auth, nc, cnonce |
| `test_digest_credentials_parse` | Parse "Digest username=...nonce=..." |
| `test_credentials_missing_field` | Erreur si champ manquant |
| `test_authenticator_challenge` | Format du challenge généré |
| `test_authenticator_verify_valid` | Vérification correcte |
| `test_authenticator_wrong_password` | Rejet mauvais mot de passe |
| `test_authenticator_invalid_nonce` | Rejet nonce invalide |
| `test_authenticator_expired_nonce` | Rejet nonce expiré (TTL) |
| `test_nonce_ttl` | Cleanup automatique |
| `test_multiple_users` | Base d'utilisateurs multiples |
| `test_prehashed_ha1` | Stockage HA1 pré-hashé (pas les mots de passe) |

---

## 3. Prometheus Metrics (metrics.rs) — 10 tests

### Compteurs et jauges

```rust
pub struct SbcMetrics {
    // Compteurs SIP
    pub sip_requests_total: Arc<AtomicU64>,
    pub sip_requests_by_method: Arc<Mutex<HashMap<String, u64>>>,
    pub sip_responses_total: Arc<AtomicU64>,
    pub sip_4xx_total: Arc<AtomicU64>,
    pub sip_5xx_total: Arc<AtomicU64>,

    // Appels
    pub calls_total: Arc<AtomicU64>,
    pub calls_connected_total: Arc<AtomicU64>,
    pub calls_failed_total: Arc<AtomicU64>,
    pub calls_terminated_total: Arc<AtomicU64>,

    // Sécurité
    pub auth_challenges_total: Arc<AtomicU64>,
    pub auth_failures_total: Arc<AtomicU64>,

    // Média
    pub rtp_packets_total: Arc<AtomicU64>,
    pub srtp_encrypted_total: Arc<AtomicU64>,

    // Jauges
    pub active_calls: Arc<AtomicU64>,
    pub active_webrtc_calls: Arc<AtomicU64>,
    pub allocated_ports: Arc<AtomicU64>,

    pub start_time: u64,
}
```

### Format Prometheus

```
# HELP sbc_sip_requests_total Total SIP requests received
# TYPE sbc_sip_requests_total counter
sbc_sip_requests_total 42

# HELP sbc_active_calls Currently active calls
# TYPE sbc_active_calls gauge
sbc_active_calls 3

# HELP sbc_uptime_seconds SBC uptime in seconds
# TYPE sbc_uptime_seconds gauge
sbc_uptime_seconds 3600
```

### Health checks

```rust
pub enum HealthStatus {
    Healthy,
    Degraded(String),   // active_calls > 8000
    Unhealthy(String),  // active_calls > 9500
}

pub struct HealthReport {
    pub status: HealthStatus,
    pub uptime_secs: u64,
    pub active_calls: u64,
    pub checks: Vec<HealthCheck>,
}
```

### Tests (10/10)

| Test | Description |
|------|-------------|
| `test_metrics_creation` | Initialisation à zéro |
| `test_sip_request_counting` | Comptage par méthode |
| `test_call_lifecycle_metrics` | total, connected, terminated |
| `test_auth_metrics` | challenges + failures |
| `test_rtp_metrics` | paquets RTP + SRTP |
| `test_gauge_metrics` | active_calls gauge |
| `test_prometheus_format` | Sortie text/plain valide |
| `test_health_healthy` | Statut healthy |
| `test_health_degraded` | > 8000 appels → degraded |
| `test_uptime` | uptime_secs correct |

---

## 4. REST API (api.rs) — 12 tests

### Routes disponibles

| Méthode | Path | Description |
|---------|------|-------------|
| GET | `/health` | Health check JSON |
| GET | `/ready` | Readiness (200 si healthy/degraded) |
| GET | `/metrics` | Prometheus text format |
| GET | `/api/v1/calls` | Liste des appels actifs |
| GET | `/api/v1/stats` | Statistiques SIP/appels |
| GET | `/api/v1/trunks` | Liste des trunks |
| POST | `/api/v1/trunks` | Créer un trunk |

### Réponses JSON

```json
// GET /health
{"status":"healthy","uptime_secs":3600,"active_calls":0}

// GET /api/v1/stats
{
  "sip_requests_total": 42,
  "sip_responses_total": 41,
  "calls_total": 10,
  "calls_connected": 8,
  "calls_failed": 2,
  "active_calls": 0,
  "active_webrtc_calls": 0,
  "auth_challenges": 5,
  "auth_failures": 1
}

// GET /api/v1/calls
[{"uuid":"...","state":"connected","call_id":"...","caller":"sip:alice@..."}]

// POST /api/v1/trunks
{"id":"uuid","name":"Trunk-1","host":"sip.example.com","port":5060}
```

### Tests (12/12)

| Test | Description |
|------|-------------|
| `test_health_endpoint` | GET /health → 200 + JSON |
| `test_ready_endpoint` | GET /ready → 200 |
| `test_metrics_endpoint` | GET /metrics → Prometheus format |
| `test_calls_empty` | GET /api/v1/calls → [] |
| `test_calls_with_data` | GET /api/v1/calls → liste |
| `test_stats_endpoint` | GET /api/v1/stats → JSON complet |
| `test_trunks_list_empty` | GET /api/v1/trunks → [] |
| `test_create_trunk` | POST /api/v1/trunks → 201 |
| `test_create_trunk_invalid` | POST body invalide → 400 |
| `test_unknown_route` | GET /unknown → 404 |
| `test_method_not_allowed` | DELETE /health → 405 |
| `test_api_router_creation` | Instanciation correcte |

---

## Résultats finaux Phase 5

```
running 199 tests
...
test result: ok. 199 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Répartition complète

| Phase | Module | Tests |
|-------|--------|-------|
| 1 | transport (UDP/TCP/TLS) | 23 |
| 2 | transaction, timers | 14 |
| 2 | dialog | 8 |
| 2 | routing | 6 |
| 2 | maintenance, config | 7 |
| 3 | media (RTP, SDP, ports) | 29 |
| 4 | srtp_crypto | 11 |
| 4 | stun | 8 |
| 4 | ice | 14 |
| 4 | dtls | 6 |
| 4 | turn | 8 |
| 4 | webrtc_handler | 12 |
| 5 | b2bua | 8 |
| 5 | auth | 15 |
| 5 | metrics | 10 |
| 5 | api | 12 |
| **TOTAL** | | **199** |

---

## Déploiement production

Phase 5 déployée le **18 février 2026** sur `51.158.117.229` (nixi.tel) :

```
● sbc.service - SBC W3tel - Session Border Controller
   Active: active (running)
   Ports: UDP:5060, TCP:5060, TLS:5061
   Certif: sip.nixi.tel (valide jusqu'au 19 mai 2026)
```

---

## Prochaine étape : Phase 6

| Composant | Description |
|-----------|-------------|
| WebSocket/WSS transport | Support navigateurs WebRTC |
| HTTP server (axum) | REST API exposée via vrai serveur HTTP |
| Prometheus endpoint | `/metrics` sur port dédié |
| PostgreSQL CDR | Enregistrement des appels en base |
| DoS protection | Rate limiting par IP en temps réel |
| Topology hiding | Masquage complet des en-têtes internes |
