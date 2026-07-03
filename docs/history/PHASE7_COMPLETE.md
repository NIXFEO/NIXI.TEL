# Phase 7 — Transcoding, Topology Hiding, REGISTER, TLS Client, ACL

## Statut : ✅ TERMINÉ

**Tests : 336 / 336** (239 → 336 : +97 nouveaux tests)

---

## Modules implémentés

### 1. `transcoding.rs` — Audio Opus ↔ G.711 (20 tests)

Transcoding audio pur Rust sans FFI.

| Codec | PT | Fréquence | Standard |
|-------|----|-----------|----------|
| PCMU  |  0 | 8 kHz     | ITU-T G.711 µ-law |
| PCMA  |  8 | 8 kHz     | ITU-T G.711 A-law |
| Opus  | 111 (dynamic) | 48 kHz | RFC 6716 |

**Fonctionnalités :**
- `pcmu_encode_sample` / `pcmu_decode_sample` — G.711 µ-law
- `pcma_encode_sample` / `pcma_decode_sample` — G.711 A-law
- `downsample_48k_to_8k` / `upsample_8k_to_48k` — Resampling 6:1
- `Transcoder::transcode()` — Conversion PCMU↔PCMA, PCMU↔Opus, PCMA↔Opus
- `sdp_prefer_codec()` / `sdp_audio_pts()` — Réécriture SDP
- `build_g711_sdp()` / `build_opus_sdp()` — Builders SDP

```rust
let t = Transcoder::new(Codec::Pcmu, Codec::Pcma);
let pcmu_payload = pcmu_encode(&pcm_samples);
let pcma_payload = t.transcode(&pcmu_payload)?;
```

---

### 2. `topology.rs` — Topology Hiding (20 tests)

Implémente la masquage de topologie réseau interne (RFC 3323 / RFC 3325).

**Fonctionnalités :**
- `RawSipMessage::parse()` — Parser SIP texte complet (headers + body)
- `apply_topology_hiding_inbound()` — Stripping Via/Contact/Record-Route entrant
- `apply_topology_hiding_outbound()` — Insertion SBC Via/RR sur la sortie
- `strip_privacy_headers()` — Suppression P-Asserted-Identity, X-Forwarded-For
- `new_branch()` — Génération branch z9hG4bK RFC 3261
- `SbcIdentity::via_header()` / `record_route()` / `contact_uri()`

```rust
let id = SbcIdentity::new("51.158.117.229", "sip.nixi.tel", 5060, false);

// Message entrant : supprimer Via/RR du peer
let hidden = apply_topology_hiding_inbound(&raw_sip, &id, "UDP")?;

// Message sortant : insérer Via + Record-Route SBC
let forwarded = apply_topology_hiding_outbound(&raw_sip, &id, "UDP")?;
```

**Actions sur message entrant :**
1. Décrémente Max-Forwards (erreur si = 0)
2. Supprime tous les Via headers du peer
3. Insère le Via du SBC avec branch unique
4. Réécrit Contact → SBC contact URI
5. Supprime Record-Route (SBC insèrera le sien)

---

### 3. `register.rs` — REGISTER Handling (21 tests)

Registrar SIP complet (RFC 3261 §10) avec deux backends.

**Trait `Registrar`:**
```rust
#[async_trait]
pub trait Registrar: Send + Sync {
    async fn register(&self, reg: Registration) -> Result<u32>;
    async fn unregister(&self, aor: &str, contact: &str) -> Result<()>;
    async fn unregister_all(&self, aor: &str) -> Result<u32>;
    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>>;
    async fn cleanup_expired(&self) -> Result<u32>;
    async fn count(&self) -> u64;
    async fn all_registrations(&self) -> Result<Vec<Registration>>;
}
```

**Backends :**
- `InMemoryRegistrar` — Développement/tests (HashMap + RwLock)
- `PostgresRegistrar` — Production (génère SQL UPSERT/DELETE/SELECT)

**Schema PostgreSQL :**
```sql
CREATE TABLE sip_registrations (
    id           BIGSERIAL PRIMARY KEY,
    aor          TEXT NOT NULL,
    contact      TEXT NOT NULL,
    expires      INTEGER NOT NULL,
    registered_at BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    call_id      TEXT NOT NULL,
    cseq         INTEGER NOT NULL,
    user_agent   TEXT,
    received_ip  TEXT NOT NULL,
    received_port INTEGER NOT NULL,
    transport    TEXT NOT NULL DEFAULT 'UDP'
);
CREATE UNIQUE INDEX idx_reg_aor_contact ON sip_registrations(aor, contact);
```

**RegisterHandler :**
```rust
let h = RegisterHandler::new_inmemory();

// REGISTER normal
let result = h.handle(aor, contact, 3600, call_id, cseq, from_addr, "UDP").await?;

// De-registration (expires=0)
let result = h.handle(aor, contact, 0, call_id, cseq, from_addr, "UDP").await?;

// Remove all contacts
let result = h.handle(aor, "*", 0, call_id, cseq, from_addr, "UDP").await?;

// Build 200 OK response
let ok = RegisterHandler::build_200_ok(&bindings, call_id, cseq);
```

**Limites :** MIN_EXPIRES=60s, MAX_EXPIRES=86400s (RFC 3261 §10.3.3)

---

### 4. `tls_client.rs` — TLS Client Outbound (18 tests)

Pool de connexions TLS sortantes pour trunks SIP (RFC 5630).

**Fonctionnalités :**
- `TlsClientConfig` — Configuration par trunk (SNI, cert verification, mTLS)
- `TlsConnection` — Connexion individuelle avec stats et keepalive
- `TlsClientPool` — Pool (réutilisation de connexions existantes)
- Keepalive SIP OPTIONS automatique
- Timeout configurable (connect, idle, keepalive)

```rust
let pool = TlsClientPool::new();

// Connexion TLS standard
let cfg = TlsClientConfig::new("193.34.16.5:5061", "trunk.operateur.com");

// Avec mTLS
let cfg = TlsClientConfig::new("193.34.16.5:5061", "trunk.operateur.com")
    .with_client_cert("/etc/sbc/client.pem", "/etc/sbc/client.key");

let conn = pool.get_or_connect(cfg).await?;
conn.send(sip_message.as_bytes()).await?;
```

**États de connexion :**
- `Connecting` → `TlsHandshake` → `Ready` → `Keepalive` / `Closed`

---

### 5. `acl.rs` — ACL Dynamique (18 tests)

Listes de contrôle d'accès IP avec règles CIDR, IPv4/IPv6.

**Fonctionnalités :**
- Règles CIDR (10.0.0.0/8, 2001:db8::/32, etc.)
- Actions : `Allow`, `Deny`, `Log`
- Priorités (plus haut = évalué en premier)
- Direction : `Inbound`, `Outbound`, `Both`
- Hot-reload (ajout/suppression à chaud sans restart)
- Import/export texte (format pipe-separated)
- Raccourcis : `block_ip()` / `unblock_ip()`
- Statistiques temps réel

```rust
let acl = AclManager::new_restrictive(); // deny by default

// Autoriser les LAN internes
acl.add_rule(AclRule::new("trusted", "LAN", "10.0.0.0/8", AclAction::Allow, 100)?).await?;

// Bloquer une IP spécifique
acl.block_ip("5.5.5.5".parse()?, "attaque détectée").await?;

// Évaluation
let result = acl.check(ip_addr, Direction::Inbound).await;
if !result.is_allowed() { /* rejeter */ }

// Import depuis config
acl.load_from_text("r1|trusted|192.168.0.0/16|allow|100\n").await?;
```

---

## Tests Phase 7

| Module | Tests | Status |
|--------|-------|--------|
| `transcoding.rs`  | 20 | ✅ |
| `topology.rs`     | 20 | ✅ |
| `register.rs`     | 21 | ✅ |
| `tls_client.rs`   | 18 | ✅ |
| `acl.rs`          | 18 | ✅ |
| **TOTAL Phase 7** | **97** | **✅** |

**Total cumulatif : 336 tests (0 échecs)**

---

## Déploiement

```
Serveur : root@51.158.117.229
Build   : cargo build --release (5m18s)
Binary  : /usr/local/bin/sbc (4.9MB)
Config  : /opt/sbc/config/production.toml
Service : systemctl status sbc → active (running)
```

Ports actifs :
- UDP 5060 — SIP standard
- TCP 5060 — SIP TCP
- TLS 5061 — SIP TLS (sip.nixi.tel)
- WSS 8443 — WebSocket TLS (webrtc.nixi.tel)

---

## Phase 8 prévue

- Failover trunks (redondance)
- SIP SUBSCRIBE/NOTIFY (présence, BLF)
- SRTP DTLS-SRTP end-to-end pour WebRTC
- REST API complète (CRUD trunks, enregistrements)
- Supervision Grafana + Prometheus dashboards
