# SBC W3tel - Session Border Controller

[![Rust](https://img.shields.io/badge/rust-1.93+-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-336%2F336-brightgreen.svg)](docs/PHASE7_COMPLETE.md)
[![RFC](https://img.shields.io/badge/RFC-3261%20%7C%203550%20%7C%204566%20%7C%203711%20%7C%205389%20%7C%208445-blue.svg)](docs/)
[![Status](https://img.shields.io/badge/status-production%20nixi.tel-success.svg)](docs/INSTALL.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Un Session Border Controller (SBC) complet écrit en Rust, déployé en production sur **nixi.tel**.

> **Production** : `sip.nixi.tel` · `webrtc.nixi.tel` · `rtp.nixi.tel` — IP: 51.158.117.229

---

## ✨ Fonctionnalités

### ✅ Phase 1 — Transport Layer
- UDP / TCP / TLS listeners (0.0.0.0)
- Multi-protocole routing automatique
- Parsing SIP complet (rsip RFC 3261)
- Configuration TOML

### ✅ Phase 2 — Signalisation SIP (RFC 3261)
- State machines INVITE + non-INVITE
- Transaction manager (client + serveur)
- Dialog management (Call-ID, From/To-tag, CSeq)
- Timers A–K avec retransmissions exponentielles
- Maintenance background (cleanup automatique)

### ✅ Phase 3 — Media Relay
- SDP Parser & Manipulator (RFC 4566)
- Port Allocator RTP/RTCP pairs (range configurable)
- RTP Proxy symétrique (RFC 3550)
- RTCP relaying
- Statistiques média temps réel

### ✅ Phase 4 — WebRTC & Crypto (RFC 3711 / 5389 / 8445)
- **SRTP** — Chiffrement AES-CM-128 + HMAC-SHA1-80 (RFC 3711)
- **SRTCP** — Chiffrement RTCP (E-bit + index)
- **STUN** — Client complet, XOR-MAPPED-ADDRESS (RFC 5389)
- **ICE** — Agent RFC 8445 : gather, check, select
- **DTLS** — Handshake pour WebRTC (RFC 6347)
- **TURN** — Structure TURN relay (RFC 8656)
- **WebRTC SDP** — Intégration JSEP (RFC 8829)
- **KDF** — Key Derivation Function RFC 3711

### ✅ Phase 5 — B2BUA, Auth, API, Métriques
- **B2BUA** — Back-to-Back User Agent complet (RFC 3261)
- **Auth SIP** — Digest Authentication RFC 7616 (MD5 pur Rust, nonce TTL)
- **REST API** — Gestion trunks, appels, stats (GET/POST)
- **Prometheus** — Métriques au format text/plain 0.0.4
- **Health checks** — `/health`, `/ready`, statut JSON

### ✅ Phase 6 — WebSocket, HTTP, CDR, DoS
- **WebSocket/WSS** — SIP over WebSocket (RFC 7118) pour browsers
- **HTTP/1.1 server** — API REST + Prometheus sans axum
- **CDR Storage** — InMemory + PostgreSQL backends (trait-based)
- **DoS Protection** — Token bucket par IP + blacklist automatique

### ✅ Phase 7 — Transcoding, Topology, REGISTER, TLS Client, ACL
- **Transcoding Opus↔G.711** — PCMU/PCMA encode/decode + resampling 8k↔48k
- **Topology Hiding** — Via/Contact/Record-Route rewriting (RFC 3323)
- **REGISTER handling** — SIP Registrar complet + PostgreSQL backend
- **TLS Client** — Pool de connexions TLS sortantes pour trunks
- **ACL dynamique** — Règles CIDR IPv4/IPv6, priorités, hot-reload

### 📊 État production
- ✅ **336 tests automatisés** (100% pass)
- ✅ **~19 000 lignes de code** (sbc-core)
- ✅ Thread-safe (Arc, Mutex, DashMap)
- ✅ Fully async (Tokio)
- ✅ Vraie crypto (AES-CM, HMAC-SHA1, MD5 RFC 1321)
- ✅ Certificats TLS Let's Encrypt (auto-renouvellement)
- ✅ Déployé sur Ubuntu 24.04 LTS

---

## Architecture

```
rsip-w3tel/
├── rsip-w3tel/          # Fork rsip — parseur SIP (dépendance locale)
└── sbc/
    ├── crates/
    │   ├── sbc-core/    # Cœur SBC : transport, signalisation, media, WebRTC
    │   │   └── src/
    │   │       ├── transport/       # UDP / TCP / TLS listeners
    │   │       ├── transaction/     # State machines RFC 3261
    │   │       ├── dialog/          # Dialog management
    │   │       ├── routing/         # Trunk routing
    │   │       ├── media/           # RTP, SDP, SRTP, ICE, DTLS, STUN, TURN
    │   │       ├── b2bua.rs         # Back-to-Back User Agent
    │   │       ├── auth.rs          # SIP Digest Authentication
    │   │       ├── metrics.rs       # Prometheus metrics
    │   │       ├── api.rs           # REST API router
    │   │       ├── config.rs        # Configuration TOML
    │   │       └── sbc.rs           # Instance principale
    │   ├── sbc-media/   # (Phase 6) Transcoding, media avancé
    │   ├── sbc-security/# (Phase 6) DoS protection, ACL, topology hiding
    │   ├── sbc-storage/ # (Phase 6) PostgreSQL CDR, Redis cache
    │   ├── sbc-management/ # (Phase 6) HTTP server axum, Prometheus endpoint
    │   └── sbc-bin/     # Exécutable principal
    ├── config/
    │   ├── production.toml  # Config production (nixi.tel)
    │   ├── dev.toml         # Config développement
    │   └── sbc.toml.example # Template commenté
    ├── docs/
    │   ├── INSTALL.md       # Guide d'installation complet
    │   ├── PHASE5_COMPLETE.md
    │   └── ...
    └── tests/
        ├── integration/
        └── scenarios/       # SIPp scenarios
```

### Flux d'un appel SIP → WebRTC

```
INVITE (depuis client SIP)
  │
  ▼
Transport Manager (UDP/TCP/TLS)
  │  parsing rsip
  ▼
Transaction Layer (RFC 3261 state machine)
  │  100 Trying
  ▼
Dialog Manager (Call-ID, From-tag, To-tag, CSeq)
  │
  ▼
B2BUA (création 2 legs indépendants)
  │  Inbound UAS ←→ Outbound UAC
  ▼
Media Manager
  │  SDP parsing → allocation ports RTP/RTCP
  │  WebRTC? → ICE gather + DTLS + SRTP keys
  ▼
Routing (trunk lookup)
  │  INVITE modifié (SDP avec nouveaux candidats)
  ▼
Destination (opérateur / browser WebRTC)
```

---

## Installation rapide

Voir **[docs/INSTALL.md](docs/INSTALL.md)** pour le guide complet.

### Développement local

```bash
# Prérequis
rustup update stable    # Rust 1.93+
# PostgreSQL 16 + Redis 7

# Build
cd sbc
cargo build --release

# Tests
cargo test --package sbc-core

# Démarrage dev
cargo run --bin sbc -- --config config/dev.toml
```

### Production (Ubuntu 24.04)

```bash
# Voir docs/INSTALL.md pour les détails complets
curl -sSf https://sh.rustup.rs | sh
apt install postgresql redis-server certbot build-essential libssl-dev pkg-config

# Certificats
certbot certonly --standalone -d sip.example.com -d webrtc.example.com

# Build
cargo build --release --package sbc-bin
cp target/release/sbc /usr/local/bin/sbc

# Service systemd
systemctl start sbc
```

---

## Configuration

### Minimal (UDP uniquement)

```toml
[general]
name = "SBC-W3tel"
instance_id = "sbc-01"

[network]
public_ipv4 = "203.0.113.10"

[[network.listeners]]
transport = "UDP"
bind_address = "0.0.0.0"
bind_port = 5060

[media]
rtp_port_range = [10000, 20000]
rtcp_enabled = true
codecs = ["PCMU", "PCMA", "Opus"]

[media.webrtc]
enabled = true
stun_servers = ["stun:stun.l.google.com:19302"]

[database]
postgres_url = "postgresql://sbc:password@localhost/sbc_db"
redis_url = "redis://localhost:6379"

[security]
rate_limit_global = 1000
rate_limit_per_ip = 50

[management]
api_enabled = true
api_port = 8080

[metrics]
prometheus_enabled = true
prometheus_port = 9090
```

### Complet (UDP + TCP + TLS + WebRTC)

Voir [`config/sbc.toml.example`](config/sbc.toml.example).

---

## API de Gestion

REST API exposée sur `http://127.0.0.1:8080` :

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Health check (JSON) |
| GET | `/ready` | Readiness check |
| GET | `/metrics` | Métriques Prometheus |
| GET | `/api/v1/calls` | Appels actifs |
| GET | `/api/v1/stats` | Statistiques globales |
| GET | `/api/v1/trunks` | Liste des trunks |
| POST | `/api/v1/trunks` | Créer un trunk |

### Exemple health check

```bash
curl http://127.0.0.1:8080/health
# {"status":"healthy","uptime_secs":3600,"active_calls":0}
```

### Métriques Prometheus

```bash
curl http://127.0.0.1:9090/metrics
# sbc_sip_requests_total 42
# sbc_active_calls 3
# sbc_calls_connected_total 150
# sbc_rtp_packets_total 48000
# ...
```

---

## Tests

```bash
# Tous les tests (199 tests)
cargo test --package sbc-core

# Par module
cargo test --package sbc-core -- transport
cargo test --package sbc-core -- transaction
cargo test --package sbc-core -- media
cargo test --package sbc-core -- auth
cargo test --package sbc-core -- b2bua
cargo test --package sbc-core -- metrics
cargo test --package sbc-core -- api

# Tests d'intégration avec SIPp
sipp -sf tests/scenarios/basic_call.xml 127.0.0.1:5060
```

### Résultats actuels

```
test result: ok. 199 passed; 0 failed; 0 ignored
```

| Module | Tests | Statut |
|--------|-------|--------|
| transport (UDP/TCP/TLS) | 23 | ✅ |
| transaction (RFC 3261) | 14 | ✅ |
| dialog | 8 | ✅ |
| routing | 6 | ✅ |
| media (RTP/SDP/ports) | 29 | ✅ |
| srtp_crypto | 11 | ✅ |
| stun | 8 | ✅ |
| ice | 14 | ✅ |
| dtls | 6 | ✅ |
| turn | 8 | ✅ |
| webrtc_handler | 12 | ✅ |
| b2bua | 8 | ✅ |
| auth | 15 | ✅ |
| metrics | 10 | ✅ |
| api | 12 | ✅ |
| config + maintenance | 15 | ✅ |
| **Total** | **199** | **✅** |

---

## Performance cible

| Métrique | Cible |
|----------|-------|
| CPS (Calls Per Second) | ≥ 1 000 |
| Appels concurrents | ≥ 10 000 |
| Latence média overhead | < 10 ms |
| CPU à charge cible | < 50% |
| Mémoire pour 10k appels | < 2 GB |
| MOS score (transcoding) | ≥ 4.0 |
| Packet Loss | < 1% |
| Jitter | < 30 ms |
| Uptime cible | 99.9% |

---

## Sécurité

- **SIP Digest Auth** — RFC 7616 (MD5, nonce TTL 300s, qop=auth)
- **SRTP** — AES-CM-128 + HMAC-SHA1-80 (RFC 3711)
- **DTLS 1.2** — Pour WebRTC (RFC 6347)
- **TLS 1.3** — Pour SIP sur TLS (RFC 5246)
- **Rate limiting** — Global + par IP
- **ACL IP** — Filtrage par réseau/sous-réseau
- **Topology Hiding** — B2BUA masque la topologie interne
- **Certificats** — Let's Encrypt avec auto-renouvellement

### Bonnes pratiques
- Toujours TLS/SRTP sur les connexions publiques
- Configurer des ACL IP strictes pour les trunks
- Token API fort pour la management API
- Prometheus en écoute sur `127.0.0.1` uniquement
- Logs d'authentification monitorés

---

## RFC implémentées

| RFC | Description | Statut |
|-----|-------------|--------|
| RFC 3261 | SIP core | ✅ Complet |
| RFC 3550 | RTP/RTCP | ✅ Complet |
| RFC 4566 | SDP | ✅ Complet |
| RFC 3711 | SRTP | ✅ Complet |
| RFC 5389 | STUN | ✅ Complet |
| RFC 8445 | ICE | ✅ Complet |
| RFC 6347 | DTLS | ✅ Structure |
| RFC 8656 | TURN | ✅ Structure |
| RFC 8829 | JSEP/WebRTC SDP | ✅ Complet |
| RFC 7616 | SIP Digest Auth | ✅ Complet |
| RFC 1321 | MD5 | ✅ Pur Rust |

---

## Roadmap

| Phase | Description | Statut |
|-------|-------------|--------|
| Phase 1 | Transport UDP/TCP/TLS | ✅ Complet |
| Phase 2 | Signalisation SIP RFC 3261 | ✅ Complet |
| Phase 3 | Media Relay RTP/RTCP | ✅ Complet |
| Phase 4 | WebRTC, SRTP, ICE, DTLS | ✅ Complet |
| Phase 5 | B2BUA, Auth, REST API, Métriques | ✅ Complet |
| Phase 6 | WebSocket/WSS, HTTP server, DB intégration | 🚧 En cours |
| Phase 7 | Transcoding Opus/G711/G729, DoS protection | 📋 Planifié |
| Phase 8 | Haute disponibilité, clustering | 📋 Planifié |

---

## Développement

### Structure des modules (sbc-core)

```
sbc-core/src/
├── transport/           # Listeners réseau
│   ├── udp.rs           # UDP (sans connexion)
│   ├── tcp.rs           # TCP (framing Content-Length)
│   ├── tls.rs           # TLS (rustls)
│   └── manager.rs       # Orchestration multi-transport
├── transaction/         # RFC 3261 §17
│   ├── state_machine.rs # INVITE/non-INVITE FSM
│   ├── manager.rs       # Registry transactions
│   └── timers.rs        # Timers A-K
├── dialog/              # RFC 3261 §12
│   ├── dialog.rs        # Dialog state
│   └── manager.rs       # Dialog registry
├── routing/             # Routage trunk
│   ├── router.rs        # Logique de routage
│   └── trunk.rs         # TrunkConfig, TrunkManager
├── media/               # Couche média
│   ├── sdp.rs           # SDP RFC 4566
│   ├── rtp.rs           # RTP proxy RFC 3550
│   ├── port_allocator.rs# Gestion ports RTP/RTCP
│   ├── manager.rs       # MediaManager
│   ├── srtp.rs          # SRTP context (SDES/DTLS)
│   ├── srtp_crypto.rs   # AES-CM + HMAC-SHA1 + KDF
│   ├── stun.rs          # STUN client RFC 5389
│   ├── ice.rs           # ICE agent RFC 8445
│   ├── dtls.rs          # DTLS RFC 6347
│   ├── turn.rs          # TURN RFC 8656
│   └── webrtc_handler.rs# WebRTC SDP (JSEP RFC 8829)
├── b2bua.rs             # B2BUA RFC 3261
├── auth.rs              # Digest Auth RFC 7616
├── metrics.rs           # Prometheus metrics
├── api.rs               # REST API router
├── config.rs            # TOML config
├── maintenance.rs       # Background tasks
└── sbc.rs               # Instance SBC principale
```

### Contribuer

```bash
git clone https://github.com/nixi-tel/sbc-w3tel
cd sbc-w3tel/sbc
cargo test --package sbc-core
# → 199 tests, 0 failed
```

---

## Licence

MIT License — voir [LICENSE](LICENSE)

## Support

- Documentation : [docs/](docs/)
- Guide installation : [docs/INSTALL.md](docs/INSTALL.md)
- Email : support@nixi.tel

## Acknowledgments

- [rsip](https://github.com/vasilakisfil/rsip) — parseur SIP Rust
- [tokio](https://tokio.rs/) — async runtime
- [webrtc-rs](https://github.com/webrtc-rs/webrtc) — WebRTC natif Rust
- [rustls](https://github.com/rustls/rustls) — TLS pure Rust
