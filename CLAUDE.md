# NIXI.TEL SBC - Development Guide

## Project

SBC (Session Border Controller) written in Rust (~31K lines), production-ready.
Open-source: https://github.com/NIXFEO/NIXI.TEL
Designed for PSTN trunking with full B2BUA call control.

**Current version**: Phase 19 (2026-04-12)
**License**: MIT (NIXFEO)

## Server

- **SSH**: `root@sip.nixi.tel`
- **Config**: `/opt/sbc/config/production.toml`
- **Binary**: `/usr/local/bin/sbc` (backup: `/usr/local/bin/sbc.bak`)
- **Logs**: `/var/log/sbc/sbc.log`
- **CDR**: `/var/log/sbc/cdr.jsonl`
- **Service**: `systemctl {start|stop|restart} sbc`
- **Systemd**: `/etc/systemd/system/sbc.service`
- **Disk**: 17G total, ~49% used, 8.8G free

### Other projects on server
- `/opt/diamy/src/` — Diamy SIP Network Monitor (code source only, no build artifacts)

## Build & Deploy

```bash
# 1. Upload sources
scp crates/sbc-core/src/*.rs root@sip.nixi.tel:/root/sbc/crates/sbc-core/src/
scp crates/sbc-core/src/sbc/*.rs root@sip.nixi.tel:/root/sbc/crates/sbc-core/src/sbc/
scp crates/sbc-core/src/media/*.rs root@sip.nixi.tel:/root/sbc/crates/sbc-core/src/media/
scp crates/sbc-core/src/routing/*.rs root@sip.nixi.tel:/root/sbc/crates/sbc-core/src/routing/

# 2. Build on server
ssh root@sip.nixi.tel 'source ~/.cargo/env && cd /root/sbc && cargo build --release'

# 3. Test on server
ssh root@sip.nixi.tel 'source ~/.cargo/env && cd /root/sbc && cargo test'

# 4. Deploy (graceful — sends BYE to all active peers)
ssh root@sip.nixi.tel 'cp /usr/local/bin/sbc /usr/local/bin/sbc.bak && systemctl stop sbc && cp /root/sbc/target/release/sbc /usr/local/bin/sbc && systemctl start sbc'

# 5. Smoke test
ssh root@sip.nixi.tel 'curl -s -H "Authorization: Bearer TOKEN" http://127.0.0.1:8080/api/v1/registrations'

# 6. Clean build artifacts after deploy (saves ~3GB)
ssh root@sip.nixi.tel 'cp /root/sbc/target/release/sbc /tmp/sbc-bak && rm -rf /root/sbc/target && mkdir -p /root/sbc/target/release && mv /tmp/sbc-bak /root/sbc/target/release/sbc'
```

**Important:** Always use `systemctl stop sbc` (SIGTERM) for graceful shutdown. Never `kill -9`.

### Rollback
```bash
ssh root@sip.nixi.tel 'systemctl stop sbc && cp /usr/local/bin/sbc.bak /usr/local/bin/sbc && systemctl start sbc'
```

### Local build (macOS)
Requires cmake for Opus. rsip fork at `../rsip-nixi`.
```bash
export PATH="/path/to/cmake/bin:$PATH"
cargo test
```

## Architecture

### Key files (refactored Phase 18)

| File | Lines | Role |
|------|-------|------|
| `sbc/mod.rs` | ~1600 | Core struct, config, event loop, REGISTER, OPTIONS |
| `sbc/invite_handler.rs` | ~665 | INVITE routing, 407 auth retry, outbound topology |
| `sbc/response_handler.rs` | ~492 | 200 OK relay, SDP, WebRTC/DTLS/SRTP handling |
| `sbc/call_handler.rs` | ~616 | BYE, CANCEL, ACK, REFER, timeouts, graceful shutdown |
| `b2bua.rs` | ~1160 | B2BUA half-mode, call state, suffix match, IP disambiguation |
| `media/rtp.rs` | ~1400 | Bidirectional RTP relay, STUN/DTLS demux, inactivity timeout (90s) |
| `media/manager.rs` | ~900 | MediaSession, RTP port management (DashMap) |
| `media/sdp.rs` | ~790 | SDP parsing/rewriting, WebRTC<->trunk SDP transform, DTMF |
| `media/srtp_crypto.rs` | ~870 | SRTP encrypt/decrypt, key derivation |
| `media/ice.rs` | ~920 | ICE agent (connectivity checks, candidate gathering) |
| `media/stun.rs` | ~780 | STUN binding requests/responses, MESSAGE-INTEGRITY |
| `media/dtls.rs` | ~620 | DTLS handshake, SRTP key export |
| `transcoding.rs` | ~1050 | Opus<->G.711 (PCMU/PCMA) transcoding, resampling |
| `topology.rs` | ~610 | Via/Contact/Record-Route rewriting (RFC 3261) |
| `config.rs` | ~375 | TOML config parsing, TrunkConfigToml, DidMapping |
| `routing/trunk.rs` | ~780 | TrunkConfig, normalize_number, normalize_caller, prefix matching, LCR |
| `routing/router.rs` | ~430 | INVITE routing, route_request_candidates() for multi-trunk failover |
| `register.rs` | ~880 | SIP REGISTER handler, InMemoryRegistrar, binding management |
| `auth.rs` | ~750 | Digest auth (401 challenge/verify), nonce management, hot-reload users |
| `api.rs` | ~580 | REST API router: /health, /api/v1/calls, /registrations, /stats, /trunks, /cdrs, /alerts, /reload |
| `http_server.rs` | ~340 | HTTP server, auth token, registrar wiring |
| `storage.rs` | ~620 | CDR (InMemory + FileCdrStorage JSON-lines) |
| `metrics.rs` | ~600 | Prometheus counters (active_calls, requests, responses, rtp_packets, auth) |
| `dos.rs` | ~525 | Rate limiting per IP (token bucket) |
| `acl.rs` | ~725 | IP access control lists |
| `trunk_register.rs` | ~200 | Outbound REGISTER to trunks (auth 401/407) |

### Inactive modules (code present, not used in production)

- `media/data_channel.rs` — WebRTC DataChannel (placeholder)
- `media/turn.rs` — TURN relay (placeholder)
- `tls_client.rs` — TLS outbound for trunks
- `dialog/` — Dialog state machine (bypassed, B2BUA manages directly)
- `transaction/` — Transaction state machine (bypassed, stateless processing)

## REST API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (200 if healthy, 503 if not) |
| GET | `/ready` | Readiness probe |
| GET | `/metrics` | Prometheus metrics (text/plain) |
| GET | `/api/v1/calls` | Active calls list (JSON) |
| GET | `/api/v1/registrations` | Registered SIP users (AOR, contact, expires, transport) |
| GET | `/api/v1/stats` | Global stats (active_calls, uptime, requests) |
| GET | `/api/v1/trunks` | Trunk list (with health status, active/total/failed calls) |
| POST | `/api/v1/trunks` | Create trunk |
| POST | `/api/v1/reload` | Hot-reload config (DIDs, users, trunks) without restart |
| GET | `/api/v1/cdrs` | Recent CDR list (last 100, enriched with caller/callee/trunk/codec) |
| GET | `/api/v1/alerts` | Active alerts (trunk down, high auth failure rate, high call failure rate) |
| GET | `/api/calls` | Legacy alias for /api/v1/calls |
| GET | `/api/registrations` | Legacy alias for /api/v1/registrations |
| GET | `/api/status` | Legacy alias for /api/v1/stats |

## Tests

**404 tests passing** (1 pre-existing failure in transcoding::test_downsample_48k_to_8k — rubato resampling edge case).

Test coverage by module:
- `b2bua.rs` — 14 tests (suffix match, IP disambiguation, port fallback, stray BYE)
- `routing/trunk.rs` — 21 tests (prefix matching, normalize_number, normalize_caller)
- `media/sdp.rs` — 16 tests (parse, round-trip, WebRTC transform, Linphone compat)
- `auth.rs` — 40+ tests (MD5, digest challenge/verify, nonce management)
- `topology.rs` — 20+ tests (Via/Contact/Record-Route rewriting)
- `dos.rs` — 13 tests (token bucket, whitelist, blacklist)
- `storage.rs` — 18 tests (CDR CRUD, JSON serialization)
- `api.rs` — 17 tests (all endpoints, registrations, legacy routes)

## Trunk interop notes

### Genesys-based trunks

- **Variable IPs**: INVITE from one IP, ACK/BYE from different IPs in the same /24 (cluster behavior)
- **Orphan BYEs**: After a call ends, a second BYE may arrive 1-8 min later with the full Call-ID. SBC responds 200 OK (stray BYE).
- **Truncated Call-ID**: INVITE Call-ID = `prefix-prefix-core@host`, BYE/ACK Call-ID = `core@host` (prefixes stripped). Handled via suffix match.
- **Trunk IP fallback**: BYE from any IP in the trunk's /24 triggers retry lookup without source filter
- **OverMaxCall**: If the SBC doesn't send BYE on shutdown, ghost sessions accumulate -> `486 Busy Here (OverMaxCall)`
- **Record-Route rewriting**: Trunk INVITE may contain multiple Record-Route headers; SBC replaces them with its own.
- **Session-Expires**: 14400s (4h), refresher=uac

### Callees that don't send BYE

Some endpoints (e.g. Jambonz-based) drop media silently without sending BYE. The RTP inactivity timeout (90s) handles these cases.

## Known issues

### 481 on inbound PSTN BYE (benign)
When the trunk sends BYE for an inbound call and the callee has already hung up (dialog removed), the callee responds 481. Benign — call is already terminated on both sides. Full fix requires building a synthetic BYE on the SBC side (true B2BUA behavior).

### Double 100 Trying (cosmetic)
The SBC sends 2x 100 Trying per INVITE: one stateless (no Record-Route) and one after processing (with Record-Route). Benign, could be optimized.

### SIP construction via format!()
Synthetic BYEs (graceful shutdown, timeout) are built by string formatting. Fragile — deserves a minimal SIP builder.

### Lock contention B2BUA
`B2buaManager.calls` uses `Mutex<HashMap>`. Fine for current volume (~5 concurrent calls) but potential bottleneck at 100+. Consider migrating to DashMap.

### transcoding::test_downsample_48k_to_8k failure
Pre-existing test failure — rubato resampling produces 551 samples instead of expected 1000. Cosmetic, transcoding works in production.

## Roadmap

### v1.1 — Reliability & Observability
- [x] `/api/v1/calls` and `/api/v1/registrations` handlers ✅ Phase 18
- [x] `/health` endpoint ✅ Phase 18
- [x] Legacy API routes (`/api/calls`, `/api/registrations`, `/api/status`) ✅ Phase 18
- [x] Log rotation (logrotate for sbc.log + cdr.jsonl, 30/90 days) ✅ Phase 19
- [x] Hot-reload config via SIGHUP + `POST /api/v1/reload` ✅ Phase 19
- [x] Enriched CDRs: caller/callee numbers, trunk name, codec ✅ Phase 19
- [x] `/api/v1/cdrs` endpoint (recent CDRs) ✅ Phase 19
- [x] `/api/v1/alerts` endpoint (trunk down, auth/call failure rates) ✅ Phase 19
- [x] Trunk health checks (OPTIONS keepalive, passive mode) ✅ Phase 19
- [x] `/api/v1/trunks` enriched with health/stats ✅ Phase 19
- [x] TLS cert auto-renewal hook (certbot → SBC reload) ✅ Phase 19
- [x] Daily config backup (`/opt/sbc/backups/`) ✅ Phase 19
- [ ] RTP timeout alerting (log warn + metric)

### v1.2 — Refactoring
- [x] Extract handle_invite -> `sbc/invite_handler.rs` ✅ Phase 18
- [x] Extract handle_response -> `sbc/response_handler.rs` ✅ Phase 18
- [x] Extract BYE/CANCEL/ACK/REFER -> `sbc/call_handler.rs` ✅ Phase 18
- [x] Unit tests: suffix match, SDP rewriting, normalize_number, normalize_caller ✅ Phase 18
- [ ] SIP message builder (replace format!())

### v1.3 — Multi-trunk & Resilience
- [ ] Active trunk failover (5s timeout, route_request_candidates ready)
- [x] Trunk health monitoring (OPTIONS keepalive every 30s) ✅ Phase 19
- [ ] Re-INVITE / Session refresh for long calls (>1h)
- [ ] End-to-end DTMF relay (RFC 2833)

### v1.4 — Security & Anti-fraud
- [ ] SBC-level SIP ban (X failed REGISTERs in Y seconds)
- [ ] Geo-blocking for unauthorized international destinations
- [ ] Per-user call rate limiting
- [ ] Mutual TLS auth for trunks

### v2.0 — Architecture
- [ ] True B2BUA: distinct Call-ID per leg
- [ ] Clustering: 2 SBC instances with session replication (Redis)
- [ ] WebRTC Gateway: browser-based PSTN calls
- [ ] SIP over WebSocket (JsSIP, SIP.js)
