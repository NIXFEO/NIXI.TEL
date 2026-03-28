# NIXI.TEL SBC - Development Guide

## Project

SBC (Session Border Controller) written in Rust (~26K lines), production-ready.
Designed for PSTN trunking with full B2BUA call control.

**Current version**: Phase 17

## Build & Deploy

```bash
# Build release
cargo build --release

# Deploy
systemctl stop sbc
cp target/release/sbc /usr/local/bin/sbc
systemctl start sbc
```

**Important:** Always use `systemctl stop sbc` (SIGTERM) for graceful shutdown — the SBC sends BYE to all active peers. Never `kill -9`.

## Architecture

### Key files

| File | Lines | Role |
|------|-------|------|
| `sbc.rs` | ~3400 | Main dispatch: handle_invite/bye/cancel/ack/refer, graceful_shutdown, event loop |
| `b2bua.rs` | ~1000 | B2BUA half-mode (same Call-ID both legs), call state, suffix match |
| `media/rtp.rs` | ~1400 | Bidirectional RTP relay, STUN/DTLS demux, inactivity timeout (90s) |
| `media/manager.rs` | ~900 | MediaSession, RTP port management (DashMap) |
| `media/sdp.rs` | ~700 | SDP parsing/rewriting, WebRTC<->trunk SDP transform, DTMF |
| `media/srtp_crypto.rs` | ~870 | SRTP encrypt/decrypt, key derivation |
| `media/ice.rs` | ~920 | ICE agent (connectivity checks, candidate gathering) |
| `media/stun.rs` | ~780 | STUN binding requests/responses, MESSAGE-INTEGRITY |
| `media/dtls.rs` | ~620 | DTLS handshake, SRTP key export |
| `transcoding.rs` | ~1050 | Opus<->G.711 (PCMU/PCMA) transcoding, resampling |
| `topology.rs` | ~610 | Via/Contact/Record-Route rewriting (RFC 3261), TLS transport param |
| `config.rs` | ~375 | TOML config parsing, TrunkConfigToml, DidMapping |
| `routing/trunk.rs` | ~640 | TrunkConfig, normalize_number, normalize_caller, prefix matching, LCR |
| `routing/router.rs` | ~430 | INVITE routing, route_request_candidates() for multi-trunk failover |
| `register.rs` | ~880 | SIP REGISTER handler, InMemoryRegistrar, binding management |
| `auth.rs` | ~750 | Digest auth (401 challenge/verify), nonce management, hot-reload users |
| `storage.rs` | ~620 | CDR (InMemory + FileCdrStorage JSON-lines) |
| `metrics.rs` | ~600 | Prometheus counters (active_calls, requests, responses, rtp_packets, auth) |
| `dos.rs` | ~525 | Rate limiting per IP (token bucket) |
| `acl.rs` | ~725 | IP access control lists |
| `http_server.rs` | ~300 | REST API + /metrics endpoint |
| `trunk_register.rs` | ~200 | Outbound REGISTER to trunks (auth 401/407) |

### Inactive modules (code present, not used in production)

- `media/data_channel.rs` — WebRTC DataChannel (placeholder)
- `media/turn.rs` — TURN relay (placeholder)
- `tls_client.rs` — TLS outbound for trunks
- `dialog/` — Dialog state machine (bypassed, B2BUA manages directly)
- `transaction/` — Transaction state machine (bypassed, stateless processing)

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

### sbc.rs too large (~3400 lines)
Main file deserves refactoring: extract handle_invite, handle_response (200 OK + SDP), and BYE/CANCEL helpers into separate modules.

### SIP construction via format!()
Synthetic BYEs (graceful shutdown, timeout) are built by string formatting. Fragile — deserves a minimal SIP builder.

### Lock contention B2BUA
`B2buaManager.calls` uses `Mutex<HashMap>`. Fine for current volume (~5 concurrent calls) but potential bottleneck at 100+. Consider migrating to DashMap.

## Roadmap

### v1.1 — Reliability & Observability
- [ ] `/api/calls` and `/api/registrations` handlers
- [ ] RTP timeout alerting (log warn + metric)
- [ ] Enriched CDRs: caller/callee numbers, trunk name, codec, rtp_packets count
- [ ] Log rotation (logrotate for sbc.log and cdr.jsonl)
- [ ] `/health` endpoint

### v1.2 — Refactoring
- [ ] Extract handle_invite -> `invite_handler.rs`
- [ ] Extract handle_response -> `response_handler.rs`
- [ ] SIP message builder (replace format!())
- [ ] Unit tests: suffix match, SDP rewriting, normalize_number, normalize_caller

### v1.3 — Multi-trunk & Resilience
- [ ] Active trunk failover (5s timeout, route_request_candidates ready)
- [ ] Trunk health monitoring (OPTIONS keepalive every 30s)
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
