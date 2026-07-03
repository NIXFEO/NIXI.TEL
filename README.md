# NIXI SBC — Session Border Controller

[![CI](https://github.com/NIXFEO/NIXI.TEL/actions/workflows/ci.yml/badge.svg)](https://github.com/NIXFEO/NIXI.TEL/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An API-first **Session Border Controller** in Rust for **SIP trunking and
WebRTC**, battle-tested in production. Full B2BUA call control, media
anchoring with transcoding, and a complete REST API — every piece of dynamic
configuration (users, trunks, DIDs, routes, ACLs, bans) is managed at
runtime over HTTP, persisted in an embedded SQLite store. No external
database required.

## Features

**SIP**
- UDP / TCP / TLS / WS / WSS transports; full RFC 3261 parsing (vendored rsip fork)
- B2BUA with topology hiding (Via/Contact/Record-Route rewriting)
- Digest authentication with hot-reloadable user store
- Active **multi-trunk failover** (no answer in 5s or 5xx → CANCEL + next trunk, LCR-ordered)
- **RFC 4028 session timers** — long calls survive trunk-side 4h expiry
- Synthetic in-dialog requests built from real dialog identity (no 481 phantom sessions)
- Trunk health checks (OPTIONS keepalive), outbound trunk registration (401/407)
- Battle-tested trunk interop: variable cluster IPs, truncated Call-IDs, late BYEs

**WebRTC gateway** ([docs/WEBRTC.md](docs/WEBRTC.md))
- SIP over WebSocket (RFC 7118), browser ↔ PSTN in both directions
- ICE / DTLS-SRTP termination, Opus ↔ G.711 transcoding, rtcp-mux, trickle-tolerant
- DTMF (RFC 4733) with payload-type re-mapping between legs
- WS disconnect cleanup: BYE to the surviving leg + unregister within 1s
- No-build [demo softphone](examples/webrtc-client/) (SIP.js)

**API-first management** ([docs/API.md](docs/API.md))
- axum REST API: CRUD for users, DIDs, trunks (full field set), routes, ACLs
- Writes hit SQLite then apply to the live runtime instantly — no reloads
- **Server-Sent Events** stream: calls, registrations, trunk health, alerts, config changes
- Prometheus `/metrics`, enriched JSON-lines CDRs with pagination, config export for backup
- Constant-time bearer auth, configurable CORS, public health probes

**Security & anti-fraud**
- fail2ban-style SIP banning (sliding window, repeat-offender escalation, persisted across restarts)
- Anti-IRSF destination blocking (longest-prefix rules, per-user or global, +881/+882/+883/+979 seeded)
- Per-user limits: concurrent calls + call-setup rate (503 + Retry-After)
- Real outbound TLS for trunks (system roots or custom CA, optional mTLS) — never falls back to plaintext
- IP ACLs, token-bucket DoS protection, INVITE anti-spam gating

## Quickstart

```bash
git clone https://github.com/NIXFEO/NIXI.TEL && cd NIXI.TEL
cp config/sbc.toml.example config/sbc.toml   # edit: realm, public IP, token
cargo run --release -- --config config/sbc.toml
```

Then drive everything over the API:

```bash
TOKEN=your-api-token
# Create a SIP user (active immediately)
curl -X POST localhost:8080/api/v1/users -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"alice","password":"s3cret"}'
# Add a PSTN trunk
curl -X POST localhost:8080/api/v1/trunks -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"pstn-1","host":"sip.provider.example","prefix_patterns":["+33","0"]}'
# Watch events live
curl -N "localhost:8080/api/v1/events?token=$TOKEN"
```

Build needs `cmake` (for the bundled Opus codec). Run the tests with
`cargo test --workspace` (~470 tests).

## Architecture

```
              SIP/UDP·TCP·TLS      SIP/WSS (browsers)
                    │                     │
             ┌──────▼─────────────────────▼──────┐
             │  transport (framing, WS lifecycle)│
             │  ban → ACL → DoS → dispatch       │
             │  B2BUA (dialogs, failover, timers)│
             │  media: RTP relay · SRTP/DTLS/ICE │
             │         Opus ↔ G.711 transcoding  │
             └──────┬─────────────────────┬──────┘
              REST API (axum)        SQLite store
              + SSE events           (users, trunks, DIDs,
              + Prometheus            routes, ACL, bans)
```

Crates: `sbc-core` (SIP engine + media), `sbc-storage` (SQLite config
store), `sbc-management` (axum API), `sbc-bin` (binary).

## Documentation

- [docs/API.md](docs/API.md) — REST API reference
- [docs/WEBRTC.md](docs/WEBRTC.md) — WebRTC gateway guide
- [docs/INSTALL.md](docs/INSTALL.md) — production install (systemd, certs)
- [examples/webrtc-client/](examples/webrtc-client/) — browser softphone demo

## License

MIT — see [LICENSE](LICENSE). Includes a vendored fork of
[rsip](https://github.com/vasilakisfil/rsip) (MIT) in `rsip-nixi/`.

## Acknowledgments

[rsip](https://github.com/vasilakisfil/rsip) · [tokio](https://tokio.rs/) ·
[axum](https://github.com/tokio-rs/axum) · [rustls](https://github.com/rustls/rustls) ·
[webrtc-rs](https://github.com/webrtc-rs/webrtc)
