# NIXI.TEL SBC

Session Border Controller (SBC) written in Rust. Production-grade, handling real PSTN traffic since February 2026.

## What is this?

A SIP Session Border Controller that sits between VoIP users and PSTN trunks. It handles:

- **B2BUA** (Back-to-Back User Agent) for call control
- **SIP signaling** — INVITE, BYE, CANCEL, ACK, REGISTER, REFER
- **Media relay** — RTP/RTCP bidirectional proxy
- **Transcoding** — Opus <-> G.711 (PCMU/PCMA) real-time audio conversion
- **SRTP/DTLS** — Encrypted media for WebRTC endpoints
- **ICE/STUN** — NAT traversal for WebRTC clients
- **Digest authentication** — RFC 2617 challenge/verify with hot-reload
- **Topology hiding** — Via, Contact, Record-Route rewriting (RFC 3261)
- **Rate limiting** — Per-IP token bucket DoS protection
- **CDR** — Call Detail Records in JSON-lines format
- **Prometheus metrics** — Active calls, RTP packets, auth counters
- **Multi-trunk routing** — LCR, prefix matching, failover candidates
- **Graceful shutdown** — Sends BYE to all active peers on SIGTERM

## Architecture

```
                    ┌─────────────────────────┐
   PSTN Trunk ◄────┤                         ├────► SIP Users
   (G.711/RTP)     │     NIXI.TEL SBC        │     (UDP/TCP/TLS)
                    │                         │
   WebRTC ◄────────┤   Rust / Tokio async     ├────► Prometheus
   (Opus/SRTP)     │   ~26K lines             │     /metrics
                    └─────────────────────────┘
```

### Crate structure

| Crate | Role |
|-------|------|
| `sbc-core` | All SBC logic: SIP processing, media, routing, auth, storage |
| `sbc-bin` | Binary entry point, config loading, signal handling |

### Key modules

| Module | Description |
|--------|-------------|
| `sbc.rs` | Main event loop, INVITE/BYE/CANCEL/ACK dispatch |
| `b2bua.rs` | B2BUA call state, Call-ID mapping (half-mode) |
| `media/rtp.rs` | RTP relay, STUN/DTLS demux, inactivity timeout |
| `media/sdp.rs` | SDP parsing/rewriting, WebRTC<->trunk transform |
| `media/srtp_crypto.rs` | SRTP encrypt/decrypt, key derivation |
| `media/ice.rs` | ICE connectivity checks, candidate gathering |
| `media/stun.rs` | STUN binding requests/responses |
| `media/dtls.rs` | DTLS handshake, SRTP key export |
| `transcoding.rs` | Opus<->G.711 transcoding, resampling |
| `topology.rs` | Via/Contact/Record-Route rewriting |
| `routing/trunk.rs` | Trunk config, number normalization, LCR |
| `routing/router.rs` | Request routing, failover candidates |
| `register.rs` | SIP REGISTER, in-memory registrar |
| `auth.rs` | Digest auth (401 challenge/verify) |
| `storage.rs` | CDR persistence (JSON-lines) |
| `metrics.rs` | Prometheus counters |
| `dos.rs` | Rate limiting (token bucket per IP) |
| `acl.rs` | IP access control lists |
| `config.rs` | TOML config parsing |

## Build

### Prerequisites

- Rust 1.75+ (nightly not required)
- cmake (for native crypto dependencies)
- pkg-config, libssl-dev (Linux)

### Compile

```bash
cargo build --release
```

The binary is at `target/release/sbc`.

## Configuration

Copy the example config and edit it:

```bash
cp config/production.toml.example config/production.toml
```

Key sections to configure:

- **`[network]`** — Public IP, SIP/TLS/WSS listeners
- **`[media]`** — RTP port range, codecs, WebRTC STUN/TURN
- **`[security]`** — Rate limits, digest auth, SIP users
- **`[[trunks]]`** — PSTN trunk(s): host, port, auth, prefix patterns
- **`[[dids]]`** — DID-to-user mappings for inbound calls
- **`[management]`** — REST API bind address and auth token

See `config/production.toml.example` for a fully documented example.

## Run

```bash
# Development
./target/release/sbc --config config/dev.toml

# Production (systemd recommended)
./target/release/sbc --config /opt/sbc/config/production.toml
```

### Systemd service

```ini
[Unit]
Description=NIXI.TEL SBC - Session Border Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sbc --config /opt/sbc/config/production.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

**Important:** Always stop with `systemctl stop sbc` (SIGTERM). The SBC sends BYE to all active peers during graceful shutdown. Never `kill -9` — it leaves ghost sessions on the trunk.

## REST API

The management API listens on `127.0.0.1:8080` by default.

```bash
# Health / active calls
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/calls

# Prometheus metrics
curl http://127.0.0.1:9090/metrics
```

## Monitoring

Prometheus metrics exposed:

- `sbc_active_calls` — Current active call count
- `sbc_total_requests` — SIP requests by method
- `sbc_total_responses` — SIP responses by status code
- `sbc_rtp_packets` — RTP packets relayed
- `sbc_auth_attempts` — Authentication attempts (success/failure)
- `sbc_call_duration_seconds` — Call duration histogram

## Supported RFCs

- RFC 3261 — SIP: Session Initiation Protocol
- RFC 3263 — SIP: Locating SIP Servers
- RFC 2617 — HTTP Digest Authentication
- RFC 2833 — RTP Payload for DTMF Digits (telephone-event)
- RFC 3550 — RTP: Real-Time Transport Protocol
- RFC 3711 — SRTP: Secure Real-time Transport Protocol
- RFC 5245 — ICE: Interactive Connectivity Establishment
- RFC 5389 — STUN: Session Traversal Utilities for NAT
- RFC 5766 — TURN: Traversal Using Relays around NAT
- RFC 4566 — SDP: Session Description Protocol

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

Contributions welcome. Please open an issue before submitting large PRs.
