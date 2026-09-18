# NIXI SBC — Contributor & Architecture Guide

Guidance for working in this repository (humans and AI assistants alike).
For usage docs see [README.md](README.md), [docs/API.md](docs/API.md) and
[docs/WEBRTC.md](docs/WEBRTC.md).

## What this is

**nixi.tel** is an API-first **Session Border Controller** in Rust for SIP
trunking and WebRTC. Full B2BUA call control, media anchoring with
transcoding, and a complete REST API — every piece of dynamic configuration
(users, trunks, DIDs, routes, ACLs, bans) is managed at runtime over HTTP
and persisted in an embedded SQLite store. No external database required.

MIT licensed. Runs in production; contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/sbc-core` | SIP engine: transports, B2BUA, media (RTP/SRTP/DTLS/ICE), transcoding, auth, security |
| `crates/sbc-storage` | SQLite `ConfigStore` — source of truth for dynamic config |
| `crates/sbc-management` | axum REST API server (routes, SSE, auth middleware) |
| `crates/sbc-bin` | Binary entry point — wires the above together |
| `rsip-nixi/` | Vendored fork of [rsip](https://github.com/vasilakisfil/rsip) (SIP parsing) |

## Build & test

```bash
cargo build --workspace
cargo test --workspace          # ~570 tests
cargo clippy --workspace
```

**cmake is required** for the bundled Opus codec (`audiopus_sys`). If your
cmake is 4.x, export `CMAKE_POLICY_VERSION_MINIMUM=3.5` (the vendored
libopus declares an older minimum). The `rsip-nixi/` fork is
workspace-excluded and built as a path dependency.

Run locally:

```bash
cp config/sbc.toml.example config/sbc.toml   # edit realm, public IP, token
cargo run --release -- --config config/sbc.toml
```

## Architecture

### Config model

Static config (network listeners, media, logging) lives in the TOML file.
**Dynamic config** (SIP users, DIDs, trunks, routes, ACL rules, bans) lives
in the SQLite store and is the source of truth. On first boot, TOML seed
entries (`[security.sip_users]`, `[[trunks]]`, `[[dids]]`) are imported once
into the store, then ignored. Every API write goes to the store and is
applied to the live runtime immediately — no reload needed. `SIGHUP` and
`POST /api/v1/reload` re-hydrate the runtime from the store and apply the
reload-class `[security]` keys (`config::classify_key`; table in
docs/API.md "Reload vs restart"); listeners, media ports, TLS material,
realm, `[management]`, `[trunk_health]` and `[logging]` need a restart.
`GET /api/v1/config` shows the effective values (`sbc/runtime_config.rs`),
what a reload loaded but could not apply, and what the file on disk would
change; `POST /reload` returns the engine's report.

Key modules: `sbc/import.rs` (first-boot seed), `sbc/hydrate.rs`
(store → live managers), `config.rs` (TOML schema), `sbc/backup.rs`
(`VACUUM INTO` copies: `POST /api/v1/backup` + timer),
`sbc-storage/src/import.rs` (`POST /api/v1/import`: an export document
applied in one transaction, merge or replace, then hydrate). The settings
keys shared by the crates live in `sbc_storage::keys`.

CDRs are store data too (table `cdrs`, migration 0003, `cdr_writer.rs`):
never seeded from TOML, not part of `/export` (use `GET /api/v1/cdrs?format=csv`).

The store is **fail-closed**: a store that cannot be opened or hydrated at
boot aborts startup (`[database] allow_missing_store = true` for the old
warn-and-run-from-TOML behaviour). `/ready` answers 503 until the store is
open, hydrated and the SIP listeners are bound (`sbc::Readiness`).

### Call flow

Inbound message → `sbc/mod.rs` pipeline: **ban → ACL → DoS → dispatch**.
INVITEs go through `sbc/invite_handler.rs` (retransmission absorb, identity
gate `classify_caller` — trunk / loopback / registered user / 407-proven
user, routing, DID mapping, trunk selection with failover, topology
hiding, unsupported extensions and untrusted identity headers stripped);
responses through
`sbc/response_handler.rs` (SDP rewriting, WebRTC/SRTP, session-timer 200s);
BYE/CANCEL/ACK/INFO/re-INVITE through `sbc/call_handler.rs`. The B2BUA
(`b2bua.rs`) holds per-call dialog state for both legs.

### Key files

| File | Role |
|------|------|
| `sbc/mod.rs` | Core struct, config, event loop, REGISTER, OPTIONS, pipeline, reload |
| `sbc/invite_handler.rs` | INVITE routing, trunk failover, 407/422 retries, session-timer offer |
| `sbc/response_handler.rs` | Response relay, non-2xx ACK + per-attempt attribution, SDP, WebRTC/DTLS/SRTP, session-timer completion |
| `sbc/call_handler.rs` | BYE/CANCEL/ACK/INFO, re-INVITE, timeouts, graceful shutdown |
| `sbc/cdr.rs` | `CallOutcome`, `finish_call` (single CDR/metrics/release path), `hangup_both_legs`, RTP/setup timeouts, admin kicks |
| `sbc/invite_tx.rs` | INVITE server-transaction memory: retransmissions replay the last response (RFC 3261 §17.2.1) |
| `sbc/trunk_state.rs` | Trunk state fed by real calls: per-trunk active-call counting, failure ladder / `503 Retry-After` park, success reset, per-trunk metrics labels |
| `trunk_tasks.rs` | Per-trunk OPTIONS health check + outbound REGISTER loops (423 Min-Expires, backoff) as a registry that follows the trunk table (API writes, reload) with cancellation |
| `sbc/hydrate.rs` · `sbc/import.rs` | Store → runtime hydration / first-boot TOML seed |
| `sbc/backup.rs` · `crates/sbc-management/src/routes/store.rs` | Store backups (`VACUUM INTO`, prune, timer) and `POST /api/v1/backup` |
| `sbc/runtime_config.rs` | Effective config + reload reports (`GET /api/v1/config`, `POST /reload`); key classes and diff live in `config.rs` |
| `sip_builder.rs` | Synthetic in-dialog requests (BYE/CANCEL/ACK/re-INVITE) from real dialog identity |
| `b2bua.rs` | B2BUA half-mode, dialog state, INVITE attempts, failover state, session timers |
| `sbc/test_support.rs` · `sbc/flow_tests.rs` | Handler test harness (real `Sbc`, call legs on channels, raw SIP builders) and the call-flow tests built on it |
| `events.rs` | `EventBus` → SSE `/api/v1/events` |
| `security/` | fail2ban banning, anti-IRSF destination rules, per-user limits |
| `routing/{trunk,router}.rs` | TrunkConfig, LCR, `route_request_candidates()` for failover |
| `media/rtp.rs` | Bidirectional RTP relay, STUN/DTLS demux, DTMF PT re-mapping, inactivity timeout |
| `media/{sdp,srtp_crypto,ice,dtls,stun}.rs` | SDP rewriting, SRTP, ICE, DTLS, STUN |
| `transport/{udp,tcp,tls,ws}.rs` · `transport/tls_connect.rs` | Listeners + real outbound TLS |
| `transport/tls_identity.rs` | Reloadable listener certificates (load + key/cert check, atomic swap, registry, expiry gauge) behind `/api/v1/tls/*` and reload |
| `transcoding.rs` | Opus ↔ G.711 (PCMU/PCMA) with resampling |
| `topology.rs` | Via/Contact/Record-Route rewriting (RFC 3261) |
| `auth.rs` · `register.rs` | Digest auth (401/407, nonce); SIP registrar |
| `metrics.rs` · `storage.rs` · `dos.rs` · `acl.rs` | Prometheus, CDR records/manager (cache + store mode), rate limiting, IP ACLs |
| `cdr_writer.rs` | CDR writer task: bounded queue → batched SQLite commits (retry, duplicates counted), JSONL mirror, one-time history import, retention purge |
| `maintenance.rs` | 60 s sweeper: bounded in-memory tables + size gauges |
| `crates/sbc-management/src/{server,state,routes/}` | axum API server |

### Removed legacy code (2026-09, lot 1)

The hand-rolled HTTP admin server (`http_server.rs`, `api.rs` — superseded
by the axum server and fail-open without a token), the simulated TLS client
(`tls_client.rs`), the unused `transaction/` and `dialog/` state machines
(the B2BUA keeps per-attempt INVITE state itself in `b2bua.rs`), the
Postgres stubs, the placeholder `sbc-media`/`sbc-security` crates and the
feature-gated `media/turn.rs` / `media/data_channel.rs` were deleted. TURN
is an external coturn (see docs/WEBRTC.md); DataChannel is out of scope.

`maintenance.rs` is now the 60 s **sweeper** that keeps the in-memory tables
bounded (DoS per-IP state, digest nonces, expired registrations, ban and
per-user rate windows) and exports their sizes as gauges
(`sbc_dos_tracked_ips`, `sbc_auth_nonces`, `sbc_active_registrations`).
`DosProtector` and `DigestAuthenticator` also enforce hard caps
(`MAX_TRACKED_IPS`, `MAX_NONCES`) so a spoofed-source flood cannot outrun
the sweeper.

## REST API

Full reference in [docs/API.md](docs/API.md). All dynamic config is
SQLite-backed and applied to the runtime immediately. Highlights: CRUD for
users/DIDs/trunks/routes/ACL; `/api/v1/security/*` (bans, destination rules,
user limits); `GET /api/v1/events` (SSE); `GET /api/v1/export` /
`POST /api/v1/import` (config backup and live restore); `POST /api/v1/backup`
(store file copy); `DELETE /api/v1/calls/{uuid}`. `/health` and `/ready` are public; everything
else needs the bearer token (constant-time comparison).

## Deployment

The SBC is a single static binary plus a TOML file and a SQLite store.
General pattern: build `--release`, copy the binary, restart under a process
manager (systemd recommended), keeping the previous binary for rollback.

**Always stop gracefully** (SIGTERM / `systemctl stop`) — the SBC sends BYE
to active peers on shutdown, preventing ghost sessions on remote trunks.
Never `kill -9`.

A production install guide (systemd unit, TLS/WSS certificates, nginx
reverse proxy for the management API) is in [docs/INSTALL.md](docs/INSTALL.md).

## Trunk interop notes

Hard-won behaviors the SBC handles (Genesys-style clustered trunks):

- **Variable IPs** — INVITE, ACK and BYE may arrive from different IPs in the
  same /24; BYE lookup falls back to the trunk's subnet without a source filter.
- **Truncated Call-IDs** — INVITE `prefix-prefix-core@host` vs BYE `core@host`;
  matched by suffix.
- **Late BYEs** — a second BYE can arrive 1–8 min after teardown; recognized
  via a 10-min terminated-dialog ring buffer and answered 200.
- **OverMaxCall** — if the SBC doesn't BYE on shutdown, ghost sessions
  accumulate and the trunk returns `486 Busy Here`; graceful shutdown prevents it.
- **Session-Expires** — trunks negotiate 14400s (4h) with `refresher=uac`; with
  `[security] session_timer_enabled = true` (off by default) the SBC refreshes
  via re-INVITE (RFC 4028) so long calls survive.
- **422 Session Interval Too Small / Min-SE 14400** — Genesys rejects any
  Session-Expires below 14400. The SBC ACKs the 422 and re-sends the INVITE
  once with the trunk's Min-SE (RFC 4028 §7.4); raise `session_expires` to
  14400 to skip that round trip (applied on SIGHUP). Timer headers are
  *replaced* on the trunk leg, never appended to the caller's own.
- **Identity** — a Digest-authenticated user binds only its own AOR on a
  served domain (`register_aor_check`); an INVITE from a registered phone
  must carry one of that phone's users; an unregistered source claiming a
  local user is challenged (407); a stranger reaches a registered user only
  from a trunk's /24; a trunk presenting a local user is flagged
  (`trunk_local_from`). Stale nonces are re-challenged with `stale=true`,
  never banned. Registrar bindings are keyed by Contact URI or
  `+sip.instance` (`register.rs`): a phone re-registering from a new port
  refreshes its one binding (inbound calls follow the newest source), two
  phones behind one NAT keep theirs; `register_min_expires` → 423,
  `register_max_expires` clamps (both reload-class). AORs have one
  spelling (`register::canonical_aor`: no display name, no URI params, no
  port, host lower-cased) so a REGISTER and a later inbound call agree.
  Within one Call-ID a REGISTER whose CSeq is not higher changes nothing
  (RFC 3261 §10.3 step 7) — a removed binding is remembered for 64 s so a
  retransmission cannot resurrect it.
- **Non-2xx finals are ACKed and attributed by Via branch** — every INVITE
  attempt toward a trunk (initial, 407/422 retry, failover) is remembered;
  a late 487/422 from a superseded attempt is ACKed and dropped instead of
  tearing the live call down. The CANCEL and the non-2xx ACK reuse the
  attempt's Via branch and CSeq; the 2xx ACK reuses only the CSeq (it is its
  own transaction, RFC 3261 §17.1.1.3). Responses relayed to the caller get
  the caller's own CSeq back. A 481/408 to the SBC's refresh re-INVITE (or
  three failed refreshes in a row) tears the call down with a BYE to the
  caller instead of refreshing a dead dialog forever.

- **Trunk capacity and cooldown are real** — a call counts on its trunk
  from the forwarded INVITE (or from the inbound INVITE's source trunk) to
  `finish_call`. Strikes: a 408/500/502/503/504 final, a send failure, no
  answer at all (not even 100 Trying) within `invite_timeout` (when a
  backup exists) or `call_setup_timeout`, and OPTIONS misses — never the
  callee's answer (486, 603, 404, 501, 6xx). 3 → 30 s, 6 → 2 min, 10 →
  5 min without new calls; a 200 OK or an OPTIONS answer resets. A
  `503 Retry-After` parks the trunk for that long; the park survives a 200
  OK and is lifted by expiry or `POST /trunks/{name}/enable`. The router
  skips full, cooling or parked trunks; failover moves the count and
  counts a `failover` outcome on the trunk it left. Per-trunk metrics:
  `sbc_trunk_up/registered/active_calls/calls_total{direction,outcome}`
  plus `sbc_trunk_enabled/available/unavailable_seconds` from the table.
  The OPTIONS/REGISTER tasks follow the trunk table (`trunk_tasks.rs`) and
  are **UDP-only**: a TCP/TLS/WS trunk gets no probe and no outbound
  REGISTER (they would be UDP datagrams on a port that speaks something
  else), so its health comes from real calls. `POST /trunks/{name}/enable`
  forgives the cooldown and the park even when the trunk was already
  enabled — that is the documented remedy.

Some callees (e.g. Jambonz-based) drop media without sending BYE — after
`security.rtp_timeout` (90 s) without RTP the SBC BYEs both legs and writes a
`rtp-timeout` CDR. Every call ends through `sbc/cdr.rs::finish_call` (one
CDR per call, real cause, setup/answer/end window) whatever the path: BYE,
CANCEL, rejected final, `max_call_duration`, `call_setup_timeout`, RTP
timeout, shutdown, WS close, admin kick, lost dialog.

## Logging

Every log line of a call carries the `call` span (`uuid`, `call_id`,
`trunk`, `direction`): `Sbc::dispatch` (sbc/mod.rs) creates it from the
dialog (`B2buaManager::log_fields_for_call_id`) and `.instrument()`s the
handler; `record_call_identity` fills the fields on the INVITE path as
they become known; timer/kick/shutdown loops instrument each call with
`call_span_for_uuid`; the RTP relay task inherits `Span::current()`.
Rules: never `span.enter()` across an `.await` (multi-thread runtime —
use `.instrument`); a new `info!` fires at most once per call, per-message
and per-packet diagnostics are `debug!`/`trace!` (the flow test
`a_normal_call_stays_within_the_info_budget` guards the budget); bodies
never at info. `[logging] format` picks text or JSON; precedence
`--verbose` > `RUST_LOG` > `[logging] level`; the writer is non-blocking
and lossy (`sbc_log_dropped_lines_total`). Library tests capture logs with
`test_support::log_capture` (thread-local `set_default`, never a global
subscriber). A field learned late (the outbound `trunk`, or a failover)
appears twice on a text line, once per `record`; in JSON a parser keeps
the last value.

## Known minor issues

- **Double 100 Trying** — the SBC sends two per INVITE (stateless, then after
  processing with Record-Route). Benign, could be optimized.
- **B2BUA lock** — `B2buaManager.calls` is a `Mutex<HashMap>`; fine at current
  volumes, migrate to DashMap if targeting 100+ concurrent calls.
- **Dead connection-oriented binding** — a registrar binding made over
  TCP/TLS keeps its reply channel after the peer's connection closed (only
  WS/WSS teardown is detected), so an inbound INVITE for that user is
  written into a dead channel and reported as sent until the binding
  expires. Pre-dates lot 3; fix with the transport-level close events.

## Roadmap

Delivered: multi-trunk failover, RFC 4028 session timers, DTMF PT
re-mapping, SIP message builder (true-B2BUA BYEs), SQLite-backed full API +
SSE, WebRTC WS lifecycle, anti-fraud (fail2ban / IRSF / per-user limits),
real outbound TLS + mTLS, enriched CDRs (negotiated codec + inbound trunk),
RTP-timeout / last-CDR metrics, per-call log spans with text/JSON output
(`[logging]`, `RUST_LOG`), per-trunk metrics and state fed by real calls,
trunk OPTIONS/REGISTER tasks that follow the trunk table, fail-closed
store with real `/ready`, store backups and config import, TLS certificate
reload, registrar bindings by Contact/instance, CDRs in SQLite with
filters and CSV.

Ideas welcome (open an issue / PR):

- True B2BUA with a distinct Call-ID per leg
- Clustering with session replication
- 2833 ↔ SIP INFO DTMF conversion
- Trickle ICE over SIP (RFC 8840)
