# Changelog

All notable changes to NIXI.TEL SBC are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
the workspace version in `Cargo.toml` and git tags `vX.Y.Z`.

## [Unreleased]

### Fixed
- Outbound calls no longer fail with `422 Session Interval Too Small`: the
  SBC ACKs the 422 and re-sends the INVITE once with the trunk's `Min-SE`
  (RFC 4028 §7.4); session-timer headers are replaced, never appended, on
  the trunk leg (`9757058`).
- Every non-2xx INVITE final on the trunk leg is ACKed; responses are
  attributed to the INVITE attempt they answer (Via branch), so a late 487 or
  422 from a superseded attempt no longer tears the live call down; CANCEL
  and ACK toward the trunk reuse the attempt's branch/CSeq; relayed
  responses carry the caller's own CSeq.
- A 481/408 to the SBC's refresh re-INVITE (or three failed refreshes)
  ends the call with a BYE instead of refreshing a dead dialog for hours.
- `terminate_call` releases the media session on every teardown path (RTP
  port leak on error relays and on `DELETE /api/v1/calls/{uuid}`).
- Graceful shutdown and WS-close CANCEL a pending INVITE instead of BYEing.
- A per-accepted-INVITE server transaction that nothing reaped (unbounded
  memory growth) is gone; the Via-branch check it implied answers 400.
- Outbound TCP/TLS connects and the TLS handshake are bounded (3 s): an
  unreachable peer no longer stalls the SIP event loop; dead pooled TCP
  sockets are evicted; TLS client configs are built once per trunk.
- The ACK toward the callee uses the Contact of its 200 OK as Request-URI
  (RFC 3261 §13.2.2.4) instead of the INVITE's Request-URI.
- A BYE from another host of the trunk's /24 (Genesys clusters) on an
  outbound call is attributed to the trunk leg and relayed to the caller;
  it used to be treated as the caller's BYE and sent back to the trunk.
- Synthetic BYEs the SBC sends on its own (max duration, shutdown, lost WS
  connection, relayed BYE after a 407/422 retry) carry a CSeq above the live
  INVITE attempt's (RFC 3261 §12.2.1.1), not the leg counter's 1.
- `security.max_call_duration` is now honoured (default 14400 s, applied on
  reload); the limit was hard-coded to 7200 s.
- CANCEL follows RFC 3261 §9.2: the caller's INVITE gets a **487 Request
  Terminated** after the 200 to the CANCEL (it used to hang with no final
  behind our 100 Trying); a CANCEL that crosses the relayed 200 OK leaves the
  dialog alone instead of tearing it down and CANCELing an answered trunk
  leg; a CANCEL for an unknown Call-ID is answered 481.
- Every response the SBC builds or relays carries the RFC reason phrase
  ("487 Request Terminated", "422 Session Interval Too Small"); the vendored
  rsip rendered variant names ("RequestTerminated") for every known code.
- Every locally generated final (480 unregistered DID target / dead WS
  contact, 503 no trunk / rate-limited / auth exhausted, 500, 501, 403
  banned) now echoes the request's Via, From, To, Call-ID and CSeq (RFC 3261
  §8.2.6.2); they were bare status lines the peer could not match to its
  transaction, so e.g. a 480 left the trunk ringing until its own timeout.
- An inbound trunk call to a number that is neither a DID nor a registered
  user is answered 404 instead of being routed back out to a trunk by LCR.
- Max-Forwards is decremented on the trunk leg and an INVITE arriving with
  Max-Forwards: 0 is answered 483 (RFC 3261 §16.3, §16.6).
- **CDRs billing can trust.** `started_at` was the hangup instant and
  `ended_at` lay in the future; only BYE, lost-dialog and WS-close wrote a
  record. Every call now ends through one path (`finish_call`) that writes
  exactly one CDR with the real cause and the setup / answer / end window:
  `answered_at`, `billable_secs`, `sip_code`, `direction`, `uuid`,
  `source_ip`, `reason` (the peer's Q.850 Reason on its BYE), schema `v` = 2
  (older file rows read back as `v` = 1). CANCEL (`cancelled`, 487),
  rejected finals (`rejected-<code>`), max duration (`timeout`), shutdown,
  WS close, admin kick, RTP timeout and setup timeout are all recorded;
  `sbc_active_calls` no longer drifts after an API kick. `GET /api/v1/cdrs`
  pages are newest first; the API keeps the last 10 000 records in memory.
- `security.rtp_timeout` was never read and the RTP relay only stopped
  itself on inactivity, leaving the SIP dialog and the ports allocated
  until a peer BYE or the max-duration BYE. The SBC now BYEs both legs
  and releases the call (`rtp-timeout`).
- `security.call_setup_timeout` (60 s) was never read: an INVITE nobody
  answers within it is CANCELed toward the callee and answered 408 to the
  caller (`setup-timeout`), which also bounds a call whose failover
  candidates are exhausted.
- `DELETE /api/v1/calls/{uuid}` released the call silently (no BYE to
  either peer, active-call gauge never decremented). It now answers 202 and
  the SIP engine ends the call on the wire (BYE/CANCEL both legs, CDR
  `admin-kick`).
- Teardowns the SBC initiates while a call is still ringing (shutdown,
  setup timeout, max duration) answer the caller's INVITE with a final
  (503 / 408 / 480) instead of a BYE for a dialog that does not exist.
- Synthetic BYEs and the `CallEnded` SSE event carry the real reason
  (`shutdown`, `timeout`, `rtp-timeout`, …) instead of "terminated".

### Added
- Maintenance sweeper (60 s) bounding the in-memory tables (DoS per-IP
  state, digest nonces, expired registrations, ban and per-user rate
  windows) with hard caps and gauges `sbc_dos_tracked_ips`,
  `sbc_auth_nonces`, `sbc_active_registrations`.
- `sbc_session_timer_422_retries_total`, `sbc_sip_send_failures_total{transport}`
  counters, Grafana tile and alert rules; every failed SIP send is logged
  with what was being sent.
- `[security]` session-timer values apply on SIGHUP / `POST /api/v1/reload`.
- `scripts/deploy.sh` (build-on-host deployment with backups and rollback);
  `sbc --version` and the startup log carry the git commit.
- Handler test harness (`sbc/test_support.rs`): a real `Sbc` with both call
  legs on channels, raw SIP builders, `SbcBuilder`; call-flow tests for
  INVITE/200/ACK/BYE, BYE from a trunk sibling host, CANCEL of the live
  attempt after a 422 retry, INVITE-timeout failover to a real UDP peer, max
  duration, graceful shutdown, re-INVITE, and a 100-call churn; management
  API tests for `/security/*`, `/dids`, `/cdrs`, `DELETE /calls/{uuid}`.
- `sbc_core::rsip` re-export (the SIP types appear in the public API).
- CI: rustfmt and clippy are blocking, `cargo deny` checks advisories and
  bans against a `deny.toml` whose every exception is dated and justified,
  Dependabot watches cargo and actions.

### Changed
- Workspace version 0.20.0; release binaries are stripped.
- `sqlx` 0.8 (no TLS features), `clap` 4 replaces `structopt`;
  `trust-dns-resolver` and `config` (unused) dropped; `anyhow`,
  `crossbeam-epoch`, `rand`, `spin` updated for RUSTSEC-2026-0190/0204/0097
  and a yanked release. Workspace crates are marked `publish = false`.
- The whole workspace is rustfmt-formatted and clippy-clean
  (`--all-targets -D warnings`).

### Removed
- Legacy hand-rolled HTTP admin server (`http_server.rs`, `api.rs`) and its
  management router, simulated TLS client, unused `transaction/` and
  `dialog/` state machines, Postgres stubs and config fields, placeholder
  `sbc-media`/`sbc-security` crates, feature-gated TURN/DataChannel modules.

## [0.19] - 2026-07-25
- Management API hardened: env-var token, fail-closed start, rate limiting,
  audit log (after the 2026-07-25 exposure incident).
- Anti-fraud counters exposed; Prometheus/Grafana monitoring shipped.
- Enriched CDRs (codec, inbound trunk), CDR/RTP health observability.
- SQLite `ConfigStore` as the source of truth for dynamic config; axum
  management API with full CRUD, SSE events, constant-time auth.
- True-B2BUA BYE relay, late-BYE recognition, SIP message builder with real
  dialog identity; multi-trunk failover; RFC 4028 session refresh; DTMF
  payload-type re-mapping; WS connection lifecycle; real outbound TLS/mTLS.

## [0.17] - 2026-03-28
- Open-source release.
