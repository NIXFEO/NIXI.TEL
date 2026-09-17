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
