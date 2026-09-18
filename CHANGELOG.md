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
- An INVITE whose forward fails (dead TCP/TLS peer, unregistered TLS
  destination, closed WS) is failed over to the next trunk, else answered
  503 and released; it used to stay ringing with its RTP ports until the
  4 h cap. The attempt is recorded before the send so failover can use it.
- Retransmitted INVITEs (lost 100 Trying or final) are absorbed and get the
  last response again (RFC 3261 §17.2.1); each copy used to create a second
  call with its own media session, leaking the first one's ports.
- Honest capabilities: `Allow` lists what the SBC implements, `Supported`
  is `timer` only; a `Require` of anything else is answered 420 with
  `Unsupported`; unsupported tokens (100rel, replaces, gruu…) are stripped
  from forwarded `Supported` headers so a trunk never waits for PRACKs the
  SBC cannot relay; unknown methods get 405 + Allow instead of 501.
- Responses to relayed INFO/REFER (and to the SBC's own CANCEL/BYE) no
  longer fall into the INVITE logic (a 200 OK to a DTMF INFO re-ran the
  answer path on the dialog).
- Session-refresh answers are classified: 491 Request Pending retries after
  2.1–4 s without counting as a failure; 405/501/420 disable the timer for
  that call and keep it; 481/408 tear down; other rejections strike with
  backoff as before.
- Relayed BYEs carry the peer's `Reason` header; a CANCEL from a trunk
  with a truncated Call-ID is matched by suffix like ACK/BYE.
- Digest failures are typed. A REGISTER with an expired, unknown or
  already-used nonce is re-challenged with `stale=true` (RFC 7616 §3.3)
  and never counts toward fail2ban — clients that cache the challenge across
  re-REGISTERs, or reconnect after an SBC restart, were answered 403 and
  banned after a few tries. Nonce counts must advance (a replayed
  Authorization is re-challenged, not banned: only the password holder can
  produce one), byte-identical UDP retransmissions are accepted, a
  non-Digest header gets 400. An unknown user is verified against a dummy
  HA1 and answered like a known one on a nonce the SBC did not issue (no
  username oracle, no strike from a forged nonce). New counter
  `sbc_auth_stale_challenges_total`.
- Identity binding (RFC 3261 §10.3 step 5, §22.3). A REGISTER authenticated
  as alice could bind, or wipe (`Contact: *`), any AOR; an INVITE's From was
  trusted whatever the source. Now: the authenticated user may only bind its
  own AOR (`register_aor_check`); the AOR host is refused only once
  `served_domains` is configured, reported otherwise; an
  INVITE from a registered phone must carry one of that phone's identities;
  an unregistered source claiming a local user is challenged with 407 and
  admitted only with the right password; a source that is none of trunk,
  registered or provable is 403 + fail2ban; a trunk presenting a local user
  is flagged (`trunk_local_from`) and its calls never count against that
  user. Every mismatch is a `identity_mismatch` security event and counts
  in `sbc_security_identity_mismatches_total`; CDR `caller` is the verified
  identity. `Registered` / `Unregistered` SSE events are published.
- Anti-fraud settings survive a restart. Destination rules created through
  the API lived in memory only and the `users.max_concurrent_calls` /
  `max_calls_per_minute` columns were never loaded: migration 0002 adds
  `destination_rules`, the API writes store-first and re-hydrates,
  `PUT /api/v1/security/user-limits/{user}` writes the user row (404 for an
  unknown user), the global defaults go to `settings`, and both are loaded
  at boot and on reload. `[security.destinations].rules`, the IRSF seeds and
  `[[security.user_limits.overrides]]` are imported once at first boot like
  users/trunks/DIDs (markers `destination_rules_seeded_at`,
  `user_limits_seeded_at`). `GET /api/v1/export` is version 2 with
  `destination_rules` and `user_limits`. From this release on, the
  migrator ignores applied migrations it does not know, so a later
  rollback to 0.20 only swaps the binary. Rolling back *from* 0.20 to an
  older binary is different: that binary refuses a store carrying
  migration 0002 — see INSTALL.md §10 (delete the `_sqlx_migrations` row
  or restore the pre-upgrade store copy that `scripts/deploy.sh` now
  takes).
- `PATCH /api/v1/trunks/{name}` and `/users/{username}` (RFC 7396 merge on
  the wire shape): only the fields sent change, the trunk password / TLS
  material and the user's password stay unless given, `null` clears a
  field, unknown keys (the GET-only `tls`, `health`…) are 400. A PUT that
  writes back the masked `"***"` password is refused instead of storing it.
  SECURITY.md documented PATCH; it was not routed.
- Management API: `X-Real-IP` / `X-Forwarded-For` are believed only from
  `[management] trusted_proxies` (loopback by default) — any client could
  shift rate limits and audit lines onto another address; `429` carries
  `Retry-After`; failed bearer-token checks strike the client's IP in
  fail2ban (`ban_on_auth_failure`); unauthenticated requests from a banned
  IP get 403 while a valid token is always served (the API is the tool
  that lifts bans).

### Added
- Trunk tasks follow the trunk table (lot 3). The OPTIONS health check and
  the outbound REGISTER loop of a trunk were spawned once at boot and never
  stopped: a trunk created through the API was never probed or registered,
  a deleted one was probed forever, changed credentials or hosts were
  ignored until a restart. `trunk_tasks.rs` keeps one set of tasks per
  enabled trunk and re-syncs on every trunk write, SIGHUP and
  `POST /api/v1/reload` (start / stop / restart on host, port, transport,
  credentials, realm, register flag or interval change); a stopped
  registered trunk gets a best-effort `Expires: 0`. Outbound REGISTER: a
  `423 Interval Too Brief` is retried with the trunk's `Min-Expires` and
  the value is remembered; a refused or unanswered REGISTER backs off
  30 s → 15 min (reset on success, cap `[trunk_health]
  register_backoff_max`) instead of every 60 s; an OPTIONS down→up
  transition re-registers immediately. New `[trunk_health]` section
  (`options_interval`, `options_timeout`, `register_backoff_max`), SSE
  events `trunk_registered` / `trunk_unregistered`, `registered` on
  `GET /api/v1/trunks`, `trunk_unregistered` in `GET /api/v1/alerts`, and a
  changed trunk host is re-resolved on hydrate.
- Trunk state fed by real calls (lot 3). `TrunkState.active_calls`,
  `consecutive_failures` and the cooldown were only ever touched by the
  OPTIONS health check, so `max_concurrent_calls` and the failure ladder
  never applied to traffic. Every call now counts on the trunk its outbound
  leg (or its inbound source) is on, moves with a failover and is released
  by `finish_call`; 408/5xx/6xx and unanswered attempts count as trunk
  failures (3 in a row → 30 s, then 2 min, then 5 min without new calls), a
  `503 Retry-After` parks the trunk for exactly that long (1 s–1 h), a 200
  OK resets. New metrics: `sbc_trunk_up{trunk}` (once the trunk answered
  OPTIONS at least once), `sbc_trunk_registered{trunk}`,
  `sbc_trunk_active_calls{trunk}`, `sbc_trunk_calls_total{trunk,outcome}`
  (answered / failed / cancelled / timeout — ASR = answered / all), and the
  histograms `sbc_call_setup_seconds` (INVITE → answer, answered calls) and
  `sbc_call_duration_seconds` (billable window). Alert rules
  `SBCTrunkDown`, `SBCTrunkRegistrationFailing`, `SBCTrunkAsrLow`,
  `SBCTrunkParked` and a "Trunks" Grafana row ship in `monitoring/`.
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
