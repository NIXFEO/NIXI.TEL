# Changelog

All notable changes to NIXI.TEL SBC are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
the workspace version in `Cargo.toml` and git tags `vX.Y.Z`.

## [Unreleased]

### Fixed

Adversarial review of the whole lot-3 change (16 areas, every finding
verified independently): the confirmed defects and the low-severity ones
worth fixing.

- `POST /api/v1/trunks/{name}/enable` now forgives the failure cooldown
  and a `503 Retry-After` park on a trunk that is *already* enabled — the
  only kind that can be parked, and the remedy the docs pointed at. It was
  a no-op unless the trunk had been disabled first.
- OPTIONS health checks and outbound REGISTER are UDP-only and now say so:
  a TCP/TLS/WS trunk gets no tasks instead of UDP datagrams on its TLS
  port (which never answered, so `sbc_trunk_registered` stayed 0 and the
  critical `SBCTrunkRegistrationFailing` alert fired for ever). Their Via
  and Contact carry the port the SIP listener is really bound to, and the
  identity used for Via/Contact/Record-Route follows the UDP listener's
  `bind_port` instead of a hardcoded 5060.
- `security.max_call_duration = 0` means unlimited, as documented: it was
  clamped to 60 s, so a reload with 0 cut every call after a minute. Other
  values keep the 60 s floor.
- **Registrar bindings are bounded**: at most 10 per AOR and 5000 in total
  (the oldest is evicted), and at most 10 Contacts per REGISTER (more is a
  400). The lot-3 rewrite had dropped the previous
  one-binding-per-source pruning with no replacement, so a single
  credential holder could fill memory — and the identity gate cloned the
  whole table on every INVITE. That scan now filters inside the
  registrar's lock.
- Registrar ordering: a REGISTER whose CSeq is not higher within its own
  Call-ID changes nothing (RFC 3261 §10.3 step 7), and a removed binding
  is remembered for 64 s so a retransmission that arrives after the
  un-REGISTER cannot resurrect it. AORs are canonicalised once
  (`canonical_aor`: no display name, no URI parameters, no port, host
  lower-cased), so a phone that registers `<sip:a@H:5060;transport=udp>`
  is reachable for a DID mapped to `sip:a@h`.
- CDRs: `CdrManager::close` is bounded by its timeout as a whole (it could
  wait for ever while the writer retried a refusing store, so
  `systemctl stop` hit `TimeoutStopSec`, SIGKILLed the process and skipped
  the trunk un-REGISTERs); the JSONL mirror is written *before* the store
  commit, so a store outage leaves a durable copy instead of records that
  only existed in the queue.
- The one-time JSONL history import is streamed and committed in chunks of
  500 instead of holding the whole history in memory and in one
  transaction (a year of CDRs would OOM a 2 GB box, and the boot would
  then loop). Imported rows get a content-derived id, so an interrupted
  import resumes without duplicating anything and two legacy lines that
  shared a clock-derived id stay two records instead of one.
- `POST /api/v1/import`: ACL rules are validated with the parser hydration
  uses (a rule like `198.51.100.0/240` was stored, listed by the API and
  silently dropped at hydration, so its deny was never enforced — the
  `POST /api/v1/acl/rules` route had the same gap), `user_limits` must
  carry both defaults or neither (the runtime applies them as a pair), and
  negative trunk numbers are refused instead of wrapping to `u32::MAX`.
  The import transaction takes the write lock up front.
- `[security.ban] enabled = false` really stops enforcing bans (stored and
  manual ones included) instead of only stopping new ones.
- A TOML parse error no longer echoes the offending source line, which can
  be the API token or a trunk password, into the log, the reload report and
  `GET /api/v1/config`.
- A reload that re-hydrates from the store flips `/ready` to 200 (a boot
  with `allow_missing_store` used to stay 503 for ever).
- A missing store file is still created empty (that is how a first boot
  works), but it is now loud: a warning naming the path,
  `sbc_store_created_empty`, the `SBCStoreCreatedEmpty` alert rule and an
  `/api/v1/alerts` entry — on a box that had a store this is a lost volume
  or a mistyped restore, and every call is being refused.
- A failed `POST /api/v1/tls/reload` publishes the SSE `tls_reload_failed`
  alert this changelog promised (only the SIGHUP path did).
- `security.rtp_timeout` now also ends a call where **no** RTP ever
  arrived (media blocked in both directions): it was gated on having seen
  at least one packet, so such a call ran to `max_call_duration` in
  silence, billed and holding its ports.
- The RTP relay only moves a learned media endpoint for a datagram that
  looks like RTP (12 bytes, version 2), so a stray byte to the port cannot
  redirect a call's audio, and the move is logged at info again. A relay
  that stops normally logs at debug instead of a warning on every
  teardown. (A source filter and a first-packet latch stay lot-4 work.)
- Logging: the RTP-timeout, setup-timeout, failover and WS-close teardowns
  run inside the call span (their warnings, BYEs and CDR lines were
  escaping the `call{…}` fields), a failed message is logged once instead
  of twice, and an empty or very short Call-ID no longer makes a line
  adopt an unrelated live call's `uuid`.
- `/api/v1/alerts` no longer reports a trunk the operator disabled as
  `trunk_down`, and disabling a trunk keeps its per-trunk series while it
  still carries calls. A trunk's `answered` counters start at 0 so the ASR
  alert fires at 0 % instead of staying silent for want of a series.
- Failover re-checks the candidate trunk's live state (disabled, full,
  cooling, parked) instead of sending it a call it just refused.
- The CSV export prefixes a field starting with `=`, `@`, or `+`/`-` and a
  non-digit with an apostrophe (spreadsheet formula injection); `+33…`
  numbers keep their exact value. `?uuid=` uses the index instead of
  scanning the table.
- `backup_name_key` no longer panics on a non-ASCII filename in the backup
  directory (reached at boot), and the last-successful-backup gauge is
  seeded from disk even when the timer is disabled.
- The keys documented as "unused" (`[metrics]`, `general.name` /
  `instance_id`, `security.rate_limit_global` / `auth_challenge_timeout`)
  can now really be deleted from the file, and `[media] public_ip` — a key
  that never existed — is gone from the example.
- The management API's rate-limit table is capped at 4096 client IPs (idle
  entries swept, then the least recently seen evicted), like the SIP-side
  tables — a spray from many addresses could grow it without bound.
- An outbound trunk registration being replaced no longer has its
  `registered` flag cleared by the loop it replaced, and the shutdown
  un-REGISTER carries credentials when the trunk challenged us before.

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
  pages are newest first (from the SQLite store since lot 3; the in-memory
  cache of the last 10 000 records only serves a box without a store).
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
- The OPTIONS health check and the outbound REGISTER loop of a trunk were
  spawned once at boot and never stopped: a trunk created through the API
  was never probed or registered, a deleted one was probed forever, changed
  credentials or hosts were ignored until a restart. `trunk_tasks.rs` keeps
  one set of tasks per enabled trunk and re-syncs on every trunk write,
  SIGHUP and `POST /api/v1/reload` (start / stop / restart on host, port,
  transport, credentials, realm, register flag or interval change; a
  removed or disabled registered trunk gets an `Expires: 0`, a restarted
  one keeps its binding). Outbound REGISTER keeps one Call-ID and a
  monotonic CSeq per sequence; a `423 Interval Too Brief` is retried with
  the trunk's `Min-Expires` (remembered); a *refused* REGISTER (4xx/5xx)
  backs off 30 s → 15 min (reset on success) while a timeout or send
  failure retries every 60 s; an OPTIONS down→up transition re-registers
  immediately; a changed trunk host is re-resolved on hydrate.
- `/ready` answered 200 unconditionally; it now answers 503 with
  `{store, hydrated, listening}` until the SQLite store is open, the first
  hydration succeeded and the SIP listeners are bound (public, unchanged
  path — probes that treated 200 as "process up" now see readiness).
- SDP offers/answers and relayed BYE/ACK bodies (WebRTC `a=ice-pwd:`
  included) were printed at info; they are debug now, and the UDP parse
  warning's snippet is one line.
- SIGHUP / `POST /api/v1/reload` re-hydrated the store and re-read only
  the session-timer, `max_call_duration`, identity and `call_setup_timeout`
  keys; `[security.ban]`, `rate_limit_per_ip`, `rtp_timeout`,
  `invite_timeout` and the destination / user-limit flags were
  constructor-only. Every reload-class key now applies (see the table in
  docs/API.md); a hydration failure applies nothing from the new file;
  `POST /api/v1/reload` returns the real outcome (200 with `applied` /
  `restart_required`, 422 `reload_failed` when the file is unusable, 202
  when the engine did not answer within 5 s). docs/INSTALL.md and
  docs/WEBRTC.md no longer claim a reload picks up renewed certificates.
- Registrar (RFC 3261 §10.3). A phone re-registering from a new NAT port or
  with a new Contact URI no longer piles up stale bindings, and two phones
  behind one NAT no longer unregister each other: a binding is identified
  by its Contact URI, or by `+sip.instance` (and `reg-id`) when the phone
  sends one (the instance id alone identifying the binding is an extension
  of RFC 5626), and the source address follows the newest REGISTER so an
  inbound call reaches the phone's current port. Every Contact of a
  REGISTER is bound (or removed with `;expires=0`), `Contact: *` needs
  `Expires: 0` (400 otherwise), an unparsable Contact is 400, a REGISTER
  without Contact lists the bindings. The 200 OK carries every Via, every
  current binding with its remaining `expires` (and instance/reg-id), and
  an `Expires` header only when something was registered.
  `sbc_active_registrations` no longer counts expired bindings.

### Added
- Trunk state fed by real calls (lot 3). `TrunkState.active_calls`,
  `consecutive_failures` and the cooldown were only ever touched by the
  OPTIONS health check, so `max_concurrent_calls` and the failure ladder
  never applied to traffic. Every call now counts on the trunk its outbound
  leg (or its inbound source) is on, moves with a failover and is released
  by `finish_call`. A trunk is struck by a 408/500/502/503/504 final, a
  send failure, or no answer at all within `invite_timeout` (with a backup)
  / `call_setup_timeout` — never by the callee's answer (486, 603, 404,
  501, 6xx fail over or relay without cooling the trunk): 3 strikes in a
  row → 30 s, then 2 min, then 5 min without new calls; a 200 OK resets. A
  `503 Retry-After` parks the trunk for exactly that long (1 s–1 h); a park
  survives a 200 OK and is lifted by expiry or a re-enable
  (`POST /api/v1/trunks/{name}/enable`, which also forgives the cooldown).
  New metrics: `sbc_trunk_up{trunk}` (once the trunk answered OPTIONS at
  least once), `sbc_trunk_registered{trunk}`, `sbc_trunk_active_calls{trunk}`,
  `sbc_trunk_calls_total{trunk,direction,outcome}` (answered / rejected /
  failed / cancelled / timeout / failover — outbound ASR = answered / all on
  `direction="outbound"`), `sbc_trunk_enabled`, `sbc_trunk_available`,
  `sbc_trunk_unavailable_seconds`, `sbc_trunk_consecutive_failures` (from
  the trunk table, appended by `GET /metrics`) and the histograms
  `sbc_call_setup_seconds` (INVITE → answer, answered calls) and
  `sbc_call_duration_seconds` (billable window). `GET /api/v1/trunks`
  `health` is now `up` / `degraded` / `down` (cooldown running) / `parked`
  with `unavailable_for_secs`, and `GET /api/v1/alerts` raises `trunk_down`
  / `trunk_parked` only while the router skips the trunk; call-fed
  transitions publish `trunk_health` SSE events too. Alert rules
  `SBCTrunkDown`, `SBCTrunkRegistrationFailing`, `SBCTrunkAsrLow`,
  `SBCTrunkUnavailable` and a "Trunks" Grafana row ship in `monitoring/`.
- CDRs live in the SQLite store (migration 0003, table `cdrs` with indexes
  on `started_at`, `caller`, `callee`, `trunk_id`, `call_id` and a unique
  `uuid`). `finish_call` never does IO on the SIP loop any more: records go
  to a bounded queue (8192) and a writer task mirrors each batch into
  `[cdr] jsonl_path` (falls back to `[general] cdr_file`) and then commits
  it, retrying with backoff while the store refuses, and purges rows older
  than `[cdr] retention_days` daily. A record that cannot reach the queue
  is counted (`sbc_cdr_write_errors_total{stage="queue"}`) and stays in the
  in-memory cache only, so a queue that stays full does lose records — the
  mirror is the durable trail. The legacy JSONL history (the live file and
  its rotated `.N` siblings, `.gz` skipped) is imported once at first boot,
  streamed in chunks with content-derived ids so it costs bounded memory
  and resumes if interrupted; the writer is drained on shutdown within its
  timeout. `GET /api/v1/cdrs` gains filters (`from` / `to` as RFC 3339
  or unix seconds on `started_at`, `direction`, `trunk`, `caller` /
  `callee` case-sensitive prefixes, `sip_code`, `answered`, `uuid`,
  `call_id`), a keyset `cursor` (`next_cursor` in every page) and a CSV
  export (`?format=csv` or `Accept: text/csv`, streamed, RFC 4180 quoting);
  every bad parameter is a `bad_request` naming it; `limit=0` is 400.
  Record ids are real UUIDs (they were derived from the sub-second clock
  and could collide). `GET /api/v1/stats` gains a `cdr` block; metrics
  `sbc_cdr_write_errors_total{stage}`, `sbc_cdr_queue_length`,
  `sbc_cdrs_written_total`, `sbc_cdrs_purged_total`; alerts
  `SBCCdrWriteErrors`, `SBCCdrQueueBacklog`. `sbc_last_cdr_written_timestamp_seconds`
  now means "committed to the store".
- `[security] register_min_expires` (60), `register_max_expires` (3600),
  `register_default_expires` (3600), reload-class: a REGISTER asking less
  than the minimum is answered `423 Interval Too Brief` + `Min-Expires`
  (it used to be silently clamped up); more than the maximum is granted
  the maximum. `GET /api/v1/registrations` gains `instance_id`, `reg_id`,
  `registered_at`, and `user_agent` is filled; SSE `unregistered` carries
  `contact` and `reason` (`client`, `wildcard`, `expired`, `ws-closed`);
  the sweeper and a WS close publish it too.
- TLS / WSS listener certificates reload without a restart:
  `POST /api/v1/tls/reload` re-reads every listener's cert/key files off
  the event loop, proves the key signs for the certificate (an in-memory
  handshake — rustls 0.22 does not check the pair) and swaps atomically
  for the next accepted socket; a broken file keeps the previous
  certificate (422 `tls_reload_failed`, SSE `alert` `tls_reload_failed`).
  SIGHUP / `POST /api/v1/reload` do the same. `GET /api/v1/tls/certificates`
  lists subject, validity, SHA-256 fingerprint and files; gauge
  `sbc_tls_cert_expiry_timestamp_seconds{listener,bind}`, alerts
  `SBCCertExpiringSoon` / `SBCCertExpired`, `/api/v1/alerts`
  `tls_cert_expiring` / `tls_cert_expired`. The certbot hook in INSTALL.md
  §6 calls the reload route (restart only when the API is unreachable).
- `GET /api/v1/config`: the effective configuration (secrets `"***"`),
  what a reload already loaded but could not apply (`restart_required`),
  what the on-disk file would change (`file.reload_pending`,
  `file.restart_required`, or its `parse_error`), the last reload report
  and the key classes (reload / restart / seed / unused). Metrics
  `sbc_config_reloads_total{result}`,
  `sbc_config_last_reload_timestamp_seconds`; alert `SBCConfigReloadFailed`;
  SSE `config` events `runtime/reloaded` and `runtime/reload_failed`.
- Structured logging (lot 3). Every log line of a call — SIP handlers,
  media relay, timer and admin teardowns — carries a `call` span with
  `uuid`, `call_id`, `trunk` and `direction` (recorded as they become
  known; absent, not empty, for a local call's trunk). `[logging] format =
  "json"` emits one object per line (`timestamp`, `level`, `target`,
  `message`, `span`) for log shipping, `"text"` prefixes lines with
  `call{uuid=… call_id=… trunk=…}:` for journald. The writer is
  non-blocking and lossy (journald back-pressure never stalls the SIP
  loop); dropped lines are counted in `sbc_log_dropped_lines_total` with
  the alert rule `SBCLogLinesDropped`.
- Store backups: `POST /api/v1/backup` writes a consistent `VACUUM INTO`
  copy `sbc-<timestamp>.db` into `[database] backup_dir` (default
  `<dir of sqlite_path>/backups`, created 0700, files 0600 — they hold
  trunk passwords and user HA1s), prunes to `backup_keep` (7) copies and
  answers `{path, bytes, took_ms, pruned}` (409 while another backup runs);
  a timer does the same every `backup_interval_hours` (24; 0 disables),
  first run a minute after boot unless a recent copy exists. Metrics
  `sbc_store_available`, `sbc_store_backups_enabled`,
  `sbc_store_backup_interval_seconds`,
  `sbc_store_backup_last_success_timestamp_seconds`,
  `sbc_store_backup_last_bytes`, `sbc_store_backup_failures_total`; alert
  rules `SBCStoreUnavailable`, `SBCStoreBackupStale`, `SBCStoreBackupFailed`;
  SSE `alert` kind `backup_failed`. Restore stays "stop, copy the file
  over `sqlite_path` (delete `-wal`/`-shm`), start" (INSTALL.md §10).
- Config import: `POST /api/v1/import?mode=merge|replace&dry_run=true`
  loads a `GET /api/v1/export` document (version 1 or 2, up to 8 MiB) into
  the store in one transaction and re-hydrates the runtime — a live
  restore, or a way to carry a config to another box. `merge` upserts the
  rows the document carries, `replace` also deletes the rows a section
  does not list (trunk routes cascade, a `null` user limit puts the TOML
  default back); absent sections are untouched. Every row is validated
  first (400 `invalid_import` naming the spot, nothing written), a replace
  that would drop a trunk with calls is 409 `trunk_busy`, the report
  counts inserted/updated/deleted per section. Routes are now upserted by
  (`prefix`, `trunk_name`); constraint violations surface as a typed
  storage error instead of a bare "Database error". The nginx block in
  INSTALL.md gains `client_max_body_size 16m`.
- Trunk tasks: `[trunk_health]` section (`options_interval`,
  `options_timeout`, `register_backoff_max`), SSE events
  `trunk_registered` / `trunk_unregistered`, `registered` on
  `GET /api/v1/trunks`, `trunk_unregistered` in `GET /api/v1/alerts`.
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
- CDR pages are ordered by `started_at` then insertion (durable, indexed)
  instead of end-of-call order, so two overlapping calls may swap places;
  `has_more` is exact. Restoring a pre-upgrade store copy also rewinds the
  CDR table (export CSV first); the `sbc-db-*` deploy backups grow with the
  CDR retention. Rolling back from this release to a 0.19 binary needs
  `DELETE FROM _sqlx_migrations WHERE version IN (2, 3)`.
- Registrations: the maximum granted interval drops from 86400 s to
  3600 s (phones re-REGISTER hourly, as the 200's Contact tells them) and
  a REGISTER asking under 60 s gets 423 instead of a silent clamp
  (`register_min_expires = 1` disables the check). `contact` in
  `GET /api/v1/registrations` and in the `registered` / `unregistered`
  events is the bare URI (no `<>`, no header parameters).
- A TLS / WSS listener whose private key does not match its certificate
  refuses to start (it used to start and fail every handshake). The
  SIP-over-TLS listener now accepts SEC1 `EC PRIVATE KEY` files like the
  WSS listener always did (both go through one loader).
- A reload applies whatever `[security]` reload-class values are on disk,
  including `[security.ban] whitelist` (an emptied list un-whitelists;
  loopback stays whitelisted) and `rate_limit_per_ip`: check
  `GET /api/v1/config` → `file.reload_pending` before the first SIGHUP
  after this upgrade. TOML `[security.user_limits] default_*` apply only
  until `PUT /api/v1/security/user-limits` has set store values.
- `[logging] level` is honoured (it was parsed into nothing): precedence
  `sbc --verbose` > `RUST_LOG` > TOML. The per-message and per-RTP-packet
  lines (`Handling … request`, `Response Call-ID`, `Transport reply`,
  `RTP A recv #…`, SDP/BYE bodies, DTLS/STUN steps, per-refresh trunk
  REGISTER lines…) moved to debug: a normal answered call is about seven
  info lines, all in its span. Anything grepping journald for the old
  `Response Call-ID:` line should grep the span's `call_id` instead.
- The SBC refuses to start when the SQLite store cannot be opened or
  hydrated (it used to warn and run with no users, trunks or DIDs while
  reporting ready). `[database] allow_missing_store = true` restores the
  old behaviour. With the documented systemd unit (`Restart=on-failure`)
  the unit ends failed within seconds — check `journalctl -u sbc`.
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
