# REST API Reference

Base URL: `http://<api_bind_address>:<api_port>` (default `127.0.0.1:8080`).

## Authentication

Every endpoint except `/health` and `/ready` requires the bearer token
(`management.api_auth_token`), compared in constant time. Three forms:

```
Authorization: Bearer <token>
X-Api-Token: <token>
GET /api/v1/events?token=<token>        # for EventSource (no headers)
```

Errors are uniform: `{"error": "<message>", "code": "<machine_code>"}`.

## Mutation semantics

Every write goes to the SQLite store first, is applied to the live runtime
immediately (no reload needed), and emits a `config` event on the SSE bus.
`GET /api/v1/export` returns the full dynamic config for backup; restoring
is replaying it through the CRUD endpoints.

## Endpoints

### Observability

| Method | Path | Description |
|---|---|---|
| GET | `/health` | 200 healthy / 503 (public) |
| GET | `/ready` | 200 `{"status":"ready","store":true,"hydrated":true,"listening":true}` once the SQLite store is open, hydrated and the SIP listeners are bound; 503 `{"status":"not_ready",…}` otherwise (a TOML-only box with `allow_missing_store` is never ready). Public. |
| GET | `/metrics` | Prometheus text exposition (`sbc_*`): calls, SIP traffic, auth, anti-fraud, media, per-trunk series (`sbc_trunk_up/registered/active_calls/calls_total{trunk,direction,outcome}`, `sbc_trunk_enabled/available/unavailable_seconds/consecutive_failures`), `sbc_call_setup_seconds` / `sbc_call_duration_seconds` histograms — see `monitoring/README.md` |
| GET | `/api/v1/stats` | active calls, totals, uptime, `cdr` (`backend` sqlite/file/memory, `queue`, `written_total`, `write_errors_total`, `last_written_at`) |
| GET | `/api/v1/alerts` | current conditions: `trunk_down` (failure cooldown running) / `trunk_parked` (503 Retry-After) with `unavailable_for_secs`, `trunk_unregistered`, `tls_cert_expiring` (< 14 days) / `tls_cert_expired`, `high_auth_failure_rate`… |
| GET | `/api/v1/events?types=call,registration,trunk,alert,config` | **SSE** stream |

### Calls & registrations

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/calls` | active calls |
| DELETE | `/api/v1/calls/{uuid}` | administrative teardown: `202`, the SIP engine BYEs/CANCELs both legs within a second and writes a CDR `admin-kick` |
| GET | `/api/v1/registrations` | current bindings: `aor`, `contact` (bare URI), `expires_in`, `registered_at`, `transport`, `received_ip` / `received_port` (where an inbound call is sent), `user_agent`, `instance_id` / `reg_id` (RFC 5626) — expired bindings are not listed |
| GET | `/api/v1/cdrs` | CDRs from the SQLite store, newest first (`started_at`, then insertion). Paging: `limit` (1–1000, default 100), `offset`, or the keyset `cursor` from the previous page's `next_cursor` (exclusive with `offset`). Filters on `started_at`: `from` (inclusive) / `to` (exclusive) as RFC 3339 or unix seconds; `direction` (`inbound` / `outbound` / `local`), `trunk`, `caller` / `callee` (case-sensitive prefixes, ≤ 64 chars), `sip_code`, `answered` (`true` / `false`), `uuid`, `call_id`. `?format=csv` or `Accept: text/csv` streams the same selection as RFC 4180 CSV (`limit` caps the rows, `offset` is ignored) — use the header (`curl -H "Authorization: Bearer $SBC_API_TOKEN" -o cdrs.csv …`), `?token=` only for a one-off browser download (it lands in nginx access logs). A bad parameter is 400 `bad_request` naming it. Without a store (TOML-only box) only plain paging of the in-memory cache is served; filters and CSV answer 503 `store_unavailable`. `GET /api/v1/export` stays config-only. |

#### CDR record

Every call gets exactly one record when it ends, whatever the cause
(`disconnect_reason`). Bill on `billable_secs` (answer → end);
`duration_secs` is the whole setup → end span, as before.

| Field | Meaning |
|---|---|
| `id`, `uuid`, `call_id` | record id, B2BUA call uuid (as in `/calls` and SSE), SIP Call-ID |
| `caller`, `callee`, `source_ip` | From user, dialed number (DID-mapped user for inbound), caller's IP |
| `direction` | `outbound` (user → trunk), `inbound` (trunk → user), `local` (user → user) |
| `trunk_id`, `codec`, `is_webrtc` | trunk name, negotiated codec, WebRTC caller |
| `started_at`, `answered_at`, `ended_at` | unix seconds: INVITE, 200 OK toward the caller (`null` if never answered), end |
| `duration_secs`, `billable_secs` | setup → end; answer → end (0 when unanswered) |
| `sip_code` | final status the caller's INVITE got: 200 once answered, 487 cancelled, 408 setup timeout, the relayed/generated code otherwise, `null` when none was sent |
| `disconnect_reason` | `normal-clearing`, `cancelled`, `rejected-<code>`, `timeout` (max duration), `setup-timeout`, `rtp-timeout`, `shutdown`, `ws-closed`, `admin-kick`, `dialog-lost` |
| `reason` | SIP `Reason` header: the peer's on its BYE/CANCEL, the SBC's own on the BYEs it sends |
| `hangup_by` | who ended the call: `caller`, `callee` (the far end, or its rejection), `sbc` |

| `v` | record schema version: `2` from 0.20; `1` rows (older file lines) carry no billing window |

Security events (`GET /api/v1/security/status` → `recent_events`, SSE `alert`): `ban_issued`, `ban_lifted`, `auth_failure`, `destination_blocked`, `user_limit`, `identity_mismatch` (a source claimed an identity that is not its own: REGISTER for another AOR, INVITE From another user, a trunk presenting a local user).

### SIP users

| Method | Path | Body |
|---|---|---|
| GET | `/api/v1/users` | — (never returns password hashes) |
| POST | `/api/v1/users` | `{"username","password"}` or `{"username","ha1"}`, optional `display_name`, `enabled`, `max_concurrent_calls`, `max_calls_per_minute` |
| PUT | `/api/v1/users/{u}` | same body (full replace of the other fields); omit password to keep it |
| PATCH | `/api/v1/users/{u}` | any subset of the fields (RFC 7396 merge): only what is sent changes, the password stays unless `password`/`ha1` is given; unknown keys → 400 |
| DELETE | `/api/v1/users/{u}` | — |

### DIDs (inbound number → user)

| Method | Path | Body |
|---|---|---|
| GET/POST | `/api/v1/dids` | `{"number","sip_user","display_name?","enabled?"}` |
| DELETE | `/api/v1/dids/{number}` | — |

### Trunks

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/trunks` | stored config + live state, password redacted: `health` = `up` / `degraded` (failures, still selectable) / `down` (failure cooldown running) / `parked` (the trunk asked for a pause with `503 Retry-After`; lifted by expiry or `/enable`), `unavailable_for_secs` (null when selectable), `active_calls`, `total_calls`, `failed_calls` (failed attempts **and** OPTIONS misses), `consecutive_failures`, `registered` (true/false for trunks with `register_with_trunk`, null otherwise) |
| POST | `/api/v1/trunks` | full field set: `name`, `host`, `port`, `transport` (UDP/TCP/TLS/WS/WSS), `auth_required`, `username`, `password`, `register_with_trunk`, `prefix_patterns[]`, `priority`, `weight`, `cost_per_minute`, `number_format`, `country_code`, `national_prefix`, `caller_number_override`, `allowed_codecs[]`, `max_concurrent_calls`, `tls_sni`, `tls_ca_cert`, `tls_verify`, `tls_client_cert`, `tls_client_key` |
| GET/PUT/PATCH/DELETE | `/api/v1/trunks/{name}` | GET masks `password` as `"***"`; PUT replaces every field (an omitted `password` clears it) and refuses `"***"`; PATCH merges any subset (RFC 7396: `null` clears a field, the password and TLS material stay unless given, unknown keys such as the GET-only `tls`/`health`/`registered` → 400); DELETE refuses while calls are active. Every write re-syncs the trunk's OPTIONS health check and outbound REGISTER loop (start, stop, or restart when host/port/transport/credentials/interval change) |
| POST | `/api/v1/trunks/{name}/enable` · `/disable` | `enable` also forgives the failure cooldown and a `503 Retry-After` park |

### Routes (prefix → trunk)

| Method | Path | Body |
|---|---|---|
| GET/POST | `/api/v1/routes` | `{"prefix","trunk_name","priority?","enabled?","description?"}` |
| PUT/DELETE | `/api/v1/routes/{id}` | |

### ACL

| Method | Path | Body |
|---|---|---|
| GET/POST | `/api/v1/acl/rules` | `{"cidr","action":"allow"\|"deny","direction?","priority?","comment?"}` |
| DELETE | `/api/v1/acl/rules/{id}` | |
| GET/PUT | `/api/v1/acl/default` | `{"action":"allow"\|"deny"}` |

### Security / anti-fraud

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/security/status` | bans, blocks, limits, last 100 events |
| GET/POST | `/api/v1/security/bans` | `{"ip","duration_secs?","reason?"}` — persisted across restarts |
| DELETE | `/api/v1/security/bans/{ip}` | lift a ban |
| GET/POST | `/api/v1/security/destination-rules` | `{"prefix","action","user?","description?","id?"}` — persisted across restarts (table `destination_rules`; TOML rules and the IRSF seeds are imported once at first boot) |
| DELETE | `/api/v1/security/destination-rules/{id}` | |
| GET/PUT | `/api/v1/security/user-limits` | defaults `{"default_max_concurrent_calls","default_max_calls_per_minute"}` — defaults persisted in `settings`, per-user overrides on the user row (`users.max_*`, so the user must exist) |
| PUT/DELETE | `/api/v1/security/user-limits/{user}` | per-user override |

### Config

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/reload` (alias `/api/v1/config/reload`) | re-reads the TOML (reload-class keys, table below) and re-hydrates from the store; 200 `{"status":"reloaded","applied":[…],"restart_required":[…],"hydrated":bool}`, 422 `reload_failed` (unusable file, nothing changed), 202 `reload_triggered` when the engine did not answer within 5 s (check `GET /api/v1/config`). Concurrent SIGHUP/API triggers coalesce. |
| GET | `/api/v1/config` | effective configuration with secrets masked (`running`), `restart_required` (loaded by a reload but needs a restart), `file` = the on-disk TOML's `reload_pending` / `restart_required` or `parse_error` / `readable:false`, `last_reload`, `key_classes`, `store`. Exposes usernames, trunk hosts and file paths like `/users`, `/trunks` and `/export`: admin only. |
| GET | `/api/v1/tls/certificates` | one entry per TLS/WSS listener: `listener`, `bind`, `cert_file`, `key_file`, `subject`, `not_before`, `not_after`, `fingerprint_sha256`, `chain_len`, `loaded_at` (`[]` without secure listeners) |
| POST | `/api/v1/tls/reload` | re-read every listener's cert/key (what a certbot deploy hook calls): 200 `{"status":"ok","listeners":[{listener,bind,changed,…}]}`; 422 `tls_reload_failed` with the same `listeners` detail when one could not reload (its previous certificate stays in use) |
| GET | `/api/v1/export` | full dynamic-config dump (includes auth material — admin only) |
| POST | `/api/v1/backup` | `VACUUM INTO` copy of the store into `[database] backup_dir` as `sbc-<timestamp>.db`, pruned to `backup_keep`: 200 `{"path","bytes","took_ms","pruned":[…]}`, 409 `backup already in progress`, 503 without a store. The copy holds trunk passwords and user HA1s. |

### Legacy aliases

`GET /api/calls`, `/api/registrations`, `/api/status`, `/api/trunks`.

## Reload vs restart

Key classes assume the SQLite store is open (always in production; on a
TOML-only box the seed keys are re-applied by a reload).

| Class | Keys | Applied by |
|---|---|---|
| reload | `security.max_call_duration`, `call_setup_timeout`, `rtp_timeout`, `invite_timeout`, `session_timer_enabled`, `session_expires`, `min_se`, `register_aor_check`, `served_domains`, `trunk_local_from`, `rate_limit_per_ip`, `[security.ban]`, `[security.destinations]` `enabled` / `default_action` / `default_country_code`, `[security.user_limits]` `enabled` / `default_*` | SIGHUP or `POST /api/v1/reload` (timers and limits apply to new calls) |
| restart | `general.cdr_file`, `[network]` listeners and `public_ipv4`, `media.rtp_port_range`, `[database]`, `security.sip_realm`, `enable_digest_auth`, `[management]`, `[trunk_health]`, `[logging]` | `systemctl restart sbc` (graceful) |
| seed | `[security.sip_users]`, `[[trunks]]`, `[[dids]]`, `[security.destinations] rules` / `seed_irsf_rules`, `[[security.user_limits.overrides]]` | imported once at first boot into the store, then the API |
| unused | `general.name` / `instance_id`, `network.public_ipv6`, `security.rate_limit_global` / `auth_challenge_timeout`, `[media]` except the port range, `[metrics]` | nothing |

## SSE events

`GET /api/v1/events` streams JSON events with the SSE `event:` field set to
the category: `call` (`call_started`/`call_answered`/`call_ended`),
`registration` (`registered` per contact with its granted `expires`,
`unregistered` with `contact` and `reason` = `client` / `wildcard` /
`expired` / `ws-closed`), `trunk` (`trunk_health` up/down transitions,
`trunk_registered` once per accepted outbound REGISTER, `trunk_unregistered`
with the reason once per failure transition), `alert` (incl. security:
bans, destination blocks, limit hits), `config` (CRUD changes, plus
`runtime` / `reloaded` and `runtime` / `reload_failed` for reloads). Slow
consumers receive a `lagged` event with the number of skipped messages.

```bash
curl -N "http://127.0.0.1:8080/api/v1/events?types=call,alert&token=$TOKEN"
```
