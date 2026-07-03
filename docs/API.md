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
| GET | `/ready` | readiness probe (public) |
| GET | `/metrics` | Prometheus text format |
| GET | `/api/v1/stats` | active calls, totals, uptime |
| GET | `/api/v1/alerts` | trunk down, auth/call failure rates |
| GET | `/api/v1/events?types=call,registration,trunk,alert,config` | **SSE** stream |

### Calls & registrations

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/calls` | active calls |
| DELETE | `/api/v1/calls/{uuid}` | administrative teardown |
| GET | `/api/v1/registrations` | registered contacts |
| GET | `/api/v1/cdrs?limit=&offset=` | paginated CDRs (`has_more` flag) |

### SIP users

| Method | Path | Body |
|---|---|---|
| GET | `/api/v1/users` | — (never returns password hashes) |
| POST | `/api/v1/users` | `{"username","password"}` or `{"username","ha1"}`, optional `display_name`, `enabled`, `max_concurrent_calls`, `max_calls_per_minute` |
| PUT | `/api/v1/users/{u}` | same body; omit password to keep it |
| DELETE | `/api/v1/users/{u}` | — |

### DIDs (inbound number → user)

| Method | Path | Body |
|---|---|---|
| GET/POST | `/api/v1/dids` | `{"number","sip_user","display_name?","enabled?"}` |
| DELETE | `/api/v1/dids/{number}` | — |

### Trunks

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/trunks` | stored config + live health, password redacted |
| POST | `/api/v1/trunks` | full field set: `name`, `host`, `port`, `transport` (UDP/TCP/TLS/WS/WSS), `auth_required`, `username`, `password`, `register_with_trunk`, `prefix_patterns[]`, `priority`, `weight`, `cost_per_minute`, `number_format`, `country_code`, `national_prefix`, `caller_number_override`, `allowed_codecs[]`, `max_concurrent_calls`, `tls_sni`, `tls_ca_cert`, `tls_verify`, `tls_client_cert`, `tls_client_key` |
| GET/PUT/DELETE | `/api/v1/trunks/{name}` | DELETE refuses while calls are active |
| POST | `/api/v1/trunks/{name}/enable` · `/disable` | |

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
| GET/POST | `/api/v1/security/destination-rules` | `{"prefix","action","user?","description?"}` |
| DELETE | `/api/v1/security/destination-rules/{id}` | |
| GET/PUT | `/api/v1/security/user-limits` | defaults `{"default_max_concurrent_calls","default_max_calls_per_minute"}` |
| PUT/DELETE | `/api/v1/security/user-limits/{user}` | per-user override |

### Config

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/reload` (alias `/api/v1/config/reload`) | re-hydrate runtime from the store |
| GET | `/api/v1/export` | full dynamic-config dump (includes auth material — admin only) |

### Legacy aliases

`GET /api/calls`, `/api/registrations`, `/api/status`, `/api/trunks`.

## SSE events

`GET /api/v1/events` streams JSON events with the SSE `event:` field set to
the category: `call` (`call_started`/`call_answered`/`call_ended`),
`registration`, `trunk` (health transitions), `alert` (incl. security:
bans, destination blocks, limit hits), `config` (CRUD changes). Slow
consumers receive a `lagged` event with the number of skipped messages.

```bash
curl -N "http://127.0.0.1:8080/api/v1/events?types=call,alert&token=$TOKEN"
```
