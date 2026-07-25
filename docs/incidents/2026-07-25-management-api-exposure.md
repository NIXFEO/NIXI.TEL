# Incident 2026-07-25 — Management API exposed to the public Internet

| | |
|---|---|
| **Date** | 2026-07-25 |
| **Server** | sip.nixi.tel — NIXI SBC |
| **Severity** | Critical |
| **Status** | Resolved (token rotation completed) |

## Summary

The SBC management API — which can create, enumerate and delete SIP users,
trunks and DIDs — was reachable from the public Internet **without any
authentication**. The API itself was correctly bound to `127.0.0.1:8080` and
port 8080 was closed at the firewall, but the nginx vhost `sip.nixi.tel`
reverse-proxied `https://sip.nixi.tel/ → 127.0.0.1:8080` **and injected the
`Authorization: Bearer <token>` header itself**. Because nginx supplied the
credential on every request, any anonymous visitor was authenticated as
administrator.

No malicious activity was found. The exposed token is nonetheless treated as
compromised and has been rotated.

## Root cause

Two mistakes combined:

1. **Public proxy to a private admin surface.** The `location /` block of the
   `sip.nixi.tel` vhost (port 443) proxied straight to the management API,
   turning a localhost-only service into a public one.
2. **Credential injection at the proxy.** The same block set
   `proxy_set_header Authorization "Bearer <token>"`, so the client did not
   need to present anything. This defeated the API's bearer-token auth
   entirely.

Either alone would have been bad; together they made the full admin API
open to the world.

Contributing factor: the token (and other secrets) lived in clear text in
`production.toml`, so exposing the API was equivalent to leaking the token.

## Timeline (2026-07-25, UTC)

- **T0** — Diagnostic review of the nginx vhost reveals the public proxy and
  the injected `Authorization` header.
- **T0** — Reachability confirmed: a single external
  `GET /api/v1/users` returned `200` (probe by the diagnostic team).
- **T0** — CDRs (`/var/log/sbc/cdr.jsonl`) and the user list reviewed for
  abuse: none found.
- **T0+** — Remediation applied (see below): nginx proxy removed, token
  rotated and moved to an environment file, binary hardened, config
  permissions tightened, stale secrets removed.

## Impact

**Observed:** one external `GET /api/v1/users → 200` (the diagnostic team's
own probe). **0 CDRs** attributable to abuse. No malicious SIP account
creation or deletion detected.

**Potential (had it been exploited):**

- **Toll fraud** — arbitrary SIP account creation → billed outbound calls on
  the PSTN trunk (premium/international destinations).
- **Data exposure** — enumeration of all customer SIP accounts and their
  configuration.
- **Denial of service** — deletion or alteration of existing accounts and
  routing.

## Remediation applied

1. **Closed the public exposure.** Removed the nginx proxy to `:8080` from
   the `sip.nixi.tel` vhost. The management API is now reachable **only via
   SSH + localhost** (or a properly restricted reverse proxy — no
   `Authorization` injection, IP/mTLS restricted, 8080 kept closed at the
   firewall). See
   [INSTALL.md §7](../INSTALL.md#7-securing-the-management-api).
2. **Rotated and externalised the token.** The API token was regenerated,
   removed from the TOML and from nginx, and is now provided via the
   `SBC_API_TOKEN` environment variable loaded by systemd
   (`EnvironmentFile=/etc/sbc/sbc.env`, `600 root:root`).
3. **Hardened the binary.** The SBC now: refuses to start when the API is
   enabled without a token (fail-closed); rate-limits and audit-logs API
   requests; and validates non-loopback binds.
4. **Tightened config permissions.** `production.toml` set to `600 root:root`.
5. **Removed stale secrets.** The obsolete `postgres_url` / `redis_url`
   entries were dropped (the Postgres/Redis dependencies were removed from
   the code — commit `d934cfc`).

## Secrets rotated

- Management API token — **regenerated**, now env-var only.
- SIP user passwords and trunk credentials — reviewed; rotate any that were
  present in the exposed config (see
  [SECURITY.md → Rotating credentials](../../SECURITY.md#rotating-credentials)).

*(No secret value is recorded in this report or anywhere in the repository.)*

## Follow-up actions

- [ ] Confirm the new token is deployed to all clients/automation and the old
  one appears nowhere (configs, nginx, shell history, CI).
- [ ] Remove the temporary `webtest1` / `webtest2` diagnostic accounts if no
  longer needed.
- [ ] Verify firewall rules expose only 80/443/5060/5061/8443 + the RTP range;
  8080 and 9090 stay closed.
- [ ] Audit other deployments/vhosts for the same "proxy injects the Bearer"
  anti-pattern.
- [ ] Alert on API auth failures and on user/trunk mutations in central
  logging.

## Lessons

- A localhost bind and a closed firewall port are not enough if a public
  reverse proxy tunnels to them.
- A reverse proxy must **never** mint credentials on behalf of clients — the
  client presents its own token; the proxy only restricts and forwards.
- Secrets belong in environment/secret stores with `600` permissions, never
  in a file that is part of a public repo's example set.
