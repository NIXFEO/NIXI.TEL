# Security Policy

## Reporting a vulnerability

Email **hello@nixfeo.com** with a description, reproduction steps and an
impact assessment. Please do not open public issues for security reports.
You will get an acknowledgment within 72 hours.

## Scope

NIXI SBC is MIT-licensed and its code is public. The following areas are
particularly interesting:

- SIP parsing / message construction (rsip fork, `sip_builder`)
- Digest authentication, nonce handling, the fail2ban path
- TLS (inbound listeners, outbound trunk connections, mTLS)
- SRTP/DTLS key handling
- The management API (auth bypass, injection, SSRF via trunk config)
- The SQLite store (paths, permissions, injection)

## Secrets and deployment hygiene

The repository is public — **no real secret ever belongs in the repo, in
`config/*.toml`, in nginx config, or in a commit.** Use placeholders in
examples (`<VOTRE_TOKEN>`, `openssl rand -hex 32`, …) and inject real values
at runtime.

- **Keep secrets out of config files.** Supply the management API token via
  the `SBC_API_TOKEN` environment variable (systemd `EnvironmentFile`), not
  `management.api_auth_token`. `SBC_API_TOKEN` overrides the TOML key.
- **Restrict file permissions.** The secrets env file and any config holding
  a secret must be `600 root:root`. The SQLite store is created `0600`.
- **Never expose the management API to the public Internet.** Bind it to
  `127.0.0.1` and administer it over SSH / a localhost tunnel, or place it
  behind a reverse proxy restricted by source IP or mutual TLS. Keep port
  8080 (API) and 9090 (metrics) closed at the firewall.
- **Never let a reverse proxy inject the `Authorization` header.** If nginx
  adds `Bearer <token>` to every request, the API is effectively open to
  anyone who can reach the proxy. The client must present its own token.
  (This is the root cause of the
  [2026-07-25 incident](docs/incidents/2026-07-25-management-api-exposure.md).)
- **Fail-closed.** The API refuses to start when it is enabled without a
  token, so a missing secret is caught at boot rather than running open.
- Keep `security.ban` enabled; whitelist only infrastructure IPs.
- Review `security.destinations` rules for your dial plan (IRSF ranges are
  blocked by default).
- Run as a dedicated non-root user; use real certificates for TLS/WSS
  listeners and `tls_verify = true` (the default) for TLS trunks.

Full deployment guidance:
[docs/INSTALL.md §7 — Securing the management API](docs/INSTALL.md#7-securing-the-management-api).

## Rotating credentials

Rotate a credential whenever it may have been exposed (config leak, proxy
misconfiguration, staff turnover, or on a routine schedule).

### Management API token

1. Generate a new token: `openssl rand -hex 32`.
2. Update `/etc/sbc/sbc.env` (`SBC_API_TOKEN=…`, mode `600 root:root`).
3. Restart gracefully: `sudo systemctl restart sbc` (sends BYE on stop).
4. Update every client/automation that calls the API (deploy hooks,
   `scripts/api_smoke.sh`, monitoring).
5. Invalidate the old token — ensure it appears nowhere in configs, nginx,
   shell history or CI secrets.

### SIP user passwords

Rotate via the API (the store is the source of truth):

```bash
curl -X PATCH -H "Authorization: Bearer $SBC_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/users/<username> \
  -d '{"password":"<NEW_PASSWORD>"}'
```

Re-provision the affected endpoints/soft-clients with the new password.

### Trunk credentials

Rotate the secret with your carrier first, then update the trunk over the
API (`PATCH /api/v1/trunks/<name>` with the new `password`), or in the
first-boot seed if the store has not been populated yet.

After any suspected exposure, also review `/var/log/sbc/cdr.jsonl` for
anomalous outbound calls (premium/international destinations, volume spikes)
and `GET /api/v1/users` for accounts you did not create.
