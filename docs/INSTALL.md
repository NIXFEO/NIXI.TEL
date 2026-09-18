# Installation Guide

Deploying NIXI SBC in production (example on Ubuntu 24.04 LTS). The SBC is a
single static binary plus a TOML config file and an embedded SQLite store —
**no external database is required**.

## Contents

1. [Requirements](#1-requirements)
2. [Server preparation](#2-server-preparation)
3. [Building](#3-building)
4. [Configuration](#4-configuration)
5. [systemd service](#5-systemd-service)
6. [TLS / WSS certificates](#6-tls--wss-certificates)
7. [Securing the management API](#7-securing-the-management-api)
8. [Firewall](#8-firewall)
9. [Verification](#9-verification)
10. [Upgrades & rollback](#10-upgrades--rollback)

---

## 1. Requirements

**Hardware** (small deployment): 1 vCPU, 1 GB RAM, 10 GB disk. The service
itself uses ~20 MB RAM; media relay scales with concurrent calls.

**Software**: a recent Rust toolchain (stable), `cmake` and a C compiler
(for the bundled Opus codec), `git`. Optional: `certbot` for TLS/WSS
certificates, a reverse proxy (nginx) to expose the management API.

**Network ports** (defaults, all configurable):

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP/TCP | SIP |
| 5061 | TCP | SIP over TLS |
| 8443 | TCP | SIP over WSS (WebRTC) |
| 10000–20000 | UDP | RTP media |
| 8080 | TCP | Management REST API, incl. `GET /metrics` for Prometheus (bind to localhost) |

**DNS** (optional, for TLS/WSS with real certificates): point your SIP and
WebRTC hostnames at the server's public IP.

## 2. Server preparation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential cmake pkg-config git curl

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Recommended: run the SBC under a dedicated non-root user and raise the file
descriptor limit for high call volumes (`/etc/security/limits.conf` →
`nofile 65535`).

## 3. Building

```bash
git clone https://github.com/NIXFEO/NIXI.TEL.git
cd NIXI.TEL
cargo build --release            # needs cmake; ~10 min on a small VPS
sudo cp target/release/sbc /usr/local/bin/sbc
```

If your cmake is 4.x, prefix the build with
`CMAKE_POLICY_VERSION_MINIMUM=3.5` (the vendored libopus declares an older
minimum).

## 4. Configuration

```bash
sudo mkdir -p /etc/sbc /var/lib/sbc /var/log/sbc
sudo cp config/sbc.toml.example /etc/sbc/sbc.toml
sudo chmod 600 /etc/sbc/sbc.toml
```

Edit `/etc/sbc/sbc.toml` — at minimum set `public_ipv4`, `sip_realm` and
`database.sqlite_path` (e.g. `/var/lib/sbc/sbc.db`). The management API needs
a strong token; **prefer supplying it via the `SBC_API_TOKEN` environment
variable** (see [§7](#7-securing-the-management-api)) rather than writing
`management.api_auth_token` in clear text in the TOML:

```bash
openssl rand -hex 32   # generate an API token
```

The API refuses to start when it is enabled without a token (fail-closed),
so a missing/empty token is caught at boot rather than silently running
unauthenticated.

The example config is fully commented, including the anti-fraud sections
(`[security.ban]`, `[security.destinations]`, `[security.user_limits]`) and
RFC 4028 session timers. TOML `[security.sip_users]`, `[[trunks]]` and
`[[dids]]` entries are imported once into the SQLite store on first boot;
after that, manage them over the API (see [API.md](API.md)).

## 5. systemd service

`/etc/systemd/system/sbc.service`:

```ini
[Unit]
Description=NIXI SBC — Session Border Controller
After=network.target

[Service]
Type=simple
# Secrets (API token) live here, not in the TOML — see §7
EnvironmentFile=/etc/sbc/sbc.env
ExecStart=/usr/local/bin/sbc --config /etc/sbc/sbc.toml
Restart=on-failure    # a store that cannot be opened is fatal: the unit ends failed within seconds, see journalctl
ExecReload=/bin/kill -HUP $MAINPID   # `systemctl reload sbc` = re-read the reload-class keys (docs/API.md)
# Graceful stop: the SBC sends BYE to active peers on SIGTERM
KillSignal=SIGTERM
TimeoutStopSec=15
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Create the secrets file that systemd reads (see §7 for details):

```bash
sudo install -m 600 -o root -g root /dev/null /etc/sbc/sbc.env
echo "SBC_API_TOKEN=$(openssl rand -hex 32)" | sudo tee /etc/sbc/sbc.env >/dev/null
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sbc
sudo systemctl status sbc
```

**Always stop gracefully** (`systemctl stop sbc`) so the SBC can BYE active
calls — this prevents ghost sessions on remote trunks. Never `kill -9`.

### Logs

The SBC logs to stdout, i.e. journald under systemd. Every line of a call
carries a `call` span (`uuid`, `call_id`, `trunk`, `direction`), so
`journalctl -u sbc | grep <Call-ID>` finds a whole call; per-message and
per-packet diagnostics are at debug. Level precedence: `sbc --verbose` >
`RUST_LOG` (put `RUST_LOG=sbc_core::media=debug,info` in `/etc/sbc/sbc.env`,
already an `EnvironmentFile` of the unit) > `[logging] level`.

For log shipping set `[logging] format = "json"`: one object per line with
`timestamp`, `level`, `target`, `message` and `span`
(`{"name":"call","uuid":…,"call_id":…,"trunk":…,"direction":…}`), e.g.

```bash
journalctl -u sbc -o cat | jq -c 'select(.span.uuid == "<uuid>")'
```

The writer is non-blocking and lossy: when journald does not keep up,
lines are dropped rather than stalling the SIP loop (`sbc_log_dropped_lines_total`,
alert `SBCLogLinesDropped`). On `systemctl stop` the last lines may reach
journald up to a second after `SBC shutdown complete`; `TimeoutStopSec=15`
is ample.

Log rotation only concerns the CDR file (`[general] cdr_file`), not the SIP
logs — `/etc/logrotate.d/sbc`:

```
/var/log/sbc/*.jsonl {
    daily
    rotate 30
    compress
    missingok
    copytruncate
}
```

## 6. TLS / WSS certificates

TLS trunks and WebRTC (WSS) need certificates the peers trust. With certbot:

```bash
sudo certbot certonly --standalone -d sip.example.com -d webrtc.example.com
```

Point the listener `cert_file`/`key_file` at
`/etc/letsencrypt/live/<host>/fullchain.pem` and `privkey.pem`. A renewal
hook asks the SBC to re-read the files; the new certificate serves the
next connection, existing sessions are untouched. A file that does not
load (permissions, key/cert mismatch) keeps the previous certificate: the
route answers 422, `SBCCertExpiringSoon` keeps firing — never restart on
an HTTP error, restart only when the API itself is unreachable (curl exit
7):

```bash
# /etc/letsencrypt/renewal-hooks/deploy/reload-sbc-tls.sh
. /etc/sbc/sbc.env
curl -fsS -X POST -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/tls/reload
rc=$?
[ $rc -eq 7 ] && systemctl restart sbc     # API down: the graceful restart reloads everything
exit 0
```

Check with `GET /api/v1/tls/certificates` (`not_after`, `fingerprint_sha256`).
Note: a key that does not match its certificate is refused at boot too.

For remote access to the management API, read [§7](#7-securing-the-management-api)
carefully before exposing it — a naive reverse proxy is how the API ends up
open to the Internet.

## 7. Securing the management API

The management API (axum) is a full administration surface: it can create,
enumerate and delete SIP users, trunks and DIDs. An unauthenticated actor who
reaches it can provision accounts and place billed calls on your PSTN trunk
(toll fraud), leak your customer list, or wipe your configuration. Treat it
with the same care as an SSH login.

### Golden rule — keep it on localhost

Bind the API to `127.0.0.1:8080` (the default) and administer it over an SSH
session on the box:

```bash
ssh admin@sip.example.com
curl -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/stats
```

For a workstation, forward the port over SSH instead of exposing it:

```bash
ssh -L 8080:127.0.0.1:8080 admin@sip.example.com
# now http://127.0.0.1:8080 on your laptop reaches the SBC API
```

With this pattern, port 8080 stays closed at the firewall and the API is
never reachable from the public Internet. The SBC also validates its own
bind: enabling the API on a non-loopback address without a firewall in front
is flagged at startup.

### The token: keep it out of the config and out of nginx

Supply the token through the environment, not in the TOML. systemd loads it
from an `EnvironmentFile` owned by root:

```bash
# /etc/sbc/sbc.env  — mode 600, root:root
SBC_API_TOKEN=<paste output of: openssl rand -hex 32>
```

```bash
sudo install -m 600 -o root -g root /dev/null /etc/sbc/sbc.env
echo "SBC_API_TOKEN=$(openssl rand -hex 32)" | sudo tee /etc/sbc/sbc.env >/dev/null
```

`SBC_API_TOKEN` overrides `management.api_auth_token`, so you can leave the
TOML free of secrets. The API **refuses to start when it is enabled without a
token** — a fail-closed boot is preferable to a silently open API. If you do
keep a token in the TOML, that file must be `chmod 600`.

### If you truly need remote access: a correct nginx block

Only expose the API remotely when SSH/localhost is genuinely not workable,
and even then lock it down. A correct reverse proxy:

- restricts by source IP (`allow`/`deny all`) or requires mutual TLS,
- terminates TLS,
- **passes the client's own `Authorization` header through unchanged** — the
  client presents its token; nginx must never mint one,
- leaves port 8080 closed at the firewall (nginx reaches it over localhost).

```nginx
server {
    listen 443 ssl;
    server_name admin.sip.example.com;

    ssl_certificate     /etc/letsencrypt/live/admin.sip.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.sip.example.com/privkey.pem;

    location / {
        # Restrict to your admin network / VPN — everything else is denied.
        allow 203.0.113.0/24;      # office / VPN egress
        deny  all;

        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # SSE (/api/v1/events) and CSV exports (/api/v1/cdrs?format=csv) stream:
        proxy_buffering    off;
        proxy_read_timeout 600s;
        # The caller supplies its own bearer token; nginx does NOT inject one.
        # (Do not set proxy_set_header Authorization here.) Query-string
        # tokens (?token=) end up in the access log: prefer the header.
        # These headers are believed only because nginx is in
        # [management] trusted_proxies (loopback by default): a proxy on
        # another host must be listed there or every client is rate-limited
        # and banned as the proxy's address.
    }
}
```

For stronger control, require a client certificate instead of an IP allowlist
(`ssl_verify_client on;` with `ssl_client_certificate <ca.pem>;`).

> **Never do this.** The following turns the reverse proxy into an open door:
> nginx adds the token to every request, so any anonymous visitor is
> authenticated as admin. This exact misconfiguration exposed the SBC API to
> the public Internet — see
> [docs/incidents/2026-07-25-management-api-exposure.md](incidents/2026-07-25-management-api-exposure.md).
>
> ```nginx
> location / {
>     proxy_pass http://127.0.0.1:8080;
>     proxy_set_header Authorization "Bearer <token>";   # ← DO NOT DO THIS
> }
> ```

### Runtime protections

The API additionally rate-limits requests and writes an audit log of
authenticated administrative actions, so credential-stuffing and unexpected
changes leave a trace. Ship those logs to your central logging and alert on
`4xx` auth failures and on user/trunk mutations you did not initiate.

## 8. Firewall

Expose only the media/signalling ports. Keep the management API (8080,
which also serves `/metrics`) closed — reach it via localhost, the nginx
reverse proxy or an SSH tunnel:

```bash
sudo ufw allow 80/tcp                 # ACME/HTTP (certbot), if used
sudo ufw allow 443/tcp                # TLS reverse proxy, if used
sudo ufw allow 5060/udp
sudo ufw allow 5060/tcp
sudo ufw allow 5061/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 10000:20000/udp        # RTP media
# Do NOT open 8080 (management API, incl. /metrics).
sudo ufw enable
```

## 9. Verification

```bash
# Health (public)
curl http://127.0.0.1:8080/health

# Authenticated endpoints — take the token from the systemd env file
source /etc/sbc/sbc.env            # sets SBC_API_TOKEN (run as root)
curl -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/stats
curl -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/trunks

# Create a user and watch events
curl -X POST http://127.0.0.1:8080/api/v1/users -H "Authorization: Bearer $SBC_API_TOKEN" \
  -d '{"username":"alice","password":"s3cret"}'
curl -N "http://127.0.0.1:8080/api/v1/events?token=$SBC_API_TOKEN"
```

The repo ships `scripts/api_smoke.sh` which exercises every endpoint —
set `SBC_API_TOKEN` and run it after each deploy.

For WebRTC, serve `examples/webrtc-client/` over HTTPS and register a user
against your WSS listener (see [WEBRTC.md](WEBRTC.md)).

## 10. Upgrades & rollback

`scripts/deploy.sh user@host` automates the whole sequence below for a box
that builds locally: rsync of the sources, timestamped backups, a temporary
swapfile and a memory-capped release build (see the small-VPS note), a
refusal to restart while calls are active, graceful stop, binary swap,
start, `/health`, the API smoke test and swap removal. `--dry-run` shows what
would change; `--rollback` restores the most recent binary and config
backups (never the store — see below). The binary reports the deployed
commit in `sbc --version` and at startup.

Manual equivalent:

```bash
git pull && cargo build --release
sudo cp /usr/local/bin/sbc /usr/local/bin/sbc.bak      # keep previous
sudo systemctl stop sbc                                 # graceful BYE
sudo cp target/release/sbc /usr/local/bin/sbc
sudo systemctl start sbc
curl -i http://127.0.0.1:8080/ready                     # 200 once store + listeners are up
curl -s -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/config | jq '.file'   # what a reload would change
curl -s -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/tls/certificates    # listener certificates and expiry
bash scripts/api_smoke.sh                               # verify

# Rollback if needed
sudo systemctl stop sbc && sudo cp /usr/local/bin/sbc.bak /usr/local/bin/sbc && sudo systemctl start sbc
```

The TOML file is untouched by binary upgrades. The SQLite store is
**migrated forward at startup**: schema migrations are embedded in the
binary, applied once and recorded in `_sqlx_migrations`. `scripts/deploy.sh`
copies the store next to the other backups (`sbc-db-<timestamp>.db`, never
pruned by the SBC). The SBC itself writes `sbc-<timestamp>.db` copies into
`[database] backup_dir` (`/var/lib/sbc/backups` in the example config;
created 0700, files 0600 — they hold trunk passwords and user HA1s) every
`backup_interval_hours` and on `POST /api/v1/backup`, keeping the
`backup_keep` newest. Take one before an upgrade:

```bash
curl -s -X POST -H "Authorization: Bearer $SBC_API_TOKEN" http://127.0.0.1:8080/api/v1/backup
```

Restore = stop, copy, start (the copy is a plain SQLite file; drop any
stale WAL of the live store). The store also holds the CDRs since lot 3:
restoring an older copy rewinds them too — export them first
(`GET /api/v1/cdrs?format=csv`), and expect the `sbc-db-*` copies to grow
with `[cdr] retention_days`:

```bash
sudo systemctl stop sbc
sudo cp -p /var/lib/sbc/backups/sbc-<timestamp>.db /var/lib/sbc/sbc.db
sudo rm -f /var/lib/sbc/sbc.db-wal /var/lib/sbc/sbc.db-shm
sudo systemctl start sbc
```

A store that cannot be opened or read at boot is fatal (the SBC would run
with no users, trunks or DIDs): the unit ends failed, `journalctl -u sbc`
names the path. `[database] allow_missing_store = true` is the escape
hatch (TOML seeds only, `/ready` stays 503). Grab a config snapshot via
`GET /api/v1/export` as well before major upgrades.

**Rolling back across a migration.** A binary older than 0.20 refuses to
open a store that carries a migration it does not know (0.20 added
`0002_security_persistence`), so `--rollback` from 0.20 to 0.19 leaves the
service down until you either

```bash
# keep the data (the new tables stay, the old binary ignores them):
sudo systemctl stop sbc
sqlite3 /var/lib/sbc/sbc.db "DELETE FROM _sqlx_migrations WHERE version IN (2, 3)"   # 0.21 added 3 (cdrs)
sudo systemctl start sbc
# — or — restore the pre-upgrade copy (loses every change made since):
sudo systemctl stop sbc && sudo cp -p /opt/sbc/backups/sbc-db-<timestamp>.db /var/lib/sbc/sbc.db && sudo systemctl start sbc
```

`--rollback` prints the applied migration versions and this reminder
instead of touching the store. From 0.20 on, the migrator ignores applied
migrations it does not know, so a rollback to 0.20 or later only swaps the
binary.

**Small VPS (2 GB RAM, no swap):** a full release build can be OOM-killed
and the kernel may pick the running SBC as the victim. Add a temporary
swapfile and cap the build's memory so an OOM hits the build, not the
service:

```bash
sudo fallocate -l 2G /swapfile.build && sudo chmod 600 /swapfile.build \
  && sudo mkswap /swapfile.build && sudo swapon /swapfile.build
systemd-run --scope -p MemoryMax=1400M -p MemorySwapMax=2G nice -n 10 cargo build --release
sudo swapoff /swapfile.build && sudo rm /swapfile.build
```

Changing the `[security]` session-timer values (`session_expires`,
`min_se`) does not need a restart: `kill -HUP` or `POST /api/v1/reload`
applies them to new calls.
