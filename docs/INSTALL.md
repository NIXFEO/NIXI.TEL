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
7. [Firewall](#7-firewall)
8. [Verification](#8-verification)
9. [Upgrades & rollback](#9-upgrades--rollback)

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
| 8080 | TCP | Management REST API (bind to localhost) |
| 9090 | TCP | Prometheus metrics (bind to localhost) |

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

Edit `/etc/sbc/sbc.toml` — at minimum set `public_ipv4`, `sip_realm`,
`database.sqlite_path` (e.g. `/var/lib/sbc/sbc.db`) and a strong
`management.api_auth_token`:

```bash
openssl rand -hex 32   # generate an API token
```

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
ExecStart=/usr/local/bin/sbc --config /etc/sbc/sbc.toml
Restart=on-failure
# Graceful stop: the SBC sends BYE to active peers on SIGTERM
KillSignal=SIGTERM
TimeoutStopSec=15
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sbc
sudo systemctl status sbc
```

**Always stop gracefully** (`systemctl stop sbc`) so the SBC can BYE active
calls — this prevents ghost sessions on remote trunks. Never `kill -9`.

Log rotation — `/etc/logrotate.d/sbc`:

```
/var/log/sbc/*.log /var/log/sbc/*.jsonl {
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
hook can reload the SBC after renewal:

```bash
# /etc/letsencrypt/renewal-hooks/deploy/reload-sbc.sh
curl -s -X POST -H "Authorization: Bearer $SBC_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/reload
```

For the management API, put it behind an nginx TLS reverse proxy rather than
exposing port 8080 directly.

## 7. Firewall

```bash
sudo ufw allow 5060/udp
sudo ufw allow 5060/tcp
sudo ufw allow 5061/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 10000:20000/udp
# Keep 8080 (API) and 9090 (metrics) closed — reach them via localhost / a proxy
sudo ufw enable
```

## 8. Verification

```bash
# Health (public)
curl http://127.0.0.1:8080/health

# Authenticated endpoints
TOKEN=your-api-token
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/stats
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/trunks

# Create a user and watch events
curl -X POST http://127.0.0.1:8080/api/v1/users -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"alice","password":"s3cret"}'
curl -N "http://127.0.0.1:8080/api/v1/events?token=$TOKEN"
```

The repo ships `scripts/api_smoke.sh` which exercises every endpoint —
set `SBC_API_TOKEN` and run it after each deploy.

For WebRTC, serve `examples/webrtc-client/` over HTTPS and register a user
against your WSS listener (see [WEBRTC.md](WEBRTC.md)).

## 9. Upgrades & rollback

```bash
git pull && cargo build --release
sudo cp /usr/local/bin/sbc /usr/local/bin/sbc.bak      # keep previous
sudo systemctl stop sbc                                 # graceful BYE
sudo cp target/release/sbc /usr/local/bin/sbc
sudo systemctl start sbc
bash scripts/api_smoke.sh                               # verify

# Rollback if needed
sudo systemctl stop sbc && sudo cp /usr/local/bin/sbc.bak /usr/local/bin/sbc && sudo systemctl start sbc
```

The SQLite store and TOML file are untouched by binary upgrades. Back up
`sqlite_path` and grab a config snapshot via `GET /api/v1/export` before
major upgrades.
