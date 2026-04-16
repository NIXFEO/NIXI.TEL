# Guide d'Installation — SBC W3tel

> Guide complet pour déployer le SBC W3tel en production sur Ubuntu 24.04 LTS.
> Exemple réel : **nixi.tel** — `sip.nixi.tel`, `webrtc.nixi.tel`, `rtp.nixi.tel`

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Préparation du serveur](#2-préparation-du-serveur)
3. [Installation de Rust](#3-installation-de-rust)
4. [Installation de PostgreSQL](#4-installation-de-postgresql)
5. [Installation de Redis](#5-installation-de-redis)
6. [Certificats TLS (Let's Encrypt)](#6-certificats-tls-lets-encrypt)
7. [Build du SBC](#7-build-du-sbc)
8. [Configuration](#8-configuration)
9. [Service systemd](#9-service-systemd)
10. [Firewall (UFW)](#10-firewall-ufw)
11. [Vérification](#11-vérification)
12. [Mise à jour](#12-mise-à-jour)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Prérequis

### Matériel minimum

| Ressource | Minimum | Recommandé (prod) |
|-----------|---------|-------------------|
| CPU | 2 cœurs | 4 cœurs+ |
| RAM | 1 GB | 4 GB+ |
| Disque | 8 GB | 20 GB SSD |
| Réseau | 100 Mbps | 1 Gbps |

### Logiciels

| Logiciel | Version minimum | Rôle |
|----------|----------------|------|
| Ubuntu | 22.04 LTS+ | OS |
| Rust | 1.75+ | Compilation |
| PostgreSQL | 14+ | Base de données |
| Redis | 6+ | Cache |
| Certbot | 2.0+ | Certificats TLS |

### Ports réseau ouverts

| Port | Protocole | Usage |
|------|-----------|-------|
| 5060 | UDP + TCP | SIP |
| 5061 | TCP | SIP TLS |
| 8443 | TCP | WebRTC WSS |
| 443 | TCP | HTTPS |
| 80 | TCP | Let's Encrypt |
| 10000–20000 | UDP | RTP Media |
| 3478 | UDP + TCP | STUN/TURN |
| 5349 | TCP | TURN TLS |
| 8080 | TCP | REST API (interne) |

### DNS

Configurez vos enregistrements A **avant** l'installation (requis pour Let's Encrypt) :

```
sip.votre-domaine.com     A   IP_DE_VOTRE_SERVEUR
webrtc.votre-domaine.com  A   IP_DE_VOTRE_SERVEUR
rtp.votre-domaine.com     A   IP_DE_VOTRE_SERVEUR
```

Vérification :
```bash
dig +short sip.votre-domaine.com
# doit retourner votre IP publique
```

---

## 2. Préparation du serveur

### Connexion SSH

```bash
ssh root@VOTRE_IP
```

### Mise à jour du système

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq
```

### Outils de compilation

```bash
apt-get install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libclang-dev \
  clang \
  cmake \
  git \
  curl \
  wget \
  net-tools \
  ufw \
  jq \
  ca-certificates \
  gnupg \
  software-properties-common
```

### Limites système

```bash
# Augmenter les limites de fichiers ouverts
cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65536
* hard nofile 65536
root soft nofile 65536
root hard nofile 65536
EOF

# Optimisations réseau pour SIP/RTP
cat >> /etc/sysctl.conf << 'EOF'
# Buffers UDP (RTP media)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
# Connexions SIP
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
# Time-wait
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
EOF
sysctl -p
```

---

## 3. Installation de Rust

```bash
# Installation via rustup (officiel)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Charger l'environnement
source /root/.cargo/env
echo 'source $HOME/.cargo/env' >> /root/.bashrc

# Vérification
rustc --version   # rustc 1.93.x
cargo --version   # cargo 1.93.x
```

---

## 4. Installation de PostgreSQL

```bash
# Installation
apt-get install -y postgresql postgresql-contrib libpq-dev

# Démarrage et activation
systemctl enable postgresql
systemctl start postgresql

# Vérification
systemctl status postgresql
```

### Création de la base de données

```bash
# Créer l'utilisateur et la base
sudo -u postgres psql << 'SQL'
CREATE USER sbc WITH PASSWORD 'VOTRE_MOT_DE_PASSE_FORT';
CREATE DATABASE sbc_db OWNER sbc;
GRANT ALL PRIVILEGES ON DATABASE sbc_db TO sbc;
SQL

# Créer le schéma initial
sudo -u postgres psql -d sbc_db << 'SQL'
CREATE TABLE IF NOT EXISTS trunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT DEFAULT 5060,
    transport VARCHAR(10) DEFAULT 'UDP',
    auth_required BOOLEAN DEFAULT false,
    username VARCHAR(255),
    realm VARCHAR(255),
    max_concurrent_calls INT DEFAULT 100,
    calls_per_second INT DEFAULT 10,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS calls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    call_id VARCHAR(255) UNIQUE NOT NULL,
    caller VARCHAR(255),
    callee VARCHAR(255),
    state VARCHAR(50),
    is_webrtc BOOLEAN DEFAULT false,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    connected_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    duration_secs INT
);

CREATE TABLE IF NOT EXISTS auth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    realm VARCHAR(255) NOT NULL,
    ha1 VARCHAR(64) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cdr (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    call_id VARCHAR(255) NOT NULL,
    caller VARCHAR(255),
    callee VARCHAR(255),
    trunk_id UUID REFERENCES trunks(id),
    duration_secs INT DEFAULT 0,
    codec VARCHAR(20),
    is_webrtc BOOLEAN DEFAULT false,
    disconnect_reason VARCHAR(100),
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_calls_call_id ON calls(call_id);
CREATE INDEX idx_cdr_started_at ON cdr(started_at);
SQL

echo "Base de données configurée avec succès"
sudo -u postgres psql -d sbc_db -c '\dt'
```

---

## 5. Installation de Redis

```bash
apt-get install -y redis-server

# Configuration Redis pour production
cat > /etc/redis/redis.conf.d/sbc.conf << 'EOF'
# Bind uniquement localhost (pas d'accès externe)
bind 127.0.0.1
# Mémoire max 256MB
maxmemory 256mb
maxmemory-policy allkeys-lru
# Persistance légère
save 900 1
save 300 10
EOF

systemctl enable redis-server
systemctl restart redis-server
redis-cli ping  # doit retourner PONG
```

---

## 6. Certificats TLS (Let's Encrypt)

### Installation de certbot

```bash
apt-get install -y certbot
```

### Génération des certificats

```bash
# Arrêter tout service sur le port 80 si nécessaire
systemctl stop apache2 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

# Générer les certificats pour tous vos sous-domaines
certbot certonly --standalone \
  --non-interactive \
  --agree-tos \
  --email admin@votre-domaine.com \
  -d sip.votre-domaine.com \
  -d webrtc.votre-domaine.com \
  -d rtp.votre-domaine.com
```

### Lier les certificats

```bash
mkdir -p /etc/sbc/certs

ln -sf /etc/letsencrypt/live/sip.votre-domaine.com/fullchain.pem \
    /etc/sbc/certs/fullchain.pem
ln -sf /etc/letsencrypt/live/sip.votre-domaine.com/privkey.pem \
    /etc/sbc/certs/privkey.pem

# Vérification
openssl x509 -in /etc/sbc/certs/fullchain.pem -noout -subject -dates
```

### Auto-renouvellement

```bash
# Hook pour redémarrer le SBC après renouvellement
cat > /etc/letsencrypt/renewal-hooks/post/sbc-restart.sh << 'EOF'
#!/bin/bash
systemctl restart sbc
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/sbc-restart.sh

# Test du renouvellement (dry-run)
certbot renew --dry-run
```

---

## 7. Build du SBC

### Récupérer le code source

```bash
# Option A : depuis le dépôt git
git clone https://github.com/nixi-tel/sbc-w3tel /opt/sbc-src
cd /opt/sbc-src/sbc

# Option B : copier depuis une machine de développement
# rsync -avz --exclude 'target/' ./sbc/ root@SERVEUR:/opt/sbc/
# rsync -avz --exclude '.git/' ./rsip-w3tel/ root@SERVEUR:/opt/rsip-w3tel/
```

### Compilation en mode release

```bash
cd /opt/sbc
source /root/.cargo/env

# Build uniquement le binaire principal (recommandé)
cargo build --package sbc-bin --release 2>&1 | grep -E 'Compiling|Finished|error'

# Le binaire est dans :
ls -lh target/release/sbc
```

> **Note** : La première compilation prend 5–10 minutes (compilation des dépendances WebRTC).
> Les compilations suivantes sont incrémentielles (quelques secondes).

### Installation du binaire

```bash
cp /opt/sbc/target/release/sbc /usr/local/bin/sbc
chmod +x /usr/local/bin/sbc

# Vérification
sbc --version
# sbc 0.1.0
```

---

## 8. Configuration

### Répertoires

```bash
mkdir -p /var/log/sbc
mkdir -p /var/lib/sbc
mkdir -p /etc/sbc/certs
```

### Fichier de configuration production

```bash
cat > /etc/sbc/production.toml << 'EOF'
[general]
name = "SBC-nixi"
instance_id = "sbc-prod-01"

[network]
# Votre IP publique
public_ipv4 = "51.158.117.229"

# SIP UDP
[[network.listeners]]
transport = "UDP"
bind_address = "0.0.0.0"
bind_port = 5060

# SIP TCP
[[network.listeners]]
transport = "TCP"
bind_address = "0.0.0.0"
bind_port = 5060

# SIP TLS (sip.votre-domaine.com)
[[network.listeners]]
transport = "TLS"
bind_address = "0.0.0.0"
bind_port = 5061
cert_file = "/etc/sbc/certs/fullchain.pem"
key_file = "/etc/sbc/certs/privkey.pem"

# WebRTC WSS (webrtc.votre-domaine.com)
[[network.listeners]]
transport = "WSS"
bind_address = "0.0.0.0"
bind_port = 8443
cert_file = "/etc/sbc/certs/fullchain.pem"
key_file = "/etc/sbc/certs/privkey.pem"

[media]
rtp_port_range = [10000, 20000]
rtcp_enabled = true
transcoding_threads = 2
codecs = ["PCMU", "PCMA", "Opus", "G729"]
public_ip = "51.158.117.229"

[media.webrtc]
enabled = true
stun_servers = ["stun:rtp.votre-domaine.com:3478"]
turn_enabled = true
turn_server = "turn:rtp.votre-domaine.com:3478"

[database]
postgres_url = "postgresql://sbc:VOTRE_MOT_DE_PASSE@localhost/sbc_db"
postgres_max_connections = 10
redis_url = "redis://127.0.0.1:6379"

[security]
rate_limit_global = 500
rate_limit_per_ip = 30
auth_challenge_timeout = 30

[management]
api_enabled = true
api_bind_address = "127.0.0.1"
api_port = 8080
api_auth_token = "VOTRE_TOKEN_SECRET_ICI"

[metrics]
prometheus_enabled = true
prometheus_bind_address = "127.0.0.1"
prometheus_port = 9090

[logging]
level = "info"
file = "/var/log/sbc/sbc.log"
EOF
```

> **Remplacez** : `VOTRE_MOT_DE_PASSE`, `VOTRE_TOKEN_SECRET_ICI`, `votre-domaine.com`, et l'IP publique.

### Générer un token API sécurisé

```bash
openssl rand -hex 32
# → utilisez ce token dans api_auth_token
```

---

## 9. Service systemd

```bash
cat > /etc/systemd/system/sbc.service << 'EOF'
[Unit]
Description=SBC W3tel - Session Border Controller
Documentation=https://github.com/nixi-tel/sbc-w3tel
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/sbc
ExecStart=/usr/local/bin/sbc --config /etc/sbc/production.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Limites
LimitNOFILE=65536
LimitNPROC=65536

# Logging
StandardOutput=append:/var/log/sbc/sbc.log
StandardError=append:/var/log/sbc/sbc.log

# Environment
Environment=RUST_LOG=info
Environment=RUST_BACKTRACE=1

[Install]
WantedBy=multi-user.target
EOF

# Activer et démarrer
systemctl daemon-reload
systemctl enable sbc
systemctl start sbc

# Vérifier
systemctl status sbc
```

### Rotation des logs

```bash
cat > /etc/logrotate.d/sbc << 'EOF'
/var/log/sbc/sbc.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP sbc.service 2>/dev/null || true
    endscript
}
EOF
```

---

## 10. Firewall (UFW)

```bash
# Réinitialiser et configurer
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH (critique - ne pas oublier !)
ufw allow 22/tcp comment 'SSH'

# SIP
ufw allow 5060/udp comment 'SIP UDP'
ufw allow 5060/tcp comment 'SIP TCP'
ufw allow 5061/tcp comment 'SIP TLS'

# WebRTC
ufw allow 8443/tcp comment 'WebRTC WSS'
ufw allow 443/tcp  comment 'HTTPS'
ufw allow 80/tcp   comment 'HTTP / Let-Encrypt'

# RTP Media
ufw allow 10000:20000/udp comment 'RTP Media'

# STUN/TURN
ufw allow 3478/udp comment 'STUN/TURN UDP'
ufw allow 3478/tcp comment 'STUN/TURN TCP'
ufw allow 5349/tcp comment 'TURN TLS'

# Activer
ufw --force enable
ufw status verbose
```

---

## 11. Vérification

### Script de status

```bash
cat > /usr/local/bin/sbc-status << 'EOF'
#!/bin/bash
echo "============================================="
echo "  SBC W3tel - Status"
echo "============================================="
echo ""
echo "--- Services ---"
for svc in sbc postgresql redis-server; do
    if systemctl is-active --quiet $svc; then
        echo "$svc: RUNNING ✓"
    else
        echo "$svc: STOPPED ✗"
    fi
done
echo ""
echo "--- Ports SIP ---"
ss -tulnp | grep -E '5060|5061|8443'
echo ""
echo "--- TLS Certificate ---"
openssl x509 -in /etc/sbc/certs/fullchain.pem -noout -subject -dates 2>/dev/null
echo ""
echo "--- Logs récents ---"
tail -10 /var/log/sbc/sbc.log 2>/dev/null
EOF
chmod +x /usr/local/bin/sbc-status

sbc-status
```

### Test SIP OPTIONS

```bash
# Installer sipsak
apt-get install -y sipsak 2>/dev/null || true

# Test SIP OPTIONS
sipsak -s sip:sip.votre-domaine.com -v 2>&1 | head -10

# Ou avec netcat (UDP)
printf 'OPTIONS sip:sip.votre-domaine.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKtest\r\nMax-Forwards: 70\r\nTo: <sip:sip.votre-domaine.com>\r\nFrom: <sip:test@127.0.0.1>;tag=test123\r\nCall-ID: test@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' | timeout 3 nc -u 127.0.0.1 5060
```

### Vérification API

```bash
# Health check
curl -s http://127.0.0.1:8080/health | jq .
# {"status":"healthy","uptime_secs":60,"active_calls":0}

# Métriques
curl -s http://127.0.0.1:8080/metrics | head -20

# Trunks
curl -s http://127.0.0.1:8080/api/v1/trunks | jq .
```

### Vérification TLS

```bash
# Tester SIP TLS
openssl s_client -connect sip.votre-domaine.com:5061 -quiet 2>&1 | head -5

# Tester le certificat
openssl s_client -connect sip.votre-domaine.com:5061 </dev/null 2>&1 | \
    openssl x509 -noout -dates
```

---

## 12. Mise à jour

### Mise à jour du code

```bash
# Sur la machine de développement
cargo test --package sbc-core  # s'assurer que les tests passent
rsync -avz --exclude 'target/' ./sbc/ root@SERVEUR:/opt/sbc/
rsync -avz --exclude '.git/' ./rsip-w3tel/ root@SERVEUR:/opt/rsip-w3tel/

# Sur le serveur
ssh root@SERVEUR << 'EOF'
source /root/.cargo/env
cd /opt/sbc
cargo build --package sbc-bin --release
cp target/release/sbc /usr/local/bin/sbc
systemctl restart sbc
systemctl status sbc
EOF
```

### Mise à jour de Rust

```bash
source /root/.cargo/env
rustup update stable
rustc --version
```

---

## 13. Troubleshooting

### Le SBC ne démarre pas

```bash
# Vérifier les logs
journalctl -u sbc --no-pager -n 50

# Problèmes courants :
# 1. missing field 'redis_url' → ajouter redis_url dans [database]
# 2. Address already in use → port 5060 déjà utilisé
ss -tulnp | grep 5060  # trouver le processus
# 3. Permission denied sur le port → vérifier les droits

# Test de la config
sbc --config /etc/sbc/production.toml --check 2>&1 || true
```

### Port déjà utilisé

```bash
# Trouver et arrêter le processus
fuser -k 5060/udp
fuser -k 5060/tcp
systemctl restart sbc
```

### Problèmes TLS

```bash
# Vérifier que les certs existent
ls -la /etc/sbc/certs/
# Les liens symboliques doivent pointer vers /etc/letsencrypt/live/...

# Tester le certificat
openssl x509 -in /etc/sbc/certs/fullchain.pem -noout -text | grep -E 'Subject:|DNS:|Not After'

# Renouveler manuellement si expiré
certbot renew --force-renewal
systemctl restart sbc
```

### Base de données inaccessible

```bash
# Tester la connexion
sudo -u postgres psql -d sbc_db -c 'SELECT 1;'

# Vérifier l'URL dans la config
grep postgres_url /etc/sbc/production.toml

# Tester directement
psql "postgresql://sbc:MOT_DE_PASSE@localhost/sbc_db" -c '\dt'
```

### Compilation échoue

```bash
# Nettoyer le cache de compilation
cd /opt/sbc
cargo clean

# Vérifier la version de Rust
rustc --version  # doit être 1.75+

# Mettre à jour si nécessaire
rustup update stable

# Relancer
cargo build --package sbc-bin --release 2>&1 | grep -E 'error\[|Finished'
```

### Logs en temps réel

```bash
# Logs service
journalctl -u sbc -f

# Logs fichier
tail -f /var/log/sbc/sbc.log

# Logs avec filtrage
journalctl -u sbc -f | grep -E 'ERROR|WARN|INVITE|BYE'
```

### Vérifier les métriques

```bash
# Toutes les métriques
curl http://127.0.0.1:8080/metrics

# Stats en JSON
curl http://127.0.0.1:8080/api/v1/stats | jq .

# Appels actifs
curl http://127.0.0.1:8080/api/v1/calls | jq .
```

---

## Récapitulatif de l'installation (nixi.tel)

Voici ce qui a été installé et configuré sur le serveur de production `51.158.117.229` :

| Composant | Version | Status |
|-----------|---------|--------|
| Ubuntu | 24.04 LTS | Production |
| Rust | 1.93.1 | Installé via rustup |
| PostgreSQL | 16 | Actif — base `sbc_db` |
| Redis | 7.x | Actif — port 5479 local |
| SBC W3tel | 0.1.0 | Actif — service systemd |
| Certbot | 2.9.0 | Let's Encrypt auto-renewal |

### Domaines et certificats

| Domaine | IP | Expiration cert |
|---------|-----|----------------|
| `sip.nixi.tel` | 51.158.117.229 | 19 mai 2026 |
| `webrtc.nixi.tel` | 51.158.117.229 | 19 mai 2026 |
| `rtp.nixi.tel` | 51.158.117.229 | 19 mai 2026 |

### Ports actifs

| Port | Proto | Usage |
|------|-------|-------|
| 5060 | UDP | SIP |
| 5060 | TCP | SIP |
| 5061 | TCP | SIP TLS |
| 22 | TCP | SSH |
| 10000–20000 | UDP | RTP |
| 3478 | UDP/TCP | STUN/TURN |

### Commandes de maintenance

```bash
sbc-status                    # Status global
systemctl restart sbc         # Redémarrer
journalctl -u sbc -f          # Logs temps réel
tail -f /var/log/sbc/sbc.log  # Logs fichier
certbot renew                 # Renouveler certs
```
