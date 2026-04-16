# Guide de Démarrage Rapide - SBC W3tel

## Installation Rapide

### Prérequis
- Rust 1.70+ avec cargo
- Git

### Étapes

```bash
# 1. Aller dans le dossier du projet
cd /Users/chadoc/Documents/ia\ works/claude/rsip-w3tel/sbc

# 2. Build le projet
cargo build

# 3. Lancer le SBC
cargo run -- --config config/dev.toml --verbose
```

Vous devriez voir :
```
2026-02-16T20:00:00.000000Z  INFO sbc: Starting SBC W3tel
2026-02-16T20:00:00.000000Z  INFO sbc: Version: 0.1.0
2026-02-16T20:00:00.000000Z  INFO sbc: Loading configuration from: config/dev.toml
2026-02-16T20:00:00.000000Z  INFO sbc_core::transport::udp: UDP listener bound to 127.0.0.1:5060
2026-02-16T20:00:00.000000Z  INFO sbc_core::transport::manager: Started UDP listener on 127.0.0.1:5060
2026-02-16T20:00:00.000000Z  INFO sbc: SBC started successfully
2026-02-16T20:00:00.000000Z  INFO sbc: Entering main event loop
```

## Test Simple avec nc (netcat)

### Envoyer un message SIP

```bash
# Dans un autre terminal
echo -e "OPTIONS sip:test@127.0.0.1 SIP/2.0\r
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK123456\r
Max-Forwards: 70\r
To: <sip:test@127.0.0.1>\r
From: <sip:test@127.0.0.1>;tag=abc123\r
Call-ID: test@127.0.0.1\r
CSeq: 1 OPTIONS\r
Contact: <sip:test@127.0.0.1:5061>\r
Content-Length: 0\r
\r
" | nc -u 127.0.0.1 5060
```

Le SBC devrait répondre avec un `200 OK`.

## Configuration Minimale

Voici une configuration minimale (`config/minimal.toml`) :

```toml
[general]
name = "SBC-Test"
instance_id = "test-01"

[network]
public_ipv4 = "127.0.0.1"

[[network.listeners]]
transport = "UDP"
bind_address = "0.0.0.0"
bind_port = 5060

[media]
rtp_port_range = [10000, 10100]
rtcp_enabled = false
transcoding_threads = 1
codecs = ["PCMU"]

[media.webrtc]
enabled = false
stun_servers = []

[database]
postgres_url = "postgresql://sbc:sbc@localhost/sbc"
postgres_max_connections = 5
redis_url = "redis://localhost:6379"

[security]
rate_limit_global = 100
rate_limit_per_ip = 10

[management]
api_enabled = false
api_bind_address = "127.0.0.1"
api_port = 8080

[metrics]
prometheus_enabled = false
prometheus_bind_address = "127.0.0.1"
prometheus_port = 9090
```

## Commandes Utiles

### Build
```bash
# Debug build
cargo build

# Release build (optimisé)
cargo build --release

# Build avec vérification uniquement
cargo check
```

### Tests
```bash
# Tous les tests
cargo test

# Tests verbeux
cargo test -- --nocapture

# Tests d'un module spécifique
cargo test transport::udp

# Tests avec pattern
cargo test parse
```

### Linting & Format
```bash
# Vérifier le format
cargo fmt --check

# Formater le code
cargo fmt

# Clippy (linter)
cargo clippy
```

### Logs
```bash
# Logs INFO (défaut)
cargo run -- --config config/dev.toml

# Logs DEBUG (verbeux)
cargo run -- --config config/dev.toml --verbose

# Rediriger vers un fichier
cargo run -- --config config/dev.toml 2>&1 | tee sbc.log
```

## Exemples de Messages SIP

### OPTIONS Request
```sip
OPTIONS sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: <sip:bob@example.com>
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 1 OPTIONS
Contact: <sip:alice@pc33.atlanta.example.com>
Accept: application/sdp
Content-Length: 0

```

### INVITE Request (Basique)
```sip
INVITE sip:bob@biloxi.example.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.example.com:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@biloxi.example.com>
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.atlanta.example.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com
s=-
c=IN IP4 pc33.atlanta.example.com
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```

## Troubleshooting

### Port déjà utilisé
```
Error: Transport error: Failed to bind UDP socket: Address already in use
```
**Solution** : Changer le port dans `config/dev.toml` ou tuer le processus :
```bash
lsof -i :5060
kill <PID>
```

### Permission refusée (port < 1024)
```
Error: Transport error: Failed to bind UDP socket: Permission denied
```
**Solution** : Utiliser un port > 1024 ou lancer avec sudo (non recommandé)

### Certificat TLS introuvable
```
Error: Config error: Failed to read cert file: No such file or directory
```
**Solution** : Créer les certificats ou désactiver le listener TLS

## Génération de Certificats TLS (Pour Tests)

```bash
# Créer le dossier
mkdir -p /etc/sbc/certs

# Générer certificat auto-signé
openssl req -x509 -newkey rsa:4096 -keyout /etc/sbc/certs/server.key \
  -out /etc/sbc/certs/server.crt -days 365 -nodes \
  -subj "/C=FR/ST=Paris/L=Paris/O=W3tel/CN=sbc.w3tel.local"

# Vérifier
ls -l /etc/sbc/certs/
```

## Monitoring

### Vérifier l'état
```bash
# Vérifier si le processus tourne
ps aux | grep sbc

# Vérifier les ports ouverts
netstat -an | grep 5060
# ou
lsof -i :5060
```

### Capturer le trafic SIP
```bash
# Avec tcpdump
sudo tcpdump -i lo0 -n port 5060 -A

# Avec sngrep (outil SIP spécialisé)
sudo sngrep port 5060
```

## Prochaines Étapes

Une fois le SBC fonctionnel :

1. **Ajouter des trunks** : Modifier le code pour charger des trunks depuis la config
2. **Tester avec un softphone** : Utiliser Linphone, Zoiper, etc.
3. **Implémenter Phase 2** : Transactions et dialogs
4. **Déployer en production** : Docker, systemd, etc.

## Ressources

- [README.md](../README.md) - Documentation complète
- [PHASE1_COMPLETE.md](PHASE1_COMPLETE.md) - Détails Phase 1
- [Plan complet](/Users/chadoc/.claude/plans/gleaming-soaring-garden.md) - Architecture et roadmap
- [RFC 3261](https://datatracker.ietf.org/doc/html/rfc3261) - Spécification SIP
- [rsip docs](https://docs.rs/rsip) - Documentation rsip

## Support

Pour toute question ou problème :
- Consulter les logs avec `--verbose`
- Vérifier la configuration TOML
- Lire le code source (bien commenté)
- Créer une issue GitHub

Bon test ! 🚀
