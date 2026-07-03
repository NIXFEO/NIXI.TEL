# Corrections de Compilation

## Erreurs Détectées

Lors de la compilation, quelques ajustements sont nécessaires pour correspondre à la version exacte de rsip et rustls.

### 1. Status Code canonical_reason

**Erreur**:
```
error[E0599]: no method named `canonical_reason` found for enum `StatusCode`
```

**Fichiers concernés**:
- `crates/sbc-core/src/transport/udp.rs:124`
- `crates/sbc-core/src/transport/tcp.rs:227`
- `crates/sbc-core/src/transport/tls.rs:282`

**Solution**: Retirer `.canonical_reason()` et utiliser juste le status_code

```rust
// Avant
format!("{} {}", resp.status_code, resp.status_code.canonical_reason())

// Après
format!("{}", resp.status_code)
```

### 2. TLS Certificate/PrivateKey Types

**Erreur**:
```
error[E0432]: unresolved imports `tokio_rustls::rustls::Certificate`, `tokio_rustls::rustls::PrivateKey`
```

**Fichier**: `crates/sbc-core/src/transport/tls.rs`

**Solution**: Utiliser les nouveaux types de rustls 0.21+

```rust
// Ligne 8-9, remplacer:
use tokio_rustls::rustls::{self, Certificate, PrivateKey, ServerConfig};

// Par:
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
```

Et ajuster la fonction `load_certs`:

```rust
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_data = fs::read(path)
        .map_err(|e| Error::Config(format!("Failed to read cert file: {}", e)))?;

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse certificates: {}", e)))?;

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key_data = fs::read(path)
        .map_err(|e| Error::Config(format!("Failed to read key file: {}", e)))?;

    // Try PKCS8
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut key_data.as_slice())
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs8(key?));
    }

    // Try RSA
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut key_data.as_slice())
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs1(key?));
    }

    Err(Error::Config("No private keys found".to_string()))
}
```

### 3. ServerConfig Builder

**Erreur**:
```
error[E0599]: no method named `with_safe_defaults` found
```

**Solution**: Utiliser le nouveau builder API

```rust
// Ligne 57-61, remplacer:
let config = ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(...)?;

// Par:
let config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(...)?;
```

### 4. HostWithPort Matching

**Erreur**:
```
error[E0599]: no associated item named `Host` found for struct `HostWithPort`
```

**Fichier**: `crates/sbc-core/src/routing/router.rs:64-72`

**Solution**: Vérifier la structure réelle de HostWithPort dans rsip

```rust
// Option 1: Utiliser to_string()
let domain = uri.host_with_port.to_string();

// Option 2: Si rsip expose directement host()
let domain = match uri.host() {
    Some(host) => host.to_string(),
    None => return Err(Error::Routing("No host in URI".to_string())),
};
```

### 5. Transport Serialization

**Erreur**:
```
error[E0277]: the trait bound `rsip::Transport: serde::Serialize` is not satisfied
```

**Fichier**: `crates/sbc-core/src/routing/trunk.rs:10`

**Solution**: Ne pas utiliser rsip::Transport directement dans les structs sérialisables

```rust
// Dans trunk.rs, ligne 10, remplacer:
pub transport: rsip::Transport,

// Par un enum local:
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl TransportType {
    pub fn to_rsip_transport(&self) -> rsip::Transport {
        match self {
            TransportType::Udp => rsip::Transport::Udp,
            TransportType::Tcp => rsip::Transport::Tcp,
            TransportType::Tls => rsip::Transport::Tls,
            TransportType::Ws => rsip::Transport::Ws,
            TransportType::Wss => rsip::Transport::Wss,
        }
    }
}

// Et modifier TrunkConfig:
pub struct TrunkConfig {
    // ...
    pub transport: TransportType,  // Au lieu de rsip::Transport
    // ...
}
```

## Script de Correction Automatique

Créer un fichier `fix_compilation.sh`:

```bash
#!/bin/bash

# Retirer canonical_reason
sed -i.bak 's/resp\.status_code\.canonical_reason()/\"OK\"/g' crates/sbc-core/src/transport/*.rs

# Message si correction manuelle nécessaire
echo "Corrections appliquées. Vérifier manuellement:"
echo "1. TLS types (Certificate/PrivateKey)"
echo "2. HostWithPort matching"
echo "3. Transport serialization"
```

## Vérification Après Corrections

```bash
cd /Users/chadoc/Documents/ia\ works/claude/rsip-w3tel/sbc

# Check compilation
cargo check

# Run tests
cargo test

# Build release
cargo build --release
```

## Alternative: Version Minimale Fonctionnelle

Si les corrections sont trop complexes, une version minimale sans TLS peut être testée en commentant:

1. Le listener TLS dans `transport/manager.rs`
2. Les imports TLS dans `transport/mod.rs`
3. Le fichier `transport/tls.rs` entier

Cela permettra de tester la Phase 1 avec UDP/TCP uniquement.

## Notes

- Ces erreurs sont dues aux différences de versions entre:
  - `rsip 0.4.0` (API peut varier)
  - `rustls 0.21+` (changements majeurs d'API)
  - `tokio-rustls 0.25` (suit rustls)

- Une fois corrigé, le code devrait compiler sans erreurs
- Tous les warnings de rsip peuvent être ignorés (code externe)
