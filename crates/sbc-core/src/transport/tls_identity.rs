//! Listener certificates that can be swapped without a restart.
//!
//! Each TLS / WSS listener holds a [`TlsListenerIdentity`]: the rustls
//! `ServerConfig` behind a lock, read once per accepted socket. A reload
//! re-reads the PEM files off the event loop, proves the private key
//! signs for the leaf certificate (an in-memory handshake — rustls 0.22
//! does not check the pair itself, and a mismatch accepted here would
//! break every handshake until a restart), then swaps atomically; on any
//! error the previous identity stays. The registry is what
//! `POST /api/v1/tls/reload`, `GET /api/v1/tls/certificates` and the
//! `sbc_tls_cert_expiry_timestamp_seconds` gauge read.
use crate::{Error, Result};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme,
};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// What is known about a loaded leaf certificate.
#[derive(Clone, Debug, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
    pub fingerprint_sha256: String,
    pub chain_len: usize,
    pub loaded_at: u64,
}

pub struct LoadedIdentity {
    pub config: Arc<ServerConfig>,
    pub info: CertInfo,
}

/// Read both PEM files, build the server config and prove the key matches
/// the certificate. Synchronous file IO: callers on the event loop wrap it
/// in `spawn_blocking`.
pub fn load_identity(cert_file: &Path, key_file: &Path) -> Result<LoadedIdentity> {
    let cert_data = std::fs::read(cert_file)
        .map_err(|e| Error::Config(format!("read cert {}: {}", cert_file.display(), e)))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Config(format!("parse cert {}: {}", cert_file.display(), e)))?;
    if certs.is_empty() {
        return Err(Error::Config(format!(
            "no certificate in {}",
            cert_file.display()
        )));
    }
    let key_data = std::fs::read(key_file)
        .map_err(|e| Error::Config(format!("read key {}: {}", key_file.display(), e)))?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_data))
        .map_err(|e| Error::Config(format!("parse key {}: {}", key_file.display(), e)))?
        .ok_or_else(|| Error::Config(format!("no private key in {}", key_file.display())))?;
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .map_err(|e| {
                Error::Config(format!("TLS config from {}: {}", cert_file.display(), e))
            })?,
    );
    verify_key_matches(&config).map_err(|e| {
        Error::Config(format!(
            "{} does not match {}: {}",
            key_file.display(),
            cert_file.display(),
            e
        ))
    })?;
    let (subject, not_before, not_after) = parse_leaf(&certs[0]);
    let fingerprint_sha256 = {
        use sha2::Digest;
        let d = sha2::Sha256::digest(certs[0].as_ref());
        d.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };
    Ok(LoadedIdentity {
        config,
        info: CertInfo {
            subject,
            not_before,
            not_after,
            fingerprint_sha256,
            chain_len: certs.len(),
            loaded_at: crate::events::event_ts(),
        },
    })
}

fn parse_leaf(der: &CertificateDer<'_>) -> (String, Option<u64>, Option<u64>) {
    match x509_parser::parse_x509_certificate(der.as_ref()) {
        Ok((_, cert)) => (
            cert.subject().to_string(),
            u64::try_from(cert.validity().not_before.timestamp()).ok(),
            u64::try_from(cert.validity().not_after.timestamp()).ok(),
        ),
        Err(e) => {
            warn!(
                "Certificate accepted by rustls but not parsed for its validity: {}",
                e
            );
            ("unknown".to_string(), None, None)
        }
    }
}

/// Accepts any certificate but checks the handshake signatures: the only
/// thing a key/cert mismatch breaks.
#[derive(Debug)]
struct SignatureOnlyVerifier;

impl ServerCertVerifier for SignatureOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// An in-memory client/server handshake against `config`: fails when the
/// private key does not sign for the certificate.
fn verify_key_matches(config: &Arc<ServerConfig>) -> std::result::Result<(), String> {
    let client_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SignatureOnlyVerifier))
        .with_no_client_auth();
    let mut server = ServerConnection::new(config.clone()).map_err(|e| e.to_string())?;
    let mut client = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("localhost").map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut slice = buf.as_slice();
        while !slice.is_empty() {
            server.read_tls(&mut slice).map_err(|e| e.to_string())?;
        }
        server.process_new_packets().map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut slice = buf.as_slice();
        while !slice.is_empty() {
            client.read_tls(&mut slice).map_err(|e| e.to_string())?;
        }
        client.process_new_packets().map_err(|e| e.to_string())?;
    }
    Err("handshake did not complete".into())
}

/// One listener's certificate, swappable.
pub struct TlsListenerIdentity {
    pub listener: &'static str,
    pub bound: SocketAddr,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    config: RwLock<Arc<ServerConfig>>,
    info: RwLock<CertInfo>,
}

/// The result of one listener's reload.
#[derive(Clone, Debug, Serialize)]
pub struct TlsReloadOutcome {
    pub listener: &'static str,
    pub bind: String,
    pub changed: bool,
    /// The identity in use after the reload (the previous one on error).
    pub info: CertInfo,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TlsListenerStatus {
    pub listener: &'static str,
    pub bind: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    #[serde(flatten)]
    pub info: CertInfo,
}

impl TlsListenerIdentity {
    pub fn load(
        listener: &'static str,
        bound: SocketAddr,
        cert_file: &Path,
        key_file: &Path,
    ) -> Result<Arc<Self>> {
        let loaded = load_identity(cert_file, key_file)?;
        Ok(Arc::new(Self {
            listener,
            bound,
            cert_file: cert_file.to_path_buf(),
            key_file: key_file.to_path_buf(),
            config: RwLock::new(loaded.config),
            info: RwLock::new(loaded.info),
        }))
    }

    /// One call per accepted socket.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(
            self.config
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
    }

    pub fn info(&self) -> CertInfo {
        self.info
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn status(&self) -> TlsListenerStatus {
        TlsListenerStatus {
            listener: self.listener,
            bind: self.bound.to_string(),
            cert_file: self.cert_file.clone(),
            key_file: self.key_file.clone(),
            info: self.info(),
        }
    }

    /// Re-read the files off the event loop; swap on success, keep the
    /// previous identity on error.
    pub async fn reload(self: &Arc<Self>) -> TlsReloadOutcome {
        let (cert, key) = (self.cert_file.clone(), self.key_file.clone());
        let loaded = tokio::task::spawn_blocking(move || load_identity(&cert, &key)).await;
        match loaded {
            Ok(Ok(new)) => {
                let changed = new.info.fingerprint_sha256 != self.info().fingerprint_sha256;
                *self.config.write().unwrap_or_else(PoisonError::into_inner) = new.config;
                *self.info.write().unwrap_or_else(PoisonError::into_inner) = new.info.clone();
                info!(
                    "{} {}: certificate {} ({})",
                    self.listener,
                    self.bound,
                    if changed { "reloaded" } else { "unchanged" },
                    new.info.subject
                );
                TlsReloadOutcome {
                    listener: self.listener,
                    bind: self.bound.to_string(),
                    changed,
                    info: new.info,
                    error: None,
                }
            }
            Ok(Err(e)) => self.reload_failed(e.to_string()),
            Err(e) => self.reload_failed(format!("reload task: {}", e)),
        }
    }

    fn reload_failed(&self, error: String) -> TlsReloadOutcome {
        warn!(
            "{} {}: certificate reload failed, keeping the previous one: {}",
            self.listener, self.bound, error
        );
        TlsReloadOutcome {
            listener: self.listener,
            bind: self.bound.to_string(),
            changed: false,
            info: self.info(),
            error: Some(error),
        }
    }
}

/// Every TLS / WSS listener's identity.
#[derive(Default)]
pub struct TlsIdentityRegistry {
    entries: RwLock<Vec<Arc<TlsListenerIdentity>>>,
}

impl TlsIdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, id: Arc<TlsListenerIdentity>) {
        let info = id.info();
        match info.not_after {
            Some(t) => {
                let now = crate::events::event_ts();
                let days = (t as i64 - now as i64) / 86_400;
                if days < 14 {
                    warn!(
                        "{} {}: certificate {} expires in {} day(s)",
                        id.listener, id.bound, info.subject, days
                    );
                } else {
                    info!(
                        "{} {}: certificate {}, expires in {} days",
                        id.listener, id.bound, info.subject, days
                    );
                }
            }
            None => warn!(
                "{} {}: certificate validity unknown (not parsed)",
                id.listener, id.bound
            ),
        }
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
    }

    fn entries(&self) -> Vec<Arc<TlsListenerIdentity>> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn is_empty(&self) -> bool {
        self.entries().is_empty()
    }

    pub fn statuses(&self) -> Vec<TlsListenerStatus> {
        self.entries().iter().map(|e| e.status()).collect()
    }

    /// Reload every listener in turn (the lock is not held across awaits).
    pub async fn reload_all(&self) -> Vec<TlsReloadOutcome> {
        let mut out = Vec::new();
        for id in self.entries() {
            out.push(id.reload().await);
        }
        out
    }

    /// Push every listener's expiry into the metrics.
    pub fn publish_expiry(&self, metrics: &crate::metrics::SbcMetrics) {
        for s in self.statuses() {
            metrics.set_tls_cert_expiry(s.listener, &s.bind, s.info.not_after.unwrap_or(0));
        }
    }
}

#[cfg(test)]
pub(crate) mod test_pem {
    /// A self-signed certificate (PEM cert, PEM key, DER leaf) for `cn`.
    pub fn self_signed(cn: &str, not_after_year: i32) -> (String, String, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let cert = rcgen::Certificate::from_params(params).unwrap();
        // ECDSA signatures are randomised: derive the DER from the very PEM
        // the listener will load, not from a second serialisation.
        let pem = cert.serialize_pem().unwrap();
        let der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();
        (pem, cert.serialize_private_key_pem(), der)
    }

    /// Write a cert/key pair into a fresh temp dir.
    pub fn write_pair(cert: &str, key: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("sbc-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = dir.join("cert.pem");
        let k = dir.join("key.pem");
        std::fs::write(&c, cert).unwrap();
        std::fs::write(&k, key).unwrap();
        (c, k)
    }
}

#[cfg(test)]
mod tests {
    use super::test_pem::*;
    use super::*;

    #[test]
    fn load_identity_reports_subject_chain_and_not_after() {
        let (cert, key, _) = self_signed("sip.test", 2031);
        let (c, k) = write_pair(&cert, &key);
        let id = load_identity(&c, &k).unwrap();
        assert!(
            id.info.subject.contains("CN=sip.test"),
            "{}",
            id.info.subject
        );
        assert_eq!(
            id.info.not_after,
            Some(1_924_992_000),
            "2031-01-01T00:00:00Z"
        );
        assert_eq!(id.info.chain_len, 1);
        assert_eq!(id.info.fingerprint_sha256.len(), 64);
    }

    #[test]
    fn load_identity_refuses_a_key_from_another_certificate() {
        let (cert_a, _, _) = self_signed("a.test", 2031);
        let (_, key_b, _) = self_signed("b.test", 2031);
        let (c, k) = write_pair(&cert_a, &key_b);
        let err = match load_identity(&c, &k) {
            Ok(_) => panic!("a foreign key was accepted"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("does not match"), "{}", err);
    }

    #[test]
    fn load_identity_refuses_missing_and_non_pem_files() {
        let missing = std::path::Path::new("/nonexistent/cert.pem");
        assert!(load_identity(missing, missing).is_err());
        let (c, k) = write_pair("not a pem", "not a pem");
        assert!(load_identity(&c, &k).is_err());
    }

    #[tokio::test]
    async fn reload_swaps_or_keeps_the_previous_identity() {
        let (cert_a, key_a, _) = self_signed("a.test", 2031);
        let (c, k) = write_pair(&cert_a, &key_a);
        let id =
            TlsListenerIdentity::load("tls", "127.0.0.1:5061".parse().unwrap(), &c, &k).unwrap();
        let first = id.info().fingerprint_sha256.clone();

        let same = id.reload().await;
        assert!(same.error.is_none() && !same.changed);

        std::fs::write(&k, "broken").unwrap();
        let broken = id.reload().await;
        assert!(broken.error.is_some() && !broken.changed);
        assert_eq!(
            id.info().fingerprint_sha256,
            first,
            "previous identity kept"
        );

        let (cert_b, key_b, _) = self_signed("b.test", 2032);
        std::fs::write(&c, cert_b).unwrap();
        std::fs::write(&k, key_b).unwrap();
        let swapped = id.reload().await;
        assert!(swapped.error.is_none() && swapped.changed, "{:?}", swapped);
        assert_ne!(id.info().fingerprint_sha256, first);
        assert!(id.info().subject.contains("CN=b.test"));

        let registry = TlsIdentityRegistry::new();
        registry.register(id.clone());
        let metrics = crate::metrics::SbcMetrics::new();
        registry.publish_expiry(&metrics);
        let out = metrics.render_prometheus();
        assert!(
            out.contains("sbc_tls_cert_expiry_timestamp_seconds{listener=\"tls\",bind=\"127.0.0.1:5061\"} 1956528000\n"),
            "{}",
            out
        );
        assert_eq!(registry.statuses().len(), 1);
        assert_eq!(registry.reload_all().await.len(), 1);
        let _ = std::fs::remove_dir_all(c.parent().unwrap());
    }
}
