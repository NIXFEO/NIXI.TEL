//! Real outbound TLS connections for SIP trunks (tokio-rustls).
//!
//! Replaces the old simulated `tls_client.rs` path: previously
//! `TransportManager::send()` routed `Transport::Tls` through **plaintext
//! TCP**. This module performs an actual TLS handshake (server-cert
//! verification against a configured CA or the system roots, optional
//! client certificate for mTLS) and spawns a reader task that frames SIP
//! messages (Content-Length) back into the SBC pipeline.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::transport::udp::ReceivedMessage;
use crate::transport::{frame_sip_message, Framing};
use crate::{Error, Result};

/// Per-destination TLS parameters (from trunk config).
#[derive(Debug, Clone)]
pub struct TlsClientParams {
    /// SNI / certificate hostname. Defaults to the trunk host.
    pub sni: String,
    /// Custom CA bundle (PEM). None = system roots.
    pub ca_cert: Option<String>,
    /// Verify the server certificate (true unless explicitly disabled).
    pub verify: bool,
    /// Client certificate + key (PEM) for mTLS.
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

impl TlsClientParams {
    pub fn is_mtls(&self) -> bool {
        self.client_cert.is_some() && self.client_key.is_some()
    }
}

/// One established outbound TLS connection (writer handle; reader task
/// feeds the SBC pipeline).
pub struct TlsClientConnection {
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    peer: SocketAddr,
    /// Set by the reader on EOF or read error, and by the writer on a
    /// write error. Without it `is_closed()` only reported a *writer task*
    /// that had exited, which a peer-initiated close never causes: the
    /// pool then handed the dead connection out again and `send` returned
    /// `Ok(())` for bytes the socket had already discarded.
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl TlsClientConnection {
    /// Connect, handshake and spawn reader/writer tasks. Inbound messages
    /// (responses, in-dialog requests from the trunk) are framed and pushed
    /// to `message_tx` with a `reply_tx` bound to this connection.
    ///
    /// `config` is built once per destination at trunk registration
    /// ([`build_client_config`]) so no certificate file or system trust
    /// store is read on the call path. Connect and handshake are each
    /// bounded by [`OUTBOUND_CONNECT_TIMEOUT`](crate::transport::OUTBOUND_CONNECT_TIMEOUT).
    pub async fn connect(
        dest: SocketAddr,
        params: &TlsClientParams,
        config: Arc<ClientConfig>,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<Arc<Self>> {
        let connector = TlsConnector::from(config);
        let timeout = crate::transport::OUTBOUND_CONNECT_TIMEOUT;

        let server_name = ServerName::try_from(params.sni.clone())
            .map_err(|e| Error::Transport(format!("invalid TLS SNI '{}': {}", params.sni, e)))?;

        let tcp = tokio::time::timeout(timeout, TcpStream::connect(dest))
            .await
            .map_err(|_| {
                Error::Transport(format!(
                    "TLS connect to {} timed out after {:?}",
                    dest, timeout
                ))
            })?
            .map_err(|e| Error::Transport(format!("TLS connect {}: {}", dest, e)))?;
        let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| {
                Error::Transport(format!(
                    "TLS handshake with {} timed out after {:?}",
                    dest, timeout
                ))
            })?
            .map_err(|e| Error::Transport(format!("TLS handshake with {} failed: {}", dest, e)))?;

        info!(
            "Outbound TLS established to {} (sni={}, mtls={})",
            dest,
            params.sni,
            params.is_mtls()
        );

        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Writer task: serialize all sends onto the connection.
        let peer = dest;
        let closed_writer = closed.clone();
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if let Err(e) = write_half.write_all(&data).await {
                    warn!("TLS write to {} failed: {}", peer, e);
                    break;
                }
                let _ = write_half.flush().await;
            }
            closed_writer.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        // Reader task: Content-Length framing → SBC pipeline.
        let reply_tx_for_reader = write_tx.clone();
        let closed_reader = closed.clone();
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::with_capacity(8192);
            let mut chunk = [0u8; 8192];
            loop {
                match read_half.read(&mut chunk).await {
                    Ok(0) => {
                        debug!("TLS connection to {} closed by peer", peer);
                        break;
                    }
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);
                        let mut closing = None;
                        loop {
                            match frame_sip_message(&buffer) {
                                Framing::Keepalive { count } => {
                                    buffer.drain(..count);
                                }
                                Framing::Message { end } => {
                                    let raw = buffer[..end].to_vec();
                                    buffer.drain(..end);
                                    match rsip::SipMessage::try_from(raw) {
                                        Ok(message) => {
                                            let _ = message_tx.send(ReceivedMessage {
                                                message,
                                                source: peer,
                                                transport: rsip::Transport::Tls,
                                                reply_tx: Some(reply_tx_for_reader.clone()),
                                            });
                                        }
                                        Err(e) => {
                                            warn!("TLS: unparseable SIP from {}: {}", peer, e)
                                        }
                                    }
                                }
                                Framing::Incomplete => break,
                                Framing::Malformed(why) => {
                                    closing = Some(why);
                                    break;
                                }
                            }
                        }
                        if let Some(why) = closing {
                            warn!(
                                "Outbound TLS to {} closed: unframeable stream ({})",
                                peer, why
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("TLS read from {} failed: {}", peer, e);
                        break;
                    }
                }
            }
            // The peer is gone (EOF, read error, or an unframeable
            // stream): the pool must not hand this connection out again.
            closed_reader.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        Ok(Arc::new(Self {
            write_tx,
            peer: dest,
            closed,
        }))
    }

    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.write_tx
            .send(data.to_vec())
            .map_err(|_| Error::Transport(format!("TLS connection to {} is closed", self.peer)))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed) || self.write_tx.is_closed()
    }
}

/// Build the rustls client configuration for a destination: CA bundle or
/// system roots, optional mTLS identity. Reads files — call it at trunk
/// registration (boot / reload), never on the call path.
pub fn build_client_config(params: &TlsClientParams) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    match &params.ca_cert {
        Some(path) => {
            let pem = std::fs::read(path)
                .map_err(|e| Error::Config(format!("read CA {}: {}", path, e)))?;
            let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_slice())
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| Error::Config(format!("parse CA {}: {}", path, e)))?;
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| Error::Config(format!("add CA cert: {}", e)))?;
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs()
                .map_err(|e| Error::Config(format!("load system roots: {}", e)))?;
            for cert in native {
                let _ = roots.add(cert);
            }
        }
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);

    let config = if params.is_mtls() {
        let cert_path = params.client_cert.as_ref().unwrap();
        let key_path = params.client_key.as_ref().unwrap();
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| Error::Config(format!("read client cert {}: {}", cert_path, e)))?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("parse client cert: {}", e)))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| Error::Config(format!("read client key {}: {}", key_path, e)))?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .map_err(|e| Error::Config(format!("parse client key: {}", e)))?
            .ok_or_else(|| Error::Config("no private key found".to_string()))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| Error::Config(format!("client auth config: {}", e)))?
    } else {
        builder.with_no_client_auth()
    };

    let mut config = config;
    if !params.verify {
        // Explicitly requested (tls_verify = false): accept any server cert.
        warn!(
            "TLS verification DISABLED for sni={} — vulnerable to MITM, use only for testing",
            params.sni
        );
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoVerifier));
    }

    Ok(config)
}

pub(crate) mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
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
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }
}

#[cfg(test)]
mod connect_timeout_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn params() -> TlsClientParams {
        TlsClientParams {
            sni: "trunk.example.invalid".to_string(),
            ca_cert: None,
            verify: false,
            client_cert: None,
            client_key: None,
        }
    }

    #[tokio::test]
    async fn tls_connect_to_a_black_hole_fails_within_the_timeout() {
        let config = Arc::new(build_client_config(&params()).expect("client config"));
        let (tx, _rx) = mpsc::unbounded_channel();
        let dest: SocketAddr = "203.0.113.1:5061".parse().unwrap();
        let started = Instant::now();
        let result = TlsClientConnection::connect(dest, &params(), config, tx).await;
        assert!(result.is_err());
        let budget = crate::transport::OUTBOUND_CONNECT_TIMEOUT + Duration::from_secs(1);
        assert!(
            started.elapsed() <= budget,
            "connect took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn build_client_config_fails_closed_on_a_missing_ca_bundle() {
        let bad = TlsClientParams {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            ..params()
        };
        assert!(build_client_config(&bad).is_err());
    }
}
