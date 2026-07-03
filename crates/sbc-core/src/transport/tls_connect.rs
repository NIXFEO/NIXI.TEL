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
}

impl TlsClientConnection {
    /// Connect, handshake and spawn reader/writer tasks. Inbound messages
    /// (responses, in-dialog requests from the trunk) are framed and pushed
    /// to `message_tx` with a `reply_tx` bound to this connection.
    pub async fn connect(
        dest: SocketAddr,
        params: &TlsClientParams,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<Arc<Self>> {
        let config = build_client_config(params)?;
        let connector = TlsConnector::from(Arc::new(config));

        let server_name = ServerName::try_from(params.sni.clone())
            .map_err(|e| Error::Transport(format!("invalid TLS SNI '{}': {}", params.sni, e)))?;

        let tcp = TcpStream::connect(dest)
            .await
            .map_err(|e| Error::Transport(format!("TLS connect {}: {}", dest, e)))?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| Error::Transport(format!("TLS handshake with {} failed: {}", dest, e)))?;

        info!(
            "Outbound TLS established to {} (sni={}, mtls={})",
            dest,
            params.sni,
            params.is_mtls()
        );

        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Writer task: serialize all sends onto the connection.
        let peer = dest;
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if let Err(e) = write_half.write_all(&data).await {
                    warn!("TLS write to {} failed: {}", peer, e);
                    break;
                }
                let _ = write_half.flush().await;
            }
        });

        // Reader task: Content-Length framing → SBC pipeline.
        let reply_tx_for_reader = write_tx.clone();
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
                        while let Some((msg_end, remaining_start)) = frame_sip_message(&buffer) {
                            let raw = buffer[..msg_end].to_vec();
                            buffer.drain(..remaining_start);
                            match rsip::SipMessage::try_from(raw) {
                                Ok(message) => {
                                    let _ = message_tx.send(ReceivedMessage {
                                        message,
                                        source: peer,
                                        transport: rsip::Transport::Tls,
                                        reply_tx: Some(reply_tx_for_reader.clone()),
                                    });
                                }
                                Err(e) => warn!("TLS: unparseable SIP from {}: {}", peer, e),
                            }
                        }
                        if buffer.len() > 256 * 1024 {
                            warn!("TLS read buffer overflow from {}, resetting", peer);
                            buffer.clear();
                        }
                    }
                    Err(e) => {
                        warn!("TLS read from {} failed: {}", peer, e);
                        break;
                    }
                }
            }
        });

        Ok(Arc::new(Self { write_tx, peer: dest }))
    }

    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.write_tx
            .send(data.to_vec())
            .map_err(|_| Error::Transport(format!("TLS connection to {} is closed", self.peer)))
    }

    pub fn is_closed(&self) -> bool {
        self.write_tx.is_closed()
    }
}

fn build_client_config(params: &TlsClientParams) -> Result<ClientConfig> {
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

/// Find one complete SIP message in `buffer` using Content-Length framing.
/// Returns (message_end, remaining_start) — identical here, kept as a pair
/// for clarity at the call site.
fn frame_sip_message(buffer: &[u8]) -> Option<(usize, usize)> {
    let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") || lower.starts_with("l:") {
                line.split(':').nth(1)?.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let message_end = header_end + 4 + content_length;
    (buffer.len() >= message_end).then_some((message_end, message_end))
}

mod danger {
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
mod tests {
    use super::*;

    #[test]
    fn framing_complete_and_partial() {
        let msg = b"SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        assert_eq!(frame_sip_message(msg), Some((msg.len(), msg.len())));

        let partial = b"SIP/2.0 200 OK\r\nContent-Length: 10\r\n\r\nbo";
        assert_eq!(frame_sip_message(partial), None);

        let no_headers = b"SIP/2.0 200";
        assert_eq!(frame_sip_message(no_headers), None);

        // Two pipelined messages: first is framed, remainder untouched
        let two = b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\nBYE sip:y SIP/2.0\r\n";
        let (end, _) = frame_sip_message(two).unwrap();
        assert!(std::str::from_utf8(&two[..end]).unwrap().starts_with("OPTIONS"));
    }
}
