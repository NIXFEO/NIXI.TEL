//! DTLS - Datagram TLS for SRTP Key Exchange
//!
//! RFC 5764 - DTLS Extension to Establish Keys for SRTP
//! RFC 8827 - WebRTC Security Architecture
//!
//! Implements a real DTLS handshake via the `webrtc-dtls` crate (v0.8).
//! DTLS packets are routed from the RTP socket via an mpsc channel through
//! `DtlsUdpBridge`, which implements the `webrtc_util::Conn` trait.

use crate::media::srtp::{CryptoSuite, SrtpContext};
use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

/// DTLS Role
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DtlsRole {
    /// Active role (initiates handshake)
    Active,

    /// Passive role (waits for handshake)
    Passive,

    /// ActPass (can be either, prefer passive)
    ActPass,
}

impl DtlsRole {
    #[allow(clippy::should_implement_trait)] // infallible-by-Option parser, not FromStr
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "passive" => Some(Self::Passive),
            "actpass" => Some(Self::ActPass),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::ActPass => "actpass",
        }
    }
}

/// DTLS Setup
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DtlsSetup {
    /// New setup
    New,

    /// Existing setup
    Existing,

    /// Held setup
    Held,
}

/// Certificate Fingerprint
#[derive(Debug, Clone)]
pub struct CertificateFingerprint {
    /// Hash algorithm (sha-256, sha-1, etc.)
    pub algorithm: String,

    /// Fingerprint value (hex encoded)
    pub fingerprint: String,
}

impl CertificateFingerprint {
    /// Parse from SDP attribute
    ///
    /// Format: a=fingerprint:sha-256 XX:XX:XX:...
    pub fn from_sdp(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();

        if parts.len() != 2 {
            return Err(Error::Media("Invalid fingerprint format".to_string()));
        }

        Ok(Self {
            algorithm: parts[0].to_string(),
            fingerprint: parts[1].to_string(),
        })
    }

    /// Format as SDP attribute
    pub fn to_sdp(&self) -> String {
        format!("{} {}", self.algorithm, self.fingerprint)
    }

    /// The certificate's fingerprint under this attribute's algorithm,
    /// as SDP writes it (upper-case hex, colon separated).
    pub fn digest_of(algorithm: &str, cert_der: &[u8]) -> Result<String> {
        use sha1::Sha1;
        use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
        let bytes: Vec<u8> = match algorithm.to_ascii_lowercase().as_str() {
            "sha-256" => Sha256::digest(cert_der).to_vec(),
            "sha-384" => Sha384::digest(cert_der).to_vec(),
            "sha-512" => Sha512::digest(cert_der).to_vec(),
            "sha-224" => Sha224::digest(cert_der).to_vec(),
            // RFC 8122 §5 allows it and some SIP endpoints still send it.
            "sha-1" => Sha1::digest(cert_der).to_vec(),
            other => {
                return Err(Error::Media(format!(
                    "Unsupported fingerprint hash algorithm: {}",
                    other
                )))
            }
        };
        Ok(bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":"))
    }

    /// Whether this certificate is the one the SDP named.
    ///
    /// This is the **only** thing that authenticates a DTLS-SRTP peer: the
    /// certificate is self-signed, so the X.509 chain says nothing and the
    /// handshake runs with `insecure_skip_verify`. Without this check
    /// anyone who can reach the media port completes the handshake and
    /// takes the call's audio (RFC 8122 §5, RFC 5763 §6.6).
    pub fn verify(&self, cert_der: &[u8]) -> Result<bool> {
        let computed = Self::digest_of(&self.algorithm, cert_der)?;
        // Compare on the bytes, not the punctuation: peers differ on case
        // and some omit the colons.
        let expected = self
            .fingerprint
            .to_ascii_uppercase()
            .replace([':', ' ', '-'], "");
        Ok(computed.replace(':', "") == expected)
    }
}

/// DTLS Context — manages DTLS-SRTP handshake and key derivation.
///
/// Stores the local certificate and fingerprint, and after handshake
/// provides the SRTP keying material.
pub struct DtlsContext {
    /// Local certificate fingerprint
    local_fingerprint: CertificateFingerprint,

    /// Remote certificate fingerprint
    remote_fingerprint: Option<CertificateFingerprint>,

    /// DTLS role (active = SBC initiates, passive = SBC waits)
    role: DtlsRole,

    /// Handshake complete flag
    handshake_complete: Arc<Mutex<bool>>,

    /// Derived SRTP keys (after handshake)
    srtp_keys: Arc<Mutex<Option<DtlsSrtpKeys>>>,

    /// Local certificate (DER-encoded) — kept for fingerprint verification
    #[allow(dead_code)]
    cert_der: Vec<u8>,

    /// webrtc-dtls Certificate — the SAME certificate used for SDP fingerprint
    /// and DTLS handshake. Must be the same to avoid fingerprint mismatch.
    dtls_certificate: webrtc_dtls::crypto::Certificate,
}

/// SRTP Keys derived from DTLS handshake
#[derive(Debug, Clone)]
pub struct DtlsSrtpKeys {
    /// Client write master key
    pub client_master_key: Vec<u8>,

    /// Client write master salt
    pub client_master_salt: Vec<u8>,

    /// Server write master key
    pub server_master_key: Vec<u8>,

    /// Server write master salt
    pub server_master_salt: Vec<u8>,
}

impl DtlsContext {
    /// Create new DTLS context with a self-signed certificate.
    ///
    /// IMPORTANT: Uses `webrtc_dtls::crypto::Certificate::generate_self_signed()` so that
    /// the SAME certificate is used for both the SDP fingerprint and the DTLS handshake.
    /// Using different certificates causes a fingerprint mismatch and the browser rejects
    /// the DTLS connection with a fatal alert.
    pub fn new(role: DtlsRole) -> Result<Self> {
        // Generate self-signed certificate via webrtc-dtls (which uses rcgen internally).
        // This is the SAME certificate used in perform_handshake().
        let dtls_certificate =
            webrtc_dtls::crypto::Certificate::generate_self_signed(
                vec!["webrtc.local".to_string()],
            )
            .map_err(|e| Error::Media(format!("DTLS certificate generation failed: {}", e)))?;

        // Extract DER bytes from the certificate for fingerprint computation
        let cert_der = dtls_certificate.certificate[0].0.clone();

        // Compute SHA-256 fingerprint from the SAME certificate
        let fingerprint = Self::compute_fingerprint(&cert_der)?;

        info!(
            "DTLS context created (role={:?}, fingerprint={})",
            role, fingerprint.fingerprint
        );

        Ok(Self {
            local_fingerprint: fingerprint,
            remote_fingerprint: None,
            role,
            handshake_complete: Arc::new(Mutex::new(false)),
            srtp_keys: Arc::new(Mutex::new(None)),
            cert_der,
            dtls_certificate,
        })
    }

    /// Compute SHA-256 fingerprint of a DER-encoded certificate.
    fn compute_fingerprint(cert_der: &[u8]) -> Result<CertificateFingerprint> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        let fingerprint = hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");

        Ok(CertificateFingerprint {
            algorithm: "sha-256".to_string(),
            fingerprint,
        })
    }

    /// Set remote fingerprint (from the browser's SDP offer).
    pub fn set_remote_fingerprint(&mut self, fingerprint: CertificateFingerprint) {
        self.remote_fingerprint = Some(fingerprint);
    }

    /// Get local fingerprint for SDP answer.
    pub fn local_fingerprint(&self) -> &CertificateFingerprint {
        &self.local_fingerprint
    }

    /// The fingerprint the signalling promised for the peer, if any. It is
    /// what `perform_handshake` authenticates the certificate against, so
    /// it must be installed before the handshake runs.
    pub fn remote_fingerprint(&self) -> Option<&CertificateFingerprint> {
        self.remote_fingerprint.as_ref()
    }

    /// Perform real DTLS-SRTP handshake via webrtc-dtls crate.
    ///
    /// The `bridge` routes DTLS packets from the RTP socket to webrtc-dtls
    /// and sends DTLS responses back via the same RTP socket.
    ///
    /// After handshake completes, SRTP keying material is exported.
    pub async fn perform_handshake(&self, bridge: Arc<DtlsUdpBridge>) -> Result<()> {
        use webrtc_dtls::conn::DTLSConn;
        use webrtc_util::KeyingMaterialExporter;

        let is_client = self.role == DtlsRole::Active;
        info!(
            "DTLS handshake starting (role: {:?}, is_client: {})",
            self.role, is_client
        );

        // CRITICAL: Use the SAME certificate that was used to compute the SDP fingerprint.
        // If we generate a new cert here, the browser sees a different fingerprint during
        // DTLS and sends a fatal alert, killing the connection.
        let config = Self::handshake_config(self.dtls_certificate.clone());

        // Perform handshake (with timeout)
        let dtls_conn = tokio::time::timeout(
            Duration::from_secs(15),
            DTLSConn::new(bridge, config, is_client, None),
        )
        .await
        .map_err(|_| Error::Media("DTLS handshake timeout (15s)".to_string()))?
        .map_err(|e| Error::Media(format!("DTLS handshake failed: {}", e)))?;

        // Export SRTP keying material (RFC 5764)
        let state = dtls_conn.connection_state().await;

        // Authenticate the peer. The certificate is self-signed, so the
        // handshake itself proves nothing (`insecure_skip_verify` above):
        // what binds this DTLS session to the call is that the
        // certificate hashes to the fingerprint the signalling carried
        // (RFC 8122 §5, RFC 5763 §6.6). Nothing checked it, so any host
        // that could reach the media port could complete the handshake
        // and take the audio.
        self.verify_peer_certificate(&state.peer_certificates)?;

        info!("DTLS handshake completed successfully");

        // For SRTP_AES128_CM_HMAC_SHA1_80: key=16 bytes, salt=14 bytes
        // Total: 2 * (16 + 14) = 60 bytes
        let keying_material = state
            .export_keying_material("EXTRACTOR-dtls_srtp", &[], 60)
            .await
            .map_err(|e| Error::Media(format!("SRTP keying material export failed: {:?}", e)))?;

        if keying_material.len() != 60 {
            return Err(Error::Media(format!(
                "Unexpected keying material length: {} (expected 60)",
                keying_material.len()
            )));
        }

        // Split keying material (RFC 5764 §4.2):
        // client_write_key(16) || server_write_key(16) ||
        // client_write_salt(14) || server_write_salt(14)
        let keys = DtlsSrtpKeys {
            client_master_key: keying_material[0..16].to_vec(),
            server_master_key: keying_material[16..32].to_vec(),
            client_master_salt: keying_material[32..46].to_vec(),
            server_master_salt: keying_material[46..60].to_vec(),
        };

        info!(
            "DTLS-SRTP keys exported: client_key={}B client_salt={}B server_key={}B server_salt={}B",
            keys.client_master_key.len(),
            keys.client_master_salt.len(),
            keys.server_master_key.len(),
            keys.server_master_salt.len()
        );

        *self.srtp_keys.lock().await = Some(keys);
        *self.handshake_complete.lock().await = true;

        Ok(())
    }

    /// The DTLS configuration both roles use.
    ///
    /// `client_auth` is **not** the default. A DTLS server that does not
    /// send a CertificateRequest gets no certificate from its client, and
    /// `peer_certificates` comes back empty — which, with the fingerprint
    /// check below, would fail every handshake where the SBC is the
    /// server. That is the normal case: a browser offers `a=setup:actpass`
    /// and `sbc_dtls_role` makes the SBC passive. RFC 5763 §5 requires the
    /// request for exactly this reason: in DTLS-SRTP both ends
    /// authenticate by certificate, so both must present one.
    ///
    /// `RequireAnyClientCert` asks for the certificate without trying to
    /// validate a chain: the certificate is self-signed and the SDP
    /// fingerprint is what authenticates it (`verify_peer_certificate`).
    fn handshake_config(
        certificate: webrtc_dtls::crypto::Certificate,
    ) -> webrtc_dtls::config::Config {
        use webrtc_dtls::config::{ClientAuthType, Config};
        use webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
        Config {
            certificates: vec![certificate],
            srtp_protection_profiles: vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            // The X.509 chain says nothing about a self-signed peer; the
            // fingerprint does.
            insecure_skip_verify: true,
            client_auth: ClientAuthType::RequireAnyClientCert,
            ..Default::default()
        }
    }

    /// The peer's certificate must hash to the fingerprint the SDP named.
    /// No fingerprint, no certificate, or a mismatch all fail the
    /// handshake: an unauthenticated DTLS-SRTP session is worth less than
    /// no session, because it looks encrypted.
    fn verify_peer_certificate(&self, peer_certificates: &[Vec<u8>]) -> Result<()> {
        let Some(expected) = self.remote_fingerprint.as_ref() else {
            return Err(Error::Media(
                "DTLS peer rejected: the offer/answer carried no a=fingerprint, \
                 so nothing binds this certificate to the call (RFC 8122 §5)"
                    .to_string(),
            ));
        };
        let Some(leaf) = peer_certificates.first() else {
            return Err(Error::Media(
                "DTLS peer rejected: the handshake produced no peer certificate".to_string(),
            ));
        };
        if !expected.verify(leaf)? {
            let actual = CertificateFingerprint::digest_of(&expected.algorithm, leaf)
                .unwrap_or_else(|_| "<unhashable>".to_string());
            return Err(Error::Media(format!(
                "DTLS peer rejected: certificate {} does not match the {} fingerprint \
                 {} from the SDP",
                actual, expected.algorithm, expected.fingerprint
            )));
        }
        info!(
            "DTLS peer certificate matches the {} fingerprint from the SDP",
            expected.algorithm
        );
        Ok(())
    }

    /// Create SRTP encryption/decryption contexts from the DTLS-derived keys.
    ///
    /// Returns `(recv_context, send_context)`:
    /// - recv_context: decrypts SRTP packets FROM the browser
    /// - send_context: encrypts RTP packets TO the browser
    pub async fn create_srtp_contexts(&self) -> Result<(SrtpContext, SrtpContext)> {
        let keys = self.srtp_keys.lock().await.clone().ok_or_else(|| {
            Error::Media("DTLS handshake not complete — no SRTP keys".to_string())
        })?;

        // Determine which key is for receive vs send based on DTLS role.
        // If SBC is DTLS client (Active): SBC uses client_key for sending, server_key for receiving.
        // If SBC is DTLS server (Passive): SBC uses server_key for sending, client_key for receiving.
        let (recv_key, recv_salt, send_key, send_salt) = match self.role {
            DtlsRole::Active => {
                // SBC = DTLS client → browser is server
                // Receive from browser (server) → use server keys to decrypt
                // Send to browser → use client keys to encrypt
                (
                    keys.server_master_key,
                    keys.server_master_salt,
                    keys.client_master_key,
                    keys.client_master_salt,
                )
            }
            DtlsRole::Passive | DtlsRole::ActPass => {
                // SBC = DTLS server → browser is client
                // Receive from browser (client) → use client keys to decrypt
                // Send to browser → use server keys to encrypt
                (
                    keys.client_master_key,
                    keys.client_master_salt,
                    keys.server_master_key,
                    keys.server_master_salt,
                )
            }
        };

        let recv_ctx = SrtpContext::new(recv_key, recv_salt, CryptoSuite::AesCm128HmacSha1_80)?;
        let send_ctx = SrtpContext::new(send_key, send_salt, CryptoSuite::AesCm128HmacSha1_80)?;

        info!(
            "SRTP contexts created from DTLS keys (role: {:?}, suite: AES_CM_128_HMAC_SHA1_80)",
            self.role
        );

        Ok((recv_ctx, send_ctx))
    }

    /// Get derived SRTP keys (raw)
    pub async fn get_srtp_keys(&self) -> Option<DtlsSrtpKeys> {
        self.srtp_keys.lock().await.clone()
    }

    /// Check if handshake is complete
    pub async fn is_handshake_complete(&self) -> bool {
        *self.handshake_complete.lock().await
    }

    /// Get DTLS role
    pub fn role(&self) -> DtlsRole {
        self.role
    }

    /// Take the concrete role the peer's `a=setup` leaves us (RFC 5763
    /// §5: the answerer chooses, the offerer takes the complement).
    /// Without this an `actpass` offer stayed `ActPass`, which
    /// `perform_handshake` reads as "not active", so a callee that
    /// answered `passive` left both ends waiting for a ClientHello.
    pub fn resolve_role_from_answer(&mut self, answer: Option<DtlsRole>) {
        self.role = match answer {
            // The peer will not initiate, so we must.
            Some(DtlsRole::Passive) => DtlsRole::Active,
            // The peer initiates (`active`), or left the choice to us
            // (`actpass`, or said nothing): we are the server.
            _ => DtlsRole::Passive,
        };
        debug!(
            "DTLS role resolved to {:?} from the peer's {:?}",
            self.role, answer
        );
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DtlsUdpBridge — routes DTLS packets between the RTP socket and webrtc-dtls
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Bridge between the shared RTP/DTLS socket and the `webrtc-dtls` library.
///
/// The RTP relay loop in `rtp.rs` demuxes incoming packets (RFC 5764 §5.1.2).
/// DTLS packets are sent to this bridge via `dtls_rx`.  Outgoing DTLS packets
/// (handshake messages) are sent directly via `rtp_socket.send_to()`.
pub struct DtlsUdpBridge {
    /// Incoming DTLS packets (routed from the RTP socket demuxer)
    dtls_rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,

    /// The shared RTP socket (for sending DTLS responses back to the browser)
    rtp_socket: Arc<UdpSocket>,

    /// The remote address (browser's IP:port), learned from first packet
    remote_addr: Mutex<Option<SocketAddr>>,

    /// Local address of the RTP socket
    local_addr: SocketAddr,
}

impl DtlsUdpBridge {
    /// Create a new DTLS-UDP bridge.
    ///
    /// `dtls_rx` receives DTLS packets from the RTP relay demuxer.
    /// `rtp_socket` is the shared socket for sending DTLS responses.
    /// `local_addr` is the local bind address of the RTP socket.
    pub fn new(
        dtls_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
        rtp_socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            dtls_rx: Mutex::new(dtls_rx),
            rtp_socket,
            remote_addr: Mutex::new(None),
            local_addr,
        }
    }
}

#[async_trait::async_trait]
impl webrtc_util::conn::Conn for DtlsUdpBridge {
    async fn connect(&self, _addr: SocketAddr) -> std::result::Result<(), webrtc_util::Error> {
        // Not used — we already have the connection via the RTP socket
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, webrtc_util::Error> {
        let mut rx = self.dtls_rx.lock().await;
        match rx.recv().await {
            Some((data, source)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                // Remember the remote address
                *self.remote_addr.lock().await = Some(source);
                Ok(len)
            }
            None => Err(webrtc_util::Error::Other("DTLS channel closed".to_string())),
        }
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), webrtc_util::Error> {
        let mut rx = self.dtls_rx.lock().await;
        match rx.recv().await {
            Some((data, source)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                *self.remote_addr.lock().await = Some(source);
                Ok((len, source))
            }
            None => Err(webrtc_util::Error::Other("DTLS channel closed".to_string())),
        }
    }

    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, webrtc_util::Error> {
        let remote = self.remote_addr.lock().await;
        if let Some(addr) = *remote {
            self.rtp_socket
                .send_to(buf, addr)
                .await
                .map_err(|e| webrtc_util::Error::Other(format!("UDP send error: {}", e)))
        } else {
            Err(webrtc_util::Error::Other(
                "No remote address known".to_string(),
            ))
        }
    }

    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::result::Result<usize, webrtc_util::Error> {
        self.rtp_socket
            .send_to(buf, target)
            .await
            .map_err(|e| webrtc_util::Error::Other(format!("UDP send_to error: {}", e)))
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, webrtc_util::Error> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        // Cannot block here (sync fn), return None — webrtc-dtls handles this
        None
    }

    async fn close(&self) -> std::result::Result<(), webrtc_util::Error> {
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DtlsManager
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// DTLS-SRTP Manager
pub struct DtlsManager {
    /// DTLS contexts by session ID
    contexts: Arc<Mutex<std::collections::HashMap<String, Arc<DtlsContext>>>>,
}

impl DtlsManager {
    /// Create new DTLS manager
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Create DTLS context for session
    pub async fn create_context(
        &self,
        session_id: String,
        role: DtlsRole,
    ) -> Result<Arc<DtlsContext>> {
        let context = Arc::new(DtlsContext::new(role)?);
        self.contexts
            .lock()
            .await
            .insert(session_id, context.clone());
        Ok(context)
    }

    /// Get DTLS context for session
    pub async fn get_context(&self, session_id: &str) -> Option<Arc<DtlsContext>> {
        self.contexts.lock().await.get(session_id).cloned()
    }

    /// Remove DTLS context
    pub async fn remove_context(&self, session_id: &str) {
        self.contexts.lock().await.remove(session_id);
    }

    /// Get statistics
    pub async fn stats(&self) -> DtlsStats {
        let contexts = self.contexts.lock().await;
        DtlsStats {
            total_contexts: contexts.len(),
        }
    }
}

impl Default for DtlsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// DTLS Statistics
#[derive(Debug, Clone)]
pub struct DtlsStats {
    pub total_contexts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_role() {
        assert_eq!(DtlsRole::from_str("active"), Some(DtlsRole::Active));
        assert_eq!(DtlsRole::from_str("passive"), Some(DtlsRole::Passive));
        assert_eq!(DtlsRole::from_str("actpass"), Some(DtlsRole::ActPass));
        assert_eq!(DtlsRole::from_str("invalid"), None);

        assert_eq!(DtlsRole::Active.to_str(), "active");
        assert_eq!(DtlsRole::Passive.to_str(), "passive");
        assert_eq!(DtlsRole::ActPass.to_str(), "actpass");
    }

    #[test]
    fn test_fingerprint_from_sdp() {
        let sdp = "sha-256 49:66:12:C7:A4:34:5D:2C:FA:7B:8D:9E:1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D";
        let fp = CertificateFingerprint::from_sdp(sdp).unwrap();

        assert_eq!(fp.algorithm, "sha-256");
        assert!(fp.fingerprint.contains("49:66:12"));
    }

    #[test]
    fn test_fingerprint_to_sdp() {
        let fp = CertificateFingerprint {
            algorithm: "sha-256".to_string(),
            fingerprint: "AA:BB:CC:DD".to_string(),
        };

        let sdp = fp.to_sdp();
        assert_eq!(sdp, "sha-256 AA:BB:CC:DD");
    }

    #[tokio::test]
    async fn test_dtls_context_creation() {
        let context = DtlsContext::new(DtlsRole::Active).unwrap();

        assert_eq!(context.role(), DtlsRole::Active);
        assert_eq!(context.local_fingerprint().algorithm, "sha-256");
        assert!(!context.is_handshake_complete().await);
    }

    #[tokio::test]
    async fn test_dtls_manager() {
        let manager = DtlsManager::new();

        let ctx = manager
            .create_context("session-1".to_string(), DtlsRole::Passive)
            .await
            .unwrap();

        assert_eq!(ctx.role(), DtlsRole::Passive);

        let retrieved = manager.get_context("session-1").await;
        assert!(retrieved.is_some());

        let stats = manager.stats().await;
        assert_eq!(stats.total_contexts, 1);
    }
}

#[cfg(test)]
mod peer_verification_tests {
    use super::*;

    /// A DTLS-SRTP certificate is self-signed: the handshake runs with
    /// `insecure_skip_verify`, so the *only* thing that ties the session
    /// to the call is the SDP fingerprint. Nothing checked it, which means
    /// any host that could reach the media port could complete the
    /// handshake and take the audio (RFC 8122 §5, RFC 5763 §6.6).
    #[tokio::test]
    async fn the_peers_certificate_must_match_the_sdp_fingerprint() {
        let mut ctx = DtlsContext::new(DtlsRole::Passive).unwrap();
        // Two different peers, each with its own self-signed certificate.
        let peer = DtlsContext::new(DtlsRole::Active).unwrap();
        let impostor = DtlsContext::new(DtlsRole::Active).unwrap();
        assert_ne!(
            peer.local_fingerprint().fingerprint,
            impostor.local_fingerprint().fingerprint
        );

        // No fingerprint at all: refused, and the message says why.
        let err = ctx
            .verify_peer_certificate(std::slice::from_ref(&peer.cert_der))
            .expect_err("a session nothing authenticates is refused");
        assert!(format!("{}", err).contains("a=fingerprint"), "{}", err);

        // The fingerprint the peer signalled: accepted.
        ctx.set_remote_fingerprint(peer.local_fingerprint().clone());
        ctx.verify_peer_certificate(std::slice::from_ref(&peer.cert_der))
            .expect("the real peer is accepted");

        // Someone else's certificate under that fingerprint: refused.
        let err = ctx
            .verify_peer_certificate(std::slice::from_ref(&impostor.cert_der))
            .expect_err("a substituted certificate is refused");
        let msg = format!("{}", err);
        assert!(msg.contains("does not match"), "{}", msg);
        assert!(
            msg.contains(&peer.local_fingerprint().fingerprint),
            "the message names the fingerprint we expected: {}",
            msg
        );

        // A handshake that yielded no certificate at all: refused.
        let err = ctx
            .verify_peer_certificate(&[])
            .expect_err("no certificate, no session");
        assert!(format!("{}", err).contains("no peer certificate"));
    }

    /// Peers write the hex differently. The comparison is on the bytes.
    #[tokio::test]
    async fn the_comparison_ignores_case_and_punctuation() {
        let peer = DtlsContext::new(DtlsRole::Active).unwrap();
        let canonical = peer.local_fingerprint().fingerprint.clone();
        for written in [
            canonical.clone(),
            canonical.to_lowercase(),
            canonical.replace(':', ""),
            canonical.to_lowercase().replace(':', ""),
        ] {
            let fp = CertificateFingerprint {
                algorithm: "sha-256".to_string(),
                fingerprint: written.clone(),
            };
            assert!(
                fp.verify(&peer.cert_der).unwrap(),
                "rejected its own certificate written as {}",
                written
            );
        }
    }

    /// Every hash RFC 8122 §5 allows, and nothing else.
    #[tokio::test]
    async fn the_hash_algorithms_are_the_ones_the_rfc_allows() {
        let peer = DtlsContext::new(DtlsRole::Active).unwrap();
        for (algorithm, bytes) in [
            ("sha-1", 20),
            ("sha-224", 28),
            ("sha-256", 32),
            ("sha-384", 48),
            ("sha-512", 64),
        ] {
            let digest = CertificateFingerprint::digest_of(algorithm, &peer.cert_der)
                .unwrap_or_else(|e| panic!("{} unsupported: {}", algorithm, e));
            assert_eq!(
                digest.split(':').count(),
                bytes,
                "{} digest length",
                algorithm
            );
            let fp = CertificateFingerprint {
                algorithm: algorithm.to_string(),
                fingerprint: digest,
            };
            assert!(fp.verify(&peer.cert_der).unwrap(), "{}", algorithm);
        }
        // An algorithm we cannot compute is an error, never a pass.
        let fp = CertificateFingerprint {
            algorithm: "md5".to_string(),
            fingerprint: "AA:BB".to_string(),
        };
        assert!(fp.verify(&peer.cert_der).is_err());
    }

    /// The session must hand the offer's fingerprint to the DTLS context,
    /// or the check above has nothing to compare against.
    #[test]
    fn the_session_carries_the_offers_fingerprint_into_the_context() {
        let offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
             m=audio 50000 UDP/TLS/RTP/SAVPF 111 0\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef\r\n\
             a=fingerprint:sha-256 \
             11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:\
             11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
             a=setup:actpass\r\n";
        let session =
            crate::media::webrtc_handler::WebRtcSession::new("c1".to_string(), offer).unwrap();
        let fp = session
            .dtls_context
            .remote_fingerprint()
            .expect("the offer's fingerprint reached the DTLS context");
        assert_eq!(fp.algorithm, "sha-256");
        assert!(fp.fingerprint.starts_with("11:22:33:44"));
    }
}

#[cfg(test)]
mod handshake_config_tests {
    use super::*;
    use webrtc_dtls::config::ClientAuthType;

    /// A DTLS server that sends no CertificateRequest gets no certificate
    /// from its client, so `peer_certificates` comes back empty and the
    /// fingerprint check refuses the session. That is the normal WebRTC
    /// case (a browser offers `a=setup:actpass`, so the SBC is passive),
    /// which means the default `client_auth` would have failed **every**
    /// WebRTC call — the check breaking the thing it protects.
    #[tokio::test]
    async fn the_server_role_asks_the_peer_for_its_certificate() {
        for role in [DtlsRole::Passive, DtlsRole::ActPass, DtlsRole::Active] {
            let ctx = DtlsContext::new(role).unwrap();
            let config = DtlsContext::handshake_config(ctx.dtls_certificate.clone());
            assert!(
                matches!(config.client_auth, ClientAuthType::RequireAnyClientCert),
                "role {:?} must request the peer's certificate",
                role
            );
            // Requested, but not chain-validated: the certificate is
            // self-signed and the SDP fingerprint is the authenticator.
            assert!(config.insecure_skip_verify);
            assert_eq!(config.certificates.len(), 1, "our own certificate is sent");
        }
    }
}
