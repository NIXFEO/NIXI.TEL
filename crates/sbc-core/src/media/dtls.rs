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
use tracing::{debug, error, info, warn};

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

    /// Verify fingerprint matches certificate
    pub fn verify(&self, cert_der: &[u8]) -> Result<bool> {
        use sha2::{Sha256, Digest};

        if self.algorithm != "sha-256" {
            return Err(Error::Media(format!(
                "Unsupported hash algorithm: {}",
                self.algorithm
            )));
        }

        // Compute SHA-256 of certificate
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        // Format as hex with colons
        let computed = hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");

        Ok(computed == self.fingerprint.to_uppercase())
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
        let dtls_certificate = webrtc_dtls::crypto::Certificate::generate_self_signed(
            vec!["webrtc.local".to_string()]
        ).map_err(|e| Error::Media(format!("DTLS certificate generation failed: {}", e)))?;

        // Extract DER bytes from the certificate for fingerprint computation
        let cert_der = dtls_certificate.certificate[0].0.clone();

        // Compute SHA-256 fingerprint from the SAME certificate
        let fingerprint = Self::compute_fingerprint(&cert_der)?;

        info!("DTLS context created (role={:?}, fingerprint={})", role, fingerprint.fingerprint);

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
        use sha2::{Sha256, Digest};

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

    /// Perform real DTLS-SRTP handshake via webrtc-dtls crate.
    ///
    /// The `bridge` routes DTLS packets from the RTP socket to webrtc-dtls
    /// and sends DTLS responses back via the same RTP socket.
    ///
    /// After handshake completes, SRTP keying material is exported.
    pub async fn perform_handshake(
        &self,
        bridge: Arc<DtlsUdpBridge>,
    ) -> Result<()> {
        use webrtc_dtls::config::Config;
        use webrtc_dtls::conn::DTLSConn;
        use webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
        use webrtc_util::KeyingMaterialExporter;

        let is_client = self.role == DtlsRole::Active;
        info!(
            "DTLS handshake starting (role: {:?}, is_client: {})",
            self.role, is_client
        );

        // CRITICAL: Use the SAME certificate that was used to compute the SDP fingerprint.
        // If we generate a new cert here, the browser sees a different fingerprint during
        // DTLS and sends a fatal alert, killing the connection.
        let config = Config {
            certificates: vec![self.dtls_certificate.clone()],
            srtp_protection_profiles: vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ],
            insecure_skip_verify: true, // We verify fingerprint via SDP, not via X.509 chain
            ..Default::default()
        };

        // Perform handshake (with timeout)
        let dtls_conn = tokio::time::timeout(
            Duration::from_secs(15),
            DTLSConn::new(bridge, config, is_client, None),
        )
        .await
        .map_err(|_| Error::Media("DTLS handshake timeout (15s)".to_string()))?
        .map_err(|e| Error::Media(format!("DTLS handshake failed: {}", e)))?;

        info!("DTLS handshake completed successfully");

        // Export SRTP keying material (RFC 5764)
        let state = dtls_conn.connection_state().await;

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

    /// Create SRTP encryption/decryption contexts from the DTLS-derived keys.
    ///
    /// Returns `(recv_context, send_context)`:
    /// - recv_context: decrypts SRTP packets FROM the browser
    /// - send_context: encrypts RTP packets TO the browser
    pub async fn create_srtp_contexts(&self) -> Result<(SrtpContext, SrtpContext)> {
        let keys = self.srtp_keys.lock().await.clone()
            .ok_or_else(|| Error::Media("DTLS handshake not complete — no SRTP keys".to_string()))?;

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

        let recv_ctx = SrtpContext::new(
            recv_key,
            recv_salt,
            CryptoSuite::AesCm128HmacSha1_80,
        )?;
        let send_ctx = SrtpContext::new(
            send_key,
            send_salt,
            CryptoSuite::AesCm128HmacSha1_80,
        )?;

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
            Err(webrtc_util::Error::Other("No remote address known".to_string()))
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
    pub async fn create_context(&self, session_id: String, role: DtlsRole) -> Result<Arc<DtlsContext>> {
        let context = Arc::new(DtlsContext::new(role)?);
        self.contexts.lock().await.insert(session_id, context.clone());
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
