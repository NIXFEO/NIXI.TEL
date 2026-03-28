//! RTP Proxy - Real-time Transport Protocol Relay
//!
//! RFC 3550 - RTP: A Transport Protocol for Real-Time Applications
//! https://tools.ietf.org/html/rfc3550
//!
//! Two-leg symmetric proxy design:
//!   - Leg A (caller side): SBC listens on `ports_a.rtp`
//!     * Receives RTP from caller → relays to callee (via leg-B socket)
//!   - Leg B (callee side): SBC listens on `ports_b.rtp`
//!     * Receives RTP from callee → relays to caller (via leg-A socket)
//!
//! SDP rewriting (note: the SDP port tells the peer WHERE to send RTP):
//!   - The 200 OK SDP sent to caller contains `ports_a.rtp` → caller sends to leg-A.
//!   - The INVITE SDP sent to callee contains `ports_b.rtp` → callee sends to leg-B.

use crate::media::PortPair;
use crate::media::srtp::SrtpContext;
use crate::media::stun::{classify_packet, build_binding_response_with_integrity, MultiplexedPacketType};
use crate::transcoding::{Codec, Transcoder};
use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, error, info, warn};

/// RTP Packet (simplified header)
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// Version (2 bits) - should be 2
    pub version: u8,

    /// Padding flag
    pub padding: bool,

    /// Extension flag
    pub extension: bool,

    /// CSRC count
    pub csrc_count: u8,

    /// Marker bit
    pub marker: bool,

    /// Payload type
    pub payload_type: u8,

    /// Sequence number
    pub sequence_number: u16,

    /// Timestamp
    pub timestamp: u32,

    /// SSRC identifier
    pub ssrc: u32,

    /// Raw payload data
    pub payload: Vec<u8>,
}

/// RTP Proxy Session — two-leg symmetric proxy
pub struct RtpSession {
    /// Session ID (usually dialog ID)
    pub session_id: String,

    /// Leg-A ports (for the caller side)
    pub ports_a: PortPair,

    /// Leg-B ports (for the callee side)
    pub ports_b: PortPair,

    // Backward compat: expose primary ports as local_ports (leg A)
    pub local_ports: PortPair,

    /// Pre-configured endpoint A (caller) — shared with relay task
    pub endpoint_a: Option<SocketAddr>,
    endpoint_a_shared: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,

    /// Pre-configured endpoint B (callee) — shared with relay task
    pub endpoint_b: Option<SocketAddr>,
    endpoint_b_shared: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,

    /// Leg-A RTP socket (receives from caller, sends to callee)
    rtp_socket_a: Arc<UdpSocket>,

    /// Leg-B RTP socket (receives from callee, sends to caller)
    rtp_socket_b: Arc<UdpSocket>,

    /// Leg-A RTCP socket
    rtcp_socket_a: Arc<UdpSocket>,

    /// Leg-B RTCP socket
    rtcp_socket_b: Arc<UdpSocket>,

    /// Statistics
    stats: Arc<RtpStats>,

    /// Global RTP packet counter (from SbcMetrics — shared across all sessions)
    global_rtp_counter: Option<Arc<AtomicU64>>,

    /// Global SRTP encrypted counter (from SbcMetrics)
    global_srtp_encrypt_counter: Option<Arc<AtomicU64>>,

    /// Global SRTP decrypted counter (from SbcMetrics)
    global_srtp_decrypt_counter: Option<Arc<AtomicU64>>,

    /// SRTP context for leg A — decrypt direction (decrypt packets FROM caller).
    /// For SDES-SRTP: same context as send. For DTLS-SRTP: separate keys.
    /// Uses Arc<Mutex<Option>> so the DTLS handshake task can hot-swap the context
    /// into the running relay task after DTLS-SRTP key export.
    srtp_recv_ctx_a: Arc<AsyncMutex<Option<SrtpContext>>>,

    /// SRTP context for leg A — send direction (encrypt packets TO caller).
    /// For SDES-SRTP: None (falls back to recv ctx which handles both).
    /// For DTLS-SRTP: separate send context with different keys.
    srtp_send_ctx_a: Arc<AsyncMutex<Option<SrtpContext>>>,

    /// SRTP context for leg B (decrypt packets FROM callee, encrypt packets TO callee).
    srtp_context_b: Arc<AsyncMutex<Option<SrtpContext>>>,

    /// Transcoder for A→B direction (caller codec → callee codec)
    /// e.g. Opus→PCMU when caller is WebRTC and callee is SIP trunk
    transcoder_a_to_b: Option<Arc<Transcoder>>,

    /// Transcoder for B→A direction (callee codec → caller codec)
    /// e.g. PCMU→Opus when callee is SIP trunk and caller is WebRTC
    transcoder_b_to_a: Option<Arc<Transcoder>>,

    /// Global transcoded packet counter
    global_transcode_counter: Option<Arc<AtomicU64>>,

    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Channel to route DTLS packets from leg-A to the DTLS handshake task.
    /// Only used when leg-A is a WebRTC endpoint (DTLS-SRTP).
    dtls_packet_tx: Option<mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,

    /// Whether leg-A is a WebRTC endpoint (enables STUN/DTLS/RTP demuxing).
    webrtc_mode_a: bool,

    /// Local ICE password (for STUN MESSAGE-INTEGRITY in responses).
    /// Only used when webrtc_mode_a is true.
    ice_pwd_local: Option<String>,

    // ── Leg-B WebRTC support (PSTN → WebRTC callee) ──────────────────

    /// Channel to route DTLS packets from leg-B to the DTLS handshake task.
    dtls_packet_tx_b: Option<mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,

    /// Whether leg-B is a WebRTC endpoint (enables STUN/DTLS/RTP demuxing on callee port).
    webrtc_mode_b: bool,

    /// Local ICE password for leg-B (for STUN MESSAGE-INTEGRITY in responses).
    ice_pwd_local_b: Option<String>,

    /// SRTP send context for leg-B (encrypt packets TO callee WebRTC).
    /// Separate from srtp_context_b for DTLS-SRTP hot-swap.
    srtp_send_ctx_b: Arc<AsyncMutex<Option<SrtpContext>>>,

    /// SRTP recv context for leg-B (decrypt packets FROM callee WebRTC).
    /// Separate from srtp_context_b for DTLS-SRTP hot-swap.
    srtp_recv_ctx_b: Arc<AsyncMutex<Option<SrtpContext>>>,
}

/// RTP Statistics
#[derive(Debug)]
pub struct RtpStats {
    /// Packets relayed A → B
    pub packets_a_to_b: AtomicU64,

    /// Packets relayed B → A
    pub packets_b_to_a: AtomicU64,

    /// Bytes relayed A → B
    pub bytes_a_to_b: AtomicU64,

    /// Bytes relayed B → A
    pub bytes_b_to_a: AtomicU64,

    /// Total packets lost (detected)
    pub packets_lost: AtomicU64,

    /// Last RTP activity timestamp (unix epoch seconds) — for timeout detection
    pub last_activity_secs: AtomicU64,
}

impl RtpPacket {
    /// Parse RTP packet from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::Parse("RTP packet too short".to_string()));
        }

        let version = (data[0] >> 6) & 0x03;
        let padding = (data[0] & 0x20) != 0;
        let extension = (data[0] & 0x10) != 0;
        let csrc_count = data[0] & 0x0F;

        let marker = (data[1] & 0x80) != 0;
        let payload_type = data[1] & 0x7F;

        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let header_len = 12 + (csrc_count as usize * 4);
        if data.len() < header_len {
            return Err(Error::Parse("Invalid RTP header length".to_string()));
        }

        let payload = data[header_len..].to_vec();

        Ok(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            payload,
        })
    }

    /// Serialize RTP packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.payload.len());

        // Byte 0: V(2), P(1), X(1), CC(4)
        let byte0 = (self.version << 6)
            | (if self.padding { 0x20 } else { 0 })
            | (if self.extension { 0x10 } else { 0 })
            | self.csrc_count;
        bytes.push(byte0);

        // Byte 1: M(1), PT(7)
        let byte1 = (if self.marker { 0x80 } else { 0 }) | self.payload_type;
        bytes.push(byte1);

        // Sequence number
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());

        // Timestamp
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());

        // SSRC
        bytes.extend_from_slice(&self.ssrc.to_be_bytes());

        // Payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }
}

/// Calculate the full RTP header length, including CSRC and header extensions.
///
/// Returns 0 if the packet is too short or malformed.
/// This properly handles WebRTC packets which typically have one-byte or
/// two-byte header extensions (RFC 5285).
fn rtp_header_length(data: &[u8]) -> usize {
    if data.len() < 12 {
        return 0;
    }

    // Base header: 12 bytes
    let mut hdr_len = 12;

    // CSRC count (bits 0-3 of byte 0)
    let cc = (data[0] & 0x0F) as usize;
    hdr_len += cc * 4;

    // Extension bit (bit 4 of byte 0)
    if data[0] & 0x10 != 0 {
        if data.len() < hdr_len + 4 {
            return 0; // Malformed: not enough data for extension header
        }
        // Extension length is in 32-bit words (bytes hdr_len+2..hdr_len+4)
        let ext_len = u16::from_be_bytes([data[hdr_len + 2], data[hdr_len + 3]]) as usize;
        hdr_len += 4 + (ext_len * 4); // 4-byte extension header + extension data
    }

    if hdr_len > data.len() {
        return 0; // Malformed
    }

    hdr_len
}

impl RtpSession {
    /// Create a new two-leg RTP proxy session
    ///
    /// `ports_a` — leg A ports (caller side, appears in callee-bound INVITE SDP)
    /// `ports_b` — leg B ports (callee side, appears in caller-bound 200 OK SDP)
    pub async fn new_two_leg(
        session_id: String,
        ports_a: PortPair,
        ports_b: PortPair,
    ) -> Result<Self> {
        // Bind leg-A RTP socket
        let rtp_socket_a = UdpSocket::bind(format!("0.0.0.0:{}", ports_a.rtp))
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind RTP-A socket: {}", e)))?;

        // Bind leg-A RTCP socket
        let rtcp_socket_a = UdpSocket::bind(format!("0.0.0.0:{}", ports_a.rtcp))
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind RTCP-A socket: {}", e)))?;

        // Bind leg-B RTP socket
        let rtp_socket_b = UdpSocket::bind(format!("0.0.0.0:{}", ports_b.rtp))
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind RTP-B socket: {}", e)))?;

        // Bind leg-B RTCP socket
        let rtcp_socket_b = UdpSocket::bind(format!("0.0.0.0:{}", ports_b.rtcp))
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind RTCP-B socket: {}", e)))?;

        info!(
            "Created two-leg RTP session {} on A={}/{} B={}/{}",
            session_id, ports_a.rtp, ports_a.rtcp, ports_b.rtp, ports_b.rtcp
        );

        Ok(Self {
            session_id,
            local_ports: ports_a,
            ports_a,
            ports_b,
            endpoint_a: None,
            endpoint_a_shared: Arc::new(tokio::sync::Mutex::new(None)),
            endpoint_b: None,
            endpoint_b_shared: Arc::new(tokio::sync::Mutex::new(None)),
            rtp_socket_a: Arc::new(rtp_socket_a),
            rtp_socket_b: Arc::new(rtp_socket_b),
            rtcp_socket_a: Arc::new(rtcp_socket_a),
            rtcp_socket_b: Arc::new(rtcp_socket_b),
            stats: Arc::new(RtpStats::new()),
            global_rtp_counter: None,
            global_srtp_encrypt_counter: None,
            global_srtp_decrypt_counter: None,
            srtp_recv_ctx_a: Arc::new(AsyncMutex::new(None)),
            srtp_send_ctx_a: Arc::new(AsyncMutex::new(None)),
            srtp_context_b: Arc::new(AsyncMutex::new(None)),
            transcoder_a_to_b: None,
            transcoder_b_to_a: None,
            global_transcode_counter: None,
            shutdown_tx: None,
            dtls_packet_tx: None,
            webrtc_mode_a: false,
            ice_pwd_local: None,
            dtls_packet_tx_b: None,
            webrtc_mode_b: false,
            ice_pwd_local_b: None,
            srtp_send_ctx_b: Arc::new(AsyncMutex::new(None)),
            srtp_recv_ctx_b: Arc::new(AsyncMutex::new(None)),
        })
    }

    /// Backward-compatible constructor (single port pair — both legs on same port)
    pub async fn new(session_id: String, local_ports: PortPair) -> Result<Self> {
        Self::new_two_leg(session_id, local_ports, local_ports).await
    }

    /// Attach global RTP packet counter (from SbcMetrics) for Prometheus reporting
    pub fn set_global_rtp_counter(&mut self, counter: Arc<AtomicU64>) {
        self.global_rtp_counter = Some(counter);
    }

    /// Attach global SRTP encrypted counter (from SbcMetrics)
    pub fn set_global_srtp_encrypt_counter(&mut self, counter: Arc<AtomicU64>) {
        self.global_srtp_encrypt_counter = Some(counter);
    }

    /// Attach global SRTP decrypted counter (from SbcMetrics)
    pub fn set_global_srtp_decrypt_counter(&mut self, counter: Arc<AtomicU64>) {
        self.global_srtp_decrypt_counter = Some(counter);
    }

    /// Set transcoder for A→B direction (caller to callee)
    ///
    /// Used when caller and callee use different codecs (e.g. WebRTC Opus → SIP G.711)
    pub fn set_transcoder_a_to_b(&mut self, transcoder: Arc<Transcoder>) {
        info!(
            "Session {} transcoding A→B: {} → {}",
            self.session_id, transcoder.src.name(), transcoder.dst.name()
        );
        self.transcoder_a_to_b = Some(transcoder);
    }

    /// Set transcoder for B→A direction (callee to caller)
    pub fn set_transcoder_b_to_a(&mut self, transcoder: Arc<Transcoder>) {
        info!(
            "Session {} transcoding B→A: {} → {}",
            self.session_id, transcoder.src.name(), transcoder.dst.name()
        );
        self.transcoder_b_to_a = Some(transcoder);
    }

    /// Attach global transcoded packet counter (from SbcMetrics)
    pub fn set_global_transcode_counter(&mut self, counter: Arc<AtomicU64>) {
        self.global_transcode_counter = Some(counter);
    }

    /// Set SRTP context for leg A (caller side) — SDES-SRTP (same key both directions).
    /// Used to decrypt SRTP from caller and encrypt RTP back to caller.
    /// Safe to call before or after start() — writes into shared Arc<Mutex<Option>>.
    pub fn set_srtp_context_a(&mut self, ctx: SrtpContext) {
        info!("Session {} SRTP enabled on leg A ({})", self.session_id, ctx.crypto_suite());
        // For SDES-SRTP, same context handles both recv and send
        // We clone the context for the send direction
        let recv_shared = self.srtp_recv_ctx_a.clone();
        let send_shared = self.srtp_send_ctx_a.clone();
        let crypto_suite = ctx.crypto_suite();
        // Create a second context with the same key material for the send direction
        let ctx2 = ctx.clone_for_send();
        tokio::spawn(async move {
            *recv_shared.lock().await = Some(ctx);
            *send_shared.lock().await = Some(ctx2);
        });
    }

    /// Set SRTP context for leg B (callee side)
    /// Used to decrypt SRTP from callee and encrypt RTP back to callee.
    pub fn set_srtp_context_b(&self, ctx: SrtpContext) {
        info!("Session {} SRTP enabled on leg B ({})", self.session_id, ctx.crypto_suite());
        let shared = self.srtp_context_b.clone();
        tokio::spawn(async move {
            *shared.lock().await = Some(ctx);
        });
    }

    /// Get the shared SRTP recv context Arc for leg A (for DTLS hot-swap — decrypt direction).
    pub fn srtp_recv_ctx_a_shared(&self) -> Arc<AsyncMutex<Option<SrtpContext>>> {
        self.srtp_recv_ctx_a.clone()
    }

    /// Get the shared SRTP send context Arc for leg A (for DTLS hot-swap — encrypt direction).
    pub fn srtp_send_ctx_a_shared(&self) -> Arc<AsyncMutex<Option<SrtpContext>>> {
        self.srtp_send_ctx_a.clone()
    }

    /// Set endpoint A (caller's real RTP address) — pre-configured from SDP
    pub fn set_endpoint_a(&mut self, addr: SocketAddr) {
        info!("Session {} endpoint A: {}", self.session_id, addr);
        self.endpoint_a = Some(addr);
        let shared = self.endpoint_a_shared.clone();
        tokio::spawn(async move {
            *shared.lock().await = Some(addr);
        });
    }

    /// Set endpoint B (callee's real RTP address) — pre-configured from SDP
    pub fn set_endpoint_b(&mut self, addr: SocketAddr) {
        info!("Session {} endpoint B: {}", self.session_id, addr);
        self.endpoint_b = Some(addr);
        let shared = self.endpoint_b_shared.clone();
        tokio::spawn(async move {
            *shared.lock().await = Some(addr);
        });
    }

    /// Enable WebRTC mode on leg A — activates STUN/DTLS/RTP demuxing.
    /// Returns a receiver for DTLS packets that will arrive on the RTP socket.
    /// `ice_pwd` is the SBC's local ICE password, used for STUN MESSAGE-INTEGRITY.
    pub fn enable_webrtc_mode_a(&mut self, ice_pwd: Option<String>) -> mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.dtls_packet_tx = Some(tx);
        self.webrtc_mode_a = true;
        self.ice_pwd_local = ice_pwd;
        info!("Session {} WebRTC mode enabled on leg A (STUN/DTLS/RTP demux, ICE-pwd={})",
            self.session_id, if self.ice_pwd_local.is_some() { "set" } else { "none" });
        rx
    }

    /// Get the leg-A RTP socket (for DTLS handshake to send responses back)
    pub fn rtp_socket_a(&self) -> Arc<UdpSocket> {
        self.rtp_socket_a.clone()
    }

    /// Enable WebRTC mode on leg B — activates STUN/DTLS/RTP demuxing on callee port.
    /// Returns a receiver for DTLS packets that will arrive on the leg-B RTP socket.
    pub fn enable_webrtc_mode_b(&mut self, ice_pwd: Option<String>) -> mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.dtls_packet_tx_b = Some(tx);
        self.webrtc_mode_b = true;
        self.ice_pwd_local_b = ice_pwd;
        info!("Session {} WebRTC mode enabled on leg B (STUN/DTLS/RTP demux, ICE-pwd={})",
            self.session_id, if self.ice_pwd_local_b.is_some() { "set" } else { "none" });
        rx
    }

    /// Get the leg-B RTP socket (for DTLS handshake to send responses back)
    pub fn rtp_socket_b(&self) -> Arc<UdpSocket> {
        self.rtp_socket_b.clone()
    }

    /// Get the shared SRTP recv context for leg B (for DTLS hot-swap)
    pub fn srtp_recv_ctx_b_shared(&self) -> Arc<AsyncMutex<Option<SrtpContext>>> {
        self.srtp_recv_ctx_b.clone()
    }

    /// Get the shared SRTP send context for leg B (for DTLS hot-swap)
    pub fn srtp_send_ctx_b_shared(&self) -> Arc<AsyncMutex<Option<SrtpContext>>> {
        self.srtp_send_ctx_b.clone()
    }

    /// Start the two-leg bidirectional RTP proxy
    ///
    /// Leg A socket receives from caller → learns caller addr → relays to callee via leg B
    /// Leg B socket receives from callee → learns callee addr → relays to caller via leg A
    pub async fn start(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        let rtp_socket_a = self.rtp_socket_a.clone();
        let rtp_socket_b = self.rtp_socket_b.clone();
        let rtcp_socket_a = self.rtcp_socket_a.clone();
        let rtcp_socket_b = self.rtcp_socket_b.clone();
        let stats = self.stats.clone();
        let session_id = self.session_id.clone();
        let global_rtp_counter = self.global_rtp_counter.clone();
        let global_srtp_encrypt_counter = self.global_srtp_encrypt_counter.clone();
        let global_srtp_decrypt_counter = self.global_srtp_decrypt_counter.clone();

        // SRTP contexts — Arc<Mutex<Option<SrtpContext>>> allows hot-swap after DTLS handshake
        let srtp_recv_a = self.srtp_recv_ctx_a.clone();
        let srtp_send_a = self.srtp_send_ctx_a.clone();
        let srtp_ctx_b = self.srtp_context_b.clone();

        // Transcoders (None = passthrough / same codec on both legs)
        let transcoder_a_to_b = self.transcoder_a_to_b.clone();
        let transcoder_b_to_a = self.transcoder_b_to_a.clone();
        let global_transcode_counter = self.global_transcode_counter.clone();

        // WebRTC mode: STUN/DTLS/RTP demuxing on leg A
        let webrtc_mode_a = self.webrtc_mode_a;
        let dtls_packet_tx = self.dtls_packet_tx.clone();
        let ice_pwd_local = self.ice_pwd_local.clone();

        // WebRTC mode: STUN/DTLS/RTP demuxing on leg B (PSTN→WebRTC callee)
        let webrtc_mode_b = self.webrtc_mode_b;
        let dtls_packet_tx_b = self.dtls_packet_tx_b.clone();
        let ice_pwd_local_b = self.ice_pwd_local_b.clone();
        let srtp_recv_b = self.srtp_recv_ctx_b.clone();
        let srtp_send_b = self.srtp_send_ctx_b.clone();

        // Shared endpoints (learned dynamically or pre-configured)
        let endpoint_a = self.endpoint_a_shared.clone(); // caller's real addr
        let endpoint_b = self.endpoint_b_shared.clone(); // callee's real addr

        let ports_a_rtp = self.ports_a.rtp;
        let ports_b_rtp = self.ports_b.rtp;

        // Check initial SRTP state (may be hot-swapped later via DTLS)
        {
            let has_srtp_a = srtp_recv_a.lock().await.is_some();
            let has_srtp_b = srtp_ctx_b.lock().await.is_some();
            if has_srtp_a || has_srtp_b {
                info!(
                    "RTP session {} SRTP mode: leg-A={} leg-B={}",
                    session_id,
                    if has_srtp_a { "SRTP" } else { "RTP" },
                    if has_srtp_b { "SRTP" } else { "RTP" },
                );
            } else if webrtc_mode_a {
                info!(
                    "RTP session {} WebRTC mode: SRTP will be enabled after DTLS handshake",
                    session_id
                );
            }
        }
        let has_transcode_ab = transcoder_a_to_b.is_some();
        let has_transcode_ba = transcoder_b_to_a.is_some();
        if has_transcode_ab || has_transcode_ba {
            info!(
                "RTP session {} transcoding enabled: A→B={} B→A={}",
                session_id,
                if has_transcode_ab { "yes" } else { "no" },
                if has_transcode_ba { "yes" } else { "no" },
            );
        }

        tokio::spawn(async move {
            let mut buf_a    = vec![0u8; 4096];
            let mut buf_b    = vec![0u8; 4096];
            let mut buf_rtcp_a = vec![0u8; 4096];
            let mut buf_rtcp_b = vec![0u8; 4096];
            let mut pkt_count: u64 = 0;

            info!(
                "RTP two-leg relay started: session={} leg-A={} leg-B={} (task alive)",
                session_id, ports_a_rtp, ports_b_rtp
            );

            // Log initial endpoint state
            {
                let ea = endpoint_a.lock().await;
                let eb = endpoint_b.lock().await;
                info!(
                    "RTP relay {} initial endpoints: A={:?} B={:?}",
                    session_id, *ea, *eb
                );
            }

            // RTP inactivity timeout: 90 seconds (covers DTLS handshake + ICE negotiation)
            let rtp_timeout_secs: u64 = 90;
            let mut rtp_timeout_interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
            // Initialize last_activity to now
            stats.last_activity_secs.store(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                Ordering::Relaxed,
            );

            loop {
                tokio::select! {
                    shutdown_result = shutdown_rx.recv() => {
                        if shutdown_result.is_some() {
                            info!("RTP session {} shutting down (explicit signal, relayed {} packets)", session_id, pkt_count);
                        } else {
                            warn!("RTP session {} shutdown: channel closed (sender dropped, relayed {} packets)", session_id, pkt_count);
                        }
                        break;
                    }

                    // ── RTP inactivity check ────────────────────────────────────────
                    _ = rtp_timeout_interval.tick() => {
                        let last = stats.last_activity_secs.load(Ordering::Relaxed);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let idle_secs = now.saturating_sub(last);
                        if idle_secs > rtp_timeout_secs && pkt_count > 0 {
                            warn!("RTP session {} no media for {}s (timeout={}s) — terminating (relayed {} packets)",
                                session_id, idle_secs, rtp_timeout_secs, pkt_count);
                            break;
                        }
                    }

                    // ── Leg A: packet from caller ──────────────────────────────
                    result = rtp_socket_a.recv_from(&mut buf_a) => {
                        if let Ok((len, source)) = result {
                            let data_slice = &buf_a[..len];

                            // ── WebRTC demux: STUN / DTLS / RTP (RFC 5764 §5.1.2) ──
                            if webrtc_mode_a {
                                match classify_packet(data_slice) {
                                    MultiplexedPacketType::Stun => {
                                        // ICE connectivity check — respond with Binding Response + MESSAGE-INTEGRITY
                                        match build_binding_response_with_integrity(data_slice, source, ice_pwd_local.as_deref()) {
                                            Ok(response) => {
                                                if let Err(e) = rtp_socket_a.send_to(&response, source).await {
                                                    warn!("STUN binding response send error: {}", e);
                                                } else {
                                                    info!("STUN binding response sent to {} on leg-A:{} (integrity={})",
                                                        source, ports_a_rtp, ice_pwd_local.is_some());
                                                }
                                            }
                                            Err(e) => {
                                                warn!("STUN parse error from {}: {}", source, e);
                                            }
                                        }
                                        // Learn caller endpoint from STUN (ICE uses same port for media)
                                        {
                                            let mut ep = endpoint_a.lock().await;
                                            if ep.is_none() {
                                                info!("RTP: learned caller (A) via STUN = {} on leg-A:{}", source, ports_a_rtp);
                                                *ep = Some(source);
                                            }
                                        }
                                        continue; // Not RTP — don't relay
                                    }
                                    MultiplexedPacketType::Dtls => {
                                        // Route to DTLS handshake task
                                        if let Some(ref tx) = dtls_packet_tx {
                                            if let Err(e) = tx.send((data_slice.to_vec(), source)) {
                                                warn!("DTLS packet channel send error: {}", e);
                                            } else {
                                                debug!("DTLS packet ({} bytes) from {} routed to handshake task", len, source);
                                            }
                                        } else {
                                            warn!("DTLS packet from {} but no handshake task attached", source);
                                        }
                                        // Learn caller endpoint from DTLS too
                                        {
                                            let mut ep = endpoint_a.lock().await;
                                            if ep.is_none() {
                                                info!("RTP: learned caller (A) via DTLS = {} on leg-A:{}", source, ports_a_rtp);
                                                *ep = Some(source);
                                            }
                                        }
                                        continue; // Not RTP — don't relay
                                    }
                                    MultiplexedPacketType::Rtp => {
                                        // Fall through to normal RTP processing below
                                    }
                                    MultiplexedPacketType::Rtcp => {
                                        debug!("RTCP packet on rtcp-mux port from {} ({} bytes), ignoring", source, len);
                                        continue;
                                    }
                                    MultiplexedPacketType::Unknown => {
                                        debug!("Unknown packet type ({} bytes) from {} on leg-A, first byte: {:02x}",
                                            len, source, data_slice.first().unwrap_or(&0));
                                        continue;
                                    }
                                }
                            }

                            pkt_count += 1;
                            let mut data = data_slice.to_vec();

                            // Log first few packets at INFO level for debugging
                            if pkt_count <= 5 {
                                info!("RTP A recv #{}: {} bytes from {} on leg-A:{}", pkt_count, len, source, ports_a_rtp);
                            }

                            // Learn / update caller's real address
                            {
                                let mut ep = endpoint_a.lock().await;
                                if ep.is_none() {
                                    info!("RTP: learned caller (A) = {} on leg-A:{}", source, ports_a_rtp);
                                    *ep = Some(source);
                                } else if *ep != Some(source) {
                                    // NAT port change — update
                                    info!("RTP: caller addr updated {} → {}", ep.unwrap(), source);
                                    *ep = Some(source);
                                }
                            }

                            // ── SRTP decrypt from caller (leg A) ────────────────
                            {
                                let mut guard = srtp_recv_a.lock().await;
                                if let Some(ref mut ctx) = *guard {
                                    match ctx.decrypt_srtp(&data) {
                                        Ok(plaintext) => {
                                            debug!("SRTP A: decrypted {} → {} bytes", data.len(), plaintext.len());
                                            data = plaintext;
                                            if let Some(ref c) = global_srtp_decrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP A decrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                } else if webrtc_mode_a {
                                    // WebRTC mode: DTLS handshake not yet complete → no SRTP keys.
                                    // DROP the packet — browser sends SRTP which we can't decrypt.
                                    // Relaying encrypted SRTP to the trunk would produce garbled audio.
                                    debug!("RTP A→B: dropping packet (WebRTC mode, DTLS/SRTP not yet ready)");
                                    continue;
                                }
                            }

                            // ── Transcode A→B (caller codec → callee codec) ─────
                            if let Some(ref tc) = transcoder_a_to_b {
                                // Parse RTP header to get payload, transcode, rebuild
                                if data.len() >= 12 {
                                    let actual_pt = data[1] & 0x7F;

                                    // ── PT filtering (Phase 16: DTMF relay) ──
                                    // DTMF telephone-event (PT 96-127) and Comfort Noise (CN=13)
                                    // must NOT be transcoded — relay them as-is (RFC 4733).
                                    // Unknown PTs that aren't DTMF/CN are dropped.
                                    let expected_pt = tc.src.pt();
                                    let is_dtmf_or_cn = actual_pt >= 96 || actual_pt == 13;
                                    if actual_pt != expected_pt && !is_dtmf_or_cn {
                                        debug!("RTP A→B: skip unknown PT {} (expected {}), {} bytes",
                                            actual_pt, expected_pt, data.len());
                                        continue;
                                    }
                                    if is_dtmf_or_cn {
                                        debug!("RTP A→B: relaying DTMF/CN PT {} as-is ({} bytes)", actual_pt, data.len());
                                        // Skip transcoding — packet goes straight to SRTP encrypt + send
                                    } else {

                                    let header_len = rtp_header_length(&data);
                                    if header_len > 0 && data.len() > header_len {
                                        let payload_len = data.len() - header_len;

                                        // ── Frame size validation for G.711 ──
                                        // G.711 20ms = 160 bytes. Non-standard sizes (CN packets
                                        // with PT=8, broken frames) cause Opus encode failures.
                                        if (tc.src == crate::transcoding::Codec::Pcma || tc.src == crate::transcoding::Codec::Pcmu)
                                            && payload_len != 160 {
                                            debug!("Transcode A→B: skip non-standard G.711 frame ({} bytes, expected 160)", payload_len);
                                            continue;
                                        }

                                        let payload_vec = data[header_len..].to_vec();
                                        // Log first few transcodings for debugging
                                        let ab_debug = stats.packets_a_to_b.load(Ordering::Relaxed);
                                        if ab_debug < 5 {
                                            info!("Transcode A→B #{}: src_pt={} payload={} bytes hdr={} total={}",
                                                ab_debug + 1, actual_pt, payload_len, header_len, data.len());
                                        }
                                        match tc.transcode(&payload_vec) {
                                            Ok(transcoded) => {
                                                if ab_debug < 5 {
                                                    info!("Transcode A→B #{}: {} → {} ({} → {} bytes)",
                                                        ab_debug + 1,
                                                        tc.src.name(), tc.dst.name(),
                                                        payload_len, transcoded.len());
                                                }
                                                // Rebuild RTP: minimal 12-byte header (strip extensions)
                                                // + update PT + new payload.
                                                // For trunk (plain RTP/AVP), header extensions are
                                                // not needed and some endpoints reject them.
                                                let mut new_pkt = Vec::with_capacity(12 + transcoded.len());
                                                new_pkt.extend_from_slice(&data[..12]);
                                                // Clear extension bit (X=0) and CSRC count (CC=0)
                                                new_pkt[0] = 0x80; // V=2, P=0, X=0, CC=0
                                                new_pkt[1] = (data[1] & 0x80) | tc.dst.pt();
                                                new_pkt.extend_from_slice(&transcoded);

                                                // ── RTP timestamp rewrite for clock rate conversion ──
                                                // PCMA/PCMU at 8kHz → Opus at 48kHz: multiply by 6
                                                // Opus at 48kHz → PCMA/PCMU at 8kHz: divide by 6
                                                if new_pkt.len() >= 8 {
                                                    let src_rate = tc.src.clock_rate();
                                                    let dst_rate = tc.dst.clock_rate();
                                                    if src_rate != dst_rate && dst_rate > 0 {
                                                        let old_ts = u32::from_be_bytes([new_pkt[4], new_pkt[5], new_pkt[6], new_pkt[7]]);
                                                        let new_ts = ((old_ts as u64) * dst_rate as u64 / src_rate as u64) as u32;
                                                        new_pkt[4..8].copy_from_slice(&new_ts.to_be_bytes());
                                                        if ab_debug < 5 {
                                                            info!("Transcode A→B #{}: TS {} → {} (rate {}→{})",
                                                                ab_debug + 1, old_ts, new_ts, src_rate, dst_rate);
                                                        }
                                                    }
                                                }

                                                data = new_pkt;
                                                if let Some(ref c) = global_transcode_counter {
                                                    c.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Transcode A→B error: {} (dropping packet)", e);
                                                continue;
                                            }
                                        }
                                    }
                                    } // end else (transcode media PT)
                                }
                            }

                            // ── SRTP encrypt toward callee (leg B) ──────────────
                            // When callee is WebRTC (DTLS-SRTP), use srtp_send_b (hot-swappable).
                            // Otherwise use srtp_ctx_b (SDES-SRTP).
                            if webrtc_mode_b {
                                let mut guard = srtp_send_b.lock().await;
                                if let Some(ref mut ctx) = *guard {
                                    match ctx.encrypt_rtp(&data) {
                                        Ok(encrypted) => {
                                            let ab_enc = stats.packets_a_to_b.load(Ordering::Relaxed);
                                            if ab_enc < 5 {
                                                info!("SRTP encrypt A→B #{}: {} → {} bytes (PT={})",
                                                    ab_enc + 1, data.len(), encrypted.len(), data[1] & 0x7F);
                                            }
                                            data = encrypted;
                                            if let Some(ref c) = global_srtp_encrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP B (DTLS) encrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                } else {
                                    // WebRTC mode B: DTLS handshake not yet complete → no SRTP keys.
                                    // DROP the packet — sending plain RTP to a WebRTC browser
                                    // causes garbled audio and may interfere with DTLS handshake.
                                    debug!("RTP A→B: dropping packet (WebRTC mode B, DTLS/SRTP not yet ready)");
                                    continue;
                                }
                            } else {
                                let mut guard = srtp_ctx_b.lock().await;
                                if let Some(ref mut ctx) = *guard {
                                    match ctx.encrypt_rtp(&data) {
                                        Ok(encrypted) => {
                                            debug!("SRTP B: encrypted {} → {} bytes", data.len(), encrypted.len());
                                            data = encrypted;
                                            if let Some(ref c) = global_srtp_encrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP B encrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                }
                            }

                            // Relay to callee via leg-B socket
                            let dest = *endpoint_b.lock().await;
                            if let Some(dst) = dest {
                                let out_len = data.len();
                                let ab_count = stats.packets_a_to_b.load(Ordering::Relaxed);
                                if ab_count < 3 {
                                    info!("RTP A→B #{}: {} → {} ({} bytes)", ab_count+1, source, dst, out_len);
                                }
                                if let Err(e) = rtp_socket_b.send_to(&data, dst).await {
                                    warn!("RTP A→B send error: {}", e);
                                } else {
                                    stats.packets_a_to_b.fetch_add(1, Ordering::Relaxed);
                                        stats.last_activity_secs.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), Ordering::Relaxed);
                                    stats.bytes_a_to_b.fetch_add(out_len as u64, Ordering::Relaxed);
                                    if let Some(ref c) = global_rtp_counter {
                                        c.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            } else {
                                info!("RTP A: callee endpoint not yet known, packet from {} dropped", source);
                            }
                        } else if let Err(e) = result {
                            error!("RTP leg-A recv error: {}", e);
                        }
                    }

                    // ── Leg B: packet from callee ──────────────────────────────
                    result = rtp_socket_b.recv_from(&mut buf_b) => {
                        if let Ok((len, source)) = result {
                            let data_slice_b = &buf_b[..len];

                            // ── WebRTC demux on leg B: STUN / DTLS / RTP (RFC 5764 §5.1.2) ──
                            if webrtc_mode_b {
                                match classify_packet(data_slice_b) {
                                    MultiplexedPacketType::Stun => {
                                        // ICE connectivity check — respond with Binding Response + MESSAGE-INTEGRITY
                                        match build_binding_response_with_integrity(data_slice_b, source, ice_pwd_local_b.as_deref()) {
                                            Ok(response) => {
                                                if let Err(e) = rtp_socket_b.send_to(&response, source).await {
                                                    warn!("STUN binding response send error (leg-B): {}", e);
                                                } else {
                                                    info!("STUN binding response sent to {} on leg-B:{} (integrity={})",
                                                        source, ports_b_rtp, ice_pwd_local_b.is_some());
                                                }
                                            }
                                            Err(e) => {
                                                warn!("STUN parse error from {} (leg-B): {}", source, e);
                                            }
                                        }
                                        // Learn callee endpoint from STUN
                                        {
                                            let mut ep = endpoint_b.lock().await;
                                            if ep.is_none() {
                                                info!("RTP: learned callee (B) via STUN = {} on leg-B:{}", source, ports_b_rtp);
                                                *ep = Some(source);
                                            }
                                        }
                                        continue;
                                    }
                                    MultiplexedPacketType::Dtls => {
                                        // Route to DTLS handshake task for leg-B
                                        if let Some(ref tx) = dtls_packet_tx_b {
                                            if let Err(e) = tx.send((data_slice_b.to_vec(), source)) {
                                                warn!("DTLS packet channel send error (leg-B): {}", e);
                                            } else {
                                                debug!("DTLS packet ({} bytes) from {} routed to leg-B handshake task", len, source);
                                            }
                                        } else {
                                            warn!("DTLS packet from {} on leg-B but no handshake task attached", source);
                                        }
                                        // Learn callee endpoint from DTLS too
                                        {
                                            let mut ep = endpoint_b.lock().await;
                                            if ep.is_none() {
                                                info!("RTP: learned callee (B) via DTLS = {} on leg-B:{}", source, ports_b_rtp);
                                                *ep = Some(source);
                                            }
                                        }
                                        continue;
                                    }
                                    MultiplexedPacketType::Rtp => {
                                        // Fall through to normal RTP processing below
                                    }
                                    MultiplexedPacketType::Rtcp => {
                                        debug!("RTCP packet on rtcp-mux port from {} ({} bytes) on leg-B, ignoring", source, len);
                                        continue;
                                    }
                                    MultiplexedPacketType::Unknown => {
                                        debug!("Unknown packet type ({} bytes) from {} on leg-B, first byte: {:02x}",
                                            len, source, data_slice_b.first().unwrap_or(&0));
                                        continue;
                                    }
                                }
                            }

                            pkt_count += 1;
                            let mut data = data_slice_b.to_vec();

                            // Log first few packets at INFO level for debugging
                            if pkt_count <= 5 {
                                info!("RTP B recv #{}: {} bytes from {} on leg-B:{}", pkt_count, len, source, ports_b_rtp);
                            }

                            // Learn / update callee's real address
                            {
                                let mut ep = endpoint_b.lock().await;
                                if ep.is_none() {
                                    info!("RTP: learned callee (B) = {} on leg-B:{}", source, ports_b_rtp);
                                    *ep = Some(source);
                                } else if *ep != Some(source) {
                                    info!("RTP: callee addr updated {} → {}", ep.unwrap(), source);
                                    *ep = Some(source);
                                }
                            }

                            // ── SRTP decrypt from callee (leg B) ────────────────
                            // When callee is WebRTC (DTLS-SRTP), use the hot-swappable srtp_recv_b.
                            // Otherwise fall back to srtp_ctx_b (SDES-SRTP).
                            if webrtc_mode_b {
                                let mut guard = srtp_recv_b.lock().await;
                                let has_ctx = guard.is_some();
                                let ba_pkt = stats.packets_b_to_a.load(Ordering::Relaxed);
                                if ba_pkt < 5 {
                                    info!("SRTP decrypt B: webrtc_mode_b=true, srtp_recv_b={}, pkt_b_to_a={}",
                                        if has_ctx { "Some" } else { "None" }, ba_pkt);
                                }
                                if let Some(ref mut ctx) = *guard {
                                    match ctx.decrypt_srtp(&data) {
                                        Ok(plaintext) => {
                                            if ba_pkt < 5 {
                                                let pt_dec = if plaintext.len() >= 2 { plaintext[1] & 0x7F } else { 0 };
                                                info!("SRTP decrypt B #{}: {} → {} bytes (PT={})",
                                                    ba_pkt + 1, data.len(), plaintext.len(), pt_dec);
                                            }
                                            data = plaintext;
                                            if let Some(ref c) = global_srtp_decrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP B (DTLS) decrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                } else {
                                    // WebRTC mode B: DTLS handshake not yet complete → no SRTP keys.
                                    // DROP the packet — browser sends SRTP which we can't decrypt.
                                    // Relaying encrypted SRTP to the trunk would produce garbled audio.
                                    debug!("RTP B→A: dropping packet (WebRTC mode B, DTLS/SRTP not yet ready)");
                                    continue;
                                }
                            } else {
                                let mut guard = srtp_ctx_b.lock().await;
                                if let Some(ref mut ctx) = *guard {
                                    match ctx.decrypt_srtp(&data) {
                                        Ok(plaintext) => {
                                            debug!("SRTP B: decrypted {} → {} bytes", data.len(), plaintext.len());
                                            data = plaintext;
                                            if let Some(ref c) = global_srtp_decrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP B decrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                }
                            } // end SRTP decrypt B (webrtc_mode_b / SDES)

                            // ── Transcode B→A (callee codec → caller codec) ─────
                            if let Some(ref tc) = transcoder_b_to_a {
                                if data.len() >= 12 {
                                    let actual_pt_b = data[1] & 0x7F;

                                    // ── PT filtering (Phase 16: DTMF relay) ──
                                    // DTMF telephone-event (PT 96-127) and CN (PT 13) bypass transcoding
                                    let expected_pt_b = tc.src.pt();
                                    let is_dtmf_or_cn_b = actual_pt_b >= 96 || actual_pt_b == 13;
                                    if actual_pt_b != expected_pt_b && !is_dtmf_or_cn_b {
                                        debug!("RTP B→A: skip unknown PT {} (expected {}), {} bytes",
                                            actual_pt_b, expected_pt_b, data.len());
                                        continue;
                                    }
                                    if is_dtmf_or_cn_b {
                                        debug!("RTP B→A: relaying DTMF/CN PT {} as-is ({} bytes)", actual_pt_b, data.len());
                                    } else {

                                    let header_len = rtp_header_length(&data);
                                    if header_len > 0 && data.len() > header_len {
                                        let payload_len = data.len() - header_len;
                                        // Validate G.711 frame size: must be 160 bytes (20ms)
                                        // Non-standard frames (e.g. 200 bytes = 25ms) cause Opus
                                        // encode failure and would pass through as raw G.711 → noise
                                        if (tc.src == crate::transcoding::Codec::Pcma || tc.src == crate::transcoding::Codec::Pcmu)
                                            && payload_len != 160 {
                                            debug!("Transcode B→A: skip non-standard G.711 frame ({} bytes, expected 160)", payload_len);
                                            continue;
                                        }
                                        let payload_vec = data[header_len..].to_vec();
                                        match tc.transcode(&payload_vec) {
                                            Ok(transcoded) => {
                                                // Rebuild RTP with 12-byte header (strip any extensions)
                                                let mut new_pkt = Vec::with_capacity(12 + transcoded.len());
                                                new_pkt.extend_from_slice(&data[..12]);
                                                // Clear extension bit and CSRC count for clean output
                                                new_pkt[0] = 0x80; // V=2, P=0, X=0, CC=0
                                                new_pkt[1] = (data[1] & 0x80) | tc.dst.pt();
                                                new_pkt.extend_from_slice(&transcoded);

                                                // ── RTP timestamp rewrite for clock rate conversion ──
                                                // PCMA/PCMU runs at 8kHz, Opus at 48kHz → multiply by 6
                                                if new_pkt.len() >= 8 {
                                                    let src_rate = tc.src.clock_rate();
                                                    let dst_rate = tc.dst.clock_rate();
                                                    if src_rate != dst_rate && dst_rate > 0 {
                                                        let old_ts = u32::from_be_bytes([new_pkt[4], new_pkt[5], new_pkt[6], new_pkt[7]]);
                                                        let new_ts = ((old_ts as u64) * dst_rate as u64 / src_rate as u64) as u32;
                                                        new_pkt[4..8].copy_from_slice(&new_ts.to_be_bytes());
                                                    }
                                                }

                                                debug!("Transcode B→A: {} → {} bytes (hdr={}, PT {}→{})",
                                                    payload_len, transcoded.len(), header_len,
                                                    tc.src.pt(), tc.dst.pt());
                                                data = new_pkt;
                                                if let Some(ref c) = global_transcode_counter {
                                                    c.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Transcode B→A error: {} (dropping packet)", e);
                                                continue;
                                            }
                                        }
                                    }
                                    } // end else (transcode media PT)
                                }
                            }

                            // ── SRTP encrypt toward caller (leg A) ──────────────
                            {
                                let mut guard = srtp_send_a.lock().await;
                                let has_send_ctx = guard.is_some();
                                let ba_enc_chk = stats.packets_b_to_a.load(Ordering::Relaxed);
                                if ba_enc_chk < 5 {
                                    info!("SRTP encrypt B→A check: srtp_send_a={}, webrtc_mode_a={}, data_len={}",
                                        if has_send_ctx { "Some" } else { "None" }, webrtc_mode_a, data.len());
                                }
                                if let Some(ref mut ctx) = *guard {
                                    let pt_before = if data.len() >= 2 { data[1] & 0x7F } else { 0 };
                                    match ctx.encrypt_rtp(&data) {
                                        Ok(encrypted) => {
                                            let ba_enc = stats.packets_b_to_a.load(Ordering::Relaxed);
                                            if ba_enc < 5 {
                                                info!("SRTP encrypt B→A #{}: {} → {} bytes (PT={})",
                                                    ba_enc + 1, data.len(), encrypted.len(), pt_before);
                                            }
                                            data = encrypted;
                                            if let Some(ref c) = global_srtp_encrypt_counter {
                                                c.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("SRTP A encrypt error: {} (dropping packet)", e);
                                            continue;
                                        }
                                    }
                                } else if webrtc_mode_a {
                                    // WebRTC mode: DTLS handshake not yet complete → no SRTP keys.
                                    // DROP the packet — sending plain RTP to a WebRTC browser
                                    // causes garbled audio (browser expects SRTP).
                                    debug!("RTP B→A: dropping packet (WebRTC mode, DTLS/SRTP not yet ready)");
                                    continue;
                                }
                            }

                            // Relay to caller via leg-A socket
                            let dest = *endpoint_a.lock().await;
                            if let Some(dst) = dest {
                                let out_len = data.len();
                                let ba_count = stats.packets_b_to_a.load(Ordering::Relaxed);
                                if ba_count < 3 {
                                    info!("RTP B→A #{}: {} → {} ({} bytes)", ba_count+1, source, dst, out_len);
                                }
                                if let Err(e) = rtp_socket_a.send_to(&data, dst).await {
                                    warn!("RTP B→A send error: {}", e);
                                } else {
                                    stats.packets_b_to_a.fetch_add(1, Ordering::Relaxed);
                                        stats.last_activity_secs.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), Ordering::Relaxed);
                                    stats.bytes_b_to_a.fetch_add(out_len as u64, Ordering::Relaxed);
                                    if let Some(ref c) = global_rtp_counter {
                                        c.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            } else {
                                info!("RTP B: caller endpoint not yet known, packet from {} dropped", source);
                            }
                        } else if let Err(e) = result {
                            error!("RTP leg-B recv error: {}", e);
                        }
                    }

                    // ── RTCP Leg A ─────────────────────────────────────────────
                    result = rtcp_socket_a.recv_from(&mut buf_rtcp_a) => {
                        if let Ok((len, _source)) = result {
                            let data = buf_rtcp_a[..len].to_vec();
                            let dest = *endpoint_b.lock().await;
                            if let Some(dst) = dest {
                                // Send RTCP to callee's RTCP port (RTP port + 1 by convention)
                                let rtcp_dst = SocketAddr::new(dst.ip(), dst.port() + 1);
                                let _ = rtcp_socket_b.send_to(&data, rtcp_dst).await;
                            }
                        }
                    }

                    // ── RTCP Leg B ─────────────────────────────────────────────
                    result = rtcp_socket_b.recv_from(&mut buf_rtcp_b) => {
                        if let Ok((len, _source)) = result {
                            let data = buf_rtcp_b[..len].to_vec();
                            let dest = *endpoint_a.lock().await;
                            if let Some(dst) = dest {
                                let rtcp_dst = SocketAddr::new(dst.ip(), dst.port() + 1);
                                let _ = rtcp_socket_a.send_to(&data, rtcp_dst).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Take the shutdown sender out of this session (for storage elsewhere to keep task alive)
    pub fn take_shutdown_tx(&mut self) -> Option<mpsc::Sender<()>> {
        self.shutdown_tx.take()
    }

    /// Stop the RTP session
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Get session statistics
    pub fn stats(&self) -> RtpSessionStats {
        RtpSessionStats {
            packets_a_to_b: self.stats.packets_a_to_b.load(Ordering::Relaxed),
            packets_b_to_a: self.stats.packets_b_to_a.load(Ordering::Relaxed),
            bytes_a_to_b: self.stats.bytes_a_to_b.load(Ordering::Relaxed),
            bytes_b_to_a: self.stats.bytes_b_to_a.load(Ordering::Relaxed),
            packets_lost: self.stats.packets_lost.load(Ordering::Relaxed),
        }
    }
}

impl RtpStats {
    fn new() -> Self {
        Self {
            packets_a_to_b: AtomicU64::new(0),
            packets_b_to_a: AtomicU64::new(0),
            bytes_a_to_b: AtomicU64::new(0),
            bytes_b_to_a: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            last_activity_secs: AtomicU64::new(0),
        }
    }
}

/// Snapshot of RTP session statistics
#[derive(Debug, Clone, Copy)]
pub struct RtpSessionStats {
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_lost: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_packet_parse() {
        // Sample RTP packet: version=2, padding=0, extension=0, csrc_count=0,
        // marker=0, payload_type=0 (PCMU), seq=12345, timestamp=67890, ssrc=0xDEADBEEF
        let data = vec![
            0x80, 0x00, // V=2, P=0, X=0, CC=0, M=0, PT=0
            0x30, 0x39, // Seq = 12345
            0x00, 0x01, 0x09, 0x32, // Timestamp = 67890
            0xDE, 0xAD, 0xBE, 0xEF, // SSRC = 0xDEADBEEF
            0x01, 0x02, 0x03, 0x04, // Payload
        ];

        let packet = RtpPacket::parse(&data).unwrap();

        assert_eq!(packet.version, 2);
        assert_eq!(packet.padding, false);
        assert_eq!(packet.extension, false);
        assert_eq!(packet.csrc_count, 0);
        assert_eq!(packet.marker, false);
        assert_eq!(packet.payload_type, 0);
        assert_eq!(packet.sequence_number, 12345);
        assert_eq!(packet.timestamp, 67890);
        assert_eq!(packet.ssrc, 0xDEADBEEF);
        assert_eq!(packet.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_rtp_packet_serialize() {
        let packet = RtpPacket {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 8,
            sequence_number: 100,
            timestamp: 1000,
            ssrc: 0x12345678,
            payload: vec![0xAA, 0xBB, 0xCC],
        };

        let bytes = packet.to_bytes();

        assert_eq!(bytes[0], 0x80); // Version 2, no flags
        assert_eq!(bytes[1], 0x08); // PT=8
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 100);
        assert_eq!(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 1000);
        assert_eq!(
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0x12345678
        );
        assert_eq!(&bytes[12..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_rtp_packet_round_trip() {
        let original = RtpPacket {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: true,
            payload_type: 97,
            sequence_number: 54321,
            timestamp: 987654,
            ssrc: 0xABCDEF00,
            payload: vec![1, 2, 3, 4, 5],
        };

        let bytes = original.to_bytes();
        let parsed = RtpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.marker, original.marker);
        assert_eq!(parsed.payload_type, original.payload_type);
        assert_eq!(parsed.sequence_number, original.sequence_number);
        assert_eq!(parsed.timestamp, original.timestamp);
        assert_eq!(parsed.ssrc, original.ssrc);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_rtp_packet_too_short() {
        let data = vec![0x80, 0x00]; // Only 2 bytes
        let result = RtpPacket::parse(&data);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rtp_session_creation() {
        let ports_a = PortPair::new(10000).unwrap();
        let ports_b = PortPair::new(10002).unwrap();
        let session = RtpSession::new_two_leg("test-session".to_string(), ports_a, ports_b).await;

        assert!(session.is_ok(), "RtpSession creation failed: {:?}", session.err());
        let session = session.unwrap();
        assert_eq!(session.session_id, "test-session");
        assert_eq!(session.local_ports, ports_a);
    }

    #[tokio::test]
    async fn test_rtp_session_endpoints() {
        let ports_a = PortPair::new(10004).unwrap();
        let ports_b = PortPair::new(10006).unwrap();
        let mut session = RtpSession::new_two_leg("test-endpoints".to_string(), ports_a, ports_b)
            .await
            .unwrap();

        let addr_a: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let addr_b: SocketAddr = "192.168.1.2:6000".parse().unwrap();

        session.set_endpoint_a(addr_a);
        session.set_endpoint_b(addr_b);

        assert_eq!(session.endpoint_a, Some(addr_a));
        assert_eq!(session.endpoint_b, Some(addr_b));
    }

    #[tokio::test]
    async fn test_rtp_session_stats() {
        let ports_a = PortPair::new(10008).unwrap();
        let ports_b = PortPair::new(10010).unwrap();
        let session = RtpSession::new_two_leg("test-stats".to_string(), ports_a, ports_b)
            .await
            .unwrap();

        let stats = session.stats();
        assert_eq!(stats.packets_a_to_b, 0);
        assert_eq!(stats.packets_b_to_a, 0);
        assert_eq!(stats.bytes_a_to_b, 0);
        assert_eq!(stats.bytes_b_to_a, 0);
    }

    #[tokio::test]
    async fn test_rtp_two_leg_session() {
        let ports_a = PortPair::new(10020).unwrap();
        let ports_b = PortPair::new(10022).unwrap();
        let session = RtpSession::new_two_leg("two-leg".to_string(), ports_a, ports_b).await;
        assert!(session.is_ok(), "RtpSession two-leg creation failed: {:?}", session.err());
        let s = session.unwrap();
        assert_eq!(s.ports_a.rtp, 10020);
        assert_eq!(s.ports_b.rtp, 10022);
    }
}
