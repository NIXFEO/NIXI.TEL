//! Media Manager - Manages RTP sessions and port allocation
//!
//! Central management for all media sessions

use crate::media::{PortAllocator, PortPair, RtpSession, SessionDescription};
use crate::media::srtp::{SrtpContext, CryptoSuite, parse_crypto_attribute};
use crate::media::webrtc_handler::WebRtcSdpInfo;
use crate::transcoding::{Codec, Transcoder, sdp_primary_codec, needs_transcoding};
use crate::{Error, Result};
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, info, warn};

/// Information returned when starting an RTP session with WebRTC mode enabled.
/// Contains the DTLS packet channel, RTP socket, and shared SRTP Arcs for hot-swap.
pub struct WebRtcRtpInfo {
    /// Receiver for DTLS packets demuxed from the RTP socket (leg-A).
    pub dtls_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    /// The leg-A RTP socket (shared with the DTLS bridge for sending responses).
    pub rtp_socket_a: Arc<UdpSocket>,
    /// The local address of the RTP socket (for DtlsUdpBridge).
    pub local_addr: SocketAddr,
    /// Shared SRTP recv context for leg-A (decrypt browser→SBC): DTLS task writes here.
    pub srtp_recv_ctx_a: Arc<AsyncMutex<Option<SrtpContext>>>,
    /// Shared SRTP send context for leg-A (encrypt SBC→browser): DTLS task writes here.
    pub srtp_send_ctx_a: Arc<AsyncMutex<Option<SrtpContext>>>,
}

/// Information returned when starting an RTP session with WebRTC mode on leg-B (callee).
pub struct WebRtcRtpInfoB {
    /// Receiver for DTLS packets demuxed from the RTP socket (leg-B).
    pub dtls_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    /// The leg-B RTP socket (shared with the DTLS bridge for sending responses).
    pub rtp_socket_b: Arc<UdpSocket>,
    /// The local address of the leg-B RTP socket.
    pub local_addr: SocketAddr,
    /// Shared SRTP recv context for leg-B (decrypt callee→SBC): DTLS task writes here.
    pub srtp_recv_ctx_b: Arc<AsyncMutex<Option<SrtpContext>>>,
    /// Shared SRTP send context for leg-B (encrypt SBC→callee): DTLS task writes here.
    pub srtp_send_ctx_b: Arc<AsyncMutex<Option<SrtpContext>>>,
}

/// Media Manager
pub struct MediaManager {
    /// Port allocator for RTP/RTCP
    port_allocator: Arc<PortAllocator>,

    /// Active RTP sessions (keyed by dialog/session ID)
    sessions: Arc<DashMap<String, MediaSession>>,

    /// Public IP for SDP rewriting
    public_ip: Option<IpAddr>,

    /// Global RTP packet counter (from SbcMetrics) for Prometheus reporting
    global_rtp_counter: Option<Arc<std::sync::atomic::AtomicU64>>,

    /// Global SRTP encrypted counter (from SbcMetrics)
    global_srtp_encrypt_counter: Option<Arc<std::sync::atomic::AtomicU64>>,

    /// Global SRTP decrypted counter (from SbcMetrics)
    global_srtp_decrypt_counter: Option<Arc<std::sync::atomic::AtomicU64>>,

    /// Global transcoded packet counter (from SbcMetrics)
    global_transcode_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// Media session information
#[derive(Debug, Clone)]
pub struct MediaSession {
    /// Dialog/Session ID
    pub session_id: String,

    /// Leg-A ports (caller side): caller sends RTP here, SBC relays to callee.
    /// The 200 OK SDP sent to the caller contains `ports.rtp`.
    pub ports: PortPair,

    /// Leg-B ports (callee side): callee sends RTP here, SBC relays to caller.
    /// The INVITE SDP sent to the callee contains `ports_b.rtp`.
    pub ports_b: Option<PortPair>,

    /// Endpoint A address (caller's real RTP address, from SDP or learned)
    pub endpoint_a: Option<SocketAddr>,

    /// Endpoint B address (callee's real RTP address, from SDP or learned)
    pub endpoint_b: Option<SocketAddr>,

    /// Original SDP from caller
    pub sdp_caller: Option<String>,

    /// Original SDP from callee
    pub sdp_callee: Option<String>,

    /// RTP relay task shutdown sender — kept alive to prevent premature task termination
    pub rtp_shutdown_tx: Option<mpsc::Sender<()>>,

    /// SRTP crypto suite for leg A (caller) — parsed from SDP a=crypto:
    pub srtp_suite_a: Option<CryptoSuite>,

    /// SRTP key params for leg A (from SDP a=crypto: inline:...)
    pub srtp_key_params_a: Option<String>,

    /// SRTP crypto suite for leg B (callee)
    pub srtp_suite_b: Option<CryptoSuite>,

    /// SRTP key params for leg B
    pub srtp_key_params_b: Option<String>,

    /// Local ICE password (SBC's ice-pwd for STUN MESSAGE-INTEGRITY).
    /// Set when the caller is a WebRTC endpoint.
    pub ice_pwd_local: Option<String>,

    /// Local ICE password for leg-B (SBC's ice-pwd for STUN MESSAGE-INTEGRITY on callee port).
    /// Set when the callee is a WebRTC endpoint (PSTN→WebRTC).
    pub ice_pwd_local_b: Option<String>,
}

/// Statistics for media manager
#[derive(Debug, Clone, Copy)]
pub struct MediaStats {
    pub active_sessions: usize,
    pub allocated_ports: usize,
    pub available_ports: usize,
}

impl MediaManager {
    /// Create a new media manager
    pub fn new(public_ip: Option<IpAddr>) -> Self {
        Self {
            port_allocator: Arc::new(PortAllocator::new()),
            sessions: Arc::new(DashMap::new()),
            public_ip,
            global_rtp_counter: None,
            global_srtp_encrypt_counter: None,
            global_srtp_decrypt_counter: None,
            global_transcode_counter: None,
        }
    }

    /// Create a new media manager with custom port range
    pub fn with_port_range(
        port_range: std::ops::Range<u16>,
        public_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            port_allocator: Arc::new(PortAllocator::with_range(port_range)),
            sessions: Arc::new(DashMap::new()),
            public_ip,
            global_rtp_counter: None,
            global_srtp_encrypt_counter: None,
            global_srtp_decrypt_counter: None,
            global_transcode_counter: None,
        }
    }

    /// Attach global RTP packet counter from SbcMetrics for Prometheus reporting
    pub fn set_global_rtp_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.global_rtp_counter = Some(counter);
    }

    /// Attach global SRTP encrypted counter from SbcMetrics
    pub fn set_global_srtp_encrypt_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.global_srtp_encrypt_counter = Some(counter);
    }

    /// Attach global SRTP decrypted counter from SbcMetrics
    pub fn set_global_srtp_decrypt_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.global_srtp_decrypt_counter = Some(counter);
    }

    /// Attach global transcoded packet counter from SbcMetrics
    pub fn set_global_transcode_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.global_transcode_counter = Some(counter);
    }

    /// Extract SRTP crypto parameters from SDP and store in MediaSession
    pub fn extract_srtp_from_sdp(&self, session_id: &str, sdp: &str, is_leg_a: bool) -> Result<()> {
        // Look for a=crypto: lines in SDP
        for line in sdp.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("a=crypto:") {
                let crypto_part = &trimmed["a=crypto:".len()..];
                if let Ok((_tag, suite, key_params)) = parse_crypto_attribute(crypto_part) {
                    info!(
                        "Session {} SRTP: parsed {} from SDP (leg {})",
                        session_id,
                        suite.to_sdp_name(),
                        if is_leg_a { "A" } else { "B" }
                    );
                    if let Some(mut entry) = self.sessions.get_mut(session_id) {
                        if is_leg_a {
                            entry.srtp_suite_a = Some(suite);
                            entry.srtp_key_params_a = Some(key_params);
                        } else {
                            entry.srtp_suite_b = Some(suite);
                            entry.srtp_key_params_b = Some(key_params);
                        }
                    }
                    return Ok(());
                }
            }
        }
        // No crypto line found — plain RTP
        debug!("Session {} no a=crypto: found in SDP (leg {})", session_id, if is_leg_a { "A" } else { "B" });
        Ok(())
    }

    /// Create a new media session (two-leg proxy: allocates two port pairs)
    ///
    /// - `ports`   (leg A): used in the INVITE SDP forwarded to the callee
    /// - `ports_b` (leg B): used in the 200 OK SDP forwarded to the caller
    pub async fn create_session(
        &self,
        session_id: String,
        sdp: Option<&str>,
    ) -> Result<MediaSession> {
        // Allocate leg-A ports (appears in INVITE forwarded to callee)
        let ports = self.port_allocator.allocate()?;

        // Allocate leg-B ports (appears in 200 OK forwarded to caller)
        let ports_b = match self.port_allocator.allocate() {
            Ok(p) => Some(p),
            Err(_) => {
                // If we can't get a second pair, fall back to single-leg mode
                None
            }
        };

        if let Some(pb) = ports_b {
            info!(
                "Created media session {} on A={}/{} B={}/{}",
                session_id, ports.rtp, ports.rtcp, pb.rtp, pb.rtcp
            );
        } else {
            info!(
                "Created media session {} on ports {}/{} (single-leg fallback)",
                session_id, ports.rtp, ports.rtcp
            );
        }

        // Parse and modify SDP if provided (rewrite to leg-A port)
        let modified_sdp = if let Some(sdp_str) = sdp {
            Some(self.modify_sdp(sdp_str, ports.rtp)?)
        } else {
            None
        };

        let media_session = MediaSession {
            session_id: session_id.clone(),
            ports,
            ports_b,
            endpoint_a: None,
            endpoint_b: None,
            sdp_caller: modified_sdp,
            sdp_callee: None,
            rtp_shutdown_tx: None,
            srtp_suite_a: None,
            srtp_key_params_a: None,
            srtp_suite_b: None,
            srtp_key_params_b: None,
            ice_pwd_local: None,
            ice_pwd_local_b: None,
        };

        self.sessions.insert(session_id, media_session.clone());

        Ok(media_session)
    }

    /// Update SDP for callee side
    pub fn update_callee_sdp(&self, session_id: &str, sdp: &str) -> Result<String> {
        let modified_sdp = if let Some(mut entry) = self.sessions.get_mut(session_id) {
            let ports = entry.ports;
            let modified = self.modify_sdp(sdp, ports.rtp)?;
            entry.sdp_callee = Some(modified.clone());
            modified
        } else {
            return Err(Error::Dialog(format!(
                "Media session not found: {}",
                session_id
            )));
        };

        Ok(modified_sdp)
    }

    /// Store the callee's raw (original) SDP in the media session.
    /// This is needed for codec analysis / automatic transcoder setup.
    pub fn set_callee_sdp(&self, session_id: &str, sdp: &str) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.sdp_callee = Some(sdp.to_string());
            debug!("Stored callee SDP for session {} ({} bytes)", session_id, sdp.len());
        }
    }

    /// Set the local ICE password for a WebRTC media session (used for STUN MESSAGE-INTEGRITY).
    pub fn set_ice_pwd_local(&self, session_id: &str, pwd: String) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            info!("Set ICE pwd local for session {} (len={})", session_id, pwd.len());
            entry.ice_pwd_local = Some(pwd);
        }
    }

    /// Set local ICE password for leg-B (callee is WebRTC)
    pub fn set_ice_pwd_local_b(&self, session_id: &str, pwd: String) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            info!("Set ICE pwd local B for session {} (len={})", session_id, pwd.len());
            entry.ice_pwd_local_b = Some(pwd);
        }
    }

    /// Rewrite SDP for NAT traversal: replace private IP with public IP.
    /// Used when forwarding INVITE/200 OK between legs behind NAT.
    /// Does NOT change the port (preserves original SDP port for pass-through mode).
    pub fn rewrite_sdp_ip(&self, sdp_str: &str) -> String {
        if let Some(ip) = self.public_ip {
            if let Ok(mut sdp) = SessionDescription::parse(sdp_str) {
                sdp.replace_ip(ip);
                return sdp.to_string();
            }
        }
        sdp_str.to_string()
    }

    /// Rewrite SDP for RTP proxy: replace IP with public IP and audio port with SBC proxy port.
    /// Also rewrites `a=rtcp:` attribute to match the proxy RTCP port (rtp_port + 1).
    /// Used when the SBC is proxying/relaying RTP media.
    pub fn rewrite_sdp_for_proxy(&self, sdp_str: &str, rtp_port: u16) -> String {
        if let Ok(mut sdp) = SessionDescription::parse(sdp_str) {
            if let Some(ip) = self.public_ip {
                sdp.replace_ip(ip);
            }
            sdp.replace_port(crate::media::MediaType::Audio, rtp_port);
            let result = sdp.to_string();

            // Rewrite a=rtcp:<port> to match the proxy RTCP port.
            // This is critical: if a=rtcp points to the original client port,
            // the peer sends RTCP to the wrong destination.
            let rtcp_port = rtp_port + 1;
            let result = rewrite_rtcp_attr(&result, rtcp_port);

            return result;
        }
        sdp_str.to_string()
    }

    /// Modify SDP (replace IP and port)
    fn modify_sdp(&self, sdp_str: &str, rtp_port: u16) -> Result<String> {
        let mut sdp = SessionDescription::parse(sdp_str)?;

        // Replace IP if configured
        if let Some(ip) = self.public_ip {
            sdp.replace_ip(ip);
        }

        // Replace audio port
        sdp.replace_port(crate::media::MediaType::Audio, rtp_port);

        // Replace video port if present (RTP + 2 for separate stream)
        if sdp.media.iter().any(|m| m.media_type == crate::media::MediaType::Video) {
            sdp.replace_port(crate::media::MediaType::Video, rtp_port + 2);
        }

        Ok(sdp.to_string())
    }

    /// Start RTP session for media relay (two-leg symmetric proxy)
    ///
    /// The running relay task's shutdown_tx is stored in the MediaSession
    /// so it stays alive for the duration of the call.
    ///
    /// If the caller's SDP is WebRTC (Opus/SAVPF), WebRTC mode is automatically
    /// enabled on leg-A (STUN/DTLS/RTP demuxing). Returns `WebRtcRtpInfo` with
    /// the DTLS channel and socket needed for the DTLS handshake task.
    pub async fn start_rtp_session(&self, session_id: &str) -> Result<(Option<WebRtcRtpInfo>, Option<WebRtcRtpInfoB>)> {
        let (ports_a, ports_b, ep_a, ep_b, srtp_suite_a, srtp_kp_a, srtp_suite_b, srtp_kp_b,
             sdp_caller_opt, sdp_callee_opt) = {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| Error::Dialog(format!("Media session not found: {}", session_id)))?;
            let pa = session.ports;
            let pb = session.ports_b.unwrap_or(pa); // fallback: same port for both legs
            (
                pa, pb, session.endpoint_a, session.endpoint_b,
                session.srtp_suite_a, session.srtp_key_params_a.clone(),
                session.srtp_suite_b, session.srtp_key_params_b.clone(),
                session.sdp_caller.clone(), session.sdp_callee.clone(),
            )
        };

        // Create two-leg RTP proxy session (binds sockets)
        let mut rtp_session = RtpSession::new_two_leg(
            session_id.to_string(),
            ports_a,
            ports_b,
        ).await?;

        // Pre-configure endpoints from SDP (relay task also does dynamic learning)
        if let Some(addr_a) = ep_a {
            rtp_session.set_endpoint_a(addr_a);
        }
        if let Some(addr_b) = ep_b {
            rtp_session.set_endpoint_b(addr_b);
        }

        // Attach global RTP packet counter for Prometheus metrics
        if let Some(ref counter) = self.global_rtp_counter {
            rtp_session.set_global_rtp_counter(counter.clone());
        }

        // Attach global SRTP counters for Prometheus metrics
        if let Some(ref counter) = self.global_srtp_encrypt_counter {
            rtp_session.set_global_srtp_encrypt_counter(counter.clone());
        }
        if let Some(ref counter) = self.global_srtp_decrypt_counter {
            rtp_session.set_global_srtp_decrypt_counter(counter.clone());
        }

        // Attach global transcoded packet counter for Prometheus metrics
        if let Some(ref counter) = self.global_transcode_counter {
            rtp_session.set_global_transcode_counter(counter.clone());
        }

        // ── Setup SRTP contexts from SDP crypto parameters ───────────────────
        if let (Some(suite), Some(ref kp)) = (srtp_suite_a, &srtp_kp_a) {
            match SrtpContext::from_key_params(kp, suite) {
                Ok(ctx) => {
                    info!("Session {} SRTP leg-A: {} active", session_id, suite.to_sdp_name());
                    rtp_session.set_srtp_context_a(ctx);
                }
                Err(e) => {
                    warn!("Session {} SRTP leg-A init failed: {} (falling back to plain RTP)", session_id, e);
                }
            }
        }

        if let (Some(suite), Some(ref kp)) = (srtp_suite_b, &srtp_kp_b) {
            match SrtpContext::from_key_params(kp, suite) {
                Ok(ctx) => {
                    info!("Session {} SRTP leg-B: {} active", session_id, suite.to_sdp_name());
                    rtp_session.set_srtp_context_b(ctx);
                }
                Err(e) => {
                    warn!("Session {} SRTP leg-B init failed: {} (falling back to plain RTP)", session_id, e);
                }
            }
        }

        // ── Setup transcoders from SDP codec analysis ────────────────────────
        // If caller and callee use different codecs, create transcoders for
        // the RTP relay to convert between them in real-time.
        //
        // IMPORTANT for WebRTC: Chrome's SDP offer includes G.711 (PT 0, 8) alongside
        // Opus (PT 111), so `needs_transcoding()` sees a "common" codec and returns false.
        // But WebRTC browsers ALWAYS use Opus as the primary codec. We must force
        // Opus↔PCMA transcoding when the caller is WebRTC and the callee uses G.711.
        if let (Some(ref caller_sdp), Some(ref callee_sdp)) = (&sdp_caller_opt, &sdp_callee_opt) {
            // Detect WebRTC on either side: SDP has UDP/TLS/RTP/SAVPF
            let caller_is_webrtc_sdp = caller_sdp.contains("UDP/TLS/RTP/SAVPF")
                || caller_sdp.contains("udp/tls/rtp/savpf");
            let callee_is_webrtc_sdp = callee_sdp.contains("UDP/TLS/RTP/SAVPF")
                || callee_sdp.contains("udp/tls/rtp/savpf");

            let do_transcode = if caller_is_webrtc_sdp {
                // For WebRTC callers: ALWAYS transcode Opus↔trunk_codec
                // even if the SDPs share payload types (Chrome includes G.711 in offer
                // but actually sends Opus).
                let callee_codec = sdp_primary_codec(callee_sdp);
                callee_codec != Codec::Opus // Only skip transcoding if callee also uses Opus
            } else if callee_is_webrtc_sdp {
                // For WebRTC callees (PSTN→WebRTC): same logic in reverse.
                // Chrome includes G.711 in its SDP answer alongside Opus,
                // so needs_transcoding() falsely returns false.
                // Force transcoding unless the caller also uses Opus.
                let caller_codec = sdp_primary_codec(caller_sdp);
                caller_codec != Codec::Opus
            } else {
                needs_transcoding(caller_sdp, callee_sdp)
            };

            if do_transcode {
                // For WebRTC: force Opus as the WebRTC side's codec
                let caller_codec = if caller_is_webrtc_sdp {
                    Codec::Opus
                } else {
                    sdp_primary_codec(caller_sdp)
                };
                let callee_codec = if callee_is_webrtc_sdp {
                    Codec::Opus
                } else {
                    sdp_primary_codec(callee_sdp)
                };

                let webrtc_label = if caller_is_webrtc_sdp {
                    " [caller WebRTC]"
                } else if callee_is_webrtc_sdp {
                    " [callee WebRTC]"
                } else {
                    ""
                };

                info!(
                    "Session {} transcoding required: caller={} ({}) → callee={} ({}){}",
                    session_id,
                    caller_codec.name(), caller_codec.pt(),
                    callee_codec.name(), callee_codec.pt(),
                    webrtc_label
                );

                // A→B: caller sends in caller_codec, callee expects callee_codec
                match Transcoder::new(caller_codec, callee_codec) {
                    Ok(tc) => {
                        info!("Session {} transcoder A→B: {} → {}", session_id, caller_codec.name(), callee_codec.name());
                        rtp_session.set_transcoder_a_to_b(Arc::new(tc));
                    }
                    Err(e) => warn!("Session {} failed to create A→B transcoder: {}", session_id, e),
                }

                // B→A: callee sends in callee_codec, caller expects caller_codec
                match Transcoder::new(callee_codec, caller_codec) {
                    Ok(tc) => {
                        info!("Session {} transcoder B→A: {} → {}", session_id, callee_codec.name(), caller_codec.name());
                        rtp_session.set_transcoder_b_to_a(Arc::new(tc));
                    }
                    Err(e) => warn!("Session {} failed to create B→A transcoder: {}", session_id, e),
                }
            } else {
                debug!("Session {} no transcoding needed (common codec found)", session_id);
            }
        }

        // ── Enable WebRTC mode on leg-A if caller SDP is WebRTC ──────────
        // Get local ICE password (set by sbc.rs when creating WebRTC session)
        let ice_pwd_local_opt = self.sessions.get(session_id)
            .and_then(|s| s.ice_pwd_local.clone());

        let webrtc_info = if let Some(ref caller_sdp) = sdp_caller_opt {
            let sdp_info = WebRtcSdpInfo::from_sdp(caller_sdp);
            if sdp_info.is_webrtc {
                info!("Session {} enabling WebRTC mode on leg-A (STUN/DTLS/RTP demux, ice_pwd={})",
                    session_id, if ice_pwd_local_opt.is_some() { "set" } else { "none" });
                let dtls_rx = rtp_session.enable_webrtc_mode_a(ice_pwd_local_opt);
                let rtp_socket_a = rtp_session.rtp_socket_a();
                let srtp_recv_ctx_a = rtp_session.srtp_recv_ctx_a_shared();
                let srtp_send_ctx_a = rtp_session.srtp_send_ctx_a_shared();
                let local_addr = SocketAddr::new(
                    "0.0.0.0".parse().unwrap(),
                    ports_a.rtp,
                );
                Some(WebRtcRtpInfo { dtls_rx, rtp_socket_a, local_addr, srtp_recv_ctx_a, srtp_send_ctx_a })
            } else {
                None
            }
        } else {
            None
        };

        // ── Enable WebRTC mode on leg-B if callee is WebRTC ──────────
        let ice_pwd_local_b_opt = self.sessions.get(session_id)
            .and_then(|s| s.ice_pwd_local_b.clone());

        let webrtc_info_b = if ice_pwd_local_b_opt.is_some() {
            // Callee is WebRTC: enable STUN/DTLS/RTP demux on leg-B
            info!("Session {} enabling WebRTC mode on leg-B (STUN/DTLS/RTP demux)",
                session_id);
            let dtls_rx = rtp_session.enable_webrtc_mode_b(ice_pwd_local_b_opt);
            let rtp_socket_b = rtp_session.rtp_socket_b();
            let srtp_recv_ctx_b = rtp_session.srtp_recv_ctx_b_shared();
            let srtp_send_ctx_b = rtp_session.srtp_send_ctx_b_shared();
            let local_addr = SocketAddr::new(
                "0.0.0.0".parse().unwrap(),
                ports_b.rtp,
            );
            Some(WebRtcRtpInfoB { dtls_rx, rtp_socket_b, local_addr, srtp_recv_ctx_b, srtp_send_ctx_b })
        } else {
            None
        };

        // Start the relay task
        rtp_session.start().await?;

        // CRITICAL: extract the shutdown_tx and store it in the MediaSession.
        // Without this, RtpSession is dropped → shutdown_tx dropped → task terminates.
        let shutdown_tx = rtp_session.take_shutdown_tx();

        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.rtp_shutdown_tx = shutdown_tx;
        }

        info!(
            "Started two-leg RTP proxy for {} (leg-A:{} leg-B:{})",
            session_id, ports_a.rtp, ports_b.rtp
        );

        Ok((webrtc_info, webrtc_info_b))
    }

    /// Set endpoint A address
    pub fn set_endpoint_a(&self, session_id: &str, addr: SocketAddr) -> Result<()> {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.endpoint_a = Some(addr);
            debug!("Set endpoint A for {}: {}", session_id, addr);
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Media session not found: {}",
                session_id
            )))
        }
    }

    /// Set endpoint B address
    pub fn set_endpoint_b(&self, session_id: &str, addr: SocketAddr) -> Result<()> {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.endpoint_b = Some(addr);
            debug!("Set endpoint B for {}: {}", session_id, addr);
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Media session not found: {}",
                session_id
            )))
        }
    }

    /// Get media session
    pub fn get_session(&self, session_id: &str) -> Option<MediaSession> {
        self.sessions.get(session_id).map(|e| e.clone())
    }

    /// Terminate media session and release all allocated ports
    pub fn terminate_session(&self, session_id: &str) -> Result<()> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            // Stop RTP relay task (dropping shutdown_tx signals the relay task to exit)
            drop(session.rtp_shutdown_tx);

            // Release leg-A ports
            self.port_allocator.release(session.ports)?;
            // Release leg-B ports if allocated separately
            if let Some(pb) = session.ports_b {
                if pb.rtp != session.ports.rtp {
                    let _ = self.port_allocator.release(pb);
                }
            }
            info!("Terminated media session {}", session_id);
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Media session not found: {}",
                session_id
            )))
        }
    }

    /// Get statistics
    pub fn stats(&self) -> MediaStats {
        MediaStats {
            active_sessions: self.sessions.len(),
            allocated_ports: self.port_allocator.allocated_count(),
            available_ports: self.port_allocator.available_count(),
        }
    }

    /// Cleanup all sessions
    pub fn cleanup_all(&self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        self.port_allocator.clear().ok();
        count
    }
}

/// Rewrite `a=rtcp:<old_port>` lines to `a=rtcp:<new_port>` in an SDP string.
/// Only replaces the port number, preserves any trailing text (e.g. `a=rtcp:12345 IN IP4 ...`).
fn rewrite_rtcp_attr(sdp: &str, new_rtcp_port: u16) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("a=rtcp:") {
            // a=rtcp:<port>  or  a=rtcp:<port> IN IP4 ...
            let rest = &trimmed["a=rtcp:".len()..];
            // Find end of digits
            let digit_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if digit_end > 0 {
                let suffix = &rest[digit_end..];
                out.push_str(&format!("a=rtcp:{}{}", new_rtcp_port, suffix));
            } else {
                out.push_str(line);
            }
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    // Remove trailing extra \r\n if original didn't end with one
    if !sdp.ends_with("\r\n") && !sdp.ends_with('\n') {
        if out.ends_with("\r\n") {
            out.truncate(out.len() - 2);
        }
    }
    out
}

impl Default for MediaManager {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SDP: &str = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 192.168.1.100\r\n\
s=Call\r\n\
c=IN IP4 192.168.1.100\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";

    #[tokio::test]
    async fn test_media_manager_creation() {
        let manager = MediaManager::new(None);
        let stats = manager.stats();
        assert_eq!(stats.active_sessions, 0);
    }

    #[tokio::test]
    async fn test_create_session_without_sdp() {
        let manager = MediaManager::new(None);

        let session = manager
            .create_session("test-session".to_string(), None)
            .await
            .unwrap();

        assert_eq!(session.session_id, "test-session");
        assert!(session.ports.rtp % 2 == 0);
        assert_eq!(session.ports.rtcp, session.ports.rtp + 1);

        let stats = manager.stats();
        assert_eq!(stats.active_sessions, 1);
        // Two-leg mode: create_session allocates 2 port pairs (leg-A + leg-B)
        assert_eq!(stats.allocated_ports, 2);
    }

    #[tokio::test]
    async fn test_create_session_with_sdp() {
        let public_ip: IpAddr = "203.0.113.1".parse().unwrap();
        let manager = MediaManager::new(Some(public_ip));

        let session = manager
            .create_session("test-session-2".to_string(), Some(SAMPLE_SDP))
            .await
            .unwrap();

        assert!(session.sdp_caller.is_some());

        let modified_sdp = session.sdp_caller.unwrap();

        // Check IP was replaced
        assert!(modified_sdp.contains("203.0.113.1"));

        // Check port was replaced
        assert!(!modified_sdp.contains("49170"));
    }

    #[tokio::test]
    async fn test_set_endpoints() {
        let manager = MediaManager::new(None);

        let session = manager
            .create_session("test-endpoints".to_string(), None)
            .await
            .unwrap();

        let addr_a: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let addr_b: SocketAddr = "192.168.1.2:6000".parse().unwrap();

        manager
            .set_endpoint_a(&session.session_id, addr_a)
            .unwrap();
        manager
            .set_endpoint_b(&session.session_id, addr_b)
            .unwrap();

        let updated = manager.get_session(&session.session_id).unwrap();
        assert_eq!(updated.endpoint_a, Some(addr_a));
        assert_eq!(updated.endpoint_b, Some(addr_b));
    }

    #[tokio::test]
    async fn test_terminate_session() {
        let manager = MediaManager::new(None);

        let session = manager
            .create_session("test-terminate".to_string(), None)
            .await
            .unwrap();

        assert_eq!(manager.stats().active_sessions, 1);

        manager.terminate_session(&session.session_id).unwrap();

        assert_eq!(manager.stats().active_sessions, 0);
        assert!(manager.get_session(&session.session_id).is_none());
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let manager = MediaManager::new(None);

        let session1 = manager
            .create_session("session-1".to_string(), None)
            .await
            .unwrap();
        let session2 = manager
            .create_session("session-2".to_string(), None)
            .await
            .unwrap();
        let session3 = manager
            .create_session("session-3".to_string(), None)
            .await
            .unwrap();

        assert_eq!(manager.stats().active_sessions, 3);
        assert_ne!(session1.ports.rtp, session2.ports.rtp);
        assert_ne!(session2.ports.rtp, session3.ports.rtp);
    }

    #[tokio::test]
    async fn test_cleanup_all() {
        let manager = MediaManager::new(None);

        manager
            .create_session("session-a".to_string(), None)
            .await
            .unwrap();
        manager
            .create_session("session-b".to_string(), None)
            .await
            .unwrap();
        manager
            .create_session("session-c".to_string(), None)
            .await
            .unwrap();

        assert_eq!(manager.stats().active_sessions, 3);

        let cleaned = manager.cleanup_all();
        assert_eq!(cleaned, 3);
        assert_eq!(manager.stats().active_sessions, 0);
    }

    #[tokio::test]
    async fn test_update_callee_sdp() {
        let public_ip: IpAddr = "203.0.113.1".parse().unwrap();
        let manager = MediaManager::new(Some(public_ip));

        let session = manager
            .create_session("test-callee".to_string(), Some(SAMPLE_SDP))
            .await
            .unwrap();

        let callee_sdp = manager
            .update_callee_sdp(&session.session_id, SAMPLE_SDP)
            .unwrap();

        assert!(callee_sdp.contains("203.0.113.1"));

        let updated = manager.get_session(&session.session_id).unwrap();
        assert!(updated.sdp_callee.is_some());
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = MediaManager::with_port_range(10000..10010, None);

        manager
            .create_session("s1".to_string(), None)
            .await
            .unwrap();
        manager
            .create_session("s2".to_string(), None)
            .await
            .unwrap();

        let stats = manager.stats();
        assert_eq!(stats.active_sessions, 2);
        // Two-leg mode: each session allocates 2 port pairs → 4 total
        assert_eq!(stats.allocated_ports, 4);
        assert_eq!(stats.available_ports, 1); // 5 total pairs - 4 allocated
    }
}
