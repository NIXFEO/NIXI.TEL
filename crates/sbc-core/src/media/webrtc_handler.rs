//! WebRTC SDP Handler for the SBC
//!
//! Detects WebRTC offers/answers, extracts ICE candidates, DTLS fingerprints,
//! SRTP crypto attributes, and prepares the SBC media session accordingly.
//!
//! RFC 8829 - JavaScript Session Establishment Protocol (JSEP)
//! RFC 8445 - ICE
//! RFC 5764 - DTLS-SRTP
//! RFC 3711 - SRTP

use crate::{Error, Result};
use crate::media::ice::{IceAgent, IceCandidate, IceStats};
use crate::media::dtls::{CertificateFingerprint, DtlsRole, DtlsContext};
use crate::media::srtp::{CryptoSuite, SrtpContext, generate_key_material};

/// Information extracted from a WebRTC SDP offer/answer
#[derive(Debug, Clone)]
pub struct WebRtcSdpInfo {
    /// ICE username fragment from SDP (a=ice-ufrag)
    pub ice_ufrag: Option<String>,

    /// ICE password from SDP (a=ice-pwd)
    pub ice_pwd: Option<String>,

    /// ICE candidates parsed from SDP
    pub candidates: Vec<IceCandidate>,

    /// DTLS fingerprint (a=fingerprint)
    pub fingerprint: Option<CertificateFingerprint>,

    /// DTLS role (a=setup)
    pub dtls_role: Option<DtlsRole>,

    /// SRTP crypto attributes (a=crypto, SDES fallback)
    pub crypto_suites: Vec<CryptoSuite>,

    /// Whether this is a WebRTC session (uses SAVPF profile)
    pub is_webrtc: bool,

    /// Media port from m= line
    pub media_port: Option<u16>,

    /// Media stream identifier (a=mid:X) — required by Chrome for BUNDLE
    pub mid: Option<String>,
}

impl WebRtcSdpInfo {
    /// Parse WebRTC-relevant fields from raw SDP text
    pub fn from_sdp(sdp: &str) -> Self {
        let mut info = WebRtcSdpInfo {
            ice_ufrag: None,
            ice_pwd: None,
            candidates: Vec::new(),
            fingerprint: None,
            dtls_role: None,
            crypto_suites: Vec::new(),
            is_webrtc: false,
            media_port: None,
            mid: None,
        };

        for line in sdp.lines() {
            let line = line.trim();

            // Detect WebRTC by RTP/SAVPF profile
            if line.starts_with("m=") && (line.contains("RTP/SAVPF") || line.contains("UDP/TLS/RTP/SAVPF")) {
                info.is_webrtc = true;
                // Extract port from m= line: "m=audio PORT ..."
                let parts: Vec<&str> = line.splitn(4, ' ').collect();
                if parts.len() >= 2 {
                    info.media_port = parts[1].parse().ok();
                }
            }

            // Also detect DTLS via fingerprint attribute
            if line.starts_with("a=fingerprint:") {
                info.is_webrtc = true;
            }

            // a=ice-ufrag:XXXX
            if let Some(val) = line.strip_prefix("a=ice-ufrag:") {
                info.ice_ufrag = Some(val.trim().to_string());
            }

            // a=ice-pwd:XXXX
            if let Some(val) = line.strip_prefix("a=ice-pwd:") {
                info.ice_pwd = Some(val.trim().to_string());
            }

            // a=candidate:...
            if let Some(val) = line.strip_prefix("a=candidate:") {
                // Pass back the raw "candidate:" prefix so from_sdp can handle both formats
                let candidate_line = format!("candidate:{}", val);
                if let Ok(cand) = IceCandidate::from_sdp(&candidate_line) {
                    info.candidates.push(cand);
                }
            }

            // a=fingerprint:sha-256 XX:XX:...
            if let Some(val) = line.strip_prefix("a=fingerprint:") {
                if let Ok(fp) = CertificateFingerprint::from_sdp(val.trim()) {
                    info.fingerprint = Some(fp);
                }
            }

            // a=setup:actpass | active | passive
            if let Some(val) = line.strip_prefix("a=setup:") {
                info.dtls_role = DtlsRole::from_str(val.trim());
            }

            // a=mid:X (media stream ID for BUNDLE)
            if let Some(val) = line.strip_prefix("a=mid:") {
                info.mid = Some(val.trim().to_string());
            }

            // a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:...
            if let Some(val) = line.strip_prefix("a=crypto:") {
                let parts: Vec<&str> = val.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    if let Some(suite) = CryptoSuite::from_sdp_name(parts[1]) {
                        info.crypto_suites.push(suite);
                    }
                }
            }
        }

        info
    }

    /// True if this SDP contains enough ICE info to set up a WebRTC session
    pub fn has_ice(&self) -> bool {
        self.ice_ufrag.is_some() && self.ice_pwd.is_some()
    }

    /// True if this SDP contains DTLS fingerprint (mandatory for WebRTC)
    pub fn has_dtls(&self) -> bool {
        self.fingerprint.is_some()
    }

    /// True if this SDP contains at least one ICE candidate
    pub fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    /// Determine DTLS role for the SBC side.
    ///
    /// In ICE-lite mode the SBC is always the ICE controlled agent.
    /// The browser (controlling) initiates the DTLS handshake, so the SBC
    /// must be the DTLS **server** (passive).
    ///
    /// - Remote `actpass` → SBC `passive` (browser initiates DTLS)
    /// - Remote `active`  → SBC `passive` (browser initiates DTLS)
    /// - Remote `passive` → SBC `active`  (SBC initiates DTLS — rare)
    pub fn sbc_dtls_role(&self) -> DtlsRole {
        match &self.dtls_role {
            Some(DtlsRole::Passive) => DtlsRole::Active,
            // actpass, active, or unknown → SBC is passive (DTLS server)
            _ => DtlsRole::Passive,
        }
    }
}

impl Default for WebRtcSdpInfo {
    fn default() -> Self {
        Self {
            ice_ufrag: None,
            ice_pwd: None,
            candidates: Vec::new(),
            fingerprint: None,
            dtls_role: None,
            crypto_suites: Vec::new(),
            is_webrtc: false,
            media_port: None,
            mid: None,
        }
    }
}

/// WebRTC session context managed by the SBC
///
/// Created when an INVITE with WebRTC SDP is received.
#[allow(dead_code)]
pub struct WebRtcSession {
    /// Call-ID this session belongs to
    pub call_id: String,

    /// ICE agent for this session
    pub ice_agent: IceAgent,

    /// DTLS context (local certificate + fingerprint)
    pub dtls_context: DtlsContext,

    /// Remote SDP info (from INVITE)
    pub remote_info: WebRtcSdpInfo,

    /// SRTP context for sending (callee → caller direction)
    pub srtp_send: Option<SrtpContext>,

    /// SRTP context for receiving (caller → callee direction)
    pub srtp_recv: Option<SrtpContext>,
}

impl std::fmt::Debug for WebRtcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcSession")
            .field("call_id", &self.call_id)
            .field("remote_info", &self.remote_info)
            .finish_non_exhaustive()
    }
}

impl WebRtcSession {
    /// Create a new WebRTC session from an incoming INVITE SDP
    pub fn new(call_id: String, remote_sdp: &str) -> Result<Self> {
        let remote_info = WebRtcSdpInfo::from_sdp(remote_sdp);

        if !remote_info.is_webrtc {
            return Err(Error::Media("Not a WebRTC SDP".to_string()));
        }

        // Determine DTLS role for SBC (opposite of remote)
        let sbc_role = remote_info.sbc_dtls_role();

        // ICE-lite: SBC is always the controlled agent (never sends checks)
        let is_controlling = false;
        let mut ice_agent = IceAgent::new(is_controlling);

        // Set remote credentials if available
        if let (Some(ufrag), Some(pwd)) = (&remote_info.ice_ufrag, &remote_info.ice_pwd) {
            ice_agent.set_remote_credentials(ufrag.clone(), pwd.clone());
        }

        // Create DTLS context
        let dtls_context = DtlsContext::new(sbc_role)?;

        Ok(Self {
            call_id,
            ice_agent,
            dtls_context,
            remote_info,
            srtp_send: None,
            srtp_recv: None,
        })
    }

    /// Add remote ICE candidates to the ICE agent
    pub async fn add_remote_candidates(&mut self) {
        for cand in self.remote_info.candidates.clone() {
            self.ice_agent.add_remote_candidate(cand).await;
        }
    }

    /// Generate local SDP answer with our ICE credentials and DTLS fingerprint
    ///
    /// This produces the WebRTC-compatible SDP answer to include in the 200 OK.
    /// The SBC offers Opus (PT 111) to the browser and acts as ICE-lite.
    pub fn generate_sdp_answer(&self, local_rtp_port: u16, sbc_public_ip: &str) -> String {
        let (ufrag, pwd) = self.ice_agent.credentials();
        let fingerprint = self.dtls_context.local_fingerprint();
        let role_str = self.dtls_context.role().to_str();

        // Extract remote mid from the offer, default to "0"
        let mid = self.remote_info.mid.as_deref().unwrap_or("0");

        let mut sdp = String::new();
        // ── Session-level ──
        sdp.push_str("v=0\r\n");
        sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str("s=SBC\r\n");
        sdp.push_str(&format!("c=IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str("t=0 0\r\n");
        sdp.push_str("a=ice-lite\r\n");
        sdp.push_str(&format!("a=group:BUNDLE {}\r\n", mid));

        // ── Media-level ──
        sdp.push_str(&format!(
            "m=audio {} UDP/TLS/RTP/SAVPF 111\r\n",
            local_rtp_port
        ));
        sdp.push_str(&format!("c=IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str(&format!("a=mid:{}\r\n", mid));
        sdp.push_str(&format!("a=ice-ufrag:{}\r\n", ufrag));
        sdp.push_str(&format!("a=ice-pwd:{}\r\n", pwd));
        sdp.push_str(&format!("a=fingerprint:{}\r\n", fingerprint.to_sdp()));
        sdp.push_str(&format!("a=setup:{}\r\n", role_str));
        sdp.push_str("a=rtpmap:111 opus/48000/2\r\n");
        sdp.push_str("a=fmtp:111 minptime=10;useinbandfec=1\r\n");
        sdp.push_str("a=rtcp-mux\r\n");
        sdp.push_str("a=sendrecv\r\n");
        sdp.push_str(&format!("a=rtcp:{}\r\n", local_rtp_port));

        // Add SBC host candidate (ICE-lite: single host candidate)
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            sbc_public_ip, local_rtp_port
        ));

        sdp
    }

    /// Setup SRTP using SDES (for non-DTLS fallback)
    pub fn setup_srtp_sdes(&mut self) -> Result<()> {
        // If remote provided crypto attributes, use first one
        if let Some(&suite) = self.remote_info.crypto_suites.first() {
            let (master_key, master_salt): (Vec<u8>, Vec<u8>) = generate_key_material(suite);
            let srtp_send = SrtpContext::new(master_key.clone(), master_salt.clone(), suite)?;
            let srtp_recv = SrtpContext::new(master_key, master_salt, suite)?;
            self.srtp_send = Some(srtp_send);
            self.srtp_recv = Some(srtp_recv);
            Ok(())
        } else {
            Err(Error::Media("No SRTP crypto suite in remote SDP".to_string()))
        }
    }

    /// Get ICE statistics
    pub async fn ice_stats(&self) -> IceStats {
        self.ice_agent.stats().await
    }

    /// Check if this session has an established ICE pair
    pub async fn is_ice_established(&self) -> bool {
        self.ice_agent.get_selected_pair().await.is_some()
    }

    // ── PSTN → WebRTC: SBC as offerer ──────────────────────────────

    /// Create a new WebRTC session for generating an SDP offer (SBC → browser callee).
    /// Used when the SBC receives an INVITE from a PSTN trunk destined for a WebRTC callee.
    /// No remote SDP is available yet — it will come in the callee's 200 OK.
    pub fn new_for_offer(call_id: String) -> Result<Self> {
        // SBC is the offerer: use actpass role (let callee choose active/passive)
        let dtls_context = DtlsContext::new(DtlsRole::ActPass)?;

        // SBC is controlling (ICE-lite offerer)
        let ice_agent = IceAgent::new(true);

        // Empty remote info — will be filled when we get the callee's 200 OK
        let remote_info = WebRtcSdpInfo::default();

        Ok(Self {
            call_id,
            ice_agent,
            dtls_context,
            remote_info,
            srtp_send: None,
            srtp_recv: None,
        })
    }

    /// Set remote SDP info from the callee's 200 OK answer.
    /// Updates ICE remote credentials and remote info.
    pub fn set_remote_sdp(&mut self, remote_sdp: &str) {
        self.remote_info = WebRtcSdpInfo::from_sdp(remote_sdp);
        // Set remote ICE credentials for STUN validation
        if let (Some(ufrag), Some(pwd)) = (&self.remote_info.ice_ufrag, &self.remote_info.ice_pwd) {
            self.ice_agent.set_remote_credentials(ufrag.clone(), pwd.clone());
        }
        // Update DTLS role: if callee chose "active", SBC must be "passive"
        // If callee chose "passive", SBC must be "active"
        // The DtlsContext role was set to ActPass at creation, but for the actual
        // handshake we need to determine the concrete role from the callee's answer.
        // Note: the dtls_context role is already ActPass; the actual client/server
        // determination happens in perform_handshake based on the role.
    }

    /// Generate SDP offer for outbound INVITE to WebRTC callee.
    /// Similar to generate_sdp_answer but as an offer (setup=actpass, SBC generates candidates).
    pub fn generate_sdp_offer(&self, local_rtp_port: u16, sbc_public_ip: &str) -> String {
        let (ufrag, pwd) = self.ice_agent.credentials();
        let fingerprint = self.dtls_context.local_fingerprint();

        let mut sdp = String::new();
        // ── Session-level ──
        sdp.push_str("v=0\r\n");
        sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str("s=SBC\r\n");
        sdp.push_str(&format!("c=IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str("t=0 0\r\n");
        sdp.push_str("a=ice-lite\r\n");
        sdp.push_str("a=group:BUNDLE 0\r\n");

        // ── Media-level ──
        sdp.push_str(&format!(
            "m=audio {} UDP/TLS/RTP/SAVPF 111\r\n",
            local_rtp_port
        ));
        sdp.push_str(&format!("c=IN IP4 {}\r\n", sbc_public_ip));
        sdp.push_str("a=mid:0\r\n");
        sdp.push_str(&format!("a=ice-ufrag:{}\r\n", ufrag));
        sdp.push_str(&format!("a=ice-pwd:{}\r\n", pwd));
        sdp.push_str(&format!("a=fingerprint:{}\r\n", fingerprint.to_sdp()));
        sdp.push_str("a=setup:actpass\r\n"); // offerer uses actpass
        sdp.push_str("a=rtpmap:111 opus/48000/2\r\n");
        sdp.push_str("a=fmtp:111 minptime=10;useinbandfec=1\r\n");
        sdp.push_str("a=rtcp-mux\r\n");
        sdp.push_str("a=sendrecv\r\n");
        sdp.push_str(&format!("a=rtcp:{}\r\n", local_rtp_port));

        // Add SBC host candidate (ICE-lite: single host candidate)
        sdp.push_str(&format!(
            "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
            sbc_public_ip, local_rtp_port
        ));

        sdp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEBRTC_SDP: &str = "\
v=0\r\n\
o=- 123456 789012 IN IP4 192.168.1.100\r\n\
s=WebRTC Call\r\n\
c=IN IP4 203.0.113.100\r\n\
t=0 0\r\n\
a=ice-ufrag:F7gI\r\n\
a=ice-pwd:x9cml5SnwQUPeOZPy2hnZ\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:actpass\r\n\
m=audio 10000 UDP/TLS/RTP/SAVPF 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=candidate:host-1 1 UDP 2130706431 192.168.1.100 10000 typ host\r\n\
a=candidate:srflx-1 1 UDP 1694498815 203.0.113.100 10000 typ srflx raddr 192.168.1.100 rport 10000\r\n\
";

    const CLASSIC_SIP_SDP: &str = "\
v=0\r\n\
o=- 1 1 IN IP4 192.168.1.50\r\n\
s=Classic SIP\r\n\
c=IN IP4 192.168.1.50\r\n\
t=0 0\r\n\
m=audio 5060 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
";

    #[test]
    fn test_parse_webrtc_sdp() {
        let info = WebRtcSdpInfo::from_sdp(WEBRTC_SDP);

        assert!(info.is_webrtc);
        assert_eq!(info.ice_ufrag.as_deref(), Some("F7gI"));
        assert_eq!(info.ice_pwd.as_deref(), Some("x9cml5SnwQUPeOZPy2hnZ"));
        assert_eq!(info.candidates.len(), 2);
        assert!(info.fingerprint.is_some());
        assert_eq!(info.media_port, Some(10000));
    }

    #[test]
    fn test_parse_classic_sdp_not_webrtc() {
        let info = WebRtcSdpInfo::from_sdp(CLASSIC_SIP_SDP);
        assert!(!info.is_webrtc);
        assert!(info.ice_ufrag.is_none());
        assert!(info.candidates.is_empty());
        assert!(info.fingerprint.is_none());
    }

    #[test]
    fn test_has_ice_and_dtls() {
        let info = WebRtcSdpInfo::from_sdp(WEBRTC_SDP);
        assert!(info.has_ice());
        assert!(info.has_dtls());
        assert!(info.has_candidates());
    }

    #[test]
    fn test_sbc_dtls_role_from_actpass() {
        let info = WebRtcSdpInfo::from_sdp(WEBRTC_SDP);
        // Remote is actpass → SBC should be passive (ICE-lite = DTLS server)
        assert_eq!(info.sbc_dtls_role(), DtlsRole::Passive);
    }

    #[test]
    fn test_sbc_dtls_role_from_active() {
        let sdp = "a=setup:active\r\nm=audio 10000 RTP/SAVPF 0\r\n";
        let info = WebRtcSdpInfo::from_sdp(sdp);
        // Remote is active → SBC should be passive
        assert_eq!(info.sbc_dtls_role(), DtlsRole::Passive);
    }

    #[test]
    fn test_fingerprint_algorithm() {
        let info = WebRtcSdpInfo::from_sdp(WEBRTC_SDP);
        let fp = info.fingerprint.unwrap();
        assert_eq!(fp.algorithm, "sha-256");
        assert!(fp.fingerprint.contains(':'));
    }

    #[test]
    fn test_ice_candidate_types_parsed() {
        let info = WebRtcSdpInfo::from_sdp(WEBRTC_SDP);
        assert_eq!(info.candidates.len(), 2);
        use crate::media::ice::CandidateType;
        assert_eq!(info.candidates[0].candidate_type, CandidateType::Host);
        assert_eq!(info.candidates[1].candidate_type, CandidateType::ServerReflexive);
    }

    #[tokio::test]
    async fn test_webrtc_session_creation() {
        let session = WebRtcSession::new("test-call-id".to_string(), WEBRTC_SDP);
        assert!(session.is_ok());

        let session = session.unwrap();
        assert_eq!(session.call_id, "test-call-id");
        // ICE agent should have remote credentials set
        // DTLS context should be created
        assert!(session.srtp_send.is_none()); // Not yet established
    }

    #[tokio::test]
    async fn test_webrtc_session_from_non_webrtc_sdp() {
        let result = WebRtcSession::new("test".to_string(), CLASSIC_SIP_SDP);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("Not a WebRTC SDP"), "got: {}", err_msg);
    }

    #[tokio::test]
    async fn test_webrtc_session_sdp_answer() {
        let mut session = WebRtcSession::new("call-1".to_string(), WEBRTC_SDP).unwrap();
        session.add_remote_candidates().await;

        let answer_sdp = session.generate_sdp_answer(20000, "203.0.113.1");

        // Answer must contain ICE credentials
        assert!(answer_sdp.contains("a=ice-ufrag:"));
        assert!(answer_sdp.contains("a=ice-pwd:"));

        // Answer must contain DTLS fingerprint
        assert!(answer_sdp.contains("a=fingerprint:sha-256"));

        // Answer must contain our media port
        assert!(answer_sdp.contains("20000"));

        // DTLS role must be passive (ICE-lite SBC is DTLS server)
        assert!(answer_sdp.contains("a=setup:passive"));

        // Must have ICE-lite
        assert!(answer_sdp.contains("a=ice-lite"));

        // Must offer Opus (PT 111)
        assert!(answer_sdp.contains("a=rtpmap:111 opus/48000/2"));
        assert!(answer_sdp.contains("UDP/TLS/RTP/SAVPF 111"));

        // Must have rtcp-mux
        assert!(answer_sdp.contains("a=rtcp-mux"));

        // Must have SBC public IP, not 0.0.0.0
        assert!(answer_sdp.contains("c=IN IP4 203.0.113.1"));
        assert!(!answer_sdp.contains("0.0.0.0"));

        // Must have host candidate
        assert!(answer_sdp.contains("a=candidate:1 1 UDP"));

        // Must have mid and BUNDLE group (Chrome requirement)
        assert!(answer_sdp.contains("a=mid:"));
        assert!(answer_sdp.contains("a=group:BUNDLE"));

        // ICE credentials must be at media level (not just session level)
        // Check that ice-ufrag appears after the m= line
        let m_line_pos = answer_sdp.find("m=audio").unwrap();
        let after_m = &answer_sdp[m_line_pos..];
        assert!(after_m.contains("a=ice-ufrag:"));
        assert!(after_m.contains("a=ice-pwd:"));
    }

    #[tokio::test]
    async fn test_webrtc_session_add_remote_candidates() {
        let mut session = WebRtcSession::new("call-2".to_string(), WEBRTC_SDP).unwrap();
        session.add_remote_candidates().await;

        let stats = session.ice_stats().await;
        // 2 remote candidates from the SDP
        assert_eq!(stats.remote_candidates, 2);
    }

    #[tokio::test]
    async fn test_webrtc_session_not_established_initially() {
        let session = WebRtcSession::new("call-3".to_string(), WEBRTC_SDP).unwrap();
        assert!(!session.is_ice_established().await);
    }
}
