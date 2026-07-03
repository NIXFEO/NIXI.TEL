//! B2BUA - Back-to-Back User Agent (RFC 3261)
//!
//! The B2BUA maintains two independent SIP dialogs:
//!   - Inbound leg  (UAC → SBC): the SBC acts as UAS
//!   - Outbound leg (SBC → UAS): the SBC acts as UAC
//!
//! This allows full control over call routing, NAT traversal,
//! codec normalisation, and media anchoring.

use crate::media::{MediaManager, WebRtcSdpInfo};
use crate::media::webrtc_handler::WebRtcSession;
use crate::{Error, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

/// Unique call identifier for a B2BUA call (different from SIP Call-ID)
pub type CallUuid = String;

/// State of the overall B2BUA call (both legs combined)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// INVITE sent to inbound leg, waiting
    Initiated,

    /// 100 Trying sent back to caller
    Proceeding,

    /// 180 Ringing received from callee
    Ringing,

    /// Both legs established (ACK exchanged)
    Connected,

    /// BYE received/sent, tearing down
    Terminating,

    /// Both legs torn down
    Terminated,
}

impl CallState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initiated    => "initiated",
            Self::Proceeding   => "proceeding",
            Self::Ringing      => "ringing",
            Self::Connected    => "connected",
            Self::Terminating  => "terminating",
            Self::Terminated   => "terminated",
        }
    }
}

/// One SIP leg (either inbound or outbound)
#[derive(Debug, Clone)]
pub struct CallLeg {
    /// SIP Call-ID for this leg
    pub call_id: String,

    /// Local tag (From-tag for UAC, To-tag for UAS)
    pub local_tag: String,

    /// Remote tag (set after 200 OK)
    pub remote_tag: Option<String>,

    /// Remote address (IP:port of the peer)
    pub remote_addr: SocketAddr,

    /// Current CSeq number (increments for UAC leg)
    pub cseq: u32,

    /// Whether this leg is fully established (200 ACK done)
    pub established: bool,

    /// Full `From` header value of the dialog (display, URI, `;tag=`),
    /// as seen on the wire for this leg. Needed to build synthetic
    /// in-dialog requests (BYE/re-INVITE) that strict UAS accept.
    pub from_raw: Option<String>,

    /// Full `To` header value with the remote tag once known.
    pub to_raw: Option<String>,

    /// Remote target: the peer's Contact URI (from INVITE or 200 OK).
    pub remote_target: Option<String>,
}

impl CallLeg {
    pub fn new(call_id: String, local_tag: String, remote_addr: SocketAddr) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag: None,
            remote_addr,
            cseq: 1,
            established: false,
            from_raw: None,
            to_raw: None,
            remote_target: None,
        }
    }

    pub fn next_cseq(&mut self) -> u32 {
        let n = self.cseq;
        self.cseq += 1;
        n
    }
}

/// A B2BUA call — two legs + shared media session
#[derive(Debug)]
pub struct B2buaCall {
    /// Internal UUID for this call
    pub uuid: CallUuid,

    /// Inbound leg (caller → SBC)
    pub inbound: CallLeg,

    /// Outbound leg (SBC → callee), None until routing complete
    pub outbound: Option<CallLeg>,

    /// Current call state
    pub state: CallState,

    /// Whether the caller's SDP is WebRTC
    pub caller_is_webrtc: bool,

    /// Caller's original SDP (from INVITE)
    pub caller_sdp: Option<String>,

    /// Callee's SDP (from 200 OK)
    pub callee_sdp: Option<String>,

    /// Media session UUID (RTP proxy ports)
    pub media_session_id: Option<String>,

    /// Timestamp when call started
    pub started_at: std::time::Instant,

    /// Reply channel back to the caller (UDP addr or TCP/TLS/WSS connection)
    pub caller_reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,

    /// Caller's source address (for UDP replies)
    pub caller_source: SocketAddr,

    /// Caller's transport (UDP/TCP/TLS/WSS)
    pub caller_transport: rsip::Transport,

    /// Reply channel to the callee (for sending BYE/ACK over existing connection)
    pub callee_reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,

    /// Callee's destination address
    pub callee_dest: Option<SocketAddr>,

    /// Callee's transport
    pub callee_transport: rsip::Transport,

    /// Callee's Request-URI (for ACK relay)
    pub callee_request_uri: Option<String>,

    /// Caller's original Via header(s) from the INVITE — stored before topology hiding
    /// strips them. Must be restored in every response (180, 200 OK, etc.) relayed
    /// back to the caller so the UAC can match the response to its INVITE transaction.
    pub caller_original_vias: Vec<String>,

    // ── Outbound trunk auth (407 retry) ─────────────────────────────
    /// Raw outbound INVITE (topology-hidden) stored for 407 challenge retry
    pub original_outbound_invite: Option<String>,

    /// Trunk ID used for this call (for credential lookup on 407)
    pub trunk_id: Option<crate::routing::TrunkId>,

    /// Number of auth retries attempted (capped at 1 to prevent loops)
    pub auth_retry_count: u32,

    /// WebRTC session (ICE agent, DTLS context, SRTP) — only set when caller_is_webrtc
    pub webrtc_session: Option<Arc<Mutex<WebRtcSession>>>,

    /// SBC's local ICE password for this WebRTC call (for STUN MESSAGE-INTEGRITY)
    pub webrtc_ice_pwd: Option<String>,

    /// Pre-generated WebRTC SDP answer (generated before DTLS task takes the lock)
    /// Used in 200 OK relay to avoid deadlock with the DTLS handshake task.
    pub webrtc_sdp_answer: Option<String>,

    // ── PSTN → WebRTC (callee is WebRTC) ─────────────────────────────
    // ── CDR enrichment fields ─────────────────────────────────────
    /// Caller's phone number or SIP user (e.g. "alice" or "+33612345678")
    pub caller_number: Option<String>,

    /// Callee's phone number or SIP user (e.g. "bob" or "0612345678")
    pub callee_number: Option<String>,

    /// Trunk name used for this call (e.g. "nixi-trunk-out")
    pub trunk_name: Option<String>,

    /// Codec negotiated for this call (e.g. "PCMU", "Opus")
    pub codec: Option<String>,

    /// Whether the callee is a WebRTC client (transport=WSS/WS)
    pub callee_is_webrtc: bool,

    /// WebRTC session for leg-B (callee side) — ICE/DTLS/SRTP for inbound PSTN→WebRTC
    pub webrtc_session_b: Option<Arc<Mutex<WebRtcSession>>>,

    /// SBC's local ICE password for leg-B (for STUN MESSAGE-INTEGRITY on callee port)
    pub webrtc_ice_pwd_b: Option<String>,

    /// Pre-generated WebRTC SDP offer (sent to callee in INVITE)
    pub webrtc_sdp_offer: Option<String>,
}

impl B2buaCall {
    pub fn new(
        inbound_call_id: String,
        inbound_tag: String,
        inbound_addr: SocketAddr,
        caller_sdp: Option<String>,
        caller_reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
        caller_transport: rsip::Transport,
    ) -> Self {
        use rand::Rng;
        let uuid = format!("{:016x}", rand::thread_rng().gen::<u64>());

        let caller_is_webrtc = caller_sdp
            .as_deref()
            .map(|s| WebRtcSdpInfo::from_sdp(s).is_webrtc)
            .unwrap_or(false);

        Self {
            uuid,
            inbound: CallLeg::new(inbound_call_id, inbound_tag, inbound_addr),
            outbound: None,
            state: CallState::Initiated,
            caller_is_webrtc,
            caller_sdp,
            callee_sdp: None,
            media_session_id: None,
            started_at: std::time::Instant::now(),
            caller_reply_tx,
            caller_source: inbound_addr,
            caller_transport,
            callee_reply_tx: None,
            callee_dest: None,
            callee_transport: rsip::Transport::Udp,
            callee_request_uri: None,
            caller_original_vias: Vec::new(),
            original_outbound_invite: None,
            trunk_id: None,
            auth_retry_count: 0,
            webrtc_session: None,
            webrtc_ice_pwd: None,
            webrtc_sdp_answer: None,
            caller_number: None,
            callee_number: None,
            trunk_name: None,
            codec: None,
            callee_is_webrtc: false,
            webrtc_session_b: None,
            webrtc_ice_pwd_b: None,
            webrtc_sdp_offer: None,
        }
    }

    /// Set outbound leg (after routing decision)
    pub fn set_outbound(&mut self, call_id: String, local_tag: String, remote_addr: SocketAddr) {
        self.outbound = Some(CallLeg::new(call_id, local_tag, remote_addr));
    }

    /// Mark inbound leg as established
    pub fn establish_inbound(&mut self, remote_tag: String) {
        self.inbound.remote_tag = Some(remote_tag);
        self.inbound.established = true;
    }

    /// Mark outbound leg as established
    pub fn establish_outbound(&mut self, remote_tag: String) {
        if let Some(leg) = &mut self.outbound {
            leg.remote_tag = Some(remote_tag);
            leg.established = true;
        }
        // Both legs up → Connected
        if self.inbound.established {
            self.state = CallState::Connected;
        }
    }

    /// Duration since call start
    pub fn duration_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Dialog identity for a synthetic request toward the caller.
    /// From/To are reversed relative to the INVITE: our identity toward the
    /// caller is the answered `To` (with its tag). None until the dialog
    /// identity has been captured (INVITE From + 200 OK To).
    pub fn dialog_info_toward_caller(
        &self,
        local_ip: &str,
        local_port: u16,
    ) -> Option<crate::sip_builder::DialogInfo> {
        let from_raw = self.inbound.to_raw.clone()?;
        let to_raw = self.inbound.from_raw.clone()?;
        let request_uri = self
            .inbound
            .remote_target
            .clone()
            .unwrap_or_else(|| format!("sip:{}", self.caller_source));
        Some(crate::sip_builder::DialogInfo {
            call_id: self.inbound.call_id.clone(),
            from_raw,
            to_raw,
            request_uri,
            cseq: 1,
            local_ip: local_ip.to_string(),
            local_port,
            transport: transport_token(self.caller_transport),
        })
    }

    /// Dialog identity for a synthetic request toward the callee
    /// (SBC acts as UAC on the outbound leg). `cseq` should come from
    /// `outbound.next_cseq()` when the leg is mutable.
    pub fn dialog_info_toward_callee(
        &self,
        local_ip: &str,
        local_port: u16,
    ) -> Option<crate::sip_builder::DialogInfo> {
        let out = self.outbound.as_ref()?;
        let from_raw = out.from_raw.clone()?;
        let to_raw = out.to_raw.clone()?;
        let request_uri = out
            .remote_target
            .clone()
            .or_else(|| self.callee_request_uri.clone())
            .or_else(|| self.callee_dest.map(|d| format!("sip:{}", d)))?;
        Some(crate::sip_builder::DialogInfo {
            call_id: out.call_id.clone(),
            from_raw,
            to_raw,
            request_uri,
            cseq: out.cseq,
            local_ip: local_ip.to_string(),
            local_port,
            transport: transport_token(self.callee_transport),
        })
    }
}

/// Via transport token for an rsip transport.
pub fn transport_token(t: rsip::Transport) -> String {
    match t {
        rsip::Transport::Udp => "UDP",
        rsip::Transport::Tcp => "TCP",
        rsip::Transport::Tls => "TLS",
        rsip::Transport::Ws => "WS",
        rsip::Transport::Wss => "WSS",
        _ => "UDP",
    }
    .to_string()
}

/// B2BUA Manager — owns all active calls
pub struct B2buaManager {
    /// Active calls indexed by their UUID
    calls: Arc<Mutex<HashMap<CallUuid, B2buaCall>>>,

    /// Media manager for RTP proxy
    media: Arc<MediaManager>,

    /// Event bus for call lifecycle events (None until wired at boot)
    events: std::sync::RwLock<Option<crate::events::EventBus>>,
}

impl B2buaManager {
    pub fn new(media: Arc<MediaManager>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
            media,
            events: std::sync::RwLock::new(None),
        }
    }

    /// Wire the event bus (called once at boot).
    pub fn set_event_bus(&self, bus: crate::events::EventBus) {
        *self.events.write().unwrap() = Some(bus);
    }

    fn emit(&self, event: crate::events::SbcEvent) {
        if let Ok(guard) = self.events.read() {
            if let Some(bus) = guard.as_ref() {
                bus.publish(event);
            }
        }
    }

    /// Create a new B2BUA call from an inbound INVITE
    ///
    /// Returns the call UUID.
    pub async fn create_call(
        &self,
        inbound_call_id: String,
        inbound_tag: String,
        caller_addr: SocketAddr,
        caller_sdp: Option<&str>,
        caller_reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
        caller_transport: rsip::Transport,
    ) -> Result<CallUuid> {
        let mut call = B2buaCall::new(
            inbound_call_id.clone(),
            inbound_tag,
            caller_addr,
            caller_sdp.map(|s| s.to_string()),
            caller_reply_tx,
            caller_transport,
        );

        // Allocate media session for RTP proxying
        if let Some(sdp) = caller_sdp {
            match self.media.create_session(inbound_call_id.clone(), Some(sdp)).await {
                Ok(session) => {
                    info!(
                        "B2BUA: allocated RTP ports {}/{} for call {}",
                        session.ports.rtp, session.ports.rtcp, call.uuid
                    );
                    call.media_session_id = Some(session.session_id.clone());
                }
                Err(e) => {
                    warn!("B2BUA: could not allocate media ports: {}", e);
                }
            }
        }

        call.state = CallState::Proceeding;
        let uuid = call.uuid.clone();

        info!(
            "B2BUA: created call {} (inbound call-id: {}, webrtc: {})",
            uuid, inbound_call_id, call.caller_is_webrtc
        );

        self.calls.lock().await.insert(uuid.clone(), call);

        self.emit(crate::events::SbcEvent::CallStarted {
            uuid: uuid.clone(),
            call_id: inbound_call_id,
            caller: caller_addr.to_string(),
            callee: None,
            ts: crate::events::event_ts(),
        });
        Ok(uuid)
    }

    /// Attach the outbound leg after routing
    pub async fn attach_outbound(
        &self,
        uuid: &CallUuid,
        outbound_call_id: String,
        local_tag: String,
        callee_addr: SocketAddr,
        callee_reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
        callee_transport: rsip::Transport,
    ) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid).ok_or_else(|| {
            Error::Dialog(format!("B2BUA call {} not found", uuid))
        })?;

        call.set_outbound(outbound_call_id, local_tag, callee_addr);
        call.callee_reply_tx = callee_reply_tx;
        call.callee_dest = Some(callee_addr);
        call.callee_transport = callee_transport;
        debug!("B2BUA: outbound leg attached for call {}", uuid);
        Ok(())
    }

    /// Record the caller-side dialog identity from the original INVITE:
    /// the raw `From` value (with the caller's tag) and the caller's Contact.
    pub async fn set_inbound_dialog(
        &self,
        uuid: &CallUuid,
        from_raw: String,
        caller_contact: Option<String>,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.inbound.from_raw = Some(from_raw);
            call.inbound.remote_target = caller_contact;
        }
    }

    /// Record dialog identity established by the 200 OK: the raw `To` value
    /// (now carrying the callee's tag) applies to both legs in half-B2BUA
    /// mode; the response's `From` matches the outbound INVITE we sent.
    pub async fn set_established_dialog(
        &self,
        uuid: &CallUuid,
        outbound_from_raw: String,
        to_raw: String,
        callee_contact: Option<String>,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.inbound.to_raw = Some(to_raw.clone());
            if let Some(out) = call.outbound.as_mut() {
                out.from_raw = Some(outbound_from_raw);
                out.to_raw = Some(to_raw);
                out.remote_target = callee_contact;
            }
        }
    }

    /// Get the media session ID for a call (for SDP rewriting / RTP proxy)
    pub async fn get_media_session_id(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.media_session_id.clone())
    }

    /// Get the callee's reply channel and transport info (for sending BYE to callee)
    pub async fn get_callee_reply_info(&self, uuid: &CallUuid) -> Option<(Option<mpsc::UnboundedSender<Vec<u8>>>, SocketAddr, rsip::Transport)> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| {
            c.callee_dest.map(|dest| (
                c.callee_reply_tx.clone(),
                dest,
                c.callee_transport,
            ))
        })
    }

    /// Get the callee's Request-URI (for ACK relay)
    pub async fn get_callee_contact_uri(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.callee_request_uri.clone())
    }

    /// Set the callee's Request-URI (stored when INVITE is forwarded)
    pub async fn set_callee_request_uri(&self, uuid: &CallUuid, uri: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.callee_request_uri = Some(uri);
        }
    }

    /// Handle 180 Ringing from callee
    /// Get the stored inbound (full) Call-ID for a call
    pub async fn get_inbound_call_id(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| c.inbound.call_id.clone())
    }

    pub async fn handle_ringing(&self, uuid: &CallUuid) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid).ok_or_else(|| {
            Error::Dialog(format!("B2BUA call {} not found", uuid))
        })?;
        call.state = CallState::Ringing;
        info!("B2BUA: call {} ringing", uuid);
        Ok(())
    }

    /// Handle 200 OK from callee (outbound leg established)
    pub async fn handle_200_ok(
        &self,
        uuid: &CallUuid,
        callee_tag: String,
        callee_sdp: Option<String>,
    ) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid).ok_or_else(|| {
            Error::Dialog(format!("B2BUA call {} not found", uuid))
        })?;

        call.callee_sdp = callee_sdp.clone();
        call.establish_outbound(callee_tag);

        // Update media session with callee SDP
        if let (Some(media_id), Some(sdp)) = (&call.media_session_id.clone(), callee_sdp) {
            if let Err(e) = self.media.update_callee_sdp(media_id, &sdp) {
                warn!("B2BUA: could not update callee SDP: {}", e);
            }
        }

        info!("B2BUA: call {} state → {}", uuid, call.state.as_str());
        drop(calls);
        self.emit(crate::events::SbcEvent::CallAnswered {
            uuid: uuid.clone(),
            ts: crate::events::event_ts(),
        });
        Ok(())
    }

    /// Handle ACK from caller (inbound leg established)
    pub async fn handle_ack(&self, uuid: &CallUuid) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid).ok_or_else(|| {
            Error::Dialog(format!("B2BUA call {} not found", uuid))
        })?;

        call.establish_inbound(call.inbound.remote_tag.clone().unwrap_or_default());

        if call.outbound.as_ref().map_or(false, |l| l.established) {
            call.state = CallState::Connected;
        }

        info!("B2BUA: ACK received, call {} state → {}", uuid, call.state.as_str());
        Ok(())
    }

    /// Handle BYE (from either leg) — tears down both legs
    pub async fn handle_bye(&self, uuid: &CallUuid) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid).ok_or_else(|| {
            Error::Dialog(format!("B2BUA call {} not found", uuid))
        })?;

        call.state = CallState::Terminating;

        // Release media session
        if let Some(media_id) = &call.media_session_id {
            if let Err(e) = self.media.terminate_session(media_id) {
                debug!("B2BUA: media session already gone: {}", e);
            }
        }

        info!("B2BUA: call {} → Terminating", uuid);
        Ok(())
    }

    /// Mark call as fully terminated
    pub async fn terminate_call(&self, uuid: &CallUuid) {
        let mut calls = self.calls.lock().await;
        let duration = if let Some(call) = calls.get_mut(uuid) {
            call.state = CallState::Terminated;
            info!("B2BUA: call {} terminated (duration {}s)", uuid, call.duration_secs());
            Some(call.duration_secs())
        } else {
            None
        };
        calls.remove(uuid);
        drop(calls);

        if let Some(duration_secs) = duration {
            self.emit(crate::events::SbcEvent::CallEnded {
                uuid: uuid.clone(),
                duration_secs,
                reason: "terminated".to_string(),
                ts: crate::events::event_ts(),
            });
        }
    }

    /// Look up a call by inbound Call-ID
    pub async fn find_by_inbound_call_id(&self, call_id: &str) -> Option<CallUuid> {
        let calls = self.calls.lock().await;
        calls.values()
            .find(|c| c.inbound.call_id == call_id)
            .map(|c| c.uuid.clone())
    }

    /// Look up a call by inbound Call-ID suffix match.
    /// Some Genesys-based trunks add prefixes to the Call-ID in the INVITE
    /// but send the ACK with the original (shorter) Call-ID.
    /// Example: INVITE Call-ID = "36f34d8-ad54ea8-57191931_133@host"
    ///          ACK   Call-ID = "57191931_133@host"
    /// This method finds a call where the stored inbound call_id ends with the given suffix.
    pub async fn find_by_inbound_call_id_suffix(&self, call_id: &str) -> Option<CallUuid> {
        let calls = self.calls.lock().await;
        calls.values()
            .find(|c| c.inbound.call_id.ends_with(call_id) && c.inbound.call_id != *call_id)
            .map(|c| c.uuid.clone())
    }

    /// Look up a call by outbound Call-ID (the leg SBC→callee)
    pub async fn find_by_outbound_call_id(&self, call_id: &str) -> Option<CallUuid> {
        let calls = self.calls.lock().await;
        calls.values()
            .find(|c| c.outbound.as_ref().map_or(false, |leg| leg.call_id == call_id))
            .map(|c| c.uuid.clone())
    }

    /// Look up a call by either inbound or outbound Call-ID.
    /// Also returns which leg matched: true = inbound (caller), false = outbound (callee).
    ///
    /// Uses source IP to disambiguate when both legs share the same Call-ID
    /// (which is the case in our half-B2BUA: we don't re-originate with a new Call-ID).
    pub async fn find_by_any_call_id(&self, call_id: &str) -> Option<(CallUuid, bool)> {
        self.find_by_any_call_id_with_source(call_id, None).await
    }

    /// Like `find_by_any_call_id` but uses the BYE/request source address to determine
    /// which leg the request came from. This is critical when both legs share the same
    /// Call-ID: without source matching, the first leg always wins (inbound = caller).
    pub async fn find_by_any_call_id_with_source(
        &self,
        call_id: &str,
        source: Option<std::net::SocketAddr>,
    ) -> Option<(CallUuid, bool)> {
        let calls = self.calls.lock().await;
        for call in calls.values() {
            let inbound_matches = call.inbound.call_id == call_id;
            let outbound_matches = call.outbound.as_ref().map_or(false, |leg| leg.call_id == call_id);

            // Also try suffix match: Genesys-based trunks adds prefixes to Call-IDs
            // e.g. INVITE Call-ID = "14823298-118e8248-104858689_65703785@host"
            //      BYE   Call-ID = "104858689_65703785@host"
            let inbound_suffix = !inbound_matches
                && call.inbound.call_id.ends_with(call_id)
                && call.inbound.call_id != *call_id;
            let outbound_suffix = !outbound_matches
                && call.outbound.as_ref().map_or(false, |leg| {
                    leg.call_id.ends_with(call_id) && leg.call_id != *call_id
                });

            if !inbound_matches && !outbound_matches && !inbound_suffix && !outbound_suffix {
                continue;
            }

            if inbound_suffix || outbound_suffix {
                info!("Call-ID suffix match: BYE '{}' matched stored '{}'",
                    call_id, call.inbound.call_id);
            }

            // If we have a source address, use it to disambiguate
            if let Some(src) = source {
                let caller_addr = call.caller_source;
                let callee_addr = call.callee_dest;

                // First try exact SocketAddr match (IP:port) — this is the most
                // reliable disambiguation, especially when both endpoints share
                // the same NAT IP (same public IP, different ports).
                if callee_addr == Some(src) {
                    return Some((call.uuid.clone(), false)); // from callee
                }
                if caller_addr == src {
                    return Some((call.uuid.clone(), true)); // from caller
                }

                // Fallback: IP-only match (for trunks that may send BYE from
                // different ports than the INVITE was sent to)
                let src_ip = src.ip();
                let caller_ip = caller_addr.ip();
                let callee_ip = callee_addr.map(|d| d.ip());

                if callee_ip == Some(src_ip) && caller_ip != src_ip {
                    return Some((call.uuid.clone(), false)); // from callee
                }
                if caller_ip == src_ip && callee_ip != Some(src_ip) {
                    return Some((call.uuid.clone(), true)); // from caller
                }
            }

            // Fallback: prefer inbound match (legacy behavior)
            if inbound_matches || inbound_suffix {
                return Some((call.uuid.clone(), true));
            }
            if outbound_matches || outbound_suffix {
                return Some((call.uuid.clone(), false));
            }
        }
        None
    }

    /// Get the caller's reply channel and transport info (for sending provisional/final responses)
    pub async fn get_caller_reply_info(&self, uuid: &CallUuid) -> Option<(Option<mpsc::UnboundedSender<Vec<u8>>>, SocketAddr, rsip::Transport)> {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| (
            c.caller_reply_tx.clone(),
            c.caller_source,
            c.caller_transport,
        ))
    }

    /// Get the stored Call-IDs for a call (inbound + outbound).
    /// Used to rewrite truncated Call-IDs in relayed BYE messages when the
    /// trunk (e.g. Genesys-based trunks) sends BYE with a shortened Call-ID.
    pub async fn get_call_ids(&self, uuid: &CallUuid) -> Option<(String, Option<String>)> {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| (
            c.inbound.call_id.clone(),
            c.outbound.as_ref().map(|l| l.call_id.clone()),
        ))
    }

    /// Store the caller's original Via headers (before topology hiding strips them)
    pub async fn set_caller_vias(&self, uuid: &CallUuid, vias: Vec<String>) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            debug!("B2BUA: stored {} original Via header(s) for call {}", vias.len(), uuid);
            call.caller_original_vias = vias;
        }
    }

    /// Get the caller's original Via headers (to restore in responses)
    pub async fn get_caller_vias(&self, uuid: &CallUuid) -> Vec<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid)
            .map(|c| c.caller_original_vias.clone())
            .unwrap_or_default()
    }

    // ── Outbound trunk auth (407 retry) helpers ────────────────────────

    /// Store the outbound INVITE raw text and trunk ID for potential 407 retry
    pub async fn store_outbound_invite(
        &self,
        uuid: &CallUuid,
        invite_raw: String,
        trunk_id: crate::routing::TrunkId,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.original_outbound_invite = Some(invite_raw);
            call.trunk_id = Some(trunk_id);
        }
    }

    /// Get auth retry info: (original_invite, trunk_id, retry_count)
    pub async fn get_auth_retry_info(
        &self,
        uuid: &CallUuid,
    ) -> Option<(String, crate::routing::TrunkId, u32)> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        let invite = call.original_outbound_invite.clone()?;
        let trunk_id = call.trunk_id?;
        Some((invite, trunk_id, call.auth_retry_count))
    }

    /// Increment auth retry count (call after each 407 retry)
    pub async fn increment_auth_retry(&self, uuid: &CallUuid) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.auth_retry_count += 1;
        }
    }

    /// Expose the calls map for read-only inspection (e.g., to read caller_sdp)
    pub async fn calls_locked(&self) -> tokio::sync::MutexGuard<'_, HashMap<CallUuid, B2buaCall>> {
        self.calls.lock().await
    }

    // ── WebRTC session management ─────────────────────────────────────

    /// Store a WebRTC session (ICE + DTLS) for a call
    pub async fn set_webrtc_session(&self, uuid: &CallUuid, session: WebRtcSession) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            info!("B2BUA: WebRTC session set for call {}", uuid);
            call.webrtc_session = Some(Arc::new(Mutex::new(session)));
        }
    }

    /// Get the WebRTC session for a call (clone of Arc)
    pub async fn get_webrtc_session(&self, uuid: &CallUuid) -> Option<Arc<Mutex<WebRtcSession>>> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_session.clone())
    }

    /// Store pre-generated WebRTC SDP answer for a call
    pub async fn set_webrtc_sdp_answer(&self, uuid: &CallUuid, sdp: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.webrtc_sdp_answer = Some(sdp);
        }
    }

    /// Get pre-generated WebRTC SDP answer for a call
    pub async fn get_webrtc_sdp_answer(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_sdp_answer.clone())
    }

    /// Check if caller is WebRTC for a given call UUID
    pub async fn is_caller_webrtc(&self, uuid: &CallUuid) -> bool {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| c.caller_is_webrtc).unwrap_or(false)
    }

    /// Store the SBC's local ICE password for a WebRTC call
    pub async fn set_webrtc_ice_pwd(&self, uuid: &CallUuid, pwd: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.webrtc_ice_pwd = Some(pwd);
        }
    }

    /// Get the SBC's local ICE password for a WebRTC call
    pub async fn get_webrtc_ice_pwd(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_ice_pwd.clone())
    }

    // ── Callee WebRTC session management (PSTN → WebRTC) ────────────

    /// Mark callee as WebRTC
    pub async fn set_callee_is_webrtc(&self, uuid: &CallUuid, is_webrtc: bool) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.callee_is_webrtc = is_webrtc;
        }
    }

    /// Check if callee is WebRTC for a given call UUID
    pub async fn is_callee_webrtc(&self, uuid: &CallUuid) -> bool {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| c.callee_is_webrtc).unwrap_or(false)
    }

    /// Store WebRTC session for leg-B (callee side)
    pub async fn set_webrtc_session_b(&self, uuid: &CallUuid, session: WebRtcSession) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            info!("B2BUA: WebRTC session B (callee) set for call {}", uuid);
            call.webrtc_session_b = Some(Arc::new(Mutex::new(session)));
        }
    }

    /// Get WebRTC session for leg-B (callee side)
    pub async fn get_webrtc_session_b(&self, uuid: &CallUuid) -> Option<Arc<Mutex<WebRtcSession>>> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_session_b.clone())
    }

    /// Store ICE password for leg-B (callee side)
    pub async fn set_webrtc_ice_pwd_b(&self, uuid: &CallUuid, pwd: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.webrtc_ice_pwd_b = Some(pwd);
        }
    }

    /// Get ICE password for leg-B (callee side)
    pub async fn get_webrtc_ice_pwd_b(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_ice_pwd_b.clone())
    }

    /// Store pre-generated WebRTC SDP offer for callee
    pub async fn set_webrtc_sdp_offer(&self, uuid: &CallUuid, sdp: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.webrtc_sdp_offer = Some(sdp);
        }
    }

    /// Get pre-generated WebRTC SDP offer for callee
    pub async fn get_webrtc_sdp_offer(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.webrtc_sdp_offer.clone())
    }

    /// Get all info needed to send a CANCEL to the callee:
    /// (outbound_call_id, outbound_cseq, callee_dest, callee_reply_tx, callee_transport)
    pub async fn get_callee_cancel_info(
        &self,
        uuid: &CallUuid,
    ) -> Option<(String, u32, SocketAddr, Option<mpsc::UnboundedSender<Vec<u8>>>, rsip::Transport)> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        let outbound = call.outbound.as_ref()?;
        let callee_dest = call.callee_dest?;
        Some((
            outbound.call_id.clone(),
            outbound.cseq,
            callee_dest,
            call.callee_reply_tx.clone(),
            call.callee_transport,
        ))
    }

    /// Get call statistics
    pub async fn stats(&self) -> B2buaStats {
        let calls = self.calls.lock().await;
        let total = calls.len();
        let connected = calls.values().filter(|c| c.state == CallState::Connected).count();
        let ringing  = calls.values().filter(|c| c.state == CallState::Ringing).count();
        let webrtc   = calls.values().filter(|c| c.caller_is_webrtc).count();
        B2buaStats { total_active: total, connected, ringing, webrtc_calls: webrtc }
    }

    /// Get snapshot of all active calls (for REST API / metrics)
    pub async fn active_calls(&self) -> Vec<CallSnapshot> {
        let calls = self.calls.lock().await;
        calls.values().map(|c| CallSnapshot {
            uuid: c.uuid.clone(),
            state: c.state.as_str().to_string(),
            inbound_call_id: c.inbound.call_id.clone(),
            caller_addr: c.inbound.remote_addr.to_string(),
            callee_addr: c.outbound.as_ref().map(|l| l.remote_addr.to_string()),
            duration_secs: c.duration_secs(),
            is_webrtc: c.caller_is_webrtc,
            media_session_id: c.media_session_id.clone(),
        }).collect()
    }
}

/// B2BUA statistics
#[derive(Debug, Clone)]
pub struct B2buaStats {
    pub total_active: usize,
    pub connected: usize,
    pub ringing: usize,
    pub webrtc_calls: usize,
}

/// Lightweight call snapshot (for API / logging)
#[derive(Debug, Clone)]
pub struct CallSnapshot {
    pub uuid: String,
    pub state: String,
    pub inbound_call_id: String,
    pub caller_addr: String,
    pub callee_addr: Option<String>,
    pub duration_secs: u64,
    pub is_webrtc: bool,
    pub media_session_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> B2buaManager {
        let media = Arc::new(MediaManager::with_port_range(20000..30000, None));
        B2buaManager::new(media)
    }

    fn caller_addr() -> SocketAddr { "192.168.1.100:5060".parse().unwrap() }
    fn callee_addr() -> SocketAddr { "192.168.1.200:5060".parse().unwrap() }

    const SIMPLE_SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";

    #[tokio::test]
    async fn test_create_call() {
        let mgr = make_manager();
        let uuid = mgr.create_call(
            "call-id-1".to_string(),
            "tag-a".to_string(),
            caller_addr(),
            Some(SIMPLE_SDP),
            None,
            rsip::Transport::Udp,
        ).await.unwrap();

        assert!(!uuid.is_empty());

        let stats = mgr.stats().await;
        assert_eq!(stats.total_active, 1);
        assert_eq!(stats.connected, 0);
    }

    #[tokio::test]
    async fn test_call_state_progression() {
        let mgr = make_manager();
        let uuid = mgr.create_call(
            "call-2".to_string(), "tag-b".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // Proceeding after create
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Proceeding);
        }

        // Attach outbound leg
        mgr.attach_outbound(&uuid, "call-2-out".to_string(), "tag-sbc".to_string(), callee_addr(),
            None, rsip::Transport::Udp)
            .await.unwrap();

        // 180 Ringing
        mgr.handle_ringing(&uuid).await.unwrap();
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Ringing);
        }

        // 200 OK from callee
        mgr.handle_200_ok(&uuid, "tag-callee".to_string(), None).await.unwrap();

        // ACK from caller → Connected
        mgr.handle_ack(&uuid).await.unwrap();
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Connected);
        }

        let stats = mgr.stats().await;
        assert_eq!(stats.connected, 1);
    }

    #[tokio::test]
    async fn test_bye_terminates_call() {
        let mgr = make_manager();
        let uuid = mgr.create_call(
            "call-3".to_string(), "tag-c".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        mgr.handle_bye(&uuid).await.unwrap();
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Terminating);
        }

        mgr.terminate_call(&uuid).await;
        let stats = mgr.stats().await;
        assert_eq!(stats.total_active, 0);
    }

    #[tokio::test]
    async fn test_find_by_inbound_call_id() {
        let mgr = make_manager();
        mgr.create_call("my-call-id".to_string(), "t".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp)
            .await.unwrap();

        let found = mgr.find_by_inbound_call_id("my-call-id").await;
        assert!(found.is_some());

        let not_found = mgr.find_by_inbound_call_id("unknown").await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_multiple_concurrent_calls() {
        let mgr = make_manager();

        for i in 0..5 {
            mgr.create_call(
                format!("call-{}", i), format!("tag-{}", i), caller_addr(), None,
                None, rsip::Transport::Udp,
            ).await.unwrap();
        }

        let stats = mgr.stats().await;
        assert_eq!(stats.total_active, 5);
    }

    #[tokio::test]
    async fn test_webrtc_call_detected() {
        let webrtc_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=ice-ufrag:abc\r\na=ice-pwd:xyz\r\na=fingerprint:sha-256 AA:BB\r\n";

        let mgr = make_manager();
        let uuid = mgr.create_call(
            "webrtc-call".to_string(), "t".to_string(), caller_addr(), Some(webrtc_sdp),
            None, rsip::Transport::Udp,
        ).await.unwrap();

        {
            let calls = mgr.calls.lock().await;
            assert!(calls[&uuid].caller_is_webrtc);
        } // lock released here

        let stats = mgr.stats().await;
        assert_eq!(stats.webrtc_calls, 1);
    }

    #[tokio::test]
    async fn test_active_calls_snapshot() {
        let mgr = make_manager();
        mgr.create_call("snap-1".to_string(), "t1".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp).await.unwrap();
        mgr.create_call("snap-2".to_string(), "t2".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp).await.unwrap();

        let snaps = mgr.active_calls().await;
        assert_eq!(snaps.len(), 2);
        assert!(snaps.iter().all(|s| s.state == "proceeding"));
    }

    #[tokio::test]
    async fn test_call_duration() {
        let mgr = make_manager();
        let uuid = mgr.create_call("dur-call".to_string(), "t".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp)
            .await.unwrap();

        let calls = mgr.calls.lock().await;
        // Duration should be 0 or very small at creation
        assert!(calls[&uuid].duration_secs() < 2);
    }

    // ── Suffix match tests (Genesys-based trunks Call-ID truncation) ────────

    #[tokio::test]
    async fn test_suffix_match_finds_call() {
        // Trunk sends INVITE with full Call-ID, then BYE with truncated Call-ID
        // INVITE: "14823298-118e8248-104858689_65703785@host"
        // BYE:    "104858689_65703785@host"
        let mgr = make_manager();
        let full_call_id = "14823298-118e8248-104858689_65703785@46.28.168.46";
        let truncated_call_id = "104858689_65703785@46.28.168.46";

        mgr.create_call(
            full_call_id.to_string(), "tag-trunk".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // Exact match should work
        let found = mgr.find_by_inbound_call_id(full_call_id).await;
        assert!(found.is_some(), "Exact Call-ID match should work");

        // Suffix match should find the call
        let found = mgr.find_by_inbound_call_id_suffix(truncated_call_id).await;
        assert!(found.is_some(), "Suffix match should find the call with truncated Call-ID");

        // Unrelated Call-ID should not match
        let found = mgr.find_by_inbound_call_id_suffix("completely-different@host").await;
        assert!(found.is_none(), "Unrelated Call-ID should not match");
    }

    #[tokio::test]
    async fn test_suffix_match_does_not_match_itself() {
        // Suffix match should NOT trigger on exact match (that's what find_by_inbound_call_id is for)
        let mgr = make_manager();
        let call_id = "simple-call-id@host";

        mgr.create_call(
            call_id.to_string(), "tag".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // Exact same Call-ID should NOT be found by suffix match
        let found = mgr.find_by_inbound_call_id_suffix(call_id).await;
        assert!(found.is_none(), "Exact same Call-ID should not trigger suffix match");
    }

    #[tokio::test]
    async fn test_find_by_any_call_id_with_source_ip_disambiguation() {
        // When both legs share the same Call-ID (half-B2BUA), source IP disambiguates
        let mgr = make_manager();
        let call_id = "shared-call-id@host";
        let trunk_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();

        let uuid = mgr.create_call(
            call_id.to_string(), "tag-caller".to_string(), user_addr, None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        mgr.attach_outbound(
            &uuid, call_id.to_string(), "tag-sbc".to_string(), trunk_addr,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // BYE from trunk (callee) → should return is_from_caller = false
        let result = mgr.find_by_any_call_id_with_source(call_id, Some(trunk_addr)).await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(!is_from_caller, "BYE from trunk IP should be identified as from callee");

        // BYE from user (caller) → should return is_from_caller = true
        let result = mgr.find_by_any_call_id_with_source(call_id, Some(user_addr)).await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(is_from_caller, "BYE from user IP should be identified as from caller");
    }

    #[tokio::test]
    async fn test_find_by_any_call_id_trunk_different_port() {
        // Genesys sends BYE from different port than INVITE (same IP)
        let mgr = make_manager();
        let call_id = "genesys-call@host";
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();
        let trunk_invite_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let trunk_bye_addr: SocketAddr = "198.51.100.10:6789".parse().unwrap();

        let uuid = mgr.create_call(
            call_id.to_string(), "tag".to_string(), user_addr, None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        mgr.attach_outbound(
            &uuid, call_id.to_string(), "tag-out".to_string(), trunk_invite_addr,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // BYE from trunk with different port → IP-only fallback should match callee
        let result = mgr.find_by_any_call_id_with_source(call_id, Some(trunk_bye_addr)).await;
        assert!(result.is_some());
        let (_uuid, is_from_caller) = result.unwrap();
        assert!(!is_from_caller, "BYE from trunk IP (different port) should be from callee via IP fallback");
    }

    #[tokio::test]
    async fn test_suffix_match_with_source_disambiguation() {
        // Combines both: truncated Call-ID + source IP disambiguation
        let mgr = make_manager();
        let full_call_id = "36f34d8-ad54ea8-57191931_133@host";
        let truncated = "57191931_133@host";
        let trunk_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();

        let uuid = mgr.create_call(
            full_call_id.to_string(), "tag".to_string(), user_addr, None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        mgr.attach_outbound(
            &uuid, full_call_id.to_string(), "tag-out".to_string(), trunk_addr,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // BYE with truncated Call-ID from trunk → suffix match + callee disambiguation
        let result = mgr.find_by_any_call_id_with_source(truncated, Some(trunk_addr)).await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(!is_from_caller, "Suffix match + trunk IP should identify callee");
    }

    #[tokio::test]
    async fn test_stray_bye_after_termination() {
        // Trunk sends a second orphan BYE after call is already terminated
        // The call should be gone from the manager
        let mgr = make_manager();
        let call_id = "orphan-bye-test@host";

        let uuid = mgr.create_call(
            call_id.to_string(), "tag".to_string(), caller_addr(), None,
            None, rsip::Transport::Udp,
        ).await.unwrap();

        // Terminate the call
        mgr.handle_bye(&uuid).await.unwrap();
        mgr.terminate_call(&uuid).await;

        // Orphan BYE arrives — call should not be found
        let result = mgr.find_by_any_call_id(call_id).await;
        assert!(result.is_none(), "Terminated call should not be found by orphan BYE");
    }
}
