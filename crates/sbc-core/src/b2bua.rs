//! B2BUA - Back-to-Back User Agent (RFC 3261)
//!
//! The B2BUA maintains two independent SIP dialogs:
//!   - Inbound leg  (UAC → SBC): the SBC acts as UAS
//!   - Outbound leg (SBC → UAS): the SBC acts as UAC
//!
//! This allows full control over call routing, NAT traversal,
//! codec normalisation, and media anchoring.

use crate::media::webrtc_handler::WebRtcSession;
use crate::media::{MediaManager, WebRtcSdpInfo};
use crate::{Error, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
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
            Self::Initiated => "initiated",
            Self::Proceeding => "proceeding",
            Self::Ringing => "ringing",
            Self::Connected => "connected",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
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

/// Active-failover state for the outbound INVITE (multi-trunk).
#[derive(Debug, Clone)]
pub struct FailoverState {
    /// Remaining candidate trunk ids, in LCR order (first = next to try).
    pub candidates: Vec<crate::routing::TrunkId>,
    /// Attempt number (1 = first trunk).
    pub attempt: u32,
    /// When the current INVITE attempt was sent.
    pub invite_sent_at: std::time::Instant,
    /// A dialog-progressing provisional (>=180) arrived — no more failover.
    pub provisional_received: bool,
}

/// RFC 4028 session-timer state for one call.
#[derive(Debug, Clone)]
pub struct SessionTimerState {
    /// Negotiated Session-Expires (seconds).
    pub interval_secs: u32,
    /// Min-SE to carry in refresh re-INVITEs (raised by a peer's 422).
    pub min_se: u32,
    /// When the next refresh re-INVITE is due (start + interval/2).
    pub next_refresh_at: std::time::Instant,
    /// CSeq of an in-flight refresh re-INVITE (to match its 200 OK).
    pub pending_refresh_cseq: Option<u32>,
    /// Raw in-flight refresh re-INVITE, so a non-2xx answer can be ACKed.
    pub pending_refresh_raw: Option<String>,
    /// Most recent refresh re-INVITE (CSeq, raw), kept after its answer so
    /// a retransmitted answer can be re-ACKed instead of being mistaken
    /// for a final of the callee-leg INVITE.
    pub last_refresh: Option<(u32, String)>,
    /// Consecutive failed refreshes (reset by a 2xx or a 422 that raised
    /// the interval): drives the retry backoff and the give-up budget.
    pub refresh_failures: u32,
}

/// Outcome of a non-2xx answer to the SBC's own refresh re-INVITE.
#[derive(Debug)]
pub struct RefreshFailure {
    /// ACK for the rejected re-INVITE (None when its raw text is unknown).
    pub ack: Option<String>,
    pub dest: SocketAddr,
    pub transport: rsip::Transport,
    pub reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// The peer no longer has the dialog (481/408, or refreshes keep
    /// failing): the caller must tear the call down.
    pub dialog_gone: bool,
}

/// Refresh failures tolerated before the session is considered dead.
const MAX_REFRESH_FAILURES: u32 = 3;

/// One INVITE transaction the SBC sent toward the callee: the initial
/// forward, a 407/422 retry or a failover re-send. Responses are attributed
/// to attempts by Via branch, so a late answer from a superseded attempt
/// (retransmitted 422, 487 after a failover CANCEL) is ACKed and dropped
/// instead of being mistaken for the live transaction.
#[derive(Debug, Clone)]
pub struct InviteAttempt {
    /// Raw INVITE exactly as sent (source for CANCEL / non-2xx ACK).
    pub raw: String,
    /// Top Via branch of `raw` (None when unparsable).
    pub branch: Option<String>,
    /// CSeq number of `raw`.
    pub cseq: u32,
    /// Where the INVITE was sent (ACK/CANCEL go to the same place).
    pub dest: SocketAddr,
    pub transport: rsip::Transport,
    /// Trunk the attempt targeted (None for registrar-routed callees).
    pub trunk_id: Option<crate::routing::TrunkId>,
}

/// Maximum attempts remembered per call (initial + retries + failovers).
const MAX_INVITE_ATTEMPTS: usize = 8;

/// Which INVITE transaction a callee-leg response belongs to.
#[derive(Debug, Clone)]
pub enum InviteResponseClass {
    /// The transaction currently in flight.
    Current,
    /// A superseded attempt (retried or failed over). Carries the attempt
    /// so the response can still be ACKed; None when it cannot be found.
    Stale(Option<InviteAttempt>),
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
    /// Wall-clock INVITE time (CDR `started_at`).
    pub started_wall: std::time::SystemTime,
    /// Wall-clock time of the 200 OK toward the caller (CDR `answered_at`);
    /// None while ringing. Set once, 200 OK retransmissions leave it alone.
    pub answered_at: Option<std::time::SystemTime>,
    /// Reason header the peer put on its BYE (CDR `reason`).
    pub peer_reason: Option<String>,
    /// The caller's INVITE `To` (no tag): needed to build a final response
    /// toward a caller whose INVITE the SBC never answered.
    pub caller_to_raw: Option<String>,

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

    /// CSeq number of the caller's INVITE. The trunk leg starts with the
    /// same number but every retry bumps it, so responses relayed back to
    /// the caller get this value restored.
    pub caller_invite_cseq: Option<u32>,

    /// INVITE transactions sent toward the callee, oldest first; the last
    /// one is live. Mirrored into `original_outbound_invite` / `trunk_id`
    /// / `callee_dest` for the existing readers.
    pub invite_attempts: Vec<InviteAttempt>,

    // ── Outbound trunk auth (407 retry) ─────────────────────────────
    /// Raw outbound INVITE (topology-hidden) as last sent — 407/422 retries
    /// and failover rebuild from it; CANCEL/BYE/refresh derive their CSeq
    /// and branch from it.
    pub original_outbound_invite: Option<String>,

    /// Trunk ID used for this call (for credential lookup on 407)
    pub trunk_id: Option<crate::routing::TrunkId>,

    /// Number of auth retries attempted (capped at 1 to prevent loops)
    pub auth_retry_count: u32,

    /// RFC 4028 §7.4 retries after a 422 for the current trunk attempt
    /// (capped at 1; reset by failover).
    pub session_timer_retry_count: u32,

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

    /// Multi-trunk failover state (None for registrar-routed calls)
    pub failover: Option<FailoverState>,

    /// RFC 4028 session-timer state (None = timers off for this call)
    pub session_timer: Option<SessionTimerState>,

    /// SDP body as last sent to the caller (rewritten 200 OK) — used to
    /// answer refresh re-INVITEs with an unchanged offer.
    pub last_sdp_to_caller: Option<String>,
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
            started_wall: std::time::SystemTime::now(),
            answered_at: None,
            peer_reason: None,
            caller_to_raw: None,
            caller_reply_tx,
            caller_source: inbound_addr,
            caller_transport,
            callee_reply_tx: None,
            callee_dest: None,
            callee_transport: rsip::Transport::Udp,
            callee_request_uri: None,
            caller_original_vias: Vec::new(),
            caller_invite_cseq: None,
            invite_attempts: Vec::new(),
            original_outbound_invite: None,
            trunk_id: None,
            auth_retry_count: 0,
            session_timer_retry_count: 0,
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
            failover: None,
            session_timer: None,
            last_sdp_to_caller: None,
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

    /// CSeq for the next request the SBC sends toward the callee: above the
    /// live INVITE attempt (a 407/422 retry raised it past the first INVITE)
    /// and above whatever the leg counter already used (RFC 3261 §12.2.1.1).
    pub fn next_outbound_cseq(&self) -> u32 {
        let invite_cseq = self
            .invite_attempts
            .last()
            .map(|a| a.cseq)
            .or_else(|| {
                self.original_outbound_invite
                    .as_deref()
                    .and_then(parse_cseq_number)
            })
            .unwrap_or(0);
        let leg = self.outbound.as_ref().map(|l| l.cseq).unwrap_or(0);
        invite_cseq.max(leg) + 1
    }

    /// In-dialog BYE toward the callee for a call the SBC tears down on its
    /// own (max duration, shutdown, lost WS connection). None until the
    /// callee leg is established (a pending INVITE must be CANCELed instead).
    pub fn bye_toward_callee(
        &self,
        local_ip: &str,
        local_port: u16,
        reason: Option<&str>,
    ) -> Option<String> {
        let mut d = self.dialog_info_toward_callee(local_ip, local_port)?;
        d.cseq = self.next_outbound_cseq();
        Some(crate::sip_builder::build_bye(&d, reason))
    }

    /// CDR direction: `outbound` (user → trunk), `inbound` (trunk → user,
    /// i.e. the source IP belongs to a trunk), else `local` (user → user).
    pub fn direction(&self) -> &'static str {
        if self.trunk_id.is_some() {
            "outbound"
        } else if self.trunk_name.is_some() {
            "inbound"
        } else {
            "local"
        }
    }

    /// A final response to the caller's still-unanswered INVITE, built from
    /// the identity captured when it arrived (its own Via list, From, To,
    /// Call-ID and CSeq), for teardowns the SBC initiates while ringing.
    pub fn final_toward_caller(&self, code: u16, reason: Option<&str>) -> Option<String> {
        if self.caller_original_vias.is_empty() {
            return None;
        }
        let from = self.inbound.from_raw.as_deref()?;
        let to = self.caller_to_raw.as_deref()?;
        let cseq = self.caller_invite_cseq?;
        let phrase = rsip::StatusCode::from(code).reason_phrase().to_string();
        let mut out = format!("SIP/2.0 {} {}\r\n", code, phrase);
        for via in &self.caller_original_vias {
            out.push_str(via);
            out.push_str("\r\n");
        }
        out.push_str(&format!("From: {}\r\n", from));
        out.push_str(&format!(
            "To: {};tag=sbc-{}\r\n",
            to,
            &self.uuid[..8.min(self.uuid.len())]
        ));
        out.push_str(&format!("Call-ID: {}\r\n", self.inbound.call_id));
        out.push_str(&format!("CSeq: {} INVITE\r\n", cseq));
        if let Some(r) = reason {
            out.push_str(&format!("Reason: {}\r\n", r));
        }
        out.push_str("Content-Length: 0\r\n\r\n");
        Some(out)
    }
}

/// True when both addresses are IPv4 and share a /24 (clustered trunks
/// answer from sibling hosts of the one the INVITE was sent to).
fn same_ipv4_subnet24(a: std::net::IpAddr, b: std::net::IpAddr) -> bool {
    match (a, b) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        _ => false,
    }
}

/// Extract the body (after the blank line) from a raw SIP message.
fn extract_body(raw: &str) -> Option<String> {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .filter(|b| !b.is_empty())
}

/// Extract the CSeq number from a raw SIP message.
pub(crate) fn parse_cseq_number(raw: &str) -> Option<u32> {
    raw.split("\r\n")
        .find(|l| l.to_lowercase().starts_with("cseq:"))
        .and_then(|l| l["cseq:".len()..].split_whitespace().next())
        .and_then(|n| n.parse().ok())
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

    /// Recently terminated dialogs (Call-IDs + when), so late BYEs
    /// (Genesys sends them 1-8 min after teardown) are recognized as benign
    /// instead of logged as phantom sessions. Pruned on insert; cap 256.
    recent_terminated: std::sync::Mutex<std::collections::VecDeque<RecentDialog>>,
}

#[derive(Debug, Clone)]
struct RecentDialog {
    inbound_call_id: String,
    outbound_call_id: Option<String>,
    terminated_at: std::time::Instant,
    /// Last INVITE sent toward the callee, so a final response that lands
    /// after teardown (487 after a caller CANCEL) can still be ACKed.
    last_attempt: Option<InviteAttempt>,
}

/// How long a terminated dialog stays recognizable for late BYEs.
const RECENT_DIALOG_TTL: Duration = Duration::from_secs(600);

impl B2buaManager {
    pub fn new(media: Arc<MediaManager>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
            media,
            events: std::sync::RwLock::new(None),
            recent_terminated: std::sync::Mutex::new(std::collections::VecDeque::new()),
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
            match self
                .media
                .create_session(inbound_call_id.clone(), Some(sdp))
                .await
            {
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
        let call = calls
            .get_mut(uuid)
            .ok_or_else(|| Error::Dialog(format!("B2BUA call {} not found", uuid)))?;

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
        to_raw: Option<String>,
        caller_contact: Option<String>,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.inbound.from_raw = Some(from_raw);
            call.caller_to_raw = to_raw;
            call.inbound.remote_target = caller_contact;
        }
    }

    /// Reason header the peer put on its BYE (goes into the CDR).
    pub async fn set_peer_reason(&self, uuid: &CallUuid, reason: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.peer_reason = Some(reason);
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

    /// Arm multi-trunk failover: remaining candidates in LCR order.
    pub async fn set_failover_candidates(
        &self,
        uuid: &CallUuid,
        candidates: Vec<crate::routing::TrunkId>,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.failover = Some(FailoverState {
                candidates,
                attempt: 1,
                invite_sent_at: std::time::Instant::now(),
                provisional_received: false,
            });
        }
    }

    /// A >=180 provisional arrived: the current trunk is progressing the
    /// dialog — disable failover for this call.
    pub async fn mark_provisional_received(&self, uuid: &CallUuid) {
        let mut calls = self.calls.lock().await;
        if let Some(fo) = calls.get_mut(uuid).and_then(|c| c.failover.as_mut()) {
            fo.provisional_received = true;
        }
    }

    /// Pop the next failover candidate and reset the attempt clock.
    /// None when failover is unarmed, already progressing, or exhausted.
    pub async fn take_next_failover_candidate(
        &self,
        uuid: &CallUuid,
    ) -> Option<crate::routing::TrunkId> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid)?;
        let fo = call.failover.as_mut()?;
        if fo.provisional_received || fo.candidates.is_empty() {
            return None;
        }
        let next = fo.candidates.remove(0);
        fo.attempt += 1;
        fo.invite_sent_at = std::time::Instant::now();
        Some(next)
    }

    /// Calls still waiting on their outbound INVITE past `timeout`:
    /// (uuid, attempt, has_remaining_candidates).
    pub async fn invite_attempts_timed_out(&self, timeout: Duration) -> Vec<(CallUuid, u32, bool)> {
        let calls = self.calls.lock().await;
        calls
            .values()
            .filter(|c| {
                matches!(c.state, CallState::Initiated | CallState::Proceeding)
                    && c.failover.as_ref().is_some_and(|f| {
                        !f.provisional_received && f.invite_sent_at.elapsed() > timeout
                    })
            })
            .map(|c| {
                let f = c.failover.as_ref().unwrap();
                (c.uuid.clone(), f.attempt, !f.candidates.is_empty())
            })
            .collect()
    }

    /// Arm the RFC 4028 session timer: SBC refreshes the callee (trunk) leg.
    /// `min_se` is carried in every refresh re-INVITE.
    pub async fn set_session_timer(&self, uuid: &CallUuid, interval_secs: u32, min_se: u32) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.session_timer = Some(SessionTimerState {
                interval_secs,
                min_se,
                next_refresh_at: std::time::Instant::now()
                    + Duration::from_secs((interval_secs / 2).max(30) as u64),
                pending_refresh_cseq: None,
                pending_refresh_raw: None,
                last_refresh: None,
                refresh_failures: 0,
            });
            info!(
                "Session timer armed for call {}: {}s (refresh every {}s, Min-SE {})",
                uuid,
                interval_secs,
                (interval_secs / 2).max(30),
                min_se
            );
        }
    }

    /// Whether `cseq` is the SBC's own in-flight refresh re-INVITE on this call.
    pub async fn is_pending_refresh(&self, uuid: &CallUuid, cseq: u32) -> bool {
        let calls = self.calls.lock().await;
        calls
            .get(uuid)
            .and_then(|c| c.session_timer.as_ref())
            .is_some_and(|st| st.pending_refresh_cseq == Some(cseq))
    }

    /// A non-2xx answer to our refresh re-INVITE. Clears the pending CSeq
    /// and returns the ACK to send. A 422 raises the interval / Min-SE to
    /// what the peer demands and the next tick retries; any other rejection
    /// is retried with backoff. `dialog_gone` is set when the peer proved it
    /// lost the dialog (481 / 408) or refreshes keep failing — the caller
    /// must then tear the call down instead of keeping a zombie session.
    pub async fn fail_session_refresh(
        &self,
        uuid: &CallUuid,
        cseq: u32,
        status: u16,
        min_se_422: Option<u32>,
        response_to: &str,
    ) -> Option<RefreshFailure> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid)?;
        let st = call.session_timer.as_mut()?;
        if st.pending_refresh_cseq != Some(cseq) {
            return None;
        }
        st.pending_refresh_cseq = None;
        let raw = st.pending_refresh_raw.take();
        let ack = raw.and_then(|r| crate::sip_builder::build_ack_for_non_2xx(&r, response_to));

        // 491 Request Pending (RFC 3261 §14.1): the peer has its own
        // re-INVITE in flight — not a failure. Retry after 2.1–4 s: in half
        // mode neither side owns the Call-ID, so a mid-range delay breaks
        // the symmetric glare (the 30 s tick makes it the next tick anyway).
        if status == 491 {
            use rand::Rng;
            let delay_ms = 2100 + rand::thread_rng().gen_range(0..1900u64);
            st.next_refresh_at = std::time::Instant::now() + Duration::from_millis(delay_ms);
            info!(
                "Session refresh 491 for call {} (CSeq {}) — glare, retrying in {} ms",
                uuid, cseq, delay_ms
            );
            return Some(RefreshFailure {
                ack,
                dest: call.callee_dest?,
                transport: call.callee_transport,
                reply_tx: call.callee_reply_tx.clone(),
                dialog_gone: false,
            });
        }

        // 405 / 501 / 420: the peer does not do re-INVITE refreshes at
        // all. Stop refreshing this call and keep it (its own timer, if
        // any, is the peer's business).
        if matches!(status, 405 | 501 | 420) {
            warn!(
                "Session refresh rejected {} for call {} (CSeq {}) — peer does not support re-INVITE refresh, timer disabled for this call",
                status, uuid, cseq
            );
            call.session_timer = None;
            return Some(RefreshFailure {
                ack,
                dest: call.callee_dest?,
                transport: call.callee_transport,
                reply_tx: call.callee_reply_tx.clone(),
                dialog_gone: false,
            });
        }
        let st = call.session_timer.as_mut()?;

        // A 422 that actually raises the interval is progress, not a failure.
        let progressed = status == 422 && min_se_422.is_some_and(|m| m > st.interval_secs);
        if status == 422 {
            if let Some(min) = min_se_422 {
                st.interval_secs = st.interval_secs.max(min);
                st.min_se = st.min_se.max(min);
            }
        }
        if progressed {
            st.refresh_failures = 0;
        } else {
            st.refresh_failures += 1;
        }
        let dialog_gone =
            matches!(status, 408 | 481) || st.refresh_failures >= MAX_REFRESH_FAILURES;
        let backoff_secs =
            (30u64 << st.refresh_failures.min(4)).min((st.interval_secs / 2).max(30) as u64);
        st.next_refresh_at = std::time::Instant::now() + Duration::from_secs(backoff_secs);
        if dialog_gone {
            warn!(
                "Session refresh rejected {} for call {} (CSeq {}, {} consecutive failures) — dialog gone, tearing down",
                status, uuid, cseq, st.refresh_failures
            );
        } else {
            warn!(
                "Session refresh rejected {} for call {} (CSeq {}) — session kept, next refresh in {}s (interval {}s, Min-SE {})",
                status, uuid, cseq, backoff_secs, st.interval_secs, st.min_se
            );
        }
        Some(RefreshFailure {
            ack,
            dest: call.callee_dest?,
            transport: call.callee_transport,
            reply_tx: call.callee_reply_tx.clone(),
            dialog_gone,
        })
    }

    /// A retransmitted answer to a refresh re-INVITE whose outcome was
    /// already consumed (its CSeq matches the last refresh sent). Returns
    /// the ACK to re-send (None for a 1xx) with its destination; outer
    /// None when `cseq` is not a known refresh.
    pub async fn refresh_duplicate_ack(
        &self,
        uuid: &CallUuid,
        cseq: u32,
        status: u16,
        response_to: &str,
        local_ip: &str,
        local_port: u16,
    ) -> Option<(
        Option<String>,
        SocketAddr,
        rsip::Transport,
        Option<mpsc::UnboundedSender<Vec<u8>>>,
    )> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        let st = call.session_timer.as_ref()?;
        let (last_cseq, raw) = st.last_refresh.as_ref()?;
        if *last_cseq != cseq {
            return None;
        }
        let ack = match status {
            100..=199 => None,
            200..=299 => call
                .dialog_info_toward_callee(local_ip, local_port)
                .map(|d| crate::sip_builder::build_ack_for_2xx(&d, cseq)),
            _ => crate::sip_builder::build_ack_for_non_2xx(raw, response_to),
        };
        Some((
            ack,
            call.callee_dest?,
            call.callee_transport,
            call.callee_reply_tx.clone(),
        ))
    }

    /// Record the negotiated media codec for a call (from the SDP answer),
    /// so it appears in the CDR. Idempotent; only sets when not already known.
    pub async fn set_codec(&self, uuid: &CallUuid, codec: &str) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            if call.codec.is_none() {
                call.codec = Some(codec.to_string());
            }
        }
    }

    /// Connected calls whose refresh is due. For each, returns the refresh
    /// re-INVITE (built from the callee-leg dialog identity + the SDP of the
    /// outbound INVITE) and the destination; bumps CSeq and re-arms the timer.
    pub async fn due_session_refreshes(
        &self,
        local_ip: &str,
        local_port: u16,
    ) -> Vec<(
        CallUuid,
        String,
        SocketAddr,
        rsip::Transport,
        Option<mpsc::UnboundedSender<Vec<u8>>>,
    )> {
        let mut out = Vec::new();
        let mut calls = self.calls.lock().await;
        let now = std::time::Instant::now();
        for call in calls.values_mut() {
            if call.state != CallState::Connected {
                continue;
            }
            let Some(dest) = call.callee_dest else {
                continue;
            };
            let Some(st) = call.session_timer.as_ref() else {
                continue;
            };
            if st.next_refresh_at > now || st.pending_refresh_cseq.is_some() {
                continue;
            }
            let Some(mut d) = call.dialog_info_toward_callee(local_ip, local_port) else {
                continue;
            };
            // SDP previously sent to the callee = body of the outbound INVITE
            let sdp = call
                .original_outbound_invite
                .as_deref()
                .and_then(extract_body)
                .unwrap_or_default();
            if sdp.is_empty() {
                continue; // no SDP to refresh with — skip rather than break media
            }
            let invite_cseq = call
                .original_outbound_invite
                .as_deref()
                .and_then(parse_cseq_number)
                .unwrap_or(1);
            let leg_cseq = call.outbound.as_ref().map(|l| l.cseq).unwrap_or(1);
            d.cseq = invite_cseq.max(leg_cseq) + 1;
            if let Some(leg) = call.outbound.as_mut() {
                leg.cseq = d.cseq;
            }

            let interval = st.interval_secs;
            let min_se = st.min_se;
            let contact = format!("<sip:sbc@{}:{}>", local_ip, local_port);
            let reinvite = crate::sip_builder::build_reinvite(
                &d,
                &sdp,
                &contact,
                Some((interval, "uac")),
                Some(min_se),
            );
            if let Some(st) = call.session_timer.as_mut() {
                st.pending_refresh_cseq = Some(d.cseq);
                st.pending_refresh_raw = Some(reinvite.clone());
                st.last_refresh = Some((d.cseq, reinvite.clone()));
                st.next_refresh_at = now + Duration::from_secs((interval / 2).max(30) as u64);
            }
            out.push((
                call.uuid.clone(),
                reinvite,
                dest,
                call.callee_transport,
                call.callee_reply_tx.clone(),
            ));
        }
        out
    }

    /// If `cseq` matches an in-flight refresh re-INVITE for this call,
    /// consume it and return the ACK to send. The 200 OK must NOT be
    /// relayed to the caller.
    pub async fn complete_session_refresh(
        &self,
        uuid: &CallUuid,
        cseq: u32,
        local_ip: &str,
        local_port: u16,
    ) -> Option<(
        String,
        SocketAddr,
        rsip::Transport,
        Option<mpsc::UnboundedSender<Vec<u8>>>,
    )> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid)?;
        let st = call.session_timer.as_mut()?;
        if st.pending_refresh_cseq != Some(cseq) {
            return None;
        }
        st.pending_refresh_cseq = None;
        st.pending_refresh_raw = None;
        st.refresh_failures = 0;
        info!(
            "Session refresh confirmed for call {} (CSeq {})",
            uuid, cseq
        );
        let d = call.dialog_info_toward_callee(local_ip, local_port)?;
        let ack = crate::sip_builder::build_ack_for_2xx(&d, cseq);
        Some((
            ack,
            call.callee_dest?,
            call.callee_transport,
            call.callee_reply_tx.clone(),
        ))
    }

    /// Store the SDP as last sent to the caller (rewritten 200 OK body).
    pub async fn set_last_sdp_to_caller(&self, uuid: &CallUuid, sdp: String) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.last_sdp_to_caller = Some(sdp);
        }
    }

    /// Get the media session ID for a call (for SDP rewriting / RTP proxy)
    pub async fn get_media_session_id(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.media_session_id.clone())
    }

    /// Get the callee's reply channel and transport info (for sending BYE to callee)
    pub async fn get_callee_reply_info(
        &self,
        uuid: &CallUuid,
    ) -> Option<(
        Option<mpsc::UnboundedSender<Vec<u8>>>,
        SocketAddr,
        rsip::Transport,
    )> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| {
            c.callee_dest
                .map(|dest| (c.callee_reply_tx.clone(), dest, c.callee_transport))
        })
    }

    /// Get the callee's Request-URI (for ACK relay)
    /// Remote target for requests toward the callee: the Contact of its
    /// 2xx once known (RFC 3261 §12.1.2 — the ACK and every in-dialog
    /// request go there), else the Request-URI the INVITE was sent to.
    pub async fn get_callee_contact_uri(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        call.outbound
            .as_ref()
            .and_then(|leg| leg.remote_target.clone())
            .or_else(|| call.callee_request_uri.clone())
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
        let call = calls
            .get_mut(uuid)
            .ok_or_else(|| Error::Dialog(format!("B2BUA call {} not found", uuid)))?;
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
        let call = calls
            .get_mut(uuid)
            .ok_or_else(|| Error::Dialog(format!("B2BUA call {} not found", uuid)))?;

        call.callee_sdp = callee_sdp.clone();
        call.establish_outbound(callee_tag);
        let first_answer = call.answered_at.is_none();
        if first_answer {
            call.answered_at = Some(std::time::SystemTime::now());
        }

        // Update media session with callee SDP
        if let (Some(media_id), Some(sdp)) = (&call.media_session_id.clone(), callee_sdp) {
            if let Err(e) = self.media.update_callee_sdp(media_id, &sdp) {
                warn!("B2BUA: could not update callee SDP: {}", e);
            }
        }

        info!("B2BUA: call {} state → {}", uuid, call.state.as_str());
        drop(calls);
        // 200 OK retransmissions re-enter here: one SSE event per call.
        if first_answer {
            self.emit(crate::events::SbcEvent::CallAnswered {
                uuid: uuid.clone(),
                ts: crate::events::event_ts(),
            });
        }
        Ok(())
    }

    /// Handle ACK from caller (inbound leg established)
    pub async fn handle_ack(&self, uuid: &CallUuid) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls
            .get_mut(uuid)
            .ok_or_else(|| Error::Dialog(format!("B2BUA call {} not found", uuid)))?;

        call.establish_inbound(call.inbound.remote_tag.clone().unwrap_or_default());

        if call.outbound.as_ref().is_some_and(|l| l.established) {
            call.state = CallState::Connected;
        }

        info!(
            "B2BUA: ACK received, call {} state → {}",
            uuid,
            call.state.as_str()
        );
        Ok(())
    }

    /// Handle BYE (from either leg) — tears down both legs
    pub async fn handle_bye(&self, uuid: &CallUuid) -> Result<()> {
        let mut calls = self.calls.lock().await;
        let call = calls
            .get_mut(uuid)
            .ok_or_else(|| Error::Dialog(format!("B2BUA call {} not found", uuid)))?;

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

    /// Mark call as fully terminated (`CallEnded` reason "terminated").
    /// Handler code goes through `Sbc::finish_call`, which passes the real
    /// cause; this form remains for direct callers (API, tests).
    pub async fn terminate_call(&self, uuid: &CallUuid) {
        self.terminate_call_with_reason(uuid, "terminated").await
    }

    /// Release the call and publish `CallEnded { reason }`.
    pub async fn terminate_call_with_reason(&self, uuid: &CallUuid, reason: &str) {
        let mut calls = self.calls.lock().await;
        let duration = if let Some(call) = calls.get_mut(uuid) {
            call.state = CallState::Terminated;
            info!(
                "B2BUA: call {} terminated (duration {}s)",
                uuid,
                call.duration_secs()
            );
            Some(call.duration_secs())
        } else {
            None
        };
        if let Some(call) = calls.get(uuid) {
            // Release the RTP port pair here so every teardown path (error
            // relay, API kick, invalid destination…) frees it, not only BYE.
            if let Some(media_id) = &call.media_session_id {
                if let Err(e) = self.media.terminate_session(media_id) {
                    debug!("B2BUA: media session already gone: {}", e);
                }
            }
            self.remember_terminated(
                call.inbound.call_id.clone(),
                call.outbound.as_ref().map(|l| l.call_id.clone()),
                call.invite_attempts.last().cloned(),
            );
        }
        calls.remove(uuid);
        drop(calls);

        if let Some(duration_secs) = duration {
            self.emit(crate::events::SbcEvent::CallEnded {
                uuid: uuid.clone(),
                duration_secs,
                reason: reason.to_string(),
                ts: crate::events::event_ts(),
            });
        }
    }

    fn remember_terminated(
        &self,
        inbound_call_id: String,
        outbound_call_id: Option<String>,
        last_attempt: Option<InviteAttempt>,
    ) {
        if let Ok(mut recent) = self.recent_terminated.lock() {
            let now = std::time::Instant::now();
            recent.retain(|d| now.duration_since(d.terminated_at) < RECENT_DIALOG_TTL);
            recent.push_back(RecentDialog {
                inbound_call_id,
                outbound_call_id,
                terminated_at: now,
                last_attempt,
            });
            while recent.len() > 256 {
                recent.pop_front();
            }
        }
    }

    /// Last INVITE attempt of a recently terminated dialog whose Call-ID
    /// matches (exact or Genesys-truncated suffix), for ACKing a stray
    /// final response after teardown.
    pub fn recent_attempt_for_call_id(&self, call_id: &str) -> Option<InviteAttempt> {
        if call_id.is_empty() {
            return None;
        }
        let recent = self.recent_terminated.lock().ok()?;
        let now = std::time::Instant::now();
        recent
            .iter()
            .rev()
            .filter(|d| now.duration_since(d.terminated_at) < RECENT_DIALOG_TTL)
            .find(|d| d.inbound_call_id == call_id || d.inbound_call_id.ends_with(call_id))
            .and_then(|d| d.last_attempt.clone())
    }

    /// Whether a Call-ID matches a dialog terminated within the TTL window.
    /// Matches full Call-IDs and truncated ones (Genesys strips prefixes,
    /// so the late BYE's Call-ID is a suffix of the stored one).
    pub fn was_recently_terminated(&self, call_id: &str) -> bool {
        if call_id.is_empty() {
            return false;
        }
        let Ok(recent) = self.recent_terminated.lock() else {
            return false;
        };
        let now = std::time::Instant::now();
        recent.iter().any(|d| {
            now.duration_since(d.terminated_at) < RECENT_DIALOG_TTL
                && (d.inbound_call_id == call_id
                    || d.inbound_call_id.ends_with(call_id)
                    || d.outbound_call_id
                        .as_deref()
                        .map(|o| o == call_id || o.ends_with(call_id))
                        .unwrap_or(false))
        })
    }

    /// Build a fresh in-dialog BYE toward the callee (used when relaying a
    /// caller BYE): real dialog identity + incremented outbound CSeq.
    /// None when the dialog identity was never captured — caller falls back
    /// to raw relay.
    pub async fn build_relay_bye_toward_callee(
        &self,
        uuid: &CallUuid,
        local_ip: &str,
        local_port: u16,
        reason: Option<&str>,
    ) -> Option<String> {
        let mut calls = self.calls.lock().await;
        let call = calls.get_mut(uuid)?;
        let mut d = call.dialog_info_toward_callee(local_ip, local_port)?;
        // In-dialog CSeq must exceed the live INVITE attempt's (not just the
        // first INVITE's: a 407/422 retry raised it) and the leg counter.
        d.cseq = call.next_outbound_cseq();
        call.outbound.as_mut()?.cseq = d.cseq;
        Some(crate::sip_builder::build_bye(&d, reason))
    }

    /// Build a fresh in-dialog BYE toward the caller (used when relaying a
    /// callee BYE). The SBC has never sent a request in this direction, so
    /// CSeq starts at 1 (own numbering space per RFC 3261 §12.2.1.1).
    pub async fn build_relay_bye_toward_caller(
        &self,
        uuid: &CallUuid,
        local_ip: &str,
        local_port: u16,
        reason: Option<&str>,
    ) -> Option<String> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        let d = call.dialog_info_toward_caller(local_ip, local_port)?;
        Some(crate::sip_builder::build_bye(&d, reason))
    }

    /// Count non-terminated calls originated by `user` (per-user limits).
    /// Derived from live state — no shadow counter to drift.
    pub async fn active_calls_for_user(&self, user: &str) -> u32 {
        let calls = self.calls.lock().await;
        calls
            .values()
            .filter(|c| !matches!(c.state, CallState::Terminated | CallState::Terminating))
            // A PSTN caller whose number happens to match a local username
            // is not that user: inbound trunk calls never count.
            .filter(|c| c.direction() != "inbound")
            .filter(|c| c.caller_number.as_deref() == Some(user))
            .count() as u32
    }

    /// Look up a call by inbound Call-ID
    pub async fn find_by_inbound_call_id(&self, call_id: &str) -> Option<CallUuid> {
        let calls = self.calls.lock().await;
        calls
            .values()
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
        calls
            .values()
            .find(|c| c.inbound.call_id.ends_with(call_id) && c.inbound.call_id != *call_id)
            .map(|c| c.uuid.clone())
    }

    /// Look up a call by outbound Call-ID (the leg SBC→callee)
    pub async fn find_by_outbound_call_id(&self, call_id: &str) -> Option<CallUuid> {
        let calls = self.calls.lock().await;
        calls
            .values()
            .find(|c| {
                c.outbound
                    .as_ref()
                    .is_some_and(|leg| leg.call_id == call_id)
            })
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
            let outbound_matches = call
                .outbound
                .as_ref()
                .is_some_and(|leg| leg.call_id == call_id);

            // Also try suffix match: Genesys-based trunks adds prefixes to Call-IDs
            // e.g. INVITE Call-ID = "14823298-118e8248-104858689_65703785@host"
            //      BYE   Call-ID = "104858689_65703785@host"
            let inbound_suffix = !inbound_matches
                && call.inbound.call_id.ends_with(call_id)
                && call.inbound.call_id != *call_id;
            let outbound_suffix = !outbound_matches
                && call
                    .outbound
                    .as_ref()
                    .is_some_and(|leg| leg.call_id.ends_with(call_id) && leg.call_id != *call_id);

            if !inbound_matches && !outbound_matches && !inbound_suffix && !outbound_suffix {
                continue;
            }

            if inbound_suffix || outbound_suffix {
                info!(
                    "Call-ID suffix match: BYE '{}' matched stored '{}'",
                    call_id, call.inbound.call_id
                );
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

                // Clustered trunks (Genesys) send the BYE from a sibling host
                // of the one the INVITE went to: attribute by /24 before the
                // "prefer inbound" fallback hands an outbound call's BYE to
                // the wrong leg.
                let callee_near = callee_ip.is_some_and(|ip| same_ipv4_subnet24(ip, src_ip));
                let caller_near = same_ipv4_subnet24(caller_ip, src_ip);
                if callee_near && !caller_near {
                    return Some((call.uuid.clone(), false)); // from callee's cluster
                }
                if caller_near && !callee_near {
                    return Some((call.uuid.clone(), true)); // from caller's cluster
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
    pub async fn get_caller_reply_info(
        &self,
        uuid: &CallUuid,
    ) -> Option<(
        Option<mpsc::UnboundedSender<Vec<u8>>>,
        SocketAddr,
        rsip::Transport,
    )> {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| {
            (
                c.caller_reply_tx.clone(),
                c.caller_source,
                c.caller_transport,
            )
        })
    }

    /// Get the stored Call-IDs for a call (inbound + outbound).
    /// Used to rewrite truncated Call-IDs in relayed BYE messages when the
    /// trunk (e.g. Genesys-based trunks) sends BYE with a shortened Call-ID.
    pub async fn get_call_ids(&self, uuid: &CallUuid) -> Option<(String, Option<String>)> {
        let calls = self.calls.lock().await;
        calls.get(uuid).map(|c| {
            (
                c.inbound.call_id.clone(),
                c.outbound.as_ref().map(|l| l.call_id.clone()),
            )
        })
    }

    /// Store the caller's original Via headers (before topology hiding strips
    /// them) and the caller's INVITE CSeq (restored in relayed responses).
    pub async fn set_caller_vias(
        &self,
        uuid: &CallUuid,
        vias: Vec<String>,
        invite_cseq: Option<u32>,
    ) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            debug!(
                "B2BUA: stored {} original Via header(s) for call {}",
                vias.len(),
                uuid
            );
            call.caller_original_vias = vias;
            call.caller_invite_cseq = invite_cseq;
        }
    }

    /// CSeq number of the caller's INVITE (None if never captured).
    pub async fn get_caller_invite_cseq(&self, uuid: &CallUuid) -> Option<u32> {
        let calls = self.calls.lock().await;
        calls.get(uuid).and_then(|c| c.caller_invite_cseq)
    }

    // ── Callee-leg INVITE attempts ───────────────────────────────────

    /// Record an INVITE just sent toward the callee (initial forward, 407 or
    /// 422 retry, failover). Becomes the live transaction: CANCEL, ACK, BYE
    /// and refreshes derive branch/CSeq from it, and the failover no-answer
    /// clock restarts. `outbound.cseq` is deliberately left alone — the
    /// synthetic BYE builders use it verbatim and must stay above it.
    pub async fn push_invite_attempt(
        &self,
        uuid: &CallUuid,
        raw: String,
        dest: SocketAddr,
        transport: rsip::Transport,
        trunk_id: Option<crate::routing::TrunkId>,
    ) {
        let branch = crate::sip_builder::top_via_branch(&raw);
        let cseq = parse_cseq_number(&raw).unwrap_or(1);
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.original_outbound_invite = Some(raw.clone());
            if trunk_id.is_some() {
                call.trunk_id = trunk_id;
            }
            call.callee_dest = Some(dest);
            call.callee_transport = transport;
            if let Some(fo) = call.failover.as_mut() {
                fo.invite_sent_at = std::time::Instant::now();
            }
            call.invite_attempts.push(InviteAttempt {
                raw,
                branch,
                cseq,
                dest,
                transport,
                trunk_id,
            });
            if call.invite_attempts.len() > MAX_INVITE_ATTEMPTS {
                call.invite_attempts.remove(0);
            }
            debug!(
                "B2BUA: INVITE attempt #{} for call {} (CSeq {}, branch {:?}) → {}",
                call.invite_attempts.len(),
                uuid,
                cseq,
                call.invite_attempts
                    .last()
                    .and_then(|a| a.branch.as_deref()),
                dest
            );
        }
    }

    /// The live INVITE attempt toward the callee, with the callee reply channel.
    pub async fn current_attempt(
        &self,
        uuid: &CallUuid,
    ) -> Option<(InviteAttempt, Option<mpsc::UnboundedSender<Vec<u8>>>)> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        Some((
            call.invite_attempts.last()?.clone(),
            call.callee_reply_tx.clone(),
        ))
    }

    /// CSeq number of the live INVITE toward the callee (None before it is sent).
    pub async fn outbound_invite_cseq(&self, uuid: &CallUuid) -> Option<u32> {
        let calls = self.calls.lock().await;
        calls
            .get(uuid)
            .and_then(|c| c.invite_attempts.last())
            .map(|a| a.cseq)
    }

    /// Attribute a callee-leg INVITE response to an attempt. Via branch is
    /// authoritative (a failover re-send keeps the CSeq and changes only the
    /// branch); the CSeq number is the fallback when a branch is missing.
    /// None when the call is unknown; `Current` when nothing was ever sent.
    pub async fn classify_invite_response(
        &self,
        uuid: &CallUuid,
        response_branch: Option<&str>,
        response_cseq: u32,
    ) -> Option<InviteResponseClass> {
        let calls = self.calls.lock().await;
        let call = calls.get(uuid)?;
        let Some(current) = call.invite_attempts.last() else {
            return Some(InviteResponseClass::Current);
        };
        let older = || call.invite_attempts.iter().rev().skip(1);
        if let Some(branch) = response_branch {
            if current.branch.as_deref() == Some(branch) {
                return Some(InviteResponseClass::Current);
            }
            if let Some(a) = older().find(|a| a.branch.as_deref() == Some(branch)) {
                return Some(InviteResponseClass::Stale(Some(a.clone())));
            }
        }
        // Responses echo the request's CSeq, so a CSeq above the live INVITE
        // cannot answer it: it belongs to an in-dialog request of ours (a
        // refresh re-INVITE whose outcome was already consumed). Never relay
        // it, never ACK it from the attempt, never tear the call down on it.
        if response_cseq > current.cseq {
            warn!(
                "B2BUA: response CSeq {} (branch {:?}) is above the live INVITE attempt of call {} (CSeq {}) — not this transaction, dropped",
                response_cseq, response_branch, uuid, current.cseq
            );
            return Some(InviteResponseClass::Stale(None));
        }
        if let Some(branch) = response_branch {
            if current.branch.is_some() && response_cseq == current.cseq {
                warn!(
                    "B2BUA: response branch {} matches no INVITE attempt of call {} (current {:?}) — treating as current",
                    branch, uuid, current.branch
                );
                return Some(InviteResponseClass::Current);
            }
        }
        if response_cseq < current.cseq {
            let by_cseq = older().find(|a| a.cseq == response_cseq).cloned();
            return Some(InviteResponseClass::Stale(by_cseq));
        }
        Some(InviteResponseClass::Current)
    }

    /// Reset the 407 retry budget (a new INVITE transaction may be
    /// challenged once more: 422 retry, failover to another trunk).
    pub async fn reset_auth_retry(&self, uuid: &CallUuid) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.auth_retry_count = 0;
        }
    }

    /// RFC 4028 422 retries already done for the current trunk attempt.
    pub async fn get_session_timer_retry_count(&self, uuid: &CallUuid) -> u32 {
        let calls = self.calls.lock().await;
        calls
            .get(uuid)
            .map(|c| c.session_timer_retry_count)
            .unwrap_or(0)
    }

    /// Count a 422 retry (call after re-sending the INVITE).
    pub async fn increment_session_timer_retry(&self, uuid: &CallUuid) {
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get_mut(uuid) {
            call.session_timer_retry_count += 1;
        }
    }

    /// Get the caller's original Via headers (to restore in responses)
    pub async fn get_caller_vias(&self, uuid: &CallUuid) -> Vec<String> {
        let calls = self.calls.lock().await;
        calls
            .get(uuid)
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
    ) -> Option<(
        String,
        u32,
        SocketAddr,
        Option<mpsc::UnboundedSender<Vec<u8>>>,
        rsip::Transport,
    )> {
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
        let connected = calls
            .values()
            .filter(|c| c.state == CallState::Connected)
            .count();
        let ringing = calls
            .values()
            .filter(|c| c.state == CallState::Ringing)
            .count();
        let webrtc = calls.values().filter(|c| c.caller_is_webrtc).count();
        B2buaStats {
            total_active: total,
            connected,
            ringing,
            webrtc_calls: webrtc,
        }
    }

    /// Get snapshot of all active calls (for REST API / metrics)
    pub async fn active_calls(&self) -> Vec<CallSnapshot> {
        let calls = self.calls.lock().await;
        calls
            .values()
            .map(|c| CallSnapshot {
                uuid: c.uuid.clone(),
                state: c.state.as_str().to_string(),
                inbound_call_id: c.inbound.call_id.clone(),
                caller_addr: c.inbound.remote_addr.to_string(),
                callee_addr: c.outbound.as_ref().map(|l| l.remote_addr.to_string()),
                duration_secs: c.duration_secs(),
                is_webrtc: c.caller_is_webrtc,
                media_session_id: c.media_session_id.clone(),
            })
            .collect()
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

    fn caller_addr() -> SocketAddr {
        "192.168.1.100:5060".parse().unwrap()
    }
    fn callee_addr() -> SocketAddr {
        "192.168.1.200:5060".parse().unwrap()
    }

    const SIMPLE_SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";

    #[tokio::test]
    async fn dialog_identity_and_synthetic_byes() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "full-call-id@host".to_string(),
                "caller-tag".to_string(),
                caller_addr(),
                Some(SIMPLE_SDP),
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        // Before identity capture: no synthetic BYE possible
        assert!(mgr
            .build_relay_bye_toward_caller(&uuid, "1.2.3.4", 5060, None)
            .await
            .is_none());

        mgr.set_inbound_dialog(
            &uuid,
            "<sip:caller@pstn.example.com>;tag=caller-tag".to_string(),
            None,
            Some("sip:caller@192.168.1.100:5060".to_string()),
        )
        .await;
        mgr.attach_outbound(
            &uuid,
            "full-call-id@host".to_string(),
            "sbc-tag".to_string(),
            callee_addr(),
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
        mgr.set_established_dialog(
            &uuid,
            "<sip:caller@pstn.example.com>;tag=caller-tag".to_string(),
            "<sip:callee@sip.example.com>;tag=callee-tag".to_string(),
            Some("sip:callee@192.168.1.200:5060".to_string()),
        )
        .await;

        // Toward caller: From = answered To (callee side), To = caller's From
        let bye = mgr
            .build_relay_bye_toward_caller(&uuid, "1.2.3.4", 5060, None)
            .await
            .unwrap();
        assert!(
            bye.contains("From: <sip:callee@sip.example.com>;tag=callee-tag\r\n"),
            "{}",
            bye
        );
        assert!(bye.contains("To: <sip:caller@pstn.example.com>;tag=caller-tag\r\n"));
        assert!(bye.starts_with("BYE sip:caller@192.168.1.100:5060 SIP/2.0"));
        rsip::SipMessage::try_from(bye.as_bytes().to_vec()).unwrap();

        // Toward callee: From/To as sent on the outbound leg
        let bye2 = mgr
            .build_relay_bye_toward_callee(&uuid, "1.2.3.4", 5060, None)
            .await
            .unwrap();
        assert!(bye2.contains("From: <sip:caller@pstn.example.com>;tag=caller-tag\r\n"));
        assert!(bye2.contains("To: <sip:callee@sip.example.com>;tag=callee-tag\r\n"));
        rsip::SipMessage::try_from(bye2.as_bytes().to_vec()).unwrap();
    }

    #[tokio::test]
    async fn recently_terminated_matches_full_and_truncated_call_ids() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "prefix-prefix-core@host".to_string(),
                "t1".to_string(),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        assert!(!mgr.was_recently_terminated("core@host"));
        mgr.terminate_call(&uuid).await;

        // Full Call-ID and Genesys-truncated suffix both recognized
        assert!(mgr.was_recently_terminated("prefix-prefix-core@host"));
        assert!(mgr.was_recently_terminated("core@host"));
        assert!(!mgr.was_recently_terminated("other@host"));
        assert!(!mgr.was_recently_terminated(""));
    }

    #[tokio::test]
    async fn test_create_call() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "call-id-1".to_string(),
                "tag-a".to_string(),
                caller_addr(),
                Some(SIMPLE_SDP),
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        assert!(!uuid.is_empty());

        let stats = mgr.stats().await;
        assert_eq!(stats.total_active, 1);
        assert_eq!(stats.connected, 0);
    }

    #[tokio::test]
    async fn test_call_state_progression() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "call-2".to_string(),
                "tag-b".to_string(),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        // Proceeding after create
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Proceeding);
        }

        // Attach outbound leg
        mgr.attach_outbound(
            &uuid,
            "call-2-out".to_string(),
            "tag-sbc".to_string(),
            callee_addr(),
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // 180 Ringing
        mgr.handle_ringing(&uuid).await.unwrap();
        {
            let calls = mgr.calls.lock().await;
            assert_eq!(calls[&uuid].state, CallState::Ringing);
        }

        // 200 OK from callee
        mgr.handle_200_ok(&uuid, "tag-callee".to_string(), None)
            .await
            .unwrap();

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
        let uuid = mgr
            .create_call(
                "call-3".to_string(),
                "tag-c".to_string(),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

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
        mgr.create_call(
            "my-call-id".to_string(),
            "t".to_string(),
            caller_addr(),
            None,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

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
                format!("call-{}", i),
                format!("tag-{}", i),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        }

        let stats = mgr.stats().await;
        assert_eq!(stats.total_active, 5);
    }

    /// Concurrency stress test: hammer the call map from many tasks at once to
    /// prove the `Mutex<HashMap>` is correct and deadlock-free well beyond
    /// production volume. Each task creates a call, mutates it through several
    /// locked methods, then half are terminated concurrently. Completion alone
    /// proves no deadlock; the count assertions prove no lost updates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_concurrent_call_storm() {
        use std::time::Instant;
        const N: usize = 200;
        let mgr = Arc::new(make_manager());

        // Phase 1 — N concurrent create + mutate.
        let start = Instant::now();
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let mgr = mgr.clone();
            handles.push(tokio::spawn(async move {
                let uuid = mgr
                    .create_call(
                        format!("storm-{}", i),
                        format!("tag-{}", i),
                        caller_addr(),
                        None,
                        None,
                        rsip::Transport::Udp,
                    )
                    .await
                    .unwrap();
                // Exercise several independent locked mutators + a read.
                mgr.set_codec(&uuid, "PCMU").await;
                mgr.set_session_timer(&uuid, 1800, 90).await;
                let _ = mgr.stats().await;
                uuid
            }));
        }
        let uuids: Vec<CallUuid> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            mgr.stats().await.total_active,
            N,
            "all calls must be present"
        );

        // Phase 2 — terminate half concurrently while the rest stay live.
        let mut handles = Vec::with_capacity(N / 2);
        for uuid in uuids.into_iter().take(N / 2) {
            let mgr = mgr.clone();
            handles.push(tokio::spawn(async move { mgr.terminate_call(&uuid).await }));
        }
        futures_util::future::join_all(handles).await;

        assert_eq!(
            mgr.stats().await.total_active,
            N - N / 2,
            "exactly half remain"
        );
        eprintln!(
            "call storm: {} creates + {} terminates in {:?}",
            N,
            N / 2,
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn test_webrtc_call_detected() {
        let webrtc_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=ice-ufrag:abc\r\na=ice-pwd:xyz\r\na=fingerprint:sha-256 AA:BB\r\n";

        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "webrtc-call".to_string(),
                "t".to_string(),
                caller_addr(),
                Some(webrtc_sdp),
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

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
        mgr.create_call(
            "snap-1".to_string(),
            "t1".to_string(),
            caller_addr(),
            None,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
        mgr.create_call(
            "snap-2".to_string(),
            "t2".to_string(),
            caller_addr(),
            None,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        let snaps = mgr.active_calls().await;
        assert_eq!(snaps.len(), 2);
        assert!(snaps.iter().all(|s| s.state == "proceeding"));
    }

    #[tokio::test]
    async fn test_call_duration() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "dur-call".to_string(),
                "t".to_string(),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

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
            full_call_id.to_string(),
            "tag-trunk".to_string(),
            caller_addr(),
            None,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // Exact match should work
        let found = mgr.find_by_inbound_call_id(full_call_id).await;
        assert!(found.is_some(), "Exact Call-ID match should work");

        // Suffix match should find the call
        let found = mgr.find_by_inbound_call_id_suffix(truncated_call_id).await;
        assert!(
            found.is_some(),
            "Suffix match should find the call with truncated Call-ID"
        );

        // Unrelated Call-ID should not match
        let found = mgr
            .find_by_inbound_call_id_suffix("completely-different@host")
            .await;
        assert!(found.is_none(), "Unrelated Call-ID should not match");
    }

    #[tokio::test]
    async fn test_suffix_match_does_not_match_itself() {
        // Suffix match should NOT trigger on exact match (that's what find_by_inbound_call_id is for)
        let mgr = make_manager();
        let call_id = "simple-call-id@host";

        mgr.create_call(
            call_id.to_string(),
            "tag".to_string(),
            caller_addr(),
            None,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // Exact same Call-ID should NOT be found by suffix match
        let found = mgr.find_by_inbound_call_id_suffix(call_id).await;
        assert!(
            found.is_none(),
            "Exact same Call-ID should not trigger suffix match"
        );
    }

    #[tokio::test]
    async fn test_find_by_any_call_id_with_source_ip_disambiguation() {
        // When both legs share the same Call-ID (half-B2BUA), source IP disambiguates
        let mgr = make_manager();
        let call_id = "shared-call-id@host";
        let trunk_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();

        let uuid = mgr
            .create_call(
                call_id.to_string(),
                "tag-caller".to_string(),
                user_addr,
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        mgr.attach_outbound(
            &uuid,
            call_id.to_string(),
            "tag-sbc".to_string(),
            trunk_addr,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // BYE from trunk (callee) → should return is_from_caller = false
        let result = mgr
            .find_by_any_call_id_with_source(call_id, Some(trunk_addr))
            .await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(
            !is_from_caller,
            "BYE from trunk IP should be identified as from callee"
        );

        // BYE from user (caller) → should return is_from_caller = true
        let result = mgr
            .find_by_any_call_id_with_source(call_id, Some(user_addr))
            .await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(
            is_from_caller,
            "BYE from user IP should be identified as from caller"
        );
    }

    #[tokio::test]
    async fn test_find_by_any_call_id_trunk_different_port() {
        // Genesys sends BYE from different port than INVITE (same IP)
        let mgr = make_manager();
        let call_id = "genesys-call@host";
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();
        let trunk_invite_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let trunk_bye_addr: SocketAddr = "198.51.100.10:6789".parse().unwrap();

        let uuid = mgr
            .create_call(
                call_id.to_string(),
                "tag".to_string(),
                user_addr,
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        mgr.attach_outbound(
            &uuid,
            call_id.to_string(),
            "tag-out".to_string(),
            trunk_invite_addr,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // BYE from trunk with different port → IP-only fallback should match callee
        let result = mgr
            .find_by_any_call_id_with_source(call_id, Some(trunk_bye_addr))
            .await;
        assert!(result.is_some());
        let (_uuid, is_from_caller) = result.unwrap();
        assert!(
            !is_from_caller,
            "BYE from trunk IP (different port) should be from callee via IP fallback"
        );
    }

    #[tokio::test]
    async fn test_suffix_match_with_source_disambiguation() {
        // Combines both: truncated Call-ID + source IP disambiguation
        let mgr = make_manager();
        let full_call_id = "36f34d8-ad54ea8-57191931_133@host";
        let truncated = "57191931_133@host";
        let trunk_addr: SocketAddr = "198.51.100.10:5060".parse().unwrap();
        let user_addr: SocketAddr = "10.0.0.50:5060".parse().unwrap();

        let uuid = mgr
            .create_call(
                full_call_id.to_string(),
                "tag".to_string(),
                user_addr,
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        mgr.attach_outbound(
            &uuid,
            full_call_id.to_string(),
            "tag-out".to_string(),
            trunk_addr,
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();

        // BYE with truncated Call-ID from trunk → suffix match + callee disambiguation
        let result = mgr
            .find_by_any_call_id_with_source(truncated, Some(trunk_addr))
            .await;
        assert!(result.is_some());
        let (found_uuid, is_from_caller) = result.unwrap();
        assert_eq!(found_uuid, uuid);
        assert!(
            !is_from_caller,
            "Suffix match + trunk IP should identify callee"
        );
    }

    #[tokio::test]
    async fn test_stray_bye_after_termination() {
        // Trunk sends a second orphan BYE after call is already terminated
        // The call should be gone from the manager
        let mgr = make_manager();
        let call_id = "orphan-bye-test@host";

        let uuid = mgr
            .create_call(
                call_id.to_string(),
                "tag".to_string(),
                caller_addr(),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();

        // Terminate the call
        mgr.handle_bye(&uuid).await.unwrap();
        mgr.terminate_call(&uuid).await;

        // Orphan BYE arrives — call should not be found
        let result = mgr.find_by_any_call_id(call_id).await;
        assert!(
            result.is_none(),
            "Terminated call should not be found by orphan BYE"
        );
    }
}

#[cfg(test)]
mod invite_attempt_tests {
    use super::*;

    fn make_manager() -> B2buaManager {
        let media = Arc::new(MediaManager::with_port_range(30000..30100, None));
        B2buaManager::new(media)
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";

    fn invite(branch: &str, cseq: u32) -> String {
        format!(
            "INVITE sip:bob@203.0.113.9:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.1:5060;branch={};rport\r\n\
             From: <sip:caller@pstn.example.com>;tag=caller-tag\r\n\
             To: <sip:bob@b.example.com>\r\n\
             Call-ID: cid-1\r\n\
             CSeq: {} INVITE\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{}",
            branch,
            cseq,
            SDP.len(),
            SDP
        )
    }

    async fn call_with_attempts(mgr: &B2buaManager) -> (CallUuid, SocketAddr, SocketAddr) {
        let uuid = mgr
            .create_call(
                "cid-1".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        mgr.set_failover_candidates(&uuid, vec![]).await;
        let trunk_a = addr("203.0.113.9:5060");
        let trunk_b = addr("203.0.113.10:5060");
        // initial INVITE, 407 retry (CSeq+1), failover (same CSeq, new branch, other trunk)
        mgr.push_invite_attempt(
            &uuid,
            invite("z9hG4bKaaa", 3),
            trunk_a,
            rsip::Transport::Udp,
            None,
        )
        .await;
        assert_eq!(mgr.outbound_invite_cseq(&uuid).await, Some(3));
        mgr.push_invite_attempt(
            &uuid,
            invite("z9hG4bKbbb", 4),
            trunk_a,
            rsip::Transport::Udp,
            None,
        )
        .await;
        // Everything stamped so far (set_failover_candidates, two pushes) is
        // strictly before this marker: only the third push can move the clock past it.
        let marker = std::time::Instant::now();
        mgr.push_invite_attempt(
            &uuid,
            invite("z9hG4bKccc", 4),
            trunk_b,
            rsip::Transport::Udp,
            None,
        )
        .await;
        {
            let calls = mgr.calls.lock().await;
            assert!(
                calls[&uuid].failover.as_ref().unwrap().invite_sent_at >= marker,
                "push restarts the no-answer clock"
            );
        }
        (uuid, trunk_a, trunk_b)
    }

    #[tokio::test]
    async fn responses_are_attributed_by_branch_then_cseq() {
        let mgr = make_manager();
        let (uuid, trunk_a, trunk_b) = call_with_attempts(&mgr).await;

        assert_eq!(mgr.outbound_invite_cseq(&uuid).await, Some(4));
        let (current, _) = mgr.current_attempt(&uuid).await.unwrap();
        assert_eq!(current.dest, trunk_b);
        assert_eq!(current.branch.as_deref(), Some("z9hG4bKccc"));

        let classify = |branch: Option<&'static str>, cseq: u32| {
            mgr.classify_invite_response(&uuid, branch, cseq)
        };

        assert!(matches!(
            classify(Some("z9hG4bKccc"), 4).await,
            Some(InviteResponseClass::Current)
        ));
        // Late 422 from trunk A's retry: same CSeq as the live attempt, old branch
        match classify(Some("z9hG4bKbbb"), 4).await {
            Some(InviteResponseClass::Stale(Some(a))) => {
                assert_eq!(a.dest, trunk_a);
                assert_eq!(a.cseq, 4);
            }
            other => panic!("expected stale with trunk A attempt, got {:?}", other),
        }
        // Retransmitted 407 of the very first attempt
        match classify(Some("z9hG4bKaaa"), 3).await {
            Some(InviteResponseClass::Stale(Some(a))) => {
                assert_eq!(a.branch.as_deref(), Some("z9hG4bKaaa"))
            }
            other => panic!("{:?}", other),
        }
        // No branch echoed: CSeq fallback
        match classify(None, 3).await {
            Some(InviteResponseClass::Stale(Some(a))) => assert_eq!(a.cseq, 3),
            other => panic!("{:?}", other),
        }
        assert!(matches!(
            classify(None, 4).await,
            Some(InviteResponseClass::Current)
        ));
        // Unknown branch: current when CSeq is the live one, stale by CSeq when older
        assert!(matches!(
            classify(Some("z9hG4bKzzz"), 4).await,
            Some(InviteResponseClass::Current)
        ));
        match classify(Some("z9hG4bKzzz"), 3).await {
            Some(InviteResponseClass::Stale(Some(a))) => assert_eq!(a.cseq, 3),
            other => panic!("{:?}", other),
        }
        // CSeq above the live INVITE (a consumed refresh re-INVITE's answer,
        // retransmitted): never the INVITE's final — dropped, not "current"
        assert!(matches!(
            classify(Some("z9hG4bKrefresh"), 5).await,
            Some(InviteResponseClass::Stale(None))
        ));
        assert!(matches!(
            classify(None, 5).await,
            Some(InviteResponseClass::Stale(None))
        ));
        // Unknown call
        assert!(mgr
            .classify_invite_response(&"nope".to_string(), Some("z9hG4bKccc"), 4)
            .await
            .is_none());

        let calls = mgr.calls.lock().await;
        let c = &calls[&uuid];
        assert_eq!(c.invite_attempts.len(), 3);
        assert!(
            c.original_outbound_invite
                .as_deref()
                .unwrap()
                .contains("z9hG4bKccc"),
            "mirror follows the live attempt"
        );
        assert_eq!(c.callee_dest, Some(trunk_b));
    }

    #[tokio::test]
    async fn no_attempt_means_current_and_attempts_are_bounded() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "cid-2".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        assert!(matches!(
            mgr.classify_invite_response(&uuid, Some("z9hG4bKx"), 1)
                .await,
            Some(InviteResponseClass::Current)
        ));
        assert!(mgr.current_attempt(&uuid).await.is_none());
        assert_eq!(mgr.outbound_invite_cseq(&uuid).await, None);

        for i in 0..12u32 {
            mgr.push_invite_attempt(
                &uuid,
                invite(&format!("z9hG4bK{}", i), 3 + i),
                addr("203.0.113.9:5060"),
                rsip::Transport::Udp,
                None,
            )
            .await;
        }
        let calls = mgr.calls.lock().await;
        assert_eq!(calls[&uuid].invite_attempts.len(), MAX_INVITE_ATTEMPTS);
        assert_eq!(
            calls[&uuid].invite_attempts.last().unwrap().cseq,
            14,
            "newest attempt kept"
        );
    }

    #[tokio::test]
    async fn terminate_call_releases_media_and_remembers_last_attempt() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "cid-3".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                Some(SDP),
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        let before = mgr.media.stats().allocated_ports;
        assert!(
            before > 0,
            "create_call with SDP allocates an RTP port pair"
        );
        mgr.push_invite_attempt(
            &uuid,
            invite("z9hG4bKaaa", 3),
            addr("203.0.113.9:5060"),
            rsip::Transport::Udp,
            None,
        )
        .await;

        mgr.terminate_call(&uuid).await;

        assert_eq!(
            mgr.media.stats().allocated_ports,
            0,
            "terminate_call must free the media session"
        );
        let a = mgr
            .recent_attempt_for_call_id("cid-3")
            .expect("last attempt remembered");
        assert_eq!(a.cseq, 3);
        assert!(
            mgr.recent_attempt_for_call_id("id-3").is_some(),
            "truncated Call-ID suffix"
        );
        assert!(mgr.recent_attempt_for_call_id("other").is_none());
        assert!(mgr.recent_attempt_for_call_id("").is_none());
    }

    #[tokio::test]
    async fn auth_retry_reset_and_caller_cseq() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "cid-4".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        let trunk_id = uuid::Uuid::new_v4();
        mgr.store_outbound_invite(&uuid, String::new(), trunk_id)
            .await;
        mgr.increment_auth_retry(&uuid).await;
        assert_eq!(mgr.get_auth_retry_info(&uuid).await.unwrap().2, 1);
        mgr.reset_auth_retry(&uuid).await;
        assert_eq!(mgr.get_auth_retry_info(&uuid).await.unwrap().2, 0);

        assert_eq!(mgr.get_caller_invite_cseq(&uuid).await, None);
        mgr.set_caller_vias(
            &uuid,
            vec!["Via: SIP/2.0/UDP 10.0.0.9;branch=z9hG4bKc".into()],
            Some(7),
        )
        .await;
        assert_eq!(mgr.get_caller_invite_cseq(&uuid).await, Some(7));
        assert_eq!(mgr.get_caller_vias(&uuid).await.len(), 1);
    }

    #[tokio::test]
    async fn refresh_failure_clears_pending_and_rearms_on_422() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "cid-5".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        mgr.set_inbound_dialog(
            &uuid,
            "<sip:caller@pstn.example.com>;tag=caller-tag".into(),
            None,
            None,
        )
        .await;
        mgr.attach_outbound(
            &uuid,
            "cid-5".into(),
            "sbc-tag".into(),
            addr("203.0.113.9:5060"),
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
        mgr.set_established_dialog(
            &uuid,
            "<sip:caller@pstn.example.com>;tag=caller-tag".into(),
            "<sip:bob@b.example.com>;tag=callee-tag".into(),
            Some("sip:bob@203.0.113.9:5060".into()),
        )
        .await;
        mgr.push_invite_attempt(
            &uuid,
            invite("z9hG4bKaaa", 3),
            addr("203.0.113.9:5060"),
            rsip::Transport::Udp,
            None,
        )
        .await;
        mgr.set_session_timer(&uuid, 1800, 90).await;
        {
            let mut calls = mgr.calls.lock().await;
            let c = calls.get_mut(&uuid).unwrap();
            c.state = CallState::Connected;
            c.session_timer.as_mut().unwrap().next_refresh_at =
                std::time::Instant::now() - Duration::from_secs(1);
        }

        let due = mgr.due_session_refreshes("1.2.3.4", 5060).await;
        assert_eq!(due.len(), 1);
        let reinvite = due[0].1.clone();
        assert!(
            reinvite.contains("Session-Expires: 1800;refresher=uac\r\n"),
            "{}",
            reinvite
        );
        assert!(
            reinvite.contains("Min-SE: 90\r\n"),
            "refresh carries Min-SE: {}",
            reinvite
        );
        let cseq = parse_cseq_number(&reinvite).unwrap();
        assert_eq!(cseq, 4, "refresh CSeq follows the stored INVITE");
        assert!(mgr.is_pending_refresh(&uuid, cseq).await);
        assert!(!mgr.is_pending_refresh(&uuid, cseq + 1).await);
        assert!(
            mgr.due_session_refreshes("1.2.3.4", 5060).await.is_empty(),
            "no second refresh while one is pending"
        );

        // Trunk answers 422 Min-SE 14400 to the refresh
        let outcome = mgr
            .fail_session_refresh(
                &uuid,
                cseq,
                422,
                Some(14400),
                "<sip:bob@b.example.com>;tag=callee-tag",
            )
            .await
            .expect("pending refresh recognised");
        let ack = outcome.ack.expect("ACK built from the stored re-INVITE");
        assert_eq!(outcome.dest, addr("203.0.113.9:5060"));
        assert!(
            !outcome.dialog_gone,
            "a 422 that raised the interval is progress"
        );
        assert!(
            ack.starts_with("ACK sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
            "{}",
            ack
        );
        assert!(ack.contains(&format!("CSeq: {} ACK\r\n", cseq)));
        let reinvite_branch = crate::sip_builder::top_via_branch(&reinvite).unwrap();
        assert!(
            ack.contains(&reinvite_branch),
            "ACK reuses the re-INVITE's branch"
        );
        assert!(!mgr.is_pending_refresh(&uuid, cseq).await);
        {
            let calls = mgr.calls.lock().await;
            let st = calls[&uuid].session_timer.as_ref().unwrap();
            assert_eq!(st.pending_refresh_cseq, None);
            assert!(st.pending_refresh_raw.is_none());
            assert_eq!(st.refresh_failures, 0);
            assert_eq!(st.interval_secs, 14400);
            assert_eq!(st.min_se, 14400);
            assert!(st.next_refresh_at > std::time::Instant::now());
            assert_eq!(
                st.last_refresh.as_ref().map(|(c, _)| *c),
                Some(cseq),
                "last refresh kept for duplicates"
            );
        }
        // Not pending any more → a second failure report is ignored…
        assert!(mgr
            .fail_session_refresh(&uuid, cseq, 481, None, "x")
            .await
            .is_none());
        // …but a retransmitted answer to that refresh is still recognised and re-ACKed
        let (dup_ack, _, _, _) = mgr
            .refresh_duplicate_ack(
                &uuid,
                cseq,
                422,
                "<sip:bob@b.example.com>;tag=callee-tag",
                "1.2.3.4",
                5060,
            )
            .await
            .expect("known refresh CSeq");
        assert!(dup_ack
            .unwrap()
            .contains(&format!("CSeq: {} ACK\r\n", cseq)));
        assert!(mgr
            .refresh_duplicate_ack(&uuid, cseq + 7, 422, "x", "1.2.3.4", 5060)
            .await
            .is_none());
        // The call itself survived
        assert_eq!(mgr.stats().await.total_active, 1);
    }

    #[tokio::test]
    async fn refresh_failures_back_off_then_give_up_and_481_is_fatal() {
        let mgr = make_manager();
        let uuid = mgr
            .create_call(
                "cid-6".into(),
                "t".into(),
                addr("192.168.1.100:5060"),
                None,
                None,
                rsip::Transport::Udp,
            )
            .await
            .unwrap();
        mgr.attach_outbound(
            &uuid,
            "cid-6".into(),
            "sbc-tag".into(),
            addr("203.0.113.9:5060"),
            None,
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
        mgr.set_session_timer(&uuid, 1800, 90).await;
        async fn fail(
            mgr: &B2buaManager,
            uuid: &CallUuid,
            cseq: u32,
            status: u16,
        ) -> RefreshFailure {
            {
                let mut calls = mgr.calls.lock().await;
                let st = calls.get_mut(uuid).unwrap().session_timer.as_mut().unwrap();
                st.pending_refresh_cseq = Some(cseq);
                st.pending_refresh_raw = None;
            }
            mgr.fail_session_refresh(uuid, cseq, status, None, "x")
                .await
                .unwrap()
        }
        // 500, 500 → kept with growing backoff; third consecutive failure → give up
        assert!(!fail(&mgr, &uuid, 10, 500).await.dialog_gone);
        let after_one = mgr.calls.lock().await[&uuid]
            .session_timer
            .as_ref()
            .unwrap()
            .next_refresh_at;
        assert!(!fail(&mgr, &uuid, 11, 500).await.dialog_gone);
        let after_two = mgr.calls.lock().await[&uuid]
            .session_timer
            .as_ref()
            .unwrap()
            .next_refresh_at;
        assert!(
            after_two > after_one,
            "backoff grows: {:?} vs {:?}",
            after_two,
            after_one
        );
        assert!(
            fail(&mgr, &uuid, 12, 500).await.dialog_gone,
            "third consecutive failure exhausts the budget"
        );

        // A 481 / 408 is fatal immediately, whatever the counter says
        mgr.set_session_timer(&uuid, 1800, 90).await;
        assert!(fail(&mgr, &uuid, 20, 481).await.dialog_gone);
        mgr.set_session_timer(&uuid, 1800, 90).await;
        assert!(fail(&mgr, &uuid, 21, 408).await.dialog_gone);
    }
}
