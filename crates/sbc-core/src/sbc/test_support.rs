//! Channel-level harness for the SIP handlers.
//!
//! A real [`Sbc`] whose call legs are wired to mpsc channels instead of
//! sockets: everything the SBC sends toward the caller or the trunk lands
//! on a receiver, so tests assert exact wire content (Via branch, CSeq,
//! dialog identity, SDP) without binding ports. The raw-message builders
//! mirror what a SIP client and a Genesys-style trunk actually send.
//!
//! Typical shape:
//!
//! ```ignore
//! let mut sbc = SbcBuilder::new().build();
//! let mut call = add_call(&mut sbc, CallSpec::default()).await; // INVITE in flight
//! connect(&mut sbc, &mut call).await;                            // 200 OK + ACK
//! sbc.handle_bye(bye_from_caller(&call.spec, 4), caller_addr(), Udp, Some(&call.caller_tx)).await?;
//! let to_trunk = drain(&mut call.callee_rx);
//! ```

use super::*;
use crate::b2bua::CallUuid;
use crate::config::{ListenerConfig, TransportType};
use crate::routing::{TrunkConfig, TrunkId};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Caller's SDP offer (leg A).
pub(crate) const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
/// Trunk's SDP answer (leg B).
pub(crate) const TRUNK_SDP: &str = "v=0\r\no=- 2 2 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\nm=audio 6004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
/// Name of the harness trunk (UDP, 203.0.113.9:5060).
pub(crate) const TRUNK_NAME: &str = "genesys";
/// Request-URI the SBC sent the INVITE to.
pub(crate) const TRUNK_INVITE_URI: &str = "sip:bob@203.0.113.9:5060";
/// Contact the trunk returns in its 200 OK: deliberately different from
/// the INVITE's Request-URI, so tests can tell which one a request uses.
pub(crate) const TRUNK_CONTACT: &str = "sip:bob-ct@203.0.113.9:5060";

pub(crate) fn caller_addr() -> SocketAddr {
    "10.0.0.9:5060".parse().unwrap()
}
pub(crate) fn trunk_addr() -> SocketAddr {
    "203.0.113.9:5060".parse().unwrap()
}

/// Identity of one harness call. Defaults are the historical fixtures
/// (Call-ID `cid-1`, From tag `al-1`, trunk-side INVITE branch
/// `z9hG4bKaaa`, CSeq 3).
#[derive(Clone, Debug)]
pub(crate) struct CallSpec {
    pub call_id: String,
    pub from_tag: String,
    /// Via branch of the INVITE the SBC sent toward the trunk.
    pub branch: String,
    /// CSeq shared by both legs (half B2BUA: same Call-ID/CSeq).
    pub cseq: u32,
}

impl Default for CallSpec {
    fn default() -> Self {
        Self {
            call_id: "cid-1".into(),
            from_tag: "al-1".into(),
            branch: "z9hG4bKaaa".into(),
            cseq: 3,
        }
    }
}

impl CallSpec {
    /// A distinct call for multi-call tests.
    pub(crate) fn numbered(n: usize) -> Self {
        Self {
            call_id: format!("cid-{n}"),
            from_tag: format!("al-{n}"),
            branch: format!("z9hG4bK{n:06}"),
            cseq: 3,
        }
    }
}

// ── Raw message builders ────────────────────────────────────────────────────

/// The INVITE the SBC sent toward the trunk for the default call.
pub(crate) fn invite(branch: &str, cseq: u32) -> String {
    invite_for(&CallSpec::default(), branch, cseq)
}

/// The INVITE the SBC sent toward the trunk (what an attempt stores).
pub(crate) fn invite_for(spec: &CallSpec, branch: &str, cseq: u32) -> String {
    format!(
        "INVITE sip:bob@203.0.113.9:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.1:5060;branch={};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@a.example.com>;tag={}\r\n\
         To: <sip:bob@b.example.com>\r\n\
         Call-ID: {}\r\n\
         CSeq: {} INVITE\r\n\
         Supported: timer\r\n\
         Session-Expires: 1800\r\n\
         Min-SE: 90\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        branch,
        spec.from_tag,
        spec.call_id,
        cseq,
        SDP.len(),
        SDP
    )
}

/// A response from the trunk to the SBC's `method` request (no body).
pub(crate) fn response(
    status_line: &str,
    branch: &str,
    cseq: u32,
    method: &str,
    extra: &str,
) -> rsip::Response {
    response_for(
        &CallSpec::default(),
        status_line,
        branch,
        cseq,
        method,
        extra,
        "",
    )
}

/// A response from the trunk, with `extra` headers and a body.
pub(crate) fn response_for(
    spec: &CallSpec,
    status_line: &str,
    branch: &str,
    cseq: u32,
    method: &str,
    extra: &str,
    body: &str,
) -> rsip::Response {
    let raw = format!(
        "SIP/2.0 {}\r\n\
         Via: SIP/2.0/UDP 198.51.100.1:5060;branch={};rport=5060;received=203.0.113.9\r\n\
         From: <sip:alice@a.example.com>;tag={}\r\n\
         To: <sip:bob@b.example.com>;tag=trunk-1\r\n\
         Call-ID: {}\r\n\
         CSeq: {} {}\r\n\
         {}Content-Length: {}\r\n\r\n{}",
        status_line,
        branch,
        spec.from_tag,
        spec.call_id,
        cseq,
        method,
        extra,
        body.len(),
        body
    );
    match rsip::SipMessage::try_from(raw.into_bytes()).expect("response parses") {
        rsip::SipMessage::Response(r) => r,
        _ => panic!("not a response"),
    }
}

/// Parse a raw request the way the transport layer would.
pub(crate) fn request(raw: String) -> rsip::Request {
    match rsip::SipMessage::try_from(raw.into_bytes()).expect("request parses") {
        rsip::SipMessage::Request(r) => r,
        _ => panic!("not a request"),
    }
}

/// In-dialog request from the caller (leg A) once the callee's tag is known.
fn caller_request(
    spec: &CallSpec,
    method: &str,
    cseq: u32,
    branch: &str,
    extra: &str,
    body: &str,
) -> rsip::Request {
    request(format!(
        "{} sip:bob@b.example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.9:5060;branch={}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@a.example.com>;tag={}\r\n\
         To: <sip:bob@b.example.com>;tag=trunk-1\r\n\
         Call-ID: {}\r\n\
         CSeq: {} {}\r\n\
         {}Content-Length: {}\r\n\r\n{}",
        method,
        branch,
        spec.from_tag,
        spec.call_id,
        cseq,
        method,
        extra,
        body.len(),
        body
    ))
}

/// The caller's ACK to the relayed 200 OK (same CSeq as its INVITE, its
/// own transaction: fresh branch, RFC 3261 §17.1.1.3).
pub(crate) fn ack_from_caller(spec: &CallSpec) -> rsip::Request {
    caller_request(spec, "ACK", spec.cseq, "z9hG4bKack", "", "")
}

/// The caller's ACK to a non-2xx final: same branch as its INVITE (hop by
/// hop, part of the INVITE transaction).
pub(crate) fn ack_for_final_from_caller(spec: &CallSpec) -> rsip::Request {
    caller_request(spec, "ACK", spec.cseq, "z9hG4bKcaller", "", "")
}

/// BYE from the caller.
pub(crate) fn bye_from_caller(spec: &CallSpec, cseq: u32) -> rsip::Request {
    caller_request(spec, "BYE", cseq, "z9hG4bKbye", "", "")
}

/// Re-INVITE from the caller offering `session_expires`.
pub(crate) fn reinvite_from_caller(
    spec: &CallSpec,
    cseq: u32,
    session_expires: u32,
) -> rsip::Request {
    caller_request(
        spec,
        "INVITE",
        cseq,
        "z9hG4bKreinv",
        &format!(
            "Supported: timer\r\nSession-Expires: {}\r\nContent-Type: application/sdp\r\n",
            session_expires
        ),
        SDP,
    )
}

/// CANCEL from the caller: its INVITE's branch and CSeq (RFC 3261 §9.1),
/// To without a tag.
pub(crate) fn cancel_from_caller(spec: &CallSpec) -> rsip::Request {
    request(format!(
        "CANCEL sip:bob@b.example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcaller\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@a.example.com>;tag={}\r\n\
         To: <sip:bob@b.example.com>\r\n\
         Call-ID: {}\r\n\
         CSeq: {} CANCEL\r\n\
         Content-Length: 0\r\n\r\n",
        spec.from_tag, spec.call_id, spec.cseq
    ))
}

/// BYE from the trunk side (leg B): From/To swapped, its own CSeq space,
/// plus `extra` header lines (each `\r\n`-terminated), e.g. a Reason.
pub(crate) fn bye_from_trunk_with(spec: &CallSpec, cseq: u32, extra: &str) -> rsip::Request {
    request(format!(
        "BYE sip:sbc@127.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKtrunkbye\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@b.example.com>;tag=trunk-1\r\n\
         To: <sip:alice@a.example.com>;tag={}\r\n\
         Call-ID: {}\r\n\
         CSeq: {} BYE\r\n\
         {}Content-Length: 0\r\n\r\n",
        spec.from_tag, spec.call_id, cseq, extra
    ))
}

/// A fresh INVITE from the trunk (inbound PSTN call) to `number`, as
/// `handle_invite` receives it. Call-ID `cid-in-1`, CSeq 1, branch
/// `z9hG4bKtrk1`.
pub(crate) fn invite_from_trunk(number: &str, max_forwards: u32) -> rsip::Request {
    invite_from_trunk_as("sip:+33612345678@203.0.113.9", number, max_forwards)
}

/// Same, presenting `from_uri` as the caller.
pub(crate) fn invite_from_trunk_as(
    from_uri: &str,
    number: &str,
    max_forwards: u32,
) -> rsip::Request {
    invite_from_trunk_tx(from_uri, number, max_forwards, 1)
}

/// Same with transaction number `tx` (Call-ID `cid-in-{tx}`, branch
/// `z9hG4bKtrk{tx}`): a distinct call.
pub(crate) fn invite_from_trunk_tx(
    from_uri: &str,
    number: &str,
    max_forwards: u32,
    tx: u32,
) -> rsip::Request {
    request(format!(
        "INVITE sip:{}@127.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKtrk{}{};rport\r\n\
         Max-Forwards: {}\r\n\
         From: <{}>;tag=g1\r\n\
         To: <sip:{}@127.0.0.1>\r\n\
         Call-ID: cid-in-{}\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:203.0.113.9:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        number,
        tx,
        "",
        max_forwards,
        from_uri,
        number,
        tx,
        TRUNK_SDP.len(),
        TRUNK_SDP
    ))
}

/// Make the harness trunk's IP known as a trunk source (what hydration
/// does from the trunks table), so its INVITEs bypass the anti-spam gate.
pub(crate) async fn register_trunk_ip(sbc: &Sbc) {
    let mut ips = sbc.trunk_ips.write().await;
    let ip = trunk_addr().ip().to_string();
    if !ips.contains(&ip) {
        ips.push(ip);
    }
}

/// A fresh INVITE from a local (loopback) client to `number`, with `extra`
/// header lines: what a co-located PBX sends the SBC for an outbound call.
/// Call-ID `cid-out-1`, CSeq 1, branch `z9hG4bKloc1`.
pub(crate) fn invite_from_local(number: &str, extra: &str) -> rsip::Request {
    request(format!(
        "INVITE sip:{}@127.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bKloc1;rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@127.0.0.1>;tag=loc1\r\n\
         To: <sip:{}@127.0.0.1>\r\n\
         Call-ID: cid-out-1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@127.0.0.1:5080>\r\n\
         {}Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        number,
        number,
        extra,
        SDP.len(),
        SDP
    ))
}

/// Source address of `invite_from_local`.
pub(crate) fn local_addr() -> SocketAddr {
    "127.0.0.1:5080".parse().unwrap()
}

/// REGISTER from the local client for `sip:{user}@{realm}` (Call-ID
/// `cid-reg-1`, branch derived from `cseq`), with `extra` header lines.
pub(crate) fn register_request(user: &str, realm: &str, cseq: u32, extra: &str) -> rsip::Request {
    register_request_for(user, &format!("sip:{}@{}", user, realm), realm, cseq, extra)
}

/// REGISTER whose To/From is `aor` (any user, any host) — what a client
/// authenticated as `user` sends when it tries to bind someone else.
pub(crate) fn register_request_for(
    user: &str,
    aor: &str,
    realm: &str,
    cseq: u32,
    extra: &str,
) -> rsip::Request {
    request(format!(
        "REGISTER sip:{realm} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bKreg{cseq}\r\n\
         Max-Forwards: 70\r\n\
         From: <{aor}>;tag=r1\r\n\
         To: <{aor}>\r\n\
         Call-ID: cid-reg-1\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{user}@127.0.0.1:5080>\r\n\
         Expires: 3600\r\n\
         {extra}Content-Length: 0\r\n\r\n"
    ))
}

/// INVITE from a registered/local user `user@realm` to `number`, with
/// `extra` header lines. Pass the source address separately.
pub(crate) fn invite_from_user(
    user: &str,
    realm: &str,
    number: &str,
    extra: &str,
) -> rsip::Request {
    invite_from_user_tx(user, realm, number, extra, 1)
}

/// Same with transaction number `tx` (CSeq and Via branch): what a client
/// sends when it retries after a 407, or places another call.
pub(crate) fn invite_from_user_tx(
    user: &str,
    realm: &str,
    number: &str,
    extra: &str,
    tx: u32,
) -> rsip::Request {
    request(format!(
        "INVITE sip:{number}@{realm} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.9:5080;branch=z9hG4bK{user}{tx};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{user}@{realm}>;tag={user}-tag\r\n\
         To: <sip:{number}@{realm}>\r\n\
         Call-ID: cid-{user}\r\n\
         CSeq: {tx} INVITE\r\n\
         Contact: <sip:{user}@10.0.0.9:5080>\r\n\
         {extra}Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        SDP.len(),
        SDP
    ))
}

/// `Proxy-Authorization:` line for an INVITE answering `nonce`.
pub(crate) fn proxy_authorization_line(
    user: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    uri: &str,
    nc: &str,
) -> String {
    let ha1 = crate::auth::compute_ha1(user, realm, password);
    let ha2 = crate::auth::compute_ha2("INVITE", uri);
    let response = crate::auth::compute_response_auth(&ha1, nonce, nc, "cn0nce", &ha2);
    format!(
        "Proxy-Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=MD5, cnonce=\"cn0nce\", nc={}, qop=auth\r\n",
        user, realm, nonce, uri, response, nc
    )
}

/// The nonce of a 401's WWW-Authenticate challenge.
pub(crate) fn nonce_of(response: &str) -> String {
    response
        .split("nonce=\"")
        .nth(1)
        .expect("nonce in challenge")
        .split('"')
        .next()
        .unwrap()
        .to_string()
}

/// An `Authorization:` header line answering `nonce` with qop=auth.
pub(crate) fn authorization_line(
    user: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    nc: &str,
) -> String {
    let ha1 = crate::auth::compute_ha1(user, realm, password);
    let ha2 = crate::auth::compute_ha2("REGISTER", &format!("sip:{}", realm));
    let response = crate::auth::compute_response_auth(&ha1, nonce, nc, "cn0nce", &ha2);
    format!(
        "Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"sip:{}\", response=\"{}\", algorithm=MD5, cnonce=\"cn0nce\", nc={}, qop=auth\r\n",
        user, realm, nonce, realm, response, nc
    )
}

/// Everything queued on a leg, as text, oldest first.
pub(crate) fn drain(rx: &mut UnboundedReceiver<Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        out.push(String::from_utf8(m).unwrap());
    }
    out
}

/// Top Via branch of a raw message.
pub(crate) fn top_branch(raw: &str) -> String {
    crate::sip_builder::top_via_branch(raw).expect("Via branch")
}

/// UDP listener on an ephemeral loopback port (for tests that need the
/// SBC to actually emit a packet, e.g. toward a fake trunk socket).
pub(crate) fn udp_loopback() -> NetworkConfig {
    NetworkConfig {
        listeners: vec![ListenerConfig {
            transport: TransportType::UDP,
            bind_address: "127.0.0.1".parse().unwrap(),
            bind_port: 0,
            cert_file: None,
            key_file: None,
        }],
        public_ipv4: None,
        public_ipv6: None,
    }
}

// ── SBC construction ────────────────────────────────────────────────────────

/// Disjoint RTP port range per SBC instance so tests running in parallel
/// never bind the same ports (Linux ephemeral ports start at 32768).
fn next_port_range() -> std::ops::Range<u16> {
    static NEXT: AtomicU16 = AtomicU16::new(22000);
    let base = NEXT.fetch_add(40, Ordering::Relaxed);
    base..base + 40
}

/// Builds an [`Sbc`] for handler tests: no sockets, one Genesys-style UDP
/// trunk, session timers on (1800/90), its own RTP port range.
pub(crate) struct SbcBuilder {
    identity: Option<SbcIdentity>,
    session_timer: Option<(u32, u32)>,
    invite_timeout: Duration,
    setup_timeout: Duration,
    max_call_duration: Duration,
    digest: Option<(String, std::collections::HashMap<String, String>)>,
    identity_policy: IdentityPolicy,
}

impl SbcBuilder {
    pub(crate) fn new() -> Self {
        Self {
            identity: None,
            session_timer: Some((1800, 90)),
            invite_timeout: Duration::from_secs(5),
            setup_timeout: Duration::from_secs(180),
            max_call_duration: Duration::from_secs(14400),
            digest: None,
            identity_policy: IdentityPolicy::default(),
        }
    }

    pub(crate) fn identity_policy(mut self, policy: IdentityPolicy) -> Self {
        self.identity_policy = policy;
        self
    }

    pub(crate) fn setup_timeout(mut self, timeout: Duration) -> Self {
        self.setup_timeout = timeout;
        self
    }

    /// Digest authentication on, with these `(user, password)` accounts.
    pub(crate) fn digest_users(mut self, realm: &str, users: &[(&str, &str)]) -> Self {
        self.digest = Some((
            realm.to_string(),
            users
                .iter()
                .map(|(u, p)| (u.to_string(), p.to_string()))
                .collect(),
        ));
        self
    }

    /// Public identity used in synthetic requests (default: 127.0.0.1:5060).
    #[allow(dead_code)]
    pub(crate) fn identity(mut self, public_ip: &str, sip_port: u16) -> Self {
        self.identity = Some(SbcIdentity {
            public_ip: public_ip.to_string(),
            sip_domain: public_ip.to_string(),
            sip_port,
            tls: false,
        });
        self
    }

    #[allow(dead_code)]
    pub(crate) fn session_timer(mut self, timer: Option<(u32, u32)>) -> Self {
        self.session_timer = timer;
        self
    }

    pub(crate) fn invite_timeout(mut self, timeout: Duration) -> Self {
        self.invite_timeout = timeout;
        self
    }

    pub(crate) fn max_call_duration(mut self, max: Duration) -> Self {
        self.max_call_duration = max;
        self
    }

    pub(crate) fn build(self) -> Sbc {
        let mut sbc = Sbc::new();
        let media = Arc::new(MediaManager::with_port_range(next_port_range(), None));
        sbc.b2bua = Arc::new(B2buaManager::new(media.clone()));
        sbc.media = media;
        sbc.identity = self.identity;
        sbc.session_timer = self.session_timer;
        sbc.invite_timeout = self.invite_timeout;
        sbc.call_setup_timeout = self.setup_timeout;
        sbc.max_call_duration = self.max_call_duration;
        if let Some((realm, users)) = self.digest {
            sbc.auth = Some(Arc::new(DigestAuthenticator::new(realm, users)));
            sbc.enable_digest_auth = true;
        }
        sbc.identity_policy = self.identity_policy;
        let mut trunk = TrunkConfig::new(TRUNK_NAME.to_string());
        trunk.host = trunk_addr().ip().to_string();
        trunk.port = trunk_addr().port();
        sbc.add_trunk(trunk);
        sbc
    }
}

/// The harness trunk's id.
pub(crate) fn trunk_id(sbc: &Sbc) -> TrunkId {
    sbc.trunk_manager
        .list_trunks()
        .into_iter()
        .find(|t| t.name == TRUNK_NAME)
        .map(|t| t.id)
        .expect("harness trunk registered")
}

/// One call created by [`add_call`].
pub(crate) struct TestCall {
    pub spec: CallSpec,
    pub uuid: CallUuid,
    pub trunk_id: TrunkId,
    /// What the SBC sends toward the caller / the trunk.
    pub caller_rx: UnboundedReceiver<Vec<u8>>,
    pub callee_rx: UnboundedReceiver<Vec<u8>>,
    /// The connection the caller's own requests arrive on (pass as
    /// `reply_tx`, so the SBC's direct answers land on `caller_rx`).
    pub caller_tx: UnboundedSender<Vec<u8>>,
}

/// One outbound call (caller → SBC → trunk) with its INVITE in flight
/// toward the trunk: exactly the state `handle_invite` leaves behind once
/// it has forwarded the INVITE (media allocated, caller Vias/CSeq stored,
/// outbound leg attached, one attempt recorded).
pub(crate) async fn add_call(sbc: &mut Sbc, spec: CallSpec) -> TestCall {
    let trunk_id = trunk_id(sbc);
    register_trunk_ip(sbc).await;
    let (caller_tx, caller_rx) = unbounded_channel();
    let (callee_tx, callee_rx) = unbounded_channel();
    let uuid = sbc
        .b2bua
        .create_call(
            spec.call_id.clone(),
            spec.from_tag.clone(),
            caller_addr(),
            Some(SDP),
            Some(caller_tx.clone()),
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
    sbc.b2bua
        .set_caller_vias(
            &uuid,
            vec!["Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcaller".into()],
            Some(spec.cseq),
        )
        .await;
    sbc.b2bua
        .set_inbound_dialog(
            &uuid,
            format!("<sip:alice@a.example.com>;tag={}", spec.from_tag),
            Some("<sip:bob@b.example.com>".into()),
            Some("sip:alice@10.0.0.9:5060".into()),
        )
        .await;
    {
        let mut calls = sbc.b2bua.calls_locked().await;
        let call = calls.get_mut(&uuid).unwrap();
        call.caller_number = Some("alice".into());
        call.callee_number = Some("bob".into());
    }
    let raw = invite_for(&spec, &spec.branch, spec.cseq);
    sbc.b2bua
        .store_outbound_invite(&uuid, raw.clone(), trunk_id)
        .await;
    sbc.b2bua
        .set_callee_request_uri(&uuid, TRUNK_INVITE_URI.to_string())
        .await;
    sbc.b2bua
        .attach_outbound(
            &uuid,
            spec.call_id.clone(),
            "sbc-tag".into(),
            trunk_addr(),
            Some(callee_tx),
            rsip::Transport::Udp,
        )
        .await
        .unwrap();
    {
        let mut calls = sbc.b2bua.calls_locked().await;
        calls.get_mut(&uuid).unwrap().trunk_name = Some(TRUNK_NAME.into());
    }
    sbc.b2bua
        .push_invite_attempt(
            &uuid,
            raw,
            trunk_addr(),
            rsip::Transport::Udp,
            Some(trunk_id),
        )
        .await;
    // The caller's INVITE transaction, as handle_invite registers it: finals
    // toward the caller are then remembered (absorb) and retransmitted (Timer G).
    let _ = sbc.invite_tx.begin(&format!(
        "z9hG4bKcaller|{}|{}|{}",
        spec.call_id, spec.from_tag, spec.cseq
    ));
    TestCall {
        spec,
        uuid,
        trunk_id,
        caller_rx,
        callee_rx,
        caller_tx,
    }
}

/// Historical fixture: the default call on a default SBC, returning the
/// SBC plus the caller-leg and callee-leg receivers.
pub(crate) async fn sbc_with_call() -> (
    Sbc,
    CallUuid,
    UnboundedReceiver<Vec<u8>>,
    UnboundedReceiver<Vec<u8>>,
) {
    let mut sbc = SbcBuilder::new().build();
    let call = add_call(&mut sbc, CallSpec::default()).await;
    (sbc, call.uuid, call.caller_rx, call.callee_rx)
}

/// Whether the default call (`cid-1`) still exists.
pub(crate) async fn alive(sbc: &Sbc) -> bool {
    call_alive(sbc, "cid-1").await
}

pub(crate) async fn call_alive(sbc: &Sbc, call_id: &str) -> bool {
    sbc.b2bua.find_by_inbound_call_id(call_id).await.is_some()
}

/// What [`connect`] observed on the wire.
pub(crate) struct Connected {
    pub ok_to_caller: String,
    pub ack_to_trunk: String,
}

/// Answer the in-flight INVITE from the trunk (200 OK with SDP and a
/// Contact) and ACK it from the caller: the call is Connected on both legs.
pub(crate) async fn connect(sbc: &mut Sbc, call: &mut TestCall) -> Connected {
    sbc.handle_response(
        response_for(
            &call.spec,
            "200 OK",
            &call.spec.branch,
            call.spec.cseq,
            "INVITE",
            &format!(
                "Contact: <{}>\r\nContent-Type: application/sdp\r\n",
                TRUNK_CONTACT
            ),
            TRUNK_SDP,
        ),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .expect("200 OK handled");
    let mut to_caller = drain(&mut call.caller_rx);
    assert_eq!(
        to_caller.len(),
        1,
        "one 200 OK toward the caller: {:?}",
        to_caller
    );
    assert!(
        to_caller[0].starts_with("SIP/2.0 200 OK\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(
        drain(&mut call.callee_rx).is_empty(),
        "nothing toward the trunk before the caller's ACK"
    );

    sbc.handle_ack(
        ack_from_caller(&call.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .expect("ACK handled");
    let mut to_trunk = drain(&mut call.callee_rx);
    assert_eq!(
        to_trunk.len(),
        1,
        "one ACK toward the trunk: {:?}",
        to_trunk
    );
    assert!(to_trunk[0].starts_with("ACK "), "{}", to_trunk[0]);
    Connected {
        ok_to_caller: to_caller.remove(0),
        ack_to_trunk: to_trunk.remove(0),
    }
}
