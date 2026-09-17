//! Minimal SIP request builder for SBC-originated (synthetic) requests:
//! BYE on timeout/shutdown, CANCEL for failover, ACK for 2xx, re-INVITE
//! for session refresh (RFC 4028).
//!
//! Replaces ad-hoc `format!()` construction: requests are built from the
//! real dialog identity (`DialogInfo`), so From/To tags, Call-ID and CSeq
//! match what the peer expects — strict UAS implementations answer 481 to
//! anything else and keep phantom sessions alive.
//!
//! Header order follows RFC 3261 conventions: Via, Max-Forwards, From, To,
//! Call-ID, CSeq, extras, Content-Length last.

use rand::Rng;

/// Dialog identity for one leg, as the peer knows it.
#[derive(Debug, Clone)]
pub struct DialogInfo {
    /// Call-ID of this leg.
    pub call_id: String,
    /// Full `From` header value (display, URI, `;tag=`) — our identity in
    /// the dialog, exactly as established.
    pub from_raw: String,
    /// Full `To` header value with the peer's tag.
    pub to_raw: String,
    /// Request-URI: the peer's Contact (remote target), falling back to its
    /// network address.
    pub request_uri: String,
    /// CSeq number to use for the request.
    pub cseq: u32,
    /// SBC IP for the Via header.
    pub local_ip: String,
    /// SBC port for the Via header (5060/5061 depending on transport).
    pub local_port: u16,
    /// Via transport token: "UDP", "TCP", "TLS", "WS", "WSS".
    pub transport: String,
}

/// Fresh RFC 3261 magic-cookie branch parameter.
pub fn new_branch() -> String {
    let bytes: [u8; 8] = rand::thread_rng().gen();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("z9hG4bK{}", hex)
}

fn build_request(
    method: &str,
    d: &DialogInfo,
    cseq_method: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> String {
    let body = body.unwrap_or("");
    let mut msg = String::with_capacity(512 + body.len());
    msg.push_str(&format!("{} {} SIP/2.0\r\n", method, d.request_uri));
    msg.push_str(&format!(
        "Via: SIP/2.0/{} {}:{};branch={};rport\r\n",
        d.transport.to_uppercase(),
        d.local_ip,
        d.local_port,
        new_branch()
    ));
    msg.push_str("Max-Forwards: 70\r\n");
    msg.push_str(&format!("From: {}\r\n", d.from_raw));
    msg.push_str(&format!("To: {}\r\n", d.to_raw));
    msg.push_str(&format!("Call-ID: {}\r\n", d.call_id));
    msg.push_str(&format!("CSeq: {} {}\r\n", d.cseq, cseq_method));
    for (name, value) in extra_headers {
        msg.push_str(&format!("{}: {}\r\n", name, value));
    }
    msg.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    msg.push_str(body);
    msg
}

/// In-dialog BYE. `reason` becomes a `Reason:` header (e.g.
/// `Q.850;cause=16;text="Call duration exceeded"`).
pub fn build_bye(d: &DialogInfo, reason: Option<&str>) -> String {
    let mut extras: Vec<(&str, &str)> = Vec::new();
    if let Some(r) = reason {
        extras.push(("Reason", r));
    }
    build_request("BYE", d, "BYE", &extras, None)
}

/// ACK for a 2xx response (its own transaction: fresh branch, CSeq number of
/// the INVITE it acknowledges).
pub fn build_ack_for_2xx(d: &DialogInfo, invite_cseq: u32) -> String {
    let d2 = DialogInfo {
        cseq: invite_cseq,
        ..d.clone()
    };
    build_request("ACK", &d2, "ACK", &[], None)
}

/// Refresh re-INVITE (RFC 4028) with unchanged SDP.
/// `session_expires` = (interval_secs, refresher), e.g. (1800, "uac").
/// `min_se` is sent as `Min-SE`: once a peer raised it with a 422, later
/// requests in the dialog must carry it (RFC 4028 §7.4).
pub fn build_reinvite(
    d: &DialogInfo,
    sdp: &str,
    contact_uri: &str,
    session_expires: Option<(u32, &str)>,
    min_se: Option<u32>,
) -> String {
    let se_value;
    let min_se_value;
    let mut extras: Vec<(&str, &str)> = vec![("Contact", contact_uri), ("Supported", "timer")];
    if let Some((interval, refresher)) = session_expires {
        se_value = format!("{};refresher={}", interval, refresher);
        extras.push(("Session-Expires", &se_value));
    }
    if let Some(min) = min_se {
        min_se_value = min.to_string();
        extras.push(("Min-SE", &min_se_value));
    }
    extras.push(("Content-Type", "application/sdp"));
    build_request("INVITE", d, "INVITE", &extras, Some(sdp))
}

/// Identity of a raw INVITE the SBC sent: everything a CANCEL or a
/// non-2xx ACK must copy verbatim to match the trunk's transaction.
#[derive(Debug, Clone)]
pub struct InviteIdentity {
    pub request_uri: String,
    /// Top Via value (after `Via:`), branch included.
    pub top_via: String,
    pub from: String,
    pub to: String,
    pub call_id: String,
    pub cseq: u32,
    /// Route header values, in order (an ACK for a non-2xx copies them).
    pub routes: Vec<String>,
}

/// Parse the identity fields out of a raw INVITE. None when the message
/// is not an INVITE or lacks a mandatory header.
pub fn parse_invite_identity(raw_invite: &str) -> Option<InviteIdentity> {
    let mut request_uri = None;
    let mut top_via = None;
    let mut from = None;
    let mut to = None;
    let mut call_id = None;
    let mut cseq = None;
    let mut routes = Vec::new();

    for (i, line) in raw_invite.split("\r\n").enumerate() {
        if i == 0 {
            // "INVITE sip:x@y SIP/2.0"
            let mut parts = line.splitn(3, ' ');
            if parts.next() != Some("INVITE") {
                return None;
            }
            request_uri = parts.next().map(str::to_string);
            continue;
        }
        if line.is_empty() {
            break; // end of headers
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_lowercase().as_str() {
            "via" | "v" if top_via.is_none() => top_via = Some(value.to_string()),
            "from" | "f" => from = Some(value.to_string()),
            "to" | "t" => to = Some(value.to_string()),
            "call-id" | "i" => call_id = Some(value.to_string()),
            "cseq" => cseq = value.split_whitespace().next().and_then(|n| n.parse().ok()),
            "route" => routes.push(value.to_string()),
            _ => {}
        }
    }

    Some(InviteIdentity {
        request_uri: request_uri?,
        top_via: top_via?,
        from: from?,
        to: to?,
        call_id: call_id?,
        cseq: cseq?,
        routes,
    })
}

/// Branch parameter of the first Via of a raw request or response.
pub fn top_via_branch(raw: &str) -> Option<String> {
    for (i, line) in raw.split("\r\n").enumerate() {
        if i == 0 {
            continue;
        }
        if line.is_empty() {
            return None;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        if name != "via" && name != "v" {
            continue;
        }
        let pos = value.find("branch=")?;
        let after = &value[pos + "branch=".len()..];
        let end = after
            .find(|c: char| [';', ','].contains(&c) || c.is_whitespace())
            .unwrap_or(after.len());
        let branch = after[..end].trim();
        return (!branch.is_empty()).then(|| branch.to_string());
    }
    None
}

/// CANCEL for a pending INVITE (RFC 3261 §9.1): same Request-URI, Via branch,
/// From, To, Call-ID and CSeq number as the INVITE — only the method differs.
/// Built directly from the raw INVITE we sent.
pub fn build_cancel(original_invite_raw: &str) -> Option<String> {
    let id = parse_invite_identity(original_invite_raw)?;
    Some(format!(
        "CANCEL {} SIP/2.0\r\n\
         Via: {}\r\n\
         Max-Forwards: 70\r\n\
         From: {}\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: {} CANCEL\r\n\
         Content-Length: 0\r\n\r\n",
        id.request_uri, id.top_via, id.from, id.to, id.call_id, id.cseq
    ))
}

/// ACK for a non-2xx final response (RFC 3261 §17.1.1.3): same
/// Request-URI, top Via (branch included), From, Call-ID, Route set and
/// CSeq number as the INVITE; `To` copied from the response (it carries
/// the peer's tag). Without it a UDP peer retransmits the response for
/// 32 s (Timer H).
pub fn build_ack_for_non_2xx(original_invite_raw: &str, response_to: &str) -> Option<String> {
    let id = parse_invite_identity(original_invite_raw)?;
    let mut msg = String::with_capacity(512);
    msg.push_str(&format!("ACK {} SIP/2.0\r\n", id.request_uri));
    msg.push_str(&format!("Via: {}\r\n", id.top_via));
    msg.push_str("Max-Forwards: 70\r\n");
    for route in &id.routes {
        msg.push_str(&format!("Route: {}\r\n", route));
    }
    msg.push_str(&format!("From: {}\r\n", id.from));
    msg.push_str(&format!("To: {}\r\n", response_to.trim()));
    msg.push_str(&format!("Call-ID: {}\r\n", id.call_id));
    msg.push_str(&format!("CSeq: {} ACK\r\n", id.cseq));
    msg.push_str("Content-Length: 0\r\n\r\n");
    Some(msg)
}

/// Turn a stored INVITE into a new transaction for a re-send (407 / 422
/// retry): fresh top-Via branch and CSeq + 1. Only the header block is
/// touched, the body is copied byte for byte (Content-Length stays valid).
pub fn renew_invite_transaction(raw_invite: &str) -> String {
    let (head, body) = match raw_invite.find("\r\n\r\n") {
        Some(pos) => (&raw_invite[..pos], &raw_invite[pos + 4..]),
        None => (raw_invite, ""),
    };
    let fresh = new_branch();
    let mut via_done = false;
    let mut lines: Vec<String> = head.split("\r\n").map(str::to_string).collect();
    for line in lines.iter_mut().skip(1) {
        let lower = line.to_lowercase();
        if !via_done && (lower.starts_with("via:") || lower.starts_with("v:")) {
            if let Some(pos) = line.find("branch=") {
                let start = pos + "branch=".len();
                let end = line[start..]
                    .find([';', ','])
                    .map(|i| start + i)
                    .unwrap_or(line.len());
                line.replace_range(start..end, &fresh);
            } else {
                line.push_str(&format!(";branch={}", fresh));
            }
            via_done = true;
        } else if lower.starts_with("cseq:") {
            let mut parts = line["cseq:".len()..].split_whitespace();
            if let (Some(num), Some(method)) = (parts.next(), parts.next()) {
                if let Ok(n) = num.parse::<u32>() {
                    *line = format!("CSeq: {} {}", n + 1, method);
                }
            }
        }
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n\r\n");
    out.push_str(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dialog() -> DialogInfo {
        DialogInfo {
            call_id: "abc123@host".to_string(),
            from_raw: "<sip:sbc@sip.example.com>;tag=sbc-tag-1".to_string(),
            to_raw: "\"Alice\" <sip:alice@peer.example.com>;tag=peer-tag-9".to_string(),
            request_uri: "sip:alice@203.0.113.5:5060".to_string(),
            cseq: 42,
            local_ip: "198.51.100.1".to_string(),
            local_port: 5060,
            transport: "UDP".to_string(),
        }
    }

    fn parse(raw: &str) -> rsip::SipMessage {
        rsip::SipMessage::try_from(raw.as_bytes().to_vec()).expect("builder output must parse")
    }

    #[test]
    fn branch_has_magic_cookie_and_is_unique() {
        let b1 = new_branch();
        let b2 = new_branch();
        assert!(b1.starts_with("z9hG4bK"));
        assert_ne!(b1, b2);
    }

    #[test]
    fn bye_parses_and_has_dialog_identity() {
        let raw = build_bye(&dialog(), Some("Q.850;cause=16;text=\"timeout\""));
        let msg = parse(&raw);
        let req = match msg {
            rsip::SipMessage::Request(r) => r,
            _ => panic!("expected request"),
        };
        assert_eq!(req.method, rsip::Method::Bye);
        assert!(raw.contains("From: <sip:sbc@sip.example.com>;tag=sbc-tag-1\r\n"));
        assert!(raw.contains("To: \"Alice\" <sip:alice@peer.example.com>;tag=peer-tag-9\r\n"));
        assert!(raw.contains("Call-ID: abc123@host\r\n"));
        assert!(raw.contains("CSeq: 42 BYE\r\n"));
        assert!(raw.contains("Reason: Q.850"));
        assert!(raw.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn header_order_via_first_content_length_last() {
        let raw = build_bye(&dialog(), None);
        let headers: Vec<&str> = raw
            .split("\r\n")
            .skip(1)
            .take_while(|l| !l.is_empty())
            .collect();
        assert!(headers[0].starts_with("Via:"));
        assert!(headers[1].starts_with("Max-Forwards:"));
        assert!(headers[2].starts_with("From:"));
        assert!(headers[3].starts_with("To:"));
        assert!(headers[4].starts_with("Call-ID:"));
        assert!(headers[5].starts_with("CSeq:"));
        assert!(headers.last().unwrap().starts_with("Content-Length:"));
    }

    #[test]
    fn ack_uses_invite_cseq_number() {
        let raw = build_ack_for_2xx(&dialog(), 7);
        parse(&raw);
        assert!(raw.contains("CSeq: 7 ACK\r\n"));
    }

    #[test]
    fn reinvite_carries_sdp_and_session_expires() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let raw = build_reinvite(
            &dialog(),
            sdp,
            "<sip:sbc@198.51.100.1:5060>",
            Some((1800, "uac")),
            Some(90),
        );
        let msg = parse(&raw);
        let req = match msg {
            rsip::SipMessage::Request(r) => r,
            _ => panic!(),
        };
        assert_eq!(req.method, rsip::Method::Invite);
        assert!(raw.contains("Session-Expires: 1800;refresher=uac\r\n"));
        assert!(raw.contains("Min-SE: 90\r\n"));
        assert!(raw.contains(&format!("Content-Length: {}\r\n", sdp.len())));
        assert!(raw.ends_with(sdp));
    }

    #[test]
    fn reinvite_without_min_se_omits_header() {
        let raw = build_reinvite(
            &dialog(),
            "v=0\r\n",
            "<sip:sbc@1.2.3.4>",
            Some((1800, "uac")),
            None,
        );
        parse(&raw);
        assert!(!raw.contains("Min-SE:"));
    }

    const INVITE_WITH_BODY: &str = "INVITE sip:bob@203.0.113.9:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKdeadbeef;rport\r\n\
         Max-Forwards: 70\r\n\
         Route: <sip:proxy.example.com;lr>\r\n\
         From: <sip:alice@a.example.com>;tag=al-1\r\n\
         To: <sip:bob@b.example.com>\r\n\
         Call-ID: xyz@host\r\n\
         CSeq: 3 INVITE\r\n\
         Proxy-Authorization: Digest username=\"u\", nonce=\"n\"\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: 22\r\n\r\n\
         v=0\r\nm=audio 1 RTP/AVP 0\r\n";

    #[test]
    fn ack_for_non_2xx_copies_invite_identity_and_response_to() {
        let raw = build_ack_for_non_2xx(INVITE_WITH_BODY, "<sip:bob@b.example.com>;tag=gen-42")
            .expect("ack built");
        parse(&raw);
        assert!(raw.starts_with("ACK sip:bob@203.0.113.9:5060 SIP/2.0\r\n"));
        assert!(
            raw.contains("Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKdeadbeef;rport\r\n"),
            "ACK must reuse the INVITE's top Via verbatim: {}",
            raw
        );
        assert!(raw.contains("Route: <sip:proxy.example.com;lr>\r\n"));
        assert!(raw.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
        assert!(raw.contains("To: <sip:bob@b.example.com>;tag=gen-42\r\n"));
        assert!(raw.contains("Call-ID: xyz@host\r\n"));
        assert!(raw.contains("CSeq: 3 ACK\r\n"));
        assert!(raw.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn ack_for_non_2xx_rejects_non_invite() {
        assert!(
            build_ack_for_non_2xx("BYE sip:x SIP/2.0\r\nCall-ID: 1\r\n\r\n", "<sip:x>").is_none()
        );
    }

    #[test]
    fn top_via_branch_variants() {
        assert_eq!(
            top_via_branch(INVITE_WITH_BODY).as_deref(),
            Some("z9hG4bKdeadbeef")
        );
        let resp = "SIP/2.0 422 Session Interval Too Small\r\n\
                    v: SIP/2.0/UDP 198.51.100.1:5060;rport=5060;received=1.2.3.4;branch=z9hG4bKabc\r\n\
                    Via: SIP/2.0/UDP other;branch=z9hG4bKnot-top\r\n\r\n";
        assert_eq!(top_via_branch(resp).as_deref(), Some("z9hG4bKabc"));
        let no_branch = "INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;rport\r\n\r\n";
        assert_eq!(top_via_branch(no_branch), None);
        assert_eq!(top_via_branch("INVITE sip:x SIP/2.0\r\n\r\n"), None);
    }

    #[test]
    fn renew_invite_transaction_bumps_cseq_fresh_branch_and_keeps_body() {
        let out = renew_invite_transaction(INVITE_WITH_BODY);
        parse(&out);
        assert!(out.contains("CSeq: 4 INVITE\r\n"), "{}", out);
        assert!(!out.contains("z9hG4bKdeadbeef"), "branch must be fresh");
        assert!(out.contains("branch=z9hG4bK"));
        assert!(
            out.contains(";rport\r\n"),
            "Via params after the branch survive"
        );
        assert!(
            out.ends_with("Content-Length: 22\r\n\r\nv=0\r\nm=audio 1 RTP/AVP 0\r\n"),
            "body must be byte-identical: {}",
            out
        );
        assert!(
            out.contains("Proxy-Authorization: Digest"),
            "other headers untouched"
        );
        assert_eq!(
            out.len(),
            INVITE_WITH_BODY.len() + (new_branch().len() - "z9hG4bKdeadbeef".len())
        );
    }

    #[test]
    fn renew_invite_transaction_without_body() {
        let invite = "INVITE sip:x@y SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKold\r\nCSeq: 7 INVITE\r\nContent-Length: 0\r\n\r\n";
        let out = renew_invite_transaction(invite);
        assert!(out.ends_with("Content-Length: 0\r\n\r\n"));
        assert!(out.contains("CSeq: 8 INVITE\r\n"));
        assert!(!out.contains("z9hG4bKold"));
    }

    #[test]
    fn invite_identity_parses_compact_and_routes() {
        let invite = "INVITE sip:x@y SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bK1\r\nf: <sip:a@b>;tag=1\r\n\
                      t: <sip:x@y>\r\ni: cid-1\r\nCSeq: 12 INVITE\r\nRoute: <sip:r1;lr>\r\nRoute: <sip:r2;lr>\r\n\r\n";
        let id = parse_invite_identity(invite).unwrap();
        assert_eq!(id.top_via, "SIP/2.0/UDP h;branch=z9hG4bK1");
        assert_eq!(id.cseq, 12);
        assert_eq!(id.routes, vec!["<sip:r1;lr>", "<sip:r2;lr>"]);
        assert!(
            parse_invite_identity("INVITE sip:x SIP/2.0\r\nVia: x\r\n\r\n").is_none(),
            "missing From/To/Call-ID"
        );
    }

    #[test]
    fn cancel_copies_invite_identity() {
        let invite = "INVITE sip:bob@203.0.113.9:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKdeadbeef;rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@a.example.com>;tag=al-1\r\n\
             To: <sip:bob@b.example.com>\r\n\
             Call-ID: xyz@host\r\n\
             CSeq: 3 INVITE\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: 0\r\n\r\n";
        let raw = build_cancel(invite).expect("cancel built");
        parse(&raw);
        assert!(raw.starts_with("CANCEL sip:bob@203.0.113.9:5060 SIP/2.0\r\n"));
        assert!(
            raw.contains("branch=z9hG4bKdeadbeef"),
            "CANCEL must reuse the INVITE branch"
        );
        assert!(raw.contains("CSeq: 3 CANCEL\r\n"));
        assert!(raw.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
        assert!(raw.contains("To: <sip:bob@b.example.com>\r\n"));
    }

    #[test]
    fn cancel_rejects_non_invite() {
        assert!(build_cancel("BYE sip:x SIP/2.0\r\nCall-ID: 1\r\n\r\n").is_none());
    }
}
