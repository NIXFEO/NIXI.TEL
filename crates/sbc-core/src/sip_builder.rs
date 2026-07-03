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
    let d2 = DialogInfo { cseq: invite_cseq, ..d.clone() };
    build_request("ACK", &d2, "ACK", &[], None)
}

/// Refresh re-INVITE (RFC 4028) with unchanged SDP.
/// `session_expires` = (interval_secs, refresher), e.g. (1800, "uac").
pub fn build_reinvite(
    d: &DialogInfo,
    sdp: &str,
    contact_uri: &str,
    session_expires: Option<(u32, &str)>,
) -> String {
    let se_value;
    let mut extras: Vec<(&str, &str)> = vec![
        ("Contact", contact_uri),
        ("Supported", "timer"),
        ("Content-Type", "application/sdp"),
    ];
    if let Some((interval, refresher)) = session_expires {
        se_value = format!("{};refresher={}", interval, refresher);
        extras.insert(2, ("Session-Expires", &se_value));
        return build_request("INVITE", d, "INVITE", &extras, Some(sdp));
    }
    build_request("INVITE", d, "INVITE", &extras, Some(sdp))
}

/// CANCEL for a pending INVITE (RFC 3261 §9.1): same Request-URI, Via branch,
/// From, To, Call-ID and CSeq number as the INVITE — only the method differs.
/// Built directly from the raw INVITE we sent.
pub fn build_cancel(original_invite_raw: &str) -> Option<String> {
    let mut request_line = None;
    let mut via = None;
    let mut from = None;
    let mut to = None;
    let mut call_id = None;
    let mut cseq_num = None;

    for (i, line) in original_invite_raw.split("\r\n").enumerate() {
        if i == 0 {
            // "INVITE sip:x@y SIP/2.0"
            let mut parts = line.splitn(3, ' ');
            if parts.next() != Some("INVITE") {
                return None;
            }
            request_line = parts.next().map(str::to_string);
            continue;
        }
        if line.is_empty() {
            break; // end of headers
        }
        let lower = line.to_lowercase();
        if lower.starts_with("via:") && via.is_none() {
            via = Some(line["via:".len()..].trim().to_string());
        } else if lower.starts_with("from:") {
            from = Some(line["from:".len()..].trim().to_string());
        } else if lower.starts_with("to:") {
            to = Some(line["to:".len()..].trim().to_string());
        } else if lower.starts_with("call-id:") {
            call_id = Some(line["call-id:".len()..].trim().to_string());
        } else if lower.starts_with("cseq:") {
            cseq_num = line["cseq:".len()..]
                .trim()
                .split_whitespace()
                .next()
                .map(str::to_string);
        }
    }

    let (uri, via, from, to, call_id, cseq_num) =
        (request_line?, via?, from?, to?, call_id?, cseq_num?);

    Some(format!(
        "CANCEL {} SIP/2.0\r\n\
         Via: {}\r\n\
         Max-Forwards: 70\r\n\
         From: {}\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: {} CANCEL\r\n\
         Content-Length: 0\r\n\r\n",
        uri, via, from, to, call_id, cseq_num
    ))
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
        let headers: Vec<&str> = raw.split("\r\n").skip(1).take_while(|l| !l.is_empty()).collect();
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
        );
        let msg = parse(&raw);
        let req = match msg {
            rsip::SipMessage::Request(r) => r,
            _ => panic!(),
        };
        assert_eq!(req.method, rsip::Method::Invite);
        assert!(raw.contains("Session-Expires: 1800;refresher=uac\r\n"));
        assert!(raw.contains(&format!("Content-Length: {}\r\n", sdp.len())));
        assert!(raw.ends_with(sdp));
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
        assert!(raw.contains("branch=z9hG4bKdeadbeef"), "CANCEL must reuse the INVITE branch");
        assert!(raw.contains("CSeq: 3 CANCEL\r\n"));
        assert!(raw.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
        assert!(raw.contains("To: <sip:bob@b.example.com>\r\n"));
    }

    #[test]
    fn cancel_rejects_non_invite() {
        assert!(build_cancel("BYE sip:x SIP/2.0\r\nCall-ID: 1\r\n\r\n").is_none());
    }
}
