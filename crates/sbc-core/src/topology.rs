//! Topology Hiding — RFC 3323 / RFC 3325
//!
//! In a B2BUA, every SIP message must have Via/Contact/Record-Route headers
//! rewritten so that:
//!   - The SBC's own address appears in place of the internal network topology
//!   - Upstream proxies and callers cannot learn internal server addresses
//!   - Route sets are maintained correctly for mid-dialog requests
//!
//! This module implements:
//!   1. **Via stripping / rewriting** — remove the client's Via, insert SBC Via
//!   2. **Contact rewriting**        — replace peer Contact with SBC contact URI
//!   3. **Record-Route rewriting**   — replace internal RR with SBC URI
//!   4. **Route stripping**          — remove Route headers pointing to SBC
//!   5. **Max-Forwards decrement**   — RFC 3261 §8.1.1

use crate::{Error, Result};

// ─────────────────────────────────────────────────────────────────────────────
// SBC identity used for header rewriting
// ─────────────────────────────────────────────────────────────────────────────

/// The SBC's public-facing identity for topology hiding.
#[derive(Debug, Clone)]
pub struct SbcIdentity {
    /// Public IP address (e.g. "203.0.113.1")
    pub public_ip: String,
    /// SIP domain (e.g. "sip.nixi.tel")
    pub sip_domain: String,
    /// SIP port (usually 5060 for UDP/TCP, 5061 for TLS)
    pub sip_port: u16,
    /// Whether to use "sips:" URIs (TLS transport)
    pub tls: bool,
}

impl SbcIdentity {
    pub fn new(public_ip: &str, sip_domain: &str, sip_port: u16, tls: bool) -> Self {
        Self {
            public_ip:  public_ip.to_string(),
            sip_domain: sip_domain.to_string(),
            sip_port,
            tls,
        }
    }

    /// Build a SIP URI for this SBC identity
    pub fn sip_uri(&self) -> String {
        let scheme = if self.tls { "sips" } else { "sip" };
        if self.sip_port == 5060 && !self.tls {
            format!("{}:{}", scheme, self.sip_domain)
        } else {
            format!("{}:{}:{}", scheme, self.sip_domain, self.sip_port)
        }
    }

    /// Build a Contact URI with the SBC public IP
    pub fn contact_uri(&self) -> String {
        let scheme = if self.tls { "sips" } else { "sip" };
        if self.tls {
            format!("{}:sbc@{}:{};transport=tls", scheme, self.public_ip, self.sip_port)
        } else {
            format!("{}:sbc@{}:{}", scheme, self.public_ip, self.sip_port)
        }
    }

    /// Build a Via header value for a given transport and branch
    pub fn via_header(&self, transport: &str, branch: &str) -> String {
        format!(
            "SIP/2.0/{transport} {ip}:{port};branch={branch}",
            transport = transport.to_uppercase(),
            ip        = self.public_ip,
            port      = self.sip_port,
            branch    = branch,
        )
    }

    /// Build a Record-Route header value
    pub fn record_route(&self) -> String {
        let uri = self.sip_uri();
        if self.tls {
            format!("<{};transport=tls;lr>", uri)
        } else {
            format!("<{};lr>", uri)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIP message header manipulation (line-based parser)
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed SIP message (headers + body split by empty line).
/// We operate on raw text because rsip focuses on parsing, not round-tripping.
#[derive(Debug, Clone)]
pub struct RawSipMessage {
    /// First line: "SIP/2.0 200 OK" or "INVITE sip:bob@domain SIP/2.0"
    pub start_line: String,
    /// All header lines (name: value)
    pub headers: Vec<String>,
    /// Body (may be empty)
    pub body: String,
}

impl RawSipMessage {
    /// Parse raw SIP text into start line + headers + body
    pub fn parse(raw: &str) -> Result<Self> {
        // Split headers from body at the first CRLFCRLF or LFLF
        let (header_part, body) = if let Some(pos) = raw.find("\r\n\r\n") {
            (&raw[..pos], raw[pos + 4..].to_string())
        } else if let Some(pos) = raw.find("\n\n") {
            (&raw[..pos], raw[pos + 2..].to_string())
        } else {
            (raw, String::new())
        };

        let mut lines = header_part.splitn(2, |c| c == '\r' || c == '\n');
        let start_line = lines.next()
            .ok_or_else(|| Error::Transport("empty SIP message".into()))?
            .trim()
            .to_string();

        // Collect header lines (handle folding: line starting with SP/TAB)
        let mut headers = Vec::new();
        let mut current: Option<String> = None;
        for line in header_part.lines().skip(1) {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Folded header continuation
                if let Some(ref mut h) = current {
                    h.push(' ');
                    h.push_str(line.trim());
                }
            } else if line.is_empty() {
                if let Some(h) = current.take() { headers.push(h); }
            } else {
                if let Some(h) = current.take() { headers.push(h); }
                current = Some(line.to_string());
            }
        }
        if let Some(h) = current { headers.push(h); }

        Ok(Self { start_line, headers, body })
    }

    /// Serialize back to a raw SIP string
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.start_line);
        out.push_str("\r\n");
        for h in &self.headers {
            out.push_str(h);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body);
        out
    }

    /// Return all values of a named header (case-insensitive).
    pub fn header_values(&self, name: &str) -> Vec<String> {
        let name_lc = name.to_lowercase();
        self.headers.iter()
            .filter_map(|h| {
                let colon = h.find(':')?;
                let hname = h[..colon].trim().to_lowercase();
                if hname == name_lc || short_form(&hname) == name_lc {
                    Some(h[colon + 1..].trim().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove all instances of a named header.
    pub fn remove_header(&mut self, name: &str) {
        let name_lc = name.to_lowercase();
        self.headers.retain(|h| {
            if let Some(colon) = h.find(':') {
                let hname = h[..colon].trim().to_lowercase();
                hname != name_lc && short_form(&hname) != name_lc
            } else {
                true
            }
        });
    }

    /// Insert a header at the top (after start line)
    pub fn prepend_header(&mut self, header: String) {
        self.headers.insert(0, header);
    }

    /// Append a header at the end (before body)
    pub fn append_header(&mut self, header: String) {
        self.headers.push(header);
    }

    /// Replace the first occurrence of a named header value.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let name_lc = name.to_lowercase();
        let new_line = format!("{}: {}", name, value);
        for h in &mut self.headers {
            if let Some(colon) = h.find(':') {
                let hname = h[..colon].trim().to_lowercase();
                if hname == name_lc || short_form(&hname) == name_lc {
                    *h = new_line.clone();
                    return;
                }
            }
        }
        self.headers.push(new_line);
    }

    /// Decrement Max-Forwards, return Err if 0.
    pub fn decrement_max_forwards(&mut self) -> Result<()> {
        let name = "max-forwards";
        for h in &mut self.headers {
            if let Some(colon) = h.find(':') {
                if h[..colon].trim().to_lowercase() == name {
                    let val_str = h[colon + 1..].trim();
                    if let Ok(n) = val_str.parse::<u32>() {
                        if n == 0 {
                            return Err(Error::Transport("Max-Forwards reached 0".into()));
                        }
                        *h = format!("Max-Forwards: {}", n - 1);
                        return Ok(());
                    }
                }
            }
        }
        // If not present, add default 70
        self.headers.push("Max-Forwards: 70".to_string());
        Ok(())
    }

    /// Check whether message is a request (not a response)
    pub fn is_request(&self) -> bool {
        !self.start_line.starts_with("SIP/2.0")
    }

    /// Extract the SIP method from a request start line
    pub fn method(&self) -> Option<&str> {
        if self.is_request() {
            self.start_line.split_whitespace().next()
        } else {
            None
        }
    }
}

/// Map compact header names to long form for comparison
fn short_form(name: &str) -> &str {
    match name {
        "v" => "via",
        "f" => "from",
        "t" => "to",
        "m" => "contact",
        "i" => "call-id",
        "e" => "content-encoding",
        "l" => "content-length",
        "c" => "content-type",
        "s" => "subject",
        "k" => "supported",
        _   => name,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Topology hiding engine
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a unique Via branch parameter (RFC 3261 magic cookie + random)
pub fn new_branch() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("z9hG4bK{:08x}", t)
}

/// Apply topology hiding to an **inbound** SIP message (coming from UA/peer).
///
/// Actions:
///   1. Remove all Via headers from the peer
///   2. Insert SBC's Via (for the outbound leg)
///   3. Rewrite Contact to SBC URI
///   4. Remove Record-Route headers (SBC will insert its own)
///   5. Decrement Max-Forwards
///   6. Optionally strip privacy-leaking headers (P-Asserted-Identity)
///
/// Returns the modified message as a String.
pub fn apply_topology_hiding_inbound(
    raw: &str,
    identity: &SbcIdentity,
    transport: &str,
) -> Result<String> {
    let mut msg = RawSipMessage::parse(raw)?;

    if msg.is_request() {
        // Decrement Max-Forwards
        msg.decrement_max_forwards()?;

        // Remove all Via headers (hide peer topology)
        msg.remove_header("via");
        msg.remove_header("v"); // compact form

        // Insert SBC Via
        let branch = new_branch();
        let via = format!("Via: {}", identity.via_header(transport, &branch));
        msg.prepend_header(via);

        // Rewrite Contact
        let values = msg.header_values("contact");
        if !values.is_empty() {
            msg.remove_header("contact");
            msg.remove_header("m"); // compact
            msg.append_header(format!("Contact: <{}>", identity.contact_uri()));
        }

        // Remove Record-Route (SBC will insert its own on forwarding)
        msg.remove_header("record-route");

        // Strip Route header entries that point back to SBC (loop prevention)
        // (In production you'd check the URI; here we remove all to let SBC rebuild)
    } else {
        // Response: strip Via headers that are not ours
        // (We keep only the topmost Via that came from the original UAC)
        // In a real B2BUA the response branches are correlated via transaction layer.
        // Here we just ensure no internal Via leaks outward.
        let vias = msg.header_values("via");
        msg.remove_header("via");
        // Re-insert only the last Via (UAC's Via)
        if let Some(last_via) = vias.last() {
            msg.prepend_header(format!("Via: {}", last_via));
        }

        // Remove Record-Route on responses (not needed)
        // Actually Record-Route should be preserved in responses — keep it
    }

    Ok(msg.to_string())
}

/// Apply topology hiding to an **outbound** SIP message (going to trunk/peer).
///
/// Actions:
///   1. Replace Contact with SBC contact URI
///   2. Insert Record-Route with SBC URI (so future in-dialog requests go through SBC)
///   3. Remove any internal Route headers
///   4. Generate a fresh Via for this outbound leg
pub fn apply_topology_hiding_outbound(
    raw: &str,
    identity: &SbcIdentity,
    transport: &str,
) -> Result<String> {
    let mut msg = RawSipMessage::parse(raw)?;

    if msg.is_request() {
        // Replace Via
        msg.remove_header("via");
        let branch = new_branch();
        let via = format!("Via: {}", identity.via_header(transport, &branch));
        msg.prepend_header(via);

        // Replace Contact
        msg.remove_header("contact");
        msg.remove_header("m");
        msg.append_header(format!("Contact: <{}>", identity.contact_uri()));

        // Insert Record-Route (so in-dialog requests route through SBC)
        msg.remove_header("record-route");
        msg.prepend_header(format!("Record-Route: {}", identity.record_route()));

        // Remove internal Route headers
        msg.remove_header("route");
    }

    Ok(msg.to_string())
}

/// Strip headers that could reveal internal topology or user identity
/// beyond what's needed (e.g. P-Asserted-Identity, X-Forwarded-For).
pub fn strip_privacy_headers(raw: &str) -> Result<String> {
    let mut msg = RawSipMessage::parse(raw)?;
    msg.remove_header("p-asserted-identity");
    msg.remove_header("p-preferred-identity");
    msg.remove_header("x-forwarded-for");
    msg.remove_header("x-real-ip");
    msg.remove_header("server");       // SIP Server header
    msg.remove_header("user-agent");   // optionally mask UA
    Ok(msg.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity() -> SbcIdentity {
        SbcIdentity::new("203.0.113.1", "sip.nixi.tel", 5060, false)
    }

    const INVITE: &str = "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK1234\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabcd\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Max-Forwards: 70\r\n\
Contact: <sip:alice@192.168.1.100:5060>\r\n\
Record-Route: <sip:proxy.atlanta.com;lr>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\
\r\n\
Test";

    const RESPONSE_200: &str = "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK1234\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabcd\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.168.1.200:5060>\r\n\
Content-Length: 0\r\n\
\r\n";

    // ── RawSipMessage parsing ─────────────────────────────────────────────────

    #[test]
    fn test_parse_request() {
        let msg = RawSipMessage::parse(INVITE).unwrap();
        assert_eq!(msg.start_line, "INVITE sip:bob@example.com SIP/2.0");
        assert!(msg.is_request());
        assert_eq!(msg.method(), Some("INVITE"));
        assert_eq!(msg.body, "Test");
    }

    #[test]
    fn test_parse_response() {
        let msg = RawSipMessage::parse(RESPONSE_200).unwrap();
        assert_eq!(msg.start_line, "SIP/2.0 200 OK");
        assert!(!msg.is_request());
        assert_eq!(msg.method(), None);
    }

    #[test]
    fn test_header_values_via() {
        let msg = RawSipMessage::parse(INVITE).unwrap();
        let vias = msg.header_values("via");
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("192.168.1.100"));
    }

    #[test]
    fn test_remove_header() {
        let mut msg = RawSipMessage::parse(INVITE).unwrap();
        msg.remove_header("via");
        assert!(msg.header_values("via").is_empty());
    }

    #[test]
    fn test_set_header() {
        let mut msg = RawSipMessage::parse(INVITE).unwrap();
        msg.set_header("Max-Forwards", "50");
        let mf = msg.header_values("max-forwards");
        assert_eq!(mf[0], "50");
    }

    #[test]
    fn test_decrement_max_forwards() {
        let mut msg = RawSipMessage::parse(INVITE).unwrap();
        msg.decrement_max_forwards().unwrap();
        let mf = msg.header_values("max-forwards")[0].parse::<u32>().unwrap();
        assert_eq!(mf, 69);
    }

    #[test]
    fn test_max_forwards_zero_error() {
        let raw = "OPTIONS sip:test@example.com SIP/2.0\r\nMax-Forwards: 0\r\n\r\n";
        let mut msg = RawSipMessage::parse(raw).unwrap();
        assert!(msg.decrement_max_forwards().is_err());
    }

    // ── Topology hiding inbound ───────────────────────────────────────────────

    #[test]
    fn test_inbound_removes_peer_via() {
        let id = make_identity();
        let out = apply_topology_hiding_inbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let vias = msg.header_values("via");
        // Only SBC's Via should remain
        assert_eq!(vias.len(), 1);
        assert!(vias[0].contains("203.0.113.1"), "Via should contain SBC IP: {:?}", vias);
    }

    #[test]
    fn test_inbound_rewrites_contact() {
        let id = make_identity();
        let out = apply_topology_hiding_inbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let contacts = msg.header_values("contact");
        assert!(!contacts.is_empty(), "Contact should be present");
        assert!(contacts[0].contains("203.0.113.1") || contacts[0].contains("sip.nixi.tel"),
            "Contact should contain SBC address: {:?}", contacts);
    }

    #[test]
    fn test_inbound_removes_record_route() {
        let id = make_identity();
        let out = apply_topology_hiding_inbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let rr = msg.header_values("record-route");
        assert!(rr.is_empty(), "Record-Route should be removed from inbound: {:?}", rr);
    }

    #[test]
    fn test_inbound_decrements_max_forwards() {
        let id = make_identity();
        let out = apply_topology_hiding_inbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let mf: u32 = msg.header_values("max-forwards")[0].parse().unwrap();
        assert_eq!(mf, 69);
    }

    // ── Topology hiding outbound ──────────────────────────────────────────────

    #[test]
    fn test_outbound_inserts_record_route() {
        let id = make_identity();
        let out = apply_topology_hiding_outbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let rr = msg.header_values("record-route");
        assert!(!rr.is_empty(), "Record-Route should be inserted");
        assert!(rr[0].contains("sip.nixi.tel") || rr[0].contains("203.0.113.1"),
            "Record-Route should contain SBC address: {:?}", rr);
    }

    #[test]
    fn test_outbound_fresh_via() {
        let id = make_identity();
        let out = apply_topology_hiding_outbound(INVITE, &id, "UDP").unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        let vias = msg.header_values("via");
        assert_eq!(vias.len(), 1);
        assert!(vias[0].contains("z9hG4bK"), "Via branch should have magic cookie");
    }

    // ── SBC identity helpers ─────────────────────────────────────────────────

    #[test]
    fn test_sip_uri() {
        let id = make_identity();
        assert_eq!(id.sip_uri(), "sip:sip.nixi.tel");

        let id_tls = SbcIdentity::new("1.2.3.4", "sip.example.com", 5061, true);
        assert_eq!(id_tls.sip_uri(), "sips:sip.example.com:5061");
    }

    #[test]
    fn test_record_route_format() {
        let id = make_identity();
        let rr = id.record_route();
        assert!(rr.starts_with('<'), "RR should be in <> brackets");
        assert!(rr.contains(";lr"), "RR should have ;lr parameter");
    }

    #[test]
    fn test_via_header_format() {
        let id = make_identity();
        let via = id.via_header("UDP", "z9hG4bKtest");
        assert!(via.starts_with("SIP/2.0/UDP"));
        assert!(via.contains("203.0.113.1"));
        assert!(via.contains("branch=z9hG4bKtest"));
    }

    // ── Privacy header stripping ──────────────────────────────────────────────

    #[test]
    fn test_strip_privacy_headers() {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
P-Asserted-Identity: <sip:alice@internal.corp>\r\n\
X-Forwarded-For: 10.0.0.1\r\n\
From: Alice <sip:alice@example.com>;tag=1\r\n\
Content-Length: 0\r\n\r\n";

        let out = strip_privacy_headers(raw).unwrap();
        let msg = RawSipMessage::parse(&out).unwrap();
        assert!(msg.header_values("p-asserted-identity").is_empty());
        assert!(msg.header_values("x-forwarded-for").is_empty());
        // From should still be present
        assert!(!msg.header_values("from").is_empty());
    }

    // ── Round-trip integrity ──────────────────────────────────────────────────

    #[test]
    fn test_body_preserved_after_topology_hiding() {
        let id = make_identity();
        let out = apply_topology_hiding_inbound(INVITE, &id, "UDP").unwrap();
        assert!(out.ends_with("Test"), "body should be preserved");
    }
}
