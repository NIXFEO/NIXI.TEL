//! SDP (Session Description Protocol) Parser and Manipulator
//!
//! RFC 4566 - SDP: Session Description Protocol
//! https://tools.ietf.org/html/rfc4566

use crate::{Error, Result};
use std::net::IpAddr;

/// SDP Session Description
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDescription {
    /// Version (v=)
    pub version: u32,

    /// Origin (o=)
    pub origin: Origin,

    /// Session Name (s=)
    pub session_name: String,

    /// Connection Information (c=)
    pub connection: Option<Connection>,

    /// Time Description (t=)
    pub time: TimeDescription,

    /// Media Descriptions (m=)
    pub media: Vec<MediaDescription>,
}

/// Origin line (o=)
#[derive(Debug, Clone, PartialEq)]
pub struct Origin {
    pub username: String,
    pub session_id: String,
    pub session_version: String,
    pub network_type: String,  // Usually "IN"
    pub address_type: String,  // Usually "IP4" or "IP6"
    pub address: String,
}

/// Connection line (c=)
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub network_type: String,  // Usually "IN"
    pub address_type: String,  // Usually "IP4" or "IP6"
    pub address: String,
}

/// Time description (t=)
#[derive(Debug, Clone, PartialEq)]
pub struct TimeDescription {
    pub start_time: String,  // Usually "0"
    pub stop_time: String,   // Usually "0"
}

/// Media description (m=)
#[derive(Debug, Clone, PartialEq)]
pub struct MediaDescription {
    /// Media type (audio, video, etc.)
    pub media_type: MediaType,

    /// Port number
    pub port: u16,

    /// Number of ports (optional, default 1)
    pub num_ports: Option<u16>,

    /// Protocol (RTP/AVP, RTP/SAVP, etc.)
    pub protocol: String,

    /// Format list (codec payload types)
    pub formats: Vec<u8>,

    /// Connection information (c=)
    pub connection: Option<Connection>,

    /// Attributes (a=)
    pub attributes: Vec<Attribute>,
}

/// Media type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Application,
    Text,
    Message,
}

/// Attribute line (a=)
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub key: String,
    pub value: Option<String>,
}

impl SessionDescription {
    /// Parse SDP from string
    ///
    /// This is a lenient parser that handles real-world SDP from Linphone,
    /// Baresip, and other softphones. It tolerates:
    /// - Extra session-level lines (b=, e=, p=, i=, u=, z=, k=, r=)
    /// - Port/count syntax in m= lines (e.g. "m=audio 49170/2 RTP/AVP 0")
    /// - Missing c= at session level (c= may be at media level only)
    /// - Attribute lines before t= (some broken implementations)
    pub fn parse(sdp: &str) -> Result<Self> {
        let mut lines = sdp.lines().peekable();

        // Skip leading blank lines (some implementations add them)
        while let Some(&line) = lines.peek() {
            if line.trim().is_empty() { lines.next(); } else { break; }
        }

        // Parse version (v=)
        let version = Self::parse_version(&mut lines)?;

        // Parse origin (o=)
        let origin = Self::parse_origin(&mut lines)?;

        // Parse session name (s=)
        let session_name = Self::parse_session_name(&mut lines)?;

        // Parse optional session-level lines until we hit t= or m=
        // These include: i=, u=, e=, p=, c=, b=
        let mut connection = None;
        loop {
            match lines.peek() {
                Some(&line) if line.starts_with("c=") => {
                    lines.next();
                    let value = line.strip_prefix("c=").unwrap();
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() == 3 {
                        connection = Some(Connection {
                            network_type: parts[0].to_string(),
                            address_type: parts[1].to_string(),
                            address: parts[2].to_string(),
                        });
                    }
                }
                Some(&line) if line.starts_with("t=") => break,
                Some(&line) if line.starts_with("m=") => break,
                Some(_) => { lines.next(); } // skip i=, u=, e=, p=, b=, etc.
                None => break,
            }
        }

        // Parse time (t=) — may be missing in some broken SDPs
        let time = if lines.peek().map_or(false, |l| l.starts_with("t=")) {
            Self::parse_time(&mut lines)?
        } else {
            TimeDescription { start_time: "0".to_string(), stop_time: "0".to_string() }
        };

        // Skip any lines between t= and first m= (r=, z=, k=, a= at session level)
        while let Some(&line) = lines.peek() {
            if line.starts_with("m=") { break; }
            if line.trim().is_empty() { lines.next(); continue; }
            lines.next(); // skip session-level a=, b=, k=, etc.
        }

        // Parse media descriptions (m=)
        let mut media = Vec::new();
        while lines.peek().is_some() {
            // Skip blank lines between media sections
            if lines.peek().map_or(false, |l| l.trim().is_empty()) {
                lines.next();
                continue;
            }
            // Only parse if next line is a media line
            if lines.peek().map_or(false, |l| !l.starts_with("m=")) {
                lines.next(); // skip stray lines
                continue;
            }
            match Self::parse_media(&mut lines) {
                Ok(m) => media.push(m),
                Err(_) => break, // Stop on parse error (lenient)
            }
        }

        Ok(Self {
            version,
            origin,
            session_name,
            connection,
            time,
            media,
        })
    }

    /// Serialize SDP to string
    pub fn to_string(&self) -> String {
        let mut sdp = String::new();

        // Version
        sdp.push_str(&format!("v={}\r\n", self.version));

        // Origin
        sdp.push_str(&format!(
            "o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.network_type,
            self.origin.address_type,
            self.origin.address
        ));

        // Session name
        sdp.push_str(&format!("s={}\r\n", self.session_name));

        // Connection (session level)
        if let Some(ref conn) = self.connection {
            sdp.push_str(&format!(
                "c={} {} {}\r\n",
                conn.network_type, conn.address_type, conn.address
            ));
        }

        // Time
        sdp.push_str(&format!("t={} {}\r\n", self.time.start_time, self.time.stop_time));

        // Media descriptions
        for media in &self.media {
            sdp.push_str(&media.to_string());
        }

        sdp
    }

    /// Replace IP address in SDP (for both session and media levels)
    pub fn replace_ip(&mut self, new_ip: IpAddr) {
        let ip_str = new_ip.to_string();
        let addr_type = if new_ip.is_ipv4() { "IP4" } else { "IP6" };

        // Update origin
        self.origin.address = ip_str.clone();
        self.origin.address_type = addr_type.to_string();

        // Update session connection if present
        if let Some(ref mut conn) = self.connection {
            conn.address = ip_str.clone();
            conn.address_type = addr_type.to_string();
        }

        // Update media connections
        for media in &mut self.media {
            if let Some(ref mut conn) = media.connection {
                conn.address = ip_str.clone();
                conn.address_type = addr_type.to_string();
            }
        }
    }

    /// Replace port for a specific media type
    pub fn replace_port(&mut self, media_type: MediaType, new_port: u16) {
        for media in &mut self.media {
            if media.media_type == media_type {
                media.port = new_port;
            }
        }
    }

    fn parse_version<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<u32>
    where
        I: Iterator<Item = &'a str>,
    {
        let line = lines.next().ok_or_else(|| Error::Parse("Missing version line".to_string()))?;
        let value = line.strip_prefix("v=")
            .ok_or_else(|| Error::Parse("Invalid version line".to_string()))?;
        value.parse().map_err(|_| Error::Parse("Invalid version number".to_string()))
    }

    fn parse_origin<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<Origin>
    where
        I: Iterator<Item = &'a str>,
    {
        let line = lines.next().ok_or_else(|| Error::Parse("Missing origin line".to_string()))?;
        let value = line.strip_prefix("o=")
            .ok_or_else(|| Error::Parse("Invalid origin line".to_string()))?;

        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 6 {
            return Err(Error::Parse("Invalid origin format".to_string()));
        }

        Ok(Origin {
            username: parts[0].to_string(),
            session_id: parts[1].to_string(),
            session_version: parts[2].to_string(),
            network_type: parts[3].to_string(),
            address_type: parts[4].to_string(),
            address: parts[5].to_string(),
        })
    }

    fn parse_session_name<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<String>
    where
        I: Iterator<Item = &'a str>,
    {
        let line = lines.next().ok_or_else(|| Error::Parse("Missing session name".to_string()))?;
        let value = line.strip_prefix("s=")
            .ok_or_else(|| Error::Parse("Invalid session name line".to_string()))?;
        Ok(value.to_string())
    }

    #[allow(dead_code)]
    fn parse_connection_opt<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<Option<Connection>>
    where
        I: Iterator<Item = &'a str>,
    {
        if let Some(&line) = lines.peek() {
            if line.starts_with("c=") {
                lines.next(); // consume the line
                let value = line.strip_prefix("c=").unwrap();
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() != 3 {
                    return Err(Error::Parse("Invalid connection format".to_string()));
                }
                return Ok(Some(Connection {
                    network_type: parts[0].to_string(),
                    address_type: parts[1].to_string(),
                    address: parts[2].to_string(),
                }));
            }
        }
        Ok(None)
    }

    fn parse_time<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<TimeDescription>
    where
        I: Iterator<Item = &'a str>,
    {
        let line = lines.next().ok_or_else(|| Error::Parse("Missing time line".to_string()))?;
        let value = line.strip_prefix("t=")
            .ok_or_else(|| Error::Parse("Invalid time line".to_string()))?;

        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(Error::Parse("Invalid time format".to_string()));
        }

        Ok(TimeDescription {
            start_time: parts[0].to_string(),
            stop_time: parts[1].to_string(),
        })
    }

    fn parse_media<'a, I>(lines: &mut std::iter::Peekable<I>) -> Result<MediaDescription>
    where
        I: Iterator<Item = &'a str>,
    {
        // Parse media line (m=)
        let line = lines.next().ok_or_else(|| Error::Parse("Missing media line".to_string()))?;
        let value = line.strip_prefix("m=")
            .ok_or_else(|| Error::Parse("Invalid media line".to_string()))?;

        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(Error::Parse("Invalid media format".to_string()));
        }

        let media_type = MediaType::from_str(parts[0])?;
        // Port may be "port" or "port/numports" (RFC 4566 §5.14)
        let port_str = parts[1].split('/').next().unwrap_or(parts[1]);
        let port: u16 = port_str.parse()
            .map_err(|_| Error::Parse(format!("Invalid port number: {}", parts[1])))?;
        let protocol = parts[2].to_string();
        let formats: Vec<u8> = parts[3..]
            .iter()
            .filter_map(|f| f.parse().ok())
            .collect();

        // Parse connection and attributes for this media
        let mut connection = None;
        let mut attributes = Vec::new();

        while let Some(&line) = lines.peek() {
            if line.starts_with("m=") {
                break; // Next media section
            }

            lines.next(); // consume

            if line.starts_with("c=") {
                let value = line.strip_prefix("c=").unwrap();
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() == 3 {
                    connection = Some(Connection {
                        network_type: parts[0].to_string(),
                        address_type: parts[1].to_string(),
                        address: parts[2].to_string(),
                    });
                }
            } else if line.starts_with("a=") {
                let value = line.strip_prefix("a=").unwrap();
                if let Some(colon_pos) = value.find(':') {
                    attributes.push(Attribute {
                        key: value[..colon_pos].to_string(),
                        value: Some(value[colon_pos + 1..].to_string()),
                    });
                } else {
                    attributes.push(Attribute {
                        key: value.to_string(),
                        value: None,
                    });
                }
            }
        }

        Ok(MediaDescription {
            media_type,
            port,
            num_ports: None,
            protocol,
            formats,
            connection,
            attributes,
        })
    }
}

impl MediaDescription {
    fn to_string(&self) -> String {
        let mut s = String::new();

        // Media line
        s.push_str(&format!(
            "m={} {} {}",
            self.media_type.as_str(),
            self.port,
            self.protocol
        ));
        for fmt in &self.formats {
            s.push_str(&format!(" {}", fmt));
        }
        s.push_str("\r\n");

        // Connection
        if let Some(ref conn) = self.connection {
            s.push_str(&format!(
                "c={} {} {}\r\n",
                conn.network_type, conn.address_type, conn.address
            ));
        }

        // Attributes
        for attr in &self.attributes {
            if let Some(ref value) = attr.value {
                s.push_str(&format!("a={}:{}\r\n", attr.key, value));
            } else {
                s.push_str(&format!("a={}\r\n", attr.key));
            }
        }

        s
    }
}

/// WebRTC-specific attributes to strip when transforming SDP for a PSTN trunk.
#[allow(dead_code)]
const WEBRTC_STRIP_ATTRS: &[&str] = &[
    "fingerprint", "setup", "ice-ufrag", "ice-pwd", "ice-options", "ice-lite",
    "candidate", "rtcp-mux", "rtcp-rsize", "mid", "extmap", "ssrc", "ssrc-group",
    "msid", "msid-semantic", "group", "rtcp-fb", "fmtp", "crypto",
];

/// Transform a WebRTC SDP offer into a plain RTP SDP suitable for a PSTN trunk.
///
/// Changes:
///   - Protocol: UDP/TLS/RTP/SAVPF → RTP/AVP
///   - Codec: strip all payload types, offer only PCMA (PT 8)
///   - Remove: all WebRTC-specific attributes (fingerprint, ICE, DTLS, SSRC, etc.)
///   - Replace: c= with SBC public IP, m= port with SBC RTP proxy port
///   - Add: a=rtpmap:8 PCMA/8000, a=sendrecv, a=ptime:20
pub fn transform_webrtc_to_trunk(webrtc_sdp: &str, sbc_ip: &str, rtp_port: u16) -> String {
    let mut sdp = String::new();

    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=- 0 0 IN IP4 {}\r\n", sbc_ip));
    sdp.push_str("s=SBC\r\n");
    sdp.push_str(&format!("c=IN IP4 {}\r\n", sbc_ip));
    sdp.push_str("t=0 0\r\n");
    // Detect telephone-event PT in original SDP first, so we can include it in m= line
    let mut te_pt: Option<u8> = None;
    for line in webrtc_sdp.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("a=rtpmap:") {
            if val.contains("telephone-event") {
                if let Some(pt_str) = val.split_whitespace().next() {
                    if let Ok(pt) = pt_str.parse::<u8>() {
                        te_pt = Some(pt);
                    }
                }
            }
        }
    }

    // m= line includes both PCMA (8) and telephone-event PT if present
    if let Some(pt) = te_pt {
        sdp.push_str(&format!("m=audio {} RTP/AVP 8 {}\r\n", rtp_port, pt));
    } else {
        sdp.push_str(&format!("m=audio {} RTP/AVP 8 101\r\n", rtp_port));
    }
    sdp.push_str("a=rtpmap:8 PCMA/8000\r\n");
    sdp.push_str("a=ptime:20\r\n");
    sdp.push_str("a=sendrecv\r\n");

    // Add telephone-event attributes
    if let Some(pt) = te_pt {
        sdp.push_str(&format!("a=rtpmap:{} telephone-event/8000\r\n", pt));
        sdp.push_str(&format!("a=fmtp:{} 0-16\r\n", pt));
    } else {
        // Default: add telephone-event with PT 101 (most common)
        sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
        sdp.push_str("a=fmtp:101 0-16\r\n");
    }

    sdp
}

impl MediaType {
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "audio" => Ok(MediaType::Audio),
            "video" => Ok(MediaType::Video),
            "application" => Ok(MediaType::Application),
            "text" => Ok(MediaType::Text),
            "message" => Ok(MediaType::Message),
            _ => Err(Error::Parse(format!("Unknown media type: {}", s))),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            MediaType::Audio => "audio",
            MediaType::Video => "video",
            MediaType::Application => "application",
            MediaType::Text => "text",
            MediaType::Message => "message",
        }
    }
}


/// Extract the negotiated telephone-event payload type (RFC 4733) and its
/// clock rate from an SDP body. Returns the first `a=rtpmap:<pt> telephone-event/<rate>`.
pub fn telephone_event_pt(sdp: &str) -> Option<(u8, u32)> {
    for line in sdp.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("a=rtpmap:") {
            if let Some(te_pos) = val.find("telephone-event") {
                let pt = val.split_whitespace().next()?.parse::<u8>().ok()?;
                let rate = val[te_pos..]
                    .split('/')
                    .nth(1)
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|r| r.parse::<u32>().ok())
                    .unwrap_or(8000);
                return Some((pt, rate));
            }
        }
    }
    None
}

/// Name of a well-known static RTP payload type (RFC 3551), for PTs that
/// carry no `a=rtpmap:` line. Returns `None` for dynamic (≥96) or unknown PTs.
fn static_pt_name(pt: u8) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU"),
        3 => Some("GSM"),
        8 => Some("PCMA"),
        9 => Some("G722"),
        18 => Some("G729"),
        _ => None,
    }
}

/// Extract the negotiated audio codec name from an SDP *answer*.
///
/// In an answer the first payload type on the `m=audio` line is the chosen
/// codec. Its name comes from the matching `a=rtpmap:<pt> NAME/rate` line, or
/// from the static payload-type table when no rtpmap is present (e.g. PCMU/0,
/// PCMA/8). `telephone-event` and comfort-noise (`CN`) are skipped — they are
/// never the primary voice codec. Returns e.g. `"PCMU"`, `"PCMA"`, `"opus"`.
pub fn negotiated_audio_codec(sdp: &str) -> Option<String> {
    // First audio m= line: "m=audio <port> <proto> <pt> <pt> ..."
    let m_audio = sdp
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("m=audio "))?;
    let pts: Vec<u8> = m_audio
        .split_whitespace()
        .skip(3)
        .filter_map(|f| f.parse::<u8>().ok())
        .collect();

    for pt in pts {
        // Resolve name via rtpmap if present, else the static table.
        let name = sdp
            .lines()
            .map(str::trim)
            .find_map(|l| {
                let val = l.strip_prefix("a=rtpmap:")?;
                let mut it = val.split_whitespace();
                let map_pt = it.next()?.parse::<u8>().ok()?;
                if map_pt != pt {
                    return None;
                }
                Some(it.next()?.split('/').next()?.to_string())
            })
            .or_else(|| static_pt_name(pt).map(str::to_string));

        match name.as_deref() {
            // Skip non-voice payloads; keep scanning the format list.
            Some("telephone-event") | Some("CN") | None => continue,
            Some(_) => return name,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_telephone_event_pt() {
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n";
        assert_eq!(telephone_event_pt(sdp), Some((101, 8000)));

        let sdp96 = "m=audio 5004 RTP/AVP 8 96\r\na=rtpmap:96 telephone-event/48000\r\n";
        assert_eq!(telephone_event_pt(sdp96), Some((96, 48000)));

        let none = "m=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(telephone_event_pt(none), None);
    }

    use super::*;

    const SAMPLE_SDP: &str = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 192.168.1.100\r\n\
s=Call\r\n\
c=IN IP4 192.168.1.100\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 97\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:97 iLBC/8000\r\n";

    #[test]
    fn test_parse_basic_sdp() {
        let sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.username, "alice");
        assert_eq!(sdp.origin.address, "192.168.1.100");
        assert_eq!(sdp.session_name, "Call");
        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[0].port, 49170);
    }

    #[test]
    fn test_sdp_round_trip() {
        let sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();
        let serialized = sdp.to_string();
        let reparsed = SessionDescription::parse(&serialized).unwrap();
        assert_eq!(sdp, reparsed);
    }

    #[test]
    fn test_replace_ip() {
        let mut sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();
        let new_ip: IpAddr = "203.0.113.1".parse().unwrap();

        sdp.replace_ip(new_ip);

        assert_eq!(sdp.origin.address, "203.0.113.1");
        assert_eq!(sdp.connection.as_ref().unwrap().address, "203.0.113.1");
    }

    #[test]
    fn test_replace_port() {
        let mut sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();

        sdp.replace_port(MediaType::Audio, 12345);

        assert_eq!(sdp.media[0].port, 12345);
    }

    #[test]
    fn test_parse_multi_media() {
        let sdp_str = "v=0\r\n\
o=bob 123 456 IN IP4 10.0.0.1\r\n\
s=Session\r\n\
t=0 0\r\n\
m=audio 5000 RTP/AVP 0\r\n\
c=IN IP4 10.0.0.1\r\n\
m=video 5002 RTP/AVP 96\r\n\
c=IN IP4 10.0.0.1\r\n";

        let sdp = SessionDescription::parse(sdp_str).unwrap();

        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].media_type, MediaType::Audio);
        assert_eq!(sdp.media[0].port, 5000);
        assert_eq!(sdp.media[1].media_type, MediaType::Video);
        assert_eq!(sdp.media[1].port, 5002);
    }

    #[test]
    fn test_parse_attributes() {
        let sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();

        assert_eq!(sdp.media[0].attributes.len(), 3);
        assert_eq!(sdp.media[0].attributes[0].key, "rtpmap");
        assert_eq!(
            sdp.media[0].attributes[0].value.as_ref().unwrap(),
            "0 PCMU/8000"
        );
    }

    #[test]
    fn test_invalid_sdp() {
        let invalid = "This is not SDP";
        assert!(SessionDescription::parse(invalid).is_err());
    }

    #[test]
    fn test_media_type_from_str() {
        assert_eq!(MediaType::from_str("audio").unwrap(), MediaType::Audio);
        assert_eq!(MediaType::from_str("video").unwrap(), MediaType::Video);
        assert!(MediaType::from_str("invalid").is_err());
    }

    #[test]
    fn test_transform_webrtc_to_trunk() {
        let webrtc_sdp = "\
v=0\r\n\
o=- 123456 789012 IN IP4 192.168.1.100\r\n\
s=WebRTC Call\r\n\
c=IN IP4 203.0.113.100\r\n\
t=0 0\r\n\
a=ice-ufrag:F7gI\r\n\
a=ice-pwd:x9cml5SnwQUPeOZPy2hnZ\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF\r\n\
a=setup:actpass\r\n\
m=audio 10000 UDP/TLS/RTP/SAVPF 111 0 101\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=candidate:host-1 1 UDP 2130706431 192.168.1.100 10000 typ host\r\n\
a=rtcp-mux\r\n\
a=sendrecv\r\n";

        let trunk_sdp = transform_webrtc_to_trunk(webrtc_sdp, "203.0.113.1", 15000);

        // Must have plain RTP/AVP protocol
        assert!(trunk_sdp.contains("m=audio 15000 RTP/AVP 8"), "got: {}", trunk_sdp);
        // Must have SBC IP
        assert!(trunk_sdp.contains("c=IN IP4 203.0.113.1"));
        // Must have PCMA
        assert!(trunk_sdp.contains("a=rtpmap:8 PCMA/8000"));
        // Must have telephone-event
        assert!(trunk_sdp.contains("a=rtpmap:101 telephone-event/8000"));
        // Must NOT have WebRTC attributes
        assert!(!trunk_sdp.contains("fingerprint"));
        assert!(!trunk_sdp.contains("ice-ufrag"));
        assert!(!trunk_sdp.contains("ice-pwd"));
        assert!(!trunk_sdp.contains("candidate"));
        assert!(!trunk_sdp.contains("SAVPF"));
        assert!(!trunk_sdp.contains("opus"));
    }

    // ── Additional SDP tests ─────────────────────────────────────────

    #[test]
    fn test_parse_sdp_missing_session_connection() {
        // Real-world: some UAs put c= only at media level, not session level
        let sdp_str = "v=0\r\n\
o=bob 123 456 IN IP4 10.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 5000 RTP/AVP 0\r\n\
c=IN IP4 10.0.0.1\r\n\
a=rtpmap:0 PCMU/8000\r\n";

        let sdp = SessionDescription::parse(sdp_str);
        assert!(sdp.is_ok(), "SDP without session-level c= should parse: {:?}", sdp.err());
        let sdp = sdp.unwrap();
        assert!(sdp.connection.is_none(), "Session-level connection should be None");
        assert!(sdp.media[0].connection.is_some(), "Media-level connection should be present");
    }

    #[test]
    fn test_replace_ip_media_level_connection() {
        // When c= is only at media level, replace_ip should still work
        let sdp_str = "v=0\r\n\
o=bob 123 456 IN IP4 10.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 5000 RTP/AVP 0\r\n\
c=IN IP4 10.0.0.1\r\n";

        let mut sdp = SessionDescription::parse(sdp_str).unwrap();
        sdp.replace_ip("203.0.113.1".parse().unwrap());

        assert_eq!(sdp.media[0].connection.as_ref().unwrap().address, "203.0.113.1");
        assert_eq!(sdp.origin.address, "203.0.113.1");
    }

    #[test]
    fn test_parse_sdp_with_telephone_event() {
        // Verify telephone-event (DTMF) payload type is preserved
        let sdp_str = "v=0\r\n\
o=- 1 1 IN IP4 10.0.0.1\r\n\
s=-\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 5000 RTP/AVP 0 8 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n";

        let sdp = SessionDescription::parse(sdp_str).unwrap();
        assert_eq!(sdp.media[0].formats, vec![0u8, 8, 101]);
        let has_tel_event = sdp.media[0].attributes.iter()
            .any(|a| a.value.as_deref().unwrap_or("").contains("telephone-event"));
        assert!(has_tel_event, "telephone-event attribute should be present");
    }

    #[test]
    fn test_transform_webrtc_to_trunk_no_telephone_event() {
        // WebRTC SDP without telephone-event — trunk SDP should still be valid
        let webrtc_sdp = "v=0\r\n\
o=- 1 1 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=IN IP4 192.168.1.1\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=ice-ufrag:abc\r\n\
a=ice-pwd:xyz\r\n\
a=fingerprint:sha-256 AA:BB\r\n";

        let trunk_sdp = transform_webrtc_to_trunk(webrtc_sdp, "203.0.113.1", 15000);

        assert!(trunk_sdp.contains("m=audio 15000 RTP/AVP"), "Should have RTP/AVP: {}", trunk_sdp);
        assert!(trunk_sdp.contains("PCMA/8000"), "Should offer PCMA");
        assert!(!trunk_sdp.contains("opus"), "Should not contain opus");
    }

    #[test]
    fn test_sdp_replace_port_no_match() {
        // Replacing a port for a media type that doesn't exist should be a no-op
        let mut sdp = SessionDescription::parse(SAMPLE_SDP).unwrap();
        let original_port = sdp.media[0].port;

        sdp.replace_port(MediaType::Video, 9999); // No video in SAMPLE_SDP

        assert_eq!(sdp.media[0].port, original_port, "Audio port should be unchanged");
    }

    #[test]
    fn test_parse_linphone_style_sdp() {
        // Linphone sometimes puts attributes before t= line
        let sdp_str = "v=0\r\n\
o=linphone 123 456 IN IP4 10.0.0.1\r\n\
s=Talk\r\n\
c=IN IP4 10.0.0.1\r\n\
a=tool:oRTP-oRTP\r\n\
t=0 0\r\n\
m=audio 7078 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";

        let result = SessionDescription::parse(sdp_str);
        assert!(result.is_ok(), "Linphone-style SDP with attributes before t= should parse: {:?}", result.err());
    }

    use super::negotiated_audio_codec;

    #[test]
    fn test_negotiated_codec_static_pcmu() {
        // PT 0 with rtpmap, telephone-event should be skipped.
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n";
        assert_eq!(negotiated_audio_codec(sdp).as_deref(), Some("PCMU"));
    }

    #[test]
    fn test_negotiated_codec_static_no_rtpmap() {
        // PCMA (PT 8) with no rtpmap line — resolved from the static table.
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 8\r\n";
        assert_eq!(negotiated_audio_codec(sdp).as_deref(), Some("PCMA"));
    }

    #[test]
    fn test_negotiated_codec_dynamic_opus() {
        let sdp = "v=0\r\nm=audio 5004 RTP/SAVPF 111 101\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:101 telephone-event/48000\r\n";
        assert_eq!(negotiated_audio_codec(sdp).as_deref(), Some("opus"));
    }

    #[test]
    fn test_negotiated_codec_skips_leading_telephone_event() {
        // telephone-event listed first must be skipped in favour of PCMA.
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 101 8\r\na=rtpmap:101 telephone-event/8000\r\na=rtpmap:8 PCMA/8000\r\n";
        assert_eq!(negotiated_audio_codec(sdp).as_deref(), Some("PCMA"));
    }

    #[test]
    fn test_negotiated_codec_none_without_audio() {
        let sdp = "v=0\r\nm=video 5004 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n";
        assert_eq!(negotiated_audio_codec(sdp), None);
    }
}
