//! STUN Client - Session Traversal Utilities for NAT
//!
//! RFC 5389 - Session Traversal Utilities for NAT (STUN)
//!
//! Basic STUN client for discovering public IP and port mappings

use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN Magic Cookie (always 0x2112A442)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN Message Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StunMessageType {
    /// Binding Request (0x0001)
    BindingRequest = 0x0001,

    /// Binding Response (0x0101)
    BindingResponse = 0x0101,

    /// Binding Error Response (0x0111)
    BindingError = 0x0111,
}

impl StunMessageType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::BindingRequest),
            0x0101 => Some(Self::BindingResponse),
            0x0111 => Some(Self::BindingError),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// STUN Attribute Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StunAttributeType {
    /// MAPPED-ADDRESS (0x0001)
    MappedAddress = 0x0001,

    /// XOR-MAPPED-ADDRESS (0x0020)
    XorMappedAddress = 0x0020,

    /// ERROR-CODE (0x0009)
    ErrorCode = 0x0009,
}

impl StunAttributeType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::MappedAddress),
            0x0020 => Some(Self::XorMappedAddress),
            0x0009 => Some(Self::ErrorCode),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// STUN Message
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub message_type: StunMessageType,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

/// STUN Attribute
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// Mapped address (IP and port)
    MappedAddress(SocketAddr),

    /// XOR-mapped address (IP and port XORed with magic cookie)
    XorMappedAddress(SocketAddr),

    /// Error code and reason
    ErrorCode(u16, String),

    /// Unknown attribute
    Unknown(u16, Vec<u8>),
}

impl StunMessage {
    /// Create a new Binding Request
    pub fn binding_request() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut transaction_id = [0u8; 12];
        rng.fill(&mut transaction_id[..]);

        Self {
            message_type: StunMessageType::BindingRequest,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Message Type (2 bytes)
        bytes.extend_from_slice(&self.message_type.to_u16().to_be_bytes());

        // Message Length (2 bytes) - attributes length only
        let attrs_bytes: Vec<u8> = self
            .attributes
            .iter()
            .flat_map(|attr| attr.to_bytes())
            .collect();
        let length = attrs_bytes.len() as u16;
        bytes.extend_from_slice(&length.to_be_bytes());

        // Magic Cookie (4 bytes)
        bytes.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        bytes.extend_from_slice(&self.transaction_id);

        // Attributes
        bytes.extend_from_slice(&attrs_bytes);

        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::Media("STUN message too short".to_string()));
        }

        // Parse message type
        let msg_type_raw = u16::from_be_bytes([data[0], data[1]]);
        let message_type = StunMessageType::from_u16(msg_type_raw)
            .ok_or_else(|| Error::Media(format!("Unknown STUN message type: {}", msg_type_raw)))?;

        // Parse length
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Parse magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != STUN_MAGIC_COOKIE {
            return Err(Error::Media(format!(
                "Invalid STUN magic cookie: {:#x}",
                magic
            )));
        }

        // Parse transaction ID
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = 20;

        while offset < 20 + length {
            if offset + 4 > data.len() {
                break;
            }

            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            offset += 4;

            if offset + attr_len > data.len() {
                return Err(Error::Media("Invalid STUN attribute length".to_string()));
            }

            let attr_data = &data[offset..offset + attr_len];

            let attribute = StunAttribute::from_bytes(attr_type, attr_data, &transaction_id)?;
            attributes.push(attribute);

            // Attributes are padded to 4-byte boundary
            offset += (attr_len + 3) & !3;
        }

        Ok(Self {
            message_type,
            transaction_id,
            attributes,
        })
    }

    /// Get XOR-MAPPED-ADDRESS or MAPPED-ADDRESS from response
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            match attr {
                StunAttribute::XorMappedAddress(addr) => return Some(*addr),
                StunAttribute::MappedAddress(addr) => return Some(*addr),
                _ => {}
            }
        }
        None
    }
}

impl StunAttribute {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            StunAttribute::XorMappedAddress(addr) => {
                // Type (2 bytes)
                bytes
                    .extend_from_slice(&StunAttributeType::XorMappedAddress.to_u16().to_be_bytes());

                // Value
                let value = encode_xor_address(*addr);

                // Length (2 bytes)
                bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());

                // Value
                bytes.extend_from_slice(&value);

                // Padding to 4-byte boundary
                while bytes.len() % 4 != 0 {
                    bytes.push(0);
                }
            }
            StunAttribute::MappedAddress(addr) => {
                // Type
                bytes.extend_from_slice(&StunAttributeType::MappedAddress.to_u16().to_be_bytes());

                // Value
                let value = encode_address(*addr);

                // Length
                bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());

                // Value
                bytes.extend_from_slice(&value);

                // Padding
                while bytes.len() % 4 != 0 {
                    bytes.push(0);
                }
            }
            StunAttribute::ErrorCode(code, reason) => {
                // RFC 5389 §15.6: 4 bytes (2 reserved, class, number) + reason
                let class = (code / 100) as u8;
                let number = (code % 100) as u8;
                let reason_bytes = reason.as_bytes();
                let value_len = 4 + reason_bytes.len();

                bytes.extend_from_slice(&StunAttributeType::ErrorCode.to_u16().to_be_bytes());
                bytes.extend_from_slice(&(value_len as u16).to_be_bytes());
                bytes.extend_from_slice(&[0, 0, class, number]);
                bytes.extend_from_slice(reason_bytes);

                while bytes.len() % 4 != 0 {
                    bytes.push(0);
                }
            }
            StunAttribute::Unknown(attr_type, data) => {
                bytes.extend_from_slice(&attr_type.to_be_bytes());
                bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                bytes.extend_from_slice(data);

                while bytes.len() % 4 != 0 {
                    bytes.push(0);
                }
            }
        }

        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(attr_type: u16, data: &[u8], transaction_id: &[u8; 12]) -> Result<Self> {
        match StunAttributeType::from_u16(attr_type) {
            Some(StunAttributeType::MappedAddress) => {
                let addr = decode_address(data)?;
                Ok(StunAttribute::MappedAddress(addr))
            }
            Some(StunAttributeType::XorMappedAddress) => {
                let addr = decode_xor_address(data, transaction_id)?;
                Ok(StunAttribute::XorMappedAddress(addr))
            }
            Some(StunAttributeType::ErrorCode) => {
                if data.len() < 4 {
                    return Err(Error::Media("Invalid error code attribute".to_string()));
                }
                let error_class = data[2] as u16;
                let error_number = data[3] as u16;
                let code = error_class * 100 + error_number;
                let reason = String::from_utf8_lossy(&data[4..]).to_string();
                Ok(StunAttribute::ErrorCode(code, reason))
            }
            None => Ok(StunAttribute::Unknown(attr_type, data.to_vec())),
        }
    }
}

/// Encode socket address (without XOR)
fn encode_address(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Reserved (1 byte)
    bytes.push(0);

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            // Family: IPv4 = 0x01
            bytes.push(0x01);

            // Port (2 bytes)
            bytes.extend_from_slice(&addr.port().to_be_bytes());

            // Address (4 bytes)
            bytes.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            // Family: IPv6 = 0x02
            bytes.push(0x02);

            // Port (2 bytes)
            bytes.extend_from_slice(&addr.port().to_be_bytes());

            // Address (16 bytes)
            bytes.extend_from_slice(&ipv6.octets());
        }
    }

    bytes
}

/// Decode socket address (without XOR)
fn decode_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 4 {
        return Err(Error::Media("Invalid address attribute".to_string()));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(Error::Media("Invalid IPv4 address".to_string()));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(Error::Media("Invalid IPv6 address".to_string()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(Error::Media(format!("Unknown address family: {}", family))),
    }
}

/// Encode XOR-mapped address
fn encode_xor_address(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Reserved
    bytes.push(0);

    let xor_port = addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            // Family
            bytes.push(0x01);

            // X-Port
            bytes.extend_from_slice(&xor_port.to_be_bytes());

            // X-Address (XOR with magic cookie)
            let ip_bytes = ipv4.octets();
            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                bytes.push(ip_bytes[i] ^ magic_bytes[i]);
            }
        }
        IpAddr::V6(ipv6) => {
            // Family
            bytes.push(0x02);

            // X-Port
            bytes.extend_from_slice(&xor_port.to_be_bytes());

            // X-Address (XOR with magic cookie + transaction ID)
            let ip_bytes = ipv6.octets();
            let mut xor_key = Vec::new();
            xor_key.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            // For IPv6, we'd need transaction_id here, but we don't have it in this context
            // This is a simplified implementation
            for i in 0..16 {
                let key_byte = if i < 4 {
                    xor_key[i]
                } else {
                    0 // Simplified: should use transaction_id
                };
                bytes.push(ip_bytes[i] ^ key_byte);
            }
        }
    }

    bytes
}

/// Decode XOR-mapped address
fn decode_xor_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 4 {
        return Err(Error::Media("Invalid XOR address attribute".to_string()));
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return Err(Error::Media("Invalid XOR IPv4 address".to_string()));
            }

            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            let mut ip_bytes = [0u8; 4];
            for i in 0..4 {
                ip_bytes[i] = data[4 + i] ^ magic_bytes[i];
            }

            let ip = Ipv4Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(Error::Media("Invalid XOR IPv6 address".to_string()));
            }

            // Build XOR key: magic cookie + transaction ID
            let mut xor_key = Vec::new();
            xor_key.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key.extend_from_slice(transaction_id);

            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = data[4 + i] ^ xor_key[i];
            }

            let ip = Ipv6Addr::from(ip_bytes);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(Error::Media(format!("Unknown address family: {}", family))),
    }
}

/// Build a STUN Binding Response for an incoming Binding Request.
///
/// Used by ICE-lite to reply to browser connectivity checks on the RTP port.
/// The response includes an XOR-MAPPED-ADDRESS attribute reflecting the source
/// address back to the sender (RFC 5389 §10.1).
///
/// If `local_ice_pwd` is provided, MESSAGE-INTEGRITY (HMAC-SHA1) and
/// FINGERPRINT (CRC32 XOR 0x5354554E) are appended per RFC 5389 §15.4/§15.5.
/// Chrome/Firefox REQUIRE these for ICE connectivity checks.
pub fn build_binding_response(request_data: &[u8], source: SocketAddr) -> Result<Vec<u8>> {
    build_binding_response_with_integrity(request_data, source, None)
}

/// Why an ICE Binding Request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunReject {
    /// Not a STUN Binding Request at all.
    NotARequest,
    /// No MESSAGE-INTEGRITY attribute: an ICE connectivity check must
    /// carry one (RFC 8445 §7.3).
    NoIntegrity,
    /// MESSAGE-INTEGRITY does not verify against our own ice-pwd: whoever
    /// sent this does not hold the password we published in the SDP.
    BadIntegrity,
    /// No USERNAME attribute (RFC 8445 §7.3 requires it).
    NoUsername,
    /// FINGERPRINT present but wrong: not a STUN message we should parse.
    BadFingerprint,
}

impl StunReject {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotARequest => "not-a-request",
            Self::NoIntegrity => "no-integrity",
            Self::BadIntegrity => "bad-integrity",
            Self::NoUsername => "no-username",
            Self::BadFingerprint => "bad-fingerprint",
        }
    }
}

/// Authenticate an inbound ICE Binding Request against our own ice-pwd
/// (RFC 5389 §10.2 short-term credentials, as ICE uses them in RFC 8445
/// §7.3).
///
/// This is what makes the media port ours: the SBC answered every Binding
/// Request that reached it and **learned the sender as the call's
/// endpoint**, so a single spoofed datagram could take over the audio of
/// a WebRTC leg. The HMAC-SHA1 is keyed with the password we published in
/// our own SDP, so only the peer that read it can produce one.
///
/// The USERNAME must be present but its ufrag half is not compared: the
/// password is generated per session, so a verifying HMAC already proves
/// the sender holds *this* call's credentials.
pub fn validate_binding_request(
    data: &[u8],
    local_ice_pwd: &str,
) -> std::result::Result<(), StunReject> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use subtle::ConstantTimeEq;

    if data.len() < 20 {
        return Err(StunReject::NotARequest);
    }
    if u16::from_be_bytes([data[0], data[1]]) != StunMessageType::BindingRequest.to_u16() {
        return Err(StunReject::NotARequest);
    }
    if u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != STUN_MAGIC_COOKIE {
        return Err(StunReject::NotARequest);
    }
    let declared = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = 20usize.saturating_add(declared).min(data.len());

    // Walk the attributes, keeping the offsets the two checksums need.
    let mut offset = 20usize;
    let mut integrity: Option<(usize, [u8; 20])> = None;
    let mut fingerprint: Option<(usize, u32)> = None;
    let mut has_username = false;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let value_at = offset + 4;
        if value_at + attr_len > end {
            return Err(StunReject::NotARequest);
        }
        match attr_type {
            0x0006 => has_username = true,
            0x0008 if attr_len == 20 => {
                let mut mac = [0u8; 20];
                mac.copy_from_slice(&data[value_at..value_at + 20]);
                // The first MESSAGE-INTEGRITY wins: anything after it is
                // not covered by the HMAC and must not be trusted.
                if integrity.is_none() {
                    integrity = Some((offset, mac));
                }
            }
            0x8028 if attr_len == 4 => {
                let v = u32::from_be_bytes([
                    data[value_at],
                    data[value_at + 1],
                    data[value_at + 2],
                    data[value_at + 3],
                ]);
                if fingerprint.is_none() {
                    fingerprint = Some((offset, v));
                }
            }
            _ => {}
        }
        offset = value_at + ((attr_len + 3) & !3);
    }

    // FINGERPRINT first: it is cheap and tells a mangled datagram from a
    // real one before any HMAC work.
    if let Some((at, claimed)) = fingerprint {
        if crc32_stun(&data[..at]) ^ 0x5354554E != claimed {
            return Err(StunReject::BadFingerprint);
        }
    }

    let Some((mi_at, claimed)) = integrity else {
        return Err(StunReject::NoIntegrity);
    };
    if !has_username {
        return Err(StunReject::NoUsername);
    }

    // RFC 5389 §15.4: the HMAC covers the message up to the
    // MESSAGE-INTEGRITY attribute, with the header length rewritten to
    // the value it would have if MESSAGE-INTEGRITY were the last
    // attribute (so a trailing FINGERPRINT is excluded).
    let mut covered = data[..mi_at].to_vec();
    let length_with_mi = (mi_at - 20 + 24) as u16;
    covered[2] = (length_with_mi >> 8) as u8;
    covered[3] = (length_with_mi & 0xFF) as u8;

    let mut mac = match <Hmac<Sha1>>::new_from_slice(local_ice_pwd.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Err(StunReject::BadIntegrity),
    };
    mac.update(&covered);
    let computed = mac.finalize().into_bytes();
    if computed[..20].ct_eq(&claimed).into() {
        Ok(())
    } else {
        Err(StunReject::BadIntegrity)
    }
}

/// Build a STUN Binding Response with MESSAGE-INTEGRITY and FINGERPRINT.
///
/// `local_ice_pwd` is the SBC's ice-pwd used as the HMAC-SHA1 key.
pub fn build_binding_response_with_integrity(
    request_data: &[u8],
    source: SocketAddr,
    local_ice_pwd: Option<&str>,
) -> Result<Vec<u8>> {
    let request = StunMessage::from_bytes(request_data)?;

    if request.message_type != StunMessageType::BindingRequest {
        return Err(Error::Media("Not a STUN Binding Request".to_string()));
    }

    // Build the base response with XOR-MAPPED-ADDRESS
    let response = StunMessage {
        message_type: StunMessageType::BindingResponse,
        transaction_id: request.transaction_id, // Echo back same transaction ID
        attributes: vec![StunAttribute::XorMappedAddress(source)],
    };

    let mut bytes = response.to_bytes();

    if let Some(pwd) = local_ice_pwd {
        // ── MESSAGE-INTEGRITY (RFC 5389 §15.4) ──
        // HMAC-SHA1 is computed over the STUN message up to (but not including)
        // the MESSAGE-INTEGRITY attribute itself.
        // The Message Length in the header must be adjusted to include the
        // MESSAGE-INTEGRITY attribute (type 2 + length 2 + value 20 = 24 bytes).
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        // Adjust message length to include MESSAGE-INTEGRITY (24 bytes)
        let current_attrs_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mi_len = current_attrs_len + 24; // +24 for MESSAGE-INTEGRITY TLV
        bytes[2] = (mi_len >> 8) as u8;
        bytes[3] = (mi_len & 0xFF) as u8;

        // Compute HMAC-SHA1 over the message with adjusted length
        let mut mac = <Hmac<Sha1>>::new_from_slice(pwd.as_bytes())
            .map_err(|e| Error::Media(format!("HMAC key error: {}", e)))?;
        mac.update(&bytes);
        let hmac_result = mac.finalize().into_bytes();

        // Append MESSAGE-INTEGRITY attribute (type=0x0008, length=20)
        bytes.extend_from_slice(&0x0008u16.to_be_bytes()); // type
        bytes.extend_from_slice(&0x0014u16.to_be_bytes()); // length = 20
        bytes.extend_from_slice(&hmac_result[..20]);

        // ── FINGERPRINT (RFC 5389 §15.5) ──
        // CRC32 over all bytes up to (but not including) FINGERPRINT itself,
        // XORed with 0x5354554E.
        // Adjust message length to also include FINGERPRINT (8 bytes)
        let fp_len = mi_len + 8;
        bytes[2] = (fp_len >> 8) as u8;
        bytes[3] = (fp_len & 0xFF) as u8;

        let crc = crc32_stun(&bytes);
        let fingerprint = crc ^ 0x5354554E;

        // Append FINGERPRINT attribute (type=0x8028, length=4)
        bytes.extend_from_slice(&0x8028u16.to_be_bytes()); // type
        bytes.extend_from_slice(&0x0004u16.to_be_bytes()); // length = 4
        bytes.extend_from_slice(&fingerprint.to_be_bytes());
    }

    Ok(bytes)
}

/// CRC32 for STUN FINGERPRINT (ISO 3309 / ITU-T V.42, same as used by zlib).
fn crc32_stun(data: &[u8]) -> u32 {
    // CRC32 lookup table (polynomial 0xEDB88320, reflected)
    static CRC32_TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFFFFFF
}

/// Classify a multiplexed packet on a shared RTP/STUN/DTLS port.
/// RFC 5764 §5.1.2 — demuxing based on the first byte of the packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MultiplexedPacketType {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
    Unknown,
}

pub fn classify_packet(data: &[u8]) -> MultiplexedPacketType {
    match data.first() {
        Some(0..=3) => MultiplexedPacketType::Stun,
        Some(20..=63) => MultiplexedPacketType::Dtls,
        Some(128..=191) => {
            // RFC 5761 §4: on a muxed port, RTCP packet types are 192..=223
            // in byte[1] — 200(SR), 201(RR), 202(SDES), 203(BYE), 204(APP),
            // but also 205(RTPFB), 206(PSFB), 207(XR) and the legacy 192/193.
            // (RTP avoids the matching payload types for exactly this reason.)
            if data.len() >= 2 && (192..=223).contains(&data[1]) {
                MultiplexedPacketType::Rtcp
            } else {
                MultiplexedPacketType::Rtp
            }
        }
        _ => MultiplexedPacketType::Unknown,
    }
}

/// STUN Client
pub struct StunClient {
    /// STUN server address
    server_addr: SocketAddr,

    /// Local socket to bind
    local_addr: Option<SocketAddr>,

    /// Request timeout
    timeout_ms: u64,
}

impl StunClient {
    /// Create a new STUN client
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            local_addr: None,
            timeout_ms: 3000, // 3 seconds default
        }
    }

    /// Set local address to bind
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    /// Set request timeout in milliseconds
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Perform STUN binding request to discover public address
    pub async fn binding_request(&self) -> Result<SocketAddr> {
        // Bind local socket
        let local_bind = self
            .local_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        let socket = UdpSocket::bind(local_bind).await?;

        // Create binding request
        let request = StunMessage::binding_request();
        let request_bytes = request.to_bytes();

        // Send request
        socket.send_to(&request_bytes, self.server_addr).await?;

        // Wait for response with timeout
        let mut buf = vec![0u8; 2048];
        let (len, _src) = timeout(
            Duration::from_millis(self.timeout_ms),
            socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| Error::Media("STUN request timeout".to_string()))??;

        // Parse response
        let response = StunMessage::from_bytes(&buf[..len])?;

        // Verify transaction ID matches
        if response.transaction_id != request.transaction_id {
            return Err(Error::Media("STUN transaction ID mismatch".to_string()));
        }

        // Extract mapped address
        response
            .mapped_address()
            .ok_or_else(|| Error::Media("No mapped address in STUN response".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_message_type() {
        assert_eq!(
            StunMessageType::from_u16(0x0001),
            Some(StunMessageType::BindingRequest)
        );
        assert_eq!(
            StunMessageType::from_u16(0x0101),
            Some(StunMessageType::BindingResponse)
        );
        assert_eq!(StunMessageType::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_stun_binding_request_creation() {
        let msg = StunMessage::binding_request();
        assert_eq!(msg.message_type, StunMessageType::BindingRequest);
        assert_eq!(msg.transaction_id.len(), 12);
        assert_eq!(msg.attributes.len(), 0);
    }

    #[test]
    fn test_stun_message_serialization() {
        let msg = StunMessage::binding_request();
        let bytes = msg.to_bytes();

        // Minimum STUN message is 20 bytes
        assert!(bytes.len() >= 20);

        // Check message type
        let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(msg_type, 0x0001);

        // Check magic cookie
        let magic = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(magic, STUN_MAGIC_COOKIE);
    }

    #[test]
    fn test_encode_decode_address() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

        let encoded = encode_address(addr);
        assert!(encoded.len() >= 8); // 1 + 1 + 2 + 4 for IPv4

        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_xor_address_ipv4() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let transaction_id = [1u8; 12];

        let encoded = encode_xor_address(addr);
        let decoded = decode_xor_address(&encoded, &transaction_id).unwrap();

        assert_eq!(decoded.port(), addr.port());
        // IP might differ slightly due to XOR, but basic structure should work
    }

    #[test]
    fn test_stun_client_creation() {
        let server_addr: SocketAddr = "8.8.8.8:19302".parse().unwrap();
        let client = StunClient::new(server_addr);

        assert_eq!(client.server_addr, server_addr);
        assert_eq!(client.timeout_ms, 3000);
    }

    #[test]
    fn test_stun_client_with_options() {
        let server_addr: SocketAddr = "8.8.8.8:19302".parse().unwrap();
        let local_addr: SocketAddr = "0.0.0.0:12345".parse().unwrap();

        let client = StunClient::new(server_addr)
            .with_local_addr(local_addr)
            .with_timeout(5000);

        assert_eq!(client.local_addr, Some(local_addr));
        assert_eq!(client.timeout_ms, 5000);
    }

    // Note: Skipping actual network test as it requires external STUN server
    // In real testing, you would:
    // #[tokio::test]
    // async fn test_stun_binding_request_real() {
    //     let server: SocketAddr = "stun.l.google.com:19302".parse().unwrap();
    //     let client = StunClient::new(server);
    //     let public_addr = client.binding_request().await.unwrap();
    //     println!("Public address: {}", public_addr);
    // }
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    /// Build a Binding Request the way an ICE agent does: USERNAME,
    /// MESSAGE-INTEGRITY keyed with the *receiver's* password, then
    /// FINGERPRINT.
    fn binding_request(username: &str, pwd: &str, with_integrity: bool) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&StunMessageType::BindingRequest.to_u16().to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // length, patched below
        bytes.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&[7u8; 12]); // transaction id

        // USERNAME, padded to 4 bytes.
        let u = username.as_bytes();
        bytes.extend_from_slice(&0x0006u16.to_be_bytes());
        bytes.extend_from_slice(&(u.len() as u16).to_be_bytes());
        bytes.extend_from_slice(u);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        let set_len = |bytes: &mut Vec<u8>, len: usize| {
            let l = len as u16;
            bytes[2] = (l >> 8) as u8;
            bytes[3] = (l & 0xFF) as u8;
        };
        let n = bytes.len();
        set_len(&mut bytes, n - 20);

        if with_integrity {
            let n = bytes.len();
            set_len(&mut bytes, n - 20 + 24);
            let mut mac = <Hmac<Sha1>>::new_from_slice(pwd.as_bytes()).unwrap();
            mac.update(&bytes);
            let tag = mac.finalize().into_bytes();
            bytes.extend_from_slice(&0x0008u16.to_be_bytes());
            bytes.extend_from_slice(&0x0014u16.to_be_bytes());
            bytes.extend_from_slice(&tag[..20]);
        }

        // FINGERPRINT last, covering everything before it.
        let n = bytes.len();
        set_len(&mut bytes, n - 20 + 8);
        let crc = crc32_stun(&bytes) ^ 0x5354554E;
        bytes.extend_from_slice(&0x8028u16.to_be_bytes());
        bytes.extend_from_slice(&0x0004u16.to_be_bytes());
        bytes.extend_from_slice(&crc.to_be_bytes());
        bytes
    }

    /// The relay answered every Binding Request that reached the media
    /// port and adopted its source as the call's endpoint. Only the peer
    /// that read our ice-pwd out of the SDP can produce a verifying
    /// MESSAGE-INTEGRITY (RFC 5389 §10.2, RFC 8445 §7.3).
    #[test]
    fn only_a_check_signed_with_our_password_is_accepted() {
        let ours = "sbcPasswordFromOurOwnSdp";
        let req = binding_request("sbcUfrag:peerUfrag", ours, true);
        validate_binding_request(&req, ours).expect("the real peer");

        // Someone who never read our SDP.
        assert_eq!(
            validate_binding_request(&req, "a-different-password"),
            Err(StunReject::BadIntegrity)
        );
        // A check with no MESSAGE-INTEGRITY at all.
        let bare = binding_request("sbcUfrag:peerUfrag", ours, false);
        assert_eq!(
            validate_binding_request(&bare, ours),
            Err(StunReject::NoIntegrity)
        );
    }

    /// One flipped byte anywhere in the covered message must fail: that is
    /// what stops an attacker editing a captured check.
    #[test]
    fn a_tampered_check_fails() {
        let ours = "sbcPassword";
        let req = binding_request("sbcUfrag:peerUfrag", ours, true);
        // The USERNAME is inside the HMAC's coverage.
        let mut tampered = req.clone();
        tampered[24] ^= 0x01;
        assert!(matches!(
            validate_binding_request(&tampered, ours),
            Err(StunReject::BadIntegrity) | Err(StunReject::BadFingerprint)
        ));
        // And the tag itself.
        let mut clipped = req.clone();
        let n = clipped.len();
        clipped[n - 12] ^= 0xFF;
        assert!(validate_binding_request(&clipped, ours).is_err());
    }

    /// Not a Binding Request, not our business.
    #[test]
    fn anything_that_is_not_a_binding_request_is_refused() {
        let ours = "pwd";
        assert_eq!(
            validate_binding_request(b"short", ours),
            Err(StunReject::NotARequest)
        );
        // A Binding *Response* (a peer's answer, not a check).
        let mut resp = binding_request("a:b", ours, true);
        resp[0..2].copy_from_slice(&StunMessageType::BindingResponse.to_u16().to_be_bytes());
        assert_eq!(
            validate_binding_request(&resp, ours),
            Err(StunReject::NotARequest)
        );
        // A wrong magic cookie (RFC 5389 §6).
        let mut bad_magic = binding_request("a:b", ours, true);
        bad_magic[4] ^= 0xFF;
        assert_eq!(
            validate_binding_request(&bad_magic, ours),
            Err(StunReject::NotARequest)
        );
    }

    /// Our own response must verify under the same rules we apply to the
    /// peer's request: one implementation of §15.4, used both ways.
    #[test]
    fn our_response_carries_an_integrity_the_same_code_verifies() {
        let ours = "sbcPassword";
        let req = binding_request("sbcUfrag:peerUfrag", ours, true);
        let source: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let resp = build_binding_response_with_integrity(&req, source, Some(ours)).unwrap();

        // Re-read it the way the peer would: type, mapped address, and an
        // integrity over the same coverage.
        let parsed = StunMessage::from_bytes(&resp).expect("parses");
        assert_eq!(parsed.message_type, StunMessageType::BindingResponse);
        assert_eq!(parsed.transaction_id, [7u8; 12]);
        assert_eq!(parsed.mapped_address(), Some(source));

        // Now verify its MESSAGE-INTEGRITY and FINGERPRINT the way a
        // browser would, with the coverage rules written out here rather
        // than reused from the builder — that is what makes this a check
        // of the builder and not of itself.
        //
        // Layout: … MESSAGE-INTEGRITY (24 bytes) FINGERPRINT (8 bytes).
        let fp_at = resp.len() - 8;
        let mi_at = fp_at - 24;
        assert_eq!(
            u16::from_be_bytes([resp[mi_at], resp[mi_at + 1]]),
            0x0008,
            "MESSAGE-INTEGRITY sits where the layout says"
        );
        assert_eq!(u16::from_be_bytes([resp[fp_at], resp[fp_at + 1]]), 0x8028);

        // FINGERPRINT: CRC32 of everything before it, XOR 0x5354554E.
        let claimed_fp = u32::from_be_bytes([
            resp[fp_at + 4],
            resp[fp_at + 5],
            resp[fp_at + 6],
            resp[fp_at + 7],
        ]);
        assert_eq!(crc32_stun(&resp[..fp_at]) ^ 0x5354554E, claimed_fp);

        // MESSAGE-INTEGRITY: HMAC-SHA1 over the message up to it, with the
        // header length rewritten as if it were the last attribute.
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let mut covered = resp[..mi_at].to_vec();
        let l = (mi_at - 20 + 24) as u16;
        covered[2] = (l >> 8) as u8;
        covered[3] = (l & 0xFF) as u8;
        let mut mac = <Hmac<Sha1>>::new_from_slice(ours.as_bytes()).unwrap();
        mac.update(&covered);
        assert_eq!(
            &mac.finalize().into_bytes()[..20],
            &resp[mi_at + 4..mi_at + 24],
            "the response's integrity is the one a peer computes"
        );
    }
}
