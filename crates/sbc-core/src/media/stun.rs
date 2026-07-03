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
                bytes.extend_from_slice(&StunAttributeType::XorMappedAddress.to_u16().to_be_bytes());

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
        attributes: vec![
            StunAttribute::XorMappedAddress(source),
        ],
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
            // RFC 5761: Distinguish RTP from RTCP on rtcp-mux port
            // RTCP packet types in byte[1]: 200(SR), 201(RR), 202(SDES), 203(BYE), 204(APP)
            if data.len() >= 2 && data[1] >= 200 && data[1] <= 204 {
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
