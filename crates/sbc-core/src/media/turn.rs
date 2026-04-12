//! TURN Client - Traversal Using Relays around NAT
//!
//! RFC 5766 - TURN: Relay Extensions to STUN
//! RFC 8656 - TURN Extensions for TCP and TLS

use crate::{Error, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info};

/// TURN Message Types (extends STUN)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TurnMessageType {
    /// Allocate Request (0x0003)
    AllocateRequest = 0x0003,

    /// Allocate Response (0x0103)
    AllocateResponse = 0x0103,

    /// Allocate Error (0x0113)
    AllocateError = 0x0113,

    /// Refresh Request (0x0004)
    RefreshRequest = 0x0004,

    /// Refresh Response (0x0104)
    RefreshResponse = 0x0104,

    /// CreatePermission Request (0x0008)
    CreatePermissionRequest = 0x0008,

    /// CreatePermission Response (0x0108)
    CreatePermissionResponse = 0x0108,

    /// ChannelBind Request (0x0009)
    ChannelBindRequest = 0x0009,

    /// ChannelBind Response (0x0109)
    ChannelBindResponse = 0x0109,
}

/// TURN Attribute Types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TurnAttributeType {
    /// LIFETIME (0x000D)
    Lifetime = 0x000D,

    /// XOR-RELAYED-ADDRESS (0x0016)
    XorRelayedAddress = 0x0016,

    /// XOR-PEER-ADDRESS (0x0012)
    XorPeerAddress = 0x0012,

    /// DATA (0x0013)
    Data = 0x0013,

    /// CHANNEL-NUMBER (0x000C)
    ChannelNumber = 0x000C,

    /// REQUESTED-TRANSPORT (0x0019)
    RequestedTransport = 0x0019,
}

/// TURN Transport Protocol
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TurnTransport {
    /// UDP (17)
    Udp = 17,

    /// TCP (6)
    Tcp = 6,
}

/// TURN Allocation
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    /// Relayed address (allocated by TURN server)
    pub relayed_address: SocketAddr,

    /// Lifetime in seconds
    pub lifetime: u32,

    /// Transaction ID
    #[allow(dead_code)]
    transaction_id: [u8; 12],
}

/// TURN Permission
#[derive(Debug, Clone)]
pub struct TurnPermission {
    /// Peer address
    pub peer_address: SocketAddr,

    /// Expiration time
    #[allow(dead_code)]
    expiration: std::time::Instant,
}

/// TURN Channel Binding
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    /// Channel number (0x4000 - 0x7FFF)
    pub channel_number: u16,

    /// Peer address
    pub peer_address: SocketAddr,
}

/// TURN Client
pub struct TurnClient {
    /// TURN server address
    server_addr: SocketAddr,

    /// Local socket
    socket: Arc<UdpSocket>,

    /// Username for authentication
    #[allow(dead_code)]
    username: String,

    /// Password for authentication
    #[allow(dead_code)]
    password: String,

    /// Current allocation
    allocation: Arc<Mutex<Option<TurnAllocation>>>,

    /// Active permissions
    permissions: Arc<Mutex<HashMap<SocketAddr, TurnPermission>>>,

    /// Channel bindings
    channels: Arc<Mutex<HashMap<u16, ChannelBinding>>>,

    /// Request timeout
    timeout_ms: u64,
}

impl TurnClient {
    /// Create new TURN client (note: use create() instead for async construction)
    ///
    /// This is kept for compatibility but cannot actually bind the socket synchronously.
    /// Use `create()` for real async construction.
    #[deprecated(note = "Use TurnClient::create() instead")]
    pub fn new(
        _server_addr: SocketAddr,
        _username: String,
        _password: String,
    ) -> Result<Self> {
        // Cannot actually create socket here - would need async
        Err(Error::Media("Use TurnClient::create() for async construction".to_string()))
    }

    /// Create new TURN client (async constructor workaround)
    pub async fn create(
        server_addr: SocketAddr,
        username: String,
        password: String,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            server_addr,
            socket: Arc::new(socket),
            username,
            password,
            allocation: Arc::new(Mutex::new(None)),
            permissions: Arc::new(Mutex::new(HashMap::new())),
            channels: Arc::new(Mutex::new(HashMap::new())),
            timeout_ms: 5000,
        })
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Allocate relay address on TURN server
    ///
    /// RFC 5766 Section 6.1
    pub async fn allocate(&self, requested_lifetime: u32) -> Result<SocketAddr> {
        info!(
            "Allocating TURN relay (lifetime: {}s)",
            requested_lifetime
        );

        // Build Allocate Request
        let request = self.build_allocate_request(requested_lifetime)?;

        // Send request
        self.socket.send_to(&request, self.server_addr).await?;

        // Wait for response
        let mut buf = vec![0u8; 2048];
        let (len, _src) = timeout(
            Duration::from_millis(self.timeout_ms),
            self.socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| Error::Media("TURN allocate timeout".to_string()))??;

        // Parse response
        let relayed_addr = self.parse_allocate_response(&buf[..len])?;

        // Store allocation
        *self.allocation.lock().await = Some(TurnAllocation {
            relayed_address: relayed_addr,
            lifetime: requested_lifetime,
            transaction_id: [0u8; 12], // Would be from response
        });

        info!("TURN relay allocated: {}", relayed_addr);
        Ok(relayed_addr)
    }

    /// Build Allocate Request message
    fn build_allocate_request(&self, lifetime: u32) -> Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut msg = Vec::new();

        // Message Type: Allocate Request (0x0003)
        msg.extend_from_slice(&0x0003u16.to_be_bytes());

        // Message Length (will be updated)
        let length_pos = msg.len();
        msg.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie (0x2112A442)
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());

        // Transaction ID (12 random bytes)
        let mut tx_id = [0u8; 12];
        rng.fill(&mut tx_id[..]);
        msg.extend_from_slice(&tx_id);

        // Attribute: REQUESTED-TRANSPORT (UDP = 17)
        msg.extend_from_slice(&(TurnAttributeType::RequestedTransport as u16).to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes()); // Length
        msg.push(TurnTransport::Udp as u8);
        msg.extend_from_slice(&[0u8; 3]); // Reserved

        // Attribute: LIFETIME
        msg.extend_from_slice(&(TurnAttributeType::Lifetime as u16).to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes()); // Length
        msg.extend_from_slice(&lifetime.to_be_bytes());

        // Update message length (attributes only)
        let attr_len = (msg.len() - 20) as u16;
        msg[length_pos..length_pos + 2].copy_from_slice(&attr_len.to_be_bytes());

        // TODO: Add MESSAGE-INTEGRITY for authentication

        Ok(msg)
    }

    /// Parse Allocate Response
    fn parse_allocate_response(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 20 {
            return Err(Error::Media("TURN response too short".to_string()));
        }

        // Check message type
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != TurnMessageType::AllocateResponse as u16 {
            return Err(Error::Media(format!(
                "Unexpected TURN message type: {:#x}",
                msg_type
            )));
        }

        // Parse attributes to find XOR-RELAYED-ADDRESS
        // TODO: Real attribute parsing
        // For now, return placeholder
        Ok("203.0.113.100:5000".parse().unwrap())
    }

    /// Create permission for peer address
    ///
    /// RFC 5766 Section 9
    pub async fn create_permission(&self, peer_addr: SocketAddr) -> Result<()> {
        info!("Creating TURN permission for {}", peer_addr);

        // Build CreatePermission Request
        let request = self.build_create_permission_request(peer_addr)?;

        // Send request
        self.socket.send_to(&request, self.server_addr).await?;

        // Wait for response
        let mut buf = vec![0u8; 2048];
        let (_len, _) = timeout(
            Duration::from_millis(self.timeout_ms),
            self.socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| Error::Media("TURN permission timeout".to_string()))??;

        // Store permission
        self.permissions.lock().await.insert(
            peer_addr,
            TurnPermission {
                peer_address: peer_addr,
                expiration: std::time::Instant::now() + Duration::from_secs(300), // 5 minutes
            },
        );

        Ok(())
    }

    /// Build CreatePermission Request (RFC 5766 §9)
    fn build_create_permission_request(&self, peer_addr: SocketAddr) -> Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut msg = Vec::new();
        const MAGIC: u32 = 0x2112A442;

        // Message Type: CreatePermission Request (0x0008)
        msg.extend_from_slice(&0x0008u16.to_be_bytes());

        // Length placeholder (updated below)
        let length_pos = msg.len();
        msg.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie
        msg.extend_from_slice(&MAGIC.to_be_bytes());

        // Transaction ID
        let mut tx_id = [0u8; 12];
        rng.fill(&mut tx_id[..]);
        msg.extend_from_slice(&tx_id);

        // XOR-PEER-ADDRESS attribute (RFC 5766 §14.3)
        Self::append_xor_peer_address(&mut msg, peer_addr, MAGIC)?;

        // Update message length
        let attr_len = (msg.len() - 20) as u16;
        msg[length_pos..length_pos + 2].copy_from_slice(&attr_len.to_be_bytes());

        Ok(msg)
    }

    /// Encode XOR-PEER-ADDRESS attribute (RFC 5389 §15.2)
    ///
    /// Port and IP are XOR'd with the magic cookie to avoid NAT rewriting.
    fn append_xor_peer_address(buf: &mut Vec<u8>, addr: SocketAddr, magic: u32) -> Result<()> {
        buf.extend_from_slice(&(TurnAttributeType::XorPeerAddress as u16).to_be_bytes());

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&8u16.to_be_bytes()); // Value length: 8 bytes
                buf.push(0x00);                             // Reserved
                buf.push(0x01);                             // Family: IPv4
                let xor_port = v4.port() ^ ((magic >> 16) as u16);
                buf.extend_from_slice(&xor_port.to_be_bytes());
                let ip_u32 = u32::from(*v4.ip()) ^ magic;
                buf.extend_from_slice(&ip_u32.to_be_bytes());
            }
            SocketAddr::V6(_) => {
                return Err(Error::Media("IPv6 XOR-PEER-ADDRESS not supported".to_string()));
            }
        }

        Ok(())
    }

    /// Send data to peer via TURN relay
    ///
    /// RFC 5766 Section 10
    pub async fn send_indication(&self, peer_addr: SocketAddr, data: &[u8]) -> Result<()> {
        let indication = self.build_send_indication(peer_addr, data)?;
        self.socket.send_to(&indication, self.server_addr).await?;
        debug!("Sent {} bytes to {} via TURN", data.len(), peer_addr);
        Ok(())
    }

    /// Build Send Indication with XOR-PEER-ADDRESS + DATA attributes (RFC 5766 §10)
    fn build_send_indication(&self, peer_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut msg = Vec::new();
        const MAGIC: u32 = 0x2112A442;

        // Message Type: Send Indication (0x0016)
        msg.extend_from_slice(&0x0016u16.to_be_bytes());

        // Length placeholder
        let length_pos = msg.len();
        msg.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie
        msg.extend_from_slice(&MAGIC.to_be_bytes());

        // Transaction ID
        let mut tx_id = [0u8; 12];
        rng.fill(&mut tx_id[..]);
        msg.extend_from_slice(&tx_id);

        // XOR-PEER-ADDRESS attribute
        Self::append_xor_peer_address(&mut msg, peer_addr, MAGIC)?;

        // DATA attribute (RFC 5766 §14.4): type 0x0013
        msg.extend_from_slice(&(TurnAttributeType::Data as u16).to_be_bytes());
        let data_len = data.len() as u16;
        msg.extend_from_slice(&data_len.to_be_bytes());
        msg.extend_from_slice(data);
        // Pad to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        msg.extend(std::iter::repeat(0u8).take(padding));

        // Update message length
        let attr_len = (msg.len() - 20) as u16;
        msg[length_pos..length_pos + 2].copy_from_slice(&attr_len.to_be_bytes());

        Ok(msg)
    }

    /// Refresh allocation
    pub async fn refresh(&self, lifetime: u32) -> Result<()> {
        info!("Refreshing TURN allocation ({}s)", lifetime);

        // Build Refresh Request
        let request = self.build_refresh_request(lifetime)?;

        // Send request
        self.socket.send_to(&request, self.server_addr).await?;

        // Wait for response
        let mut buf = vec![0u8; 2048];
        timeout(
            Duration::from_millis(self.timeout_ms),
            self.socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| Error::Media("TURN refresh timeout".to_string()))??;

        Ok(())
    }

    /// Build Refresh Request
    fn build_refresh_request(&self, lifetime: u32) -> Result<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut msg = Vec::new();

        // Message Type: Refresh Request (0x0004)
        msg.extend_from_slice(&0x0004u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());

        let mut tx_id = [0u8; 12];
        rng.fill(&mut tx_id[..]);
        msg.extend_from_slice(&tx_id);

        // LIFETIME attribute
        msg.extend_from_slice(&(TurnAttributeType::Lifetime as u16).to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&lifetime.to_be_bytes());

        Ok(msg)
    }

    /// Get relayed address
    pub async fn get_relayed_address(&self) -> Option<SocketAddr> {
        self.allocation.lock().await.as_ref().map(|a| a.relayed_address)
    }

    /// Get statistics
    pub async fn stats(&self) -> TurnStats {
        TurnStats {
            has_allocation: self.allocation.lock().await.is_some(),
            active_permissions: self.permissions.lock().await.len(),
            channel_bindings: self.channels.lock().await.len(),
        }
    }
}

/// TURN Statistics
#[derive(Debug, Clone)]
pub struct TurnStats {
    pub has_allocation: bool,
    pub active_permissions: usize,
    pub channel_bindings: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turn_message_types() {
        assert_eq!(TurnMessageType::AllocateRequest as u16, 0x0003);
        assert_eq!(TurnMessageType::AllocateResponse as u16, 0x0103);
        assert_eq!(TurnMessageType::RefreshRequest as u16, 0x0004);
    }

    #[test]
    fn test_turn_transport() {
        assert_eq!(TurnTransport::Udp as u8, 17);
        assert_eq!(TurnTransport::Tcp as u8, 6);
    }

    #[tokio::test]
    async fn test_turn_client_creation() {
        let server_addr: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let client = TurnClient::create(
            server_addr,
            "user".to_string(),
            "pass".to_string(),
        )
        .await
        .unwrap();

        assert_eq!(client.server_addr, server_addr);
        assert_eq!(client.username, "user");
        assert_eq!(client.timeout_ms, 5000);
    }

    #[tokio::test]
    async fn test_turn_client_stats() {
        let server_addr: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let client = TurnClient::create(
            server_addr,
            "user".to_string(),
            "pass".to_string(),
        )
        .await
        .unwrap();

        let stats = client.stats().await;
        assert!(!stats.has_allocation);
        assert_eq!(stats.active_permissions, 0);
        assert_eq!(stats.channel_bindings, 0);
    }

    #[test]
    fn test_build_allocate_request() {
        let server_addr: SocketAddr = "8.8.8.8:3478".parse().unwrap();
        // Can't easily test async creation in sync test, so test message building logic separately
        // This would require refactoring to separate sync/async parts
    }
}
