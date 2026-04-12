//! WebRTC Data Channel (SCTP-based)
//!
//! Implements WebRTC data channels over SCTP (RFC 8831, RFC 8832).
//! Data channels allow bidirectional messaging between peers for:
//!   - Text chat / instant messaging
//!   - File transfer
//!   - Generic binary data
//!
//! # Architecture
//!
//! WebRTC data channels use SCTP (Stream Control Transmission Protocol)
//! encapsulated in DTLS over UDP:
//!
//!   Application Data  →  SCTP  →  DTLS  →  UDP
//!
//! The SBC can proxy data channels between WebRTC and SIP endpoints,
//! or between two WebRTC endpoints through the B2BUA.
//!
//! # SCTP Protocol (RFC 4960)
//!
//! SCTP provides:
//!   - Reliable, ordered delivery (like TCP)
//!   - Message boundaries (like UDP)
//!   - Multi-streaming (no head-of-line blocking)
//!   - Bi-directional shutdown

use crate::{Error, Result};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::info;

// ─────────────────────────────────────────────────────────────────────────────
// SCTP Constants (RFC 4960 / RFC 8831)
// ─────────────────────────────────────────────────────────────────────────────

/// SCTP PPID for WebRTC String (UTF-8 text)
pub const PPID_STRING: u32 = 51;
/// SCTP PPID for WebRTC Binary
pub const PPID_BINARY: u32 = 53;
/// SCTP PPID for WebRTC String (empty)
pub const PPID_STRING_EMPTY: u32 = 56;
/// SCTP PPID for WebRTC Binary (empty)
pub const PPID_BINARY_EMPTY: u32 = 57;
/// SCTP PPID for DCEP (Data Channel Establishment Protocol)
pub const PPID_DCEP: u32 = 50;

/// Maximum number of data channels per session
pub const MAX_DATA_CHANNELS: usize = 256;
/// Default SCTP port for WebRTC (RFC 8841)
pub const SCTP_PORT: u16 = 5000;

// ─────────────────────────────────────────────────────────────────────────────
// Data Channel Types
// ─────────────────────────────────────────────────────────────────────────────

/// Data channel message type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataChannelMessage {
    /// UTF-8 text message
    Text(String),
    /// Binary message
    Binary(Vec<u8>),
}

impl DataChannelMessage {
    /// SCTP PPID for this message type
    pub fn ppid(&self) -> u32 {
        match self {
            Self::Text(s) if s.is_empty() => PPID_STRING_EMPTY,
            Self::Text(_) => PPID_STRING,
            Self::Binary(b) if b.is_empty() => PPID_BINARY_EMPTY,
            Self::Binary(_) => PPID_BINARY,
        }
    }

    /// Convert to bytes for SCTP transport
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(s) => s.as_bytes().to_vec(),
            Self::Binary(b) => b.clone(),
        }
    }

    /// Create from SCTP payload based on PPID
    pub fn from_sctp(ppid: u32, data: &[u8]) -> Result<Self> {
        match ppid {
            PPID_STRING | PPID_STRING_EMPTY => {
                let text = std::str::from_utf8(data)
                    .map_err(|e| Error::Other(format!("Invalid UTF-8 in data channel: {}", e)))?;
                Ok(Self::Text(text.to_string()))
            }
            PPID_BINARY | PPID_BINARY_EMPTY => {
                Ok(Self::Binary(data.to_vec()))
            }
            _ => Err(Error::Other(format!("Unknown SCTP PPID: {}", ppid))),
        }
    }
}

/// Data channel reliability mode (RFC 8831 §6.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    /// Reliable, ordered (like TCP)
    Reliable,
    /// Reliable, unordered
    ReliableUnordered,
    /// Unreliable with max retransmits
    PartialReliableRexmit(u16),
    /// Unreliable with max lifetime (ms)
    PartialReliableTimed(u16),
}

impl ChannelType {
    /// DCEP channel type byte (RFC 8832 §8.2.1)
    pub fn to_dcep_type(&self) -> u8 {
        match self {
            Self::Reliable => 0x00,
            Self::ReliableUnordered => 0x80,
            Self::PartialReliableRexmit(_) => 0x01,
            Self::PartialReliableTimed(_) => 0x02,
        }
    }

    /// Parse DCEP channel type byte
    pub fn from_dcep_type(byte: u8, reliability_param: u16) -> Self {
        match byte & 0x7F {
            0x00 => {
                if byte & 0x80 != 0 {
                    Self::ReliableUnordered
                } else {
                    Self::Reliable
                }
            }
            0x01 => Self::PartialReliableRexmit(reliability_param),
            0x02 => Self::PartialReliableTimed(reliability_param),
            _ => Self::Reliable,
        }
    }
}

/// Data channel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelState {
    /// Channel is being set up
    Connecting,
    /// Channel is open and ready for communication
    Open,
    /// Channel is being closed
    Closing,
    /// Channel is closed
    Closed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Channel
// ─────────────────────────────────────────────────────────────────────────────

/// A single WebRTC data channel
#[derive(Debug, Clone)]
pub struct DataChannel {
    /// Stream ID (SCTP stream identifier)
    pub stream_id: u16,
    /// Human-readable label
    pub label: String,
    /// Protocol (sub-protocol string, e.g., "" or "json")
    pub protocol: String,
    /// Channel reliability type
    pub channel_type: ChannelType,
    /// Current state
    pub state: DataChannelState,
    /// Whether this channel was opened by the local side
    pub is_local: bool,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
}

impl DataChannel {
    /// Create a new data channel
    pub fn new(stream_id: u16, label: &str, channel_type: ChannelType, is_local: bool) -> Self {
        Self {
            stream_id,
            label: label.to_string(),
            protocol: String::new(),
            channel_type,
            state: DataChannelState::Connecting,
            is_local,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Mark channel as open
    pub fn open(&mut self) {
        self.state = DataChannelState::Open;
    }

    /// Mark channel as closing
    pub fn close(&mut self) {
        self.state = DataChannelState::Closing;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DCEP (Data Channel Establishment Protocol - RFC 8832)
// ─────────────────────────────────────────────────────────────────────────────

/// DCEP message types
const DCEP_DATA_CHANNEL_OPEN: u8 = 0x03;
const DCEP_DATA_CHANNEL_ACK: u8 = 0x02;

/// Build a DCEP DATA_CHANNEL_OPEN message (RFC 8832 §8.2.1)
pub fn build_dcep_open(
    channel_type: ChannelType,
    priority: u16,
    reliability_param: u32,
    label: &str,
    protocol: &str,
) -> Vec<u8> {
    let label_bytes = label.as_bytes();
    let protocol_bytes = protocol.as_bytes();

    let mut msg = Vec::with_capacity(12 + label_bytes.len() + protocol_bytes.len());

    // Message type
    msg.push(DCEP_DATA_CHANNEL_OPEN);
    // Channel type
    msg.push(channel_type.to_dcep_type());
    // Priority (big-endian u16)
    msg.extend_from_slice(&priority.to_be_bytes());
    // Reliability parameter (big-endian u32)
    msg.extend_from_slice(&reliability_param.to_be_bytes());
    // Label length (big-endian u16)
    msg.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
    // Protocol length (big-endian u16)
    msg.extend_from_slice(&(protocol_bytes.len() as u16).to_be_bytes());
    // Label
    msg.extend_from_slice(label_bytes);
    // Protocol
    msg.extend_from_slice(protocol_bytes);

    msg
}

/// Build a DCEP DATA_CHANNEL_ACK message (RFC 8832 §8.2.2)
pub fn build_dcep_ack() -> Vec<u8> {
    vec![DCEP_DATA_CHANNEL_ACK]
}

/// Parse a DCEP message
pub fn parse_dcep(data: &[u8]) -> Result<DcepMessage> {
    if data.is_empty() {
        return Err(Error::Other("Empty DCEP message".to_string()));
    }

    match data[0] {
        DCEP_DATA_CHANNEL_OPEN => {
            if data.len() < 12 {
                return Err(Error::Other("DCEP OPEN too short".to_string()));
            }

            let channel_type_byte = data[1];
            let priority = u16::from_be_bytes([data[2], data[3]]);
            let reliability_param = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let label_len = u16::from_be_bytes([data[8], data[9]]) as usize;
            let protocol_len = u16::from_be_bytes([data[10], data[11]]) as usize;

            if data.len() < 12 + label_len + protocol_len {
                return Err(Error::Other("DCEP OPEN truncated".to_string()));
            }

            let label = std::str::from_utf8(&data[12..12 + label_len])
                .map_err(|e| Error::Other(format!("DCEP label not UTF-8: {}", e)))?
                .to_string();

            let protocol = std::str::from_utf8(&data[12 + label_len..12 + label_len + protocol_len])
                .map_err(|e| Error::Other(format!("DCEP protocol not UTF-8: {}", e)))?
                .to_string();

            let channel_type = ChannelType::from_dcep_type(
                channel_type_byte,
                reliability_param as u16,
            );

            Ok(DcepMessage::Open {
                channel_type,
                priority,
                reliability_param,
                label,
                protocol,
            })
        }
        DCEP_DATA_CHANNEL_ACK => Ok(DcepMessage::Ack),
        other => Err(Error::Other(format!("Unknown DCEP message type: {}", other))),
    }
}

/// Parsed DCEP message
#[derive(Debug, Clone)]
pub enum DcepMessage {
    /// DATA_CHANNEL_OPEN request
    Open {
        channel_type: ChannelType,
        priority: u16,
        reliability_param: u32,
        label: String,
        protocol: String,
    },
    /// DATA_CHANNEL_ACK response
    Ack,
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Channel Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages data channels for a single session (leg A ↔ SBC ↔ leg B).
///
/// Handles DCEP negotiation, message relay, and lifecycle management.
pub struct DataChannelManager {
    /// Active data channels (keyed by stream_id)
    channels: HashMap<u16, DataChannel>,

    /// Message handler for inbound messages (sends to application)
    msg_tx: mpsc::UnboundedSender<(u16, DataChannelMessage)>,

    /// Next available stream ID for locally-opened channels
    /// (even IDs for the DTLS client, odd IDs for the DTLS server)
    next_stream_id: u16,

    /// Whether this side is the DTLS client (uses even stream IDs)
    #[allow(dead_code)]
    is_dtls_client: bool,

    /// Total messages relayed
    total_relayed: u64,
}

impl DataChannelManager {
    /// Create a new data channel manager
    ///
    /// `is_dtls_client` — if true, locally-opened channels use even stream IDs.
    pub fn new(
        is_dtls_client: bool,
        msg_tx: mpsc::UnboundedSender<(u16, DataChannelMessage)>,
    ) -> Self {
        let start_id = if is_dtls_client { 0 } else { 1 };
        Self {
            channels: HashMap::new(),
            msg_tx,
            next_stream_id: start_id,
            is_dtls_client,
            total_relayed: 0,
        }
    }

    /// Open a new data channel locally
    pub fn open_channel(&mut self, label: &str, channel_type: ChannelType) -> Result<u16> {
        if self.channels.len() >= MAX_DATA_CHANNELS {
            return Err(Error::Other("Max data channels reached".to_string()));
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // skip 2 (even/odd interleaving)

        let channel = DataChannel::new(stream_id, label, channel_type, true);
        self.channels.insert(stream_id, channel);

        info!(
            "Opened data channel {} label='{}' type={:?}",
            stream_id, label, channel_type
        );

        Ok(stream_id)
    }

    /// Handle an incoming DCEP message (from SCTP with PPID_DCEP)
    pub fn handle_dcep(&mut self, stream_id: u16, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let msg = parse_dcep(data)?;

        match msg {
            DcepMessage::Open {
                channel_type,
                label,
                protocol,
                ..
            } => {
                info!(
                    "Remote opened data channel {} label='{}' protocol='{}'",
                    stream_id, label, protocol
                );

                let mut channel = DataChannel::new(stream_id, &label, channel_type, false);
                channel.protocol = protocol;
                channel.open();
                self.channels.insert(stream_id, channel);

                // Reply with ACK
                Ok(Some(build_dcep_ack()))
            }
            DcepMessage::Ack => {
                if let Some(channel) = self.channels.get_mut(&stream_id) {
                    channel.open();
                    info!("Data channel {} acknowledged and open", stream_id);
                }
                Ok(None)
            }
        }
    }

    /// Handle an incoming data message (from SCTP)
    pub fn handle_message(
        &mut self,
        stream_id: u16,
        ppid: u32,
        data: &[u8],
    ) -> Result<()> {
        if ppid == PPID_DCEP {
            let _reply = self.handle_dcep(stream_id, data)?;
            return Ok(());
        }

        let msg = DataChannelMessage::from_sctp(ppid, data)?;

        if let Some(channel) = self.channels.get_mut(&stream_id) {
            channel.messages_received += 1;
            channel.bytes_received += data.len() as u64;
        }

        // Forward to application
        let _ = self.msg_tx.send((stream_id, msg));
        self.total_relayed += 1;

        Ok(())
    }

    /// Send a message on a data channel
    pub fn send_message(
        &mut self,
        stream_id: u16,
        msg: &DataChannelMessage,
    ) -> Result<(u32, Vec<u8>)> {
        let channel = self.channels.get_mut(&stream_id)
            .ok_or_else(|| Error::Other(format!("Data channel {} not found", stream_id)))?;

        if channel.state != DataChannelState::Open {
            return Err(Error::Other(format!(
                "Data channel {} not open (state: {:?})",
                stream_id, channel.state
            )));
        }

        let bytes = msg.to_bytes();
        channel.messages_sent += 1;
        channel.bytes_sent += bytes.len() as u64;

        Ok((msg.ppid(), bytes))
    }

    /// Close a data channel
    pub fn close_channel(&mut self, stream_id: u16) -> bool {
        if let Some(channel) = self.channels.get_mut(&stream_id) {
            channel.state = DataChannelState::Closed;
            info!(
                "Closed data channel {} (sent:{} recv:{})",
                stream_id, channel.messages_sent, channel.messages_received
            );
            true
        } else {
            false
        }
    }

    /// Get channel by stream ID
    pub fn get_channel(&self, stream_id: u16) -> Option<&DataChannel> {
        self.channels.get(&stream_id)
    }

    /// List all channels
    pub fn list_channels(&self) -> Vec<&DataChannel> {
        self.channels.values().collect()
    }

    /// Get total relayed messages
    pub fn total_relayed(&self) -> u64 {
        self.total_relayed
    }

    /// Get statistics
    pub fn stats(&self) -> DataChannelStats {
        let open = self.channels.values()
            .filter(|c| c.state == DataChannelState::Open)
            .count();
        let total_sent: u64 = self.channels.values().map(|c| c.messages_sent).sum();
        let total_recv: u64 = self.channels.values().map(|c| c.messages_received).sum();

        DataChannelStats {
            total_channels: self.channels.len(),
            open_channels: open,
            messages_sent: total_sent,
            messages_received: total_recv,
        }
    }
}

/// Data channel statistics
#[derive(Debug, Clone, Copy)]
pub struct DataChannelStats {
    pub total_channels: usize,
    pub open_channels: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// SDP helpers for data channels
// ─────────────────────────────────────────────────────────────────────────────

/// Add a data channel m= line to an SDP body.
///
/// WebRTC data channels use `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`.
pub fn sdp_add_data_channel(sdp: &str, sctp_port: u16) -> String {
    let dc_sdp = format!(
        "m=application {} UDP/DTLS/SCTP webrtc-datachannel\r\n\
         a=sctp-port:{}\r\n\
         a=max-message-size:262144\r\n",
        sctp_port, sctp_port
    );
    format!("{}{}", sdp.trim_end(), &format!("\r\n{}", dc_sdp))
}

/// Check if an SDP body includes a data channel offer
pub fn sdp_has_data_channel(sdp: &str) -> bool {
    sdp.lines().any(|l| {
        l.trim().starts_with("m=application") && l.contains("webrtc-datachannel")
    })
}

/// Extract the SCTP port from SDP
pub fn sdp_sctp_port(sdp: &str) -> Option<u16> {
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("a=sctp-port:") {
            return line["a=sctp-port:".len()..].trim().parse().ok();
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_channel_message_text() {
        let msg = DataChannelMessage::Text("Hello, World!".to_string());
        assert_eq!(msg.ppid(), PPID_STRING);
        let bytes = msg.to_bytes();
        assert_eq!(bytes, b"Hello, World!");

        let parsed = DataChannelMessage::from_sctp(PPID_STRING, &bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_data_channel_message_binary() {
        let data = vec![0x01, 0x02, 0x03, 0xFF];
        let msg = DataChannelMessage::Binary(data.clone());
        assert_eq!(msg.ppid(), PPID_BINARY);
        let bytes = msg.to_bytes();
        assert_eq!(bytes, data);

        let parsed = DataChannelMessage::from_sctp(PPID_BINARY, &bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_data_channel_message_empty() {
        let msg = DataChannelMessage::Text(String::new());
        assert_eq!(msg.ppid(), PPID_STRING_EMPTY);

        let msg2 = DataChannelMessage::Binary(Vec::new());
        assert_eq!(msg2.ppid(), PPID_BINARY_EMPTY);
    }

    #[test]
    fn test_channel_type_dcep() {
        assert_eq!(ChannelType::Reliable.to_dcep_type(), 0x00);
        assert_eq!(ChannelType::ReliableUnordered.to_dcep_type(), 0x80);
        assert_eq!(ChannelType::PartialReliableRexmit(3).to_dcep_type(), 0x01);
        assert_eq!(ChannelType::PartialReliableTimed(5000).to_dcep_type(), 0x02);
    }

    #[test]
    fn test_dcep_open_parse_round_trip() {
        let msg = build_dcep_open(
            ChannelType::Reliable,
            0,   // priority
            0,   // reliability_param
            "chat",
            "json",
        );

        let parsed = parse_dcep(&msg).unwrap();
        match parsed {
            DcepMessage::Open { label, protocol, channel_type, .. } => {
                assert_eq!(label, "chat");
                assert_eq!(protocol, "json");
                assert_eq!(channel_type, ChannelType::Reliable);
            }
            _ => panic!("Expected Open message"),
        }
    }

    #[test]
    fn test_dcep_ack() {
        let msg = build_dcep_ack();
        assert_eq!(msg, vec![0x02]);

        let parsed = parse_dcep(&msg).unwrap();
        assert!(matches!(parsed, DcepMessage::Ack));
    }

    #[test]
    fn test_data_channel_manager_open() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut mgr = DataChannelManager::new(true, tx);

        let id = mgr.open_channel("chat", ChannelType::Reliable).unwrap();
        assert_eq!(id, 0); // DTLS client starts at 0 (even)

        let id2 = mgr.open_channel("files", ChannelType::ReliableUnordered).unwrap();
        assert_eq!(id2, 2);

        let stats = mgr.stats();
        assert_eq!(stats.total_channels, 2);
    }

    #[test]
    fn test_data_channel_manager_remote_open() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut mgr = DataChannelManager::new(false, tx);

        // Simulate remote opening a channel
        let open_msg = build_dcep_open(
            ChannelType::Reliable, 0, 0, "remote-chat", "",
        );

        let reply = mgr.handle_dcep(0, &open_msg).unwrap();
        assert!(reply.is_some()); // Should get ACK back
        assert_eq!(reply.unwrap(), build_dcep_ack());

        let channel = mgr.get_channel(0).unwrap();
        assert_eq!(channel.label, "remote-chat");
        assert_eq!(channel.state, DataChannelState::Open);
        assert!(!channel.is_local);
    }

    #[test]
    fn test_data_channel_send_receive() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut mgr = DataChannelManager::new(true, tx);

        // Open channel and mark it as open
        let id = mgr.open_channel("test", ChannelType::Reliable).unwrap();
        mgr.channels.get_mut(&id).unwrap().open();

        // Send a message
        let msg = DataChannelMessage::Text("Hello!".to_string());
        let (ppid, bytes) = mgr.send_message(id, &msg).unwrap();
        assert_eq!(ppid, PPID_STRING);
        assert_eq!(bytes, b"Hello!");

        // Receive a message (simulate incoming)
        mgr.handle_message(id, PPID_STRING, b"Reply!").unwrap();

        let (stream, received) = rx.try_recv().unwrap();
        assert_eq!(stream, id);
        assert_eq!(received, DataChannelMessage::Text("Reply!".to_string()));

        let channel = mgr.get_channel(id).unwrap();
        assert_eq!(channel.messages_sent, 1);
        assert_eq!(channel.messages_received, 1);
    }

    #[test]
    fn test_data_channel_close() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut mgr = DataChannelManager::new(true, tx);

        let id = mgr.open_channel("closing", ChannelType::Reliable).unwrap();
        assert!(mgr.close_channel(id));

        let channel = mgr.get_channel(id).unwrap();
        assert_eq!(channel.state, DataChannelState::Closed);
    }

    #[test]
    fn test_sdp_data_channel() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n";
        let with_dc = sdp_add_data_channel(sdp, 5000);
        assert!(with_dc.contains("m=application 5000 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(with_dc.contains("a=sctp-port:5000"));
        assert!(sdp_has_data_channel(&with_dc));
        assert_eq!(sdp_sctp_port(&with_dc), Some(5000));
    }

    #[test]
    fn test_sdp_no_data_channel() {
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 0\r\n";
        assert!(!sdp_has_data_channel(sdp));
        assert_eq!(sdp_sctp_port(sdp), None);
    }

    #[test]
    fn test_data_channel_stats() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut mgr = DataChannelManager::new(true, tx);

        mgr.open_channel("ch1", ChannelType::Reliable).unwrap();
        mgr.open_channel("ch2", ChannelType::Reliable).unwrap();
        mgr.channels.get_mut(&0).unwrap().open();

        let stats = mgr.stats();
        assert_eq!(stats.total_channels, 2);
        assert_eq!(stats.open_channels, 1);
    }
}
