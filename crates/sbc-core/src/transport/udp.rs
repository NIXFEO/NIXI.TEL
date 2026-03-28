//! UDP Transport Listener
//!
//! Handles SIP message reception and transmission over UDP.

use crate::{Error, Result};
use rsip::SipMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Maximum UDP packet size for SIP (RFC 3261 recommends 1300 bytes)
const MAX_PACKET_SIZE: usize = 65535;

/// UDP listener for SIP messages
pub struct UdpListener {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

/// Represents a received SIP message with its source
#[derive(Debug)]
pub struct ReceivedMessage {
    pub message: SipMessage,
    pub source: SocketAddr,
    pub transport: rsip::Transport,
    /// For connection-oriented transports (TCP/TLS/WS), a channel to send
    /// the response back on the SAME connection (avoids opening a new one).
    pub reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl UdpListener {
    /// Create a new UDP listener
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind UDP socket: {}", e)))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local address: {}", e)))?;

        info!("UDP listener bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
        })
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start listening for SIP messages
    pub async fn listen(
        &self,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
        info!("Starting UDP listener on {}", self.local_addr);

        let socket = self.socket.clone();
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            // Receive UDP packet
            let (len, peer_addr) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("UDP receive error: {}", e);
                    continue;
                }
            };

            debug!("Received {} bytes from {}", len, peer_addr);

            // Parse SIP message
            let data = &buf[..len];

            // Skip CRLF keep-alive pings (RFC 5626 §4.4.1)
            // Linphone and other SIP clients send periodic "\r\n\r\n" or
            // "\r\n" as connection keep-alive over UDP outbound flows.
            let non_ws = data.iter().filter(|&&b| b != b'\r' && b != b'\n' && b != b' ').count();
            if non_ws == 0 {
                trace!("SIP keep-alive (CRLF) from {} ({} bytes)", peer_addr, len);
                continue;
            }

            match Self::parse_sip_message(data, peer_addr) {
                Ok(received_msg) => {
                    // Send to message handler
                    if let Err(e) = message_tx.send(received_msg) {
                        error!("Failed to send message to handler: {}", e);
                        // Channel closed, stop listening
                        break;
                    }
                }
                Err(e) => {
                    let snippet = std::str::from_utf8(data)
                        .unwrap_or("<binary>")
                        .chars()
                        .take(300)
                        .collect::<String>();
                    warn!("Failed to parse SIP message from {}: {} — raw: {}", peer_addr, e, snippet);
                    // Continue listening for other messages
                }
            }
        }

        Ok(())
    }

    /// Parse SIP message from raw bytes
    fn parse_sip_message(data: &[u8], source: SocketAddr) -> Result<ReceivedMessage> {
        // Use rsip to parse the message
        let message = SipMessage::try_from(data).map_err(|e| {
            Error::Parse(format!("Failed to parse SIP message: {}", e))
        })?;

        debug!(
            "Parsed SIP message: {} from {}",
            Self::message_summary(&message),
            source
        );

        Ok(ReceivedMessage {
            message,
            source,
            transport: rsip::Transport::Udp,
            reply_tx: None,
        })
    }

    /// Get a summary of the message for logging
    fn message_summary(msg: &SipMessage) -> String {
        match msg {
            SipMessage::Request(req) => {
                format!("{} {}", req.method, req.uri)
            }
            SipMessage::Response(resp) => {
                format!("{}", resp.status_code)
            }
        }
    }

    /// Send SIP message to a destination
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        debug!("Sending {} bytes to {} via UDP", data.len(), dest);

        self.socket
            .send_to(data, dest)
            .await
            .map_err(|e| Error::Transport(format!("Failed to send UDP packet: {}", e)))?;

        Ok(())
    }

    /// Get a clone of the underlying UDP socket (for sharing with trunk registration)
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_listener_bind() {
        let listener = UdpListener::new("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        assert!(listener.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_parse_valid_invite() {
        let sip_msg = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
                        Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
                        Max-Forwards: 70\r\n\
                        To: Bob <sip:bob@biloxi.example.com>\r\n\
                        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
                        Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
                        Content-Length: 0\r\n\
                        \r\n";

        let result = UdpListener::parse_sip_message(
            sip_msg,
            "192.168.1.1:5060".parse().unwrap(),
        );

        assert!(result.is_ok());
        let received = result.unwrap();

        match received.message {
            SipMessage::Request(req) => {
                assert_eq!(req.method, rsip::Method::Invite);
            }
            _ => panic!("Expected request"),
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_message() {
        let invalid_msg = b"This is not a SIP message";

        let result = UdpListener::parse_sip_message(
            invalid_msg,
            "192.168.1.1:5060".parse().unwrap(),
        );

        assert!(result.is_err());
    }
}
