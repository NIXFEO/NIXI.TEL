//! TCP Transport Listener
//!
//! Handles SIP message reception and transmission over TCP.
//! Supports connection pooling and proper stream parsing.

use crate::{Error, Result};
use crate::transport::udp::ReceivedMessage;
use rsip::SipMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Maximum size for a single SIP message over TCP
const MAX_MESSAGE_SIZE: usize = 65535;

/// TCP listener for SIP messages
pub struct TcpListenerServer {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl TcpListenerServer {
    /// Create a new TCP listener
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind TCP socket: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local address: {}", e)))?;

        info!("TCP listener bound to {}", local_addr);

        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start listening for incoming TCP connections
    pub async fn listen(
        self,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
        info!("Starting TCP listener on {}", self.local_addr);

        loop {
            // Accept new connection
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    continue;
                }
            };

            info!("Accepted TCP connection from {}", peer_addr);

            // Spawn a task to handle this connection
            let tx = message_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, peer_addr, tx).await {
                    // TCP connection errors are common: scanners, connection resets, etc.
                    debug!("TCP connection handler error for {}: {}", peer_addr, e);
                }
                debug!("TCP connection closed: {}", peer_addr);
            });
        }
    }

    /// Handle a single TCP connection
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
        // Split stream into read/write halves
        let (mut reader, writer) = stream.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        // Create a reply channel: messages sent here go back on this TCP connection
        let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Spawn writer task: drains reply_rx and writes to TCP
        let writer_clone = writer.clone();
        let peer_str = peer_addr.to_string();
        tokio::spawn(async move {
            while let Some(data) = reply_rx.recv().await {
                let mut w = writer_clone.lock().await;
                use tokio::io::AsyncWriteExt;
                if let Err(e) = w.write_all(&data).await {
                    debug!("TCP write error to {}: {}", peer_str, e);
                    break;
                }
                let _ = w.flush().await;
            }
        });

        let mut buffer = Vec::with_capacity(4096);

        loop {
            // Read data from stream
            let mut chunk = vec![0u8; 4096];
            let n = reader
                .read(&mut chunk)
                .await
                .map_err(|e| Error::Transport(format!("TCP read error: {}", e)))?;

            if n == 0 {
                // Connection closed
                debug!("TCP connection closed by peer: {}", peer_addr);
                break;
            }

            // Append to buffer
            buffer.extend_from_slice(&chunk[..n]);

            // Try to extract complete SIP messages
            while let Some((message, remaining)) = Self::extract_message(&buffer)? {
                // Skip pure CRLF keepalives (RFC 5626 §4.4.1)
                let trimmed = message.iter().filter(|&&b| b != b'\r' && b != b'\n').count();
                if trimmed == 0 {
                    buffer = remaining.to_vec();
                    continue;
                }

                // Parse and send the message with the reply channel
                match Self::parse_sip_message_with_reply(&message, peer_addr, reply_tx.clone()) {
                    Ok(received_msg) => {
                        if let Err(e) = message_tx.send(received_msg) {
                            error!("Failed to send message to handler: {}", e);
                            return Ok(()); // Channel closed
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse SIP message from {}: {}", peer_addr, e);
                    }
                }

                // Update buffer with remaining data
                buffer = remaining.to_vec();
            }

            // Prevent buffer from growing indefinitely
            if buffer.len() > MAX_MESSAGE_SIZE {
                warn!(
                    "Buffer overflow for TCP connection from {}, resetting",
                    peer_addr
                );
                buffer.clear();
            }
        }

        Ok(())
    }

    /// Extract a complete SIP message from the buffer
    /// Returns (message, remaining_data) if a complete message is found
    fn extract_message(buffer: &[u8]) -> Result<Option<(&[u8], &[u8])>> {
        // SIP messages are separated by \r\n\r\n between headers and body
        // We need to find Content-Length to know where the message ends

        // Find end of headers
        let header_end = if let Some(pos) = Self::find_subsequence(buffer, b"\r\n\r\n") {
            pos
        } else {
            // No complete headers yet
            return Ok(None);
        };

        // Extract headers
        let headers = &buffer[..header_end];

        // Parse Content-Length
        let content_length = Self::parse_content_length(headers)?;

        // Calculate total message size
        let message_end = header_end + 4 + content_length; // +4 for \r\n\r\n

        if buffer.len() >= message_end {
            // We have a complete message
            Ok(Some((&buffer[..message_end], &buffer[message_end..])))
        } else {
            // Waiting for more data
            Ok(None)
        }
    }

    /// Find a subsequence in a byte slice
    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Parse Content-Length header from SIP headers
    fn parse_content_length(headers: &[u8]) -> Result<usize> {
        let headers_str = std::str::from_utf8(headers)
            .map_err(|e| Error::Parse(format!("Invalid UTF-8 in headers: {}", e)))?;

        // Look for Content-Length header (case-insensitive)
        for line in headers_str.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-length:")
                || line_lower.starts_with("l:") // Compact form
            {
                let value = line
                    .split(':')
                    .nth(1)
                    .ok_or_else(|| Error::Parse("Invalid Content-Length header".to_string()))?
                    .trim();

                return value.parse::<usize>().map_err(|e| {
                    Error::Parse(format!("Failed to parse Content-Length: {}", e))
                });
            }
        }

        // No Content-Length header, assume 0
        Ok(0)
    }

    /// Parse SIP message from raw bytes (with reply channel for responses)
    fn parse_sip_message_with_reply(
        data: &[u8],
        source: SocketAddr,
        reply_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<ReceivedMessage> {
        let message = SipMessage::try_from(data)
            .map_err(|e| Error::Parse(format!("Failed to parse SIP message: {}", e)))?;

        debug!(
            "Parsed SIP message from TCP: {} from {}",
            Self::message_summary(&message),
            source
        );

        Ok(ReceivedMessage {
            message,
            source,
            transport: rsip::Transport::Tcp,
            reply_tx: Some(reply_tx),
        })
    }

    /// Parse SIP message from raw bytes (no reply channel)
    fn parse_sip_message(data: &[u8], source: SocketAddr) -> Result<ReceivedMessage> {
        let message = SipMessage::try_from(data)
            .map_err(|e| Error::Parse(format!("Failed to parse SIP message: {}", e)))?;

        debug!(
            "Parsed SIP message from TCP: {} from {}",
            Self::message_summary(&message),
            source
        );

        Ok(ReceivedMessage {
            message,
            source,
            transport: rsip::Transport::Tcp,
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
}

/// TCP connection for sending messages
pub struct TcpConnection {
    stream: Arc<tokio::sync::Mutex<TcpStream>>,
    peer_addr: SocketAddr,
}

impl TcpConnection {
    /// Create a new TCP connection to a destination
    pub async fn connect(dest: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(dest)
            .await
            .map_err(|e| Error::Transport(format!("Failed to connect to {}: {}", dest, e)))?;

        debug!("Established TCP connection to {}", dest);

        Ok(Self {
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            peer_addr: dest,
        })
    }

    /// Send SIP message over this connection
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        debug!(
            "Sending {} bytes to {} via TCP",
            data.len(),
            self.peer_addr
        );

        let mut stream = self.stream.lock().await;
        stream
            .write_all(data)
            .await
            .map_err(|e| Error::Transport(format!("Failed to write to TCP stream: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| Error::Transport(format!("Failed to flush TCP stream: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subsequence() {
        let haystack = b"Hello\r\n\r\nWorld";
        let needle = b"\r\n\r\n";
        assert_eq!(
            TcpListenerServer::find_subsequence(haystack, needle),
            Some(5)
        );
    }

    #[test]
    fn test_parse_content_length() {
        let headers = b"Via: SIP/2.0/TCP example.com\r\nContent-Length: 142\r\n";
        assert_eq!(TcpListenerServer::parse_content_length(headers).unwrap(), 142);
    }

    #[test]
    fn test_parse_content_length_compact() {
        let headers = b"Via: SIP/2.0/TCP example.com\r\nl: 50\r\n";
        assert_eq!(TcpListenerServer::parse_content_length(headers).unwrap(), 50);
    }

    #[test]
    fn test_parse_content_length_missing() {
        let headers = b"Via: SIP/2.0/TCP example.com\r\n";
        assert_eq!(TcpListenerServer::parse_content_length(headers).unwrap(), 0);
    }

    #[test]
    fn test_extract_message_complete() {
        let buffer = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let result = TcpListenerServer::extract_message(buffer).unwrap();
        assert!(result.is_some());
        let (msg, remaining) = result.unwrap();
        assert_eq!(msg.len(), buffer.len());
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_extract_message_incomplete() {
        let buffer = b"INVITE sip:bob@example.com SIP/2.0\r\n";
        let result = TcpListenerServer::extract_message(buffer).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_message_with_body() {
        let buffer = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nHello";
        let result = TcpListenerServer::extract_message(buffer).unwrap();
        assert!(result.is_some());
        let (msg, remaining) = result.unwrap();
        assert_eq!(msg.len(), buffer.len());
        assert_eq!(remaining.len(), 0);
    }
}
