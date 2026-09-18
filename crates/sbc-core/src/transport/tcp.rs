//! TCP Transport Listener
//!
//! Handles SIP message reception and transmission over TCP.
//! Supports connection pooling and proper stream parsing.

use crate::transport::udp::ReceivedMessage;
use crate::{Error, Result};
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
    pub async fn listen(self, message_tx: mpsc::UnboundedSender<ReceivedMessage>) -> Result<()> {
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

            debug!("Accepted TCP connection from {}", peer_addr);

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
                let trimmed = message
                    .iter()
                    .filter(|&&b| b != b'\r' && b != b'\n')
                    .count();
                if trimmed == 0 {
                    buffer = remaining.to_vec();
                    continue;
                }

                // Parse and send the message with the reply channel
                match Self::parse_sip_message_with_reply(message, peer_addr, reply_tx.clone()) {
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
            if line_lower.starts_with("content-length:") || line_lower.starts_with("l:")
            // Compact form
            {
                let value = line
                    .split(':')
                    .nth(1)
                    .ok_or_else(|| Error::Parse("Invalid Content-Length header".to_string()))?
                    .trim();

                return value
                    .parse::<usize>()
                    .map_err(|e| Error::Parse(format!("Failed to parse Content-Length: {}", e)));
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
    #[allow(dead_code)]
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

/// One outbound TCP connection to a peer (trunk or phone).
///
/// **It reads.** RFC 3261 §18.2.2: a UAS sends its responses back on the
/// connection the request arrived on. Without a reader on the connections
/// *we* open, every response to a request the SBC sent over TCP was
/// dropped on the floor by the kernel — a TCP trunk could not complete a
/// single call, and the only symptom was the setup timeout. The reader
/// task frames by `Content-Length` and pushes into the same pipeline the
/// listeners feed, with `reply_tx` bound to this connection so the answer
/// goes back the way it came.
///
/// Writes stay synchronous (a `Mutex` over the write half, awaited by the
/// sender) so a failing send is still reported to the caller that must
/// fail over, unlike the TLS path where the writer is a task.
pub struct TcpConnection {
    writer: Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    peer_addr: SocketAddr,
    /// Set by the reader task on EOF or read error: the pool must not
    /// hand this connection out again.
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl TcpConnection {
    /// Connect to a destination — bounded by
    /// [`OUTBOUND_CONNECT_TIMEOUT`](crate::transport::OUTBOUND_CONNECT_TIMEOUT)
    /// — and spawn the reader task that feeds `message_tx`.
    pub async fn connect(
        dest: SocketAddr,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<Self> {
        let timeout = crate::transport::OUTBOUND_CONNECT_TIMEOUT;
        let stream = tokio::time::timeout(timeout, TcpStream::connect(dest))
            .await
            .map_err(|_| {
                Error::Transport(format!(
                    "TCP connect to {} timed out after {:?}",
                    dest, timeout
                ))
            })?
            .map_err(|e| Error::Transport(format!("Failed to connect to {}: {}", dest, e)))?;

        debug!("Established TCP connection to {}", dest);

        let (mut read_half, write_half) = stream.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(write_half));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Anything we write back on this connection: the reply channel the
        // handlers receive with each message.
        let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let reply_writer = writer.clone();
        tokio::spawn(async move {
            while let Some(data) = reply_rx.recv().await {
                let mut w = reply_writer.lock().await;
                if let Err(e) = w.write_all(&data).await {
                    debug!("TCP write to {} failed: {}", dest, e);
                    break;
                }
                let _ = w.flush().await;
            }
        });

        // Reader task: Content-Length framing → the SBC pipeline.
        let closed_flag = closed.clone();
        tokio::spawn(async move {
            let mut buffer: Vec<u8> = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            loop {
                match read_half.read(&mut chunk).await {
                    Ok(0) => {
                        debug!("Outbound TCP connection to {} closed by peer", dest);
                        break;
                    }
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);
                        while let Some((msg_end, remaining_start)) =
                            crate::transport::frame_sip_message(&buffer)
                        {
                            let raw = buffer[..msg_end].to_vec();
                            buffer.drain(..remaining_start);
                            if crate::transport::is_keepalive(&raw) {
                                continue;
                            }
                            match rsip::SipMessage::try_from(raw) {
                                Ok(message) => {
                                    let _ = message_tx.send(ReceivedMessage {
                                        message,
                                        source: dest,
                                        transport: rsip::Transport::Tcp,
                                        reply_tx: Some(reply_tx.clone()),
                                    });
                                }
                                Err(e) => {
                                    warn!("TCP: unparseable SIP from {}: {}", dest, e)
                                }
                            }
                        }
                        if buffer.len() > MAX_MESSAGE_SIZE {
                            warn!("TCP read buffer overflow from {}, resetting", dest);
                            buffer.clear();
                        }
                    }
                    Err(e) => {
                        debug!("Outbound TCP read from {} failed: {}", dest, e);
                        break;
                    }
                }
            }
            closed_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        Ok(Self {
            writer,
            peer_addr: dest,
            closed,
        })
    }

    /// Send a SIP message on this connection.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to {} via TCP", data.len(), self.peer_addr);

        let mut writer = self.writer.lock().await;
        writer
            .write_all(data)
            .await
            .map_err(|e| Error::Transport(format!("Failed to write to TCP stream: {}", e)))?;

        writer
            .flush()
            .await
            .map_err(|e| Error::Transport(format!("Failed to flush TCP stream: {}", e)))?;

        Ok(())
    }

    /// Whether the peer has closed the connection (or the read failed):
    /// the pool reconnects instead of writing into a dead socket.
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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
        assert_eq!(
            TcpListenerServer::parse_content_length(headers).unwrap(),
            142
        );
    }

    #[test]
    fn test_parse_content_length_compact() {
        let headers = b"Via: SIP/2.0/TCP example.com\r\nl: 50\r\n";
        assert_eq!(
            TcpListenerServer::parse_content_length(headers).unwrap(),
            50
        );
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

#[cfg(test)]
mod connect_timeout_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// TEST-NET-3 (RFC 5737) is never routed: the connect either fails at
    /// once (no route) or hangs — and must then be cut by our timeout, never
    /// by the kernel's SYN timeout minutes later.
    #[tokio::test]
    async fn connect_to_a_black_hole_fails_within_the_timeout() {
        let dest: SocketAddr = "203.0.113.1:5060".parse().unwrap();
        let started = Instant::now();
        let (tx, _rx) = mpsc::unbounded_channel();
        let result = TcpConnection::connect(dest, tx).await;
        assert!(result.is_err());
        let budget = crate::transport::OUTBOUND_CONNECT_TIMEOUT + Duration::from_secs(1);
        assert!(
            started.elapsed() <= budget,
            "connect took {:?}",
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod outbound_reader_tests {
    use super::*;
    use std::time::Duration;

    /// RFC 3261 §18.2.2: the peer answers on the connection our request
    /// arrived on. Nothing read those connections, so every response to a
    /// request the SBC sent over TCP was dropped by the kernel and the
    /// call died at the setup timeout with no diagnostic at all.
    #[tokio::test]
    async fn a_response_on_our_own_connection_reaches_the_pipeline() {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        // The far end: read whatever arrives, answer 100 Trying then 200 OK
        // in a single write (two messages in one segment, so the framing is
        // exercised too).
        tokio::spawn(async move {
            let (mut sock, _) = peer.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("INVITE "));
            let answers =
                "SIP/2.0 100 Trying\r\nVia: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK1\r\n\
                 From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>\r\nCall-ID: c1\r\n\
                 CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n\
                 SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK1\r\n\
                 From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>;tag=2\r\nCall-ID: c1\r\n\
                 CSeq: 1 INVITE\r\nContent-Length: 4\r\n\r\nbody";
            sock.write_all(answers.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            // Keep the socket open so the reader is not torn down.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let conn = TcpConnection::connect(peer_addr, tx)
            .await
            .expect("connect");
        conn.send(
            b"INVITE sip:b@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK1\r\n\
              CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("send");

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the 100 Trying reached the pipeline")
            .unwrap();
        assert_eq!(first.transport, rsip::Transport::Tcp);
        assert_eq!(first.source, peer_addr);
        assert!(
            first.reply_tx.is_some(),
            "the answer must go back on this very connection"
        );
        match first.message {
            SipMessage::Response(r) => assert_eq!(u16::from(r.status_code), 100),
            other => panic!("expected a response, got {:?}", other),
        }

        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the 200 OK was framed after it")
            .unwrap();
        match second.message {
            SipMessage::Response(r) => {
                assert_eq!(u16::from(r.status_code), 200);
                assert_eq!(r.body, b"body", "the body was framed by Content-Length");
            }
            other => panic!("expected a response, got {:?}", other),
        }
        assert!(!conn.is_closed());
    }

    /// The peer hanging up marks the connection unusable, so the pool
    /// reconnects instead of writing into a dead socket until restart.
    #[tokio::test]
    async fn a_closed_connection_is_marked_closed() {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = peer.accept().await.unwrap();
            drop(sock);
        });

        let (tx, _rx) = mpsc::unbounded_channel();
        let conn = TcpConnection::connect(peer_addr, tx)
            .await
            .expect("connect");
        for _ in 0..50 {
            if conn.is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the reader never noticed the peer closing");
    }
}
