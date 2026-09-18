//! TCP Transport Listener
//!
//! Handles SIP message reception and transmission over TCP.
//! Supports connection pooling and proper stream parsing.

use crate::transport::udp::ReceivedMessage;
use crate::transport::Framing;
use crate::{Error, Result};
use rsip::SipMessage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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

            // Frame every complete message in the buffer. Each arm either
            // consumes bytes or leaves the loop: this runs inside the
            // per-connection task, *before* the ban/ACL/DoS pipeline, so a
            // framing result that consumed nothing used to pin a core on
            // one unauthenticated connection with nothing able to stop it.
            loop {
                match crate::transport::frame_sip_message(&buffer) {
                    Framing::Keepalive { count } => {
                        buffer.drain(..count);
                    }
                    Framing::Message { end } => {
                        let message = buffer[..end].to_vec();
                        buffer.drain(..end);
                        match Self::parse_sip_message_with_reply(
                            &message,
                            peer_addr,
                            reply_tx.clone(),
                        ) {
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
                    }
                    Framing::Incomplete => break,
                    Framing::Malformed(why) => {
                        warn!(
                            "TCP connection from {} closed: unframeable stream ({})",
                            peer_addr, why
                        );
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
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
                        // Every arm consumes bytes or leaves the loop, so
                        // no framing result can spin this task.
                        let mut closing = None;
                        loop {
                            match crate::transport::frame_sip_message(&buffer) {
                                Framing::Keepalive { count } => {
                                    buffer.drain(..count);
                                }
                                Framing::Message { end } => {
                                    let raw = buffer[..end].to_vec();
                                    buffer.drain(..end);
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
                                Framing::Incomplete => break,
                                Framing::Malformed(why) => {
                                    closing = Some(why);
                                    break;
                                }
                            }
                        }
                        if let Some(why) = closing {
                            warn!(
                                "Outbound TCP to {} closed: unframeable stream ({})",
                                dest, why
                            );
                            break;
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
    ///
    /// Bounded, like the connect: the SIP event loop awaits this inline,
    /// so a peer that advertises a zero receive window and never drains
    /// it would otherwise park the whole SBC in `write_all` for ever. The
    /// elapsed case is a transport error, which makes `send_tcp` evict the
    /// connection and the caller fail over.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to {} via TCP", data.len(), self.peer_addr);

        let peer = self.peer_addr;
        let write = async {
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
        };
        match tokio::time::timeout(crate::transport::OUTBOUND_WRITE_TIMEOUT, write).await {
            Ok(result) => result,
            Err(_) => {
                self.closed
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Err(Error::Transport(format!(
                    "TCP write to {} timed out after {:?}",
                    peer,
                    crate::transport::OUTBOUND_WRITE_TIMEOUT
                )))
            }
        }
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

#[cfg(test)]
mod listener_hardening_tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpStream;

    /// The critical one. `header_end + 4 + content_length` was unchecked
    /// arithmetic on a peer-controlled value, so a `Content-Length` of
    /// `2^64 - 4 - header_end` wrapped the message end to zero: the
    /// listener framed an empty message, consumed nothing, and re-framed
    /// it for ever without ever awaiting. That loop runs in the
    /// per-connection task, **before** the ban, ACL and DoS gates, so one
    /// unauthenticated connection pinned a core with nothing able to see
    /// or stop it, and two saturated the production box.
    ///
    /// The observable fix: the connection is closed instead. Before it,
    /// this test hangs at 100% of a core.
    #[tokio::test]
    async fn a_crafted_content_length_closes_the_connection_instead_of_spinning() {
        let listener = TcpListenerServer::new("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr();
        let (tx, _rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        });

        let mut peer = TcpStream::connect(addr).await.expect("connect");
        peer.write_all(b"SIP/2.0 200 OK\r\nP: \r\nl: 18446744073709551568\r\n\r\n")
            .await
            .expect("write");

        // EOF, quickly: the listener refuses to resynchronise a stream it
        // cannot frame.
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut buf))
            .await
            .expect("the listener neither answered nor closed: it is spinning")
            .expect("read");
        assert_eq!(n, 0, "the connection is closed, not answered");
    }

    /// A legitimate message on the same path still gets through, and a
    /// single CRLF keepalive in front of it does not eat it (RFC 3261
    /// §7.5).
    #[tokio::test]
    async fn a_keepalive_then_a_real_message_both_arrive() {
        let listener = TcpListenerServer::new("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr();
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        });

        let mut peer = TcpStream::connect(addr).await.expect("connect");
        peer.write_all(
            b"\r\nOPTIONS sip:sbc@127.0.0.1 SIP/2.0\r\n\
              Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKopt\r\n\
              From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>\r\n\
              Call-ID: framing-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("write");

        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the message reached the pipeline")
            .expect("channel open");
        assert_eq!(received.transport, rsip::Transport::Tcp);
        match received.message {
            SipMessage::Request(r) => assert_eq!(r.method, rsip::Method::Options),
            other => panic!("expected an OPTIONS request, got {:?}", other),
        }
    }
}
