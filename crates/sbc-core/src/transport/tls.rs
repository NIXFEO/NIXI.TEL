//! TLS Transport Listener
//!
//! Handles SIP message reception and transmission over TLS (SIPS).

use crate::transport::udp::ReceivedMessage;
use crate::transport::Framing;
use crate::{Error, Result};
use rsip::SipMessage;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// TLS listener for SIP messages
pub struct TlsListenerServer {
    listener: TcpListener,
    identity: Arc<crate::transport::tls_identity::TlsListenerIdentity>,
    local_addr: SocketAddr,
}

impl TlsListenerServer {
    /// Bind, then load the certificate (a key that does not match the
    /// certificate is refused here rather than at every handshake).
    pub async fn new(bind_addr: SocketAddr, cert_path: &Path, key_path: &Path) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind TLS socket: {}", e)))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local address: {}", e)))?;
        let identity = crate::transport::tls_identity::TlsListenerIdentity::load(
            "tls", local_addr, cert_path, key_path,
        )?;
        info!("TLS listener bound to {}", local_addr);
        Ok(Self {
            listener,
            identity,
            local_addr,
        })
    }

    pub fn identity(&self) -> Arc<crate::transport::tls_identity::TlsListenerIdentity> {
        self.identity.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start listening for incoming TLS connections
    pub async fn listen(self, message_tx: mpsc::UnboundedSender<ReceivedMessage>) -> Result<()> {
        info!("Starting TLS listener on {}", self.local_addr);

        loop {
            // Accept new TCP connection
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    continue;
                }
            };

            debug!(
                "Accepted TCP connection from {}, starting TLS handshake",
                peer_addr
            );

            // Perform TLS handshake
            let acceptor = self.identity.acceptor();
            let tx = message_tx.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        debug!("TLS handshake successful with {}", peer_addr);
                        if let Err(e) = Self::handle_connection(tls_stream, peer_addr, tx).await {
                            // Connection handler errors (read errors, resets) are
                            // normal for SIP clients that close abruptly.
                            debug!("TLS connection handler error for {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        // TLS handshake failures are common and expected:
                        // - Scanners/bots probing the port
                        // - Clients using IP instead of hostname (Illegal SNI)
                        // - Outdated TLS versions
                        debug!("TLS handshake failed with {}: {}", peer_addr, e);
                    }
                }
                debug!("TLS connection closed: {}", peer_addr);
            });
        }
    }

    /// Handle a single TLS connection
    async fn handle_connection(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
        // Split into read/write halves so we can write responses back on same conn
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        // Create a reply channel: messages sent here go back on this TLS connection
        let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Spawn writer task: drains reply_rx and writes back on the TLS stream
        let writer_clone = writer.clone();
        let peer_str = peer_addr.to_string();
        tokio::spawn(async move {
            while let Some(data) = reply_rx.recv().await {
                let mut w = writer_clone.lock().await;
                if let Err(e) = w.write_all(&data).await {
                    debug!("TLS write error to {}: {}", peer_str, e);
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
                .map_err(|e| Error::Transport(format!("TLS read error: {}", e)))?;

            if n == 0 {
                // Connection closed
                debug!("TLS connection closed by peer: {}", peer_addr);
                break;
            }

            // Append to buffer
            buffer.extend_from_slice(&chunk[..n]);

            // One hardened framer for both listeners and both outbound
            // readers: each arm consumes bytes or leaves the loop, so a
            // crafted Content-Length cannot pin this task.
            loop {
                match crate::transport::frame_sip_message(&buffer) {
                    Framing::Keepalive { count } => {
                        buffer.drain(..count);
                    }
                    Framing::Message { end } => {
                        let message = buffer[..end].to_vec();
                        buffer.drain(..end);
                        if let Ok(text) = std::str::from_utf8(&message) {
                            let first_line = text.lines().next().unwrap_or("(empty)");
                            debug!("TLS message from {}: {}", peer_addr, first_line);
                        }
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
                            "TLS connection from {} closed: unframeable stream ({})",
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
            "Parsed SIP message from TLS: {} from {}",
            Self::message_summary(&message),
            source
        );

        Ok(ReceivedMessage {
            message,
            source,
            transport: rsip::Transport::Tls,
            reply_tx: Some(reply_tx),
        })
    }

    /// Parse SIP message from raw bytes (no reply channel)
    #[allow(dead_code)]
    fn parse_sip_message(data: &[u8], source: SocketAddr) -> Result<ReceivedMessage> {
        let message = SipMessage::try_from(data)
            .map_err(|e| Error::Parse(format!("Failed to parse SIP message: {}", e)))?;

        debug!(
            "Parsed SIP message from TLS: {} from {}",
            Self::message_summary(&message),
            source
        );

        Ok(ReceivedMessage {
            message,
            source,
            transport: rsip::Transport::Tls,
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
