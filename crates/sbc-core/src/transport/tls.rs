//! TLS Transport Listener
//!
//! Handles SIP message reception and transmission over TLS (SIPS).

use crate::{Error, Result};
use crate::transport::udp::ReceivedMessage;
use rsip::SipMessage;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Maximum size for a single SIP message over TLS
const MAX_MESSAGE_SIZE: usize = 65535;

/// TLS listener for SIP messages
pub struct TlsListenerServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    local_addr: SocketAddr,
}

impl TlsListenerServer {
    /// Create a new TLS listener
    pub async fn new(
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        // Load TLS certificates
        let certs = Self::load_certs(cert_path)?;
        let key = Self::load_private_key(key_path)?;

        // Create TLS config
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Transport(format!("Failed to create TLS config: {}", e)))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));

        // Bind TCP listener
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind TLS socket: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local address: {}", e)))?;

        info!("TLS listener bound to {}", local_addr);

        Ok(Self {
            listener,
            acceptor,
            local_addr,
        })
    }

    /// Load TLS certificates from file
    fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        let cert_data = fs::read(path)
            .map_err(|e| Error::Config(format!("Failed to read cert file: {}", e)))?;

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse certificates: {}", e)))?;

        Ok(certs)
    }

    /// Load private key from file
    fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
        let key_data = fs::read(path)
            .map_err(|e| Error::Config(format!("Failed to read key file: {}", e)))?;

        // Try PKCS8 format first
        let mut key_slice = key_data.as_slice();
        let mut pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut key_slice);
        if let Some(key_result) = pkcs8_keys.next() {
            let key = key_result.map_err(|e| Error::Config(format!("Failed to parse PKCS8 key: {}", e)))?;
            return Ok(PrivateKeyDer::Pkcs8(key));
        }

        // Try RSA format
        let mut key_slice = key_data.as_slice();
        let mut rsa_keys = rustls_pemfile::rsa_private_keys(&mut key_slice);
        if let Some(key_result) = rsa_keys.next() {
            let key = key_result.map_err(|e| Error::Config(format!("Failed to parse RSA key: {}", e)))?;
            return Ok(PrivateKeyDer::Pkcs1(key));
        }

        Err(Error::Config("No private keys found in key file".to_string()))
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Start listening for incoming TLS connections
    pub async fn listen(
        self,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
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

            debug!("Accepted TCP connection from {}, starting TLS handshake", peer_addr);

            // Perform TLS handshake
            let acceptor = self.acceptor.clone();
            let tx = message_tx.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("TLS handshake successful with {}", peer_addr);
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

            // Try to extract complete SIP messages
            while let Some((message, remaining)) = Self::extract_message(&buffer)? {
                // Skip pure CRLF keepalives (RFC 5626 §4.4.1)
                let trimmed = message.iter().filter(|&&b| b != b'\r' && b != b'\n').count();
                if trimmed == 0 {
                    buffer = remaining.to_vec();
                    continue;
                }

                // Log first line for diagnostics
                if let Ok(text) = std::str::from_utf8(message) {
                    let first_line = text.lines().next().unwrap_or("(empty)");
                    info!("TLS message from {}: {}", peer_addr, first_line);
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
                    "Buffer overflow for TLS connection from {}, resetting",
                    peer_addr
                );
                buffer.clear();
            }
        }

        Ok(())
    }

    /// Extract a complete SIP message from the buffer (same as TCP)
    fn extract_message(buffer: &[u8]) -> Result<Option<(&[u8], &[u8])>> {
        // Skip leading CRLF keepalives (RFC 5626 §4.4.1)
        // Softphones send "\r\n\r\n" or "\r\n" as keepalive pings on TLS connections.
        let buffer = {
            let mut start = 0;
            while start < buffer.len()
                && (buffer[start] == b'\r' || buffer[start] == b'\n')
            {
                start += 1;
            }
            &buffer[start..]
        };

        if buffer.is_empty() {
            return Ok(None);
        }

        // Find end of headers
        let header_end = if let Some(pos) = Self::find_subsequence(buffer, b"\r\n\r\n") {
            pos
        } else {
            return Ok(None);
        };

        // Empty headers = another keepalive, skip
        if header_end == 0 {
            return Ok(Some((&buffer[..4], &buffer[4..])));
        }

        // Extract headers
        let headers = &buffer[..header_end];

        // Parse Content-Length
        let content_length = Self::parse_content_length(headers)?;

        // Calculate total message size
        let message_end = header_end + 4 + content_length;

        if buffer.len() >= message_end {
            Ok(Some((&buffer[..message_end], &buffer[message_end..])))
        } else {
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

        for line in headers_str.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("content-length:") || line_lower.starts_with("l:") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subsequence() {
        let haystack = b"Hello\r\n\r\nWorld";
        let needle = b"\r\n\r\n";
        assert_eq!(
            TlsListenerServer::find_subsequence(haystack, needle),
            Some(5)
        );
    }

    #[test]
    fn test_parse_content_length() {
        let headers = b"Via: SIP/2.0/TLS example.com\r\nContent-Length: 142\r\n";
        assert_eq!(TlsListenerServer::parse_content_length(headers).unwrap(), 142);
    }
}
