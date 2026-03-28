//! WebSocket / WSS Transport Listener
//!
//! Handles SIP over WebSocket (RFC 7118) for WebRTC browsers.
//! Supports both WS (plain) and WSS (TLS-secured) connections.
//!
//! RFC 7118 - The WebSocket Protocol as a Transport for SIP
//! Sub-protocol: "sip" (registered IANA)

use crate::transport::udp::ReceivedMessage;
use crate::{Error, Result};
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::accept_hdr_async;
use tracing::{debug, error, info, warn};

/// WebSocket listener for SIP over WebSocket (RFC 7118)
pub struct WsListenerServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
}

impl WsListenerServer {
    /// Create a plain WebSocket (WS) listener
    pub async fn new_ws(bind_addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind WS socket: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local address: {}", e)))?;

        info!("WS listener bound to {}", local_addr);

        Ok(Self {
            listener,
            local_addr,
            tls_acceptor: None,
        })
    }

    /// Create a secure WebSocket (WSS) listener with TLS
    pub async fn new_wss(
        bind_addr: SocketAddr,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        let certs = Self::load_certs(cert_path)?;
        let key = Self::load_private_key(key_path)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Transport(format!("Failed to create WSS TLS config: {}", e)))?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| Error::Transport(format!("Failed to bind WSS socket: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Transport(format!("Failed to get local WSS address: {}", e)))?;

        info!("WSS listener bound to {}", local_addr);

        Ok(Self {
            listener,
            local_addr,
            tls_acceptor: Some(tls_acceptor),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_secure(&self) -> bool {
        self.tls_acceptor.is_some()
    }

    /// Load TLS certificates from PEM file
    fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Config(format!("Failed to read cert: {}", e)))?;
        rustls_pemfile::certs(&mut data.as_slice())
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse cert: {}", e)))
    }

    /// Load private key from PEM file
    fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
        let data = std::fs::read(path)
            .map_err(|e| Error::Config(format!("Failed to read key: {}", e)))?;
        let mut cursor = std::io::Cursor::new(data);
        rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| Error::Config(format!("Failed to parse key: {}", e)))?
            .ok_or_else(|| Error::Config("No private key found in file".to_string()))
    }

    /// Start listening for WebSocket connections
    pub async fn listen(
        self,
        message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    ) -> Result<()> {
        let proto = if self.tls_acceptor.is_some() { "WSS" } else { "WS" };
        info!("Starting {} listener on {}", proto, self.local_addr);

        loop {
            let (tcp_stream, peer_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("{} accept error: {}", proto, e);
                    continue;
                }
            };

            debug!("{} connection from {}", proto, peer_addr);

            let tx = message_tx.clone();
            let acceptor = self.tls_acceptor.clone();
            let is_wss = acceptor.is_some();

            tokio::spawn(async move {
                if let Err(e) = handle_ws_connection(tcp_stream, peer_addr, tx, acceptor, is_wss).await {
                    // WSS connection errors are mostly scanners/bots sending
                    // invalid HTTP to the WebSocket port — log at debug.
                    debug!("{} connection error from {}: {}", proto, peer_addr, e);
                }
            });
        }
    }
}

/// Handle a single WebSocket connection (WS or WSS)
async fn handle_ws_connection(
    tcp_stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    message_tx: mpsc::UnboundedSender<ReceivedMessage>,
    tls_acceptor: Option<TlsAcceptor>,
    is_wss: bool,
) -> Result<()> {
    // Upgrade to WebSocket, optionally wrapping with TLS first
    // We use a callback to validate the SIP sub-protocol (RFC 7118)
    let callback = |req: &Request, mut resp: Response| {
        // RFC 7118 §5: sub-protocol MUST be "sip"
        let proto = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if proto.contains("sip") {
            resp.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                "sip".parse().unwrap(),
            );
        }
        Ok(resp)
    };

    let ws_stream = if let Some(acceptor) = tls_acceptor {
        // WSS: TLS first, then WebSocket upgrade
        let tls_stream = acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| Error::Transport(format!("TLS handshake failed: {}", e)))?;

        let ws = accept_hdr_async(tls_stream, callback)
            .await
            .map_err(|e| Error::Transport(format!("WSS upgrade failed: {}", e)))?;

        // Wrap in enum for unified handling
        WsStream::Secure(ws)
    } else {
        let ws = accept_hdr_async(tcp_stream, callback)
            .await
            .map_err(|e| Error::Transport(format!("WS upgrade failed: {}", e)))?;
        WsStream::Plain(ws)
    };

    let transport = if is_wss {
        rsip::Transport::Wss
    } else {
        rsip::Transport::Ws
    };

    info!("WebSocket connection established from {}", peer_addr);

    // Process WebSocket messages
    process_ws_messages(ws_stream, peer_addr, transport, message_tx).await
}

/// Unified WebSocket stream (plain or TLS-wrapped)
enum WsStream {
    Plain(tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>),
    Secure(tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
}

/// Sink half of a split WebSocket (for writing replies)
enum WsSink {
    Plain(SplitSink<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, Message>),
    Secure(SplitSink<tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, Message>),
}

/// Stream half of a split WebSocket (for reading messages)
enum WsReader {
    Plain(SplitStream<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>),
    Secure(SplitStream<tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>),
}

impl WsSink {
    async fn send_text(&mut self, text: String) -> std::result::Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WsSink::Plain(s) => s.send(Message::Text(text)).await,
            WsSink::Secure(s) => s.send(Message::Text(text)).await,
        }
    }

    async fn send_pong(&mut self, data: Vec<u8>) -> std::result::Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WsSink::Plain(s) => s.send(Message::Pong(data)).await,
            WsSink::Secure(s) => s.send(Message::Pong(data)).await,
        }
    }
}

impl WsReader {
    async fn next_msg(&mut self) -> Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> {
        match self {
            WsReader::Plain(s) => s.next().await,
            WsReader::Secure(s) => s.next().await,
        }
    }
}

/// Process messages on an established WebSocket connection
async fn process_ws_messages(
    ws_stream: WsStream,
    peer_addr: SocketAddr,
    transport: rsip::Transport,
    message_tx: mpsc::UnboundedSender<ReceivedMessage>,
) -> Result<()> {
    // Create a reply channel: SIP responses queued here are sent back over this WebSocket connection
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Split the WebSocket into independent reader and writer halves (no shared lock needed)
    let (mut sink, mut reader) = match ws_stream {
        WsStream::Plain(s) => {
            let (sink, reader) = s.split();
            (WsSink::Plain(sink), WsReader::Plain(reader))
        }
        WsStream::Secure(s) => {
            let (sink, reader) = s.split();
            (WsSink::Secure(sink), WsReader::Secure(reader))
        }
    };

    // Channel to forward pings to the writer task
    let (ping_tx, mut ping_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let peer_str = peer_addr.to_string();

    // Spawn a writer task: drains reply_rx (SIP responses) and ping_rx (pong replies)
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // SIP response to send back
                Some(data) = reply_rx.recv() => {
                    let text = match String::from_utf8(data) {
                        Ok(s) => s,
                        Err(e) => { warn!("WS reply: non-UTF8 data: {}", e); continue; }
                    };
                    if let Err(e) = sink.send_text(text).await {
                        debug!("WS write error to {}: {}", peer_str, e);
                        break;
                    }
                }
                // Pong reply
                Some(data) = ping_rx.recv() => {
                    if let Err(e) = sink.send_pong(data).await {
                        debug!("WS pong error to {}: {}", peer_str, e);
                        break;
                    }
                }
                else => break,
            }
        }
    });

    // Reader loop: receive SIP messages from the WebSocket and forward to the SBC pipeline
    loop {
        match reader.next_msg().await {
            Some(Ok(Message::Text(text))) => {
                // SIP message as text (RFC 7118 §7.2)
                debug!("WS SIP message from {}: {} bytes", peer_addr, text.len());
                match parse_and_forward(&text, peer_addr, transport, &message_tx, reply_tx.clone()) {
                    Ok(_) => {},
                    Err(e) => warn!("Failed to parse WS SIP message: {}", e),
                }
            }
            Some(Ok(Message::Binary(data))) => {
                // SIP message as binary (uncommon but valid per RFC 7118)
                let text = String::from_utf8_lossy(&data);
                match parse_and_forward(&text, peer_addr, transport, &message_tx, reply_tx.clone()) {
                    Ok(_) => {},
                    Err(e) => warn!("Failed to parse WS binary SIP message: {}", e),
                }
            }
            Some(Ok(Message::Ping(data))) => {
                // Forward ping to writer task for pong response
                let _ = ping_tx.send(data);
            }
            Some(Ok(Message::Close(_))) | None => {
                info!("WebSocket connection closed from {}", peer_addr);
                break;
            }
            Some(Err(e)) => {
                warn!("WebSocket error from {}: {}", peer_addr, e);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Parse a SIP message and send it to the processing channel, with a reply channel
fn parse_and_forward(
    text: &str,
    source: SocketAddr,
    transport: rsip::Transport,
    tx: &mpsc::UnboundedSender<ReceivedMessage>,
    reply_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> Result<()> {
    let message = rsip::SipMessage::try_from(text)
        .map_err(|e| Error::Transport(format!("Failed to parse SIP over WS: {}", e)))?;

    tx.send(ReceivedMessage {
        message,
        source,
        transport,
        reply_tx: Some(reply_tx),
    })
    .map_err(|_| Error::Transport("Message channel closed".to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_ws_listener_creation() {
        // Bind on random port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = WsListenerServer::new_ws(addr).await.unwrap();
        assert!(!listener.is_secure());
        assert_eq!(listener.local_addr().ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn test_ws_listener_port_allocated() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = WsListenerServer::new_ws(addr).await.unwrap();
        // Should have a non-zero port
        assert!(listener.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn test_parse_and_forward_valid_options() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (reply_tx, _reply_rx) = mpsc::unbounded_channel();
        let sip = "OPTIONS sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/WS 127.0.0.1:5060;branch=z9hG4bKtest\r\nMax-Forwards: 70\r\nTo: <sip:127.0.0.1>\r\nFrom: <sip:test@127.0.0.1>;tag=abc\r\nCall-ID: test-ws-001@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let source: SocketAddr = "127.0.0.1:55000".parse().unwrap();

        parse_and_forward(sip, source, rsip::Transport::Ws, &tx, reply_tx).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.source, source);
        assert_eq!(received.transport, rsip::Transport::Ws);
        assert!(received.reply_tx.is_some());
    }

    #[tokio::test]
    async fn test_parse_and_forward_invalid_sip() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (reply_tx, _reply_rx) = mpsc::unbounded_channel();
        let bad_sip = "NOT A VALID SIP MESSAGE";
        let source: SocketAddr = "127.0.0.1:55001".parse().unwrap();

        let result = parse_and_forward(bad_sip, source, rsip::Transport::Ws, &tx, reply_tx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ws_listener_not_secure() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ws = WsListenerServer::new_ws(addr).await.unwrap();
        assert!(!ws.is_secure());
    }

    #[tokio::test]
    async fn test_wss_needs_cert_files() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Non-existent cert files should fail
        let result = WsListenerServer::new_wss(
            addr,
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        ).await;
        assert!(result.is_err());
    }
}
