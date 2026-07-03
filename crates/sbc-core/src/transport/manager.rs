//! Transport Manager
//!
//! Manages all transport listeners (UDP, TCP, TLS) and routes incoming messages.

use crate::config::{ListenerConfig, NetworkConfig, TransportType};
use crate::transport::tcp::{TcpConnection, TcpListenerServer};
use crate::transport::tls::TlsListenerServer;
use crate::transport::udp::{ReceivedMessage, UdpListener};
use crate::transport::ws::WsListenerServer;
use crate::{Error, Result};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Transport manager that handles all listeners
/// Out-of-band transport events (drained from the SBC event loop tick).
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A connection-oriented transport (WS/WSS) closed.
    ConnectionClosed {
        peer: std::net::SocketAddr,
        transport: rsip::Transport,
    },
}

pub struct TransportManager {
    /// UDP listeners
    udp_listeners: Vec<Arc<UdpListener>>,

    /// TCP connection pool
    tcp_connections: Arc<DashMap<SocketAddr, Arc<TcpConnection>>>,

    /// Channel for receiving messages from all listeners
    message_rx: mpsc::UnboundedReceiver<ReceivedMessage>,
    message_tx: mpsc::UnboundedSender<ReceivedMessage>,

    event_rx: mpsc::UnboundedReceiver<TransportEvent>,
    event_tx: mpsc::UnboundedSender<TransportEvent>,

    /// Outbound TLS: per-destination parameters (registered from trunk
    /// config) and established connections.
    tls_params: Arc<dashmap::DashMap<SocketAddr, crate::transport::tls_connect::TlsClientParams>>,
    tls_connections: Arc<dashmap::DashMap<SocketAddr, Arc<crate::transport::tls_connect::TlsClientConnection>>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            udp_listeners: Vec::new(),
            tcp_connections: Arc::new(DashMap::new()),
            message_rx,
            message_tx,
            event_rx,
            event_tx,
            tls_params: Arc::new(dashmap::DashMap::new()),
            tls_connections: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Start all listeners defined in config
    pub async fn start_listeners(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Starting transport listeners...");

        for listener_config in &config.listeners {
            match listener_config.transport {
                TransportType::UDP => {
                    self.start_udp_listener(listener_config).await?;
                }
                TransportType::TCP => {
                    self.start_tcp_listener(listener_config).await?;
                }
                TransportType::TLS => {
                    self.start_tls_listener(listener_config).await?;
                }
                TransportType::WS => {
                    self.start_ws_listener(listener_config, false).await?;
                }
                TransportType::WSS => {
                    self.start_ws_listener(listener_config, true).await?;
                }
            }
        }

        info!("All transport listeners started successfully");
        Ok(())
    }

    /// Start a UDP listener
    async fn start_udp_listener(&mut self, config: &ListenerConfig) -> Result<()> {
        let bind_addr = SocketAddr::new(config.bind_address, config.bind_port);
        let listener = Arc::new(UdpListener::new(bind_addr).await?);
        let local_addr = listener.local_addr();

        info!("Started UDP listener on {}", local_addr);

        // Store the listener
        self.udp_listeners.push(listener.clone());

        // Start listening in background
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.listen(tx).await {
                error!("UDP listener error: {}", e);
            }
        });

        Ok(())
    }

    /// Start a TCP listener
    async fn start_tcp_listener(&mut self, config: &ListenerConfig) -> Result<()> {
        let bind_addr = SocketAddr::new(config.bind_address, config.bind_port);
        let listener = TcpListenerServer::new(bind_addr).await?;

        info!("Started TCP listener on {}", listener.local_addr());

        // Start listening in background
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.listen(tx).await {
                error!("TCP listener error: {}", e);
            }
        });

        Ok(())
    }

    /// Start a WebSocket (WS or WSS) listener
    async fn start_ws_listener(&mut self, config: &ListenerConfig, secure: bool) -> Result<()> {
        let bind_addr = SocketAddr::new(config.bind_address, config.bind_port);

        let listener = if secure {
            let cert_file = config.cert_file.as_ref().ok_or_else(|| {
                Error::Config("WSS listener requires cert_file".to_string())
            })?;
            let key_file = config.key_file.as_ref().ok_or_else(|| {
                Error::Config("WSS listener requires key_file".to_string())
            })?;
            WsListenerServer::new_wss(bind_addr, cert_file, key_file).await?
        } else {
            WsListenerServer::new_ws(bind_addr).await?
        };

        let proto = if secure { "WSS" } else { "WS" };
        info!("Started {} listener on {}", proto, listener.local_addr());

        let tx = self.message_tx.clone();
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.listen(tx, event_tx).await {
                error!("{} listener error: {}", proto, e);
            }
        });

        Ok(())
    }

    /// Start a TLS listener
    async fn start_tls_listener(&mut self, config: &ListenerConfig) -> Result<()> {
        let cert_file = config.cert_file.as_ref().ok_or_else(|| {
            Error::Config("TLS listener requires cert_file".to_string())
        })?;

        let key_file = config.key_file.as_ref().ok_or_else(|| {
            Error::Config("TLS listener requires key_file".to_string())
        })?;

        let bind_addr = SocketAddr::new(config.bind_address, config.bind_port);
        let listener = TlsListenerServer::new(bind_addr, cert_file, key_file).await?;

        info!("Started TLS listener on {}", listener.local_addr());

        // Start listening in background
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.listen(tx).await {
                error!("TLS listener error: {}", e);
            }
        });

        Ok(())
    }

    /// Receive the next message from any transport
    pub async fn recv_message(&mut self) -> Option<ReceivedMessage> {
        self.message_rx.recv().await
    }

    /// Drain pending transport events (non-blocking). Called from the SBC
    /// event-loop tick — WS disconnect cleanup tolerates up to 1s latency.
    pub fn drain_events(&mut self) -> Vec<TransportEvent> {
        let mut events = Vec::new();
        while let Ok(ev) = self.event_rx.try_recv() {
            events.push(ev);
        }
        events
    }

    /// Send a message via UDP
    pub async fn send_udp(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        // Use first UDP listener
        if let Some(listener) = self.udp_listeners.first() {
            listener.send_to(data, dest).await
        } else {
            Err(Error::Transport("No UDP listener available".to_string()))
        }
    }

    /// Register TLS parameters for an outbound destination (trunk load).
    pub fn register_tls_destination(
        &self,
        dest: SocketAddr,
        params: crate::transport::tls_connect::TlsClientParams,
    ) {
        self.tls_params.insert(dest, params);
    }

    /// Send a message via TLS. NEVER falls back to plaintext: a destination
    /// without registered TLS parameters is an error.
    pub async fn send_tls(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        // Reuse a live connection
        if let Some(conn) = self.tls_connections.get(&dest) {
            if !conn.is_closed() {
                return conn.send(data);
            }
            drop(conn);
            self.tls_connections.remove(&dest);
        }

        let params = self
            .tls_params
            .get(&dest)
            .map(|p| p.clone())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "no TLS parameters registered for {} — refusing plaintext fallback",
                    dest
                ))
            })?;

        let conn = crate::transport::tls_connect::TlsClientConnection::connect(
            dest,
            &params,
            self.message_tx.clone(),
        )
        .await?;
        self.tls_connections.insert(dest, conn.clone());
        conn.send(data)
    }

    /// Send a message via TCP
    pub async fn send_tcp(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        // Get or create TCP connection
        let conn = if let Some(existing) = self.tcp_connections.get(&dest) {
            existing.clone()
        } else {
            // Create new connection
            let new_conn = Arc::new(TcpConnection::connect(dest).await?);
            self.tcp_connections.insert(dest, new_conn.clone());
            new_conn
        };

        conn.send(data).await
    }

    /// Send a message to the specified destination.
    /// Automatically selects the appropriate transport.
    pub async fn send(
        &self,
        data: &[u8],
        dest: SocketAddr,
        transport: rsip::Transport,
    ) -> Result<()> {
        match transport {
            rsip::Transport::Udp => self.send_udp(data, dest).await,
            rsip::Transport::Tcp => self.send_tcp(data, dest).await,
            rsip::Transport::Tls => self.send_tls(data, dest).await,
            _ => Err(Error::Transport(format!(
                "Unsupported transport: {:?}",
                transport
            ))),
        }
    }

    /// Reply to an inbound message using its existing connection when possible.
    /// For TCP/TLS, uses the `reply_tx` channel from the ReceivedMessage.
    /// For UDP, falls back to `send_udp`.
    pub async fn reply(
        &self,
        data: &[u8],
        dest: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&mpsc::UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        // For connection-oriented transports, reply on the existing connection
        if let Some(tx) = reply_tx {
            match tx.send(data.to_vec()) {
                Ok(()) => {
                    // Log first few lines of what we sent for diagnostics
                    if let Ok(text) = std::str::from_utf8(data) {
                        let preview: String = text.lines().take(6).collect::<Vec<_>>().join(" | ");
                        tracing::info!("Transport reply via existing channel to {}: {}", dest, preview);
                    }
                    return Ok(());
                }
                Err(_) => {
                    tracing::warn!("Reply channel closed for {}, falling back to new connection", dest);
                    // Fall through to open new connection
                }
            }
        }
        // Fallback: open new connection or send UDP
        tracing::info!("Transport send (new conn) to {} via {:?}", dest, transport);
        self.send(data, dest, transport).await
    }

    /// Get the first UDP socket (for sending outbound REGISTER from port 5060).
    /// Returns None if no UDP listener is configured.
    pub fn udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_listeners.first().map(|l| l.socket())
    }

    /// Get statistics about active connections
    pub fn stats(&self) -> TransportStats {
        TransportStats {
            udp_listeners: self.udp_listeners.len(),
            tcp_connections: self.tcp_connections.len(),
        }
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Transport statistics
#[derive(Debug, Clone)]
pub struct TransportStats {
    pub udp_listeners: usize,
    pub tcp_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenerConfig, NetworkConfig, TransportType};

    #[tokio::test]
    async fn test_transport_manager_creation() {
        let manager = TransportManager::new();
        let stats = manager.stats();
        assert_eq!(stats.udp_listeners, 0);
        assert_eq!(stats.tcp_connections, 0);
    }

    #[tokio::test]
    async fn test_start_udp_listener() {
        let mut manager = TransportManager::new();
        let config = NetworkConfig {
            listeners: vec![ListenerConfig {
                transport: TransportType::UDP,
                bind_address: "127.0.0.1".parse().unwrap(),
                bind_port: 0, // Random port
                cert_file: None,
                key_file: None,
            }],
            public_ipv4: None,
            public_ipv6: None,
        };

        manager.start_listeners(&config).await.unwrap();
        assert_eq!(manager.stats().udp_listeners, 1);
    }
}
