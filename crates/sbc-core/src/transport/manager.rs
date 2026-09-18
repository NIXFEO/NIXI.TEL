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

/// TLS parameters and the client config built from them, once.
#[derive(Clone)]
struct TlsDestination {
    params: crate::transport::tls_connect::TlsClientParams,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
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

    /// Outbound TLS: per-destination parameters + prebuilt client config
    /// (registered from trunk config) and established connections.
    tls_params: Arc<dashmap::DashMap<SocketAddr, TlsDestination>>,
    tls_connections:
        Arc<dashmap::DashMap<SocketAddr, Arc<crate::transport::tls_connect::TlsClientConnection>>>,
    /// The TLS / WSS listeners' certificates (reloadable).
    tls_identities: Arc<crate::transport::tls_identity::TlsIdentityRegistry>,
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
            tls_identities: Arc::new(crate::transport::tls_identity::TlsIdentityRegistry::new()),
        }
    }

    pub fn tls_identities(&self) -> Arc<crate::transport::tls_identity::TlsIdentityRegistry> {
        self.tls_identities.clone()
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
            let cert_file = config
                .cert_file
                .as_ref()
                .ok_or_else(|| Error::Config("WSS listener requires cert_file".to_string()))?;
            let key_file = config
                .key_file
                .as_ref()
                .ok_or_else(|| Error::Config("WSS listener requires key_file".to_string()))?;
            WsListenerServer::new_wss(bind_addr, cert_file, key_file).await?
        } else {
            WsListenerServer::new_ws(bind_addr).await?
        };

        let proto = if secure { "WSS" } else { "WS" };
        info!("Started {} listener on {}", proto, listener.local_addr());
        if let Some(id) = listener.identity() {
            self.tls_identities.register(id);
        }

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
        let cert_file = config
            .cert_file
            .as_ref()
            .ok_or_else(|| Error::Config("TLS listener requires cert_file".to_string()))?;

        let key_file = config
            .key_file
            .as_ref()
            .ok_or_else(|| Error::Config("TLS listener requires key_file".to_string()))?;

        let bind_addr = SocketAddr::new(config.bind_address, config.bind_port);
        let listener = TlsListenerServer::new(bind_addr, cert_file, key_file).await?;
        info!("Started TLS listener on {}", listener.local_addr());
        self.tls_identities.register(listener.identity());

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

    /// Register TLS parameters for an outbound destination (trunk load /
    /// reload). The client config (CA bundle, system roots, mTLS identity)
    /// is built here, once, so nothing touches the filesystem when a call
    /// needs the connection. A destination whose config cannot be built is
    /// not registered: sends to it fail closed instead of at call time.
    pub fn register_tls_destination(
        &self,
        dest: SocketAddr,
        params: crate::transport::tls_connect::TlsClientParams,
    ) -> Result<()> {
        let config = crate::transport::tls_connect::build_client_config(&params)?;
        self.tls_params.insert(
            dest,
            TlsDestination {
                params,
                config: Arc::new(config),
            },
        );
        // A new config must not keep reusing a connection made with the old one
        self.tls_connections.remove(&dest);
        Ok(())
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

        let target = self
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
            &target.params,
            target.config,
            self.message_tx.clone(),
        )
        .await?;
        self.tls_connections.insert(dest, conn.clone());
        conn.send(data)
    }

    /// Send a message via TCP, reusing the pooled connection. A connection
    /// whose send fails is dropped from the pool so the next send
    /// reconnects instead of failing on a dead socket until restart.
    pub async fn send_tcp(&self, data: &[u8], dest: SocketAddr) -> Result<()> {
        // A connection the peer has closed is replaced, not written to.
        // The lookup is scoped: holding a DashMap guard across the insert
        // below would deadlock on the same shard.
        let live = {
            let entry = self.tcp_connections.get(&dest);
            match entry {
                Some(existing) if !existing.is_closed() => Some(existing.clone()),
                _ => None,
            }
        };
        let conn = match live {
            Some(existing) => existing,
            None => {
                self.tcp_connections.remove(&dest);
                let new_conn =
                    Arc::new(TcpConnection::connect(dest, self.message_tx.clone()).await?);
                self.tcp_connections.insert(dest, new_conn.clone());
                new_conn
            }
        };

        if let Err(e) = conn.send(data).await {
            self.tcp_connections.remove(&dest);
            tracing::warn!(
                "TCP send to {} failed, connection dropped from pool: {}",
                dest,
                e
            );
            return Err(e);
        }
        Ok(())
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
                        tracing::debug!(
                            "Transport reply via existing channel to {}: {}",
                            dest,
                            preview
                        );
                    }
                    return Ok(());
                }
                Err(_) => {
                    tracing::warn!(
                        "Reply channel closed for {}, falling back to new connection",
                        dest
                    );
                    // Fall through to open new connection
                }
            }
        }
        // Fallback: open new connection or send UDP
        tracing::debug!("Transport send (new conn) to {} via {:?}", dest, transport);
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

#[cfg(test)]
mod outbound_pool_tests {
    use super::*;
    use crate::transport::tls_connect::TlsClientParams;
    use tokio::net::TcpListener;

    /// A destination that stops listening must not leave a pool entry
    /// behind. The peer here accepts once and stops, so the retry's
    /// reconnect fails — which is the path this test actually covers; the
    /// write-failure eviction is covered by
    /// `a_send_failure_never_leaves_the_connection_in_the_pool` below.
    #[tokio::test]
    async fn a_destination_that_stopped_listening_leaves_no_pool_entry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            drop(sock);
        });

        let tm = TransportManager::new();
        let mut failed = false;
        for _ in 0..20 {
            match tm
                .send_tcp(
                    b"OPTIONS sip:probe SIP/2.0\r\nContent-Length: 0\r\n\r\n",
                    dest,
                )
                .await
            {
                Ok(()) => tokio::time::sleep(std::time::Duration::from_millis(30)).await,
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed, "a peer that stopped listening must fail a send");
        assert!(
            !tm.tcp_connections.contains_key(&dest),
            "no entry for a destination we cannot reach"
        );
    }

    /// The eviction inside `send_tcp`'s error branch: a send that fails
    /// on a pooled connection must take that connection out of the pool,
    /// so the next call reconnects instead of writing into a dead socket
    /// until restart.
    ///
    /// The peer accepts, reads once and drops the socket. The sends
    /// follow each other with no pause, so the reader has not yet
    /// condemned the connection and `send_tcp` takes the *reuse* path —
    /// which is the branch under test, rather than the reconnect one.
    #[tokio::test]
    async fn a_send_failure_never_leaves_the_connection_in_the_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                use tokio::io::AsyncReadExt;
                let _ = sock.read(&mut buf).await;
                // Dropped with data still unread by us: the kernel sends
                // a reset, so our next write on it fails.
                drop(sock);
            }
        });

        let tm = TransportManager::new();
        let probe = b"OPTIONS sip:probe SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        let mut saw_failure = false;
        // No sleeps: a reset arrives within a few writes on loopback.
        for _ in 0..200 {
            if tm.send_tcp(probe, dest).await.is_err() {
                assert!(
                    !tm.tcp_connections.contains_key(&dest),
                    "a failed send left its connection in the pool"
                );
                saw_failure = true;
                break;
            }
        }
        assert!(
            saw_failure,
            "a peer that resets every connection must eventually fail a send"
        );
    }

    #[test]
    fn register_tls_destination_prebuilds_the_config_and_fails_closed() {
        let tm = TransportManager::new();
        let ok_dest: SocketAddr = "203.0.113.9:5061".parse().unwrap();
        let params = TlsClientParams {
            sni: "trunk.example.invalid".to_string(),
            ca_cert: None,
            verify: false,
            client_cert: None,
            client_key: None,
        };
        tm.register_tls_destination(ok_dest, params.clone())
            .expect("system roots load");
        assert!(tm.tls_params.contains_key(&ok_dest));

        let bad_dest: SocketAddr = "203.0.113.10:5061".parse().unwrap();
        let bad = TlsClientParams {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            ..params
        };
        assert!(tm.register_tls_destination(bad_dest, bad).is_err());
        assert!(
            !tm.tls_params.contains_key(&bad_dest),
            "a destination whose config cannot be built is not registered"
        );
    }
}

#[cfg(test)]
mod tls_reload_tests {
    use super::*;
    use crate::config::{ListenerConfig, NetworkConfig, TransportType as CfgTransport};
    use crate::transport::tls_identity::test_pem::{self_signed, write_pair};

    /// The leaf certificate a TLS server presents, via a raw rustls client.
    async fn peer_leaf_der(addr: SocketAddr) -> Vec<u8> {
        let cfg = tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                crate::transport::tls_connect::danger::NoVerifier,
            ))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let stream = connector.connect(name, tcp).await.unwrap();
        stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
    }

    #[tokio::test]
    async fn tls_and_wss_listeners_serve_the_swapped_certificate_on_the_next_accept() {
        for transport in [CfgTransport::TLS, CfgTransport::WSS] {
            let (cert_a, key_a, der_a) = self_signed("a.test", 2031);
            let (c, k) = write_pair(&cert_a, &key_a);
            let mut tm = TransportManager::new();
            let config = NetworkConfig {
                listeners: vec![ListenerConfig {
                    transport,
                    bind_address: "127.0.0.1".parse().unwrap(),
                    bind_port: 0,
                    cert_file: Some(c.clone()),
                    key_file: Some(k.clone()),
                }],
                public_ipv4: None,
                public_ipv6: None,
            };
            tm.start_listeners(&config).await.unwrap();
            let registry = tm.tls_identities();
            let bound: SocketAddr = registry.statuses()[0].bind.parse().unwrap();
            assert_eq!(peer_leaf_der(bound).await, der_a, "{:?}", transport);

            let (cert_b, key_b, der_b) = self_signed("b.test", 2032);
            std::fs::write(&c, cert_b).unwrap();
            std::fs::write(&k, key_b).unwrap();
            let out = registry.reload_all().await;
            assert!(out[0].error.is_none() && out[0].changed, "{:?}", out);
            assert_eq!(
                peer_leaf_der(bound).await,
                der_b,
                "swapped for the next accept"
            );

            std::fs::write(&k, "broken").unwrap();
            let out = registry.reload_all().await;
            assert!(out[0].error.is_some());
            assert_eq!(
                peer_leaf_der(bound).await,
                der_b,
                "previous certificate kept"
            );
            let _ = std::fs::remove_dir_all(c.parent().unwrap());
        }
    }
}
