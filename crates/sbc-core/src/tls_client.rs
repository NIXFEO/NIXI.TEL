//! TLS Client — Outbound TLS connections for SIP trunks (RFC 5246 / RFC 5630)
//!
//! This module provides:
//!   - [`TlsClientConfig`]  — per-trunk TLS settings
//!   - [`TlsClient`]        — manages outbound TLS connections
//!   - [`TlsConnection`]    — a single TLS-over-TCP connection to a trunk
//!   - Connection pooling   — reuses established connections when possible
//!   - Mutual TLS (mTLS)    — optional client certificate authentication
//!
//! # Transport flows
//! ```text
//!   SBC → (TLS/TCP) → SIP trunk
//!         ^^^^^^
//!         Port 5061 (default SIP TLS)
//! ```

use crate::{Error, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// TLS configuration
// ─────────────────────────────────────────────────────────────────────────────

/// TLS version policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 and above (recommended)
    Tls12Plus,
    /// TLS 1.3 only
    Tls13Only,
}

impl Default for TlsVersion {
    fn default() -> Self { Self::Tls12Plus }
}

/// Certificate verification policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertVerification {
    /// Verify server certificate (recommended for production)
    Verify,
    /// Skip verification (for self-signed certs in lab environments)
    SkipVerify,
}

impl Default for CertVerification {
    fn default() -> Self { Self::Verify }
}

/// TLS configuration for outbound trunk connections
#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    /// Remote address (host:port)
    pub remote_addr: String,
    /// SNI hostname (used for TLS handshake and cert verification)
    pub sni_hostname: String,
    /// TLS version policy
    pub tls_version: TlsVersion,
    /// Certificate verification
    pub cert_verification: CertVerification,
    /// Path to CA certificate(s) for verification (PEM)
    pub ca_cert_path: Option<String>,
    /// Path to client certificate (PEM) for mutual TLS
    pub client_cert_path: Option<String>,
    /// Path to client private key (PEM) for mutual TLS
    pub client_key_path: Option<String>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keepalive interval (SIP OPTIONS sent as PING)
    pub keepalive_interval: Duration,
    /// Maximum idle time before closing connection
    pub idle_timeout: Duration,
}

impl TlsClientConfig {
    /// Create a basic TLS client config for a SIP trunk
    pub fn new(remote_addr: &str, sni_hostname: &str) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            sni_hostname: sni_hostname.to_string(),
            tls_version: TlsVersion::Tls12Plus,
            cert_verification: CertVerification::Verify,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Create config with verification disabled (lab/testing use only)
    pub fn insecure(remote_addr: &str, sni_hostname: &str) -> Self {
        let mut cfg = Self::new(remote_addr, sni_hostname);
        cfg.cert_verification = CertVerification::SkipVerify;
        cfg
    }

    /// Enable mutual TLS (client presents a certificate)
    pub fn with_client_cert(mut self, cert_path: &str, key_path: &str) -> Self {
        self.client_cert_path = Some(cert_path.to_string());
        self.client_key_path  = Some(key_path.to_string());
        self
    }

    /// Use a custom CA for verification
    pub fn with_ca_cert(mut self, ca_path: &str) -> Self {
        self.ca_cert_path = Some(ca_path.to_string());
        self
    }

    /// Is mutual TLS configured?
    pub fn is_mtls(&self) -> bool {
        self.client_cert_path.is_some() && self.client_key_path.is_some()
    }

    /// Parse remote address as SocketAddr
    pub fn remote_socket_addr(&self) -> Result<SocketAddr> {
        self.remote_addr.parse::<SocketAddr>().map_err(|e| {
            Error::Transport(format!("invalid remote address '{}': {}", self.remote_addr, e))
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection state
// ─────────────────────────────────────────────────────────────────────────────

/// State of a TLS connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connecting in progress
    Connecting,
    /// TLS handshake in progress
    TlsHandshake,
    /// Connected and ready for SIP
    Ready,
    /// Connection failed or closed
    Closed,
    /// In keepalive state (waiting for OPTIONS response)
    Keepalive,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connecting    => "connecting",
            Self::TlsHandshake  => "tls_handshake",
            Self::Ready         => "ready",
            Self::Closed        => "closed",
            Self::Keepalive     => "keepalive",
        }
    }
}

/// Statistics for a single connection
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub remote_addr: String,
    pub sni_hostname: String,
    pub state: &'static str,
    pub connected_at: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub last_activity: Instant,
    pub tls_version: &'static str,
    pub cipher_suite: String,
}

/// A managed TLS connection to a SIP trunk
pub struct TlsConnection {
    pub id: String,
    pub config: TlsClientConfig,
    pub state: Arc<Mutex<ConnectionState>>,
    pub stats: Arc<Mutex<ConnectionStats>>,
}

impl TlsConnection {
    fn new_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!("tlsconn-{:08x}", t)
    }

    pub fn new(config: TlsClientConfig) -> Self {
        let id = Self::new_id();
        let stats = ConnectionStats {
            remote_addr: config.remote_addr.clone(),
            sni_hostname: config.sni_hostname.clone(),
            state: "connecting",
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            last_activity: Instant::now(),
            tls_version: "TLS1.2",
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
        };

        Self {
            id,
            config,
            state: Arc::new(Mutex::new(ConnectionState::Connecting)),
            stats: Arc::new(Mutex::new(stats)),
        }
    }

    /// Simulate establishing a TLS connection (in production: tokio-rustls)
    pub async fn connect(&self) -> Result<()> {
        let remote = self.config.remote_socket_addr()?;

        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::TlsHandshake;
        }

        debug!(
            "TLS: connecting to {} (SNI: {}, verify: {:?}, mtls: {})",
            remote, self.config.sni_hostname,
            self.config.cert_verification,
            self.config.is_mtls()
        );

        // In production: tokio::net::TcpStream::connect + TlsConnector::connect
        // Here we simulate the connection setup

        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::Ready;
        }
        {
            let mut stats = self.stats.lock().await;
            stats.connected_at = Some(Instant::now());
            stats.state = "ready";
            stats.last_activity = Instant::now();
        }

        info!(
            "TLS: connected to {} (conn-id: {})",
            self.config.remote_addr, self.id
        );
        Ok(())
    }

    /// Send a SIP message over the TLS connection
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let state = self.state.lock().await;
        if *state != ConnectionState::Ready {
            return Err(Error::Transport(format!(
                "TLS connection {} not ready (state: {})", self.id, state.as_str()
            )));
        }
        drop(state);

        let mut stats = self.stats.lock().await;
        stats.bytes_sent += data.len() as u64;
        stats.messages_sent += 1;
        stats.last_activity = Instant::now();

        debug!("TLS: sent {} bytes to {}", data.len(), self.config.remote_addr);
        Ok(())
    }

    /// Close the connection gracefully
    pub async fn close(&self) {
        let mut state = self.state.lock().await;
        *state = ConnectionState::Closed;
        let mut stats = self.stats.lock().await;
        stats.state = "closed";
        info!("TLS: closed connection {} to {}", self.id, self.config.remote_addr);
    }

    /// Check if connection is ready
    pub async fn is_ready(&self) -> bool {
        *self.state.lock().await == ConnectionState::Ready
    }

    /// Check if idle timeout has been exceeded
    pub async fn is_idle(&self) -> bool {
        let stats = self.stats.lock().await;
        stats.last_activity.elapsed() > self.config.idle_timeout
    }

    /// Get current stats snapshot
    pub async fn get_stats(&self) -> ConnectionStats {
        self.stats.lock().await.clone()
    }

    /// Build a SIP OPTIONS keepalive message
    pub fn build_options_keepalive(&self, local_uri: &str) -> String {
        format!(
            "OPTIONS sip:{remote} SIP/2.0\r\n\
Via: SIP/2.0/TLS {local};branch=z9hG4bKka{ts}\r\n\
From: <{local_uri}>;tag=ka{ts}\r\n\
To: <sip:{remote}>\r\n\
Call-ID: ka-{ts}@{local}\r\n\
CSeq: 1 OPTIONS\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n",
            remote = self.config.remote_addr,
            local_uri = local_uri,
            local = "sbc",
            ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS Client pool
// ─────────────────────────────────────────────────────────────────────────────

/// Pool statistics
#[derive(Debug, Clone)]
pub struct TlsPoolStats {
    pub total_connections: usize,
    pub ready_connections: usize,
    pub closed_connections: usize,
    pub total_bytes_sent: u64,
    pub total_messages_sent: u64,
}

/// TLS client connection pool
///
/// Manages multiple TLS connections to SIP trunks.
/// Each trunk (identified by remote address) can have one connection.
pub struct TlsClientPool {
    /// Active connections keyed by remote address
    connections: Arc<RwLock<HashMap<String, Arc<TlsConnection>>>>,
}

impl TlsClientPool {
    pub fn new() -> Self {
        Self { connections: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Get or create a connection to the given remote address
    pub async fn get_or_connect(&self, config: TlsClientConfig) -> Result<Arc<TlsConnection>> {
        let key = config.remote_addr.clone();

        // Check for existing ready connection
        {
            let conns = self.connections.read().await;
            if let Some(conn) = conns.get(&key) {
                if conn.is_ready().await && !conn.is_idle().await {
                    debug!("TLS: reusing existing connection to {}", key);
                    return Ok(Arc::clone(conn));
                }
            }
        }

        // Create new connection
        let conn = Arc::new(TlsConnection::new(config));
        conn.connect().await?;

        {
            let mut conns = self.connections.write().await;
            conns.insert(key.clone(), Arc::clone(&conn));
        }

        Ok(conn)
    }

    /// Remove a closed or idle connection
    pub async fn remove(&self, remote_addr: &str) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(remote_addr) {
            conn.close().await;
        }
    }

    /// Clean up idle and closed connections
    pub async fn cleanup(&self) -> u32 {
        let mut to_remove = Vec::new();
        {
            let conns = self.connections.read().await;
            for (key, conn) in conns.iter() {
                if !conn.is_ready().await || conn.is_idle().await {
                    to_remove.push(key.clone());
                }
            }
        }
        let count = to_remove.len() as u32;
        for key in to_remove {
            self.remove(&key).await;
        }
        if count > 0 {
            info!("TLS: cleaned up {} idle/closed connections", count);
        }
        count
    }

    /// Get pool statistics
    pub async fn stats(&self) -> TlsPoolStats {
        let conns = self.connections.read().await;
        let mut ready = 0;
        let mut closed = 0;
        let mut bytes = 0u64;
        let mut msgs = 0u64;

        for conn in conns.values() {
            let s = conn.get_stats().await;
            if s.state == "ready" { ready += 1; }
            if s.state == "closed" { closed += 1; }
            bytes += s.bytes_sent;
            msgs  += s.messages_sent;
        }

        TlsPoolStats {
            total_connections: conns.len(),
            ready_connections: ready,
            closed_connections: closed,
            total_bytes_sent: bytes,
            total_messages_sent: msgs,
        }
    }

    /// Send a SIP message to a specific trunk
    pub async fn send_to(&self, remote_addr: &str, data: &[u8]) -> Result<()> {
        let conns = self.connections.read().await;
        let conn = conns.get(remote_addr).ok_or_else(|| {
            Error::Transport(format!("no TLS connection to {}", remote_addr))
        })?;
        conn.send(data).await
    }

    /// Number of active connections
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}

impl Default for TlsClientPool {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(addr: &str) -> TlsClientConfig {
        TlsClientConfig::insecure(addr, "sip.example.com")
    }

    // ── TlsClientConfig ───────────────────────────────────────────────────────

    #[test]
    fn test_config_new() {
        let cfg = TlsClientConfig::new("192.168.1.1:5061", "sip.example.com");
        assert_eq!(cfg.remote_addr, "192.168.1.1:5061");
        assert_eq!(cfg.cert_verification, CertVerification::Verify);
        assert!(!cfg.is_mtls());
    }

    #[test]
    fn test_config_insecure() {
        let cfg = TlsClientConfig::insecure("10.0.0.1:5061", "sip.example.com");
        assert_eq!(cfg.cert_verification, CertVerification::SkipVerify);
    }

    #[test]
    fn test_config_with_mtls() {
        let cfg = TlsClientConfig::new("10.0.0.1:5061", "sip.example.com")
            .with_client_cert("/etc/sbc/client.pem", "/etc/sbc/client.key");
        assert!(cfg.is_mtls());
        assert_eq!(cfg.client_cert_path.unwrap(), "/etc/sbc/client.pem");
    }

    #[test]
    fn test_config_parse_addr() {
        let cfg = TlsClientConfig::insecure("127.0.0.1:5061", "localhost");
        let addr = cfg.remote_socket_addr().unwrap();
        assert_eq!(addr.port(), 5061);
    }

    #[test]
    fn test_config_invalid_addr() {
        let cfg = TlsClientConfig::insecure("not-an-address", "localhost");
        assert!(cfg.remote_socket_addr().is_err());
    }

    // ── TlsConnection ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_connection_connect() {
        let cfg = make_config("127.0.0.1:5061");
        let conn = TlsConnection::new(cfg);
        conn.connect().await.unwrap();
        assert!(conn.is_ready().await);
    }

    #[tokio::test]
    async fn test_connection_send() {
        let cfg = make_config("127.0.0.1:5061");
        let conn = TlsConnection::new(cfg);
        conn.connect().await.unwrap();

        let data = b"OPTIONS sip:test@example.com SIP/2.0\r\n\r\n";
        conn.send(data).await.unwrap();

        let stats = conn.get_stats().await;
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.bytes_sent, data.len() as u64);
    }

    #[tokio::test]
    async fn test_connection_send_when_not_ready() {
        let cfg = make_config("127.0.0.1:5061");
        let conn = TlsConnection::new(cfg);
        // Do NOT call connect()
        let result = conn.send(b"test").await;
        assert!(result.is_err(), "should fail when not connected");
    }

    #[tokio::test]
    async fn test_connection_close() {
        let cfg = make_config("127.0.0.1:5061");
        let conn = TlsConnection::new(cfg);
        conn.connect().await.unwrap();
        assert!(conn.is_ready().await);
        conn.close().await;
        assert!(!conn.is_ready().await);
    }

    #[tokio::test]
    async fn test_options_keepalive_format() {
        let cfg = make_config("192.168.1.10:5061");
        let conn = TlsConnection::new(cfg);
        let opts = conn.build_options_keepalive("sip:sbc@203.0.113.1");
        assert!(opts.starts_with("OPTIONS sip:192.168.1.10:5061 SIP/2.0"));
        assert!(opts.contains("CSeq: 1 OPTIONS"));
        assert!(opts.contains("Content-Length: 0"));
    }

    // ── TlsClientPool ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pool_connect_and_get() {
        let pool = TlsClientPool::new();
        let cfg = make_config("127.0.0.1:5061");
        let conn = pool.get_or_connect(cfg).await.unwrap();
        assert!(conn.is_ready().await);
        assert_eq!(pool.connection_count().await, 1);
    }

    #[tokio::test]
    async fn test_pool_reuses_connection() {
        let pool = TlsClientPool::new();
        let cfg1 = make_config("127.0.0.1:5061");
        let cfg2 = make_config("127.0.0.1:5061");

        let conn1 = pool.get_or_connect(cfg1).await.unwrap();
        let conn2 = pool.get_or_connect(cfg2).await.unwrap();

        // Same ID → reused
        assert_eq!(conn1.id, conn2.id, "should reuse same connection");
        assert_eq!(pool.connection_count().await, 1);
    }

    #[tokio::test]
    async fn test_pool_multiple_remotes() {
        let pool = TlsClientPool::new();
        pool.get_or_connect(make_config("127.0.0.1:5061")).await.unwrap();
        pool.get_or_connect(make_config("127.0.0.2:5061")).await.unwrap();
        assert_eq!(pool.connection_count().await, 2);
    }

    #[tokio::test]
    async fn test_pool_send_to() {
        let pool = TlsClientPool::new();
        pool.get_or_connect(make_config("127.0.0.1:5061")).await.unwrap();
        let result = pool.send_to("127.0.0.1:5061", b"SIP/2.0 200 OK\r\n\r\n").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pool_send_to_unknown() {
        let pool = TlsClientPool::new();
        let result = pool.send_to("10.0.0.99:5061", b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let pool = TlsClientPool::new();
        pool.get_or_connect(make_config("127.0.0.1:5061")).await.unwrap();
        pool.get_or_connect(make_config("127.0.0.2:5061")).await.unwrap();

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.ready_connections, 2);
    }

    #[tokio::test]
    async fn test_pool_remove() {
        let pool = TlsClientPool::new();
        pool.get_or_connect(make_config("127.0.0.1:5061")).await.unwrap();
        assert_eq!(pool.connection_count().await, 1);
        pool.remove("127.0.0.1:5061").await;
        assert_eq!(pool.connection_count().await, 0);
    }

    // ── Connection state transitions ──────────────────────────────────────────

    #[test]
    fn test_connection_state_as_str() {
        assert_eq!(ConnectionState::Ready.as_str(), "ready");
        assert_eq!(ConnectionState::Closed.as_str(), "closed");
        assert_eq!(ConnectionState::TlsHandshake.as_str(), "tls_handshake");
    }
}
