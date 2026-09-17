//! Transport layer - UDP, TCP, TLS, WebSocket listeners

use std::time::Duration;

/// Bound on establishing an outbound TCP/TLS connection (connect, and the
/// TLS handshake separately). The SIP event loop awaits sends inline, so an
/// unreachable peer must fail fast — into failover — instead of parking
/// every call on the box for the kernel's SYN timeout.
pub const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub mod manager;
pub mod tcp;
pub mod tls;
pub mod tls_connect;
pub mod udp;
pub mod ws;

pub use manager::{TransportManager, TransportStats};
pub use tcp::{TcpConnection, TcpListenerServer};
pub use tls::TlsListenerServer;
pub use udp::{ReceivedMessage, UdpListener};
pub use ws::WsListenerServer;
