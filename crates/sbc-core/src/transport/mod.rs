//! Transport layer - UDP, TCP, TLS, WebSocket listeners

use std::time::Duration;

/// Bound on establishing an outbound TCP/TLS connection (connect, and the
/// TLS handshake separately). The SIP event loop awaits sends inline, so an
/// unreachable peer must fail fast — into failover — instead of parking
/// every call on the box for the kernel's SYN timeout.
pub const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// One SIP message's end in a stream buffer (TCP and TLS both frame by
/// `Content-Length`): `(message_end, remaining_start)`, or None while the
/// message is incomplete. Bodies are binary, so framing never scans past
/// the length the headers declare.
pub(crate) fn frame_sip_message(buffer: &[u8]) -> Option<(usize, usize)> {
    let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") || lower.starts_with("l:") {
                line.split(':').nth(1)?.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let message_end = header_end + 4 + content_length;
    (buffer.len() >= message_end).then_some((message_end, message_end))
}

/// A CRLF keepalive (RFC 5626 §4.4.1), not a message to parse.
pub(crate) fn is_keepalive(raw: &[u8]) -> bool {
    raw.iter().all(|b| *b == b'\r' || *b == b'\n')
}

pub mod manager;
pub mod tcp;
pub mod tls;
pub mod tls_connect;
pub mod tls_identity;
pub mod udp;
pub mod ws;

pub use manager::{TransportManager, TransportStats};
pub use tcp::{TcpConnection, TcpListenerServer};
pub use tls::TlsListenerServer;
pub use tls_identity::{TlsIdentityRegistry, TlsListenerIdentity, TlsReloadOutcome};
pub use udp::{ReceivedMessage, UdpListener};
pub use ws::WsListenerServer;
