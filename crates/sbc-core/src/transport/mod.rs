//! Transport layer - UDP, TCP, TLS, WebSocket listeners

use std::time::Duration;

/// Bound on establishing an outbound TCP/TLS connection (connect, and the
/// TLS handshake separately). The SIP event loop awaits sends inline, so an
/// unreachable peer must fail fast — into failover — instead of parking
/// every call on the box for the kernel's SYN timeout.
pub const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Bound on one write to an outbound TCP connection. Same reasoning as
/// the connect bound above: `TransportManager::send_tcp` is awaited inline
/// in the SIP event loop, so a peer that advertises a zero receive window
/// and never drains it would park every call on the box in `write_all`.
pub const OUTBOUND_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest SIP message this SBC will frame off a stream, header
/// section and body each. A `Content-Length` above it cannot be honoured,
/// and a header section that long is a peer that will never terminate one.
pub(crate) const MAX_SIP_MESSAGE: usize = 65535;

/// What one framing attempt found at the front of a stream buffer.
///
/// Every variant either tells the caller how many bytes to consume or
/// tells it to stop, which is what makes a framing bug unable to spin the
/// reader: the old shape returned `Option<(usize, usize)>` and a crafted
/// `Content-Length` of `2^64 - 4 - header_end` wrapped the end offset to
/// zero, so the loop framed an empty message, consumed nothing and
/// re-framed it for ever at 100% of a core — on the **inbound** listener,
/// before the ban, ACL and DoS gates could see anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// A complete message occupies `..end`.
    Message { end: usize },
    /// `count` leading CR/LF bytes to discard: a stream transport drops
    /// them before the start line (RFC 3261 §7.5) and softphones send
    /// them as keepalives (RFC 5626 §4.4.1).
    Keepalive { count: usize },
    /// Not a whole message yet — read more.
    Incomplete,
    /// The stream cannot be resynchronised (an impossible
    /// `Content-Length`, a header section over the cap, non-UTF-8
    /// headers): the connection must be closed.
    Malformed(&'static str),
}

/// Frame one SIP message at the front of `buffer` (TCP and TLS both frame
/// by `Content-Length`). One implementation for the two listeners and the
/// two outbound readers, so a framing fix lands in all four.
pub(crate) fn frame_sip_message(buffer: &[u8]) -> Framing {
    let skip = buffer
        .iter()
        .take_while(|b| **b == b'\r' || **b == b'\n')
        .count();
    if skip > 0 {
        return Framing::Keepalive { count: skip };
    }
    let Some(header_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buffer.len() > MAX_SIP_MESSAGE {
            Framing::Malformed("header section over 64 KiB with no terminator")
        } else {
            Framing::Incomplete
        };
    };
    let Ok(headers) = std::str::from_utf8(&buffer[..header_end]) else {
        return Framing::Malformed("non-UTF-8 header section");
    };
    let mut content_length = 0usize;
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if !(lower.starts_with("content-length:") || lower.starts_with("l:")) {
            continue;
        }
        let Some(value) = line.split(':').nth(1) else {
            return Framing::Malformed("Content-Length without a value");
        };
        match value.trim().parse::<usize>() {
            Ok(n) => content_length = n,
            Err(_) => return Framing::Malformed("Content-Length is not a number"),
        }
        break;
    }
    if content_length > MAX_SIP_MESSAGE {
        return Framing::Malformed("Content-Length over 64 KiB");
    }
    // Checked, because both operands come from the peer.
    let Some(end) = header_end
        .checked_add(4)
        .and_then(|n| n.checked_add(content_length))
    else {
        return Framing::Malformed("Content-Length overflows the message end");
    };
    if buffer.len() >= end {
        Framing::Message { end }
    } else {
        Framing::Incomplete
    }
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

#[cfg(test)]
mod framing_tests {
    use super::*;

    fn msg(headers: &str, body: &str) -> Vec<u8> {
        format!("{}\r\n\r\n{}", headers, body).into_bytes()
    }

    #[test]
    fn a_complete_message_is_framed_body_included() {
        let m = msg("INVITE sip:b@x SIP/2.0\r\nContent-Length: 5", "Hello");
        assert_eq!(frame_sip_message(&m), Framing::Message { end: m.len() });
        // The compact form counts too.
        let m = msg("INVITE sip:b@x SIP/2.0\r\nl: 5", "Hello");
        assert_eq!(frame_sip_message(&m), Framing::Message { end: m.len() });
        // No Content-Length means no body.
        let m = msg("OPTIONS sip:b@x SIP/2.0", "");
        assert_eq!(frame_sip_message(&m), Framing::Message { end: m.len() });
    }

    #[test]
    fn two_messages_in_one_read_are_framed_one_at_a_time() {
        let first = msg("OPTIONS sip:b@x SIP/2.0\r\nContent-Length: 0", "");
        let second = msg("INVITE sip:b@x SIP/2.0\r\nContent-Length: 2", "hi");
        let mut buffer = first.clone();
        buffer.extend_from_slice(&second);
        let Framing::Message { end } = frame_sip_message(&buffer) else {
            panic!("first message")
        };
        assert_eq!(end, first.len(), "the first message only");
        assert_eq!(
            frame_sip_message(&buffer[end..]),
            Framing::Message { end: second.len() }
        );
    }

    #[test]
    fn an_incomplete_message_waits_for_more_bytes() {
        assert_eq!(frame_sip_message(b"INVITE sip"), Framing::Incomplete);
        assert_eq!(
            frame_sip_message(b"INVITE sip:b@x SIP/2.0\r\nContent-Length: 5\r\n\r\nHel"),
            Framing::Incomplete,
            "the body is short"
        );
    }

    /// RFC 3261 §7.5: a stream transport discards CR/LF before the start
    /// line, and softphones send them as keepalives (RFC 5626 §4.4.1). A
    /// framer that only recognised the four-byte form left a single
    /// `\r\n` at the front, and the next framing attempt then swallowed
    /// it together with the real message, which no parser accepts.
    #[test]
    fn leading_crlf_is_its_own_frame() {
        assert_eq!(
            frame_sip_message(b"\r\n"),
            Framing::Keepalive { count: 2 },
            "a single CRLF keepalive"
        );
        assert_eq!(
            frame_sip_message(b"\r\n\r\n"),
            Framing::Keepalive { count: 4 }
        );
        let mut buffer = b"\r\n".to_vec();
        let real = msg("OPTIONS sip:b@x SIP/2.0\r\nContent-Length: 0", "");
        buffer.extend_from_slice(&real);
        let Framing::Keepalive { count } = frame_sip_message(&buffer) else {
            panic!("the keepalive is consumed on its own")
        };
        assert_eq!(
            frame_sip_message(&buffer[count..]),
            Framing::Message { end: real.len() },
            "the message that followed it survives intact"
        );
    }

    /// The reason this enum exists. `header_end + 4 + content_length` was
    /// unchecked `usize` arithmetic on a peer-controlled value: a
    /// `Content-Length` of `2^64 - 4 - header_end` wrapped the end offset
    /// to zero, the caller framed an empty message, consumed nothing and
    /// re-framed it for ever — one unauthenticated TCP connection pinning
    /// a core, upstream of the ban, ACL and DoS gates.
    #[test]
    fn a_content_length_that_would_overflow_is_malformed_not_a_frame() {
        let headers = "SIP/2.0 200 OK\r\nP: \r\nl: 18446744073709551568";
        let m = msg(headers, "");
        match frame_sip_message(&m) {
            Framing::Malformed(_) => {}
            other => panic!("expected Malformed, got {:?}", other),
        }
        // And every other unusable length, so the caller never loops.
        for length in ["18446744073709551615", "65536", "-1", "abc", ""] {
            let m = msg(&format!("SIP/2.0 200 OK\r\nContent-Length: {}", length), "");
            match frame_sip_message(&m) {
                Framing::Malformed(_) => {}
                other => panic!("length {:?} framed as {:?}", length, other),
            }
        }
    }

    #[test]
    fn a_header_section_that_never_ends_is_malformed() {
        let flood = vec![b'A'; MAX_SIP_MESSAGE + 1];
        match frame_sip_message(&flood) {
            Framing::Malformed(_) => {}
            other => panic!("expected Malformed, got {:?}", other),
        }
        // Under the cap it is merely incomplete.
        assert_eq!(frame_sip_message(&[b'A'; 100]), Framing::Incomplete);
    }

    /// Whatever the input, a framing result either consumes bytes or ends
    /// the loop: that is the property that makes a reader unable to spin.
    #[test]
    fn every_result_consumes_bytes_or_stops() {
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\r".to_vec(),
            b"\n\n\n".to_vec(),
            b"\r\n\r\n".to_vec(),
            msg("SIP/2.0 200 OK\r\nContent-Length: 0", ""),
            msg("SIP/2.0 200 OK\r\nContent-Length: 18446744073709551568", ""),
            msg("SIP/2.0 200 OK\r\nContent-Length: 4", "ab"),
            vec![0xff, 0xfe, b'\r', b'\n', b'\r', b'\n'],
        ];
        for input in inputs {
            match frame_sip_message(&input) {
                Framing::Message { end } => assert!(end > 0, "framed 0 bytes: {:?}", input),
                Framing::Keepalive { count } => {
                    assert!(count > 0, "consumed 0 bytes: {:?}", input)
                }
                Framing::Incomplete | Framing::Malformed(_) => {}
            }
        }
    }
}
