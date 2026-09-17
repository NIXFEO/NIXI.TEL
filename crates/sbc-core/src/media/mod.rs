//! Media Layer - RTP/RTCP Proxy and SDP Manipulation
//!
//! Phase 3 implementation for media relay
//! Phase 4 implementation for SRTP (Secure RTP), STUN, and ICE (NAT traversal)

pub mod dtls;
pub mod ice;
pub mod manager;
pub mod port_allocator;
pub mod rtp;
pub mod sdp;
pub mod srtp;
pub mod srtp_crypto;
pub mod stun;
// TURN relay is intentionally NOT implemented in the SBC: it runs on a
// public IP and never needs TURN itself; browsers behind hostile NAT should
// use an external TURN server (coturn) configured client-side. See
// docs/WEBRTC.md. WebRTC DataChannel (SCTP/DCEP) is out of scope for an
// audio SBC.
pub mod webrtc_handler;

// Re-export main types
pub use dtls::{CertificateFingerprint, DtlsContext, DtlsManager, DtlsRole, DtlsSrtpKeys};
pub use ice::{CandidatePair, CandidateType, IceAgent, IceCandidate, IceStats};
pub use manager::{MediaManager, MediaSession, MediaStats, WebRtcRtpInfo, WebRtcRtpInfoB};
pub use port_allocator::{PortAllocator, PortPair};
pub use rtp::{RtpPacket, RtpSession, RtpSessionStats};
pub use sdp::{Attribute, Connection, MediaDescription, MediaType, Origin, SessionDescription};
pub use srtp::{generate_key_material, parse_crypto_attribute, CryptoSuite, SrtpContext};
pub use srtp_crypto::{derive_srtcp_keys, derive_srtp_keys, SrtcpCrypto, SrtpCrypto};
pub use stun::{StunClient, StunMessage, StunMessageType};
pub use webrtc_handler::{WebRtcSdpInfo, WebRtcSession};
