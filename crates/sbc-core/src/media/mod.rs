//! Media Layer - RTP/RTCP Proxy and SDP Manipulation
//!
//! Phase 3 implementation for media relay
//! Phase 4 implementation for SRTP (Secure RTP), STUN, and ICE (NAT traversal)

pub mod sdp;
pub mod port_allocator;
pub mod rtp;
pub mod manager;
pub mod srtp;
pub mod srtp_crypto;
pub mod stun;
pub mod ice;
pub mod dtls;
// TURN relay is intentionally NOT implemented in the SBC: it runs on a
// public IP and never needs TURN itself; browsers behind hostile NAT should
// use an external TURN server (coturn) configured client-side. See docs/WEBRTC.md.
#[cfg(feature = "turn")]
pub mod turn;
pub mod webrtc_handler;
// WebRTC DataChannel (SCTP/DCEP) is out of scope for the audio SBC.
#[cfg(feature = "data-channel")]
pub mod data_channel;

// Re-export main types
pub use sdp::{SessionDescription, MediaDescription, MediaType, Connection, Origin, Attribute};
pub use port_allocator::{PortAllocator, PortPair};
pub use rtp::{RtpPacket, RtpSession, RtpSessionStats};
pub use manager::{MediaManager, MediaSession, MediaStats, WebRtcRtpInfo, WebRtcRtpInfoB};
pub use srtp::{CryptoSuite, SrtpContext, generate_key_material, parse_crypto_attribute};
pub use srtp_crypto::{SrtpCrypto, SrtcpCrypto, derive_srtp_keys, derive_srtcp_keys};
pub use stun::{StunClient, StunMessage, StunMessageType};
pub use ice::{IceAgent, IceCandidate, CandidateType, CandidatePair, IceStats};
pub use dtls::{DtlsContext, DtlsManager, CertificateFingerprint, DtlsRole, DtlsSrtpKeys};
#[cfg(feature = "turn")]
pub use turn::{TurnClient, TurnAllocation, TurnStats, TurnMessageType};
pub use webrtc_handler::{WebRtcSdpInfo, WebRtcSession};
#[cfg(feature = "data-channel")]
pub use data_channel::{DataChannelManager, DataChannel, DataChannelMessage, DataChannelStats};
