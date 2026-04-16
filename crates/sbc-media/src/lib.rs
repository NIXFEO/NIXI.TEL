//! SBC Media - RTP, SDP, Transcoding, and WebRTC
//!
//! This crate handles all media-related functionality:
//! - RTP/RTCP proxy and relay
//! - SDP parsing and manipulation
//! - Audio transcoding (G.711, Opus, G.729)
//! - WebRTC support (SRTP, ICE, DTLS)

pub mod rtp;
pub mod sdp;
pub mod transcoding;
pub mod webrtc;
pub mod error;

pub use error::{Error, Result};
