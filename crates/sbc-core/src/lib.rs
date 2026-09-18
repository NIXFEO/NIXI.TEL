//! SBC Core - Transport, B2BUA call control, Media and Routing
//!
//! This crate provides the core SBC functionality including:
//! - Transport layer (UDP, TCP, TLS, WebSocket)
//! - B2BUA call control (per-attempt INVITE bookkeeping, failover, session timers)
//! - Call routing between trunks
//! - Background maintenance (bounded in-memory tables)
//! - Integrated SBC instance
//! - Media relay (RTP/RTCP proxy, SDP manipulation)
//! - Audio transcoding (Opus ↔ G.711 PCMU/PCMA)
//! - Topology hiding (Via/Contact/Record-Route rewriting)
//! - REGISTER handling (in-memory registrar)
//! - Outbound TLS/mTLS toward trunks
//! - Dynamic ACL (IP access control lists)

pub mod auth;
pub mod b2bua;
pub mod config;
pub mod dos;
pub mod error;
pub mod events;
pub mod maintenance;
pub mod media;
pub mod metrics;
pub mod routing;
pub mod sbc;
pub mod storage;
pub mod transport;

// Phase 7 modules
pub mod acl;
pub mod register;
pub mod security;
pub mod sip_builder;
pub mod topology;
pub mod transcoding;

pub mod trunk_register;
pub mod trunk_tasks;

pub use error::{Error, Result};
/// SIP parser used throughout the public API (`rsip::Transport`, requests, responses).
pub use rsip;
pub use sbc::Sbc;
