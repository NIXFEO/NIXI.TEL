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

pub mod transport;
pub mod routing;
pub mod config;
pub mod error;
pub mod maintenance;
pub mod sbc;
pub mod media;
pub mod b2bua;
pub mod auth;
pub mod metrics;
pub mod events;
pub mod storage;
pub mod dos;

// Phase 7 modules
pub mod transcoding;
pub mod topology;
pub mod register;
pub mod sip_builder;
pub mod security;
pub mod acl;

pub mod trunk_register;

pub use error::{Error, Result};
pub use sbc::Sbc;
