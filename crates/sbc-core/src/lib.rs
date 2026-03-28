//! SBC Core - Transport, Transaction, Dialog, and Routing
//!
//! This crate provides the core SBC functionality including:
//! - Transport layer (UDP, TCP, TLS, WebSocket)
//! - Transaction state machines (RFC 3261 compliant)
//! - Dialog management
//! - Call routing between trunks
//! - Background maintenance tasks
//! - Integrated SBC instance
//! - Media relay (RTP/RTCP proxy, SDP manipulation)
//! - Audio transcoding (Opus ↔ G.711 PCMU/PCMA)
//! - Topology hiding (Via/Contact/Record-Route rewriting)
//! - REGISTER handling + PostgreSQL backend
//! - TLS client for outbound trunks
//! - Dynamic ACL (IP access control lists)

pub mod transport;
pub mod transaction;
pub mod dialog;
pub mod routing;
pub mod config;
pub mod error;
pub mod maintenance;
pub mod sbc;
pub mod media;
pub mod b2bua;
pub mod auth;
pub mod metrics;
pub mod api;
pub mod http_server;
pub mod storage;
pub mod dos;

// Phase 7 modules
pub mod transcoding;
pub mod topology;
pub mod register;
pub mod tls_client;
pub mod acl;

pub mod trunk_register;

pub use error::{Error, Result};
pub use sbc::Sbc;
