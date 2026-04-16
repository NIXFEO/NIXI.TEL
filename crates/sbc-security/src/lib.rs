//! SBC Security - Authentication, Topology Hiding, DoS Protection
//!
//! This crate provides security features for the SBC:
//! - SIP Digest Authentication
//! - Topology hiding (B2BUA)
//! - DoS protection and rate limiting
//! - IP-based access control lists (ACL)

pub mod auth;
pub mod topology_hiding;
pub mod dos_protection;
pub mod firewall;
pub mod error;

pub use error::{Error, Result};
