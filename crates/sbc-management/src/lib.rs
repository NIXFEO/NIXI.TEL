//! SBC Management - REST API and Metrics
//!
//! This crate provides management and observability:
//! - REST API (axum) for users, DIDs, trunks, routes, ACL, security and calls
//! - Prometheus metrics export
//! - Event logging and monitoring

pub mod error;
pub mod metrics;
pub mod rate_limit;
pub mod routes;
pub mod server;
pub mod state;

pub use error::{Error, Result};
