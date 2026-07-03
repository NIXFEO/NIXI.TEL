//! SBC Management - REST API and Metrics
//!
//! This crate provides management and observability:
//! - REST API for trunk and session management
//! - Prometheus metrics export
//! - Event logging and monitoring

pub mod api;
pub mod error;
pub mod metrics;
pub mod routes;
pub mod server;
pub mod state;

pub use error::{Error, Result};
