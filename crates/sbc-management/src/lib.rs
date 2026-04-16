//! SBC Management - REST API and Metrics
//!
//! This crate provides management and observability:
//! - REST API for trunk and session management
//! - Prometheus metrics export
//! - Event logging and monitoring

pub mod api;
pub mod metrics;
pub mod error;

pub use error::{Error, Result};
