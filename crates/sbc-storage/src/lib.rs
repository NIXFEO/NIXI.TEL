//! SBC Storage - Database and Persistence
//!
//! This crate handles data persistence:
//! - PostgreSQL for sessions, trunks, CDR
//! - Redis for caching and real-time data
//! - Database models and repositories

pub mod models;
pub mod repositories;
pub mod error;

pub use error::{Error, Result};
