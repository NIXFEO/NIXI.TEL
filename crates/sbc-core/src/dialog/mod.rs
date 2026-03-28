//! Dialog Management (RFC 3261 Section 12)
//!
//! Implements SIP dialog tracking for established sessions

pub mod dialog;
pub mod manager;

// Re-export main types
pub use dialog::{Dialog, DialogId, DialogState};
pub use manager::{DialogManager, DialogStats};
