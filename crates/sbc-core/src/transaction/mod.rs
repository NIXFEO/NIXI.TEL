//! Transaction Layer (RFC 3261 Section 17)
//!
//! Implements SIP transaction layer with state machines, timers, and transaction management

pub mod manager;
pub mod state_machine;
pub mod timers;

// Re-export commonly used types
pub use manager::{TransactionManager, TransactionStats};
pub use state_machine::{
    ClientTransaction, ClientTransactionState, ServerTransaction, ServerTransactionState,
    TransactionEvent, TransactionId, TransactionType,
};
pub use timers::{RetransmitScheduler, SipTimers};
