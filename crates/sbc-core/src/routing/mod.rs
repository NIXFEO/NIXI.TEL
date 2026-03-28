//! Routing - Trunk selection and call routing

pub mod router;
pub mod trunk;

pub use trunk::{TrunkConfig, TrunkManager, TrunkId, TransportType};
pub use router::Router;
