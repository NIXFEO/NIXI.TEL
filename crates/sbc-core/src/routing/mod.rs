//! Routing - Trunk selection and call routing

pub mod router;
pub mod trunk;

pub use router::Router;
pub use trunk::{TransportType, TrunkConfig, TrunkId, TrunkManager};
