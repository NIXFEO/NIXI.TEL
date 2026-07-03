//! SBC Storage — embedded SQLite persistence for dynamic configuration.
//!
//! `ConfigStore` is the source of truth for API-managed config: SIP users,
//! DIDs, trunks, routes, ACL rules, and security bans. Static config
//! (network listeners, media, logging) stays in the TOML file; its dynamic
//! entries are imported into the store on first boot.

pub mod error;
pub mod models;
pub mod store;

pub use error::{Error, Result};
pub use models::{AclRuleRow, BanRow, DidRow, RouteRow, TrunkRow, UserRow};
pub use store::{ConfigStore, Table};
