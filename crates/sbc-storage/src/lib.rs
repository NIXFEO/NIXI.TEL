//! SBC Storage — embedded SQLite persistence for dynamic configuration.
//!
//! `ConfigStore` is the source of truth for API-managed config: SIP users,
//! DIDs, trunks, routes, ACL rules, and security bans. Static config
//! (network listeners, media, logging) stays in the TOML file; its dynamic
//! entries are imported into the store on first boot.

pub mod cdr;
pub mod error;
pub mod import;
pub mod models;
pub mod store;

pub use error::{Error, Result};
pub use import::{ImportDoc, ImportMode, ImportReport, ImportUserLimits, SectionReport};
pub use models::keys;
pub use models::{
    AclRuleRow, BackupInfo, BanRow, CdrFilter, CdrRow, DestinationRuleRow, DidRow, RouteRow,
    TrunkRow, UserRow,
};
pub use store::{newest_backup, prune_backups, ConfigStore, Table};
