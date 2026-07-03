//! Shared state for the axum management server.

use sbc_core::acl::AclManager;
use sbc_core::auth::DigestAuthenticator;
use sbc_core::b2bua::B2buaManager;
use sbc_core::config::DidMapping;
use sbc_core::events::EventBus;
use sbc_core::metrics::SbcMetrics;
use sbc_core::register::Registrar;
use sbc_core::routing::TrunkManager;
use sbc_core::sbc::hydrate::RuntimeHandles;
use sbc_core::storage::CdrManager;
use sbc_storage::ConfigStore;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub metrics: Arc<SbcMetrics>,
    pub b2bua: Arc<B2buaManager>,
    pub trunks: Arc<TrunkManager>,
    pub registrar: Arc<dyn Registrar>,
    pub cdr: Arc<CdrManager>,
    pub acl: Arc<AclManager>,
    pub auth: Option<Arc<DigestAuthenticator>>,
    pub dids: Arc<RwLock<Vec<DidMapping>>>,
    /// Trunk-IP whitelist shared with the SIP engine — refreshed on trunk mutations.
    pub trunk_ips: Arc<RwLock<Vec<String>>>,
    /// None when the SQLite store could not be opened (mutating config
    /// endpoints then answer 503).
    pub store: Option<Arc<ConfigStore>>,
    pub events: EventBus,
    pub reload: Arc<Notify>,
    pub realm: String,
    /// Bearer token; None disables auth (bind to localhost only!).
    pub api_token: Option<String>,
}

impl AppState {
    pub fn runtime_handles(&self) -> RuntimeHandles {
        RuntimeHandles {
            auth: self.auth.clone(),
            dids: self.dids.clone(),
            trunks: self.trunks.clone(),
            acl: self.acl.clone(),
        }
    }

    /// Rebuild the trunk-IP whitelist after trunk changes.
    pub async fn refresh_trunk_ips(&self) {
        let ips: Vec<String> = self
            .trunks
            .list_trunks()
            .iter()
            .flat_map(|t| {
                t.resolved_addr
                    .map(|a| a.ip().to_string())
                    .into_iter()
                    .chain(std::iter::once(t.host.clone()))
            })
            .collect();
        *self.trunk_ips.write().await = ips;
    }
}
