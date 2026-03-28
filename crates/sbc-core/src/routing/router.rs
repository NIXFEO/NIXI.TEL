//! SIP Router
//!
//! Routes SIP messages to appropriate trunks based on Request-URI.

use crate::routing::trunk::{TrunkConfig, TrunkManager};
use crate::{Error, Result};
use rsip::prelude::*;
use rsip::{Request, SipMessage};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// SIP message router
pub struct Router {
    trunk_manager: Arc<TrunkManager>,
}

impl Router {
    /// Create a new router
    pub fn new(trunk_manager: Arc<TrunkManager>) -> Self {
        Self { trunk_manager }
    }

    /// Get the trunk manager (for external trunk configuration)
    pub fn trunk_manager(&self) -> &Arc<TrunkManager> {
        &self.trunk_manager
    }

    /// Route an incoming SIP request to a trunk
    /// Returns the selected trunk configuration
    pub fn route_request(&self, request: &Request) -> Result<TrunkConfig> {
        debug!("Routing {} request to {}", request.method, request.uri);

        // Extract destination from Request-URI
        let request_uri = &request.uri;

        // For now, simple routing based on domain matching
        // In production, this would use dial plans, LCR, etc.
        let trunk = self.find_trunk_for_uri(request_uri)?;

        // Check if trunk can handle the call
        if !trunk.enabled {
            warn!("Selected trunk {} is disabled", trunk.name);
            return Err(Error::Routing(format!(
                "Trunk {} is disabled",
                trunk.name
            )));
        }

        // Check concurrent call limit
        if let Some(state) = self.trunk_manager.get_state(&trunk.id) {
            if !state.can_accept_call(&trunk) {
                warn!(
                    "Trunk {} has reached max concurrent calls limit",
                    trunk.name
                );
                return Err(Error::Routing(format!(
                    "Trunk {} at capacity",
                    trunk.name
                )));
            }
        }

        debug!("Selected trunk: {} ({})", trunk.name, trunk.id);
        Ok(trunk)
    }

    /// Find the appropriate trunk for a URI using LCR (Least Cost Routing)
    ///
    /// Algorithm:
    /// 1. Domain-exact match first (bypass LCR if direct host match)
    /// 2. Extract phone number from user part of URI
    /// 3. Filter by prefix match
    /// 4. Filter by capacity (concurrent call limit)
    /// 5. Sort by (priority ASC, cost_per_minute ASC) — cheapest available
    /// 6. Fall back to default trunk if no match
    fn find_trunk_for_uri(&self, uri: &rsip::Uri) -> Result<TrunkConfig> {
        let domain = uri.host_with_port.to_string();
        let user = uri.auth.as_ref().map(|a| a.to_string()).unwrap_or_default();

        debug!("LCR routing: user={} domain={}", user, domain);

        let trunks = self.trunk_manager.list_trunks();

        // Step 1: exact domain match
        for trunk in &trunks {
            if trunk.enabled && trunk.host == domain {
                if let Some(state) = self.trunk_manager.get_state(&trunk.id) {
                    if state.can_accept_call(trunk) {
                        info!("LCR: domain-match trunk '{}' ({})", trunk.name, trunk.host);
                        return Ok(trunk.clone());
                    }
                } else {
                    info!("LCR: domain-match trunk '{}' ({})", trunk.name, trunk.host);
                    return Ok(trunk.clone());
                }
            }
        }

        // Step 2: LCR — filter enabled + prefix match + capacity, sort by priority/cost
        let mut candidates: Vec<&TrunkConfig> = trunks.iter()
            .filter(|t| t.enabled)
            .filter(|t| t.matches_prefix(&user))
            .filter(|t| {
                self.trunk_manager.get_state(&t.id)
                    .map_or(true, |s| s.can_accept_call(t))
            })
            .collect();

        candidates.sort_by_key(|t| t.lcr_sort_key());

        if let Some(best) = candidates.first() {
            info!(
                "LCR: selected trunk '{}' (priority={}, cost={}¢/min) for '{}'",
                best.name, best.priority, best.cost_per_minute, user
            );
            return Ok((*best).clone());
        }

        // Fallback: first enabled trunk
        self.get_default_trunk()
            .ok_or_else(|| Error::Routing("No trunk available for route".to_string()))
    }


    /// Route an incoming SIP request — return ALL candidate trunks (ordered by priority/cost)
    /// for failover. The caller should try each trunk in order.
    pub fn route_request_candidates(&self, request: &Request) -> Vec<TrunkConfig> {
        let request_uri = &request.uri;
        self.find_all_trunks_for_uri(request_uri)
    }

    /// Find ALL matching trunks for a URI, ordered by LCR priority
    fn find_all_trunks_for_uri(&self, uri: &rsip::Uri) -> Vec<TrunkConfig> {
        let domain = uri.host_with_port.to_string();
        let user = uri.auth.as_ref().map(|a| a.to_string()).unwrap_or_default();

        debug!("LCR failover routing: user={} domain={}", user, domain);

        let trunks = self.trunk_manager.list_trunks();
        let mut candidates: Vec<TrunkConfig> = Vec::new();

        // Step 1: domain-exact matches first
        for trunk in &trunks {
            if trunk.enabled && trunk.host == domain {
                if let Some(state) = self.trunk_manager.get_state(&trunk.id) {
                    if state.can_accept_call(trunk) {
                        candidates.push(trunk.clone());
                    }
                } else {
                    candidates.push(trunk.clone());
                }
            }
        }

        // Step 2: LCR prefix-match candidates
        let mut lcr_candidates: Vec<TrunkConfig> = trunks.iter()
            .filter(|t| t.enabled)
            .filter(|t| t.host != domain) // already added domain matches
            .filter(|t| t.matches_prefix(&user))
            .filter(|t| {
                self.trunk_manager.get_state(&t.id)
                    .map_or(true, |s| s.can_accept_call(t))
            })
            .cloned()
            .collect();
        lcr_candidates.sort_by_key(|t| t.lcr_sort_key());
        candidates.extend(lcr_candidates);

        // Step 3: if nothing matched, add default trunks as last resort
        if candidates.is_empty() {
            let mut defaults: Vec<TrunkConfig> = trunks.iter()
                .filter(|t| t.enabled)
                .filter(|t| {
                    self.trunk_manager.get_state(&t.id)
                        .map_or(true, |s| s.can_accept_call(t))
                })
                .cloned()
                .collect();
            defaults.sort_by_key(|t| t.lcr_sort_key());
            candidates = defaults;
        }

        info!("LCR failover: {} candidate trunk(s) for user='{}'", candidates.len(), user);
        for (i, t) in candidates.iter().enumerate() {
            debug!("  #{}: {} (priority={}, cost={})", i+1, t.name, t.priority, t.cost_per_minute);
        }

        candidates
    }

    /// Get the default trunk (first enabled trunk, lowest priority)
    fn get_default_trunk(&self) -> Option<TrunkConfig> {
        let mut trunks: Vec<TrunkConfig> = self.trunk_manager
            .list_trunks()
            .into_iter()
            .filter(|t| t.enabled)
            .collect();
        trunks.sort_by_key(|t| t.lcr_sort_key());
        trunks.into_iter().next()
    }

    /// Route a response back to the source
    /// For now, just returns Ok as we'll use Via headers for response routing
    pub fn route_response(&self, _response: &rsip::Response) -> Result<()> {
        // Response routing uses Via headers (RFC 3261)
        // This is handled by the transport layer
        Ok(())
    }

    /// Check if a message should be handled locally (for this SBC)
    pub fn is_local_request(&self, request: &Request) -> bool {
        // Check if Request-URI points to this SBC
        // For now, we'll route everything externally
        // In a real implementation, check against local domains/IPs

        match request.method {
            // OPTIONS are often used for keepalives/health checks
            rsip::Method::Options => true,
            // REGISTER is always handled locally
            rsip::Method::Register => true,
            _ => false,
        }
    }

    /// Handle local requests (like OPTIONS ping)
    pub fn handle_local_request(&self, request: &Request) -> Result<SipMessage> {
        debug!("Handling local request: {}", request.method);

        match request.method {
            rsip::Method::Options => self.create_options_response(request),
            rsip::Method::Register => self.create_register_response(request),
            _ => Err(Error::Routing(format!(
                "Cannot handle local request: {}",
                request.method
            ))),
        }
    }

    /// Create a 200 OK response for REGISTER
    fn create_register_response(&self, request: &Request) -> Result<SipMessage> {
        let mut headers: rsip::Headers = Default::default();

        // Copy Via, From, To, Call-ID, CSeq headers
        headers.push(request.via_header()?.clone().into());
        headers.push(request.from_header()?.clone().into());

        // To header with tag
        let mut to = request.to_header()?.typed()?;
        if to.params.iter().all(|p| !matches!(p, rsip::Param::Tag(_))) {
            to.params.push(rsip::Param::Tag(rsip::param::Tag::new(
                &uuid::Uuid::new_v4().to_string()[..8],
            )));
        }
        headers.push(to.into());

        headers.push(request.call_id_header()?.clone().into());
        headers.push(request.cseq_header()?.clone().into());

        // Copy Contact header if present (echo back the registration)
        if let Ok(contact) = request.contact_header() {
            headers.push(contact.clone().into());
        }

        // Add Expires header
        let expires = if let Some(exp) = request.expires_header() {
            exp.clone()
        } else {
            rsip::headers::Expires::new("3600")
        };
        headers.push(expires.into());

        headers.push(rsip::Header::ContentLength(Default::default()));

        let response = rsip::Response {
            status_code: 200.into(),
            version: rsip::Version::V2,
            headers,
            body: Vec::new(),
        };

        Ok(SipMessage::Response(response))
    }

    /// Create a 200 OK response for OPTIONS
    fn create_options_response(&self, request: &Request) -> Result<SipMessage> {
        let mut headers: rsip::Headers = Default::default();

        // Copy Via, From, To, Call-ID, CSeq
        headers.push(request.via_header()?.clone().into());
        headers.push(request.from_header()?.clone().into());

        // To header with tag
        let mut to = request.to_header()?.typed()?;
        if to.params.iter().all(|p| !matches!(p, rsip::Param::Tag(_))) {
            to.params.push(rsip::Param::Tag(rsip::param::Tag::new(
                &uuid::Uuid::new_v4().to_string()[..8],
            )));
        }
        headers.push(to.into());

        headers.push(request.call_id_header()?.clone().into());
        headers.push(request.cseq_header()?.clone().into());

        // Add Accept, Allow, Supported headers
        headers.push(rsip::Header::Accept(rsip::headers::Accept::new(
            "application/sdp",
        )));
        headers.push(rsip::Header::Allow(rsip::headers::Allow::new(
            "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO",
        )));
        headers.push(rsip::Header::Supported(rsip::headers::Supported::new(
            "replaces, timer",
        )));

        headers.push(rsip::Header::ContentLength(Default::default()));

        let response = rsip::Response {
            status_code: 200.into(),
            version: rsip::Version::V2,
            headers,
            body: Vec::new(),
        };

        Ok(SipMessage::Response(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::trunk::TrunkConfig;

    #[test]
    fn test_router_creation() {
        let trunk_manager = Arc::new(TrunkManager::new());
        let _router = Router::new(trunk_manager);
    }

    #[test]
    fn test_is_local_request() {
        let trunk_manager = Arc::new(TrunkManager::new());
        let router = Router::new(trunk_manager);

        // Create OPTIONS request
        let mut headers: rsip::Headers = Default::default();
        headers.push(
            rsip::typed::Via {
                version: rsip::Version::V2,
                transport: rsip::Transport::Udp,
                uri: rsip::Uri {
                    host_with_port: rsip::Domain::from("example.com").into(),
                    ..Default::default()
                },
                params: vec![rsip::Param::Branch(rsip::param::Branch::new(
                    "z9hG4bK776asdhds",
                ))],
            }
            .into(),
        );
        headers.push(
            rsip::typed::From {
                display_name: None,
                uri: rsip::Uri {
                    scheme: Some(rsip::Scheme::Sip),
                    auth: Some(("alice", None::<&str>).into()),
                    host_with_port: rsip::Domain::from("atlanta.example.com").into(),
                    ..Default::default()
                },
                params: vec![rsip::Param::Tag(rsip::param::Tag::new("1928301774"))],
            }
            .into(),
        );
        headers.push(
            rsip::typed::To {
                display_name: None,
                uri: rsip::Uri {
                    scheme: Some(rsip::Scheme::Sip),
                    auth: Some(("bob", None::<&str>).into()),
                    host_with_port: rsip::Domain::from("biloxi.example.com").into(),
                    ..Default::default()
                },
                params: vec![],
            }
            .into(),
        );
        headers.push(rsip::headers::CallId::default().into());
        headers.push(
            rsip::typed::CSeq {
                seq: 1,
                method: rsip::Method::Options,
            }
            .into(),
        );
        headers.push(rsip::headers::ContentLength::default().into());

        let request = rsip::Request {
            method: rsip::Method::Options,
            uri: rsip::Uri {
                scheme: Some(rsip::Scheme::Sip),
                host_with_port: rsip::Domain::from("biloxi.example.com").into(),
                ..Default::default()
            },
            version: rsip::Version::V2,
            headers,
            body: Vec::new(),
        };

        assert!(router.is_local_request(&request));
    }

    #[test]
    fn test_find_trunk_by_domain() {
        let trunk_manager = Arc::new(TrunkManager::new());

        let mut trunk = TrunkConfig::new("TestTrunk".to_string());
        trunk.host = "example.com".to_string();
        trunk.enabled = true;
        trunk_manager.add_trunk(trunk);

        let router = Router::new(trunk_manager);

        let uri = rsip::Uri {
            scheme: Some(rsip::Scheme::Sip),
            host_with_port: rsip::Domain::from("example.com").into(),
            ..Default::default()
        };

        let result = router.find_trunk_for_uri(&uri);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().host, "example.com");
    }
}
