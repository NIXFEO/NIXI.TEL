//! Hydration: push dynamic config from the SQLite store into the live
//! runtime managers. Called at boot, on SIGHUP / `POST /api/v1/reload`,
//! and directly by API write handlers so mutations apply immediately.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sbc_storage::{ConfigStore, TrunkRow};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::acl::{AclAction, AclManager, AclRule};
use crate::auth::DigestAuthenticator;
use crate::config::DidMapping;
use crate::routing::trunk::NumberFormat;
use crate::routing::{TransportType, TrunkConfig, TrunkManager};

/// Load users from the store into the digest authenticator.
/// Disabled users are excluded (they can no longer authenticate).
pub async fn apply_users(
    auth: &DigestAuthenticator,
    store: &ConfigStore,
) -> crate::Result<(usize, usize, usize)> {
    let rows = store
        .list_users()
        .await
        .map_err(|e| crate::Error::Config(format!("load users: {}", e)))?;

    let ha1_map: HashMap<String, String> = rows
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| (r.username, r.ha1))
        .collect();

    let (added, removed, total) = auth.set_users_ha1(ha1_map).await;
    info!(
        "Hydrate: users — {} total ({} added, {} removed)",
        total, added, removed
    );
    Ok((added, removed, total))
}

/// Load DID mappings from the store into the shared runtime vector.
pub async fn apply_dids(
    dids: &RwLock<Vec<DidMapping>>,
    store: &ConfigStore,
) -> crate::Result<usize> {
    let rows = store
        .list_dids()
        .await
        .map_err(|e| crate::Error::Config(format!("load dids: {}", e)))?;

    let mappings: Vec<DidMapping> = rows
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| DidMapping {
            number: r.number,
            user: r.sip_user,
            display_name: r.display_name,
        })
        .collect();

    let count = mappings.len();
    *dids.write().await = mappings;
    info!("Hydrate: DID mappings — {} entries", count);
    Ok(count)
}

/// Convert a stored trunk row (with its route prefixes merged in) to the
/// runtime `TrunkConfig`.
pub fn trunk_row_to_config(row: &TrunkRow, extra_prefixes: &[String]) -> TrunkConfig {
    let transport = match row.transport.to_uppercase().as_str() {
        "TCP" => TransportType::Tcp,
        "TLS" => TransportType::Tls,
        "WSS" => TransportType::Wss,
        "WS" => TransportType::Ws,
        _ => TransportType::Udp,
    };
    let number_format = match row.number_format.to_lowercase().as_str() {
        "national" => NumberFormat::National,
        "local" => NumberFormat::Local,
        _ => NumberFormat::E164,
    };

    let mut prefix_patterns = row.prefix_patterns_vec();
    for p in extra_prefixes {
        if !prefix_patterns.contains(p) {
            prefix_patterns.push(p.clone());
        }
    }

    TrunkConfig {
        id: uuid::Uuid::new_v4(),
        name: row.name.clone(),
        enabled: row.enabled,
        transport,
        host: row.host.clone(),
        port: row.port as u16,
        resolved_addr: None,
        auth_required: row.auth_required,
        username: row.username.clone(),
        password: row.password.clone(),
        realm: row.realm.clone(),
        allowed_codecs: row.allowed_codecs_vec(),
        transcoding_enabled: false,
        max_concurrent_calls: row.max_concurrent_calls as u32,
        calls_per_second: 10,
        allowed_ips: Vec::new(),
        register_with_trunk: row.register_with_trunk,
        registration_interval: Duration::from_secs(row.registration_interval.max(0) as u64),
        cost_per_minute: row.cost_per_minute as u32,
        priority: row.priority as u32,
        weight: row.weight as u32,
        prefix_patterns,
        number_format,
        country_code: row.country_code.clone(),
        national_prefix: row.national_prefix.clone(),
        caller_number_format: row.caller_number_format.as_deref().map(|f| {
            match f.to_lowercase().as_str() {
                "national" => NumberFormat::National,
                "local" => NumberFormat::Local,
                _ => NumberFormat::E164,
            }
        }),
        caller_number_override: row.caller_number_override.clone(),
        caller_display_name: row.caller_display_name.clone(),
    }
}

/// Sync trunks (and their routes) from the store into the TrunkManager.
///
/// Semantics: upsert by name; trunks present in the manager but absent from
/// the store are disabled, not removed (active calls may reference them).
/// Returns (added, updated, disabled).
pub async fn apply_trunks_and_routes(
    tm: &TrunkManager,
    store: &ConfigStore,
) -> crate::Result<(usize, usize, usize)> {
    let trunk_rows = store
        .list_trunks()
        .await
        .map_err(|e| crate::Error::Config(format!("load trunks: {}", e)))?;
    let route_rows = store
        .list_routes()
        .await
        .map_err(|e| crate::Error::Config(format!("load routes: {}", e)))?;

    // trunk name → extra prefixes from enabled routes
    let mut routes_by_trunk: HashMap<String, Vec<String>> = HashMap::new();
    for r in route_rows.into_iter().filter(|r| r.enabled) {
        routes_by_trunk.entry(r.trunk_name).or_default().push(r.prefix);
    }

    let mut added = 0usize;
    let mut updated = 0usize;

    let store_names: std::collections::HashSet<String> =
        trunk_rows.iter().map(|r| r.name.clone()).collect();

    for row in &trunk_rows {
        let extra = routes_by_trunk.get(&row.name).map(|v| v.as_slice()).unwrap_or(&[]);
        let mut cfg = trunk_row_to_config(row, extra);

        if tm.find_by_name(&row.name).is_some() {
            tm.update_trunk_by_name(&row.name, cfg);
            updated += 1;
        } else {
            match cfg.resolve_destination().await {
                Some(addr) => info!(
                    "Hydrate: trunk '{}' → {}:{} → {}",
                    cfg.name, cfg.host, cfg.port, addr
                ),
                None => warn!(
                    "Hydrate: trunk '{}': DNS resolution failed for {}:{} — will retry",
                    cfg.name, cfg.host, cfg.port
                ),
            }
            tm.add_trunk(cfg);
            added += 1;
        }
    }

    // Disable manager trunks that are no longer in the store
    let mut disabled = 0usize;
    for t in tm.list_trunks() {
        if !store_names.contains(&t.name) && t.enabled {
            tm.disable_trunk(&t.id);
            warn!("Hydrate: trunk '{}' absent from store — disabled", t.name);
            disabled += 1;
        }
    }

    info!(
        "Hydrate: trunks — {} added, {} updated, {} disabled ({} total)",
        added,
        updated,
        disabled,
        tm.list_trunks().len()
    );
    Ok((added, updated, disabled))
}

/// Load ACL rules and the default action from the store.
/// With no stored rules and no stored default, the ACL stays permissive
/// (unchanged legacy behavior).
pub async fn apply_acl(acl: &AclManager, store: &ConfigStore) -> crate::Result<usize> {
    let rows = store
        .list_acl_rules()
        .await
        .map_err(|e| crate::Error::Config(format!("load acl: {}", e)))?;

    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let action = match row.action.as_str() {
            "deny" => AclAction::Deny,
            _ => AclAction::Allow,
        };
        match AclRule::new(&row.id, &row.id, &row.cidr, action, row.priority as i32) {
            Ok(mut rule) => {
                rule.enabled = row.enabled;
                if let Some(comment) = &row.comment {
                    rule = rule.with_comment(comment);
                }
                rule = rule.with_direction(match row.direction.as_str() {
                    "inbound" => crate::acl::Direction::Inbound,
                    "outbound" => crate::acl::Direction::Outbound,
                    _ => crate::acl::Direction::Both,
                });
                rules.push(rule);
            }
            Err(e) => warn!("Hydrate: skipping ACL rule '{}': {}", row.id, e),
        }
    }

    let count = acl.replace_rules(rules).await;

    if let Ok(Some(action)) = store.get_setting("acl_default_action").await {
        let action = match action.as_str() {
            "deny" => AclAction::Deny,
            _ => AclAction::Allow,
        };
        acl.set_default_action(action).await;
    }

    info!("Hydrate: ACL — {} rules", count);
    Ok(count)
}

/// Shared handles the API layer needs to re-hydrate the runtime after writes.
#[derive(Clone)]
pub struct RuntimeHandles {
    pub auth: Option<Arc<DigestAuthenticator>>,
    pub dids: Arc<RwLock<Vec<DidMapping>>>,
    pub trunks: Arc<TrunkManager>,
    pub acl: Arc<AclManager>,
}

/// Hydrate everything from the store.
pub async fn hydrate_all(handles: &RuntimeHandles, store: &ConfigStore) -> crate::Result<()> {
    if let Some(auth) = &handles.auth {
        apply_users(auth, store).await?;
    }
    apply_dids(&handles.dids, store).await?;
    apply_trunks_and_routes(&handles.trunks, store).await?;
    apply_acl(&handles.acl, store).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbc_storage::{DidRow, RouteRow, UserRow};

    fn user_row(name: &str, enabled: bool) -> UserRow {
        UserRow {
            username: name.to_string(),
            ha1: format!("{:0>32}", name.len()),
            realm: "sip.example.com".to_string(),
            display_name: None,
            enabled,
            max_concurrent_calls: None,
            max_calls_per_minute: None,
        }
    }

    fn trunk_row(name: &str) -> TrunkRow {
        TrunkRow {
            name: name.to_string(),
            enabled: true,
            host: "192.0.2.10".to_string(),
            port: 5060,
            transport: "UDP".to_string(),
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            register_with_trunk: false,
            registration_interval: 300,
            prefix_patterns: r#"["+33"]"#.to_string(),
            priority: 100,
            weight: 100,
            cost_per_minute: 0,
            number_format: "e164".to_string(),
            country_code: None,
            national_prefix: None,
            caller_number_format: None,
            caller_number_override: None,
            caller_display_name: None,
            allowed_codecs: r#"["PCMU"]"#.to_string(),
            max_concurrent_calls: 100,
            tls_sni: None,
            tls_ca_cert: None,
            tls_verify: true,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    #[tokio::test]
    async fn users_hydrate_excludes_disabled() {
        let store = ConfigStore::open_memory().await.unwrap();
        store.upsert_user(&user_row("alice", true)).await.unwrap();
        store.upsert_user(&user_row("mallory", false)).await.unwrap();

        let auth = DigestAuthenticator::new("sip.example.com", HashMap::new());
        let (_, _, total) = apply_users(&auth, &store).await.unwrap();
        assert_eq!(total, 1);
        assert!(auth.user_exists("alice").await);
        assert!(!auth.user_exists("mallory").await);
    }

    #[tokio::test]
    async fn dids_hydrate_replaces_vector() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .upsert_did(&DidRow {
                number: "+33123".to_string(),
                sip_user: "alice".to_string(),
                display_name: None,
                enabled: true,
            })
            .await
            .unwrap();
        store
            .upsert_did(&DidRow {
                number: "+33999".to_string(),
                sip_user: "off".to_string(),
                display_name: None,
                enabled: false,
            })
            .await
            .unwrap();

        let dids = RwLock::new(vec![DidMapping {
            number: "old".to_string(),
            user: "old".to_string(),
            display_name: None,
        }]);
        let count = apply_dids(&dids, &store).await.unwrap();
        assert_eq!(count, 1);
        let v = dids.read().await;
        assert_eq!(v[0].number, "+33123");
    }

    #[tokio::test]
    async fn trunks_hydrate_upserts_and_disables() {
        let store = ConfigStore::open_memory().await.unwrap();
        store.upsert_trunk(&trunk_row("pstn-1")).await.unwrap();
        store
            .insert_route(&RouteRow {
                id: 0,
                prefix: "+1".to_string(),
                trunk_name: "pstn-1".to_string(),
                priority: 10,
                enabled: true,
                description: None,
            })
            .await
            .unwrap();

        let tm = TrunkManager::new();
        // Pre-existing trunk not in store → must get disabled
        let mut stale = trunk_row_to_config(&trunk_row("stale"), &[]);
        stale.name = "stale".to_string();
        tm.add_trunk(stale);

        let (added, updated, disabled) = apply_trunks_and_routes(&tm, &store).await.unwrap();
        assert_eq!((added, updated, disabled), (1, 0, 1));

        let t = tm.find_by_name("pstn-1").unwrap();
        assert!(t.prefix_patterns.contains(&"+33".to_string()));
        assert!(t.prefix_patterns.contains(&"+1".to_string()));
        assert!(!tm.find_by_name("stale").unwrap().enabled);

        // Second run: update, id preserved
        let id_before = t.id;
        let (added2, updated2, _) = apply_trunks_and_routes(&tm, &store).await.unwrap();
        assert_eq!((added2, updated2), (0, 1));
        assert_eq!(tm.find_by_name("pstn-1").unwrap().id, id_before);
    }

    #[tokio::test]
    async fn acl_hydrate_loads_rules_and_default() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .upsert_acl_rule(&sbc_storage::AclRuleRow {
                id: "block-scanner".to_string(),
                cidr: "198.51.100.0/24".to_string(),
                action: "deny".to_string(),
                direction: "inbound".to_string(),
                priority: 10,
                enabled: true,
                comment: Some("scanner".to_string()),
            })
            .await
            .unwrap();

        let acl = AclManager::new_permissive();
        let count = apply_acl(&acl, &store).await.unwrap();
        assert_eq!(count, 1);

        let denied = acl
            .check("198.51.100.7".parse().unwrap(), crate::acl::Direction::Inbound)
            .await;
        assert!(!denied.is_allowed());
        // Default stays permissive for other IPs
        let allowed = acl
            .check("203.0.113.1".parse().unwrap(), crate::acl::Direction::Inbound)
            .await;
        assert!(allowed.is_allowed());
    }
}
