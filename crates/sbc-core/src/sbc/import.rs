//! First-boot import of TOML dynamic config into the SQLite store.
//!
//! Idempotent: each table is only seeded when it is empty, so TOML entries
//! act as bootstrap seeds and the store remains the source of truth
//! afterwards. Runs at every boot; a non-empty table is left untouched.

use sbc_storage::{ConfigStore, DidRow, Table, TrunkRow, UserRow};
use tracing::{info, warn};

use crate::auth::compute_ha1;
use crate::config::SbcConfig;

/// Seed the store from TOML config where tables are empty.
/// Returns (users, dids, trunks) imported counts.
pub async fn first_boot_import(store: &ConfigStore, config: &SbcConfig) -> (usize, usize, usize) {
    let mut imported = (0usize, 0usize, 0usize);

    match store.table_is_empty(Table::Users).await {
        Ok(true) if !config.security.sip_users.is_empty() => {
            let realm = &config.security.sip_realm;
            for (username, password) in &config.security.sip_users {
                let row = UserRow {
                    username: username.clone(),
                    ha1: compute_ha1(username, realm, password),
                    realm: realm.clone(),
                    display_name: None,
                    enabled: true,
                    max_concurrent_calls: None,
                    max_calls_per_minute: None,
                };
                match store.upsert_user(&row).await {
                    Ok(_) => imported.0 += 1,
                    Err(e) => warn!("Import user '{}' failed: {}", username, e),
                }
            }
        }
        Ok(_) => {}
        Err(e) => warn!("Import: users table check failed: {}", e),
    }

    match store.table_is_empty(Table::Dids).await {
        Ok(true) if !config.dids.is_empty() => {
            for did in &config.dids {
                let row = DidRow {
                    number: did.number.clone(),
                    sip_user: did.user.clone(),
                    display_name: did.display_name.clone(),
                    enabled: true,
                };
                match store.upsert_did(&row).await {
                    Ok(_) => imported.1 += 1,
                    Err(e) => warn!("Import DID '{}' failed: {}", did.number, e),
                }
            }
        }
        Ok(_) => {}
        Err(e) => warn!("Import: dids table check failed: {}", e),
    }

    match store.table_is_empty(Table::Trunks).await {
        Ok(true) if !config.trunks.is_empty() => {
            for tc in &config.trunks {
                let row = TrunkRow {
                    name: tc.name.clone(),
                    enabled: tc.enabled,
                    host: tc.host.clone(),
                    port: tc.port as i64,
                    transport: tc.transport.clone(),
                    auth_required: tc.auth_required,
                    username: tc.username.clone(),
                    password: tc.password.clone(),
                    realm: tc.realm.clone(),
                    register_with_trunk: tc.register_with_trunk,
                    registration_interval: tc.registration_interval as i64,
                    prefix_patterns: serde_json::to_string(&tc.prefix_patterns)
                        .unwrap_or_else(|_| "[]".to_string()),
                    priority: tc.priority as i64,
                    weight: tc.weight as i64,
                    cost_per_minute: tc.cost_per_minute as i64,
                    number_format: tc.number_format.clone(),
                    country_code: tc.country_code.clone(),
                    national_prefix: tc.national_prefix.clone(),
                    caller_number_format: tc.caller_number_format.clone(),
                    caller_number_override: tc.caller_number_override.clone(),
                    caller_display_name: tc.caller_display_name.clone(),
                    allowed_codecs: serde_json::to_string(&tc.allowed_codecs)
                        .unwrap_or_else(|_| "[]".to_string()),
                    max_concurrent_calls: tc.max_concurrent_calls as i64,
                    tls_sni: None,
                    tls_ca_cert: None,
                    tls_verify: true,
                    tls_client_cert: None,
                    tls_client_key: None,
                };
                match store.upsert_trunk(&row).await {
                    Ok(_) => imported.2 += 1,
                    Err(e) => warn!("Import trunk '{}' failed: {}", tc.name, e),
                }
            }
        }
        Ok(_) => {}
        Err(e) => warn!("Import: trunks table check failed: {}", e),
    }

    if imported != (0, 0, 0) {
        let now = chrono_free_now_rfc3339();
        let _ = store.set_setting("toml_imported_at", &now).await;
        info!(
            "First-boot import from TOML: {} users, {} DIDs, {} trunks",
            imported.0, imported.1, imported.2
        );
    }

    imported
}

/// RFC 3339 UTC timestamp without pulling chrono into sbc-core.
fn chrono_free_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Days since epoch → civil date (valid for 1970-2099)
    let days = now / 86400;
    let secs = now % 86400;
    let (mut y, mut rem) = (1970u64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if rem < len {
            break;
        }
        rem -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_len = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while rem >= month_len[m] {
        rem -= month_len[m];
        m += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        rem + 1,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_with_seeds() -> SbcConfig {
        let mut config = SbcConfig::default();
        config.security.sip_realm = "sip.example.com".to_string();
        config.security.sip_users =
            HashMap::from([("alice".to_string(), "secret".to_string())]);
        config.dids = vec![crate::config::DidMapping {
            number: "+33123456789".to_string(),
            user: "alice".to_string(),
            display_name: None,
        }];
        config
    }

    #[tokio::test]
    async fn import_seeds_empty_store() {
        let store = ConfigStore::open_memory().await.unwrap();
        let (u, d, t) = first_boot_import(&store, &config_with_seeds()).await;
        assert_eq!((u, d, t), (1, 1, 0));

        let user = store.get_user("alice").await.unwrap().unwrap();
        assert_eq!(user.ha1, compute_ha1("alice", "sip.example.com", "secret"));
        assert!(store.get_did("+33123456789").await.unwrap().is_some());
        assert!(store.get_setting("toml_imported_at").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn import_is_idempotent() {
        let store = ConfigStore::open_memory().await.unwrap();
        first_boot_import(&store, &config_with_seeds()).await;

        // Simulate an API-side change, then re-import (e.g. restart)
        store.delete_user("alice").await.unwrap();
        let mut bob = sbc_storage::UserRow {
            username: "bob".to_string(),
            ha1: "x".repeat(32),
            realm: "sip.example.com".to_string(),
            display_name: None,
            enabled: true,
            max_concurrent_calls: None,
            max_calls_per_minute: None,
        };
        bob.ha1 = "f".repeat(32);
        store.upsert_user(&bob).await.unwrap();

        let (u, _, _) = first_boot_import(&store, &config_with_seeds()).await;
        assert_eq!(u, 0, "non-empty table must not be re-seeded");
        assert!(store.get_user("alice").await.unwrap().is_none());
        assert!(store.get_user("bob").await.unwrap().is_some());
    }

    #[test]
    fn rfc3339_shape() {
        let s = chrono_free_now_rfc3339();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert!(s.starts_with("20"));
    }
}
