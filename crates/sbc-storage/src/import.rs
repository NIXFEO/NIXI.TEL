//! Bulk import of a `GET /api/v1/export` document — the store side of
//! `POST /api/v1/import`.
//!
//! One transaction for the whole document. `merge` upserts the rows the
//! document carries; `replace` makes every section the document carries
//! exactly the document (rows it does not mention are deleted). A section
//! absent from the document is never touched, in either mode. Validation
//! of the rows is the API's job; the schema constraints (foreign keys,
//! CHECKs) are the last line and surface as [`Error::Constraint`] naming
//! the offending row, with nothing written.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

use crate::models::keys;
use crate::store::db_err;
use crate::{
    AclRuleRow, ConfigStore, DestinationRuleRow, DidRow, Result, RouteRow, TrunkRow, UserRow,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Upsert the document's rows; rows it does not mention stay.
    Merge,
    /// Every section the document carries becomes exactly the document:
    /// rows it does not mention are deleted.
    Replace,
}

impl ImportMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "merge" => Some(Self::Merge),
            "replace" => Some(Self::Replace),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }
}

/// The document `GET /api/v1/export` produces (version 1 or 2). Every
/// section is optional.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct ImportDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dids: Option<Vec<DidRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trunks: Option<Vec<TrunkRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<RouteRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_rules: Option<Vec<AclRuleRow>>,
    /// `allow` | `deny`; absent = untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_default_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_rules: Option<Vec<DestinationRuleRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_limits: Option<ImportUserLimits>,
}

/// The API-set global per-user limits. A `null` (or absent) value leaves
/// the stored setting alone in merge mode and removes it in replace mode
/// (the TOML `[security.user_limits]` defaults apply again).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportUserLimits {
    #[serde(default)]
    pub default_max_concurrent_calls: Option<u32>,
    #[serde(default)]
    pub default_max_calls_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SectionReport {
    pub inserted: usize,
    pub updated: usize,
    pub deleted: usize,
}

/// What an import did (or, on a dry run, would do). A section the document
/// did not carry is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub users: Option<SectionReport>,
    pub dids: Option<SectionReport>,
    pub trunks: Option<SectionReport>,
    pub routes: Option<SectionReport>,
    pub acl_rules: Option<SectionReport>,
    pub destination_rules: Option<SectionReport>,
    /// Settings written (`key → value`).
    pub settings_set: BTreeMap<String, String>,
    /// Settings removed (replace mode, `null` user limit).
    pub settings_removed: Vec<String>,
    /// Trunks a replace deleted. Their routes went with them (SQLite
    /// cascades) and are not counted in `routes.deleted`.
    pub deleted_trunks: Vec<String>,
}

impl ImportReport {
    /// One line for logs and events: `users +1/~2/-0, trunks +0/~1/-1, …`
    /// (inserted / updated / deleted).
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (name, section) in [
            ("users", &self.users),
            ("dids", &self.dids),
            ("trunks", &self.trunks),
            ("routes", &self.routes),
            ("acl_rules", &self.acl_rules),
            ("destination_rules", &self.destination_rules),
        ] {
            if let Some(s) = section {
                parts.push(format!(
                    "{} +{}/~{}/-{}",
                    name, s.inserted, s.updated, s.deleted
                ));
            }
        }
        if !self.settings_set.is_empty() || !self.settings_removed.is_empty() {
            parts.push(format!(
                "settings +{}/-{}",
                self.settings_set.len(),
                self.settings_removed.len()
            ));
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl ConfigStore {
    /// Apply `doc` in one transaction. With `dry_run` the transaction is
    /// rolled back after counting, so the report says what a real run
    /// would do. On any error nothing is written.
    ///
    /// The whole import runs on the transaction's connection and touches
    /// the pool exactly once (`begin`), so it also works on a
    /// one-connection pool.
    pub async fn import(
        &self,
        doc: &ImportDoc,
        mode: ImportMode,
        dry_run: bool,
    ) -> Result<ImportReport> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let report = import_on(&mut tx, doc, mode).await?;
        if dry_run {
            tx.rollback().await.map_err(db_err)?;
        } else {
            tx.commit().await.map_err(db_err)?;
        }
        Ok(report)
    }
}

async fn import_on(
    conn: &mut SqliteConnection,
    doc: &ImportDoc,
    mode: ImportMode,
) -> Result<ImportReport> {
    let replace = mode == ImportMode::Replace;
    let mut report = ImportReport::default();

    // Trunks first: a replace deletes the trunks the document dropped and
    // SQLite cascades their routes (migration 0001), so those routes are
    // counted with the trunk, not in the routes section.
    if let Some(trunks) = &doc.trunks {
        let mut section = SectionReport::default();
        if replace {
            let wanted: BTreeSet<&str> = trunks.iter().map(|t| t.name.as_str()).collect();
            report.deleted_trunks = delete_missing(conn, "trunks", "name", &wanted).await?;
            section.deleted = report.deleted_trunks.len();
        }
        for t in trunks {
            let inserted = ConfigStore::upsert_trunk_on(conn, t)
                .await
                .map_err(|e| e.at("trunks", &t.name))?;
            count(&mut section, inserted);
        }
        report.trunks = Some(section);
    }

    if let Some(routes) = &doc.routes {
        let mut section = SectionReport::default();
        if replace {
            let existing: Vec<(i64, String, String)> =
                sqlx::query_as("SELECT id, prefix, trunk_name FROM routes ORDER BY id")
                    .fetch_all(&mut *conn)
                    .await
                    .map_err(db_err)?;
            let wanted: BTreeSet<(&str, &str)> = routes
                .iter()
                .map(|r| (r.prefix.as_str(), r.trunk_name.as_str()))
                .collect();
            for (id, prefix, trunk) in existing {
                if wanted.contains(&(prefix.as_str(), trunk.as_str())) {
                    continue;
                }
                sqlx::query("DELETE FROM routes WHERE id = ?")
                    .bind(id)
                    .execute(&mut *conn)
                    .await
                    .map_err(db_err)?;
                section.deleted += 1;
            }
        }
        for r in routes {
            let inserted = ConfigStore::upsert_route_on(conn, r)
                .await
                .map_err(|e| e.at("routes", &format!("{} → {}", r.prefix, r.trunk_name)))?;
            count(&mut section, inserted);
        }
        report.routes = Some(section);
    }

    if let Some(users) = &doc.users {
        let mut section = SectionReport::default();
        if replace {
            let wanted: BTreeSet<&str> = users.iter().map(|u| u.username.as_str()).collect();
            section.deleted = delete_missing(conn, "users", "username", &wanted)
                .await?
                .len();
        }
        for u in users {
            let inserted = ConfigStore::upsert_user_on(conn, u)
                .await
                .map_err(|e| e.at("users", &u.username))?;
            count(&mut section, inserted);
        }
        report.users = Some(section);
    }

    if let Some(dids) = &doc.dids {
        let mut section = SectionReport::default();
        if replace {
            let wanted: BTreeSet<&str> = dids.iter().map(|d| d.number.as_str()).collect();
            section.deleted = delete_missing(conn, "dids", "number", &wanted).await?.len();
        }
        for d in dids {
            let inserted = ConfigStore::upsert_did_on(conn, d)
                .await
                .map_err(|e| e.at("dids", &d.number))?;
            count(&mut section, inserted);
        }
        report.dids = Some(section);
    }

    if let Some(rules) = &doc.acl_rules {
        let mut section = SectionReport::default();
        if replace {
            let wanted: BTreeSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
            section.deleted = delete_missing(conn, "acl_rules", "id", &wanted)
                .await?
                .len();
        }
        for r in rules {
            let inserted = ConfigStore::upsert_acl_rule_on(conn, r)
                .await
                .map_err(|e| e.at("acl_rules", &r.id))?;
            count(&mut section, inserted);
        }
        report.acl_rules = Some(section);
    }

    if let Some(rules) = &doc.destination_rules {
        let mut section = SectionReport::default();
        if replace {
            let wanted: BTreeSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
            section.deleted = delete_missing(conn, "destination_rules", "id", &wanted)
                .await?
                .len();
        }
        for r in rules {
            let inserted = ConfigStore::upsert_destination_rule_on(conn, r)
                .await
                .map_err(|e| e.at("destination_rules", &r.id))?;
            count(&mut section, inserted);
        }
        report.destination_rules = Some(section);
    }

    if let Some(action) = &doc.acl_default_action {
        ConfigStore::set_setting_on(conn, keys::ACL_DEFAULT_ACTION, action).await?;
        report
            .settings_set
            .insert(keys::ACL_DEFAULT_ACTION.to_string(), action.clone());
    }
    if let Some(limits) = &doc.user_limits {
        for (key, value) in [
            (
                keys::USER_LIMITS_DEFAULT_CONCURRENT,
                limits.default_max_concurrent_calls,
            ),
            (
                keys::USER_LIMITS_DEFAULT_CPM,
                limits.default_max_calls_per_minute,
            ),
        ] {
            match value {
                Some(v) => {
                    ConfigStore::set_setting_on(conn, key, &v.to_string()).await?;
                    report.settings_set.insert(key.to_string(), v.to_string());
                }
                None => {
                    if replace && ConfigStore::delete_setting_on(conn, key).await? {
                        report.settings_removed.push(key.to_string());
                    }
                }
            }
        }
    }

    // A document that carries a seeded section makes the store the truth
    // for it: the TOML seeds must not come back at the next boot.
    if doc.destination_rules.is_some() {
        mark_seeded(conn, keys::DESTINATION_RULES_SEEDED_AT).await?;
    }
    if doc.users.is_some() {
        mark_seeded(conn, keys::USER_LIMITS_SEEDED_AT).await?;
    }

    Ok(report)
}

fn count(section: &mut SectionReport, inserted: bool) {
    if inserted {
        section.inserted += 1;
    } else {
        section.updated += 1;
    }
}

/// Delete every row of `table` whose `key_col` is not in `wanted`; returns
/// the deleted keys in key order. `table`/`key_col` are compile-time names.
async fn delete_missing(
    conn: &mut SqliteConnection,
    table: &str,
    key_col: &str,
    wanted: &BTreeSet<&str>,
) -> Result<Vec<String>> {
    let select = format!("SELECT {} FROM {} ORDER BY {}", key_col, table, key_col);
    let existing: Vec<String> = sqlx::query_scalar(&select)
        .fetch_all(&mut *conn)
        .await
        .map_err(db_err)?;
    let delete = format!("DELETE FROM {} WHERE {} = ?", table, key_col);
    let mut deleted = Vec::new();
    for key in existing {
        if wanted.contains(key.as_str()) {
            continue;
        }
        sqlx::query(&delete)
            .bind(&key)
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
        deleted.push(key);
    }
    Ok(deleted)
}

async fn mark_seeded(conn: &mut SqliteConnection, key: &str) -> Result<()> {
    if ConfigStore::get_setting_on(conn, key).await?.is_none() {
        ConfigStore::set_setting_on(conn, key, &chrono::Utc::now().to_rfc3339()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn user(name: &str) -> UserRow {
        UserRow {
            username: name.to_string(),
            ha1: "0123456789abcdef0123456789abcdef".to_string(),
            realm: "sip.example.com".to_string(),
            display_name: None,
            enabled: true,
            max_concurrent_calls: None,
            max_calls_per_minute: None,
        }
    }

    fn trunk(name: &str) -> TrunkRow {
        TrunkRow {
            name: name.to_string(),
            enabled: true,
            host: "trunk.example.com".to_string(),
            port: 5060,
            transport: "UDP".to_string(),
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            register_with_trunk: false,
            registration_interval: 300,
            prefix_patterns: "[]".to_string(),
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

    fn route(prefix: &str, trunk: &str, priority: i64) -> RouteRow {
        RouteRow {
            id: 0,
            prefix: prefix.to_string(),
            trunk_name: trunk.to_string(),
            priority,
            enabled: true,
            description: None,
        }
    }

    fn did(number: &str, user: &str) -> DidRow {
        DidRow {
            number: number.to_string(),
            sip_user: user.to_string(),
            display_name: None,
            enabled: true,
        }
    }

    fn acl(id: &str) -> AclRuleRow {
        AclRuleRow {
            id: id.to_string(),
            cidr: "203.0.113.0/24".to_string(),
            action: "allow".to_string(),
            direction: "both".to_string(),
            priority: 100,
            enabled: true,
            comment: None,
        }
    }

    fn dest(id: &str) -> DestinationRuleRow {
        DestinationRuleRow {
            id: id.to_string(),
            prefix: "+882".to_string(),
            action: "deny".to_string(),
            user: None,
            description: String::new(),
            enabled: true,
        }
    }

    async fn seeded_store() -> ConfigStore {
        let store = ConfigStore::open_memory().await.unwrap();
        store.upsert_trunk(&trunk("t1")).await.unwrap();
        store.upsert_trunk(&trunk("t2")).await.unwrap();
        store.insert_route(&route("+33", "t1", 10)).await.unwrap();
        store.insert_route(&route("+1", "t1", 20)).await.unwrap();
        store.insert_route(&route("+44", "t2", 30)).await.unwrap();
        store.upsert_user(&user("a")).await.unwrap();
        store.upsert_user(&user("b")).await.unwrap();
        store.upsert_did(&did("+3312", "a")).await.unwrap();
        store.upsert_acl_rule(&acl("r1")).await.unwrap();
        store.upsert_destination_rule(&dest("d1")).await.unwrap();
        store
    }

    #[tokio::test]
    async fn merge_upserts_what_the_document_carries_and_keeps_the_rest() {
        let store = seeded_store().await;
        let mut a = user("a");
        a.display_name = Some("Alice".into());
        let doc = ImportDoc {
            users: Some(vec![a, user("c")]),
            routes: Some(vec![route("+33", "t1", 99), route("+49", "t2", 5)]),
            ..Default::default()
        };
        let report = store.import(&doc, ImportMode::Merge, false).await.unwrap();
        assert_eq!(
            report.users,
            Some(SectionReport {
                inserted: 1,
                updated: 1,
                deleted: 0
            })
        );
        assert_eq!(
            report.routes,
            Some(SectionReport {
                inserted: 1,
                updated: 1,
                deleted: 0
            })
        );
        assert_eq!(report.trunks, None, "absent section is not reported");
        assert_eq!(report.summary(), "users +1/~1/-0, routes +1/~1/-0");

        let users = store.list_users().await.unwrap();
        assert_eq!(users.len(), 3, "b kept, c added");
        assert_eq!(users[0].display_name.as_deref(), Some("Alice"));
        let routes = store.list_routes().await.unwrap();
        assert_eq!(routes.len(), 4);
        let r33 = routes.iter().find(|r| r.prefix == "+33").unwrap();
        assert_eq!(r33.priority, 99, "route updated by (prefix, trunk) key");
        assert_eq!(store.list_trunks().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn replace_deletes_rows_absent_from_the_document_and_cascades_routes() {
        let store = seeded_store().await;
        let doc = ImportDoc {
            trunks: Some(vec![trunk("t1"), trunk("t3")]),
            routes: Some(vec![route("+33", "t1", 10), route("+7", "t3", 1)]),
            users: Some(vec![user("b")]),
            dids: Some(vec![]),
            acl_rules: Some(vec![acl("r1"), acl("r2")]),
            destination_rules: Some(vec![]),
            ..Default::default()
        };
        let report = store
            .import(&doc, ImportMode::Replace, false)
            .await
            .unwrap();
        assert_eq!(report.deleted_trunks, vec!["t2".to_string()]);
        assert_eq!(
            report.trunks,
            Some(SectionReport {
                inserted: 1,
                updated: 1,
                deleted: 1
            })
        );
        // +44 went with t2 (cascade) and is not counted here; +1 is.
        assert_eq!(
            report.routes,
            Some(SectionReport {
                inserted: 1,
                updated: 1,
                deleted: 1
            })
        );
        assert_eq!(report.users.unwrap().deleted, 1);
        assert_eq!(report.dids.unwrap().deleted, 1);
        assert_eq!(report.acl_rules.unwrap().inserted, 1);
        assert_eq!(report.destination_rules.unwrap().deleted, 1);

        let names: Vec<String> = store
            .list_trunks()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["t1", "t3"]);
        let routes: Vec<(String, String)> = store
            .list_routes()
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.prefix, r.trunk_name))
            .collect();
        assert_eq!(
            routes,
            vec![
                ("+7".to_string(), "t3".to_string()),
                ("+33".to_string(), "t1".to_string())
            ]
        );
        assert_eq!(store.list_users().await.unwrap().len(), 1);
        assert!(store.list_dids().await.unwrap().is_empty());
        assert_eq!(store.list_acl_rules().await.unwrap().len(), 2);
        assert!(store.list_destination_rules().await.unwrap().is_empty());
        // The store is now the truth for the seeded sections.
        assert!(store
            .get_setting(keys::DESTINATION_RULES_SEEDED_AT)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_setting(keys::USER_LIMITS_SEEDED_AT)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn replace_leaves_absent_sections_alone() {
        let store = seeded_store().await;
        let doc = ImportDoc {
            acl_default_action: Some("deny".into()),
            ..Default::default()
        };
        let report = store
            .import(&doc, ImportMode::Replace, false)
            .await
            .unwrap();
        assert_eq!(report.summary(), "settings +1/-0");
        assert_eq!(store.list_trunks().await.unwrap().len(), 2);
        assert_eq!(store.list_users().await.unwrap().len(), 2);
        assert_eq!(store.list_routes().await.unwrap().len(), 3);
        assert_eq!(
            store
                .get_setting(keys::ACL_DEFAULT_ACTION)
                .await
                .unwrap()
                .as_deref(),
            Some("deny")
        );
        assert!(
            store
                .get_setting(keys::DESTINATION_RULES_SEEDED_AT)
                .await
                .unwrap()
                .is_none(),
            "no destination section, no marker"
        );
    }

    #[tokio::test]
    async fn dry_run_reports_without_writing() {
        let store = seeded_store().await;
        let doc = ImportDoc {
            trunks: Some(vec![trunk("t1")]),
            users: Some(vec![user("z")]),
            acl_default_action: Some("deny".into()),
            ..Default::default()
        };
        let report = store.import(&doc, ImportMode::Replace, true).await.unwrap();
        assert_eq!(report.deleted_trunks, vec!["t2".to_string()]);
        assert_eq!(report.users.unwrap().deleted, 2);
        assert_eq!(
            report.summary(),
            "users +1/~0/-2, trunks +0/~1/-1, settings +1/-0"
        );

        assert_eq!(store.list_trunks().await.unwrap().len(), 2);
        assert_eq!(store.list_users().await.unwrap().len(), 2);
        assert_eq!(store.list_routes().await.unwrap().len(), 3);
        assert!(store
            .get_setting(keys::ACL_DEFAULT_ACTION)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_constraint_violation_is_typed_and_writes_nothing() {
        let store = seeded_store().await;
        let doc = ImportDoc {
            users: Some(vec![user("new")]),
            routes: Some(vec![route("+1", "no-such-trunk", 1)]),
            ..Default::default()
        };
        let err = store
            .import(&doc, ImportMode::Merge, false)
            .await
            .unwrap_err();
        match &err {
            Error::Constraint { table, key, detail } => {
                assert_eq!(table, "routes");
                assert_eq!(key, "+1 → no-such-trunk");
                assert!(detail.contains("FOREIGN KEY"), "{}", detail);
            }
            other => panic!("expected a constraint error, got {:?}", other),
        }
        assert!(err.is_constraint());
        assert_eq!(
            err.to_string(),
            "routes '+1 → no-such-trunk': FOREIGN KEY constraint failed"
        );
        // Users came before routes in the transaction; rolled back.
        assert_eq!(store.list_users().await.unwrap().len(), 2);

        let doc = ImportDoc {
            acl_rules: Some(vec![AclRuleRow {
                action: "maybe".into(),
                ..acl("bad")
            }]),
            ..Default::default()
        };
        let err = store
            .import(&doc, ImportMode::Merge, false)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Constraint { table, .. } if table == "acl_rules"),
            "{}",
            err
        );
    }

    #[tokio::test]
    async fn user_limits_null_removes_settings_only_in_replace_mode() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .set_setting(keys::USER_LIMITS_DEFAULT_CONCURRENT, "3")
            .await
            .unwrap();
        store
            .set_setting(keys::USER_LIMITS_DEFAULT_CPM, "30")
            .await
            .unwrap();

        let doc = ImportDoc {
            user_limits: Some(ImportUserLimits::default()),
            ..Default::default()
        };
        let report = store.import(&doc, ImportMode::Merge, false).await.unwrap();
        assert!(report.settings_removed.is_empty());
        assert_eq!(
            store
                .get_setting(keys::USER_LIMITS_DEFAULT_CPM)
                .await
                .unwrap()
                .as_deref(),
            Some("30")
        );

        let doc = ImportDoc {
            user_limits: Some(ImportUserLimits {
                default_max_concurrent_calls: Some(5),
                default_max_calls_per_minute: None,
            }),
            ..Default::default()
        };
        let report = store
            .import(&doc, ImportMode::Replace, false)
            .await
            .unwrap();
        assert_eq!(
            report.settings_removed,
            vec![keys::USER_LIMITS_DEFAULT_CPM.to_string()]
        );
        assert_eq!(
            report
                .settings_set
                .get(keys::USER_LIMITS_DEFAULT_CONCURRENT)
                .map(String::as_str),
            Some("5")
        );
        assert_eq!(
            store
                .get_setting(keys::USER_LIMITS_DEFAULT_CONCURRENT)
                .await
                .unwrap()
                .as_deref(),
            Some("5")
        );
        assert!(store
            .get_setting(keys::USER_LIMITS_DEFAULT_CPM)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn the_export_shape_deserializes_with_absent_sections() {
        let doc: ImportDoc = serde_json::from_str(
            r#"{"users": [], "user_limits": {"default_max_concurrent_calls": null}}"#,
        )
        .unwrap();
        assert_eq!(doc.users, Some(vec![]));
        assert_eq!(doc.trunks, None);
        assert_eq!(doc.user_limits, Some(ImportUserLimits::default()));
        assert!(serde_json::from_str::<ImportUserLimits>(r#"{"bogus": 1}"#).is_err());
        assert_eq!(ImportMode::parse("replace"), Some(ImportMode::Replace));
        assert_eq!(ImportMode::parse("Replace"), None);
    }
}
