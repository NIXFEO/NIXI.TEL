//! Call detail records in the store (`cdrs`, migration 0003).
use crate::models::{CdrFilter, CdrRow};
use crate::store::ConfigStore;
use crate::{Error, Result};
use sqlx::QueryBuilder;

const COLUMNS: &str = "id, v, uuid, call_id, direction, caller, callee, source_ip, trunk_id, codec, is_webrtc, started_at, answered_at, ended_at, duration_secs, billable_secs, sip_code, disconnect_reason, reason, hangup_by, rtp_tx_caller, rtp_tx_callee, media_flags";

/// `INSERT OR IGNORE` every row on an open transaction; returns how many
/// were actually stored.
async fn insert_rows_on(conn: &mut sqlx::SqliteConnection, rows: &[CdrRow]) -> Result<usize> {
    let mut n = 0usize;
    for r in rows {
        let mut qb = QueryBuilder::new("");
        push_row(&mut qb, r);
        n += qb
            .build()
            .execute(&mut *conn)
            .await
            .map_err(db_err)?
            .rows_affected() as usize;
    }
    Ok(n)
}

fn db_err(e: sqlx::Error) -> Error {
    Error::Database(e.to_string())
}

fn push_row<'a>(qb: &mut QueryBuilder<'a, sqlx::Sqlite>, r: &'a CdrRow) {
    qb.push("INSERT OR IGNORE INTO cdrs (")
        .push(COLUMNS)
        .push(") VALUES (");
    let mut sep = qb.separated(", ");
    sep.push_bind(&r.id)
        .push_bind(r.v)
        .push_bind(&r.uuid)
        .push_bind(&r.call_id)
        .push_bind(&r.direction)
        .push_bind(&r.caller)
        .push_bind(&r.callee)
        .push_bind(&r.source_ip)
        .push_bind(&r.trunk_id)
        .push_bind(&r.codec)
        .push_bind(r.is_webrtc)
        .push_bind(r.started_at)
        .push_bind(r.answered_at)
        .push_bind(r.ended_at)
        .push_bind(r.duration_secs)
        .push_bind(r.billable_secs)
        .push_bind(r.sip_code)
        .push_bind(&r.disconnect_reason)
        .push_bind(&r.reason)
        .push_bind(&r.hangup_by)
        .push_bind(r.rtp_tx_caller)
        .push_bind(r.rtp_tx_callee)
        .push_bind(&r.media_flags);
    qb.push(")");
}

/// The exclusive upper bound of a prefix range: the prefix with its last
/// character incremented (None when it cannot be incremented).
fn prefix_upper(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    let last = chars.pop()?;
    let next = char::from_u32(last as u32 + 1)?;
    chars.push(next);
    Some(chars.into_iter().collect())
}

impl ConfigStore {
    /// Insert records in one transaction; duplicates (same id or uuid) are
    /// ignored. Returns the number actually inserted.
    pub async fn insert_cdrs(&self, rows: &[CdrRow]) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let mut n = 0usize;
        for r in rows {
            let mut qb = QueryBuilder::new("");
            push_row(&mut qb, r);
            n += qb
                .build()
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected() as usize;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(n)
    }

    /// One-time import: every row and the settings marker commit together,
    /// so an interrupted import leaves nothing behind.
    pub async fn import_cdrs(
        &self,
        rows: &[CdrRow],
        marker_key: &str,
        marker_value: &str,
    ) -> Result<usize> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let n = insert_rows_on(&mut tx, rows).await?;
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(marker_key)
        .bind(marker_value)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(n)
    }

    /// One chunk of an import: the rows commit on their own, without the
    /// marker, so a long history can be loaded in bounded pieces instead
    /// of one transaction that has to hold everything in memory. The rows
    /// are idempotent (`INSERT OR IGNORE` on a content-derived id), so an
    /// interrupted import simply resumes at the next boot.
    pub async fn import_cdr_chunk(&self, rows: &[CdrRow]) -> Result<usize> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let n = insert_rows_on(&mut tx, rows).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(n)
    }

    /// Newest first (`started_at DESC, rowid DESC`); the bool says whether
    /// more rows exist beyond `limit`.
    pub async fn query_cdrs(&self, f: &CdrFilter) -> Result<(Vec<CdrRow>, bool)> {
        let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new("SELECT rowid AS rowid, ");
        qb.push(COLUMNS).push(" FROM cdrs WHERE 1=1");
        if let Some(from) = f.from {
            qb.push(" AND started_at >= ").push_bind(from);
        }
        if let Some(to) = f.to {
            qb.push(" AND started_at < ").push_bind(to);
        }
        if let Some(d) = &f.direction {
            qb.push(" AND direction = ").push_bind(d.clone());
        }
        if let Some(t) = &f.trunk {
            qb.push(" AND trunk_id = ").push_bind(t.clone());
        }
        if let Some(u) = &f.uuid {
            // `uuid <> ''` lets SQLite use the partial unique index
            // (`WHERE uuid <> ''`) instead of scanning the table; an empty
            // uuid never identifies a call anyway.
            qb.push(" AND uuid <> '' AND uuid = ").push_bind(u.clone());
        }
        if let Some(c) = &f.call_id {
            qb.push(" AND call_id = ").push_bind(c.clone());
        }
        for (col, prefix) in [("caller", &f.caller_prefix), ("callee", &f.callee_prefix)] {
            if let Some(p) = prefix.as_deref().filter(|p| !p.is_empty()) {
                qb.push(format!(" AND {} >= ", col))
                    .push_bind(p.to_string());
                if let Some(hi) = prefix_upper(p) {
                    qb.push(format!(" AND {} < ", col)).push_bind(hi);
                }
            }
        }
        if let Some(code) = f.sip_code {
            qb.push(" AND sip_code = ").push_bind(code);
        }
        match f.answered {
            Some(true) => {
                qb.push(" AND answered_at IS NOT NULL");
            }
            Some(false) => {
                qb.push(" AND answered_at IS NULL");
            }
            None => {}
        }
        if let Some((started, rowid)) = f.before {
            qb.push(" AND (started_at < ")
                .push_bind(started)
                .push(" OR (started_at = ")
                .push_bind(started)
                .push(" AND rowid < ")
                .push_bind(rowid)
                .push("))");
        }
        let limit = f.limit.max(1) as i64;
        qb.push(" ORDER BY started_at DESC, rowid DESC LIMIT ")
            .push_bind(limit + 1)
            .push(" OFFSET ")
            .push_bind(f.offset as i64);
        let mut rows: Vec<CdrRow> = qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        rows.truncate(limit as usize);
        Ok((rows, has_more))
    }

    /// Delete up to `batch` rows started before `cutoff`; loop until 0.
    pub async fn purge_cdrs_started_before(&self, cutoff: i64, batch: usize) -> Result<u64> {
        let res = sqlx::query(
            "DELETE FROM cdrs WHERE rowid IN (SELECT rowid FROM cdrs WHERE started_at < ? LIMIT ?)",
        )
        .bind(cutoff)
        .bind(batch as i64)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected())
    }

    pub async fn count_cdrs(&self) -> Result<i64> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cdrs")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn row(
        id: &str,
        started: i64,
        caller: &str,
        callee: &str,
        trunk: Option<&str>,
        direction: &str,
        answered: bool,
        code: i64,
    ) -> CdrRow {
        CdrRow {
            rowid: 0,
            id: id.into(),
            v: 2,
            uuid: format!("u-{}", id),
            call_id: format!("c-{}", id),
            direction: direction.into(),
            caller: caller.into(),
            callee: callee.into(),
            source_ip: "10.0.0.9".into(),
            trunk_id: trunk.map(String::from),
            codec: Some("PCMU".into()),
            is_webrtc: false,
            started_at: started,
            answered_at: answered.then_some(started + 5),
            ended_at: started + 60,
            duration_secs: 60,
            billable_secs: if answered { 55 } else { 0 },
            sip_code: Some(code),
            disconnect_reason: "normal-clearing".into(),
            reason: None,
            hangup_by: "caller".into(),
            rtp_tx_caller: 1500,
            rtp_tx_callee: 1500,
            media_flags: String::new(),
        }
    }

    async fn seeded() -> ConfigStore {
        let store = ConfigStore::open_memory().await.unwrap();
        let rows = vec![
            row(
                "1",
                100,
                "alice",
                "+33612",
                Some("t1"),
                "outbound",
                true,
                200,
            ),
            row(
                "2",
                200,
                "alice",
                "+33699",
                Some("t1"),
                "outbound",
                false,
                486,
            ),
            row("3", 300, "bob", "+33612", Some("t2"), "outbound", true, 200),
            row(
                "4",
                400,
                "+33612",
                "alice",
                Some("t1"),
                "inbound",
                true,
                200,
            ),
            row("5", 500, "carol", "bob", None, "local", false, 487),
            row(
                "6",
                600,
                "alicia",
                "+3361299",
                Some("t2"),
                "outbound",
                true,
                200,
            ),
        ];
        assert_eq!(store.insert_cdrs(&rows).await.unwrap(), 6);
        store
    }

    fn ids(rows: &[CdrRow]) -> Vec<&str> {
        rows.iter().map(|r| r.id.as_str()).collect()
    }

    #[tokio::test]
    async fn insert_is_idempotent_and_pages_newest_first() {
        let store = seeded().await;
        let again = vec![row("1", 100, "x", "y", None, "outbound", true, 200)];
        assert_eq!(
            store.insert_cdrs(&again).await.unwrap(),
            0,
            "same id ignored"
        );
        let dup_uuid = CdrRow {
            id: "7".into(),
            ..row("1", 700, "x", "y", None, "outbound", true, 200)
        };
        assert_eq!(
            store.insert_cdrs(&[dup_uuid]).await.unwrap(),
            0,
            "same uuid ignored"
        );
        assert_eq!(store.count_cdrs().await.unwrap(), 6);
        let (rows, more) = store
            .query_cdrs(&CdrFilter {
                limit: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(ids(&rows), ["6", "5"]);
        assert!(more);
        let (rows, more) = store
            .query_cdrs(&CdrFilter {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 6);
        assert!(!more);
    }

    #[tokio::test]
    async fn filters_and_prefix_ranges() {
        let store = seeded().await;
        let store_ref = &store;
        let q = |f: CdrFilter| async move {
            store_ref
                .query_cdrs(&CdrFilter { limit: 10, ..f })
                .await
                .unwrap()
                .0
        };
        assert_eq!(
            ids(&q(CdrFilter {
                from: Some(200),
                to: Some(400),
                ..Default::default()
            })
            .await),
            ["3", "2"],
            "from inclusive, to exclusive"
        );
        assert_eq!(
            ids(&q(CdrFilter {
                direction: Some("inbound".into()),
                ..Default::default()
            })
            .await),
            ["4"]
        );
        assert_eq!(
            ids(&q(CdrFilter {
                trunk: Some("t2".into()),
                ..Default::default()
            })
            .await),
            ["6", "3"]
        );
        assert_eq!(
            ids(&q(CdrFilter {
                caller_prefix: Some("ali".into()),
                ..Default::default()
            })
            .await),
            ["6", "2", "1"],
            "prefix, case-sensitive"
        );
        assert_eq!(
            ids(&q(CdrFilter {
                caller_prefix: Some("Ali".into()),
                ..Default::default()
            })
            .await),
            Vec::<&str>::new()
        );
        assert_eq!(
            ids(&q(CdrFilter {
                callee_prefix: Some("+33612".into()),
                ..Default::default()
            })
            .await),
            ["6", "3", "1"],
            "+33612 and +3361299, not +33699"
        );
        assert_eq!(
            ids(&q(CdrFilter {
                sip_code: Some(486),
                ..Default::default()
            })
            .await),
            ["2"]
        );
        assert_eq!(
            ids(&q(CdrFilter {
                answered: Some(false),
                ..Default::default()
            })
            .await),
            ["5", "2"]
        );
        assert_eq!(
            ids(&q(CdrFilter {
                uuid: Some("u-3".into()),
                ..Default::default()
            })
            .await),
            ["3"]
        );
        assert_eq!(
            ids(&q(CdrFilter {
                call_id: Some("c-4".into()),
                ..Default::default()
            })
            .await),
            ["4"]
        );
    }

    #[tokio::test]
    async fn keyset_cursor_matches_offset_paging() {
        let store = seeded().await;
        let mut by_cursor = Vec::new();
        let mut before = None;
        loop {
            let (rows, more) = store
                .query_cdrs(&CdrFilter {
                    limit: 2,
                    before,
                    ..Default::default()
                })
                .await
                .unwrap();
            by_cursor.extend(rows.iter().map(|r| r.id.clone()));
            if !more {
                break;
            }
            let last = rows.last().unwrap();
            before = Some((last.started_at, last.rowid));
        }
        let mut by_offset = Vec::new();
        for offset in (0..6).step_by(2) {
            let (rows, _) = store
                .query_cdrs(&CdrFilter {
                    limit: 2,
                    offset,
                    ..Default::default()
                })
                .await
                .unwrap();
            by_offset.extend(rows.iter().map(|r| r.id.clone()));
        }
        assert_eq!(by_cursor, by_offset);
        assert_eq!(by_cursor.len(), 6);
    }

    #[tokio::test]
    async fn purge_batches_and_import_is_atomic_with_its_marker() {
        let store = seeded().await;
        assert_eq!(store.purge_cdrs_started_before(400, 2).await.unwrap(), 2);
        assert_eq!(store.purge_cdrs_started_before(400, 2).await.unwrap(), 1);
        assert_eq!(store.purge_cdrs_started_before(400, 2).await.unwrap(), 0);
        assert_eq!(store.count_cdrs().await.unwrap(), 3);
        let imported = vec![row("9", 50, "x", "y", None, "outbound", true, 200)];
        assert_eq!(
            store
                .import_cdrs(&imported, "cdr_jsonl_imported_at", "now rows=1")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .get_setting("cdr_jsonl_imported_at")
                .await
                .unwrap()
                .as_deref(),
            Some("now rows=1")
        );
        assert_eq!(prefix_upper("+336").as_deref(), Some("+337"));
        assert_eq!(prefix_upper(""), None);
    }
}
