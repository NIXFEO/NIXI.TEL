//! The CDR writer task: `finish_call` pushes a record into a bounded queue
//! (never any IO on the SIP loop); this task batches them into the SQLite
//! store (retrying on errors, records are never dropped on a DB failure),
//! mirrors each batch into the optional JSONL file, imports the legacy
//! JSONL history once at first boot (atomically with its settings marker),
//! and purges rows older than `retention_days` daily.
use crate::metrics::SbcMetrics;
use crate::storage::CdrRecord;
use sbc_storage::{CdrRow, ConfigStore};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

pub const CDR_QUEUE_CAPACITY: usize = 8192;
const BATCH_MAX: usize = 64;
/// Rows per transaction while importing the JSONL history.
const IMPORT_CHUNK: usize = 500;
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
const RETENTION_FIRST_RUN: Duration = Duration::from_secs(60);
const RETENTION_TICK: Duration = Duration::from_secs(24 * 3600);
const PURGE_BATCH: usize = 5000;
/// Settings key written when the JSONL history was imported.
pub const JSONL_IMPORT_MARKER: &str = "cdr_jsonl_imported_at";

pub(crate) enum CdrMsg {
    Record(Box<CdrRecord>),
    Flush(oneshot::Sender<()>),
}

/// `[cdr]` (plus the legacy `[general] cdr_file`).
#[derive(Debug, Clone)]
pub struct CdrWriterConfig {
    /// JSONL mirror of every committed batch (None: no file).
    pub jsonl_path: Option<PathBuf>,
    /// The history to import once (default: the mirror path and its
    /// rotated `.N` siblings, oldest first; `.gz` files are skipped).
    pub import_path: Option<PathBuf>,
    /// 0 = keep everything.
    pub retention_days: u32,
    pub import_jsonl: bool,
}

impl Default for CdrWriterConfig {
    fn default() -> Self {
        Self {
            jsonl_path: None,
            import_path: None,
            retention_days: 0,
            import_jsonl: true,
        }
    }
}

impl CdrWriterConfig {
    pub fn from_config(cfg: &crate::config::SbcConfig) -> Self {
        let jsonl_path = cfg
            .cdr
            .jsonl_path
            .clone()
            .or_else(|| cfg.general.cdr_file.clone())
            .map(PathBuf::from);
        Self {
            import_path: cfg
                .cdr
                .import_path
                .clone()
                .map(PathBuf::from)
                .or_else(|| jsonl_path.clone()),
            jsonl_path,
            retention_days: cfg.cdr.retention_days,
            import_jsonl: cfg.cdr.import_jsonl,
        }
    }
}

pub struct CdrWriter {
    rx: mpsc::Receiver<CdrMsg>,
    store: Arc<ConfigStore>,
    metrics: Arc<SbcMetrics>,
    cfg: CdrWriterConfig,
    queue_len: Arc<AtomicU64>,
    /// Set by `CdrManager::close`: stop retrying a refusing store so the
    /// drain stays inside the shutdown budget (the batch is already in the
    /// JSONL mirror).
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl CdrWriter {
    pub(crate) fn spawn(
        rx: mpsc::Receiver<CdrMsg>,
        store: Arc<ConfigStore>,
        metrics: Arc<SbcMetrics>,
        cfg: CdrWriterConfig,
        queue_len: Arc<AtomicU64>,
        stopping: Arc<std::sync::atomic::AtomicBool>,
    ) -> JoinHandle<()> {
        tokio::spawn(
            Self {
                rx,
                store,
                metrics,
                cfg,
                queue_len,
                stopping,
            }
            .run(),
        )
    }

    async fn run(mut self) {
        if self.cfg.import_jsonl {
            if let Some(path) = self.cfg.import_path.clone() {
                self.import_jsonl_once(&path).await;
            }
        }
        let mut retention = tokio::time::interval_at(
            tokio::time::Instant::now() + RETENTION_FIRST_RUN,
            RETENTION_TICK,
        );
        loop {
            tokio::select! {
                msg = self.rx.recv() => match msg {
                    Some(CdrMsg::Record(r)) => {
                        let mut batch = vec![*r];
                        let mut flushes = Vec::new();
                        while batch.len() < BATCH_MAX {
                            match self.rx.try_recv() {
                                Ok(CdrMsg::Record(r)) => batch.push(*r),
                                Ok(CdrMsg::Flush(tx)) => flushes.push(tx),
                                Err(_) => break,
                            }
                        }
                        self.write_batch(&batch).await;
                        for tx in flushes {
                            let _ = tx.send(());
                        }
                    }
                    Some(CdrMsg::Flush(tx)) => {
                        let _ = tx.send(());
                    }
                    None => break,
                },
                _ = retention.tick(), if self.cfg.retention_days > 0 => {
                    let now = crate::events::event_ts() as i64;
                    match purge_once(&self.store, self.cfg.retention_days, now).await {
                        Ok(n) if n > 0 => {
                            self.metrics.add_cdrs_purged(n);
                            info!("CDR retention: {} record(s) older than {} days purged", n, self.cfg.retention_days);
                        }
                        Ok(_) => {}
                        Err(e) => warn!("CDR retention purge failed: {}", e),
                    }
                }
            }
        }
        info!("CDR writer stopped");
    }

    /// Mirror a batch, then commit it (retrying while the store refuses).
    ///
    /// The JSONL mirror is written *first* on purpose: it is the only
    /// durable copy while the store is failing, and a restart during an
    /// outage would otherwise lose the queue with no trace anywhere.
    async fn write_batch(&self, batch: &[CdrRecord]) {
        let rows: Vec<CdrRow> = batch.iter().map(CdrRecord::to_row).collect();
        if let Some(path) = &self.cfg.jsonl_path {
            if let Err(e) = mirror(path, batch).await {
                self.metrics.inc_cdr_write_error("jsonl");
                warn!("CDR mirror {}: {}", path.display(), e);
            }
        }
        let mut wait = RETRY_MIN;
        loop {
            match self.store.insert_cdrs(&rows).await {
                Ok(n) => {
                    if n < rows.len() {
                        let dup = rows.len() - n;
                        self.metrics.add_cdr_write_errors("duplicate", dup as u64);
                        error!(
                            "CDR: {} record(s) of the batch were already stored (duplicate id/uuid): {:?}",
                            dup,
                            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>()
                        );
                    }
                    self.metrics.record_cdr_written();
                    self.metrics.add_cdrs_written(n as u64);
                    break;
                }
                Err(e) => {
                    self.metrics.inc_cdr_write_error("sqlite");
                    if self.stopping.load(Ordering::Relaxed) {
                        error!(
                            "CDR: storing {} record(s) failed during shutdown ({}) — left in {}",
                            rows.len(),
                            e,
                            self.cfg
                                .jsonl_path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "no mirror configured".into())
                        );
                        break;
                    }
                    error!(
                        "CDR: storing {} record(s) failed ({}) — retrying in {:?}",
                        rows.len(),
                        e,
                        wait
                    );
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                }
            }
        }
        let left = self
            .queue_len
            .fetch_sub(batch.len() as u64, Ordering::Relaxed)
            .saturating_sub(batch.len() as u64);
        self.metrics.set_cdr_queue_length(left);
    }

    /// Commit one import chunk, leaving `chunk` empty. A failure is
    /// logged and counted: the marker is only written at the end, so the
    /// next boot retries what did not land.
    async fn commit_import_chunk(&self, chunk: &mut Vec<CdrRow>) -> usize {
        if chunk.is_empty() {
            return 0;
        }
        let n = match self.store.import_cdr_chunk(chunk).await {
            Ok(n) => n,
            Err(e) => {
                self.metrics.inc_cdr_write_error("sqlite");
                warn!(
                    "CDR import: a chunk of {} record(s) failed ({}) — retried at the next boot",
                    chunk.len(),
                    e
                );
                0
            }
        };
        chunk.clear();
        n
    }

    /// Import the JSONL history once: rotated `.N` siblings oldest first,
    /// then the live file.
    ///
    /// Streamed line by line and committed in chunks of
    /// [`IMPORT_CHUNK`], so a history of any size costs bounded memory (a
    /// whole-file read of a year of CDRs would OOM a small box, and the
    /// boot would then loop). Every row's id is derived from its content,
    /// so the chunks are idempotent and an interrupted import resumes at
    /// the next boot. The marker is written last, in its own transaction.
    async fn import_jsonl_once(&self, path: &Path) {
        match self.store.get_setting(JSONL_IMPORT_MARKER).await {
            Ok(None) => {}
            Ok(Some(_)) => return,
            Err(e) => {
                warn!("CDR import: marker check failed: {}", e);
                return;
            }
        }
        let files = import_files(path);
        if files.is_empty() {
            return;
        }
        let mut parsed = 0usize;
        let mut stored = 0usize;
        let mut skipped = 0usize;
        let mut per_file = Vec::new();
        let mut chunk: Vec<CdrRow> = Vec::with_capacity(IMPORT_CHUNK);
        for f in &files {
            let file = match tokio::fs::File::open(f).await {
                Ok(file) => file,
                Err(e) => {
                    warn!("CDR import: cannot read {}: {}", f.display(), e);
                    continue;
                }
            };
            let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(file));
            let before = parsed;
            loop {
                let line = match lines.next_line().await {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(
                            "CDR import: {} stopped at line {}: {}",
                            f.display(),
                            parsed,
                            e
                        );
                        break;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                match crate::storage::parse_cdr_json(&line) {
                    Some(r) => {
                        let mut row = r.to_row();
                        // A legacy id came from a sub-second clock and can
                        // repeat; two different lines must not collapse
                        // into one row (`INSERT OR IGNORE`). Derive it
                        // from the line instead: same line → same id (so
                        // a resumed import is idempotent), different
                        // lines → different ids.
                        row.id = legacy_row_id(&row.id, &line);
                        parsed += 1;
                        chunk.push(row);
                    }
                    None => skipped += 1,
                }
                if chunk.len() >= IMPORT_CHUNK {
                    stored += self.commit_import_chunk(&mut chunk).await;
                }
            }
            per_file.push(format!("{}={}", f.display(), parsed - before));
        }
        stored += self.commit_import_chunk(&mut chunk).await;
        let marker = format!(
            "{} rows={} stored={} skipped={} files=[{}]",
            crate::sbc::import::now_rfc3339(),
            parsed,
            stored,
            skipped,
            per_file.join(", ")
        );
        match self
            .store
            .import_cdrs(&[], JSONL_IMPORT_MARKER, &marker)
            .await
        {
            Ok(_) => {
                if stored < parsed {
                    // Rows already in the store: a resumed import, or a
                    // marker removed by hand. Say so instead of hiding it.
                    warn!(
                        "CDR import: {} of {} record(s) were already stored",
                        parsed - stored,
                        parsed
                    );
                }
                info!(
                    "CDR import: {} record(s) from {} file(s) stored ({} unparsable line(s) skipped)",
                    stored,
                    files.len(),
                    skipped
                )
            }
            Err(e) => {
                self.metrics.inc_cdr_write_error("sqlite");
                error!(
                    "CDR import failed (nothing stored, retried at next boot): {}",
                    e
                );
            }
        }
        let gz = path
            .parent()
            .and_then(|d| std::fs::read_dir(d).ok())
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.starts_with(
                            &path
                                .file_name()
                                .map(|f| f.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        ) && n.ends_with(".gz")
                    })
                    .count()
            })
            .unwrap_or(0);
        if gz > 0 {
            warn!(
                "CDR import: {} compressed rotated file(s) next to {} were not imported (zcat them into [cdr] import_path before the first boot if needed)",
                gz,
                path.display()
            );
        }
    }
}

/// The live file and its plain rotated siblings, oldest first.
/// A stable id for an imported legacy row: the original id when it is
/// usable, with the line's own fingerprint appended so two different
/// lines that shared a clock-derived id stay two rows. Deterministic, so
/// re-importing the same line is a no-op.
fn legacy_row_id(original: &str, line: &str) -> String {
    // FNV-1a over the line: no dependency, and collisions here would only
    // merge two byte-identical lines, which is the wanted behaviour.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in line.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    if original.is_empty() {
        format!("jsonl-{:016x}", hash)
    } else {
        format!("{}-{:016x}", original, hash)
    }
}

fn import_files(path: &Path) -> Vec<PathBuf> {
    let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
    if let (Some(dir), Some(name)) = (
        path.parent(),
        path.file_name().map(|n| n.to_string_lossy().into_owned()),
    ) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if let Some(suffix) = n.strip_prefix(&format!("{}.", name)) {
                    if let Ok(k) = suffix.parse::<u32>() {
                        rotated.push((k, e.path()));
                    }
                }
            }
        }
    }
    rotated.sort_by_key(|(k, _)| std::cmp::Reverse(*k)); // highest N = oldest
    let mut files: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    if path.exists() {
        files.push(path.to_path_buf());
    }
    files
}

async fn mirror(path: &Path, batch: &[CdrRecord]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    let mut buf = String::new();
    for r in batch {
        buf.push_str(&r.to_json());
        buf.push('\n');
    }
    file.write_all(buf.as_bytes()).await?;
    file.flush().await
}

/// Purge rows started more than `retention_days` before `now`.
pub(crate) async fn purge_once(
    store: &ConfigStore,
    retention_days: u32,
    now: i64,
) -> crate::Result<u64> {
    let cutoff = now - i64::from(retention_days) * 86_400;
    let mut total = 0u64;
    loop {
        let n = store
            .purge_cdrs_started_before(cutoff, PURGE_BATCH)
            .await
            .map_err(|e| crate::Error::Transport(format!("cdr purge: {}", e)))?;
        total += n;
        if n == 0 {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CdrManager;
    use sbc_storage::CdrFilter;

    fn record(n: u32, started: u64) -> CdrRecord {
        let t = std::time::UNIX_EPOCH + Duration::from_secs(started);
        let mut r = CdrRecord::new(format!("c-{}", n), "alice".into(), "bob".into()).with_window(
            t,
            Some(t + Duration::from_secs(5)),
            t + Duration::from_secs(60),
        );
        r.uuid = format!("u-{}", n);
        r.direction = "outbound".into();
        r.sip_code = Some(200);
        r
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sbc-cdr-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A store that refuses every write must not hold the shutdown open,
    /// and the records must still exist somewhere: the JSONL mirror is
    /// written before the commit for exactly that reason.
    #[tokio::test]
    async fn a_broken_store_bounds_close_and_the_mirror_still_has_the_records() {
        let dir = temp_dir("broken");
        let jsonl = dir.join("cdr.jsonl");
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let metrics = Arc::new(SbcMetrics::new());
        let cdr = CdrManager::with_store(
            store.clone(),
            metrics.clone(),
            CdrWriterConfig {
                jsonl_path: Some(jsonl.clone()),
                import_jsonl: false,
                ..CdrWriterConfig::default()
            },
        );
        // Every write from here on fails (disk full, I/O error, …).
        store.pool().close().await;
        cdr.insert(&record(1, 1_700_000_000)).await.unwrap();

        let started = std::time::Instant::now();
        cdr.close(Duration::from_millis(300)).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "close took {:?} — the retry loop must stop at shutdown",
            started.elapsed()
        );
        let mirrored = tokio::fs::read_to_string(&jsonl).await.unwrap_or_default();
        assert!(
            mirrored.contains("\"uuid\":\"u-1\""),
            "the record must survive in the mirror: {:?}",
            mirrored
        );
        assert!(metrics
            .cdr_write_errors
            .lock()
            .unwrap()
            .contains_key("sqlite"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn writer_persists_in_order_flush_waits_and_close_drains() {
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let metrics = Arc::new(SbcMetrics::new());
        let cdr =
            CdrManager::with_store(store.clone(), metrics.clone(), CdrWriterConfig::default());
        for n in 1..=3 {
            cdr.insert(&record(n, 1_700_000_000 + n as u64))
                .await
                .unwrap();
        }
        cdr.flush().await;
        let (rows, more) = store
            .query_cdrs(&CdrFilter {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.uuid.as_str()).collect::<Vec<_>>(),
            ["u-3", "u-2", "u-1"]
        );
        assert!(!more);
        assert_eq!(metrics.cdrs_written_total.load(Ordering::Relaxed), 3);
        assert!(metrics.last_cdr_written_time.load(Ordering::Relaxed) > 0);
        assert_eq!(
            cdr.get_recent(10).await.unwrap().len(),
            3,
            "the cache stays synchronous"
        );
        for n in 4..=53 {
            cdr.insert(&record(n, 1_700_000_100 + n as u64))
                .await
                .unwrap();
        }
        cdr.close(Duration::from_secs(5)).await;
        assert_eq!(store.count_cdrs().await.unwrap(), 53);
        assert_eq!(cdr.backend(), "sqlite");
    }

    #[tokio::test]
    async fn queue_overflow_keeps_the_record_in_cache_and_counts() {
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let metrics = Arc::new(SbcMetrics::new());
        let cdr = CdrManager::with_unspawned_writer_for_tests(store, metrics.clone(), 2);
        for n in 1..=3 {
            cdr.insert(&record(n, 1_700_000_000)).await.unwrap();
        }
        assert_eq!(cdr.get_recent(10).await.unwrap().len(), 3);
        let errors = metrics.cdr_write_errors.lock().unwrap();
        assert_eq!(errors.get("queue"), Some(&1));
    }

    #[tokio::test]
    async fn jsonl_mirror_and_one_time_import_of_rotated_history() {
        let dir = temp_dir("import");
        let live = dir.join("cdr.jsonl");
        // History: cdr.jsonl.2 (oldest), cdr.jsonl.1, live file, plus a gz and garbage.
        std::fs::write(
            dir.join("cdr.jsonl.2"),
            format!("{}\n", record(1, 100).to_json()),
        )
        .unwrap();
        std::fs::write(
            dir.join("cdr.jsonl.1"),
            format!("{}\nnot json\n", record(2, 200).to_json()),
        )
        .unwrap();
        std::fs::write(&live, format!("{}\n", record(3, 300).to_json())).unwrap();
        std::fs::write(dir.join("cdr.jsonl.3.gz"), b"x").unwrap();
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let metrics = Arc::new(SbcMetrics::new());
        let cfg = CdrWriterConfig {
            jsonl_path: Some(live.clone()),
            import_path: Some(live.clone()),
            retention_days: 0,
            import_jsonl: true,
        };
        let cdr = CdrManager::with_store(store.clone(), metrics.clone(), cfg.clone());
        cdr.insert(&record(4, 400)).await.unwrap();
        cdr.flush().await;
        assert_eq!(store.count_cdrs().await.unwrap(), 4, "3 imported + 1 live");
        let marker = store
            .get_setting(JSONL_IMPORT_MARKER)
            .await
            .unwrap()
            .unwrap();
        assert!(
            marker.contains("rows=3") && marker.contains("skipped=1"),
            "{}",
            marker
        );
        let mirrored = std::fs::read_to_string(&live).unwrap();
        assert_eq!(
            mirrored.lines().count(),
            2,
            "the live record was mirrored: {}",
            mirrored
        );
        cdr.close(Duration::from_secs(2)).await;
        // A second boot imports nothing again.
        let cdr2 = CdrManager::with_store(store.clone(), metrics, cfg);
        cdr2.flush().await;
        assert_eq!(store.count_cdrs().await.unwrap(), 4);
        cdr2.close(Duration::from_secs(2)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The history is read line by line and committed in chunks, so a
    /// file larger than memory is fine; two legacy lines that shared a
    /// clock-derived id stay two records; and a re-run stores nothing new.
    #[tokio::test]
    async fn the_history_import_is_chunked_and_keeps_colliding_legacy_ids_apart() {
        let dir = temp_dir("import-chunks");
        let live = dir.join("cdr.jsonl");
        let mut lines = String::new();
        // More lines than one chunk, all sharing one legacy id.
        for n in 0..(IMPORT_CHUNK + 20) {
            let mut r = record(n as u32, 1_000 + n as u64);
            r.id = "same-legacy-id".to_string();
            lines.push_str(&r.to_json());
            lines.push('\n');
        }
        std::fs::write(&live, &lines).unwrap();
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let metrics = Arc::new(SbcMetrics::new());
        let cfg = CdrWriterConfig {
            jsonl_path: None,
            import_path: Some(live.clone()),
            retention_days: 0,
            import_jsonl: true,
        };
        let cdr = CdrManager::with_store(store.clone(), metrics.clone(), cfg.clone());
        cdr.flush().await;
        assert_eq!(
            store.count_cdrs().await.unwrap() as usize,
            IMPORT_CHUNK + 20,
            "every line is its own record despite the shared legacy id"
        );
        let marker = store
            .get_setting(JSONL_IMPORT_MARKER)
            .await
            .unwrap()
            .unwrap();
        assert!(
            marker.contains(&format!("stored={}", IMPORT_CHUNK + 20)),
            "{}",
            marker
        );
        cdr.close(Duration::from_secs(2)).await;

        // Same file, marker cleared by hand: the ids are content-derived,
        // so nothing is duplicated.
        store.delete_setting(JSONL_IMPORT_MARKER).await.unwrap();
        let cdr2 = CdrManager::with_store(store.clone(), metrics, cfg);
        cdr2.flush().await;
        assert_eq!(
            store.count_cdrs().await.unwrap() as usize,
            IMPORT_CHUNK + 20
        );
        cdr2.close(Duration::from_secs(2)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_id_is_derived_from_the_line() {
        let a = legacy_row_id("x", "{\"id\":\"x\",\"caller\":\"a\"}");
        let b = legacy_row_id("x", "{\"id\":\"x\",\"caller\":\"b\"}");
        assert_ne!(a, b, "different lines must not collapse into one row");
        assert_eq!(a, legacy_row_id("x", "{\"id\":\"x\",\"caller\":\"a\"}"));
        assert!(legacy_row_id("", "line").starts_with("jsonl-"));
    }

    #[tokio::test]
    async fn retention_purges_only_older_rows() {
        let store = Arc::new(ConfigStore::open_memory().await.unwrap());
        let now = 1_800_000_000i64;
        let rows = vec![
            record(1, (now - 40 * 86_400) as u64).to_row(),
            record(2, (now - 86_400) as u64).to_row(),
        ];
        store.insert_cdrs(&rows).await.unwrap();
        assert_eq!(purge_once(&store, 30, now).await.unwrap(), 1);
        assert_eq!(store.count_cdrs().await.unwrap(), 1);
    }
}
