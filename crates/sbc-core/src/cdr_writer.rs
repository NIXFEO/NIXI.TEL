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
}

impl CdrWriter {
    pub(crate) fn spawn(
        rx: mpsc::Receiver<CdrMsg>,
        store: Arc<ConfigStore>,
        metrics: Arc<SbcMetrics>,
        cfg: CdrWriterConfig,
        queue_len: Arc<AtomicU64>,
    ) -> JoinHandle<()> {
        tokio::spawn(
            Self {
                rx,
                store,
                metrics,
                cfg,
                queue_len,
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

    /// Commit a batch (retrying until the store takes it), then mirror it.
    async fn write_batch(&self, batch: &[CdrRecord]) {
        let rows: Vec<CdrRow> = batch.iter().map(CdrRecord::to_row).collect();
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
        if let Some(path) = &self.cfg.jsonl_path {
            if let Err(e) = mirror(path, batch).await {
                self.metrics.inc_cdr_write_error("jsonl");
                warn!("CDR mirror {}: {}", path.display(), e);
            }
        }
    }

    /// Import the JSONL history once: rotated `.N` siblings oldest first,
    /// then the live file; every row and the marker commit together.
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
        let mut rows: Vec<CdrRow> = Vec::new();
        let mut skipped = 0usize;
        let mut per_file = Vec::new();
        for f in &files {
            let raw = match tokio::fs::read_to_string(f).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("CDR import: cannot read {}: {}", f.display(), e);
                    continue;
                }
            };
            let before = rows.len();
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                match crate::storage::parse_cdr_json(line) {
                    Some(r) => rows.push(r.to_row()),
                    None => skipped += 1,
                }
            }
            per_file.push(format!("{}={}", f.display(), rows.len() - before));
        }
        let marker = format!(
            "{} rows={} skipped={} files=[{}]",
            crate::sbc::import::now_rfc3339(),
            rows.len(),
            skipped,
            per_file.join(", ")
        );
        match self
            .store
            .import_cdrs(&rows, JSONL_IMPORT_MARKER, &marker)
            .await
        {
            Ok(n) => info!(
                "CDR import: {} record(s) from {} file(s) stored ({} unparsable line(s) skipped)",
                n,
                files.len(),
                skipped
            ),
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
