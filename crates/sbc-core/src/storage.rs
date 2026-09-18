//! Storage — Call Detail Records (CDR).
//!
//! Two backends: in-memory (tests) and a JSON-lines file (production,
//! `[general] cdr_file`). Dynamic configuration lives in `sbc-storage`.

use crate::{Error, Result};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Call Detail Record.
///
/// Legacy keys (`v` = 1 rows, written before 0.20) keep their names and
/// types; `v` = 2 rows add the billing window (`answered_at`,
/// `billable_secs`), the final status toward the caller (`sip_code`), the
/// `direction`, the B2BUA `uuid`, the caller's `source_ip` and the SIP
/// `reason` (Q.850) when one was given. `duration_secs` stays the
/// setup→end span; bill on `billable_secs`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CdrRecord {
    #[serde(default = "uuid_v4")]
    pub id: String,
    pub call_id: String,
    pub caller: String,
    pub callee: String,
    pub trunk_id: Option<String>,
    /// Seconds from the INVITE to the end of the call (ring time included).
    pub duration_secs: u64,
    pub codec: Option<String>,
    pub is_webrtc: bool,
    /// normal-clearing | cancelled | rejected-<code> | timeout | shutdown |
    /// ws-closed | admin-kick | dialog-lost | rtp-timeout | setup-timeout
    pub disconnect_reason: String,
    /// Unix seconds of the INVITE.
    pub started_at: u64,
    /// Unix seconds of the end of the call.
    pub ended_at: u64,
    /// Record schema version (1 = before 0.20, no billing window).
    #[serde(default = "legacy_version")]
    pub v: u8,
    #[serde(default)]
    pub uuid: String,
    /// outbound (user → trunk) | inbound (trunk → user) | local (user → user)
    #[serde(default)]
    pub direction: String,
    /// Final status the caller's INVITE got (200 when answered).
    #[serde(default)]
    pub sip_code: Option<u16>,
    /// Unix seconds of the 200 OK toward the caller; None = never answered.
    #[serde(default)]
    pub answered_at: Option<u64>,
    /// Seconds from the answer to the end; 0 when never answered.
    #[serde(default)]
    pub billable_secs: u64,
    #[serde(default)]
    pub source_ip: String,
    /// SIP Reason header (peer's on a BYE, the SBC's own otherwise).
    #[serde(default)]
    pub reason: Option<String>,
    /// Who ended the call: caller | callee | sbc ("" on legacy rows).
    #[serde(default)]
    pub hangup_by: String,
}

fn legacy_version() -> u8 {
    1
}

pub const CDR_SCHEMA_VERSION: u8 = 2;

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl CdrRecord {
    pub fn new(call_id: String, caller: String, callee: String) -> Self {
        let now = unix_secs(SystemTime::now());
        Self {
            id: uuid_v4(),
            call_id,
            caller,
            callee,
            trunk_id: None,
            duration_secs: 0,
            codec: None,
            is_webrtc: false,
            disconnect_reason: "normal".to_string(),
            started_at: now,
            ended_at: now,
            v: CDR_SCHEMA_VERSION,
            uuid: String::new(),
            direction: String::new(),
            sip_code: None,
            answered_at: None,
            billable_secs: 0,
            source_ip: String::new(),
            reason: None,
            hangup_by: String::new(),
        }
    }

    /// The call's real window: `started` = INVITE, `answered` = 200 OK
    /// toward the caller (None when never answered), `ended` = teardown.
    /// `duration_secs` is the whole span, `billable_secs` the answered part.
    pub fn with_window(
        mut self,
        started: SystemTime,
        answered: Option<SystemTime>,
        ended: SystemTime,
    ) -> Self {
        let started_s = unix_secs(started);
        let ended_s = unix_secs(ended).max(started_s);
        self.started_at = started_s;
        self.ended_at = ended_s;
        self.duration_secs = ended_s - started_s;
        self.answered_at = answered.map(unix_secs);
        self.billable_secs = self
            .answered_at
            .map(|a| ended_s.saturating_sub(a))
            .unwrap_or(0);
        self
    }

    /// Legacy helper: `ended_at = started_at + secs` (no answer time).
    pub fn with_duration(mut self, secs: u64) -> Self {
        self.duration_secs = secs;
        self.ended_at = self.started_at + secs;
        self
    }

    pub fn with_codec(mut self, codec: &str) -> Self {
        self.codec = Some(codec.to_string());
        self
    }

    pub fn with_webrtc(mut self, webrtc: bool) -> Self {
        self.is_webrtc = webrtc;
        self
    }

    pub fn with_disconnect_reason(mut self, reason: &str) -> Self {
        self.disconnect_reason = reason.to_string();
        self
    }

    /// One JSON object (JSON-lines file format and API items). Legacy keys
    /// come first, in their historical order.
    /// The store row of this record (`cdrs`, migration 0003).
    pub fn to_row(&self) -> sbc_storage::CdrRow {
        sbc_storage::CdrRow {
            rowid: 0,
            id: self.id.clone(),
            v: i64::from(self.v),
            uuid: self.uuid.clone(),
            call_id: self.call_id.clone(),
            direction: self.direction.clone(),
            caller: self.caller.clone(),
            callee: self.callee.clone(),
            source_ip: self.source_ip.clone(),
            trunk_id: self.trunk_id.clone(),
            codec: self.codec.clone(),
            is_webrtc: self.is_webrtc,
            started_at: self.started_at as i64,
            answered_at: self.answered_at.map(|t| t as i64),
            ended_at: self.ended_at as i64,
            duration_secs: self.duration_secs as i64,
            billable_secs: self.billable_secs as i64,
            sip_code: self.sip_code.map(i64::from),
            disconnect_reason: self.disconnect_reason.clone(),
            reason: self.reason.clone(),
            hangup_by: self.hangup_by.clone(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            error!("CDR serialization failed: {}", e);
            format!(
                r#"{{"id":"{}","call_id":"{}","error":"serialize"}}"#,
                self.id, self.call_id
            )
        })
    }
}

/// Most recent records kept in memory for the API; the file is the source
/// of truth for billing.
pub const MAX_CACHED_CDRS: usize = 10_000;

impl From<sbc_storage::CdrRow> for CdrRecord {
    fn from(r: sbc_storage::CdrRow) -> Self {
        Self {
            id: r.id,
            call_id: r.call_id,
            caller: r.caller,
            callee: r.callee,
            trunk_id: r.trunk_id,
            duration_secs: r.duration_secs.max(0) as u64,
            codec: r.codec,
            is_webrtc: r.is_webrtc,
            disconnect_reason: r.disconnect_reason,
            started_at: r.started_at.max(0) as u64,
            ended_at: r.ended_at.max(0) as u64,
            v: u8::try_from(r.v).unwrap_or(CDR_SCHEMA_VERSION),
            uuid: r.uuid,
            direction: r.direction,
            sip_code: r.sip_code.and_then(|c| u16::try_from(c).ok()),
            answered_at: r.answered_at.map(|t| t.max(0) as u64),
            billable_secs: r.billable_secs.max(0) as u64,
            source_ip: r.source_ip,
            reason: r.reason,
            hangup_by: r.hangup_by,
        }
    }
}

/// What `CdrManager::insert` did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrInsert {
    /// Queued for the store writer (durable within milliseconds).
    Queued,
    /// Written by the file/memory backend (no store).
    Stored,
    /// The writer queue was full or closed: the record lives in the cache only.
    CacheOnly,
}

/// Statistiques de stockage
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub total_cdrs: usize,
    pub total_inserts: u64,
    pub total_errors: u64,
    pub backend: String,
}

/// Interface de stockage CDR (trait pour faciliter les tests/mocks)
#[async_trait::async_trait]
pub trait CdrStorage: Send + Sync {
    async fn insert_cdr(&self, record: &CdrRecord) -> Result<()>;
    async fn get_cdr(&self, call_id: &str) -> Result<Option<CdrRecord>>;
    async fn list_recent_cdrs(&self, limit: usize) -> Result<Vec<CdrRecord>>;
    async fn stats(&self) -> StorageStats;
}

/// Stockage en mémoire (pour développement et tests)
pub struct InMemoryCdrStorage {
    records: Arc<Mutex<std::collections::VecDeque<CdrRecord>>>,
    insert_count: Arc<std::sync::atomic::AtomicU64>,
    error_count: Arc<std::sync::atomic::AtomicU64>,
}

impl InMemoryCdrStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            insert_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            error_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn note_error(&self) {
        self.error_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for InMemoryCdrStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl CdrStorage for InMemoryCdrStorage {
    async fn insert_cdr(&self, record: &CdrRecord) -> Result<()> {
        let mut records = self.records.lock().await;
        if records.len() >= MAX_CACHED_CDRS {
            records.pop_front();
        }
        records.push_back(record.clone());
        self.insert_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("CDR inserted in memory: call_id={}", record.call_id);
        Ok(())
    }

    async fn get_cdr(&self, call_id: &str) -> Result<Option<CdrRecord>> {
        let records = self.records.lock().await;
        Ok(records.iter().find(|r| r.call_id == call_id).cloned())
    }

    async fn list_recent_cdrs(&self, limit: usize) -> Result<Vec<CdrRecord>> {
        let records = self.records.lock().await;
        let count = records.len();
        let start = count.saturating_sub(limit);
        Ok(records.range(start..).cloned().collect())
    }

    async fn stats(&self) -> StorageStats {
        let records = self.records.lock().await;
        StorageStats {
            total_cdrs: records.len(),
            total_inserts: self.insert_count.load(std::sync::atomic::Ordering::Relaxed),
            total_errors: self.error_count.load(std::sync::atomic::Ordering::Relaxed),
            backend: "memory".to_string(),
        }
    }
}

/// File-based CDR storage (JSON-lines format — one JSON object per line)
/// Persists CDRs to disk for production use without a database.
/// Thread-safe with async file I/O.
pub struct FileCdrStorage {
    path: std::path::PathBuf,
    inner: InMemoryCdrStorage,
}

impl FileCdrStorage {
    pub async fn new(path: &str) -> Result<Self> {
        let path = std::path::PathBuf::from(path);
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    Error::Config(format!("Cannot create CDR directory {:?}: {}", parent, e))
                })?;
            }
        }
        // Load existing CDRs from file (if it exists)
        let inner = InMemoryCdrStorage::new();
        if path.exists() {
            match tokio::fs::File::open(&path).await {
                Ok(file) => {
                    use tokio::io::AsyncBufReadExt;
                    // Stream the file: only the last MAX_CACHED_CDRS rows are
                    // kept, without ever holding the whole file in memory.
                    let mut tail: std::collections::VecDeque<CdrRecord> =
                        std::collections::VecDeque::with_capacity(1024);
                    let mut skipped = 0u64;
                    let mut older = 0u64;
                    let mut lines = tokio::io::BufReader::new(file).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let line = line.trim();
                        if line.is_empty() || !line.starts_with('{') {
                            continue;
                        }
                        match parse_cdr_json(line) {
                            Some(record) => {
                                if tail.len() >= MAX_CACHED_CDRS {
                                    tail.pop_front();
                                    older += 1;
                                }
                                tail.push_back(record);
                            }
                            None => skipped += 1,
                        }
                    }
                    let loaded = tail.len();
                    *inner.records.lock().await = tail;
                    info!(
                        "CDR file storage: loaded {} records from {:?} ({} unparsable, {} older rows left on disk)",
                        loaded, path, skipped, older
                    );
                }
                Err(e) => {
                    warn!(
                        "CDR file storage: could not read {:?}: {} (starting fresh)",
                        path, e
                    );
                }
            }
        } else {
            info!("CDR file storage: new file at {:?}", path);
        }
        Ok(Self { path, inner })
    }
}

#[async_trait::async_trait]
impl CdrStorage for FileCdrStorage {
    async fn insert_cdr(&self, record: &CdrRecord) -> Result<()> {
        // Write to file first (append mode)
        let json_line = format!("{}\n", record.to_json());
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = file.write_all(json_line.as_bytes()).await {
                    error!("CDR file write error: {}", e);
                    self.inner.note_error();
                    return Err(Error::Transport(format!("CDR file write: {}", e)));
                }
                // Flush so data reaches the kernel buffer before the handle drops.
                if let Err(e) = file.flush().await {
                    error!("CDR file flush error: {}", e);
                    self.inner.note_error();
                    return Err(Error::Transport(format!("CDR file write: {}", e)));
                }
            }
            Err(e) => {
                error!("CDR file open error: {}", e);
                self.inner.note_error();
                return Err(Error::Transport(format!("CDR file open: {}", e)));
            }
        }
        // Also keep in memory for fast queries
        self.inner.insert_cdr(record).await
    }

    async fn get_cdr(&self, call_id: &str) -> Result<Option<CdrRecord>> {
        self.inner.get_cdr(call_id).await
    }

    async fn list_recent_cdrs(&self, limit: usize) -> Result<Vec<CdrRecord>> {
        self.inner.list_recent_cdrs(limit).await
    }

    async fn stats(&self) -> StorageStats {
        let mut stats = self.inner.stats().await;
        stats.backend = format!("file:{}", self.path.display());
        stats
    }
}

/// Parse one JSON line: serde for well-formed rows (v1 and v2), the
/// historical substring parser as a fallback for damaged legacy lines.
pub(crate) fn parse_cdr_json(json: &str) -> Option<CdrRecord> {
    match serde_json::from_str::<CdrRecord>(json) {
        Ok(r) => Some(r),
        Err(_) => parse_cdr_json_legacy(json),
    }
}

/// Minimal substring parser for pre-0.20 lines that serde rejects.
fn parse_cdr_json_legacy(json: &str) -> Option<CdrRecord> {
    // Extract fields from JSON object using simple string matching
    let get_str = |key: &str| -> Option<String> {
        let search = format!("\"{}\":\"", key);
        if let Some(pos) = json.find(&search) {
            let start = pos + search.len();
            let rest = &json[start..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
        None
    };
    let get_u64 = |key: &str| -> u64 {
        let search1 = format!("\"{}\":", key);
        if let Some(pos) = json.find(&search1) {
            let start = pos + search1.len();
            let rest = json[start..].trim();
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return num_str.parse().unwrap_or(0);
        }
        0
    };
    let get_bool = |key: &str| -> bool {
        let search = format!("\"{}\":true", key);
        json.contains(&search)
    };

    let call_id = get_str("call_id")?;
    let caller = get_str("caller").unwrap_or_default();
    let callee = get_str("callee").unwrap_or_default();

    Some(CdrRecord {
        id: get_str("id").unwrap_or_else(uuid_v4),
        call_id,
        caller,
        callee,
        trunk_id: get_str("trunk_id"),
        duration_secs: get_u64("duration_secs"),
        codec: get_str("codec"),
        is_webrtc: get_bool("is_webrtc"),
        disconnect_reason: get_str("disconnect_reason").unwrap_or_else(|| "unknown".to_string()),
        started_at: get_u64("started_at"),
        ended_at: get_u64("ended_at"),
        v: 1,
        uuid: String::new(),
        direction: String::new(),
        sip_code: None,
        answered_at: None,
        billable_secs: 0,
        source_ip: String::new(),
        reason: None,
        hangup_by: String::new(),
    })
}

/// UUID v4 simple (hex aléatoire)
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// CDR Manager — orchestre le stockage
pub struct CdrManager {
    /// The in-memory cache (and, without a store, the file backend).
    storage: Arc<dyn CdrStorage>,
    /// Store mode: the writer task's queue.
    tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<crate::cdr_writer::CdrMsg>>>,
    writer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    queue_len: Arc<std::sync::atomic::AtomicU64>,
    store: Option<Arc<sbc_storage::ConfigStore>>,
    metrics: Option<Arc<crate::metrics::SbcMetrics>>,
    backend_name: &'static str,
    /// Shutdown signal for the writer task (see `close`).
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl CdrManager {
    fn without_store(storage: Arc<dyn CdrStorage>, backend_name: &'static str) -> Self {
        Self {
            storage,
            tx: std::sync::Mutex::new(None),
            writer: std::sync::Mutex::new(None),
            queue_len: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            store: None,
            metrics: None,
            backend_name,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn new_memory() -> Self {
        Self::without_store(Arc::new(InMemoryCdrStorage::new()), "memory")
    }

    pub fn with_storage(storage: Arc<dyn CdrStorage>) -> Self {
        Self::without_store(storage, "custom")
    }

    /// Store mode: records are cached and queued to a writer task that
    /// commits them to SQLite (needs a runtime).
    pub fn with_store(
        store: Arc<sbc_storage::ConfigStore>,
        metrics: Arc<crate::metrics::SbcMetrics>,
        cfg: crate::cdr_writer::CdrWriterConfig,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(crate::cdr_writer::CDR_QUEUE_CAPACITY);
        let queue_len = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = crate::cdr_writer::CdrWriter::spawn(
            rx,
            store.clone(),
            metrics.clone(),
            cfg,
            queue_len.clone(),
            stopping.clone(),
        );
        Self {
            storage: Arc::new(InMemoryCdrStorage::new()),
            tx: std::sync::Mutex::new(Some(tx)),
            writer: std::sync::Mutex::new(Some(writer)),
            queue_len,
            store: Some(store),
            metrics: Some(metrics),
            backend_name: "sqlite",
            stopping,
        }
    }

    /// A store-mode manager whose writer is never spawned (queue tests).
    #[cfg(test)]
    pub(crate) fn with_unspawned_writer_for_tests(
        store: Arc<sbc_storage::ConfigStore>,
        metrics: Arc<crate::metrics::SbcMetrics>,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        std::mem::forget(rx);
        Self {
            storage: Arc::new(InMemoryCdrStorage::new()),
            tx: std::sync::Mutex::new(Some(tx)),
            writer: std::sync::Mutex::new(None),
            queue_len: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            store: Some(store),
            metrics: Some(metrics),
            backend_name: "sqlite",
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get a reference to the underlying storage (for direct CDR inserts)
    pub fn storage(&self) -> &dyn CdrStorage {
        self.storage.as_ref()
    }

    /// Create a CDR manager with file-based storage (JSON-lines)
    pub async fn new_file(path: &str) -> Result<Self> {
        let storage = FileCdrStorage::new(path).await?;
        Ok(Self::without_store(Arc::new(storage), "file"))
    }

    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }

    /// `sqlite` (store mode), `file` or `memory`.
    pub fn backend(&self) -> &'static str {
        self.backend_name
    }

    pub fn queue_len(&self) -> u64 {
        self.queue_len.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn sender(&self) -> Option<tokio::sync::mpsc::Sender<crate::cdr_writer::CdrMsg>> {
        self.tx.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Store one finished call's record (the SBC's single write path). In
    /// store mode this never does IO: the record goes to the cache and the
    /// writer's queue.
    pub async fn insert(&self, record: &CdrRecord) -> Result<CdrInsert> {
        let Some(tx) = self.sender() else {
            self.storage.insert_cdr(record).await?;
            return Ok(CdrInsert::Stored);
        };
        let _ = self.storage.insert_cdr(record).await;
        match tx.try_send(crate::cdr_writer::CdrMsg::Record(Box::new(record.clone()))) {
            Ok(()) => {
                let n = self
                    .queue_len
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if let Some(m) = &self.metrics {
                    m.set_cdr_queue_length(n);
                }
                Ok(CdrInsert::Queued)
            }
            Err(e) => {
                if let Some(m) = &self.metrics {
                    m.inc_cdr_write_error("queue");
                }
                error!(
                    "CDR writer queue unavailable ({}): record {} kept in the memory cache only",
                    e, record.id
                );
                Ok(CdrInsert::CacheOnly)
            }
        }
    }

    /// Wait until everything queued so far is committed (no-op without a writer).
    pub async fn flush(&self) {
        let Some(tx) = self.sender() else { return };
        let (ack, done) = tokio::sync::oneshot::channel();
        if tx.send(crate::cdr_writer::CdrMsg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Drain the queue and stop the writer (shutdown), bounded by
    /// `timeout` **as a whole**: a store that refuses every write (disk
    /// full) must not hold the SIP shutdown open. The writer stops
    /// retrying as soon as this is called; what it could not commit is in
    /// the JSONL mirror.
    pub async fn close(&self, timeout: std::time::Duration) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let deadline = tokio::time::Instant::now() + timeout;
        if tokio::time::timeout_at(deadline, self.flush())
            .await
            .is_err()
        {
            warn!(
                "CDR writer did not drain within {:?} — {} record(s) still queued",
                timeout,
                self.queue_len()
            );
        }
        let tx = self.tx.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(tx);
        let handle = self.writer.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            if tokio::time::timeout_at(deadline, h).await.is_err() {
                warn!("CDR writer did not stop within {:?}", timeout);
            }
        }
    }

    /// A filtered page from the store (newest first) and whether more
    /// rows exist. Errors without a store.
    pub async fn page(
        &self,
        filter: &sbc_storage::CdrFilter,
    ) -> Result<(Vec<sbc_storage::CdrRow>, bool)> {
        let Some(store) = &self.store else {
            return Err(Error::Config("no CDR store".into()));
        };
        store
            .query_cdrs(filter)
            .await
            .map_err(|e| Error::Transport(format!("cdr query: {}", e)))
    }

    /// The store behind this manager, when any.
    pub fn store(&self) -> Option<Arc<sbc_storage::ConfigStore>> {
        self.store.clone()
    }

    /// Enregistrer un appel terminé (legacy helper, tests only: no window).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_call(
        &self,
        call_id: &str,
        caller: &str,
        callee: &str,
        duration_secs: u64,
        is_webrtc: bool,
        codec: Option<&str>,
        reason: &str,
    ) -> Result<()> {
        let mut record =
            CdrRecord::new(call_id.to_string(), caller.to_string(), callee.to_string())
                .with_duration(duration_secs)
                .with_webrtc(is_webrtc)
                .with_disconnect_reason(reason);

        if let Some(c) = codec {
            record = record.with_codec(c);
        }

        self.insert(&record).await?;
        info!(
            "CDR recorded: {} → {} ({} secs, webrtc={})",
            caller, callee, duration_secs, is_webrtc
        );
        Ok(())
    }

    pub async fn get_recent(&self, limit: usize) -> Result<Vec<CdrRecord>> {
        self.storage.list_recent_cdrs(limit).await
    }

    /// Paginated recent CDRs, **newest first**: skip `offset`, take `limit`.
    /// The fetch window is capped at offset+limit (and at the in-memory
    /// cache), so the returned count only signals whether more pages may
    /// exist.
    pub async fn get_page(&self, limit: usize, offset: usize) -> Result<(Vec<CdrRecord>, usize)> {
        let mut window = self
            .storage
            .list_recent_cdrs(offset.saturating_add(limit))
            .await?;
        let total = window.len();
        window.reverse();
        let page = window.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }

    pub async fn stats(&self) -> StorageStats {
        self.storage.stats().await
    }

    /// Formatter les CDR récents en JSON
    pub async fn recent_to_json(&self, limit: usize) -> String {
        match self.get_recent(limit).await {
            Ok(cdrs) => {
                let items: Vec<String> = cdrs.iter().map(|c| c.to_json()).collect();
                format!("[{}]", items.join(","))
            }
            Err(e) => {
                error!("Failed to get CDR: {}", e);
                "[]".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_window_computes_the_billing_window() {
        let t0 = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let r = CdrRecord::new("c".into(), "a".into(), "b".into()).with_window(
            t0,
            Some(t0 + std::time::Duration::from_secs(20)),
            t0 + std::time::Duration::from_secs(80),
        );
        assert_eq!(r.v, CDR_SCHEMA_VERSION);
        assert_eq!(r.started_at, 1_700_000_000);
        assert_eq!(r.answered_at, Some(1_700_000_020));
        assert_eq!(r.ended_at, 1_700_000_080);
        assert_eq!(r.duration_secs, 80, "setup → end");
        assert_eq!(r.billable_secs, 60, "answer → end");

        let unanswered = CdrRecord::new("c".into(), "a".into(), "b".into()).with_window(
            t0,
            None,
            t0 + std::time::Duration::from_secs(15),
        );
        assert_eq!(unanswered.answered_at, None);
        assert_eq!(unanswered.billable_secs, 0);
        assert_eq!(unanswered.duration_secs, 15);

        // A clock that went backwards never yields a negative span.
        let backwards = CdrRecord::new("c".into(), "a".into(), "b".into()).with_window(
            t0 + std::time::Duration::from_secs(5),
            None,
            t0,
        );
        assert_eq!(backwards.duration_secs, 0);
        assert_eq!(backwards.ended_at, backwards.started_at);
    }

    #[test]
    fn json_round_trip_and_legacy_rows() {
        let t0 = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut r = CdrRecord::new("c1".into(), "alice".into(), "+33612".into())
            .with_window(t0, Some(t0), t0 + std::time::Duration::from_secs(3))
            .with_codec("PCMU")
            .with_disconnect_reason("normal-clearing");
        r.direction = "outbound".into();
        r.sip_code = Some(200);
        r.reason = Some("Q.850;cause=16;text=\"x\"".into());
        let json = r.to_json();
        assert!(json.starts_with("{\"id\":"), "legacy keys first: {}", json);
        assert!(json.contains("\"billable_secs\":3"));
        let back = parse_cdr_json(&json).expect("parses");
        assert_eq!(back.call_id, "c1");
        assert_eq!(back.reason.as_deref(), Some("Q.850;cause=16;text=\"x\""));
        assert_eq!(back.sip_code, Some(200));
        assert_eq!(back.v, 2);

        // A row written before 0.20: legacy keys only.
        let legacy = r#"{"id":"x","call_id":"c","caller":"a","callee":"b","trunk_id":null,"duration_secs":5,"codec":null,"is_webrtc":false,"disconnect_reason":"normal-clearing","started_at":1,"ended_at":6}"#;
        let old = parse_cdr_json(legacy).expect("legacy parses");
        assert_eq!(
            old.v, 1,
            "legacy rows are marked so billing can tell them apart"
        );
        assert_eq!(old.duration_secs, 5);
        assert_eq!(old.billable_secs, 0);
        assert_eq!(old.answered_at, None);
        assert_eq!(old.sip_code, None);
        assert!(parse_cdr_json("not json at all").is_none());
    }

    #[tokio::test]
    async fn pages_are_newest_first_and_bounded() {
        let mgr = CdrManager::new_memory();
        for n in 0..5u64 {
            let mut r = CdrRecord::new(format!("c{}", n), "a".into(), "b".into());
            r.started_at = n;
            mgr.insert(&r).await.unwrap();
        }
        let (page, fetched) = mgr.get_page(2, 0).await.unwrap();
        assert_eq!(fetched, 2);
        assert_eq!(
            page.iter().map(|r| r.call_id.as_str()).collect::<Vec<_>>(),
            ["c4", "c3"]
        );
        let (page, _) = mgr.get_page(2, 2).await.unwrap();
        assert_eq!(
            page.iter().map(|r| r.call_id.as_str()).collect::<Vec<_>>(),
            ["c2", "c1"]
        );
        let (page, fetched) = mgr.get_page(2, 4).await.unwrap();
        assert_eq!(fetched, 5, "window capped at what exists");
        assert_eq!(
            page.iter().map(|r| r.call_id.as_str()).collect::<Vec<_>>(),
            ["c0"]
        );
    }

    #[tokio::test]
    async fn test_cdr_record_creation() {
        let record = CdrRecord::new(
            "call-001".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
        );
        assert_eq!(record.call_id, "call-001");
        assert_eq!(record.caller, "sip:alice@example.com");
        assert_eq!(record.callee, "sip:bob@example.com");
        assert_eq!(record.duration_secs, 0);
        assert!(!record.is_webrtc);
    }

    #[tokio::test]
    async fn test_cdr_record_with_duration() {
        let record = CdrRecord::new("call-002".to_string(), "a".to_string(), "b".to_string())
            .with_duration(120);
        assert_eq!(record.duration_secs, 120);
        assert!(record.ended_at >= record.started_at);
    }

    #[tokio::test]
    async fn test_cdr_record_to_json() {
        let record = CdrRecord::new(
            "call-003".to_string(),
            "alice".to_string(),
            "bob".to_string(),
        )
        .with_duration(60)
        .with_codec("PCMU")
        .with_webrtc(true);
        let json = record.to_json();
        assert!(json.contains("call-003"));
        assert!(json.contains("alice"));
        assert!(json.contains("60"));
        assert!(json.contains("PCMU"));
        assert!(json.contains("true"));
    }

    #[tokio::test]
    async fn test_in_memory_storage_insert_and_get() {
        let storage = InMemoryCdrStorage::new();
        let record = CdrRecord::new("call-100".to_string(), "a".to_string(), "b".to_string());

        storage.insert_cdr(&record).await.unwrap();

        let found = storage.get_cdr("call-100").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().call_id, "call-100");
    }

    #[tokio::test]
    async fn test_in_memory_storage_not_found() {
        let storage = InMemoryCdrStorage::new();
        let found = storage.get_cdr("nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_storage_list_recent() {
        let storage = InMemoryCdrStorage::new();
        for i in 0..5 {
            let r = CdrRecord::new(format!("call-{}", i), "a".to_string(), "b".to_string());
            storage.insert_cdr(&r).await.unwrap();
        }
        let recent = storage.list_recent_cdrs(3).await.unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[tokio::test]
    async fn test_in_memory_storage_stats() {
        let storage = InMemoryCdrStorage::new();
        for i in 0..3 {
            let r = CdrRecord::new(format!("c{}", i), "a".to_string(), "b".to_string());
            storage.insert_cdr(&r).await.unwrap();
        }
        let stats = storage.stats().await;
        assert_eq!(stats.total_cdrs, 3);
        assert_eq!(stats.total_inserts, 3);
        assert_eq!(stats.backend, "memory");
    }

    #[tokio::test]
    async fn test_cdr_manager_record_call() {
        let mgr = CdrManager::new_memory();
        mgr.record_call(
            "call-200",
            "alice",
            "bob",
            300,
            false,
            Some("PCMA"),
            "normal",
        )
        .await
        .unwrap();

        let stats = mgr.stats().await;
        assert_eq!(stats.total_cdrs, 1);
    }

    #[tokio::test]
    async fn test_cdr_manager_recent_json() {
        let mgr = CdrManager::new_memory();
        mgr.record_call("call-201", "a", "b", 60, true, None, "user-hangup")
            .await
            .unwrap();

        let json = mgr.recent_to_json(10).await;
        assert!(json.starts_with('['));
        assert!(json.contains("call-201"));
    }
}
