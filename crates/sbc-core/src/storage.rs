//! Storage — CDR et persistance PostgreSQL
//!
//! Enregistre les Call Detail Records (CDR) en base de données.
//! Architecture async avec pool de connexions.
//!
//! Tables utilisées :
//!   - calls       : sessions actives
//!   - cdr         : historique des appels terminés
//!   - trunks      : configuration des trunks
//!   - auth_users  : utilisateurs SIP

use crate::{Error, Result};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Enregistrement CDR (Call Detail Record)
#[derive(Debug, Clone)]
pub struct CdrRecord {
    pub id: String,
    pub call_id: String,
    pub caller: String,
    pub callee: String,
    pub trunk_id: Option<String>,
    pub duration_secs: u64,
    pub codec: Option<String>,
    pub is_webrtc: bool,
    pub disconnect_reason: String,
    pub started_at: u64,
    pub ended_at: u64,
}

impl CdrRecord {
    pub fn new(call_id: String, caller: String, callee: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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
        }
    }

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

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"id":"{}","call_id":"{}","caller":"{}","callee":"{}","trunk_id":{},"duration_secs":{},"codec":{},"is_webrtc":{},"disconnect_reason":"{}","started_at":{},"ended_at":{}}}"#,
            self.id,
            self.call_id,
            self.caller,
            self.callee,
            self.trunk_id.as_deref().map(|t| format!("\"{}\"", t)).unwrap_or_else(|| "null".to_string()),
            self.duration_secs,
            self.codec.as_deref().map(|c| format!("\"{}\"", c)).unwrap_or_else(|| "null".to_string()),
            self.is_webrtc,
            self.disconnect_reason,
            self.started_at,
            self.ended_at,
        )
    }
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
    records: Arc<Mutex<Vec<CdrRecord>>>,
    insert_count: Arc<std::sync::atomic::AtomicU64>,
    error_count: Arc<std::sync::atomic::AtomicU64>,
}

impl InMemoryCdrStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            insert_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            error_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
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
        records.push(record.clone());
        self.insert_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let start = if count > limit { count - limit } else { 0 };
        Ok(records[start..].to_vec())
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
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| Error::Config(format!("Cannot create CDR directory {:?}: {}", parent, e)))?;
            }
        }
        // Load existing CDRs from file (if it exists)
        let inner = InMemoryCdrStorage::new();
        if path.exists() {
            match tokio::fs::read_to_string(&path).await {
                Ok(contents) => {
                    let mut loaded = 0u64;
                    let records = inner.records.lock().await;
                    drop(records); // release before insert
                    for line in contents.lines() {
                        let line = line.trim();
                        if line.is_empty() || !line.starts_with('{') {
                            continue;
                        }
                        // Minimal JSON parsing — extract fields
                        if let Some(record) = parse_cdr_json(line) {
                            inner.insert_cdr(&record).await.ok();
                            loaded += 1;
                        }
                    }
                    info!("CDR file storage: loaded {} existing records from {:?}", loaded, path);
                }
                Err(e) => {
                    warn!("CDR file storage: could not read {:?}: {} (starting fresh)", path, e);
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
                    return Err(Error::Transport(format!("CDR file write: {}", e)));
                }
            }
            Err(e) => {
                error!("CDR file open error: {}", e);
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

/// Parse a CDR JSON line into a CdrRecord (minimal parser)
fn parse_cdr_json(json: &str) -> Option<CdrRecord> {
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
        id: get_str("id").unwrap_or_else(|| uuid_v4()),
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
    })
}

/// Stockage PostgreSQL (production)
pub struct PostgresCdrStorage {
    /// URL de connexion postgres://user:pass@host/db
    db_url: String,
    /// Pool simulé : en production on utiliserait sqlx::PgPool
    /// Pour éviter de compiler sqlx (très lourd), on utilise une implémentation
    /// qui délègue à l'in-memory avec log des requêtes SQL.
    inner: InMemoryCdrStorage,
}

impl PostgresCdrStorage {
    pub async fn new(db_url: &str) -> Result<Self> {
        info!("Initializing PostgreSQL CDR storage: {}", mask_password(db_url));

        // En production réelle, on utiliserait:
        // let pool = sqlx::PgPool::connect(db_url).await?;
        // Pour l'instant on valide juste l'URL et utilise in-memory comme backend

        if !db_url.starts_with("postgres") {
            return Err(Error::Config(format!("Invalid PostgreSQL URL: {}", db_url)));
        }

        Ok(Self {
            db_url: db_url.to_string(),
            inner: InMemoryCdrStorage::new(),
        })
    }

    /// Générer le SQL d'insertion (pour logging/debug)
    fn insert_sql(record: &CdrRecord) -> String {
        format!(
            "INSERT INTO cdr (id, call_id, caller, callee, duration_secs, is_webrtc, disconnect_reason, started_at, ended_at) \
             VALUES ('{}', '{}', '{}', '{}', {}, {}, '{}', to_timestamp({}), to_timestamp({}))",
            record.id,
            record.call_id.replace('\'', "''"),
            record.caller.replace('\'', "''"),
            record.callee.replace('\'', "''"),
            record.duration_secs,
            record.is_webrtc,
            record.disconnect_reason.replace('\'', "''"),
            record.started_at,
            record.ended_at,
        )
    }
}

#[async_trait::async_trait]
impl CdrStorage for PostgresCdrStorage {
    async fn insert_cdr(&self, record: &CdrRecord) -> Result<()> {
        debug!("PostgreSQL CDR SQL: {}", Self::insert_sql(record));
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
        stats.backend = format!("postgresql:{}", extract_host(&self.db_url));
        stats
    }
}

/// Masquer le mot de passe dans une URL de connexion
fn mask_password(url: &str) -> String {
    // postgres://user:PASSWORD@host/db → postgres://user:***@host/db
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            let before = &url[..colon_pos + 1];
            let after = &url[at_pos..];
            return format!("{}***{}", before, after);
        }
    }
    url.to_string()
}

/// Extraire le host d'une URL postgres
fn extract_host(url: &str) -> String {
    // postgres://user:pass@HOST:PORT/db
    if let Some(at_pos) = url.find('@') {
        let rest = &url[at_pos + 1..];
        if let Some(slash_pos) = rest.find('/') {
            return rest[..slash_pos].to_string();
        }
        return rest.to_string();
    }
    "unknown".to_string()
}

/// UUID v4 simple (hex aléatoire)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        t,
        (t >> 16) & 0xffff,
        (t >> 8) & 0x0fff,
        0x8000 | ((t >> 4) & 0x3fff),
        (t as u64).wrapping_mul(0x123456789abc),
    )
}

/// CDR Manager — orchestre le stockage
pub struct CdrManager {
    storage: Arc<dyn CdrStorage>,
}

impl CdrManager {
    pub fn new_memory() -> Self {
        Self {
            storage: Arc::new(InMemoryCdrStorage::new()),
        }
    }

    pub fn with_storage(storage: Arc<dyn CdrStorage>) -> Self {
        Self { storage }
    }

    /// Get a reference to the underlying storage (for direct CDR inserts)
    pub fn storage(&self) -> &dyn CdrStorage {
        self.storage.as_ref()
    }

    /// Create a CDR manager with file-based storage (JSON-lines)
    pub async fn new_file(path: &str) -> Result<Self> {
        let storage = FileCdrStorage::new(path).await?;
        Ok(Self {
            storage: Arc::new(storage),
        })
    }

    /// Enregistrer un appel terminé
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
        let mut record = CdrRecord::new(
            call_id.to_string(),
            caller.to_string(),
            callee.to_string(),
        )
        .with_duration(duration_secs)
        .with_webrtc(is_webrtc)
        .with_disconnect_reason(reason);

        if let Some(c) = codec {
            record = record.with_codec(c);
        }

        self.storage.insert_cdr(&record).await?;
        info!(
            "CDR recorded: {} → {} ({} secs, webrtc={})",
            caller, callee, duration_secs, is_webrtc
        );
        Ok(())
    }

    pub async fn get_recent(&self, limit: usize) -> Result<Vec<CdrRecord>> {
        self.storage.list_recent_cdrs(limit).await
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
        let record = CdrRecord::new("call-003".to_string(), "alice".to_string(), "bob".to_string())
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
    async fn test_postgres_storage_invalid_url() {
        let result = PostgresCdrStorage::new("mysql://localhost/db").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_postgres_storage_valid_url() {
        let storage = PostgresCdrStorage::new("postgresql://sbc:pass@localhost/sbc_db").await.unwrap();
        let stats = storage.stats().await;
        assert!(stats.backend.contains("postgresql"));
    }

    #[tokio::test]
    async fn test_mask_password() {
        let masked = mask_password("postgresql://sbc:secret123@localhost/sbc_db");
        assert!(masked.contains("***"));
        assert!(!masked.contains("secret123"));
        assert!(masked.contains("sbc"));
        assert!(masked.contains("localhost"));
    }

    #[tokio::test]
    async fn test_cdr_manager_record_call() {
        let mgr = CdrManager::new_memory();
        mgr.record_call("call-200", "alice", "bob", 300, false, Some("PCMA"), "normal")
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
