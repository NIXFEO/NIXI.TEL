//! REGISTER Handling — RFC 3261 §10
//!
//! The SBC acts as a SIP Registrar for its served domains.
//! Registrations are stored in:
//!   - [`InMemoryRegistrar`]  — for tests and development
//!   - [`PostgresRegistrar`]  — for production (schema below)
//!
//! # PostgreSQL schema
//! ```sql
//! CREATE TABLE sip_registrations (
//!     id           BIGSERIAL PRIMARY KEY,
//!     aor          TEXT NOT NULL,          -- Address-of-Record (sip:user@domain)
//!     contact      TEXT NOT NULL,          -- Contact URI
//!     expires      INTEGER NOT NULL,        -- Expiry in seconds (from client)
//!     registered_at BIGINT NOT NULL,        -- UNIX timestamp
//!     expires_at   BIGINT NOT NULL,         -- registered_at + expires
//!     call_id      TEXT NOT NULL,           -- Call-ID of REGISTER
//!     cseq         INTEGER NOT NULL,        -- CSeq of REGISTER
//!     user_agent   TEXT,
//!     received_ip  TEXT NOT NULL,           -- IP where request came from
//!     received_port INTEGER NOT NULL,
//!     transport    TEXT NOT NULL DEFAULT 'UDP'
//! );
//! CREATE UNIQUE INDEX idx_reg_aor_contact ON sip_registrations(aor, contact);
//! ```

use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Default registration expiry in seconds (RFC 3261 §10.2)
pub const DEFAULT_EXPIRES: u32 = 3600;
/// Minimum expiry allowed (RFC 3261 §10.3.3)
pub const MIN_EXPIRES: u32 = 60;
/// Maximum expiry allowed (sanity cap)
pub const MAX_EXPIRES: u32 = 86400;

/// A single registration record
#[derive(Debug, Clone)]
pub struct Registration {
    /// Address-of-Record: sip:user@domain
    pub aor: String,
    /// Contact URI: sip:user@ip:port
    pub contact: String,
    /// Requested expiry (seconds)
    pub expires: u32,
    /// UNIX timestamp when registered (seconds)
    pub registered_at: u64,
    /// UNIX timestamp when registered (milliseconds) — used for race detection
    pub registered_at_ms: u64,
    /// UNIX timestamp when registration expires
    pub expires_at: u64,
    /// Call-ID of the REGISTER request
    pub call_id: String,
    /// CSeq of the REGISTER request
    pub cseq: u32,
    /// User-Agent string (optional)
    pub user_agent: Option<String>,
    /// IP address where request came from (NAT-detected)
    pub received_ip: String,
    /// Port where request came from
    pub received_port: u16,
    /// Transport (UDP/TCP/TLS/WS/WSS)
    pub transport: String,

    /// Reply channel for WebSocket/WSS clients.
    /// When set, INVITE messages for this user can be sent directly over
    /// the existing WebSocket connection without opening a new one.
    /// This is critical for WSS clients behind NAT/firewalls.
    #[allow(dead_code)]
    pub reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

impl Registration {
    pub fn new(
        aor: String,
        contact: String,
        expires: u32,
        call_id: String,
        cseq: u32,
        received: SocketAddr,
        transport: &str,
    ) -> Self {
        let now = unix_now();
        let now_ms = unix_now_ms();
        let expires = expires.clamp(MIN_EXPIRES, MAX_EXPIRES);
        Self {
            aor,
            contact,
            expires,
            registered_at: now,
            registered_at_ms: now_ms,
            expires_at: now + expires as u64,
            call_id,
            cseq,
            user_agent: None,
            received_ip: received.ip().to_string(),
            received_port: received.port(),
            transport: transport.to_uppercase(),
            reply_tx: None,
        }
    }

    /// Is this registration still valid?
    pub fn is_valid(&self) -> bool {
        unix_now() < self.expires_at
    }

    /// Remaining seconds of validity
    pub fn remaining_secs(&self) -> u64 {
        self.expires_at.saturating_sub(unix_now())
    }

    /// Refresh registration (update timestamps), optionally updating the reply_tx
    pub fn refresh(&mut self, expires: u32, call_id: String, cseq: u32) {
        let now = unix_now();
        let expires = expires.clamp(MIN_EXPIRES, MAX_EXPIRES);
        self.expires       = expires;
        self.registered_at = now;
        self.expires_at    = now + expires as u64;
        self.call_id       = call_id;
        self.cseq          = cseq;
        // reply_tx is preserved (updated separately via refresh_with_tx)
    }

    /// Refresh registration and update the WebSocket reply channel
    pub fn refresh_with_tx(
        &mut self,
        expires: u32,
        call_id: String,
        cseq: u32,
        reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    ) {
        self.refresh(expires, call_id, cseq);
        if reply_tx.is_some() {
            self.reply_tx = reply_tx;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// Registrar trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait Registrar: Send + Sync {
    /// Store or refresh a registration.
    /// Returns the effective expires value.
    async fn register(&self, reg: Registration) -> Result<u32>;

    /// Remove a registration (expires=0 from client).
    async fn unregister(&self, aor: &str, contact: &str) -> Result<()>;

    /// Remove a registration only if it belongs to the given Call-ID.
    /// RFC 3261 §10.3: prevents a stale UNREGISTER (old Call-ID) from erasing
    /// a binding that was just refreshed by a newer REGISTER (different Call-ID).
    async fn unregister_with_call_id(&self, aor: &str, contact: &str, call_id: Option<String>) -> Result<()>;

    /// Remove all registrations for an AOR (contact=*)
    async fn unregister_all(&self, aor: &str) -> Result<u32>;

    /// Look up all valid contacts for an AOR
    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>>;

    /// Remove expired registrations (should be called periodically)
    async fn cleanup_expired(&self) -> Result<u32>;

    /// Total number of active registrations
    async fn count(&self) -> u64;

    /// Get all registrations (for admin API)
    async fn all_registrations(&self) -> Result<Vec<Registration>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory backend
// ─────────────────────────────────────────────────────────────────────────────

/// Key: (AOR, Contact)
type RegKey = (String, String);

pub struct InMemoryRegistrar {
    /// Registrations indexed by (AOR, Contact)
    regs: Arc<RwLock<HashMap<RegKey, Registration>>>,
}

impl InMemoryRegistrar {
    pub fn new() -> Self {
        Self { regs: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl Default for InMemoryRegistrar {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Registrar for InMemoryRegistrar {
    async fn register(&self, reg: Registration) -> Result<u32> {
        let expires = reg.expires;
        let key = (reg.aor.clone(), reg.contact.clone());
        let mut map = self.regs.write().await;

        if let Some(existing) = map.get_mut(&key) {
            // Refresh, preserving/updating the reply_tx
            existing.refresh_with_tx(reg.expires, reg.call_id.clone(), reg.cseq, reg.reply_tx);
            debug!("REGISTER: refreshed {} <-> {} ({}s)", existing.aor, existing.contact, expires);
        } else {
            // Remove stale bindings from same AOR + same public IP
            // (Linphone opens a new TLS connection with a different port on each reconnect,
            //  resulting in a different Contact URI but the same source IP.
            //  We keep only the latest binding per IP to avoid stale reply_tx channels.)
            let aor = reg.aor.clone();
            let source_ip = reg.received_ip.clone();
            let stale_keys: Vec<RegKey> = map.iter()
                .filter(|((a, _), r)| {
                    *a == aor && r.received_ip == source_ip
                })
                .map(|(k, _)| k.clone())
                .collect();
            for stale in &stale_keys {
                debug!("REGISTER: removing stale binding for {} from {} (replaced by new contact)", aor, source_ip);
                map.remove(stale);
            }
            info!("REGISTER: new {} <-> {} ({}s)", reg.aor, reg.contact, reg.expires);
            map.insert(key, reg);
        }
        Ok(expires)
    }

    async fn unregister(&self, aor: &str, contact: &str) -> Result<()> {
        self.unregister_with_call_id(aor, contact, None).await
    }

    async fn unregister_with_call_id(&self, aor: &str, contact: &str, call_id: Option<String>) -> Result<()> {
        let key = (aor.to_string(), contact.to_string());
        let mut map = self.regs.write().await;
        if let Some(existing) = map.get(&key) {
            // RFC 3261 §10.3 / race-condition guard:
            // If a call-id is provided and it DIFFERS from the stored binding's call-id,
            // then the binding was created by a newer REGISTER dialog.
            // Only suppress the unregister if the stored binding is very fresh (< 500ms),
            // which indicates a race: a concurrent REGISTER won the race and created a new
            // binding just before this stale UNREGISTER arrived.
            if let Some(ref cid) = call_id {
                if existing.call_id != *cid {
                    let now_ms = unix_now_ms();
                    let binding_age_ms = now_ms.saturating_sub(existing.registered_at_ms);
                    // If the binding was registered in the last 500ms and has a different
                    // call-id, it was likely just created by a concurrent REGISTER — skip the
                    // stale UNREGISTER. This handles Linphone's rapid re-registration pattern
                    // where UNREGISTER (old Call-ID) races with new REGISTER (new Call-ID).
                    if binding_age_ms < 500 {
                        debug!("REGISTER: ignoring stale UNREGISTER for {} (call-id {}, binding owned by {} registered {}ms ago)",
                            aor, cid, existing.call_id, binding_age_ms);
                        return Ok(());
                    }
                }
            }
            map.remove(&key);
            info!("REGISTER: removed {} <-> {}", aor, contact);
        }
        Ok(())
    }

    async fn unregister_all(&self, aor: &str) -> Result<u32> {
        let mut map = self.regs.write().await;
        let before = map.len();
        map.retain(|(a, _), _| a != aor);
        let removed = (before - map.len()) as u32;
        info!("REGISTER: removed all ({}) contacts for {}", removed, aor);
        Ok(removed)
    }

    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>> {
        let map = self.regs.read().await;
        let now = unix_now();
        let results: Vec<Registration> = map.iter()
            .filter(|((a, _), r)| a == aor && r.expires_at > now)
            .map(|(_, r)| r.clone())
            .collect();
        Ok(results)
    }

    async fn cleanup_expired(&self) -> Result<u32> {
        let mut map = self.regs.write().await;
        let before = map.len();
        let now = unix_now();
        map.retain(|_, r| r.expires_at > now);
        let removed = (before - map.len()) as u32;
        if removed > 0 {
            debug!("REGISTER: cleaned up {} expired registrations", removed);
        }
        Ok(removed)
    }

    async fn count(&self) -> u64 {
        self.regs.read().await.len() as u64
    }

    async fn all_registrations(&self) -> Result<Vec<Registration>> {
        let map = self.regs.read().await;
        Ok(map.values().cloned().collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL backend (generates SQL without actually executing in unit tests)
// ─────────────────────────────────────────────────────────────────────────────

/// PostgreSQL-backed registrar.
/// In production this would use sqlx. Here we generate correct SQL
/// and expose it via `last_sql()` for testing, while delegating actual
/// storage to an in-memory cache for environments without a DB.
pub struct PostgresRegistrar {
    #[allow(dead_code)]
    db_url: String,
    /// Fallback in-memory store (used when DB is unavailable)
    fallback: InMemoryRegistrar,
    /// Last SQL statement generated (for testing)
    last_sql: Arc<RwLock<String>>,
}

impl PostgresRegistrar {
    pub fn new(db_url: &str) -> Self {
        Self {
            db_url: db_url.to_string(),
            fallback: InMemoryRegistrar::new(),
            last_sql: Arc::new(RwLock::new(String::new())),
        }
    }

    fn upsert_sql(reg: &Registration) -> String {
        format!(
            "INSERT INTO sip_registrations \
             (aor, contact, expires, registered_at, expires_at, call_id, cseq, user_agent, received_ip, received_port, transport) \
             VALUES ('{aor}', '{contact}', {expires}, {reg_at}, {exp_at}, '{call_id}', {cseq}, {ua}, '{recv_ip}', {recv_port}, '{transport}') \
             ON CONFLICT (aor, contact) DO UPDATE SET \
             expires=EXCLUDED.expires, registered_at=EXCLUDED.registered_at, \
             expires_at=EXCLUDED.expires_at, call_id=EXCLUDED.call_id, cseq=EXCLUDED.cseq",
            aor       = reg.aor,
            contact   = reg.contact,
            expires   = reg.expires,
            reg_at    = reg.registered_at,
            exp_at    = reg.expires_at,
            call_id   = reg.call_id,
            cseq      = reg.cseq,
            ua        = reg.user_agent.as_deref().map(|s| format!("'{}'", s)).unwrap_or("NULL".into()),
            recv_ip   = reg.received_ip,
            recv_port = reg.received_port,
            transport = reg.transport,
        )
    }

    fn delete_sql(aor: &str, contact: &str) -> String {
        format!(
            "DELETE FROM sip_registrations WHERE aor='{}' AND contact='{}'",
            aor, contact
        )
    }

    fn delete_all_sql(aor: &str) -> String {
        format!("DELETE FROM sip_registrations WHERE aor='{}'", aor)
    }

    fn select_sql(aor: &str) -> String {
        format!(
            "SELECT * FROM sip_registrations WHERE aor='{}' AND expires_at > {}",
            aor, unix_now()
        )
    }

    fn cleanup_sql() -> String {
        format!(
            "DELETE FROM sip_registrations WHERE expires_at <= {}",
            unix_now()
        )
    }

    pub async fn last_sql(&self) -> String {
        self.last_sql.read().await.clone()
    }

    async fn set_sql(&self, sql: String) {
        *self.last_sql.write().await = sql;
    }
}

#[async_trait]
impl Registrar for PostgresRegistrar {
    async fn register(&self, reg: Registration) -> Result<u32> {
        let sql = Self::upsert_sql(&reg);
        self.set_sql(sql).await;
        // Delegate to in-memory fallback
        self.fallback.register(reg).await
    }

    async fn unregister(&self, aor: &str, contact: &str) -> Result<()> {
        let sql = Self::delete_sql(aor, contact);
        self.set_sql(sql).await;
        self.fallback.unregister(aor, contact).await
    }

    async fn unregister_with_call_id(&self, aor: &str, contact: &str, call_id: Option<String>) -> Result<()> {
        // For Postgres, we'd add WHERE call_id=? but delegate to fallback for now
        self.fallback.unregister_with_call_id(aor, contact, call_id).await
    }

    async fn unregister_all(&self, aor: &str) -> Result<u32> {
        let sql = Self::delete_all_sql(aor);
        self.set_sql(sql).await;
        self.fallback.unregister_all(aor).await
    }

    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>> {
        let sql = Self::select_sql(aor);
        self.set_sql(sql).await;
        self.fallback.lookup(aor).await
    }

    async fn cleanup_expired(&self) -> Result<u32> {
        let sql = Self::cleanup_sql();
        self.set_sql(sql).await;
        self.fallback.cleanup_expired().await
    }

    async fn count(&self) -> u64 {
        self.fallback.count().await
    }

    async fn all_registrations(&self) -> Result<Vec<Registration>> {
        self.fallback.all_registrations().await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTER request handler
// ─────────────────────────────────────────────────────────────────────────────

/// Parse and handle an incoming REGISTER request.
///
/// Returns `(status_code, response_body)` to be sent back.
/// In production the response is a full SIP 200 OK.
pub struct RegisterHandler {
    registrar: Arc<dyn Registrar>,
}

impl RegisterHandler {
    pub fn new(registrar: Arc<dyn Registrar>) -> Self {
        Self { registrar }
    }

    /// Underlying registrar handle (shared with the HTTP API).
    pub fn registrar(&self) -> Arc<dyn Registrar> {
        self.registrar.clone()
    }

    pub fn new_inmemory() -> Self {
        Self::new(Arc::new(InMemoryRegistrar::new()))
    }

    /// Process a REGISTER request (simplified parser — in production use rsip).
    ///
    /// Expected fields extracted from the headers map:
    ///   - `To`      → AOR
    ///   - `Contact` → contact URI (or "*" for remove-all)
    ///   - `Expires` → expiry (header or Contact param)
    ///   - `Call-ID` → call identifier
    ///   - `CSeq`    → sequence number
    pub async fn handle(
        &self,
        aor: &str,
        contact: &str,
        expires: u32,
        call_id: &str,
        cseq: u32,
        from_addr: SocketAddr,
        transport: &str,
    ) -> Result<RegisterResult> {
        self.handle_with_tx(aor, contact, expires, call_id, cseq, from_addr, transport, None).await
    }

    /// Extended REGISTER handler that accepts a WebSocket reply channel.
    /// When a WSS client registers, its reply_tx is stored so incoming INVITEs
    /// can be forwarded over the existing WebSocket connection.
    pub async fn handle_with_tx(
        &self,
        aor: &str,
        contact: &str,
        expires: u32,
        call_id: &str,
        cseq: u32,
        from_addr: SocketAddr,
        transport: &str,
        reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    ) -> Result<RegisterResult> {
        // Remove-all (contact = "*", expires = 0)
        if contact == "*" && expires == 0 {
            let removed = self.registrar.unregister_all(aor).await?;
            return Ok(RegisterResult::Removed { count: removed });
        }

        // Remove specific contact (expires = 0)
        // RFC 3261 §10.3: only remove if Call-ID matches the stored binding,
        // to prevent a late/stale UNREGISTER from erasing a fresher registration.
        if expires == 0 {
            self.registrar.unregister_with_call_id(aor, contact, Some(call_id.to_string())).await?;
            return Ok(RegisterResult::Removed { count: 1 });
        }

        // Register / refresh
        let mut reg = Registration::new(
            aor.to_string(),
            contact.to_string(),
            expires,
            call_id.to_string(),
            cseq,
            from_addr,
            transport,
        );
        // Attach WebSocket reply channel if provided (for WSS clients)
        reg.reply_tx = reply_tx;
        let effective_expires = self.registrar.register(reg).await?;

        // Return all current bindings
        let bindings = self.registrar.lookup(aor).await?;
        Ok(RegisterResult::Ok { expires: effective_expires, bindings })
    }

    /// Build a SIP 200 OK response for a successful REGISTER.
    pub fn build_200_ok(bindings: &[Registration], call_id: &str, cseq: u32) -> String {
        let contacts: Vec<String> = bindings.iter().map(|r| {
            format!("<{}>;expires={}", r.contact, r.remaining_secs())
        }).collect();
        let contact_hdr = if contacts.is_empty() {
            String::new()
        } else {
            format!("Contact: {}\r\n", contacts.join(", "))
        };

        format!(
            "SIP/2.0 200 OK\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} REGISTER\r\n\
{contact}Content-Length: 0\r\n\
\r\n",
            call_id  = call_id,
            cseq     = cseq,
            contact  = contact_hdr,
        )
    }

    /// Build a SIP 423 Interval Too Brief response
    pub fn build_423(call_id: &str, cseq: u32) -> String {
        format!(
            "SIP/2.0 423 Interval Too Brief\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} REGISTER\r\n\
Min-Expires: {min}\r\n\
Content-Length: 0\r\n\
\r\n",
            call_id = call_id,
            cseq    = cseq,
            min     = MIN_EXPIRES,
        )
    }

    /// Look up active registrations for an AOR (Address-of-Record)
    /// Used by INVITE routing to find the registered contact of a callee.
    ///
    /// Handles these AOR formats:
    /// - `sip:alice@sip.example.com`   (Request-URI from INVITE — canonical form)
    /// - `<sip:alice@sip.example.com>` (raw To header with angle brackets)
    /// - `alice@sip.example.com`        (user@domain shorthand)
    ///
    /// AORs stored in the registrar are normalized (no angle brackets).
    pub async fn lookup(&self, aor: &str) -> Result<Vec<Registration>> {
        // Normalize: strip angle brackets and display name
        let s = aor.trim();
        let normalized = if let (Some(start), Some(end)) = (s.find('<'), s.rfind('>')) {
            s[start+1..end].trim().to_string()
        } else {
            s.to_string()
        };

        // Try exact normalized match
        let results = self.registrar.lookup(&normalized).await?;
        if !results.is_empty() {
            return Ok(results);
        }

        // Try adding "sip:" prefix if missing
        if !normalized.starts_with("sip:") && !normalized.starts_with("sips:") {
            let with_sip = format!("sip:{}", normalized);
            return self.registrar.lookup(&with_sip).await;
        }

        Ok(vec![])
    }

    /// Get registration count
    pub async fn count(&self) -> u64 {
        self.registrar.count().await
    }

    /// Get all registrations
    pub async fn all_registrations(&self) -> Result<Vec<Registration>> {
        self.registrar.all_registrations().await
    }
}

/// Result of processing a REGISTER request
#[derive(Debug)]
pub enum RegisterResult {
    Ok { expires: u32, bindings: Vec<Registration> },
    Removed { count: u32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr { "192.168.1.100:5060".parse().unwrap() }
    fn aor() -> &'static str { "sip:alice@example.com" }
    fn contact() -> &'static str { "sip:alice@192.168.1.100:5060" }

    fn make_reg(expires: u32) -> Registration {
        Registration::new(
            aor().to_string(),
            contact().to_string(),
            expires,
            "call-id-1".to_string(),
            1,
            addr(),
            "UDP",
        )
    }

    // ── InMemoryRegistrar ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_register_new() {
        let r = InMemoryRegistrar::new();
        let eff = r.register(make_reg(3600)).await.unwrap();
        assert_eq!(eff, 3600);
        assert_eq!(r.count().await, 1);
    }

    #[tokio::test]
    async fn test_register_refresh() {
        let r = InMemoryRegistrar::new();
        r.register(make_reg(3600)).await.unwrap();
        // Refresh with different expiry
        r.register(make_reg(1800)).await.unwrap();
        assert_eq!(r.count().await, 1, "should still be one registration");
        let bindings = r.lookup(aor()).await.unwrap();
        assert_eq!(bindings[0].expires, 1800);
    }

    #[tokio::test]
    async fn test_register_multiple_contacts() {
        let r = InMemoryRegistrar::new();
        let reg1 = make_reg(3600);
        // Second registration from a DIFFERENT source IP (different device/location)
        let mut reg2 = Registration::new(
            aor().to_string(),
            "sip:alice@10.0.0.2:5060".to_string(),
            1800,
            "call-2".to_string(),
            1,
            "10.0.0.2:5060".parse().unwrap(), // different source IP
            "UDP",
        );

        r.register(reg1).await.unwrap();
        r.register(reg2).await.unwrap();
        assert_eq!(r.count().await, 2);

        let bindings = r.lookup(aor()).await.unwrap();
        assert_eq!(bindings.len(), 2);
    }

    #[tokio::test]
    async fn test_lookup_returns_only_valid() {
        let r = InMemoryRegistrar::new();
        // Register with minimum valid expiry
        r.register(make_reg(MIN_EXPIRES)).await.unwrap();
        let bindings = r.lookup(aor()).await.unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(bindings[0].is_valid());
    }

    #[tokio::test]
    async fn test_unregister() {
        let r = InMemoryRegistrar::new();
        r.register(make_reg(3600)).await.unwrap();
        r.unregister(aor(), contact()).await.unwrap();
        assert_eq!(r.count().await, 0);
    }

    #[tokio::test]
    async fn test_unregister_all() {
        let r = InMemoryRegistrar::new();
        // Two contacts from different source IPs
        let reg1 = make_reg(3600);
        let reg2 = Registration::new(
            aor().to_string(),
            "sip:alice@192.168.1.200:5060".to_string(),
            3600,
            "call-2".to_string(),
            1,
            "192.168.1.200:5060".parse().unwrap(), // different source IP
            "UDP",
        );
        r.register(reg1).await.unwrap();
        r.register(reg2).await.unwrap();
        let removed = r.unregister_all(aor()).await.unwrap();
        assert_eq!(removed, 2);
        assert_eq!(r.count().await, 0);
    }

    #[tokio::test]
    async fn test_expires_clamped_to_min() {
        let r = InMemoryRegistrar::new();
        let eff = r.register(make_reg(10)).await.unwrap(); // below MIN_EXPIRES
        assert_eq!(eff, MIN_EXPIRES);
    }

    #[tokio::test]
    async fn test_expires_clamped_to_max() {
        let r = InMemoryRegistrar::new();
        let eff = r.register(make_reg(999_999)).await.unwrap();
        assert_eq!(eff, MAX_EXPIRES);
    }

    // ── RegisterHandler ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_handler_register() {
        let h = RegisterHandler::new_inmemory();
        let result = h.handle(aor(), contact(), 3600, "call-1", 1, addr(), "UDP").await.unwrap();
        match result {
            RegisterResult::Ok { expires, bindings } => {
                assert_eq!(expires, 3600);
                assert_eq!(bindings.len(), 1);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn test_handler_unregister_specific() {
        let h = RegisterHandler::new_inmemory();
        h.handle(aor(), contact(), 3600, "call-1", 1, addr(), "UDP").await.unwrap();
        // RFC 3261: UNREGISTER uses same Call-ID, higher CSeq
        let result = h.handle(aor(), contact(), 0, "call-1", 2, addr(), "UDP").await.unwrap();
        match result {
            RegisterResult::Removed { count } => assert_eq!(count, 1),
            _ => panic!("expected Removed"),
        }
        assert_eq!(h.count().await, 0);
    }

    #[tokio::test]
    async fn test_handler_unregister_all() {
        let h = RegisterHandler::new_inmemory();
        // Register two contacts from different source IPs
        h.handle(aor(), contact(), 3600, "call-1", 1, addr(), "UDP").await.unwrap();
        h.handle(aor(), "sip:alice@10.0.0.2:5060", 3600, "call-2", 1,
            "10.0.0.2:5060".parse().unwrap(), "UDP").await.unwrap();
        // contact="*", expires=0 → remove all (unregister_all bypasses call-id check)
        let result = h.handle(aor(), "*", 0, "call-1", 2, addr(), "UDP").await.unwrap();
        match result {
            RegisterResult::Removed { count } => assert_eq!(count, 2),
            _ => panic!("expected Removed"),
        }
    }

    // ── PostgresRegistrar ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_postgres_generates_upsert_sql() {
        let r = PostgresRegistrar::new("postgresql://sbc:pass@localhost/sbc_db");
        r.register(make_reg(3600)).await.unwrap();
        let sql = r.last_sql().await;
        assert!(sql.contains("INSERT INTO sip_registrations"), "SQL: {}", sql);
        assert!(sql.contains("ON CONFLICT"), "SQL should have upsert: {}", sql);
        assert!(sql.contains(aor()), "SQL should have AOR: {}", sql);
    }

    #[tokio::test]
    async fn test_postgres_generates_delete_sql() {
        let r = PostgresRegistrar::new("postgresql://sbc:pass@localhost/sbc_db");
        r.register(make_reg(3600)).await.unwrap();
        r.unregister(aor(), contact()).await.unwrap();
        let sql = r.last_sql().await;
        assert!(sql.starts_with("DELETE FROM sip_registrations"), "SQL: {}", sql);
        assert!(sql.contains(aor()), "SQL should contain AOR: {}", sql);
    }

    #[tokio::test]
    async fn test_postgres_generates_select_sql() {
        let r = PostgresRegistrar::new("postgresql://sbc:pass@localhost/sbc_db");
        r.register(make_reg(3600)).await.unwrap();
        r.lookup(aor()).await.unwrap();
        let sql = r.last_sql().await;
        assert!(sql.starts_with("SELECT * FROM sip_registrations"), "SQL: {}", sql);
        assert!(sql.contains(aor()), "SQL should contain AOR: {}", sql);
    }

    #[tokio::test]
    async fn test_postgres_generates_cleanup_sql() {
        let r = PostgresRegistrar::new("postgresql://sbc:pass@localhost/sbc_db");
        r.cleanup_expired().await.unwrap();
        let sql = r.last_sql().await;
        assert!(sql.starts_with("DELETE FROM sip_registrations WHERE expires_at"), "SQL: {}", sql);
    }

    // ── 200 OK builder ────────────────────────────────────────────────────────

    #[test]
    fn test_build_200_ok() {
        let reg = make_reg(3600);
        let ok = RegisterHandler::build_200_ok(&[reg], "call-id-1", 1);
        assert!(ok.starts_with("SIP/2.0 200 OK"));
        assert!(ok.contains("Contact:"));
        assert!(ok.contains("expires="));
        assert!(ok.contains("Content-Length: 0"));
    }

    #[test]
    fn test_build_423() {
        let resp = RegisterHandler::build_423("call-id-1", 1);
        assert!(resp.starts_with("SIP/2.0 423 Interval Too Brief"));
        assert!(resp.contains("Min-Expires:"));
    }

    // ── Registration validity ─────────────────────────────────────────────────

    #[test]
    fn test_registration_is_valid() {
        let reg = make_reg(3600);
        assert!(reg.is_valid());
        assert!(reg.remaining_secs() > 0);
    }

    #[test]
    fn test_registration_refresh() {
        let mut reg = make_reg(3600);
        let old_expires_at = reg.expires_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        reg.refresh(1800, "new-call-id".to_string(), 2);
        assert_eq!(reg.expires, 1800);
        assert_eq!(reg.call_id, "new-call-id");
    }
}
