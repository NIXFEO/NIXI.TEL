//! REGISTER Handling — RFC 3261 §10
//!
//! The SBC acts as a SIP Registrar for its served domains. Bindings live in
//! [`InMemoryRegistrar`]: they are lost on restart and re-created by the
//! clients' next REGISTER (typically within a minute).
//!
//! A binding is identified by its Contact URI, or — when the Contact
//! carries `+sip.instance` — by that instance id (and `reg-id`), so a phone
//! that re-registers from a new port or with a new URI refreshes its one
//! binding instead of piling up stale ones (RFC 5626 §6; the instance id
//! alone identifying the binding is an extension of that rule). Two phones
//! behind one NAT keep their own bindings. `RegisterPolicy` decides the
//! granted interval: below `min_expires` → 423 Interval Too Brief, above
//! `max_expires` → clamped (the phone reads it back in the 200's Contact).
use crate::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Policy
// ─────────────────────────────────────────────────────────────────────────────

/// `[security] register_*_expires` (RFC 3261 §10.3 steps 7-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterPolicy {
    /// Below this a REGISTER is answered 423 with `Min-Expires`.
    pub min_expires: u32,
    /// Above this the granted interval is clamped.
    pub max_expires: u32,
    /// Granted when the request names no interval.
    pub default_expires: u32,
}

impl Default for RegisterPolicy {
    fn default() -> Self {
        Self {
            min_expires: 60,
            max_expires: 3600,
            default_expires: 3600,
        }
    }
}

impl RegisterPolicy {
    /// From the config, with nonsense corrected (and logged).
    pub fn from_config(sec: &crate::config::SecurityConfig) -> Self {
        let min = sec.register_min_expires.max(1);
        let max = sec.register_max_expires.max(min);
        let default = sec.register_default_expires.clamp(min, max);
        if (min, max, default)
            != (
                sec.register_min_expires,
                sec.register_max_expires,
                sec.register_default_expires,
            )
        {
            warn!(
                "register_*_expires corrected to min {} / max {} / default {}",
                min, max, default
            );
        }
        Self {
            min_expires: min,
            max_expires: max,
            default_expires: default,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// A single registration record
#[derive(Debug, Clone)]
pub struct Registration {
    /// Address-of-Record: sip:user@domain
    pub aor: String,
    /// Contact URI as an addr-spec: `sip:user@ip:port[;uri-params]`
    pub contact: String,
    /// Granted expiry (seconds)
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
    /// User-Agent of the REGISTER request
    pub user_agent: Option<String>,
    /// IP address where request came from (NAT-detected)
    pub received_ip: String,
    /// Port where request came from
    pub received_port: u16,
    /// Transport (UDP/TCP/TLS/WS/WSS)
    pub transport: String,
    /// Reply channel for connection-oriented clients (WS/WSS/TLS/TCP):
    /// INVITEs for this user go down the existing connection (NAT).
    pub reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// `+sip.instance` of the Contact (RFC 5626), quotes stripped.
    pub instance_id: Option<String>,
    /// `reg-id` of the Contact (RFC 5626).
    pub reg_id: Option<u32>,
}

/// Most bindings one AOR may hold at once (RFC 5626 says a device may
/// keep several; a phone plus a softphone plus churn is a handful). Past
/// it the oldest binding is evicted.
pub const MAX_BINDINGS_PER_AOR: usize = 10;
/// Most Contacts one REGISTER may carry. A conformant client sends one
/// (or a few for RFC 5626 flows); thousands is an attempt to fill memory.
pub const MAX_CONTACTS_PER_REQUEST: usize = 10;
/// Hard cap on the whole table, so no set of credentials can grow it
/// without bound. Past it the oldest binding is evicted.
pub const MAX_BINDINGS_TOTAL: usize = 5000;

/// One spelling for an Address-of-Record, so a REGISTER and a later
/// inbound call agree: display name and angle brackets removed, scheme and
/// host lower-cased (the user part is case-sensitive, RFC 3261 §19.1.4),
/// URI parameters, headers and the port dropped — an AOR is `user@domain`,
/// and phones spell it with and without `:5060` interchangeably.
pub fn canonical_aor(raw: &str) -> String {
    let s = raw.trim();
    let inner = match (s.find('<'), s.rfind('>')) {
        (Some(start), Some(end)) if start < end => s[start + 1..end].trim(),
        _ => s,
    };
    // Cut parameters and headers: sip:a@h;transport=tcp?X=1
    let inner = inner
        .split([';', '?'])
        .next()
        .unwrap_or(inner)
        .trim()
        .trim_end_matches('>');
    let (scheme, rest) = match inner.split_once(':') {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips") =>
        {
            (format!("{}:", scheme.to_ascii_lowercase()), rest)
        }
        _ => (String::new(), inner),
    };
    let (user, host) = match rest.rsplit_once('@') {
        Some((user, host)) => (format!("{}@", user), host),
        None => (String::new(), rest),
    };
    // Drop the port (but keep an IPv6 reference intact).
    let host = match host.rsplit_once(':') {
        Some((h, port)) if !h.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    format!("{}{}{}", scheme, user, host.to_ascii_lowercase())
}

/// What identifies a binding within an AOR: the instance id (plus reg-id
/// when given), else the Contact URI.
pub fn binding_key(contact: &str, instance_id: Option<&str>, reg_id: Option<u32>) -> String {
    match instance_id {
        Some(id) => format!("instance:{}:{}", id, reg_id.unwrap_or(0)),
        None => format!("contact:{}", contact),
    }
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
            instance_id: None,
            reg_id: None,
        }
    }

    pub fn binding_key(&self) -> String {
        binding_key(&self.contact, self.instance_id.as_deref(), self.reg_id)
    }

    /// Is this registration still valid?
    pub fn is_valid(&self) -> bool {
        unix_now() < self.expires_at
    }

    /// Remaining seconds of validity
    pub fn remaining_secs(&self) -> u64 {
        self.expires_at.saturating_sub(unix_now())
    }

    /// Refresh in place from a newer REGISTER of the same binding: the
    /// contact URI, expiry, dialog identity and source address follow the
    /// newest request (a phone behind NAT that rebinds its port stays
    /// reachable); the reply channel is replaced only when the request
    /// brought one.
    pub fn refresh_from(&mut self, fresh: Registration) {
        self.contact = fresh.contact;
        self.expires = fresh.expires;
        self.registered_at = fresh.registered_at;
        self.registered_at_ms = fresh.registered_at_ms;
        self.expires_at = fresh.expires_at;
        self.call_id = fresh.call_id;
        self.cseq = fresh.cseq;
        self.received_ip = fresh.received_ip;
        self.received_port = fresh.received_port;
        self.transport = fresh.transport;
        if fresh.user_agent.is_some() {
            self.user_agent = fresh.user_agent;
        }
        if fresh.reply_tx.is_some() {
            self.reply_tx = fresh.reply_tx;
        }
        self.instance_id = fresh.instance_id;
        self.reg_id = fresh.reg_id;
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
    /// Store or refresh a binding; returns the stored copy.
    async fn register(&self, reg: Registration) -> Result<Registration>;

    /// Remove one binding by key. `dialog` is the requesting REGISTER's
    /// (Call-ID, CSeq): a binding held by the *same* dialog with a CSeq
    /// that is not lower is kept (an out-of-order or duplicated request,
    /// RFC 3261 §10.3 step 7), and so is one refreshed less than 500 ms
    /// ago by a *different* dialog (a stale un-REGISTER racing a fresh
    /// REGISTER). Returns the removed binding.
    async fn unregister_binding(
        &self,
        aor: &str,
        key: &str,
        dialog: Option<(&str, u32)>,
    ) -> Result<Option<Registration>>;

    /// Remove every binding of an AOR (`Contact: *`); returns them.
    /// `dialog` applies the same §10.3 step 7 rule per binding.
    async fn unregister_all(
        &self,
        aor: &str,
        dialog: Option<(&str, u32)>,
    ) -> Result<Vec<Registration>>;

    /// The unexpired bindings of an AOR.
    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>>;

    /// Drop expired bindings (called by the sweeper); returns them.
    async fn cleanup_expired(&self) -> Result<Vec<Registration>>;

    /// Unexpired bindings.
    async fn count(&self) -> u64;

    /// Every unexpired binding (admin API, WS close).
    async fn all_registrations(&self) -> Result<Vec<Registration>>;

    /// The user parts of the unexpired bindings, split into those
    /// registered from `source_ip` and all of them — the identity gate
    /// runs this on every INVITE, so it must not clone the table.
    async fn registered_users(&self, source_ip: &str) -> (Vec<String>, Vec<String>);

    /// True when a REGISTER is out of order *within its own dialog*
    /// (RFC 3261 §10.3 step 7): same Call-ID, CSeq not higher than the
    /// binding's — or than the CSeq that removed it moments ago, so a
    /// retransmission cannot resurrect a binding the client just
    /// un-registered. Backends without that memory answer false.
    async fn is_out_of_order(&self, _aor: &str, _key: &str, _call_id: &str, _cseq: u32) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory backend
// ─────────────────────────────────────────────────────────────────────────────

/// Key: (AOR, binding key)
type RegKey = (String, String);

/// A removed binding: the (Call-ID, CSeq) that removed it and when, in ms.
type Tombstone = (String, u32, u64);

pub struct InMemoryRegistrar {
    regs: Arc<RwLock<HashMap<RegKey, Registration>>>,
    /// Bindings removed recently: (Call-ID, CSeq, when) of the request
    /// that removed them, so a retransmitted REGISTER with a lower CSeq
    /// cannot bring the binding back (RFC 3261 §10.3 step 7). Swept by
    /// `cleanup_expired` and hard-capped.
    tombstones: Arc<RwLock<HashMap<RegKey, Tombstone>>>,
}

/// How long a removed binding is remembered (well past any UDP
/// retransmission window: Timer F / 64×T1 is 32 s).
const TOMBSTONE_TTL_MS: u64 = 64_000;
/// Hard cap so a flood of un-REGISTERs cannot grow the map without bound.
const MAX_TOMBSTONES: usize = 4096;

impl InMemoryRegistrar {
    pub fn new() -> Self {
        Self {
            regs: Arc::new(RwLock::new(HashMap::new())),
            tombstones: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Remember which request removed a binding.
    async fn entomb(&self, key: &RegKey, dialog: Option<(&str, u32)>) {
        let Some((call_id, cseq)) = dialog else {
            return;
        };
        let now = unix_now_ms();
        let mut tombs = self.tombstones.write().await;
        if tombs.len() >= MAX_TOMBSTONES {
            tombs.retain(|_, (_, _, at)| now.saturating_sub(*at) < TOMBSTONE_TTL_MS);
            if tombs.len() >= MAX_TOMBSTONES {
                return;
            }
        }
        tombs.insert(key.clone(), (call_id.to_string(), cseq, now));
    }
}

impl Default for InMemoryRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop the oldest binding (by registration time) while `full` holds.
fn evict_oldest_while(
    map: &mut HashMap<RegKey, Registration>,
    full: impl Fn(&HashMap<RegKey, Registration>) -> bool,
) {
    while full(map) {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, r)| (r.registered_at_ms, r.expires_at))
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        if let Some(r) = map.remove(&oldest) {
            info!(
                "REGISTER: evicted the oldest binding {} <-> {} (table cap reached)",
                r.aor, r.contact
            );
        }
    }
}

#[async_trait]
impl Registrar for InMemoryRegistrar {
    async fn register(&self, reg: Registration) -> Result<Registration> {
        let key = (reg.aor.clone(), reg.binding_key());
        let mut map = self.regs.write().await;
        match map.get_mut(&key) {
            Some(existing) => {
                // RFC 3261 §10.3 step 7: same dialog, CSeq not higher →
                // the update is aborted (a retransmission that overtook a
                // newer request must not resurrect a binding).
                if existing.call_id == reg.call_id && reg.cseq <= existing.cseq {
                    debug!(
                        "REGISTER: ignoring out-of-order refresh of {} <-> {} (CSeq {} <= stored {})",
                        existing.aor, reg.contact, reg.cseq, existing.cseq
                    );
                    return Ok(existing.clone());
                }
                debug!(
                    "REGISTER: refreshed {} <-> {} ({}s) from {}:{}",
                    existing.aor, reg.contact, reg.expires, reg.received_ip, reg.received_port
                );
                existing.refresh_from(reg);
                Ok(existing.clone())
            }
            None => {
                info!(
                    "REGISTER: new {} <-> {} ({}s) from {}:{}",
                    reg.aor, reg.contact, reg.expires, reg.received_ip, reg.received_port
                );
                // Bound the table: the oldest binding of this AOR goes
                // first, then the oldest of any AOR. Without this one set
                // of credentials could grow it until the box runs out of
                // memory (every binding is also scanned per INVITE).
                evict_oldest_while(&mut map, |m| {
                    m.iter().filter(|((aor, _), _)| *aor == key.0).count() >= MAX_BINDINGS_PER_AOR
                });
                evict_oldest_while(&mut map, |m| m.len() >= MAX_BINDINGS_TOTAL);
                map.insert(key.clone(), reg);
                Ok(map[&key].clone())
            }
        }
    }

    async fn unregister_binding(
        &self,
        aor: &str,
        key: &str,
        dialog: Option<(&str, u32)>,
    ) -> Result<Option<Registration>> {
        let key = (aor.to_string(), key.to_string());
        let mut map = self.regs.write().await;
        let Some(existing) = map.get(&key) else {
            return Ok(None);
        };
        if let Some((cid, cseq)) = dialog {
            if existing.call_id == cid {
                // RFC 3261 §10.3 step 7.
                if cseq <= existing.cseq {
                    debug!(
                        "REGISTER: ignoring out-of-order un-REGISTER for {} (CSeq {} <= stored {})",
                        aor, cseq, existing.cseq
                    );
                    return Ok(None);
                }
            } else {
                let age_ms = unix_now_ms().saturating_sub(existing.registered_at_ms);
                if age_ms < 500 {
                    debug!(
                        "REGISTER: ignoring stale un-REGISTER for {} (call-id {}, binding owned by {} registered {}ms ago)",
                        aor, cid, existing.call_id, age_ms
                    );
                    return Ok(None);
                }
            }
        }
        let removed = map.remove(&key);
        drop(map);
        if let Some(r) = &removed {
            info!("REGISTER: removed {} <-> {}", aor, r.contact);
            self.entomb(&key, dialog).await;
        }
        Ok(removed)
    }

    async fn unregister_all(
        &self,
        aor: &str,
        dialog: Option<(&str, u32)>,
    ) -> Result<Vec<Registration>> {
        let mut map = self.regs.write().await;
        let keys: Vec<RegKey> = map
            .iter()
            .filter(|((a, _), _)| a == aor)
            .filter(|(_, reg)| match dialog {
                // RFC 3261 §10.3 step 7: a `Contact: *` that arrives out of
                // order within its own dialog wipes nothing.
                Some((cid, cseq)) => !(reg.call_id == cid && cseq <= reg.cseq),
                None => true,
            })
            .map(|(k, _)| k.clone())
            .collect();
        let removed: Vec<Registration> = keys.iter().filter_map(|k| map.remove(k)).collect();
        drop(map);
        for k in &keys {
            self.entomb(k, dialog).await;
        }
        info!(
            "REGISTER: removed all ({}) contacts for {}",
            removed.len(),
            aor
        );
        Ok(removed)
    }

    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>> {
        let map = self.regs.read().await;
        let now = unix_now();
        Ok(map
            .iter()
            .filter(|((a, _), r)| a == aor && r.expires_at > now)
            .map(|(_, r)| r.clone())
            .collect())
    }

    async fn registered_users(&self, source_ip: &str) -> (Vec<String>, Vec<String>) {
        let now = unix_now();
        let map = self.regs.read().await;
        let mut here = Vec::new();
        let mut anywhere = Vec::new();
        for reg in map.values().filter(|r| r.expires_at > now) {
            let Some(user) = crate::sbc::uri_user(&reg.aor) else {
                continue;
            };
            if reg.received_ip == source_ip {
                here.push(user.clone());
            }
            anywhere.push(user);
        }
        (here, anywhere)
    }

    async fn is_out_of_order(&self, aor: &str, key: &str, call_id: &str, cseq: u32) -> bool {
        let k = (aor.to_string(), key.to_string());
        if let Some(existing) = self.regs.read().await.get(&k) {
            return existing.call_id == call_id && cseq <= existing.cseq;
        }
        match self.tombstones.read().await.get(&k) {
            Some((cid, last, at)) => {
                unix_now_ms().saturating_sub(*at) < TOMBSTONE_TTL_MS
                    && cid == call_id
                    && cseq <= *last
            }
            None => false,
        }
    }

    async fn cleanup_expired(&self) -> Result<Vec<Registration>> {
        {
            let now = unix_now_ms();
            self.tombstones
                .write()
                .await
                .retain(|_, (_, _, at)| now.saturating_sub(*at) < TOMBSTONE_TTL_MS);
        }
        let mut map = self.regs.write().await;
        let now = unix_now();
        let keys: Vec<RegKey> = map
            .iter()
            .filter(|(_, r)| r.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        let removed: Vec<Registration> = keys.iter().filter_map(|k| map.remove(k)).collect();
        if !removed.is_empty() {
            debug!(
                "REGISTER: cleaned up {} expired registrations",
                removed.len()
            );
        }
        Ok(removed)
    }

    async fn count(&self) -> u64 {
        let now = unix_now();
        self.regs
            .read()
            .await
            .values()
            .filter(|r| r.expires_at > now)
            .count() as u64
    }

    async fn all_registrations(&self) -> Result<Vec<Registration>> {
        let now = unix_now();
        Ok(self
            .regs
            .read()
            .await
            .values()
            .filter(|r| r.expires_at > now)
            .cloned()
            .collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Contact parsing
// ─────────────────────────────────────────────────────────────────────────────

/// One Contact of a REGISTER, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactBinding {
    /// The addr-spec (`sip:user@host:port[;uri-params]`).
    pub uri: String,
    /// `;expires=` contact parameter.
    pub expires: Option<u32>,
    pub instance_id: Option<String>,
    pub reg_id: Option<u32>,
}

/// Split a header value on commas outside quotes and angle brackets.
fn split_contacts(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut depth) = (false, 0i32);
    for c in value.chars() {
        match c {
            '"' => quoted = !quoted,
            '<' if !quoted => depth += 1,
            '>' if !quoted => depth -= 1,
            ',' if !quoted && depth <= 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    out.push(cur);
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse one Contact header value (possibly several comma-separated
/// contacts). `Ok(None)` for the wildcard `*`.
pub fn parse_contact_header(
    value: &str,
) -> std::result::Result<Option<Vec<ContactBinding>>, String> {
    if value.trim() == "*" {
        return Ok(None);
    }
    let mut out = Vec::new();
    for item in split_contacts(value) {
        // The URI is the first <…>; a '>' inside a quoted parameter value
        // (+sip.instance="<urn:uuid:…>") must not be taken for its end.
        let angle = item
            .find('<')
            .and_then(|a| item[a..].find('>').map(|off| (a, a + off)));
        let (uri, params): (String, Vec<String>) = match angle {
            Some((a, b)) => (
                item[a + 1..b].trim().to_string(),
                item[b + 1..]
                    .split(';')
                    .skip(1)
                    .map(|p| p.trim().to_string())
                    .collect(),
            ),
            None if item.contains('<') || item.contains('>') => {
                return Err(format!("unbalanced angle brackets in Contact '{}'", item))
            }
            None => {
                let mut parts = item.split(';');
                let uri = parts.next().unwrap_or("").trim().to_string();
                // Without <>, a `;expires=` belongs to the header, not the URI.
                (uri, parts.map(|p| p.trim().to_string()).collect())
            }
        };
        if !(uri.starts_with("sip:") || uri.starts_with("sips:"))
            || (!uri.contains('@') && !uri.contains(':'))
        {
            return Err(format!("not a SIP URI in Contact '{}'", item));
        }
        let mut binding = ContactBinding {
            uri,
            expires: None,
            instance_id: None,
            reg_id: None,
        };
        for p in params {
            let (name, val) = match p.split_once('=') {
                Some((n, v)) => (
                    n.trim().to_ascii_lowercase(),
                    v.trim().trim_matches('"').to_string(),
                ),
                None => (p.trim().to_ascii_lowercase(), String::new()),
            };
            match name.as_str() {
                "expires" => {
                    binding.expires = Some(
                        val.parse::<u32>()
                            .map_err(|_| format!("bad expires '{}' in Contact", val))?,
                    )
                }
                "+sip.instance" => binding.instance_id = Some(val),
                "reg-id" => binding.reg_id = val.parse().ok(),
                _ => {}
            }
        }
        out.push(binding);
    }
    if out.is_empty() {
        return Err("empty Contact".into());
    }
    Ok(Some(out))
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTER request handler
// ─────────────────────────────────────────────────────────────────────────────

/// A REGISTER as the handler sees it (headers already parsed).
#[derive(Clone)]
pub struct RegisterRequest {
    pub aor: String,
    pub contacts: Vec<ContactBinding>,
    /// `Contact: *`
    pub wildcard: bool,
    pub expires_header: Option<u32>,
    pub call_id: String,
    pub cseq: u32,
    pub source: SocketAddr,
    pub transport: String,
    pub user_agent: Option<String>,
    pub reply_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

/// What a REGISTER did.
#[derive(Debug)]
pub enum RegisterResult {
    /// 200 OK: every current binding of the AOR, plus what this request
    /// registered (new or refreshed) and removed.
    Ok {
        bindings: Vec<Registration>,
        registered: Vec<Registration>,
        removed: Vec<Registration>,
        /// The interval granted to the request's own contacts.
        granted: Option<u32>,
    },
    /// 423 Interval Too Brief with `Min-Expires`.
    IntervalTooBrief { min_expires: u32 },
    /// 400.
    BadRequest(String),
}

pub struct RegisterHandler {
    registrar: Arc<dyn Registrar>,
}

impl RegisterHandler {
    pub fn new(registrar: Arc<dyn Registrar>) -> Self {
        Self { registrar }
    }

    pub fn registrar(&self) -> Arc<dyn Registrar> {
        self.registrar.clone()
    }

    pub fn new_inmemory() -> Self {
        Self::new(Arc::new(InMemoryRegistrar::new()))
    }

    /// Apply a REGISTER (RFC 3261 §10.3 steps 6-8) under `policy`. The
    /// interval is checked for every contact before anything is stored.
    pub async fn process(
        &self,
        policy: RegisterPolicy,
        req: RegisterRequest,
    ) -> Result<RegisterResult> {
        if req.wildcard {
            if !req.contacts.is_empty() {
                return Ok(RegisterResult::BadRequest(
                    "Contact: * cannot be combined with other contacts".into(),
                ));
            }
            return Ok(match req.expires_header {
                Some(0) => {
                    let removed = self
                        .registrar
                        .unregister_all(&req.aor, Some((&req.call_id, req.cseq)))
                        .await?;
                    RegisterResult::Ok {
                        bindings: Vec::new(),
                        registered: Vec::new(),
                        removed,
                        granted: None,
                    }
                }
                _ => RegisterResult::BadRequest("Contact: * requires Expires: 0".into()),
            });
        }
        if req.contacts.is_empty() {
            return Ok(RegisterResult::Ok {
                bindings: self.registrar.lookup(&req.aor).await?,
                registered: Vec::new(),
                removed: Vec::new(),
                granted: None,
            });
        }
        if req.contacts.len() > MAX_CONTACTS_PER_REQUEST {
            return Ok(RegisterResult::BadRequest(format!(
                "too many Contact bindings in one REGISTER ({}, max {})",
                req.contacts.len(),
                MAX_CONTACTS_PER_REQUEST
            )));
        }
        let mut plan: Vec<(ContactBinding, u32)> = Vec::new();
        for c in &req.contacts {
            let asked = c
                .expires
                .or(req.expires_header)
                .unwrap_or(policy.default_expires);
            if asked > 0 && asked < policy.min_expires {
                return Ok(RegisterResult::IntervalTooBrief {
                    min_expires: policy.min_expires,
                });
            }
            plan.push((c.clone(), asked.min(policy.max_expires)));
        }
        let mut registered = Vec::new();
        let mut removed = Vec::new();
        let mut granted = None;
        for (c, expires) in plan {
            let key = binding_key(&c.uri, c.instance_id.as_deref(), c.reg_id);
            if self
                .registrar
                .is_out_of_order(&req.aor, &key, &req.call_id, req.cseq)
                .await
            {
                // RFC 3261 §10.3 step 7: a request that is not newer than
                // what this dialog already did changes nothing.
                debug!(
                    "REGISTER: {} CSeq {} is not newer for {} — binding left alone",
                    req.call_id, req.cseq, c.uri
                );
                continue;
            }
            if expires == 0 {
                if let Some(r) = self
                    .registrar
                    .unregister_binding(&req.aor, &key, Some((&req.call_id, req.cseq)))
                    .await?
                {
                    removed.push(r);
                }
                continue;
            }
            let mut reg = Registration::new(
                req.aor.clone(),
                c.uri.clone(),
                expires,
                req.call_id.clone(),
                req.cseq,
                req.source,
                &req.transport,
            );
            reg.user_agent = req.user_agent.clone();
            reg.reply_tx = req.reply_tx.clone();
            reg.instance_id = c.instance_id.clone();
            reg.reg_id = c.reg_id;
            registered.push(self.registrar.register(reg).await?);
            granted.get_or_insert(expires);
        }
        Ok(RegisterResult::Ok {
            bindings: self.registrar.lookup(&req.aor).await?,
            registered,
            removed,
            granted,
        })
    }

    pub async fn lookup(&self, aor: &str) -> Result<Vec<Registration>> {
        let normalized = canonical_aor(aor);
        let results = self.registrar.lookup(&normalized).await?;
        if !results.is_empty() {
            return Ok(results);
        }
        if !normalized.starts_with("sip:") && !normalized.starts_with("sips:") {
            let with_sip = format!("sip:{}", normalized);
            return self.registrar.lookup(&with_sip).await;
        }
        Ok(vec![])
    }

    pub async fn count(&self) -> u64 {
        self.registrar.count().await
    }

    pub async fn all_registrations(&self) -> Result<Vec<Registration>> {
        self.registrar.all_registrations().await
    }

    pub async fn registered_users(&self, source_ip: &str) -> (Vec<String>, Vec<String>) {
        self.registrar.registered_users(source_ip).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("192.168.1.100:{}", port).parse().unwrap()
    }
    fn aor() -> &'static str {
        "sip:alice@example.com"
    }

    fn reg(contact: &str, expires: u32, call_id: &str, port: u16) -> Registration {
        Registration::new(
            aor().to_string(),
            contact.to_string(),
            expires,
            call_id.to_string(),
            1,
            addr(port),
            "UDP",
        )
    }

    /// A client's CSeq grows within its Call-ID (RFC 3261 §8.1.1.5), so
    /// the helper does too.
    fn next_cseq() -> u32 {
        static CSEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        CSEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    fn request(
        contacts: Vec<ContactBinding>,
        wildcard: bool,
        expires: Option<u32>,
    ) -> RegisterRequest {
        RegisterRequest {
            aor: aor().to_string(),
            contacts,
            wildcard,
            expires_header: expires,
            call_id: "cid-1".into(),
            cseq: next_cseq(),
            source: addr(5060),
            transport: "UDP".into(),
            user_agent: Some("Test/1".into()),
            reply_tx: None,
        }
    }

    fn contact(uri: &str, expires: Option<u32>) -> ContactBinding {
        ContactBinding {
            uri: uri.into(),
            expires,
            instance_id: None,
            reg_id: None,
        }
    }

    #[test]
    fn contact_header_parsing() {
        assert_eq!(parse_contact_header("*").unwrap(), None);
        let one = parse_contact_header("<sip:alice@10.0.0.9:5060;transport=tcp>;expires=1800")
            .unwrap()
            .unwrap();
        assert_eq!(one[0].uri, "sip:alice@10.0.0.9:5060;transport=tcp");
        assert_eq!(one[0].expires, Some(1800));
        let two = parse_contact_header(
            "\"A, B\" <sip:a@h>;q=0.5, <sip:b@h>;+sip.instance=\"<urn:uuid:1234>\";reg-id=2",
        )
        .unwrap()
        .unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[1].instance_id.as_deref(), Some("<urn:uuid:1234>"));
        assert_eq!(two[1].reg_id, Some(2));
        let bare = parse_contact_header("sip:c@h;expires=60").unwrap().unwrap();
        assert_eq!(
            (bare[0].uri.as_str(), bare[0].expires),
            ("sip:c@h", Some(60))
        );
        assert!(parse_contact_header("garbage<<").is_err());
        assert!(parse_contact_header("<sip:a@h>;expires=x").is_err());
    }

    #[tokio::test]
    async fn two_contacts_of_one_aor_from_one_ip_coexist() {
        let r = InMemoryRegistrar::new();
        r.register(reg("sip:alice@192.168.1.10:5060", 3600, "c1", 5080))
            .await
            .unwrap();
        r.register(reg("sip:alice@192.168.1.11:5060", 3600, "c2", 5081))
            .await
            .unwrap();
        assert_eq!(r.count().await, 2, "no same-IP purge");
        let key = binding_key("sip:alice@192.168.1.10:5060", None, None);
        let removed = r.unregister_binding(aor(), &key, None).await.unwrap();
        assert_eq!(removed.unwrap().contact, "sip:alice@192.168.1.10:5060");
        assert_eq!(
            r.lookup(aor()).await.unwrap()[0].contact,
            "sip:alice@192.168.1.11:5060"
        );
    }

    #[test]
    fn aors_have_one_spelling() {
        for (raw, want) in [
            ("sip:Alice@SIP.Example.COM", "sip:Alice@sip.example.com"),
            (
                "\"Alice\" <sip:alice@sip.example.com:5060>",
                "sip:alice@sip.example.com",
            ),
            (
                "<sip:alice@sip.example.com;transport=tcp>",
                "sip:alice@sip.example.com",
            ),
            (
                "sip:alice@sip.example.com?X-Custom=1",
                "sip:alice@sip.example.com",
            ),
            ("sips:alice@Example.com:5061", "sips:alice@example.com"),
            ("alice@example.com", "alice@example.com"),
            ("sip:+33123456789@1.2.3.4:5080", "sip:+33123456789@1.2.3.4"),
        ] {
            assert_eq!(canonical_aor(raw), want, "{}", raw);
        }
    }

    /// RFC 3261 §10.3 step 7: a REGISTER that a client already superseded
    /// must not resurrect the binding it removed.
    #[tokio::test]
    async fn a_retransmitted_register_cannot_resurrect_a_removed_binding() {
        let h = RegisterHandler::new_inmemory();
        let policy = RegisterPolicy::default();
        let mut first = request(
            vec![contact("sip:alice@10.0.0.9:5060", Some(3600))],
            false,
            None,
        );
        first.cseq = 9;
        assert!(matches!(
            h.process(policy, first.clone()).await.unwrap(),
            RegisterResult::Ok { .. }
        ));
        assert_eq!(h.count().await, 1);

        // The phone un-registers (same dialog, next CSeq).
        let mut bye = request(
            vec![contact("sip:alice@10.0.0.9:5060", Some(0))],
            false,
            None,
        );
        bye.cseq = 10;
        match h.process(policy, bye).await.unwrap() {
            RegisterResult::Ok { removed, .. } => assert_eq!(removed.len(), 1),
            other => panic!("{:?}", other),
        }
        assert_eq!(h.count().await, 0);

        // A duplicate of the first request arrives late: nothing changes.
        match h.process(policy, first).await.unwrap() {
            RegisterResult::Ok {
                bindings,
                registered,
                removed,
                ..
            } => {
                assert!(bindings.is_empty(), "{:?}", bindings);
                assert!(registered.is_empty() && removed.is_empty());
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(h.count().await, 0, "the binding stayed removed");

        // A genuinely newer request registers again.
        let mut again = request(
            vec![contact("sip:alice@10.0.0.9:5060", Some(3600))],
            false,
            None,
        );
        again.cseq = 11;
        assert!(matches!(
            h.process(policy, again).await.unwrap(),
            RegisterResult::Ok { .. }
        ));
        assert_eq!(h.count().await, 1);
    }

    /// One credential holder must not be able to grow the binding table
    /// without bound (memory, and a per-INVITE scan).
    #[tokio::test]
    async fn bindings_are_capped_per_aor_and_the_oldest_goes_first() {
        let r = InMemoryRegistrar::new();
        for n in 0..(MAX_BINDINGS_PER_AOR + 4) {
            r.register(reg(
                &format!("sip:alice@10.0.0.{}:5060", n),
                3600,
                &format!("c{}", n),
                5060 + n as u16,
            ))
            .await
            .unwrap();
            // Distinct registration timestamps so "oldest" is well defined.
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let bindings = r.lookup(aor()).await.unwrap();
        assert_eq!(bindings.len(), MAX_BINDINGS_PER_AOR);
        let contacts: Vec<&str> = bindings.iter().map(|b| b.contact.as_str()).collect();
        assert!(
            !contacts.contains(&"sip:alice@10.0.0.0:5060"),
            "the oldest binding must be evicted: {:?}",
            contacts
        );
        assert!(
            contacts
                .contains(&format!("sip:alice@10.0.0.{}:5060", MAX_BINDINGS_PER_AOR + 3).as_str()),
            "the newest binding must be kept: {:?}",
            contacts
        );
    }

    /// A REGISTER carrying a flood of Contacts is refused outright.
    #[tokio::test]
    async fn a_register_with_too_many_contacts_is_refused() {
        let h = RegisterHandler::new_inmemory();
        let contacts: Vec<ContactBinding> = (0..MAX_CONTACTS_PER_REQUEST + 1)
            .map(|n| contact(&format!("sip:alice@10.0.0.{}", n), Some(3600)))
            .collect();
        match h
            .process(RegisterPolicy::default(), request(contacts, false, None))
            .await
            .unwrap()
        {
            RegisterResult::BadRequest(why) => assert!(why.contains("too many Contact"), "{}", why),
            other => panic!("{:?}", other),
        }
        assert_eq!(h.count().await, 0);
    }

    #[tokio::test]
    async fn registered_users_splits_by_source_and_skips_expired() {
        let r = InMemoryRegistrar::new();
        r.register(reg("sip:alice@10.0.0.9:5060", 3600, "c1", 5060))
            .await
            .unwrap();
        let mut expired = reg("sip:alice@10.0.0.8:5060", 0, "c2", 5061);
        expired.expires_at = unix_now().saturating_sub(10);
        r.register(expired).await.unwrap();
        let (here, anywhere) = r.registered_users("192.168.1.100").await;
        assert_eq!(here, vec!["alice".to_string()]);
        assert_eq!(anywhere, vec!["alice".to_string()]);
        let (elsewhere, _) = r.registered_users("203.0.113.1").await;
        assert!(elsewhere.is_empty());
    }

    #[tokio::test]
    async fn refresh_updates_source_address_and_call_id() {
        let r = InMemoryRegistrar::new();
        r.register(reg("sip:alice@192.168.1.10:5060", 3600, "c1", 5080))
            .await
            .unwrap();
        let stored = r
            .register(reg("sip:alice@192.168.1.10:5060", 1800, "c2", 6100))
            .await
            .unwrap();
        assert_eq!(r.count().await, 1);
        assert_eq!(
            (
                stored.received_port,
                stored.call_id.as_str(),
                stored.expires
            ),
            (6100, "c2", 1800)
        );
    }

    #[tokio::test]
    async fn instance_binding_replaces_the_contact_in_place() {
        let r = InMemoryRegistrar::new();
        let mut a = reg("sip:alice@10.0.0.9:5060", 3600, "c1", 5060);
        a.instance_id = Some("<urn:uuid:abcd>".into());
        a.reg_id = Some(1);
        r.register(a).await.unwrap();
        let mut b = reg("sip:alice@10.0.0.9:6100", 3600, "c2", 6100);
        b.instance_id = Some("<urn:uuid:abcd>".into());
        b.reg_id = Some(1);
        r.register(b).await.unwrap();
        let all = r.lookup(aor()).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].contact, "sip:alice@10.0.0.9:6100");
        // The instance id alone (no reg-id) also collapses — an extension of RFC 5626.
        let mut c = reg("sip:alice@10.0.0.9:7000", 3600, "c3", 7000);
        c.instance_id = Some("<urn:uuid:efgh>".into());
        r.register(c.clone()).await.unwrap();
        c.contact = "sip:alice@10.0.0.9:7001".into();
        r.register(c).await.unwrap();
        assert_eq!(r.count().await, 2);
    }

    #[tokio::test]
    async fn stale_unregister_within_500ms_is_ignored() {
        let r = InMemoryRegistrar::new();
        r.register(reg("sip:alice@192.168.1.10:5060", 3600, "new", 5080))
            .await
            .unwrap();
        let key = binding_key("sip:alice@192.168.1.10:5060", None, None);
        assert!(r
            .unregister_binding(aor(), &key, Some(("old", 1)))
            .await
            .unwrap()
            .is_none());
        assert_eq!(r.count().await, 1);
        assert!(r
            .unregister_binding(aor(), &key, Some(("new", 2)))
            .await
            .unwrap()
            .is_some());
        assert_eq!(r.count().await, 0);
    }

    #[tokio::test]
    async fn count_excludes_expired_and_cleanup_returns_them() {
        let r = InMemoryRegistrar::new();
        let mut expired = reg("sip:alice@192.168.1.10:5060", 3600, "c1", 5080);
        expired.expires_at = unix_now() - 1;
        r.regs
            .write()
            .await
            .insert((expired.aor.clone(), expired.binding_key()), expired);
        r.register(reg("sip:alice@192.168.1.11:5060", 3600, "c2", 5081))
            .await
            .unwrap();
        assert_eq!(r.count().await, 1);
        assert_eq!(r.all_registrations().await.unwrap().len(), 1);
        let removed = r.cleanup_expired().await.unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].contact, "sip:alice@192.168.1.10:5060");
    }

    #[tokio::test]
    async fn process_rejects_below_min_before_touching_the_store_and_clamps_to_max() {
        let h = RegisterHandler::new_inmemory();
        let policy = RegisterPolicy::default();
        let r = h
            .process(
                policy,
                request(
                    vec![contact("sip:a@h", Some(3600)), contact("sip:b@h", Some(10))],
                    false,
                    None,
                ),
            )
            .await
            .unwrap();
        assert!(matches!(
            r,
            RegisterResult::IntervalTooBrief { min_expires: 60 }
        ));
        assert_eq!(h.count().await, 0);

        let r = h
            .process(
                policy,
                request(vec![contact("sip:a@h", None)], false, Some(86400)),
            )
            .await
            .unwrap();
        match r {
            RegisterResult::Ok {
                registered,
                granted,
                bindings,
                ..
            } => {
                assert_eq!(granted, Some(3600));
                assert_eq!(registered[0].expires, 3600);
                assert_eq!(bindings.len(), 1);
            }
            other => panic!("{:?}", other),
        }
        // Default when nothing is asked.
        let r = h
            .process(policy, request(vec![contact("sip:c@h", None)], false, None))
            .await
            .unwrap();
        assert!(matches!(
            r,
            RegisterResult::Ok {
                granted: Some(3600),
                ..
            }
        ));
        // Zero removes: with the same call-id.
        let r = h
            .process(
                policy,
                request(vec![contact("sip:c@h", Some(0))], false, None),
            )
            .await
            .unwrap();
        match r {
            RegisterResult::Ok {
                removed, bindings, ..
            } => {
                assert_eq!(removed.len(), 1);
                assert_eq!(bindings.len(), 1);
            }
            other => panic!("{:?}", other),
        }
    }

    #[tokio::test]
    async fn process_wildcard_and_query_rules() {
        let h = RegisterHandler::new_inmemory();
        let policy = RegisterPolicy::default();
        h.process(
            policy,
            request(
                vec![contact("sip:a@h", None), contact("sip:b@h", None)],
                false,
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(h.count().await, 2);
        // Query: nothing changes, bindings listed.
        match h
            .process(policy, request(vec![], false, None))
            .await
            .unwrap()
        {
            RegisterResult::Ok {
                bindings,
                registered,
                removed,
                granted,
            } => {
                assert_eq!(bindings.len(), 2);
                assert!(registered.is_empty() && removed.is_empty() && granted.is_none());
            }
            other => panic!("{:?}", other),
        }
        assert!(matches!(
            h.process(policy, request(vec![], true, Some(3600)))
                .await
                .unwrap(),
            RegisterResult::BadRequest(_)
        ));
        assert!(matches!(
            h.process(
                policy,
                request(vec![contact("sip:a@h", None)], true, Some(0))
            )
            .await
            .unwrap(),
            RegisterResult::BadRequest(_)
        ));
        match h
            .process(policy, request(vec![], true, Some(0)))
            .await
            .unwrap()
        {
            RegisterResult::Ok {
                removed, bindings, ..
            } => {
                assert_eq!(removed.len(), 2);
                assert!(bindings.is_empty());
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(h.count().await, 0);
    }

    #[test]
    fn policy_from_config_corrects_nonsense() {
        let mut sec = crate::config::SbcConfig::default().security;
        sec.register_min_expires = 0;
        sec.register_max_expires = 10;
        sec.register_default_expires = 999;
        let p = RegisterPolicy::from_config(&sec);
        assert_eq!(
            (p.min_expires, p.max_expires, p.default_expires),
            (1, 10, 10)
        );
    }

    #[test]
    fn registration_is_valid_and_remaining() {
        let r = reg("sip:a@h", 60, "c", 5060);
        assert!(r.is_valid());
        assert!(r.remaining_secs() <= 60);
    }
}
