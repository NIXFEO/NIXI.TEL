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

    /// Remove one binding by key. With a Call-ID, a binding refreshed less
    /// than 500 ms ago by a *different* REGISTER dialog is kept (a stale
    /// un-REGISTER racing a fresh REGISTER, RFC 3261 §10.3). Returns the
    /// removed binding.
    async fn unregister_binding(
        &self,
        aor: &str,
        key: &str,
        call_id: Option<&str>,
    ) -> Result<Option<Registration>>;

    /// Remove every binding of an AOR (`Contact: *`); returns them.
    async fn unregister_all(&self, aor: &str) -> Result<Vec<Registration>>;

    /// The unexpired bindings of an AOR.
    async fn lookup(&self, aor: &str) -> Result<Vec<Registration>>;

    /// Drop expired bindings (called by the sweeper); returns them.
    async fn cleanup_expired(&self) -> Result<Vec<Registration>>;

    /// Unexpired bindings.
    async fn count(&self) -> u64;

    /// Every unexpired binding (admin API, identity gate, WS close).
    async fn all_registrations(&self) -> Result<Vec<Registration>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory backend
// ─────────────────────────────────────────────────────────────────────────────

/// Key: (AOR, binding key)
type RegKey = (String, String);

pub struct InMemoryRegistrar {
    regs: Arc<RwLock<HashMap<RegKey, Registration>>>,
}

impl InMemoryRegistrar {
    pub fn new() -> Self {
        Self {
            regs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Registrar for InMemoryRegistrar {
    async fn register(&self, reg: Registration) -> Result<Registration> {
        let key = (reg.aor.clone(), reg.binding_key());
        let mut map = self.regs.write().await;
        match map.get_mut(&key) {
            Some(existing) => {
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
                map.insert(key.clone(), reg);
                Ok(map[&key].clone())
            }
        }
    }

    async fn unregister_binding(
        &self,
        aor: &str,
        key: &str,
        call_id: Option<&str>,
    ) -> Result<Option<Registration>> {
        let key = (aor.to_string(), key.to_string());
        let mut map = self.regs.write().await;
        let Some(existing) = map.get(&key) else {
            return Ok(None);
        };
        if let Some(cid) = call_id {
            if existing.call_id != cid {
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
        if let Some(r) = &removed {
            info!("REGISTER: removed {} <-> {}", aor, r.contact);
        }
        Ok(removed)
    }

    async fn unregister_all(&self, aor: &str) -> Result<Vec<Registration>> {
        let mut map = self.regs.write().await;
        let keys: Vec<RegKey> = map.keys().filter(|(a, _)| a == aor).cloned().collect();
        let removed: Vec<Registration> = keys.iter().filter_map(|k| map.remove(k)).collect();
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

    async fn cleanup_expired(&self) -> Result<Vec<Registration>> {
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
                    let removed = self.registrar.unregister_all(&req.aor).await?;
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
            if expires == 0 {
                if let Some(r) = self
                    .registrar
                    .unregister_binding(&req.aor, &key, Some(&req.call_id))
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
        let s = aor.trim();
        let normalized = if let (Some(start), Some(end)) = (s.find('<'), s.rfind('>')) {
            s[start + 1..end].trim().to_string()
        } else {
            s.to_string()
        };
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
            cseq: 1,
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
            .unregister_binding(aor(), &key, Some("old"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(r.count().await, 1);
        assert!(r
            .unregister_binding(aor(), &key, Some("new"))
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
