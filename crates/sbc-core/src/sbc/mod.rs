//! Integrated SBC Core
//!
//! Combines Transport, Transaction, Dialog, Media, B2BUA, Router, Auth,
//! ACL, DoS protection, REGISTER handling, and Topology hiding into a
//! single SBC instance that owns the full message processing pipeline.

mod invite_handler;
pub(crate) use invite_handler::extract_contact_uri as invite_handler_contact_uri;
mod response_handler;
pub(crate) use response_handler::parse_session_expires as response_handler_session_expires;
pub mod backup;
mod call_handler;
mod cdr;
mod invite_tx;
mod trunk_state;
pub(crate) use cdr::CallOutcome;
#[cfg(test)]
mod flow_tests;
pub mod hydrate;
pub mod import;
#[cfg(test)]
pub(crate) mod test_support;

use crate::acl::{AclManager, Direction};
use crate::auth::{generate_digest_response, DigestAuthenticator, DigestChallenge};
use crate::b2bua::B2buaManager;
use crate::config::{DidMapping, NetworkConfig, SbcConfig};
use crate::dos::{DosProtector, RateLimitConfig};
use crate::maintenance::{MaintenanceConfig, MaintenanceHandle, MaintenanceTask};
use crate::media::dtls::DtlsUdpBridge;
use crate::media::sdp::transform_webrtc_to_trunk;
use crate::media::webrtc_handler::WebRtcSession;
use crate::media::MediaManager;
use crate::metrics::SbcMetrics;
use crate::register::{InMemoryRegistrar, RegisterHandler, RegisterResult};
use crate::routing::router::Router;
use crate::routing::trunk::NumberFormat;
use crate::routing::{TrunkConfig, TrunkManager};
use crate::storage::CdrManager;
use crate::topology::{apply_topology_hiding_outbound, SbcIdentity};
use crate::transport::manager::TransportManager;
use crate::transport::udp::ReceivedMessage;
use crate::{Error, Result};
use dashmap::DashMap;
use rsip::prelude::*;
use rsip::{Method, Request, Response, SipMessage};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};

/// Integrated SBC combining all layers
/// How claimed identities are policed (`[security]`).
#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    /// 403 (true) or log-only on a REGISTER for someone else's AOR.
    pub enforce_register_aor: bool,
    /// Hosts accepted as the domain of an AOR / local From, besides the
    /// realm, the SBC domain, its public IP and loopback.
    pub served_domains: Vec<String>,
    /// 403 (true) or flag-and-relay an INVITE from a trunk whose From
    /// claims a local user.
    pub reject_trunk_local_from: bool,
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        Self {
            enforce_register_aor: true,
            served_domains: Vec::new(),
            reject_trunk_local_from: false,
        }
    }
}

impl IdentityPolicy {
    pub fn from_config(sec: &crate::config::SecurityConfig) -> Self {
        Self {
            enforce_register_aor: !sec.register_aor_check.eq_ignore_ascii_case("log"),
            served_domains: sec
                .served_domains
                .iter()
                .map(|d| d.trim().to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            reject_trunk_local_from: sec.trunk_local_from.eq_ignore_ascii_case("reject"),
        }
    }
}

/// Why an authenticated user may not act for an AOR (RFC 3261 §10.3 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AorRejection {
    /// The AOR's user part is not the authenticated user.
    User(String),
    /// The AOR's host is not a domain this SBC serves.
    Domain(String),
}

impl std::fmt::Display for AorRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(u) => write!(f, "AOR belongs to '{}'", u),
            Self::Domain(d) => write!(f, "domain '{}' is not served here", d),
        }
    }
}

/// The addr-spec of a name-addr or addr-spec header value: what is
/// between the LAST `<` and the following `>` (a quoted display name may
/// contain anything, including `<`, `@` or `;`), else the value up to its
/// first header parameter.
pub(crate) fn addr_spec(value: &str) -> &str {
    let s = value.trim();
    match (s.rfind('<'), s.rfind('>')) {
        (Some(a), Some(b)) if a < b => s[a + 1..b].trim(),
        _ => s.split(';').next().unwrap_or(s).trim(),
    }
}

/// User part of a SIP URI ("sip:alice@h;p" → "alice"), None without one.
pub(crate) fn uri_user(uri: &str) -> Option<String> {
    let s = addr_spec(uri);
    let s = s
        .strip_prefix("sips:")
        .or_else(|| s.strip_prefix("sip:"))
        .unwrap_or(s);
    let (user, _) = s.split_once('@')?;
    let user = user.split(';').next().unwrap_or(user).trim();
    (!user.is_empty()).then(|| user.to_string())
}

/// Host of a SIP URI, lowercased, without port, params or brackets.
pub(crate) fn uri_host(uri: &str) -> Option<String> {
    let s = addr_spec(uri);
    let s = s
        .strip_prefix("sips:")
        .or_else(|| s.strip_prefix("sip:"))
        .unwrap_or(s);
    let host_port = s.split_once('@').map(|(_, h)| h).unwrap_or(s);
    let host_port = host_port
        .split([';', '>', '?'])
        .next()
        .unwrap_or(host_port)
        .trim();
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// May `auth_user` bind `aor`? User part must be its own; host must be
/// served (skipped when no served domain is known at all).
pub(crate) fn authorize_aor(
    auth_user: &str,
    aor: &str,
    served: &[String],
) -> std::result::Result<(), AorRejection> {
    let user = uri_user(aor).unwrap_or_default();
    if user != auth_user {
        return Err(AorRejection::User(user));
    }
    if !served.is_empty() {
        let host = uri_host(aor).unwrap_or_default();
        if !served.iter().any(|d| d.eq_ignore_ascii_case(&host)) {
            return Err(AorRejection::Domain(host));
        }
    }
    Ok(())
}

/// What `/ready` reports: the store is open, the first hydration
/// succeeded, the SIP listeners are bound. A reload that fails later keeps
/// the last good runtime and does not clear the flags.
#[derive(Default, Debug)]
pub struct Readiness {
    store_open: std::sync::atomic::AtomicBool,
    hydrated: std::sync::atomic::AtomicBool,
    listening: std::sync::atomic::AtomicBool,
}

impl Readiness {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_store_open(&self) {
        self.store_open
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn set_hydrated(&self) {
        self.hydrated
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn set_listening(&self) {
        self.listening
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn store_open(&self) -> bool {
        self.store_open.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn hydrated(&self) -> bool {
        self.hydrated.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn listening(&self) -> bool {
        self.listening.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn is_ready(&self) -> bool {
        self.store_open() && self.hydrated() && self.listening()
    }
}

/// Administrative teardown requests (`DELETE /api/v1/calls/{uuid}`). The
/// API has no SIP transport: it queues the uuid here and the event loop
/// ends the call properly (BYE/CANCEL on both legs, CDR "admin-kick").
#[derive(Default)]
pub struct AdminKicks {
    queue: std::sync::Mutex<Vec<String>>,
    notify: tokio::sync::Notify,
}

impl AdminKicks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a call for teardown and wake the event loop.
    pub fn request(&self, uuid: String) {
        if let Ok(mut q) = self.queue.lock() {
            if !q.contains(&uuid) {
                q.push(uuid);
            }
        }
        self.notify.notify_one();
    }

    /// Take every queued uuid.
    pub fn drain(&self) -> Vec<String> {
        self.queue
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    /// Queued uuids (not yet processed by the engine).
    pub fn pending(&self) -> Vec<String> {
        self.queue.lock().map(|q| q.clone()).unwrap_or_default()
    }

    /// Resolves when a request was queued (permit-based: never misses one).
    pub async fn notified(&self) {
        self.notify.notified().await
    }
}

pub struct Sbc {
    /// Transport layer (UDP, TCP, TLS, WSS)
    transport: TransportManager,

    /// Media layer (RTP proxy, SDP manipulation)
    media: Arc<MediaManager>,

    /// B2BUA call manager (dual-leg call state)
    b2bua: Arc<B2buaManager>,

    /// SIP message router (trunk selection)
    router: Arc<Router>,

    /// REGISTER handler (SIP registrar)
    register_handler: Arc<RegisterHandler>,

    /// Digest authenticator (401 challenge / verify)
    auth: Option<Arc<DigestAuthenticator>>,

    /// IP access control list
    acl: Arc<AclManager>,

    /// DoS / rate limiting protector
    dos: Arc<DosProtector>,

    /// SBC topology identity (public IP / domain for Via rewriting)
    identity: Option<SbcIdentity>,

    /// Whether Digest auth is enabled for REGISTER
    enable_digest_auth: bool,

    /// SBC operational metrics (counters for Prometheus)
    metrics: Arc<SbcMetrics>,

    /// CDR (Call Detail Records) manager
    cdr: Arc<CdrManager>,

    /// Background maintenance tasks handle
    _maintenance: Option<MaintenanceHandle>,

    /// Path to configuration file (for SIGHUP hot-reload)
    config_path: Option<String>,

    /// Trunk manager reference (for outbound REGISTER, hot-reload)
    pub trunk_manager: Arc<TrunkManager>,

    /// Pending outbound REGISTER responses (Call-ID → oneshot sender)
    /// Used by TrunkRegistrar to receive 401/407/200 responses to its REGISTER requests
    pub pending_register_responses: crate::trunk_tasks::PendingResponses,

    /// OPTIONS health checks and outbound REGISTER loops, one set per
    /// enabled trunk, following the trunk table (`trunk_tasks.rs`).
    trunk_tasks: Arc<crate::trunk_tasks::TrunkTasks>,

    /// What `/ready` reports.
    readiness: Arc<Readiness>,
    /// Store backups (`POST /api/v1/backup`, timer).
    backup_policy: Arc<backup::BackupPolicy>,
    backup_lock: Arc<tokio::sync::Mutex<()>>,
    _backup_timer: Option<tokio::task::JoinHandle<()>>,

    /// DID → SIP user mappings for inbound PSTN calls.
    /// Shared with the API layer (hydrated from the SQLite store).
    did_mappings: Arc<tokio::sync::RwLock<Vec<DidMapping>>>,

    /// Known trunk IPs (whitelisted for inbound INVITE anti-spam).
    /// Shared with the API layer (refreshed when trunks change).
    trunk_ips: Arc<tokio::sync::RwLock<Vec<String>>>,

    /// Notify signal for API-triggered config reload
    reload_notify: Arc<tokio::sync::Notify>,

    /// SQLite store for dynamic config (users, DIDs, trunks, routes, ACL).
    /// `None` when the store could not be opened (SBC still boots from TOML).
    config_store: Option<Arc<sbc_storage::ConfigStore>>,

    /// Event bus feeding the SSE API endpoint.
    events: crate::events::EventBus,

    /// Outbound INVITE answer timeout before trunk failover.
    invite_timeout: Duration,

    /// `security.call_setup_timeout`: an INVITE unanswered this long is
    /// CANCELed toward the callee and answered 408 to the caller.
    call_setup_timeout: Duration,

    /// Teardown requests from the management API.
    admin_kicks: Arc<AdminKicks>,

    /// REGISTER / INVITE identity rules (`[security]`).
    identity_policy: IdentityPolicy,

    /// INVITE server transactions in flight or just completed: a
    /// retransmission replays the last response (RFC 3261 §17.2.1).
    invite_tx: invite_tx::InviteTxCache,

    /// Hard cap on a connected call (`security.max_call_duration`): past it
    /// the SBC BYEs both legs, so a callee that vanished without BYE cannot
    /// pin a trunk session forever.
    max_call_duration: Duration,

    /// RFC 4028 session timers (None = disabled): (session_expires, min_se).
    session_timer: Option<(u32, u32)>,

    /// Anti-fraud: bans, destination blocking, per-user limits.
    security: Arc<crate::security::SecurityManager>,
}

impl Sbc {
    /// Create a new SBC instance from full configuration. Nothing HTTP is
    /// started here: the management API (axum, `sbc-management`) is
    /// assembled by the binary from the SBC's handles, fail-closed on the
    /// API token.
    pub async fn new_from_config(config: &SbcConfig) -> Result<Self> {
        Self::_new_from_config_inner(config).await
    }

    async fn _new_from_config_inner(config: &SbcConfig) -> Result<Self> {
        // --- Metrics (created early so counters can be shared with Media) ---
        let metrics = Arc::new(SbcMetrics::new());

        // --- Media ---
        let port_range = config.media.rtp_port_range.0..config.media.rtp_port_range.1;
        let public_ip = config.network.public_ipv4.map(|ip| {
            std::net::IpAddr::V4(match ip {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
            })
        });
        let mut media_mgr = MediaManager::with_port_range(port_range, public_ip);
        media_mgr.set_global_rtp_counter(metrics.rtp_packets_total.clone());
        media_mgr.set_global_srtp_encrypt_counter(metrics.srtp_encrypted_total.clone());
        media_mgr.set_global_srtp_decrypt_counter(metrics.srtp_decrypted_total.clone());
        media_mgr.set_global_rtp_timeout_counter(metrics.rtp_timeouts_total.clone());
        media_mgr.set_rtp_timeout(config.security.rtp_timeout.max(10));
        media_mgr.set_global_transcode_counter(metrics.transcoded_total.clone());
        let media = Arc::new(media_mgr);

        // --- B2BUA ---
        let b2bua = Arc::new(B2buaManager::new(media.clone()));

        // --- Router / Trunks ---
        let trunk_manager = Arc::new(TrunkManager::new());

        // Load trunks from TOML config [[trunks]] sections
        for tc in &config.trunks {
            if !tc.enabled {
                info!("Trunk '{}' is disabled, skipping", tc.name);
                continue;
            }
            let transport = match tc.transport.to_uppercase().as_str() {
                "TCP" => crate::routing::TransportType::Tcp,
                "TLS" => crate::routing::TransportType::Tls,
                "WSS" => crate::routing::TransportType::Wss,
                "WS" => crate::routing::TransportType::Ws,
                _ => crate::routing::TransportType::Udp,
            };
            let number_format = match tc.number_format.to_lowercase().as_str() {
                "national" => NumberFormat::National,
                "local" => NumberFormat::Local,
                _ => NumberFormat::E164,
            };
            let mut trunk = TrunkConfig {
                id: uuid::Uuid::new_v4(),
                name: tc.name.clone(),
                enabled: true,
                transport,
                host: tc.host.clone(),
                port: tc.port,
                resolved_addr: None,
                auth_required: tc.auth_required,
                username: tc.username.clone(),
                password: tc.password.clone(),
                realm: tc.realm.clone(),
                allowed_codecs: tc.allowed_codecs.clone(),
                transcoding_enabled: false,
                max_concurrent_calls: tc.max_concurrent_calls,
                calls_per_second: 10,
                allowed_ips: Vec::new(),
                register_with_trunk: tc.register_with_trunk,
                registration_interval: Duration::from_secs(tc.registration_interval),
                cost_per_minute: tc.cost_per_minute,
                priority: tc.priority,
                weight: tc.weight,
                prefix_patterns: tc.prefix_patterns.clone(),
                number_format,
                country_code: tc.country_code.clone(),
                national_prefix: tc.national_prefix.clone(),
                caller_number_format: None,
                caller_number_override: None,
                caller_display_name: None,
                tls_sni: None,
                tls_ca_cert: None,
                tls_verify: true,
                tls_client_cert: None,
                tls_client_key: None,
            };

            // Resolve DNS for hostnames (e.g. trunk.example.com → IP)
            match trunk.resolve_destination().await {
                Some(addr) => info!(
                    "Loaded trunk '{}' from config → resolved {}:{} → {}",
                    trunk.name, trunk.host, trunk.port, addr
                ),
                None => warn!(
                    "Trunk '{}': DNS resolution failed for {}:{} — will retry",
                    trunk.name, trunk.host, trunk.port
                ),
            }

            let trunk_id = trunk_manager.add_trunk(trunk);
            info!("Trunk '{}' added (id: {})", tc.name, trunk_id);
        }

        let router = Arc::new(Router::new(trunk_manager.clone()));

        // --- Registrar ---
        let registrar: Arc<dyn crate::register::Registrar> = Arc::new(InMemoryRegistrar::new());
        let register_handler = Arc::new(RegisterHandler::new(registrar.clone()));

        // --- Digest Auth ---
        // Created whenever digest auth is enabled, even with no TOML users:
        // the user database may live entirely in the SQLite store.
        let (auth, enable_digest_auth) = if config.security.enable_digest_auth {
            let authenticator = Arc::new(DigestAuthenticator::new(
                config.security.sip_realm.clone(),
                config.security.sip_users.clone(),
            ));
            (Some(authenticator), true)
        } else {
            (None, false)
        };

        // --- ACL ---
        let acl = Arc::new(AclManager::new_permissive());

        // --- Security / anti-fraud (Ban → ACL → DoS pipeline) ---
        let security = Arc::new(crate::security::SecurityManager::new(
            config.security.features.clone(),
        ));

        // --- DoS ---
        let dos_config = RateLimitConfig {
            requests_per_second: config.security.rate_limit_per_ip,
            burst_size: config.security.rate_limit_per_ip * 2,
            ..Default::default()
        };
        let dos = Arc::new(DosProtector::new(dos_config));

        // --- Topology identity ---
        let identity = config.network.public_ipv4.map(|public_ip| {
            // Extract domain from SIP realm, fallback to IP
            let domain = if !config.security.sip_realm.is_empty()
                && config.security.sip_realm != "sbc.local"
            {
                config.security.sip_realm.clone()
            } else {
                public_ip.to_string()
            };
            SbcIdentity::new(&public_ip.to_string(), &domain, 5060, false)
        });

        // --- Reload notify (shared between API and event loop) ---
        let reload_notify = Arc::new(tokio::sync::Notify::new());

        // --- CDR storage (shared between call handler and API) ---
        let cdr: Arc<CdrManager> = if let Some(ref cdr_file) = config.general.cdr_file {
            match CdrManager::new_file(cdr_file).await {
                Ok(mgr) => {
                    info!("CDR file storage: {}", cdr_file);
                    Arc::new(mgr)
                }
                Err(e) => {
                    warn!(
                        "CDR file storage failed ({}), using memory: {}",
                        cdr_file, e
                    );
                    Arc::new(CdrManager::new_memory())
                }
            }
        } else {
            Arc::new(CdrManager::new_memory())
        };

        // --- Event bus (feeds the SSE API endpoint) ---
        let events = crate::events::EventBus::new();
        b2bua.set_event_bus(events.clone());
        security.set_event_bus(events.clone());

        // --- Shared dynamic-config holders (hydrated from the store) ---
        let did_mappings = Arc::new(tokio::sync::RwLock::new(config.dids.clone()));

        // --- SQLite config store (dynamic config source of truth) ---
        let readiness = Arc::new(Readiness::new());
        let config_store = match sbc_storage::ConfigStore::open(&config.database.sqlite_path).await
        {
            Ok(store) => {
                let store = Arc::new(store);
                import::first_boot_import(&store, config).await;
                import::seed_security(&store, config).await;

                // The store is the source of truth from here on: hydrate the
                // runtime managers from it (TOML entries were seeded above).
                let handles = hydrate::RuntimeHandles {
                    auth: auth.clone(),
                    dids: did_mappings.clone(),
                    trunks: trunk_manager.clone(),
                    acl: acl.clone(),
                    security: security.clone(),
                };
                readiness.set_store_open();
                match hydrate::hydrate_all(&handles, &store).await {
                    Ok(()) => readiness.set_hydrated(),
                    Err(e) if config.database.allow_missing_store => warn!(
                        "Hydration from config store failed: {} — TOML values remain active (allow_missing_store)",
                        e
                    ),
                    Err(e) => {
                        return Err(crate::Error::Config(format!(
                            "config store {}: hydration failed: {} — refusing to start with a runtime that does not match the store (set [database].allow_missing_store = true to run from the TOML seeds only)",
                            config.database.sqlite_path, e
                        )));
                    }
                }
                metrics.set_store_available(readiness.hydrated());

                // Restore persisted bans (restart must not amnesty offenders)
                let now = crate::sbc::import::now_rfc3339();
                match store.load_active_bans(&now).await {
                    Ok(rows) => {
                        let count = rows.len();
                        for row in rows {
                            if let Some(entry) = ban_row_to_entry(&row) {
                                security.bans.restore(entry);
                            }
                        }
                        if count > 0 {
                            info!("Restored {} active ban(s) from store", count);
                        }
                    }
                    Err(e) => warn!("Ban restore failed: {}", e),
                }
                Some(store)
            }
            Err(e) if config.database.allow_missing_store => {
                warn!(
                    "Config store unavailable ({}): {} — running from TOML only (allow_missing_store)",
                    config.database.sqlite_path, e
                );
                None
            }
            Err(e) => {
                return Err(crate::Error::Config(format!(
                    "config store {} cannot be opened: {} — refusing to start with no users, trunks or DIDs (set [database].allow_missing_store = true to run from the TOML seeds only)",
                    config.database.sqlite_path, e
                )));
            }
        };

        // ── Collect trunk IPs for inbound INVITE whitelist ──
        // (after hydration, so API/store-defined trunks are included)
        let trunk_ips_vec: Vec<String> = trunk_manager
            .list_trunks()
            .iter()
            .filter_map(|t| t.resolved_addr.map(|a| a.ip().to_string()))
            .chain(trunk_manager.list_trunks().iter().map(|t| t.host.clone()))
            .chain(config.trunks.iter().map(|t| t.host.clone()))
            .collect();
        if !trunk_ips_vec.is_empty() {
            info!(
                "Trunk IPs whitelisted for inbound INVITE: {:?}",
                trunk_ips_vec
            );
        }
        let trunk_ips = Arc::new(tokio::sync::RwLock::new(trunk_ips_vec));

        // ── Load DID mappings ──
        for did in did_mappings.read().await.iter() {
            info!("DID mapping: {} → {}", did.number, did.user);
        }

        let pending_register_responses: crate::trunk_tasks::PendingResponses =
            Arc::new(DashMap::new());
        let trunk_tasks = Arc::new(crate::trunk_tasks::TrunkTasks::new(
            trunk_manager.clone(),
            pending_register_responses.clone(),
            metrics.clone(),
            events.clone(),
            crate::trunk_tasks::TrunkTasksConfig::from(&config.trunk_health),
        ));
        let backup_policy = Arc::new(config.database.backup_policy());
        Ok(Self {
            readiness,
            backup_policy,
            backup_lock: Arc::new(tokio::sync::Mutex::new(())),
            _backup_timer: None,
            transport: TransportManager::new(),
            media,
            b2bua,
            router,
            register_handler,
            auth,
            acl,
            dos,
            identity,
            enable_digest_auth,
            metrics,
            cdr,
            _maintenance: None,
            config_path: None,
            trunk_manager: trunk_manager.clone(),
            pending_register_responses,
            trunk_tasks,
            did_mappings,
            trunk_ips,
            reload_notify,
            config_store,
            events,
            invite_timeout: Duration::from_secs(config.security.invite_timeout.max(1)),
            call_setup_timeout: Duration::from_secs(config.security.call_setup_timeout.max(10)),
            admin_kicks: Arc::new(AdminKicks::new()),
            identity_policy: IdentityPolicy::from_config(&config.security),
            invite_tx: invite_tx::InviteTxCache::new(),
            max_call_duration: Duration::from_secs(config.security.max_call_duration.max(60)),
            security,
            session_timer: config.security.session_timer_enabled.then(|| {
                (
                    config.security.session_expires.max(config.security.min_se) as u32,
                    config.security.min_se as u32,
                )
            }),
        })
    }

    /// SQLite store for dynamic config, when available.
    pub fn config_store(&self) -> Option<Arc<sbc_storage::ConfigStore>> {
        self.config_store.clone()
    }

    /// Digest authenticator handle (None when digest auth is disabled).
    pub fn auth(&self) -> Option<Arc<DigestAuthenticator>> {
        self.auth.clone()
    }

    /// Shared DID mappings (hydrated from the config store).
    pub fn did_mappings(&self) -> Arc<tokio::sync::RwLock<Vec<DidMapping>>> {
        self.did_mappings.clone()
    }

    /// Persist a ban to the config store (fire-and-forget) so restarts
    /// do not amnesty offenders.
    pub fn persist_ban(&self, entry: &crate::security::BanEntry) {
        let Some(store) = self.config_store.clone() else {
            return;
        };
        let row = sbc_storage::BanRow {
            ip: entry.ip.to_string(),
            reason: entry.reason.clone(),
            banned_at: systemtime_rfc3339(entry.banned_at),
            expires_at: systemtime_rfc3339(entry.expires_at),
            failures: entry.failures as i64,
            manual: entry.manual,
            offense_count: entry.offense_count as i64,
        };
        tokio::spawn(async move {
            if let Err(e) = store.save_ban(&row).await {
                warn!("Ban persistence failed for {}: {}", row.ip, e);
            }
        });
    }

    /// Runtime handles bundle for API-triggered hydration.
    pub fn runtime_handles(&self) -> hydrate::RuntimeHandles {
        hydrate::RuntimeHandles {
            auth: self.auth.clone(),
            dids: self.did_mappings.clone(),
            trunks: self.trunk_manager.clone(),
            acl: self.acl.clone(),
            security: self.security.clone(),
        }
    }

    /// Set the config file path (for SIGHUP hot-reload)
    pub fn set_config_path(&mut self, path: impl Into<String>) {
        self.config_path = Some(path.into());
    }

    /// Get the reload notifier (for API-triggered reload)
    pub fn reload_notify(&self) -> Arc<tokio::sync::Notify> {
        self.reload_notify.clone()
    }

    /// Hot-reload configuration from the TOML file.
    /// Currently reloads: SIP users (Digest auth), trunks.
    /// Preserves: transport listeners, active calls, registrations, nonces.
    pub async fn reload_config(&mut self) -> Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| Error::Config("No config path set for reload".to_string()))?;

        info!("SIGHUP: reloading configuration from {}", path);

        let config = SbcConfig::from_file(path)?;

        // ── RFC 4028 session-timer offer: applied without a restart, so an
        // operator can raise session_expires to a trunk's floor (e.g. 14400
        // for Genesys) on the fly. Affects new calls only.
        let session_timer = config.security.session_timer_enabled.then(|| {
            (
                config.security.session_expires.max(config.security.min_se) as u32,
                config.security.min_se as u32,
            )
        });
        if session_timer != self.session_timer {
            info!(
                "Reload: session timers {:?} → {:?}",
                self.session_timer, session_timer
            );
            self.session_timer = session_timer;
        }
        let max_call_duration = Duration::from_secs(config.security.max_call_duration.max(60));
        if max_call_duration != self.max_call_duration {
            info!(
                "Reload: max_call_duration {}s → {}s",
                self.max_call_duration.as_secs(),
                max_call_duration.as_secs()
            );
            self.max_call_duration = max_call_duration;
        }
        self.identity_policy = IdentityPolicy::from_config(&config.security);
        let setup_timeout = Duration::from_secs(config.security.call_setup_timeout.max(10));
        if setup_timeout != self.call_setup_timeout {
            info!(
                "Reload: call_setup_timeout {}s → {}s",
                self.call_setup_timeout.as_secs(),
                setup_timeout.as_secs()
            );
            self.call_setup_timeout = setup_timeout;
        }

        // ── SQLite store present: it is the source of truth for dynamic
        // config — re-hydrate users/DIDs/trunks/ACL from it and skip the
        // legacy TOML merge below.
        if let Some(store) = self.config_store.clone() {
            let handles = hydrate::RuntimeHandles {
                auth: self.auth.clone(),
                dids: self.did_mappings.clone(),
                trunks: self.trunk_manager.clone(),
                acl: self.acl.clone(),
                security: self.security.clone(),
            };
            hydrate::hydrate_all(&handles, &store).await?;
            self.refresh_trunk_ips().await;
            self.register_trunk_tls_configs();
            self.trunk_tasks.sync();
            info!("Reload: runtime re-hydrated from config store");
            return Ok(());
        }

        // ── Legacy TOML-only reload path ──
        // Reload SIP users in DigestAuthenticator
        if let Some(ref auth) = self.auth {
            if !config.security.sip_users.is_empty() {
                let (added, removed, total) = auth.reload_users(&config.security.sip_users).await;
                info!(
                    "SIGHUP: users reloaded — {} total ({} added, {} removed)",
                    total, added, removed
                );
            } else {
                info!("SIGHUP: no users in config, auth unchanged");
            }
        } else {
            info!("SIGHUP: digest auth not enabled, skipping user reload");
        }

        // Reload trunks from [[trunks]] sections
        // Note: we do NOT remove existing trunks (active calls depend on them).
        // We add new trunks and update existing ones by name.
        let mut trunks_added = 0u32;
        for tc in &config.trunks {
            if !tc.enabled {
                continue;
            }

            // Check if trunk already exists (by name)
            let existing = self
                .trunk_manager
                .list_trunks()
                .iter()
                .find(|t| t.name == tc.name)
                .map(|t| t.id);

            if existing.is_none() {
                let transport = match tc.transport.to_uppercase().as_str() {
                    "TCP" => crate::routing::TransportType::Tcp,
                    "TLS" => crate::routing::TransportType::Tls,
                    "WSS" => crate::routing::TransportType::Wss,
                    "WS" => crate::routing::TransportType::Ws,
                    _ => crate::routing::TransportType::Udp,
                };
                let number_format = match tc.number_format.to_lowercase().as_str() {
                    "national" => NumberFormat::National,
                    "local" => NumberFormat::Local,
                    _ => NumberFormat::E164,
                };
                let mut trunk = TrunkConfig {
                    id: uuid::Uuid::new_v4(),
                    name: tc.name.clone(),
                    enabled: true,
                    transport,
                    host: tc.host.clone(),
                    port: tc.port,
                    resolved_addr: None,
                    auth_required: tc.auth_required,
                    username: tc.username.clone(),
                    password: tc.password.clone(),
                    realm: tc.realm.clone(),
                    allowed_codecs: tc.allowed_codecs.clone(),
                    transcoding_enabled: false,
                    max_concurrent_calls: tc.max_concurrent_calls,
                    calls_per_second: 10,
                    allowed_ips: Vec::new(),
                    register_with_trunk: tc.register_with_trunk,
                    registration_interval: Duration::from_secs(tc.registration_interval),
                    cost_per_minute: tc.cost_per_minute,
                    priority: tc.priority,
                    weight: tc.weight,
                    prefix_patterns: tc.prefix_patterns.clone(),
                    number_format,
                    country_code: tc.country_code.clone(),
                    national_prefix: tc.national_prefix.clone(),
                    caller_number_format: None,
                    caller_number_override: None,
                    caller_display_name: None,
                    tls_sni: None,
                    tls_ca_cert: None,
                    tls_verify: true,
                    tls_client_cert: None,
                    tls_client_key: None,
                };
                let _ = trunk.resolve_destination().await;
                self.trunk_manager.add_trunk(trunk);
                trunks_added += 1;
            }
        }
        let total_trunks = self.trunk_manager.list_trunks().len();
        info!(
            "SIGHUP: trunks reloaded — {} total ({} added)",
            total_trunks, trunks_added
        );

        // Reload DID mappings
        {
            let mut dids = self.did_mappings.write().await;
            *dids = config.dids.clone();
            info!("SIGHUP: DID mappings reloaded — {} entries", dids.len());
        }

        // Reload trunk IPs whitelist and the per-trunk tasks
        self.refresh_trunk_ips().await;
        self.trunk_tasks.sync();

        info!("SIGHUP: configuration reloaded successfully");
        Ok(())
    }

    /// Register outbound-TLS parameters for every TLS trunk with the
    /// transport manager (send_tls refuses unregistered destinations —
    /// plaintext fallback is gone).
    pub fn register_trunk_tls_configs(&self) {
        for t in self.trunk_manager.list_trunks() {
            if t.transport == crate::routing::TransportType::Tls {
                if let Some(dest) = t.destination() {
                    let params = crate::transport::tls_connect::TlsClientParams {
                        sni: t.tls_sni.clone().unwrap_or_else(|| t.host.clone()),
                        ca_cert: t.tls_ca_cert.clone(),
                        verify: t.tls_verify,
                        client_cert: t.tls_client_cert.clone(),
                        client_key: t.tls_client_key.clone(),
                    };
                    match self.transport.register_tls_destination(dest, params) {
                        Ok(()) => info!("TLS trunk '{}': outbound TLS registered for {}", t.name, dest),
                        Err(e) => error!(
                            "TLS trunk '{}': outbound TLS NOT registered for {} ({}) — sends to it will fail closed",
                            t.name, dest, e
                        ),
                    }
                }
            }
        }
    }

    /// Rebuild the inbound-INVITE trunk IP whitelist from the trunk manager.
    pub async fn refresh_trunk_ips(&self) {
        let ips: Vec<String> = self
            .trunk_manager
            .list_trunks()
            .iter()
            .flat_map(|t| {
                t.resolved_addr
                    .map(|a| a.ip().to_string())
                    .into_iter()
                    .chain(std::iter::once(t.host.clone()))
            })
            .collect();
        info!("Trunk IPs whitelist refreshed — {:?}", ips);
        *self.trunk_ips.write().await = ips;
    }

    /// Create a minimal SBC instance (for tests / simple usage)
    pub fn new() -> Self {
        let media = Arc::new(MediaManager::default());
        let b2bua = Arc::new(B2buaManager::new(media.clone()));
        let trunk_manager = Arc::new(TrunkManager::new());
        let router = Arc::new(Router::new(trunk_manager.clone()));
        let registrar = Arc::new(InMemoryRegistrar::new());
        let register_handler = Arc::new(RegisterHandler::new(registrar));

        let metrics = Arc::new(SbcMetrics::new());
        let events = crate::events::EventBus::new();
        let pending_register_responses: crate::trunk_tasks::PendingResponses =
            Arc::new(DashMap::new());
        let trunk_tasks = Arc::new(crate::trunk_tasks::TrunkTasks::new(
            trunk_manager.clone(),
            pending_register_responses.clone(),
            metrics.clone(),
            events.clone(),
            crate::trunk_tasks::TrunkTasksConfig::default(),
        ));
        Self {
            readiness: Arc::new(Readiness::new()),
            backup_policy: Arc::new(backup::BackupPolicy {
                dir: std::path::PathBuf::from("data/backups"),
                interval: None,
                keep: 7,
            }),
            backup_lock: Arc::new(tokio::sync::Mutex::new(())),
            _backup_timer: None,
            transport: TransportManager::new(),
            media,
            b2bua,
            router,
            register_handler,
            auth: None,
            acl: Arc::new(AclManager::new_permissive()),
            dos: Arc::new(DosProtector::new(RateLimitConfig::default())),
            identity: None,
            enable_digest_auth: false,
            metrics,
            cdr: Arc::new(CdrManager::new_memory()),
            _maintenance: None,
            config_path: None,
            trunk_manager,
            pending_register_responses,
            trunk_tasks,
            did_mappings: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            trunk_ips: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            config_store: None,
            events,
            invite_timeout: Duration::from_secs(5),
            call_setup_timeout: Duration::from_secs(60),
            admin_kicks: Arc::new(AdminKicks::new()),
            identity_policy: IdentityPolicy::default(),
            invite_tx: invite_tx::InviteTxCache::new(),
            max_call_duration: Duration::from_secs(14400),
            session_timer: None,
            security: Arc::new(crate::security::SecurityManager::new(Default::default())),
        }
    }

    /// Add a trunk to the router (for programmatic trunk configuration)
    pub fn add_trunk(&self, trunk: TrunkConfig) -> crate::routing::TrunkId {
        self.router.trunk_manager().add_trunk(trunk)
    }

    /// Start (or re-sync) the per-trunk OPTIONS health checks and outbound
    /// REGISTER loops (`trunk_tasks.rs`). Must be called after `start()`
    /// so the UDP socket exists; later trunk changes (API, reload) re-sync
    /// the tasks by themselves.
    pub fn start_trunk_tasks(&self) {
        match self.transport.udp_socket() {
            Some(sock) => {
                self.trunk_tasks.attach_socket(sock, self.identity.clone());
                self.trunk_tasks.sync();
            }
            None => warn!(
                "No UDP socket available — trunk health checks and registrations will not start"
            ),
        }
    }

    pub fn trunk_tasks(&self) -> Arc<crate::trunk_tasks::TrunkTasks> {
        self.trunk_tasks.clone()
    }

    pub fn readiness(&self) -> Arc<Readiness> {
        self.readiness.clone()
    }

    pub fn backup_policy(&self) -> Arc<backup::BackupPolicy> {
        self.backup_policy.clone()
    }

    pub fn backup_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.backup_lock.clone()
    }

    /// Start the SBC with network configuration
    pub async fn start(
        &mut self,
        network_config: &NetworkConfig,
        maintenance_config: Option<MaintenanceConfig>,
    ) -> Result<()> {
        info!("Starting SBC...");

        // Start transport listeners
        self.transport.start_listeners(network_config).await?;
        info!("Transport listeners started");
        self.readiness.set_listening();

        // Periodic store backups (only with a store; the policy decides).
        if let Some(store) = self.config_store.clone() {
            self._backup_timer = backup::spawn_backup_timer(
                store,
                self.backup_policy.clone(),
                self.metrics.clone(),
                self.events.clone(),
                self.backup_lock.clone(),
            );
        }

        // Outbound TLS for TLS trunks (no plaintext fallback)
        self.register_trunk_tls_configs();

        // Start the maintenance sweeper (keeps the in-memory tables bounded)
        let config = maintenance_config.unwrap_or_default();
        let maintenance = MaintenanceTask::new(
            self.dos.clone(),
            self.auth.clone(),
            self.register_handler.registrar(),
            self.security.clone(),
            self.metrics.clone(),
            config,
        );
        self._maintenance = Some(maintenance.start());
        info!("Maintenance sweeper started");

        info!("SBC started successfully");
        Ok(())
    }

    /// Process incoming SIP messages in a loop (main event loop)
    pub async fn run(&mut self) {
        info!("SBC event loop starting...");

        // Listen for SIGHUP (Unix only) for config hot-reload
        #[cfg(unix)]
        let mut sighup = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler")
        };

        // Listen for SIGTERM for graceful shutdown
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler")
        };

        // ── Periodic call timeout check (every 30s) ──
        // Detects calls that have been active too long (e.g. callee dropped without BYE)
        // and sends BYE to both sides to prevent phantom sessions on remote trunks.
        let mut call_timeout_interval = tokio::time::interval(Duration::from_secs(30));
        call_timeout_interval.tick().await; // consume the immediate first tick

        // ── Fast tick for INVITE failover (1s) ──
        // Scans calls waiting on their outbound INVITE; after invite_timeout
        // with no >=180 provisional, CANCEL and try the next candidate trunk.
        let mut failover_interval = tokio::time::interval(Duration::from_secs(1));
        failover_interval.tick().await;
        // ── Timer G tick (500 ms): non-2xx finals we generated over UDP are
        // resent until their ACK (RFC 3261 §17.2.1).
        let mut retransmit_interval = tokio::time::interval(Duration::from_millis(500));
        retransmit_interval.tick().await;
        let kicks = self.admin_kicks.clone();

        loop {
            #[cfg(unix)]
            tokio::select! {
                received = self.transport.recv_message() => {
                    match received {
                        Some(msg) => {
                            if let Err(e) = self.handle_message(msg).await {
                                error!("Error handling message: {}", e);
                            }
                        }
                        None => {
                            warn!("Transport channel closed, stopping SBC");
                            break;
                        }
                    }
                }
                _ = call_timeout_interval.tick() => {
                    self.check_call_timeouts().await;
                    self.send_session_refreshes().await;
                    self.invite_tx.prune();
                }
                _ = failover_interval.tick() => {
                    self.check_invite_failover().await;
                    self.check_setup_timeouts().await;
                    self.check_media_timeouts().await;
                    for event in self.transport.drain_events() {
                        self.handle_transport_event(event).await;
                    }
                }
                _ = kicks.notified() => {
                    self.process_admin_kicks().await;
                }
                _ = retransmit_interval.tick() => {
                    self.retransmit_finals().await;
                }
                _ = sighup.recv() => {
                    info!("SIGHUP received — reloading configuration");
                    if let Err(e) = self.reload_config().await {
                        error!("SIGHUP reload failed: {}", e);
                    }
                }
                _ = self.reload_notify.notified() => {
                    info!("API reload requested — reloading configuration");
                    if let Err(e) = self.reload_config().await {
                        error!("API reload failed: {}", e);
                    }
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received — graceful shutdown");
                    self.graceful_shutdown().await;
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — graceful shutdown");
                    self.graceful_shutdown().await;
                    break;
                }
            }

            #[cfg(not(unix))]
            {
                tokio::select! {
                    received = self.transport.recv_message() => {
                        match received {
                            Some(msg) => {
                                if let Err(e) = self.handle_message(msg).await {
                                    error!("Error handling message: {}", e);
                                }
                            }
                            None => {
                                warn!("Transport channel closed, stopping SBC");
                                break;
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("SIGINT received — graceful shutdown");
                        self.graceful_shutdown().await;
                    break;
                    }
                }
            }
        }

        info!("SBC event loop stopped");
    }

    /// Handle a single received message — full pipeline: ACL → DoS → dispatch
    async fn handle_message(&mut self, received: ReceivedMessage) -> Result<()> {
        let source = received.source;
        let transport = received.transport;
        let reply_tx = received.reply_tx;

        // 0. Ban check (fail2ban) — one DashMap read on the hot path
        if self.security.bans.is_banned(source.ip()) {
            self.metrics.inc_security_ban_drop();
            if !self.security.bans.silent_drop() {
                self.metrics.inc_sip_response(403);
                let response_403 = response_for_message(&received.message, 403, "Forbidden");
                self.send_sip(
                    "403 (banned) → source",
                    response_403.as_bytes(),
                    source,
                    transport,
                    reply_tx.as_ref(),
                )
                .await;
            }
            return Ok(());
        }

        // 1. ACL check
        let acl_result = self.acl.check_addr(source, Direction::Inbound).await;
        if !acl_result.is_allowed() {
            debug!("ACL denied message from {}", source);
            self.metrics.inc_acl_denied();
            return Ok(());
        }

        // 2. DoS / rate limit check
        let dos_result = self.dos.check_addr(source).await;
        if !dos_result.is_allowed() {
            debug!("DoS rate limited message from {}", source);
            self.metrics.inc_dos_blocked();
            self.metrics.inc_sip_response(503);
            let response_503 = response_for_message(&received.message, 503, "Service Unavailable");
            self.send_sip(
                "503 (rate-limited) → source",
                response_503.as_bytes(),
                source,
                transport,
                reply_tx.as_ref(),
            )
            .await;
            return Ok(());
        }

        debug!("Processing message from {} via {:?}", source, transport);

        // 3. Dispatch
        match received.message {
            SipMessage::Request(request) => {
                self.handle_request(request, source, transport, reply_tx.as_ref())
                    .await
            }
            SipMessage::Response(response) => {
                self.handle_response(response, source, transport, reply_tx.as_ref())
                    .await
            }
        }
    }

    /// Dispatch incoming SIP request to the appropriate handler
    async fn handle_request(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Handling {} request from {}", request.method, source);

        // ── Metrics: count every incoming SIP request ──
        self.metrics.inc_sip_request(&request.method.to_string());

        match &request.method {
            Method::Options => {
                self.handle_options(&request, source, transport, reply_tx)
                    .await
            }
            Method::Register => {
                self.handle_register(&request, source, transport, reply_tx)
                    .await
            }
            Method::Invite => {
                self.handle_invite(request, source, transport, reply_tx)
                    .await
            }
            Method::Ack => self.handle_ack(request, source, transport, reply_tx).await,
            Method::Bye => self.handle_bye(request, source, transport, reply_tx).await,
            Method::Cancel => {
                self.handle_cancel(request, source, transport, reply_tx)
                    .await
            }
            Method::Refer => {
                self.handle_refer(request, source, transport, reply_tx)
                    .await
            }
            Method::Info => self.handle_info(request, source, transport, reply_tx).await,
            method => {
                // RFC 3261 §8.2.1: a method the UAS does not support → 405
                // with what it does (PRACK, UPDATE, SUBSCRIBE, NOTIFY,
                // MESSAGE, PUBLISH…).
                warn!("Unsupported SIP method {} from {} — 405", method, source);
                self.metrics.inc_sip_response(405);
                let mut response_405 = response_for_request(&request, 405, "Method Not Allowed");
                if let Ok(mut m) = crate::topology::RawSipMessage::parse(&response_405) {
                    m.set_header("Allow", crate::sip_builder::ALLOWED_METHODS);
                    response_405 = m.to_string();
                }
                self.send_sip(
                    "405 → source",
                    response_405.as_bytes(),
                    source,
                    transport,
                    reply_tx,
                )
                .await;
                Ok(())
            }
        }
    }

    // =========================================================================
    // Local request handlers
    // =========================================================================

    /// Handle OPTIONS — always reply 200 OK locally (keepalive / health check)
    async fn handle_options(
        &self,
        request: &Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Handling local request: OPTIONS");
        self.metrics.inc_sip_response(200);
        let response = self.router.handle_local_request(request)?;
        let data = response.to_string().into_bytes();
        self.transport
            .reply(&data, source, transport, reply_tx)
            .await
    }

    /// Handle REGISTER with optional Digest 401 challenge
    async fn handle_register(
        &self,
        request: &Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Handling local request: REGISTER");

        // If Digest auth is enabled, challenge first
        let mut authenticated: Option<String> = None;
        if self.enable_digest_auth {
            if let Some(auth) = &self.auth {
                // Check for Authorization header
                let auth_header: Option<String> = request
                    .authorization_header()
                    .map(|h| h.value().to_string());

                match auth_header {
                    None => {
                        // No auth header → send 401 challenge
                        self.metrics.inc_auth_challenge();
                        self.metrics.inc_sip_response(401);
                        let challenge = auth.generate_challenge().await;
                        let response_401 = build_register_401(request, &challenge)?;
                        let data = response_401.to_string().into_bytes();
                        return self
                            .transport
                            .reply(&data, source, transport, reply_tx)
                            .await;
                    }
                    Some(ref auth_value) => {
                        // Verify the credentials. The fingerprint lets a
                        // byte-identical UDP retransmission of an accepted
                        // REGISTER pass again instead of counting as a replay.
                        let method = request.method.to_string();
                        let fingerprint = {
                            use std::hash::{Hash, Hasher};
                            let mut h = std::collections::hash_map::DefaultHasher::new();
                            auth_value.hash(&mut h);
                            source.hash(&mut h);
                            request
                                .contact_header()
                                .map(|c| c.value().to_string())
                                .unwrap_or_default()
                                .hash(&mut h);
                            h.finish()
                        };
                        match auth
                            .verify_with(auth_value, &method, Some(fingerprint))
                            .await
                        {
                            Ok(username) => {
                                info!("REGISTER authenticated for user: {}", username);
                                authenticated = Some(username);
                            }
                            Err(failure) => {
                                return self
                                    .reject_register_auth(
                                        request, source, transport, reply_tx, auth, failure,
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }

        // Extract registration fields
        // Normalize AOR: extract URI from angle brackets if present
        // e.g. "<sip:user@domain>" → "sip:user@domain"
        let aor_raw = request
            .to_header()
            .map_err(|e| Error::Other(format!("Missing To header: {}", e)))?
            .value()
            .to_string();
        let aor = normalize_aor(&aor_raw);

        // RFC 3261 §10.3 step 5: an authenticated user binds (or unbinds,
        // Expires: 0 / Contact: *) only its own AOR, on a domain we serve —
        // alice's password must not register or wipe bob's phone.
        if let Some(user) = authenticated.as_deref() {
            if let Err(why) = authorize_aor(user, &aor, &self.served_domains()) {
                self.metrics.inc_security_identity_mismatch();
                self.security
                    .emit(crate::security::SecurityEvent::IdentityMismatch {
                        ip: source.ip().to_string(),
                        user: user.to_string(),
                        claimed: aor.clone(),
                        method: "REGISTER".to_string(),
                        ts: crate::events::event_ts(),
                    });
                // The user half is always enforced under "enforce". The
                // domain half only once the operator listed served_domains:
                // phones registered against a LAN IP or a DNS alias must
                // keep working after an upgrade (reported, not refused).
                let enforce = match &why {
                    AorRejection::User(_) => self.identity_policy.enforce_register_aor,
                    AorRejection::Domain(_) => {
                        self.identity_policy.enforce_register_aor
                            && !self.identity_policy.served_domains.is_empty()
                    }
                };
                if enforce {
                    warn!(
                        "REGISTER from {} authenticated as '{}' for {} refused: {}",
                        source.ip(),
                        user,
                        aor,
                        why
                    );
                    self.metrics.inc_sip_response(403);
                    let r = response_for_request(request, 403, "Forbidden");
                    self.send_sip(
                        "403 (AOR) → REGISTER",
                        r.as_bytes(),
                        source,
                        transport,
                        reply_tx,
                    )
                    .await;
                    return Ok(());
                }
                warn!(
                    "REGISTER from {} authenticated as '{}' for {}: {} (reported, allowed: register_aor_check = log or no served_domains configured)",
                    source.ip(),
                    user,
                    aor,
                    why
                );
            }
        }

        let contact = request
            .contact_header()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // RFC 3261 §10.2.1: expires can be in the Contact header params (;expires=N)
        // OR in the top-level Expires header. Contact-level expires takes priority.
        // Linphone often sends ;expires=0 in the Contact param to unregister a specific binding.
        let contact_expires: Option<u32> = {
            let raw = contact.to_lowercase();
            // Look for ";expires=NNN" in the contact string
            raw.split(';')
                .skip(1) // skip the URI part
                .find_map(|p| {
                    let p = p.trim();
                    if let Some(val) = p.strip_prefix("expires=") {
                        val.trim_matches('>').parse::<u32>().ok()
                    } else {
                        None
                    }
                })
        };
        let expires: u32 = contact_expires
            .or_else(|| {
                request
                    .expires_header()
                    .and_then(|h| h.value().parse().ok())
            })
            .unwrap_or(3600);

        let call_id = request
            .call_id_header()
            .map_err(|e| Error::Other(format!("Missing Call-ID: {}", e)))?
            .value()
            .to_string();

        let cseq: u32 = request
            .cseq_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .map(|c: rsip::typed::CSeq| c.seq)
            .unwrap_or(1);

        let transport_str = format!("{:?}", transport).to_uppercase();

        // For connection-oriented transports (WS/WSS/TLS/TCP), store the reply_tx
        // so incoming INVITEs can be forwarded over the SAME existing connection.
        // This is essential for clients behind NAT: we can't open a new outbound
        // connection to their private IP — we must reuse the inbound channel.
        let ws_reply_tx = match transport {
            rsip::Transport::Ws
            | rsip::Transport::Wss
            | rsip::Transport::Tls
            | rsip::Transport::Tcp => reply_tx.cloned(),
            _ => None,
        };

        // Process registration
        match self
            .register_handler
            .handle_with_tx(
                &aor,
                &contact,
                expires,
                &call_id,
                cseq,
                source,
                &transport_str,
                ws_reply_tx,
            )
            .await
        {
            Ok(RegisterResult::Ok {
                expires: exp,
                bindings,
            }) => {
                info!(
                    "Registered {} with {} binding(s), expires={}s",
                    aor,
                    bindings.len(),
                    exp
                );
                self.metrics.inc_registration();
                self.metrics
                    .set_active_registrations(self.register_handler.count().await);
                self.events.publish(crate::events::SbcEvent::Registered {
                    aor: aor.clone(),
                    contact: contact.clone(),
                    expires: exp,
                    ts: crate::events::event_ts(),
                });
                self.metrics.inc_sip_response(200);
                let response_200 = build_register_200(request, &bindings, &call_id, cseq)?;
                let data = response_200.to_string().into_bytes();
                self.transport
                    .reply(&data, source, transport, reply_tx)
                    .await
            }
            Ok(RegisterResult::Removed { count }) => {
                info!("Unregistered {} contact(s) for {}", count, aor);
                self.metrics
                    .set_active_registrations(self.register_handler.count().await);
                self.events.publish(crate::events::SbcEvent::Unregistered {
                    aor: aor.clone(),
                    ts: crate::events::event_ts(),
                });
                self.metrics.inc_sip_response(200);
                let response_200 = build_plain_response_for_request(request, 200, "OK")?;
                let data = response_200.to_string().into_bytes();
                self.transport
                    .reply(&data, source, transport, reply_tx)
                    .await
            }
            Err(e) => {
                warn!("Registration failed for {}: {}", aor, e);
                self.metrics.inc_sip_response(500);
                let response_500 = response_for_request(request, 500, "Server Internal Error");
                self.send_sip(
                    "500 → REGISTER",
                    response_500.as_bytes(),
                    source,
                    transport,
                    reply_tx,
                )
                .await;
                Ok(())
            }
        }
    }

    /// Hosts a local identity may live on: the digest realm, the SBC's
    /// domain and public IP, loopback, plus `[security] served_domains`.
    pub(crate) fn served_domains(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |d: &str| {
            let d = d.trim().to_ascii_lowercase();
            if !d.is_empty() && !out.contains(&d) {
                out.push(d);
            }
        };
        if let Some(auth) = &self.auth {
            push(&auth.realm);
        }
        if let Some(id) = &self.identity {
            push(&id.sip_domain);
            push(&id.public_ip);
        }
        push("127.0.0.1");
        push("localhost");
        for d in &self.identity_policy.served_domains {
            push(d);
        }
        out
    }

    /// A REGISTER whose credentials did not verify. A stale nonce gets a
    /// fresh challenge with `stale=true` (RFC 7616 §3.3) and is never a
    /// fail2ban strike — clients cache challenges across re-REGISTERs and
    /// every restart empties the nonce table. A wrong password, an unknown
    /// user or a replayed Authorization is a strike and a 403; a header
    /// that is not Digest at all is a 400.
    async fn reject_register_auth(
        &self,
        request: &Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
        auth: &DigestAuthenticator,
        failure: crate::auth::AuthFailure,
    ) -> Result<()> {
        use crate::auth::AuthFailure;
        let replayed = matches!(failure, AuthFailure::Replay { .. });
        match failure {
            AuthFailure::StaleNonce { user } | AuthFailure::Replay { user } => {
                if replayed {
                    warn!(
                        "REGISTER from {} (user {}): replayed Authorization (same nonce and nc from another request) — re-challenging",
                        source.ip(),
                        user
                    );
                } else {
                    debug!(
                        "REGISTER from {} (user {}): stale nonce — re-challenging with stale=true",
                        source.ip(),
                        user
                    );
                }
                self.metrics.inc_auth_challenge();
                self.metrics.inc_auth_stale_challenge();
                self.metrics.inc_sip_response(401);
                let challenge = auth.generate_challenge_with(true).await;
                let response_401 = build_register_401(request, &challenge)?;
                let data = response_401.to_string().into_bytes();
                self.send_sip("401 (stale) → REGISTER", &data, source, transport, reply_tx)
                    .await;
            }
            AuthFailure::Malformed => {
                warn!(
                    "REGISTER from {}: Authorization header is not a Digest — 400",
                    source.ip()
                );
                self.metrics.inc_auth_failure();
                self.metrics.inc_sip_response(400);
                let r = response_for_request(request, 400, "Bad Request");
                self.send_sip("400 → REGISTER", r.as_bytes(), source, transport, reply_tx)
                    .await;
            }
            other => {
                warn!("REGISTER auth failed from {}: {}", source.ip(), other);
                self.metrics.inc_auth_failure();
                self.metrics.inc_sip_response(403);
                if let Some(entry) =
                    self.security
                        .record_auth_failure(source.ip(), other.user(), "REGISTER")
                {
                    self.metrics.inc_security_ban();
                    self.persist_ban(&entry);
                }
                let r = response_for_request(request, 403, "Forbidden");
                self.send_sip("403 → REGISTER", r.as_bytes(), source, transport, reply_tx)
                    .await;
            }
        }
        Ok(())
    }

    /// Send a SIP message on a leg and account for the outcome. A send that
    /// fails (no UDP listener, unregistered TLS destination, dead TCP peer,
    /// closed WS channel) is logged with what was being sent and counted in
    /// `sbc_sip_send_failures_total{transport}` — a ghost call must never
    /// hide behind a clean log. Returns whether the send succeeded.
    pub(crate) async fn send_sip(
        &self,
        what: &str,
        data: &[u8],
        dest: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> bool {
        // Every response to an INVITE is remembered so a retransmitted
        // INVITE gets it again (RFC 3261 §17.2.1).
        if data.starts_with(b"SIP/2.0 ") {
            if let Ok(text) = std::str::from_utf8(data) {
                if let Some((key, status)) = invite_tx::InviteTxCache::key_of_response(text) {
                    self.invite_tx.record_sent(
                        &key,
                        data,
                        status,
                        dest,
                        transport,
                        reply_tx.cloned(),
                    );
                }
            }
        }
        match self.transport.reply(data, dest, transport, reply_tx).await {
            Ok(()) => true,
            Err(e) => {
                warn!(
                    "SIP send failed: {} → {} via {:?}: {}",
                    what, dest, transport, e
                );
                self.metrics.inc_sip_send_failure(transport);
                false
            }
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    pub fn transport_mut(&mut self) -> &mut TransportManager {
        &mut self.transport
    }
    pub fn media(&self) -> &Arc<MediaManager> {
        &self.media
    }
    pub fn b2bua(&self) -> &Arc<B2buaManager> {
        &self.b2bua
    }
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }
    pub fn acl(&self) -> &Arc<AclManager> {
        &self.acl
    }
    pub fn dos(&self) -> &Arc<DosProtector> {
        &self.dos
    }
    pub fn register_handler(&self) -> &Arc<RegisterHandler> {
        &self.register_handler
    }
    pub fn cdr(&self) -> &Arc<CdrManager> {
        &self.cdr
    }
    pub fn metrics(&self) -> &Arc<SbcMetrics> {
        &self.metrics
    }
    pub fn events(&self) -> crate::events::EventBus {
        self.events.clone()
    }
    pub fn security(&self) -> Arc<crate::security::SecurityManager> {
        self.security.clone()
    }
    /// Queue shared with the management API for `DELETE /api/v1/calls/{uuid}`.
    pub fn admin_kicks(&self) -> Arc<AdminKicks> {
        self.admin_kicks.clone()
    }
    pub fn trunk_ips(&self) -> Arc<tokio::sync::RwLock<Vec<String>>> {
        self.trunk_ips.clone()
    }
}

impl Default for Sbc {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper functions for building SIP responses
// =============================================================================

/// Normalize an AOR/URI by removing angle brackets and display names.
/// "<sip:user@domain>" → "sip:user@domain"
/// "Display Name <sip:user@domain>" → "sip:user@domain"
/// "sip:user@domain" → "sip:user@domain" (unchanged)
fn normalize_aor(raw: &str) -> String {
    let s = raw.trim();
    if let (Some(start), Some(end)) = (s.find('<'), s.rfind('>')) {
        s[start + 1..end].trim().to_string()
    } else {
        s.to_string()
    }
}

/// Extract the callee AOR from the INVITE Request-URI.
/// Returns the full AOR like "sip:alice@sip.example.com"
/// or user-only "alice@sip.example.com" for registrar lookup.
///
/// The registrar stores AORs from the To header of REGISTER requests,
/// which is typically "sip:user@domain".
fn extract_callee_aor(request: &Request) -> Option<String> {
    // Use the Request-URI (first line of INVITE: "sip:user@domain")
    let uri_str = request.uri.to_string();
    // Also check To header as fallback
    let to_str = request
        .to_header()
        .ok()
        .map(|h| h.value().to_string())
        .unwrap_or_default();

    // Return the full Request-URI for lookup
    // The registrar lookup() handles "sip:" prefix normalization
    if !uri_str.is_empty() {
        Some(uri_str)
    } else if !to_str.is_empty() {
        Some(to_str)
    } else {
        None
    }
}

/// Build a 100 Trying response for INVITE (RFC 3261 §8.2.6.1)
/// Note: 100 Trying does NOT add a To-tag
fn build_trying(request: &Request) -> Result<SipMessage> {
    let mut headers: rsip::Headers = Default::default();
    headers.push(request.via_header()?.clone().into());
    headers.push(request.from_header()?.clone().into());
    headers.push(request.to_header()?.clone().into()); // No tag for 100 Trying
    headers.push(request.call_id_header()?.clone().into());
    headers.push(request.cseq_header()?.clone().into());
    headers.push(rsip::Header::ContentLength(Default::default()));
    Ok(SipMessage::Response(rsip::Response {
        status_code: 100.into(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }))
}

/// Build a BYE request to send to the other leg of a B2BUA call.
/// Creates a minimal but valid BYE using a new Call-ID/CSeq for the outbound leg.
#[allow(dead_code)]
fn build_bye_for_other_leg(original_bye: &Request, _dest: std::net::SocketAddr) -> String {
    // Extract Call-ID from the inbound BYE for logging, but we create a fresh BYE
    // that reuses From/To from the inbound request so the callee recognizes the dialog.
    // In a full B2BUA, we'd track the outbound dialog state and use its Call-ID/From/To.
    // For now, we generate a minimal BYE that will be recognized by the callee's dialog.
    let call_id = original_bye
        .call_id_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

    let from_value = original_bye
        .from_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:sbc@localhost>".to_string());

    let to_value = original_bye
        .to_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:callee@localhost>".to_string());

    // Build a minimal BYE using the inbound dialog identifiers
    // The Request-URI uses the To URI (callee)
    let to_uri = if let Ok(to_hdr) = original_bye.to_header() {
        let val = to_hdr.value().to_string();
        // Extract URI from angle brackets if present
        if let (Some(start), Some(end)) = (val.find('<'), val.rfind('>')) {
            val[start + 1..end].trim().to_string()
        } else {
            val.split(';')
                .next()
                .unwrap_or("sip:callee@localhost")
                .trim()
                .to_string()
        }
    } else {
        "sip:callee@localhost".to_string()
    };

    let branch = format!("z9hG4bK-bye-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let via_host = "sbc.local:5060"; // Will be rewritten by topology hiding if configured

    format!(
        "BYE {} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {};branch={}\r\n\
         From: {}\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: 2 BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        to_uri, via_host, branch, from_value, to_value, call_id
    )
}

/// Build a CANCEL request to send to the callee.
///
/// RFC 3261 §9.1: A CANCEL matches the INVITE it cancels by having the same
/// Call-ID, From-tag, To, CSeq number (but method=CANCEL), and top-most Via.
/// We reuse From/To/CSeq from the original CANCEL (which mirrors the INVITE)
/// but substitute the outbound Call-ID (the leg SBC→callee used the same Call-ID).
#[allow(dead_code)]
fn build_cancel_for_callee(
    original_cancel: &Request,
    outbound_call_id: &str,
    _dest: std::net::SocketAddr,
) -> String {
    let from_value = original_cancel
        .from_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:sbc@localhost>".to_string());

    let to_value = original_cancel
        .to_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:callee@localhost>".to_string());

    // Request-URI = To URI (without tag or display name)
    let to_uri = {
        let val = original_cancel
            .to_header()
            .map(|h| h.value().to_string())
            .unwrap_or_default();
        if let (Some(start), Some(end)) = (val.find('<'), val.rfind('>')) {
            val[start + 1..end].trim().to_string()
        } else {
            val.split(';')
                .next()
                .unwrap_or("sip:callee@localhost")
                .trim()
                .to_string()
        }
    };

    let cseq_num = original_cancel
        .cseq_header()
        .ok()
        .and_then(|h| h.typed().ok())
        .map(|cseq| cseq.seq.to_string())
        .unwrap_or_else(|| "1".to_string());

    let branch = format!("z9hG4bK-cancel-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let via_host = "sbc.local:5060"; // Will be overwritten by topology hiding

    format!(
        "CANCEL {} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {};branch={}\r\n\
         From: {}\r\n\
         To: {}\r\n\
         Call-ID: {}\r\n\
         CSeq: {} CANCEL\r\n\
         Content-Length: 0\r\n\
         \r\n",
        to_uri, via_host, branch, from_value, to_value, outbound_call_id, cseq_num
    )
}

/// Strip SDP body from a SIP response (for WebRTC 183 Session Progress).
///
/// The trunk's 183 contains a PCMA/AVP SDP that is incompatible with WebRTC.
/// We strip the body and update Content-Type/Content-Length.
fn strip_sdp_body(raw: &str) -> String {
    let mut result = String::new();
    let in_body = false;
    for line in raw.split("\r\n") {
        if in_body {
            continue; // Skip body
        }
        if line.is_empty() {
            // End of headers — write Content-Length: 0 and stop
            result.push_str("Content-Length: 0\r\n\r\n");
            break;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("content-type:") || lower.starts_with("content-length:") {
            continue; // Skip old Content-Type and Content-Length
        }
        result.push_str(line);
        result.push_str("\r\n");
    }
    result
}

/// Returns true if the IP address is a private/RFC-1918/loopback address.
/// Private addresses cannot be reached from the internet and need NAT correction.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()           // 127.x.x.x
            || v4.is_private()         // 10.x, 172.16-31.x, 192.168.x
            || v4.is_link_local()      // 169.254.x.x
            || v4.is_unspecified()     // 0.0.0.0
            || octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)  // 100.64.0.0/10 (CGNAT)
            || octets[0] == 192 && octets[1] == 0 && octets[2] == 0       // 192.0.0.0/24 (IETF Protocol)
            || octets[0] == 192 && octets[1] == 0 && octets[2] == 2       // 192.0.2.0/24 (TEST-NET-1)
            || octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)   // 198.18.0.0/15 (benchmark)
            || octets[0] == 198 && octets[1] == 51 && octets[2] == 100    // 198.51.100.0/24 (TEST-NET-2)
            || octets[0] == 203 && octets[1] == 0 && octets[2] == 113 // 203.0.113.0/24 (TEST-NET-3)
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Extract the RTP endpoint (IP:port) from an SDP body.
/// Looks for the first audio media line (`m=audio <port>`) and the
/// connection line (`c=IN IP4 <ip>`) and returns `ip:port` as a SocketAddr.
/// Falls back to `source` if parsing fails.
fn extract_sdp_rtp_addr(sdp: &str) -> Option<std::net::SocketAddr> {
    let mut ip: Option<std::net::IpAddr> = None;
    let mut port: Option<u16> = None;

    for line in sdp.lines() {
        let line = line.trim();
        if let Some(addr_str) = line.strip_prefix("c=IN IP4 ") {
            if let Ok(parsed) = addr_str.trim().parse::<std::net::IpAddr>() {
                ip = Some(parsed);
            }
        } else if line.starts_with("m=audio ") {
            // m=audio <port> <proto> <fmt>
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(p) = parts[1].parse::<u16>() {
                    port = Some(p);
                }
            }
        }
        if ip.is_some() && port.is_some() {
            break;
        }
    }

    match (ip, port) {
        (Some(ip), Some(port)) if port > 0 => Some(std::net::SocketAddr::new(ip, port)),
        _ => None,
    }
}

/// Update Content-Length header to match actual body size.
/// MUST be called after rewriting the SDP body so that TCP framing
/// (which relies on Content-Length) stays consistent.
fn update_content_length_response(response: &mut rsip::Response) {
    let cl = rsip::headers::ContentLength::from(response.body.len() as u32);
    response
        .headers
        .unique_push(rsip::Header::ContentLength(cl));
}

fn update_content_length_request(request: &mut rsip::Request) {
    let cl = rsip::headers::ContentLength::from(request.body.len() as u32);
    request.headers.unique_push(rsip::Header::ContentLength(cl));
}

/// Rewrite a SIP response for the caller (B2BUA response fixup).
///
/// When the SBC forwards an INVITE with topology hiding, it strips the caller's
/// original Via headers and replaces them with the SBC's own Via. Responses from
/// the callee therefore contain the SBC's outbound Via — NOT the caller's Via.
///
/// If the response is sent as-is to the caller, the caller's SIP stack cannot
/// match the response to its original INVITE transaction (because the Via branch
/// doesn't match) and will **silently discard it**.
///
/// This function:
///   1. Strips all Via headers from the response (SBC's outbound Via)
///   2. Re-inserts the caller's original Via headers
///   3. Rewrites the Contact header to the SBC's URI (topology hiding)
///   4. Inserts a Record-Route for the SBC (so mid-dialog requests route through SBC)
fn rewrite_response_for_caller(
    raw_response: &str,
    caller_vias: &[String],
    identity: Option<&crate::topology::SbcIdentity>,
    caller_invite_cseq: Option<u32>,
) -> String {
    use crate::topology::RawSipMessage;

    let mut msg = match RawSipMessage::parse(raw_response) {
        Ok(m) => m,
        Err(_) => return raw_response.to_string(), // fallback: send as-is
    };

    // 1. Remove all Via headers (these are the SBC's outbound Via)
    msg.remove_header("via");
    msg.remove_header("v"); // compact form

    // 2. Re-insert the caller's original Via headers (in order)
    // Insert in reverse so the first Via ends up at the top
    for via in caller_vias.iter().rev() {
        msg.prepend_header(via.clone());
    }

    // 2b. Restore the caller's INVITE CSeq number: a 407/422 retry bumps
    // the CSeq on the callee leg only, and the caller's dialog state
    // (RFC 3261 §12.2.1.1) expects its own number echoed. No-op when the
    // numbers already agree; other methods (BYE…) are left alone.
    if let Some(n) = caller_invite_cseq {
        let is_invite = msg
            .header_values("cseq")
            .first()
            .map(|v| {
                v.split_whitespace()
                    .nth(1)
                    .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))
            })
            .unwrap_or(false);
        if is_invite {
            msg.set_header("CSeq", &format!("{} INVITE", n));
        }
    }

    // 3. Rewrite Contact to SBC URI (topology hiding for responses)
    if let Some(id) = identity {
        let contacts = msg.header_values("contact");
        if !contacts.is_empty() {
            msg.remove_header("contact");
            msg.remove_header("m"); // compact
            msg.append_header(format!("Contact: <{}>", id.contact_uri()));
        }

        // 4. Ensure Record-Route is present so mid-dialog requests route through SBC
        // Remove existing Record-Route (from callee's side) and insert SBC's
        msg.remove_header("record-route");
        msg.prepend_header(format!("Record-Route: {}", id.record_route()));
    }

    let result = msg.to_string();
    debug!("Rewritten response for caller (Via restored, Contact/RR rewritten)");
    result
}

/// Build a minimal SIP response string (no request headers — last resort)
fn build_plain_response(status: u16, reason: &str) -> String {
    format!("SIP/2.0 {} {}\r\nContent-Length: 0\r\n\r\n", status, reason)
}

/// A response to `request` that the peer can match to its transaction
/// (Via/From/To/Call-ID/CSeq echoed, RFC 3261 §8.2.6.2), falling back to a
/// header-less status line only when the request lacks those headers.
pub(super) fn response_for_request(request: &Request, status: u16, reason: &str) -> String {
    match build_plain_response_for_request(request, status, reason) {
        Ok(r) => r.to_string(),
        Err(_) => build_plain_response(status, reason),
    }
}

/// Same for a message that may be a request or a response (pipeline
/// rejections before dispatch): a response gets no answer body but the
/// status line.
fn response_for_message(msg: &SipMessage, status: u16, reason: &str) -> String {
    match msg {
        SipMessage::Request(r) => response_for_request(r, status, reason),
        SipMessage::Response(_) => build_plain_response(status, reason),
    }
}

/// Build a proper SIP response echoing Via/From/To/Call-ID/CSeq from the request.
/// The reason phrase on the wire is the canonical one for `status`
/// (`rsip::StatusCode::reason_phrase`, RFC 3261 §21); `_reason` documents
/// the caller's intent only.
fn build_plain_response_for_request(
    request: &Request,
    status: u16,
    _reason: &str,
) -> Result<SipMessage> {
    let mut headers: rsip::Headers = Default::default();

    // Copy ALL Via headers from the request (RFC 3261 §8.2.6.2)
    // A response MUST contain all Via headers in the same order as the request.
    // Only copying the top Via breaks responses when the request traversed proxies.
    let mut via_count = 0;
    for h in request.headers.iter() {
        let s = h.to_string();
        if s.to_lowercase().starts_with("via:") || s.to_lowercase().starts_with("v:") {
            headers.push(h.clone());
            via_count += 1;
        }
    }
    if via_count == 0 {
        // Fallback: use the single via_header() method
        headers.push(request.via_header()?.clone().into());
    }

    headers.push(request.from_header()?.clone().into());

    // To with tag
    let mut to = request.to_header()?.typed()?;
    if to.params.iter().all(|p| !matches!(p, rsip::Param::Tag(_))) {
        to.params.push(rsip::Param::Tag(rsip::param::Tag::new(
            &uuid::Uuid::new_v4().to_string()[..8],
        )));
    }
    headers.push(to.into());

    headers.push(request.call_id_header()?.clone().into());
    headers.push(request.cseq_header()?.clone().into());
    headers.push(rsip::Header::ContentLength(Default::default()));

    Ok(SipMessage::Response(rsip::Response {
        status_code: status.into(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }))
}

/// Build 401 Unauthorized for REGISTER with WWW-Authenticate challenge
fn build_register_401(request: &Request, challenge: &str) -> Result<SipMessage> {
    let mut headers: rsip::Headers = Default::default();

    headers.push(request.via_header()?.clone().into());
    headers.push(request.from_header()?.clone().into());

    let mut to = request.to_header()?.typed()?;
    if to.params.iter().all(|p| !matches!(p, rsip::Param::Tag(_))) {
        to.params.push(rsip::Param::Tag(rsip::param::Tag::new(
            &uuid::Uuid::new_v4().to_string()[..8],
        )));
    }
    headers.push(to.into());

    headers.push(request.call_id_header()?.clone().into());
    headers.push(request.cseq_header()?.clone().into());

    // WWW-Authenticate header with the Digest challenge
    headers.push(rsip::Header::WwwAuthenticate(
        rsip::headers::WwwAuthenticate::new(challenge),
    ));

    headers.push(rsip::Header::ContentLength(Default::default()));

    Ok(SipMessage::Response(rsip::Response {
        status_code: 401.into(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }))
}

/// Build 200 OK for successful REGISTER with Contact bindings
fn build_register_200(
    request: &Request,
    bindings: &[crate::register::Registration],
    _call_id: &str,
    _cseq: u32,
) -> Result<SipMessage> {
    let mut headers: rsip::Headers = Default::default();

    headers.push(request.via_header()?.clone().into());
    headers.push(request.from_header()?.clone().into());

    let mut to = request.to_header()?.typed()?;
    if to.params.iter().all(|p| !matches!(p, rsip::Param::Tag(_))) {
        to.params.push(rsip::Param::Tag(rsip::param::Tag::new(
            &uuid::Uuid::new_v4().to_string()[..8],
        )));
    }
    headers.push(to.into());

    headers.push(request.call_id_header()?.clone().into());
    headers.push(request.cseq_header()?.clone().into());

    // Echo back Contact bindings with expires
    for binding in bindings {
        let contact_value = format!("{};expires={}", binding.contact, binding.expires);
        headers.push(rsip::Header::Contact(rsip::headers::Contact::new(
            &contact_value,
        )));
    }

    // If no bindings, echo the request contact
    if bindings.is_empty() {
        if let Ok(contact) = request.contact_header() {
            headers.push(contact.clone().into());
        }
    }

    // Expires header
    let expires_val = bindings.first().map(|b| b.expires).unwrap_or(3600);
    headers.push(rsip::Header::Expires(rsip::headers::Expires::new(
        expires_val.to_string(),
    )));

    headers.push(rsip::Header::ContentLength(Default::default()));

    Ok(SipMessage::Response(rsip::Response {
        status_code: 200.into(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }))
}

/// Extract the user part from a SIP URI.
/// e.g. "sip:+33612345678@sip.nixi.tel" → "+33612345678"
/// e.g. "sip:0612345678@trunk.example.com" → "0612345678"
#[allow(dead_code)]
fn extract_uri_user(uri: &str) -> Option<String> {
    // Strip "sip:" or "sips:" prefix
    let without_scheme = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;
    // Take everything before '@'
    let user = without_scheme.split('@').next()?;
    if user.is_empty() {
        None
    } else {
        Some(user.to_string())
    }
}

/// Extract the Request-URI from a raw SIP INVITE message.
/// e.g. "INVITE sip:+33612345678@sip.nixi.tel SIP/2.0\r\n..." → "sip:+33612345678@sip.nixi.tel"
fn extract_request_uri_from_raw(raw: &str) -> Option<String> {
    let first_line = raw.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Inject Proxy-Authorization into a raw INVITE and update Via branch + CSeq.
/// This creates a new INVITE suitable for 407 auth retry.
fn inject_proxy_auth_into_invite(raw_invite: &str, auth_value: &str) -> String {
    // 1+2. New transaction: fresh top-Via branch (RFC 3261 §8.1.1.7) and
    //      CSeq+1 (§22.2). Header block only — the SDP body is untouched.
    let renewed = crate::sip_builder::renew_invite_transaction(raw_invite);
    let (head, body) = match renewed.find("\r\n\r\n") {
        Some(pos) => (&renewed[..pos], &renewed[pos + 4..]),
        None => (renewed.as_str(), ""),
    };
    let mut lines: Vec<String> = head.split("\r\n").map(|l| l.to_string()).collect();

    // 3. Drop any earlier Proxy-Authorization (a 422 retry may precede a
    //    fresh challenge) so the new credentials are the only ones.
    lines.retain(|l| !l.to_lowercase().starts_with("proxy-authorization:"));

    // 4. Inject Proxy-Authorization after the request line and the top Via
    let insert_pos = lines
        .iter()
        .position(|l| {
            let lower = l.to_lowercase();
            !lower.starts_with("invite ") && !lower.starts_with("via:") && !lower.starts_with("v:")
        })
        .unwrap_or(1);
    lines.insert(insert_pos, format!("Proxy-Authorization: {}", auth_value));

    let mut out = lines.join("\r\n");
    out.push_str("\r\n\r\n");
    out.push_str(body);
    out
}

/// RFC 3339 for a SystemTime (UTC).
pub(crate) fn systemtime_rfc3339(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let rem_secs = secs % 86400;
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
        rem_secs / 3600,
        (rem_secs % 3600) / 60,
        rem_secs % 60
    )
}

/// Convert a persisted ban row back to a live entry.
fn ban_row_to_entry(row: &sbc_storage::BanRow) -> Option<crate::security::BanEntry> {
    let ip: std::net::IpAddr = row.ip.parse().ok()?;
    let parse_ts = |s: &str| -> Option<std::time::SystemTime> {
        // RFC 3339 "YYYY-MM-DDTHH:MM:SSZ" → SystemTime (UTC, 1970-2099)
        let (date, time) = s.split_once('T')?;
        let mut d = date.split('-');
        let (y, m, day): (u64, u64, u64) = (
            d.next()?.parse().ok()?,
            d.next()?.parse().ok()?,
            d.next()?.parse().ok()?,
        );
        let mut t = time.trim_end_matches('Z').split(':');
        let (hh, mm, ss): (u64, u64, u64) = (
            t.next()?.parse().ok()?,
            t.next()?.parse().ok()?,
            t.next()?.split('.').next()?.parse().ok()?,
        );
        let mut days = 0u64;
        for yy in 1970..y {
            days += if (yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0 {
                366
            } else {
                365
            };
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
        for len in month_len.iter().take(m.saturating_sub(1) as usize) {
            days += len;
        }
        days += day.saturating_sub(1);
        Some(std::time::UNIX_EPOCH + Duration::from_secs(days * 86400 + hh * 3600 + mm * 60 + ss))
    };
    Some(crate::security::BanEntry {
        ip,
        reason: row.reason.clone(),
        banned_at: parse_ts(&row.banned_at)?,
        expires_at: parse_ts(&row.expires_at)?,
        failures: row.failures as u32,
        manual: row.manual,
        offense_count: row.offense_count as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenerConfig, TransportType};

    #[tokio::test]
    async fn test_sbc_creation() {
        let sbc = Sbc::new();
        assert_eq!(sbc.b2bua().stats().await.total_active, 0);
        assert_eq!(sbc.media().stats().allocated_ports, 0);
    }

    #[tokio::test]
    async fn test_sbc_start() {
        let mut sbc = Sbc::new();
        let config = NetworkConfig {
            listeners: vec![ListenerConfig {
                transport: TransportType::UDP,
                bind_address: "127.0.0.1".parse().unwrap(),
                bind_port: 0, // Random port
                cert_file: None,
                key_file: None,
            }],
            public_ipv4: None,
            public_ipv6: None,
        };

        let result = sbc.start(&config, None).await;
        assert!(result.is_ok());

        // Let maintenance tasks run briefly
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// A config whose store lives in a private temp dir (the default
    /// `data/sbc.db` would be shared by every test in the binary).
    fn config_with_temp_store() -> (SbcConfig, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("sbc-boot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = SbcConfig::default();
        config.database.sqlite_path = dir.join("sbc.db").to_string_lossy().into_owned();
        config.database.backup_interval_hours = 0;
        (config, dir)
    }

    #[tokio::test]
    async fn test_sbc_from_config() {
        let (config, dir) = config_with_temp_store();
        let sbc = Sbc::new_from_config(&config).await.unwrap();
        let ready = sbc.readiness();
        assert!(ready.store_open() && ready.hydrated());
        assert!(!ready.listening(), "not before start()");
        assert!(!ready.is_ready());
        assert_eq!(
            sbc.metrics
                .store_available
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn store_open_failure_is_fatal_by_default_and_tolerated_when_allowed() {
        // The store path's parent is a regular file: it cannot be created.
        let dir = std::env::temp_dir().join(format!("sbc-boot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let mut config = SbcConfig::default();
        config.database.sqlite_path = blocker.join("sbc.db").to_string_lossy().into_owned();
        config.database.backup_interval_hours = 0;
        let err = Sbc::new_from_config(&config).await.err().expect("fatal");
        let msg = err.to_string();
        assert!(msg.contains("refusing to start"), "{}", msg);
        assert!(msg.contains("allow_missing_store"), "{}", msg);

        config.database.allow_missing_store = true;
        let sbc = Sbc::new_from_config(&config).await.unwrap();
        assert!(sbc.config_store().is_none());
        assert!(!sbc.readiness().store_open());
        assert!(!sbc.readiness().is_ready());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_sbc_with_digest_auth() {
        let (mut config, _dir) = config_with_temp_store();
        config.security.enable_digest_auth = true;
        config.security.sip_realm = "test.sbc.local".to_string();
        config
            .security
            .sip_users
            .insert("alice".to_string(), "password123".to_string());

        let sbc = Sbc::new_from_config(&config).await.unwrap();
        assert!(sbc.auth.is_some());
        assert!(sbc.enable_digest_auth);
    }
}

#[cfg(test)]
mod send_sip_tests {
    use super::*;

    #[tokio::test]
    async fn failed_sends_are_counted_per_transport() {
        let sbc = Sbc::new();
        let dest: SocketAddr = "203.0.113.1:5061".parse().unwrap();
        // No WSS connection channel and no listener: the send cannot succeed.
        let sent = sbc
            .send_sip(
                "test BYE",
                b"BYE sip:x SIP/2.0\r\n\r\n",
                dest,
                rsip::Transport::Wss,
                None,
            )
            .await;
        assert!(!sent);
        let failures = sbc.metrics.sip_send_failures.lock().unwrap().clone();
        assert_eq!(failures.get("wss"), Some(&1));
        let output = sbc.metrics.render_prometheus();
        assert!(
            output.contains("sbc_sip_send_failures_total{transport=\"wss\"} 1"),
            "{}",
            output
        );
    }
}

#[cfg(test)]
mod cseq_mapping_tests {
    use super::*;

    const RESP_200: &str = "SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKsbc\r\n\
        From: <sip:a@b>;tag=1\r\n\
        To: <sip:c@d>;tag=2\r\n\
        Call-ID: x\r\n\
        CSeq: 4 INVITE\r\n\
        Content-Length: 0\r\n\r\n";

    #[test]
    fn rewrite_response_restores_caller_invite_cseq() {
        let vias = vec!["Via: SIP/2.0/UDP 10.0.0.9;branch=z9hG4bKcaller".to_string()];
        let out = rewrite_response_for_caller(RESP_200, &vias, None, Some(3));
        assert!(out.contains("CSeq: 3 INVITE\r\n"), "{}", out);
        assert!(out.contains("branch=z9hG4bKcaller"));
        assert!(!out.contains("z9hG4bKsbc"));
        rsip::SipMessage::try_from(out.as_bytes().to_vec()).unwrap();

        // Same number: no-op
        let same = rewrite_response_for_caller(RESP_200, &vias, None, Some(4));
        assert!(same.contains("CSeq: 4 INVITE\r\n"));
        // Unknown caller CSeq: untouched
        let none = rewrite_response_for_caller(RESP_200, &vias, None, None);
        assert!(none.contains("CSeq: 4 INVITE\r\n"));
        // Other methods are never rewritten
        let bye = RESP_200.replace("4 INVITE", "4 BYE");
        assert!(rewrite_response_for_caller(&bye, &vias, None, Some(3)).contains("CSeq: 4 BYE\r\n"));
        // A header-less 503 must not gain a CSeq
        let plain = build_plain_response(503, "Service Unavailable");
        assert!(!rewrite_response_for_caller(&plain, &vias, None, Some(3)).contains("CSeq:"));
    }

    #[test]
    fn inject_proxy_auth_renews_transaction_dedupes_and_keeps_body() {
        let invite = "INVITE sip:x@y SIP/2.0\r\n\
            Via: SIP/2.0/UDP h;branch=z9hG4bKold;rport\r\n\
            Proxy-Authorization: Digest stale\r\n\
            From: <sip:a@b>;tag=1\r\n\
            To: <sip:x@y>\r\n\
            Call-ID: c\r\n\
            CSeq: 3 INVITE\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: 5\r\n\r\n\
            v=0\r\n";
        let out = inject_proxy_auth_into_invite(invite, "Digest fresh");
        assert_eq!(out.matches("Proxy-Authorization:").count(), 1, "{}", out);
        assert!(out.contains("Proxy-Authorization: Digest fresh\r\n"));
        assert!(out.contains("CSeq: 4 INVITE\r\n"));
        assert!(!out.contains("z9hG4bKold"));
        assert!(out.contains("branch=z9hG4bK"));
        assert!(
            out.ends_with("Content-Length: 5\r\n\r\nv=0\r\n"),
            "body and its CRLF preserved: {:?}",
            out
        );
        let lines: Vec<&str> = out.split("\r\n").collect();
        assert!(lines[1].starts_with("Via:"));
        assert!(
            lines[2].starts_with("Proxy-Authorization:"),
            "inserted right after the top Via"
        );
        rsip::SipMessage::try_from(out.as_bytes().to_vec()).unwrap();
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn uri_parts() {
        assert_eq!(
            uri_user("sip:alice@sip.example.com").as_deref(),
            Some("alice")
        );
        assert_eq!(
            uri_user("\"Bob\" <sip:bob@sip.example.com>;tag=1").as_deref(),
            Some("bob"),
            "display names are not the user"
        );
        assert_eq!(
            uri_host("\"x@evil.example\" <sip:alice@sip.example.com>;tag=1").as_deref(),
            Some("sip.example.com"),
            "an @ in the display name does not fool the host"
        );
        assert_eq!(
            uri_host("\"<x>\" <sip:alice@h>").as_deref(),
            Some("h"),
            "a < inside the display name: the last <…> wins"
        );
        assert_eq!(uri_user("<sip:alice@h>").as_deref(), Some("alice"));
        assert_eq!(
            uri_user("<sips:Alice@h:5061;transport=tls>").as_deref(),
            Some("Alice")
        );
        assert_eq!(uri_user("sip:sip.example.com"), None);
        assert_eq!(
            uri_host("sip:alice@Sip.Example.COM:5060;x=1").as_deref(),
            Some("sip.example.com")
        );
        assert_eq!(
            uri_host("sip:alice@[2001:db8::1]:5060").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(uri_host("sip:203.0.113.1").as_deref(), Some("203.0.113.1"));
    }

    #[test]
    fn aor_authorization() {
        let served = vec!["sip.example.com".to_string(), "203.0.113.1".to_string()];
        assert!(authorize_aor("alice", "sip:alice@sip.example.com", &served).is_ok());
        assert!(authorize_aor("alice", "sip:alice@203.0.113.1:5060", &served).is_ok());
        assert_eq!(
            authorize_aor("alice", "sip:bob@sip.example.com", &served),
            Err(AorRejection::User("bob".into()))
        );
        assert_eq!(
            authorize_aor("alice", "sip:Alice@sip.example.com", &served),
            Err(AorRejection::User("Alice".into())),
            "user part is case-sensitive (RFC 3261 §19.1.4)"
        );
        assert_eq!(
            authorize_aor("alice", "sip:alice@evil.example", &served),
            Err(AorRejection::Domain("evil.example".into()))
        );
        assert!(
            authorize_aor("alice", "sip:alice@anything", &[]).is_ok(),
            "no served domain known: only the user part is checked"
        );
    }
}
