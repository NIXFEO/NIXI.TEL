//! Integrated SBC Core
//!
//! Combines Transport, Transaction, Dialog, Media, B2BUA, Router, Auth,
//! ACL, DoS protection, REGISTER handling, and Topology hiding into a
//! single SBC instance that owns the full message processing pipeline.

mod invite_handler;
mod response_handler;
mod call_handler;

use crate::acl::{AclManager, Direction};
use crate::auth::{DigestAuthenticator, DigestChallenge, generate_digest_response};
use crate::b2bua::B2buaManager;
use crate::config::{DidMapping, NetworkConfig, SbcConfig};
use crate::dialog::DialogManager;
use crate::dos::{DosProtector, RateLimitConfig};
use crate::http_server::{HttpServer, HttpServerConfig};
use crate::maintenance::{MaintenanceConfig, MaintenanceHandle, MaintenanceTask};
use crate::media::MediaManager;
use crate::media::dtls::DtlsUdpBridge;
use crate::media::sdp::transform_webrtc_to_trunk;
use crate::media::webrtc_handler::WebRtcSession;
use crate::metrics::SbcMetrics;
use crate::register::{InMemoryRegistrar, RegisterHandler, RegisterResult};
use crate::routing::router::Router;
use crate::routing::trunk::NumberFormat;
use crate::routing::{TrunkManager, TrunkConfig};
use crate::storage::CdrManager;
use crate::topology::{apply_topology_hiding_outbound, SbcIdentity};
use crate::transaction::TransactionManager;
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
pub struct Sbc {
    /// Transport layer (UDP, TCP, TLS, WSS)
    transport: TransportManager,

    /// Transaction layer (RFC 3261 state machines)
    transactions: Arc<TransactionManager>,

    /// Dialog layer (call state tracking)
    dialogs: Arc<DialogManager>,

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
    pub pending_register_responses: Arc<DashMap<String, tokio::sync::oneshot::Sender<String>>>,

    /// DID → SIP user mappings for inbound PSTN calls
    did_mappings: Vec<DidMapping>,

    /// Known trunk IPs (whitelisted for inbound INVITE anti-spam)
    trunk_ips: Vec<String>,

    /// Notify signal for API-triggered config reload
    reload_notify: Arc<tokio::sync::Notify>,
}

impl Sbc {
    /// Create a new SBC instance from full configuration (with optional Phase 5 management handler).
    ///
    /// If `management` is `Some`, the management API endpoints (users, DIDs, config/reload)
    /// are wired into the HTTP server.  Pass `None` to omit them (existing behaviour).
    pub async fn new_from_config_with_management(
        config: &SbcConfig,
        management: Option<Arc<dyn crate::api::ManagementHandler>>,
    ) -> Result<Self> {
        Self::_new_from_config_inner(config, management).await
    }

    /// Create a new SBC instance from full configuration (no management handler).
    pub async fn new_from_config(config: &SbcConfig) -> Result<Self> {
        Self::_new_from_config_inner(config, None).await
    }

    async fn _new_from_config_inner(
        config: &SbcConfig,
        management: Option<Arc<dyn crate::api::ManagementHandler>>,
    ) -> Result<Self> {
        // --- Metrics (created early so counters can be shared with Media) ---
        let metrics = Arc::new(SbcMetrics::new());

        // --- Media ---
        let port_range = config.media.rtp_port_range.0..config.media.rtp_port_range.1;
        let public_ip = config.network.public_ipv4.map(|ip| std::net::IpAddr::V4(
            match ip { std::net::IpAddr::V4(v4) => v4, std::net::IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED }
        ));
        let mut media_mgr = MediaManager::with_port_range(port_range, public_ip);
        media_mgr.set_global_rtp_counter(metrics.rtp_packets_total.clone());
        media_mgr.set_global_srtp_encrypt_counter(metrics.srtp_encrypted_total.clone());
        media_mgr.set_global_srtp_decrypt_counter(metrics.srtp_decrypted_total.clone());
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
                "WS"  => crate::routing::TransportType::Ws,
                _     => crate::routing::TransportType::Udp,
            };
            let number_format = match tc.number_format.to_lowercase().as_str() {
                "national" => NumberFormat::National,
                "local"    => NumberFormat::Local,
                _          => NumberFormat::E164,
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
            };

            // Resolve DNS for hostnames (e.g. trunk.example.com → IP)
            match trunk.resolve_destination().await {
                Some(addr) => info!("Loaded trunk '{}' from config → resolved {}:{} → {}", trunk.name, trunk.host, trunk.port, addr),
                None => warn!("Trunk '{}': DNS resolution failed for {}:{} — will retry", trunk.name, trunk.host, trunk.port),
            }

            let trunk_id = trunk_manager.add_trunk(trunk);
            info!("Trunk '{}' added (id: {})", tc.name, trunk_id);
        }

        let router = Arc::new(Router::new(trunk_manager.clone()));

        // --- Registrar ---
        let registrar: Arc<dyn crate::register::Registrar> = Arc::new(InMemoryRegistrar::new());
        let register_handler = Arc::new(RegisterHandler::new(registrar.clone()));

        // --- Digest Auth ---
        let (auth, enable_digest_auth) = if config.security.enable_digest_auth
            && !config.security.sip_users.is_empty()
        {
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
                    warn!("CDR file storage failed ({}), using memory: {}", cdr_file, e);
                    Arc::new(CdrManager::new_memory())
                }
            }
        } else {
            Arc::new(CdrManager::new_memory())
        };

        // --- HTTP API + /metrics endpoint ---
        if config.management.api_enabled {
            let http_addr: std::net::SocketAddr = format!(
                "{}:{}",
                config.management.api_bind_address,
                config.management.api_port
            ).parse().unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap());

            let mut http_config = HttpServerConfig::new(http_addr);
            if let Some(ref token) = config.management.api_auth_token {
                http_config = http_config.with_token(token.clone());
            }
            let mut http_server = HttpServer::new(
                http_config,
                metrics.clone(),
                b2bua.clone(),
                trunk_manager.clone(),
            ).with_registrar(registrar.clone())
             .with_reload_notify(reload_notify.clone())
             .with_cdr(cdr.clone());
            if let Some(mgmt) = management {
                http_server = http_server.with_management(mgmt);
            }
            if let Err(e) = http_server.start().await {
                warn!("HTTP API server failed to start: {}", e);
            } else {
                info!("HTTP API + /metrics listening on http://{}", http_addr);
            }
        }

        // ── Collect trunk IPs for inbound INVITE whitelist ──
        let trunk_ips: Vec<String> = trunk_manager.list_trunks().iter()
            .filter_map(|t| t.resolved_addr.map(|a| a.ip().to_string()))
            .chain(config.trunks.iter().map(|t| t.host.clone()))
            .collect();
        if !trunk_ips.is_empty() {
            info!("Trunk IPs whitelisted for inbound INVITE: {:?}", trunk_ips);
        }

        // ── Load DID mappings ──
        for did in &config.dids {
            info!("DID mapping: {} → {}", did.number, did.user);
        }

        Ok(Self {
            transport: TransportManager::new(),
            transactions: Arc::new(TransactionManager::new()),
            dialogs: Arc::new(DialogManager::new()),
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
            pending_register_responses: Arc::new(DashMap::new()),
            did_mappings: config.dids.clone(),
            trunk_ips,
            reload_notify,
        })
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
        let path = self.config_path.as_deref()
            .ok_or_else(|| Error::Config("No config path set for reload".to_string()))?;

        info!("SIGHUP: reloading configuration from {}", path);

        let config = SbcConfig::from_file(path)?;

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
            if !tc.enabled { continue; }

            // Check if trunk already exists (by name)
            let existing = self.trunk_manager.list_trunks().iter()
                .find(|t| t.name == tc.name)
                .map(|t| t.id);

            if existing.is_none() {
                let transport = match tc.transport.to_uppercase().as_str() {
                    "TCP" => crate::routing::TransportType::Tcp,
                    "TLS" => crate::routing::TransportType::Tls,
                    "WSS" => crate::routing::TransportType::Wss,
                    "WS"  => crate::routing::TransportType::Ws,
                    _     => crate::routing::TransportType::Udp,
                };
                let number_format = match tc.number_format.to_lowercase().as_str() {
                    "national" => NumberFormat::National,
                    "local"    => NumberFormat::Local,
                    _          => NumberFormat::E164,
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
                };
                let _ = trunk.resolve_destination().await;
                self.trunk_manager.add_trunk(trunk);
                trunks_added += 1;
            }
        }
        let total_trunks = self.trunk_manager.list_trunks().len();
        info!("SIGHUP: trunks reloaded — {} total ({} added)", total_trunks, trunks_added);

        // Reload DID mappings
        self.did_mappings = config.dids.clone();
        info!("SIGHUP: DID mappings reloaded — {} entries", self.did_mappings.len());

        // Reload trunk IPs whitelist
        self.trunk_ips = self.trunk_manager.list_trunks().iter()
            .filter_map(|t| t.resolved_addr.map(|a| a.ip().to_string()))
            .chain(config.trunks.iter().map(|t| t.host.clone()))
            .collect();
        info!("SIGHUP: trunk IPs reloaded — {:?}", self.trunk_ips);

        info!("SIGHUP: configuration reloaded successfully");
        Ok(())
    }

    /// Create a minimal SBC instance (for tests / simple usage)
    pub fn new() -> Self {
        let media = Arc::new(MediaManager::default());
        let b2bua = Arc::new(B2buaManager::new(media.clone()));
        let trunk_manager = Arc::new(TrunkManager::new());
        let router = Arc::new(Router::new(trunk_manager.clone()));
        let registrar = Arc::new(InMemoryRegistrar::new());
        let register_handler = Arc::new(RegisterHandler::new(registrar));

        Self {
            transport: TransportManager::new(),
            transactions: Arc::new(TransactionManager::new()),
            dialogs: Arc::new(DialogManager::new()),
            media,
            b2bua,
            router,
            register_handler,
            auth: None,
            acl: Arc::new(AclManager::new_permissive()),
            dos: Arc::new(DosProtector::new(RateLimitConfig::default())),
            identity: None,
            enable_digest_auth: false,
            metrics: Arc::new(SbcMetrics::new()),
            cdr: Arc::new(CdrManager::new_memory()),
            _maintenance: None,
            config_path: None,
            trunk_manager,
            pending_register_responses: Arc::new(DashMap::new()),
            did_mappings: Vec::new(),
            trunk_ips: Vec::new(),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Add a trunk to the router (for programmatic trunk configuration)
    pub fn add_trunk(&self, trunk: TrunkConfig) -> crate::routing::TrunkId {
        self.router.trunk_manager().add_trunk(trunk)
    }

    /// Start outbound REGISTER loops for trunks that need it.
    /// Must be called AFTER `sbc.start()` so UDP listeners are available.
    /// Uses the main UDP socket (port 5060) so that the trunk sees the same
    /// source address for REGISTER and INVITE. Responses arrive on the main
    /// event loop and are routed via `pending_register_responses`.
    pub fn start_trunk_registrations(&self) {
        let trunks = self.trunk_manager.list_trunks();
        let identity = self.identity.clone();

        // Get the main UDP socket (port 5060)
        let udp_socket = match self.transport.udp_socket() {
            Some(s) => s,
            None => {
                warn!("No UDP socket available — trunk registrations will not start");
                return;
            }
        };

        let pending = self.pending_register_responses.clone();

        for trunk in trunks {
            if !trunk.register_with_trunk || !trunk.enabled {
                continue;
            }
            info!("Starting outbound REGISTER loop for trunk '{}'", trunk.name);
            let identity = identity.clone();
            let sock = udp_socket.clone();
            let pending = pending.clone();
            tokio::spawn(Self::trunk_register_task(trunk, identity, sock, pending));
        }
    }

    /// Single trunk registration task — uses the shared UDP socket (port 5060).
    /// Responses are routed from handle_response() via pending_register_responses.
    async fn trunk_register_task(
        trunk: TrunkConfig,
        identity: Option<SbcIdentity>,
        sock: Arc<tokio::net::UdpSocket>,
        pending: Arc<DashMap<String, tokio::sync::oneshot::Sender<String>>>,
    ) {
        let trunk_name = trunk.name.clone();
        let interval = trunk.registration_interval.as_secs().max(60);

        loop {
            info!("Trunk '{}': sending REGISTER", trunk_name);
            match Self::send_trunk_register(&trunk, &sock, &identity, &pending).await {
                Ok(expires) => {
                    info!("Trunk '{}': registered successfully (expires={}s)", trunk_name, expires);
                    let sleep_secs = ((expires as f64) * 0.8) as u64;
                    let sleep_secs = sleep_secs.max(30).min(interval);
                    tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
                }
                Err(reason) => {
                    warn!("Trunk '{}': REGISTER failed: {}, retrying in 60s", trunk_name, reason);
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            }
        }
    }

    /// Send a REGISTER to a trunk via the shared UDP socket (port 5060).
    /// Waits for the response via a oneshot channel populated by handle_response().
    /// Handles 401/407 auth challenge inline.
    async fn send_trunk_register(
        trunk: &TrunkConfig,
        sock: &tokio::net::UdpSocket,
        identity: &Option<SbcIdentity>,
        pending: &Arc<DashMap<String, tokio::sync::oneshot::Sender<String>>>,
    ) -> std::result::Result<u32, String> {
        let dest = trunk.destination()
            .ok_or_else(|| format!("No destination for trunk '{}'", trunk.name))?;

        let call_id = format!("reg-{}-{}", trunk.name, &uuid::Uuid::new_v4().to_string()[..8]);
        let branch = format!("z9hG4bK{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..16]);
        let tag = uuid::Uuid::new_v4().to_string()[..8].to_string();

        let (sbc_ip, _sbc_domain) = match identity {
            Some(id) => (id.public_ip.clone(), id.sip_domain.clone()),
            None => ("127.0.0.1".to_string(), trunk.host.clone()),
        };

        let username = trunk.username.as_deref().unwrap_or("anonymous");
        let request_uri = format!("sip:{}", trunk.host);
        let from = format!("<sip:{}@{}>;tag={}", username, trunk.host, tag);
        let to = format!("<sip:{}@{}>", username, trunk.host);
        let contact = format!("<sip:{}@{}:5060;transport=udp>", username, sbc_ip);
        let via = format!("SIP/2.0/UDP {}:5060;branch={};rport", sbc_ip, branch);
        let expires = trunk.registration_interval.as_secs();

        let register_msg = format!(
            "REGISTER {} SIP/2.0\r\n\
             Via: {}\r\n\
             Max-Forwards: 70\r\n\
             From: {}\r\n\
             To: {}\r\n\
             Call-ID: {}\r\n\
             CSeq: 1 REGISTER\r\n\
             Contact: {}\r\n\
             Expires: {}\r\n\
             User-Agent: NIXI-SBC/1.0\r\n\
             Content-Length: 0\r\n\r\n",
            request_uri, via, from, to, call_id, contact, expires
        );

        // Register a oneshot channel so handle_response() can route the reply to us
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        pending.insert(call_id.clone(), tx);

        // Send via the shared socket (port 5060)
        sock.send_to(register_msg.as_bytes(), dest).await
            .map_err(|e| { pending.remove(&call_id); format!("Send failed: {}", e) })?;

        debug!("Trunk '{}': sent REGISTER to {} via port 5060 (Call-ID: {})", trunk.name, dest, call_id);

        // Wait for response via the oneshot channel (routed by handle_response)
        let response_raw = match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            rx,
        ).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(_)) => { pending.remove(&call_id); return Err("Response channel closed".to_string()); }
            Err(_) => { pending.remove(&call_id); return Err("Timeout (10s)".to_string()); }
        };

        let status = crate::trunk_register::parse_status(&response_raw);
        debug!("Trunk '{}': got {} for REGISTER", trunk.name, status);

        match status {
            200 => {
                let exp = crate::trunk_register::parse_expires(&response_raw).unwrap_or(300);
                Ok(exp)
            }
            401 | 407 => {
                // Extract challenge and retry with auth
                let header_name = if status == 401 { "www-authenticate" } else { "proxy-authenticate" };
                let challenge_str = crate::trunk_register::extract_header(&response_raw, header_name)
                    .ok_or_else(|| format!("No {} header in {}", header_name, status))?;
                let challenge = DigestChallenge::from_header(&challenge_str)
                    .map_err(|e| format!("Bad challenge: {}", e))?;

                let password = trunk.password.as_deref().unwrap_or("");
                let auth_value = generate_digest_response(username, password, &challenge, "REGISTER", &request_uri);

                info!("Trunk '{}': {} challenge, retrying with auth (realm='{}')", trunk.name, status, challenge.realm);

                let auth_header_name = if status == 401 { "Authorization" } else { "Proxy-Authorization" };
                let branch2 = format!("z9hG4bK{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..16]);
                let via2 = format!("SIP/2.0/UDP {}:5060;branch={};rport", sbc_ip, branch2);

                let register_auth = format!(
                    "REGISTER {} SIP/2.0\r\n\
                     Via: {}\r\n\
                     Max-Forwards: 70\r\n\
                     From: {}\r\n\
                     To: {}\r\n\
                     Call-ID: {}\r\n\
                     CSeq: 2 REGISTER\r\n\
                     Contact: {}\r\n\
                     {}: {}\r\n\
                     Expires: {}\r\n\
                     User-Agent: NIXI-SBC/1.0\r\n\
                     Content-Length: 0\r\n\r\n",
                    request_uri, via2, from, to, call_id, contact,
                    auth_header_name, auth_value, expires
                );

                // Register a new oneshot for the auth response
                let (tx2, rx2) = tokio::sync::oneshot::channel::<String>();
                pending.insert(call_id.clone(), tx2);

                sock.send_to(register_auth.as_bytes(), dest).await
                    .map_err(|e| { pending.remove(&call_id); format!("Auth send failed: {}", e) })?;

                // Wait for auth response via oneshot channel
                let response_raw2 = match tokio::time::timeout(
                    tokio::time::Duration::from_secs(10),
                    rx2,
                ).await {
                    Ok(Ok(raw)) => raw,
                    Ok(Err(_)) => { pending.remove(&call_id); return Err("Auth response channel closed".to_string()); }
                    Err(_) => { pending.remove(&call_id); return Err("Auth response timeout".to_string()); }
                };

                let status2 = crate::trunk_register::parse_status(&response_raw2);
                if status2 == 200 {
                    let exp = crate::trunk_register::parse_expires(&response_raw2).unwrap_or(300);
                    Ok(exp)
                } else {
                    Err(format!("Auth retry got {}", status2))
                }
            }
            _ => Err(format!("Unexpected status: {}", status)),
        }
    }

    /// Start trunk health checks (OPTIONS keepalive every 30s)
    pub fn start_trunk_health_checks(&self) {
        let trunks = self.trunk_manager.list_trunks();
        let identity = self.identity.clone();
        let trunk_manager = self.trunk_manager.clone();
        let metrics = self.metrics.clone();

        let udp_socket = match self.transport.udp_socket() {
            Some(s) => s,
            None => {
                warn!("No UDP socket available — trunk health checks will not start");
                return;
            }
        };

        let pending = self.pending_register_responses.clone();

        for trunk in trunks {
            if !trunk.enabled { continue; }
            info!("Starting OPTIONS health check for trunk '{}' ({}:{})", trunk.name, trunk.host, trunk.port);
            let identity = identity.clone();
            let sock = udp_socket.clone();
            let pending = pending.clone();
            let tm = trunk_manager.clone();
            let metrics = metrics.clone();
            tokio::spawn(Self::trunk_health_check_task(trunk, identity, sock, pending, tm, metrics));
        }
    }

    /// Health check task — sends OPTIONS to trunk every 30s, tracks up/down state
    async fn trunk_health_check_task(
        trunk: TrunkConfig,
        identity: Option<SbcIdentity>,
        sock: Arc<tokio::net::UdpSocket>,
        pending: Arc<DashMap<String, tokio::sync::oneshot::Sender<String>>>,
        trunk_manager: Arc<TrunkManager>,
        _metrics: Arc<SbcMetrics>,
    ) {
        let trunk_name = trunk.name.clone();
        let trunk_id = trunk.id;
        let mut was_up = true;
        let mut ever_responded = false; // Track if trunk supports OPTIONS at all

        // Wait 5s before first check (let SBC finish starting)
        tokio::time::sleep(Duration::from_secs(5)).await;

        loop {
            let dest = match trunk.destination() {
                Some(d) => d,
                None => {
                    warn!("Trunk '{}': no destination for health check", trunk_name);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };

            let call_id = format!("hc-{}-{}", trunk_name, &uuid::Uuid::new_v4().to_string()[..8]);
            let branch = format!("z9hG4bK{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..16]);

            let (sbc_ip, _) = match &identity {
                Some(id) => (id.public_ip.clone(), id.sip_domain.clone()),
                None => ("127.0.0.1".to_string(), trunk.host.clone()),
            };

            let options_msg = format!(
                "OPTIONS sip:{}:{} SIP/2.0\r\n\
                 Via: SIP/2.0/UDP {}:5060;branch={};rport\r\n\
                 Max-Forwards: 70\r\n\
                 From: <sip:healthcheck@{}>;tag={}\r\n\
                 To: <sip:{}:{}>\r\n\
                 Call-ID: {}\r\n\
                 CSeq: 1 OPTIONS\r\n\
                 User-Agent: NIXI-SBC/1.0\r\n\
                 Content-Length: 0\r\n\r\n",
                trunk.host, trunk.port,
                sbc_ip, branch,
                sbc_ip, &uuid::Uuid::new_v4().to_string()[..8],
                trunk.host, trunk.port,
                call_id,
            );

            // Register oneshot for response
            let (tx, rx) = tokio::sync::oneshot::channel::<String>();
            pending.insert(call_id.clone(), tx);

            let is_up = match sock.send_to(options_msg.as_bytes(), dest).await {
                Ok(_) => {
                    match tokio::time::timeout(Duration::from_secs(5), rx).await {
                        Ok(Ok(raw)) => {
                            let status = crate::trunk_register::parse_status(&raw);
                            status >= 200 && status < 500
                        }
                        _ => {
                            pending.remove(&call_id);
                            false
                        }
                    }
                }
                Err(_) => {
                    pending.remove(&call_id);
                    false
                }
            };

            // State transition logging
            if is_up {
                ever_responded = true;
                if !was_up {
                    info!("Trunk '{}' is UP — responding to OPTIONS", trunk_name);
                    trunk_manager.update_state(&trunk_id, |s| s.record_success());
                }
            } else if ever_responded {
                // Trunk previously responded to OPTIONS but stopped — real issue
                if was_up {
                    warn!("Trunk '{}' is DOWN — no response to OPTIONS (timeout 5s)", trunk_name);
                    trunk_manager.update_state(&trunk_id, |s| s.record_trunk_failure());
                } else {
                    trunk_manager.update_state(&trunk_id, |s| s.record_trunk_failure());
                    debug!("Trunk '{}' still DOWN", trunk_name);
                }
            } else {
                // Trunk never responded to OPTIONS — probably doesn't support it
                // Log once at info level, then go quiet
                if was_up {
                    info!("Trunk '{}' does not respond to OPTIONS — health check passive only", trunk_name);
                }
            }

            was_up = is_up;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
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

        // Start maintenance tasks
        let config = maintenance_config.unwrap_or_default();
        let maintenance = MaintenanceTask::new(
            self.transactions.clone(),
            self.dialogs.clone(),
            config,
        );
        self._maintenance = Some(maintenance.start());
        info!("Maintenance tasks started");

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
        let source    = received.source;
        let transport = received.transport;
        let reply_tx  = received.reply_tx;

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
            let response_503 = build_plain_response(503, "Service Unavailable");
            let _ = self.transport.reply(response_503.as_bytes(), source, transport, reply_tx.as_ref()).await;
            return Ok(());
        }

        debug!("Processing message from {} via {:?}", source, transport);

        // 3. Dispatch
        match received.message {
            SipMessage::Request(request) => {
                self.handle_request(request, source, transport, reply_tx.as_ref()).await
            }
            SipMessage::Response(response) => {
                self.handle_response(response, source, transport).await
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
            Method::Options  => self.handle_options(&request, source, transport, reply_tx).await,
            Method::Register => self.handle_register(&request, source, transport, reply_tx).await,
            Method::Invite   => self.handle_invite(request, source, transport, reply_tx).await,
            Method::Ack      => self.handle_ack(request, source, transport, reply_tx).await,
            Method::Bye      => self.handle_bye(request, source, transport, reply_tx).await,
            Method::Cancel   => self.handle_cancel(request, source, transport, reply_tx).await,
            Method::Refer    => self.handle_refer(request, source, transport, reply_tx).await,
            method => {
                warn!("Unhandled SIP method: {}", method);
                self.metrics.inc_sip_response(501);
                let response_501 = build_plain_response(501, "Not Implemented");
                let _ = self.transport.reply(response_501.as_bytes(), source, transport, reply_tx).await;
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
        self.transport.reply(&data, source, transport, reply_tx).await
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
        if self.enable_digest_auth {
            if let Some(auth) = &self.auth {
                // Check for Authorization header
                let auth_header: Option<String> = request.authorization_header()
                    .map(|h| h.value().to_string());

                match auth_header {
                    None => {
                        // No auth header → send 401 challenge
                        self.metrics.inc_auth_challenge();
                        self.metrics.inc_sip_response(401);
                        let challenge = auth.generate_challenge().await;
                        let response_401 = build_register_401(request, &challenge)?;
                        let data = response_401.to_string().into_bytes();
                        return self.transport.reply(&data, source, transport, reply_tx).await;
                    }
                    Some(ref auth_value) => {
                        // Verify the credentials
                        let method = request.method.to_string();
                        match auth.verify(auth_value, &method).await {
                            Ok(username) => {
                                info!("REGISTER authenticated for user: {}", username);
                                // Fall through to registration
                            }
                            Err(e) => {
                                self.metrics.inc_auth_failure();
                                self.metrics.inc_sip_response(403);
                                // Nonce-related failures are expected (client retries
                                // with stale nonce after re-REGISTER) — log at debug.
                                // Real auth failures (wrong password, unknown user)
                                // are logged at warn for security monitoring.
                                let err_str = e.to_string();
                                if err_str.contains("nonce") || err_str.contains("Nonce") {
                                    debug!("REGISTER auth: nonce issue from {}: {}", source.ip(), e);
                                } else {
                                    warn!("REGISTER auth failed from {}: {}", source.ip(), e);
                                }
                                let response_403 = build_plain_response_for_request(request, 403, "Forbidden")?;
                                let data = response_403.to_string().into_bytes();
                                return self.transport.reply(&data, source, transport, reply_tx).await;
                            }
                        }
                    }
                }
            }
        }

        // Extract registration fields
        // Normalize AOR: extract URI from angle brackets if present
        // e.g. "<sip:user@domain>" → "sip:user@domain"
        let aor_raw = request.to_header()
            .map_err(|e| Error::Other(format!("Missing To header: {}", e)))?
            .value()
            .to_string();
        let aor = normalize_aor(&aor_raw);

        let contact = request.contact_header()
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
            .or_else(|| request.expires_header().and_then(|h| h.value().parse().ok()))
            .unwrap_or(3600);

        let call_id = request.call_id_header()
            .map_err(|e| Error::Other(format!("Missing Call-ID: {}", e)))?
            .value()
            .to_string();

        let cseq: u32 = request.cseq_header()
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
        match self.register_handler.handle_with_tx(&aor, &contact, expires, &call_id, cseq, source, &transport_str, ws_reply_tx).await {
            Ok(RegisterResult::Ok { expires: exp, bindings }) => {
                info!("Registered {} with {} binding(s), expires={}s", aor, bindings.len(), exp);
                self.metrics.inc_registration();
                self.metrics.set_active_registrations(self.register_handler.count().await);
                self.metrics.inc_sip_response(200);
                let response_200 = build_register_200(request, &bindings, &call_id, cseq)?;
                let data = response_200.to_string().into_bytes();
                self.transport.reply(&data, source, transport, reply_tx).await
            }
            Ok(RegisterResult::Removed { count }) => {
                info!("Unregistered {} contact(s) for {}", count, aor);
                self.metrics.set_active_registrations(self.register_handler.count().await);
                self.metrics.inc_sip_response(200);
                let response_200 = build_plain_response_for_request(request, 200, "OK")?;
                let data = response_200.to_string().into_bytes();
                self.transport.reply(&data, source, transport, reply_tx).await
            }
            Err(e) => {
                warn!("Registration failed for {}: {}", aor, e);
                self.metrics.inc_sip_response(500);
                let response_500 = build_plain_response(500, "Server Internal Error");
                let _ = self.transport.reply(response_500.as_bytes(), source, transport, reply_tx).await;
                Ok(())
            }
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    pub fn transactions(&self) -> &Arc<TransactionManager> { &self.transactions }
    pub fn dialogs(&self) -> &Arc<DialogManager>           { &self.dialogs }
    pub fn transport_mut(&mut self) -> &mut TransportManager { &mut self.transport }
    pub fn media(&self) -> &Arc<MediaManager>              { &self.media }
    pub fn b2bua(&self) -> &Arc<B2buaManager>              { &self.b2bua }
    pub fn router(&self) -> &Arc<Router>                   { &self.router }
    pub fn acl(&self) -> &Arc<AclManager>                  { &self.acl }
    pub fn dos(&self) -> &Arc<DosProtector>                { &self.dos }
    pub fn register_handler(&self) -> &Arc<RegisterHandler> { &self.register_handler }
    pub fn cdr(&self) -> &Arc<CdrManager>                  { &self.cdr }
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
        s[start+1..end].trim().to_string()
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
    let to_str = request.to_header().ok()
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
    let call_id = original_bye.call_id_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

    let from_value = original_bye.from_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:sbc@localhost>".to_string());

    let to_value = original_bye.to_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:callee@localhost>".to_string());

    // Build a minimal BYE using the inbound dialog identifiers
    // The Request-URI uses the To URI (callee)
    let to_uri = if let Ok(to_hdr) = original_bye.to_header() {
        let val = to_hdr.value().to_string();
        // Extract URI from angle brackets if present
        if let (Some(start), Some(end)) = (val.find('<'), val.rfind('>')) {
            val[start+1..end].trim().to_string()
        } else {
            val.split(';').next().unwrap_or("sip:callee@localhost").trim().to_string()
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
    let from_value = original_cancel.from_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:sbc@localhost>".to_string());

    let to_value = original_cancel.to_header()
        .map(|h| h.value().to_string())
        .unwrap_or_else(|_| "<sip:callee@localhost>".to_string());

    // Request-URI = To URI (without tag or display name)
    let to_uri = {
        let val = original_cancel.to_header()
            .map(|h| h.value().to_string())
            .unwrap_or_default();
        if let (Some(start), Some(end)) = (val.find('<'), val.rfind('>')) {
            val[start+1..end].trim().to_string()
        } else {
            val.split(';').next().unwrap_or("sip:callee@localhost").trim().to_string()
        }
    };

    let cseq_num = original_cancel.cseq_header()
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
            || octets[0] == 203 && octets[1] == 0 && octets[2] == 113     // 203.0.113.0/24 (TEST-NET-3)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
            || v6.is_unspecified()
        }
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
        if line.starts_with("c=IN IP4 ") {
            let addr_str = &line["c=IN IP4 ".len()..];
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
        (Some(ip), Some(port)) if port > 0 => {
            Some(std::net::SocketAddr::new(ip, port))
        }
        _ => None,
    }
}

/// Update Content-Length header to match actual body size.
/// MUST be called after rewriting the SDP body so that TCP framing
/// (which relies on Content-Length) stays consistent.
fn update_content_length_response(response: &mut rsip::Response) {
    let cl = rsip::headers::ContentLength::from(response.body.len() as u32);
    response.headers.unique_push(rsip::Header::ContentLength(cl));
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
    format!(
        "SIP/2.0 {} {}\r\nContent-Length: 0\r\n\r\n",
        status, reason
    )
}

/// Build a proper SIP response echoing Via/From/To/Call-ID/CSeq from the request
fn build_plain_response_for_request(request: &Request, status: u16, reason: &str) -> Result<SipMessage> {
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
        headers.push(rsip::Header::Contact(rsip::headers::Contact::new(&contact_value)));
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
        &expires_val.to_string(),
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
    let without_scheme = uri.strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?;
    // Take everything before '@'
    let user = without_scheme.split('@').next()?;
    if user.is_empty() { None } else { Some(user.to_string()) }
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
    let mut lines: Vec<String> = raw_invite.lines().map(|l| l.to_string()).collect();

    // 1. Generate a new Via branch (RFC 3261 §8.1.1.7 requires unique branch per request)
    let new_branch = format!("z9hG4bK-{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string());

    // 2. Update the Via header with a new branch parameter
    for line in lines.iter_mut() {
        if line.to_lowercase().starts_with("via:") || line.to_lowercase().starts_with("v:") {
            // Replace the branch parameter
            if let Some(branch_start) = line.find("branch=") {
                // Find end of branch value (next ';' or end of line)
                let rest = &line[branch_start + 7..];
                let branch_end = rest.find(|c: char| c == ';' || c == ',' || c == '\r' || c == '\n')
                    .unwrap_or(rest.len());
                let old_branch = format!("branch={}", &rest[..branch_end]);
                *line = line.replace(&old_branch, &format!("branch={}", new_branch));
            }
            break; // Only update the top Via
        }
    }

    // 3. Increment CSeq number
    for line in lines.iter_mut() {
        if line.to_lowercase().starts_with("cseq:") {
            // CSeq format: "CSeq: 1 INVITE"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(seq_num) = parts[1].parse::<u32>() {
                    *line = format!("CSeq: {} {}", seq_num + 1, parts[2]);
                }
            }
            break;
        }
    }

    // 4. Inject Proxy-Authorization header after the first line (Request-Line)
    // Insert it after the Via header for proper ordering
    let insert_pos = lines.iter()
        .position(|l| {
            let lower = l.to_lowercase();
            !lower.starts_with("invite ") && !lower.starts_with("via:") && !lower.starts_with("v:")
        })
        .unwrap_or(1);

    lines.insert(insert_pos, format!("Proxy-Authorization: {}", auth_value));

    lines.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenerConfig, TransportType};

    #[tokio::test]
    async fn test_sbc_creation() {
        let sbc = Sbc::new();
        assert_eq!(sbc.transactions().stats().client_transactions, 0);
        assert_eq!(sbc.dialogs().stats().total, 0);
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

    #[tokio::test]
    async fn test_sbc_from_config() {
        let config = SbcConfig::default();
        let sbc = Sbc::new_from_config(&config).await;
        assert!(sbc.is_ok());
    }

    #[tokio::test]
    async fn test_sbc_with_digest_auth() {
        let mut config = SbcConfig::default();
        config.security.enable_digest_auth = true;
        config.security.sip_realm = "test.sbc.local".to_string();
        config.security.sip_users.insert("alice".to_string(), "password123".to_string());

        let sbc = Sbc::new_from_config(&config).await.unwrap();
        assert!(sbc.auth.is_some());
        assert!(sbc.enable_digest_auth);
    }
}
