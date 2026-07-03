//! NIXI.TEL SBC - Session Border Controller
//!
//! Main entry point for the SBC application.
//! All message handling is delegated to sbc_core::Sbc.

use anyhow::Result;
use sbc_core::config::SbcConfig;
use sbc_core::Sbc;
use sbc_management::state::AppState;
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::{info, warn};

#[derive(Debug, StructOpt)]
#[structopt(name = "sbc", about = "NIXI.TEL SBC - Session Border Controller")]
struct Opt {
    /// Path to configuration file
    #[structopt(short, long, default_value = "config/dev.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[structopt(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    // Initialize tracing
    init_logging(opt.verbose);

    info!("Starting NIXI.TEL SBC");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = opt.config.to_str().unwrap().to_string();
    info!("Loading configuration from: {}", config_path);
    let config = SbcConfig::from_file(&config_path)?;
    info!("Configuration loaded: {}", config.general.name);

    // Build integrated SBC from config (wires all modules). The management
    // API (axum) is assembled from the SBC's handles and spawned below.
    let mut sbc = Sbc::new_from_config_without_http(&config).await?;

    if config.management.api_enabled {
        let state = AppState {
            metrics: sbc.metrics().clone(),
            b2bua: sbc.b2bua().clone(),
            trunks: sbc.trunk_manager.clone(),
            registrar: sbc.register_handler().registrar(),
            cdr: sbc.cdr().clone(),
            acl: sbc.acl().clone(),
            auth: sbc.auth(),
            dids: sbc.did_mappings(),
            trunk_ips: sbc.trunk_ips(),
            store: sbc.config_store(),
            events: sbc.events(),
            reload: sbc.reload_notify(),
            realm: config.security.sip_realm.clone(),
            api_token: config.management.api_auth_token.clone(),
            security: sbc.security(),
        };
        if state.store.is_none() {
            warn!("Management API: config store unavailable — mutating endpoints return 503");
        }
        if state.api_token.is_none() {
            warn!("Management API: no api_auth_token configured — API is UNAUTHENTICATED");
        }
        let addr: std::net::SocketAddr = format!(
            "{}:{}",
            config.management.api_bind_address, config.management.api_port
        )
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap());
        let cors = config.management.cors_allowed_origins.clone();
        tokio::spawn(async move {
            if let Err(e) = sbc_management::server::serve(addr, state, cors).await {
                warn!("Management API server failed: {}", e);
            }
        });
    }

    // Store config path for SIGHUP hot-reload
    sbc.set_config_path(config_path);

    // Start transport listeners
    sbc.start(&config.network, None).await?;

    // Start outbound REGISTER loops for trunks that need it
    sbc.start_trunk_registrations();

    // Start trunk health checks (OPTIONS keepalive every 30s)
    sbc.start_trunk_health_checks();

    info!("SBC started successfully");
    info!("Instance ID: {}", config.general.instance_id);
    info!(
        "Digest auth: {}",
        if config.security.enable_digest_auth { "enabled" } else { "disabled" }
    );

    // Run main event loop — blocks until shutdown
    sbc.run().await;

    info!("SBC shutdown complete");
    Ok(())
}

/// Initialize logging based on verbosity
fn init_logging(verbose: bool) {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_ansi(false)
        .init();
}
