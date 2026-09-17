//! NIXI.TEL SBC - Session Border Controller
//!
//! Main entry point for the SBC application.
//! All message handling is delegated to sbc_core::Sbc.

use anyhow::Result;
use clap::Parser;
use sbc_core::config::SbcConfig;
use sbc_core::Sbc;
use sbc_management::state::AppState;
use std::path::PathBuf;
use tracing::{info, warn};

/// Build identity: crate version + git commit (see build.rs).
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("SBC_GIT_SHA"), ")");

#[derive(Debug, Parser)]
#[command(name = "sbc", about = "NIXI.TEL SBC - Session Border Controller", version = VERSION)]
struct Opt {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/dev.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Initialize tracing
    init_logging(opt.verbose);

    info!("Starting NIXI.TEL SBC");
    info!("Version: {}", VERSION);

    // Load configuration
    let config_path = opt.config.to_str().unwrap().to_string();
    info!("Loading configuration from: {}", config_path);
    let config = SbcConfig::from_file(&config_path)?;
    info!("Configuration loaded: {}", config.general.name);

    // Build integrated SBC from config (wires all modules). The management
    // API (axum) is assembled from the SBC's handles and spawned below.
    let mut sbc = Sbc::new_from_config(&config).await?;

    if config.management.api_enabled {
        // Resolve the management API token (env SBC_API_TOKEN overrides TOML)
        // and FAIL CLOSED if none is configured — never start an
        // unauthenticated management API.
        let api_token = sbc_core::config::resolve_api_token(&config.management.api_auth_token);
        if api_token.is_none() {
            anyhow::bail!(
                "management API is enabled but no API token is configured. Set the \
                 SBC_API_TOKEN environment variable or [management].api_auth_token in \
                 the config file. Refusing to start an unauthenticated management API."
            );
        }
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
            api_token,
            api_rate_limit_per_min: config.management.api_rate_limit_per_min,
            security: sbc.security(),
            kicks: sbc.admin_kicks(),
        };
        if state.store.is_none() {
            warn!("Management API: config store unavailable — mutating endpoints return 503");
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
        if config.security.enable_digest_auth {
            "enabled"
        } else {
            "disabled"
        }
    );

    // Run main event loop — blocks until shutdown
    sbc.run().await;

    info!("SBC shutdown complete");
    Ok(())
}

/// Initialize logging.
///
/// Level precedence: `--verbose` forces DEBUG; otherwise the `RUST_LOG`
/// environment variable is honored (e.g. `RUST_LOG=debug`, or targeted
/// `RUST_LOG=sbc_core=debug,info`); if unset, defaults to INFO. This makes
/// the log level adjustable via the systemd unit's `Environment=RUST_LOG=…`
/// without editing the binary invocation.
fn init_logging(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_ansi(false)
        .init();
}
