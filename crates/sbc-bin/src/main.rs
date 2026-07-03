//! NIXI.TEL SBC - Session Border Controller
//!
//! Main entry point for the SBC application.
//! All message handling is delegated to sbc_core::Sbc.

use anyhow::Result;
use sbc_core::api::ManagementHandler;
use sbc_core::config::SbcConfig;
use sbc_core::Sbc;
use sbc_management::api::ManagementRouter;
use std::path::PathBuf;
use std::sync::Arc;
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

    // Build Phase 5 management handler (Postgres-backed users/DIDs/reload).
    // Legacy path — only active when postgres_url is configured; the SQLite
    // store (config.database.sqlite_path) is becoming the source of truth.
    let management: Option<Arc<dyn ManagementHandler>> = match (
        config.management.api_enabled,
        config.database.postgres_url.as_deref(),
    ) {
        (true, Some(postgres_url)) => {
            match ManagementRouter::new(postgres_url, config.security.sip_realm.clone()).await {
                Ok(router) => {
                    router.ensure_schema().await;
                    info!(
                        "Management API: users/DID endpoints active (realm={})",
                        config.security.sip_realm
                    );
                    Some(Arc::new(router))
                }
                Err(e) => {
                    warn!(
                        "Management API: Postgres unavailable ({}) — \
                         /api/v1/users and /api/v1/dids will return 500",
                        e
                    );
                    None
                }
            }
        }
        _ => None,
    };

    // Build integrated SBC from config (wires all modules), including the
    // management handler so it is registered with the HTTP server before start.
    let mut sbc = Sbc::new_from_config_with_management(&config, management).await?;

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
