//! NIXI.TEL SBC - Session Border Controller
//!
//! Main entry point for the SBC application.
//! All message handling is delegated to sbc_core::Sbc.

use anyhow::Result;
use sbc_core::config::SbcConfig;
use sbc_core::Sbc;
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::info;

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

    // Build integrated SBC from config (wires all modules)
    let mut sbc = Sbc::new_from_config(&config).await?;

    // Store config path for SIGHUP hot-reload
    sbc.set_config_path(config_path);

    // Start transport listeners
    sbc.start(&config.network, None).await?;

    // Start outbound REGISTER loops for trunks that need it
    sbc.start_trunk_registrations();

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

