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

    // Load configuration first: [logging] decides the subscriber. A parse
    // error is reported by anyhow on stderr.
    let config_path = opt.config.to_str().unwrap().to_string();
    let config = SbcConfig::from_file(&config_path)?;

    // The guard flushes the non-blocking writer when main returns.
    let (_log_guard, dropped_lines) = init_logging(&config.logging, opt.verbose)?;

    info!("Starting NIXI.TEL SBC");
    info!("Version: {}", VERSION);
    info!(
        "Configuration loaded from {}: {}",
        config_path, config.general.name
    );

    // Build integrated SBC from config (wires all modules). The management
    // API (axum) is assembled from the SBC's handles and spawned below.
    let mut sbc = Sbc::new_from_config(&config).await?;

    // Dropped log lines → sbc_log_dropped_lines_total (sampled each minute).
    {
        let metrics = sbc.metrics().clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                metrics.set_log_dropped_lines(dropped_lines.dropped_lines() as u64);
            }
        });
    }

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
            trunk_tasks: sbc.trunk_tasks(),
            ready: sbc.readiness(),
            backup: sbc.backup_policy(),
            backup_lock: sbc.backup_lock(),
            trusted_proxies: std::sync::Arc::new(config.management.trusted_proxies.clone()),
            ban_on_auth_failure: config.management.ban_on_auth_failure,
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

    // OPTIONS health checks + outbound REGISTER loops per enabled trunk;
    // they follow the trunk table from here on (API writes, reload).
    sbc.start_trunk_tasks();

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
    // The SIP loop is gone: stop the trunk tasks (fire-and-forget
    // un-REGISTERs, bounded wait).
    sbc.trunk_tasks().shutdown().await;

    info!("SBC shutdown complete");
    Ok(())
}

/// Initialize logging.
///
/// Level precedence: `--verbose` forces DEBUG; otherwise `RUST_LOG` (e.g.
/// `debug`, or targeted `sbc_core=debug,info`, set from the systemd unit's
/// `EnvironmentFile`); otherwise `[logging] level`. `[logging] format`
/// picks text (journald/terminal) or JSON (one object per line, the call
/// span in `span`). The writer is non-blocking and lossy: journald
/// back-pressure drops lines (counted) instead of stalling the SIP loop.
fn init_logging(
    cfg: &sbc_core::config::LoggingConfig,
    verbose: bool,
) -> Result<(
    tracing_appender::non_blocking::WorkerGuard,
    tracing_appender::non_blocking::ErrorCounter,
)> {
    use tracing_subscriber::prelude::*;
    let filter = logging::resolve_filter(verbose, std::env::var("RUST_LOG").ok(), &cfg.level)?;
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let counter = writer.error_counter();
    tracing_subscriber::registry()
        .with(filter)
        .with(logging::build_layer(cfg.format, writer))
        .try_init()
        .map_err(|e| anyhow::anyhow!("logging init: {}", e))?;
    Ok((guard, counter))
}

mod logging {
    use anyhow::Result;
    use sbc_core::config::LogFormat;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::{EnvFilter, Layer};

    /// `--verbose` > `RUST_LOG` (non-empty) > `[logging] level`.
    pub fn resolve_filter(
        verbose: bool,
        env: Option<String>,
        cfg_level: &str,
    ) -> Result<EnvFilter> {
        let directive = if verbose {
            "debug".to_string()
        } else {
            match env {
                Some(e) if !e.trim().is_empty() => e,
                _ => cfg_level.to_string(),
            }
        };
        EnvFilter::try_new(&directive).map_err(|e| {
            anyhow::anyhow!(
                "invalid log filter '{}' ([logging].level / RUST_LOG): {}",
                directive,
                e
            )
        })
    }

    /// The formatting layer for `format`, writing to `writer`.
    pub fn build_layer<S, W>(format: LogFormat, writer: W) -> Box<dyn Layer<S> + Send + Sync>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        match format {
            LogFormat::Json => tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_target(true)
                .with_current_span(true)
                .with_span_list(false)
                .flatten_event(true)
                .with_ansi(false)
                .boxed(),
            LogFormat::Text => tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_ansi(false)
                .boxed(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        struct BufGuard(Arc<Mutex<Vec<u8>>>);
        impl Write for BufGuard {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buf {
            type Writer = BufGuard;
            fn make_writer(&'a self) -> BufGuard {
                BufGuard(self.0.clone())
            }
        }
        impl Buf {
            fn lines(&self) -> Vec<String> {
                String::from_utf8(self.0.lock().unwrap().clone())
                    .unwrap()
                    .lines()
                    .map(String::from)
                    .collect()
            }
        }

        fn emit(buf: Buf, format: LogFormat) {
            let sub = tracing_subscriber::registry()
                .with(EnvFilter::new("trace"))
                .with(build_layer(format, buf));
            tracing::subscriber::with_default(sub, || {
                let span = tracing::info_span!(
                    "call",
                    uuid = "u1",
                    call_id = "c1",
                    trunk = tracing::field::Empty,
                    direction = "outbound"
                );
                let _e = span.enter();
                span.record("trunk", "t1");
                tracing::info!("hello");
                tracing::warn!(target: "security", "ban");
            });
        }

        #[test]
        fn resolve_filter_precedence() {
            assert_eq!(
                resolve_filter(true, Some("warn".into()), "info")
                    .unwrap()
                    .to_string(),
                "debug"
            );
            assert_eq!(
                resolve_filter(false, Some("warn".into()), "info")
                    .unwrap()
                    .to_string(),
                "warn"
            );
            assert_eq!(
                resolve_filter(false, Some("  ".into()), "sbc_core=debug,info")
                    .unwrap()
                    .to_string(),
                "sbc_core=debug,info"
            );
            let err = resolve_filter(false, None, "info=notalevel")
                .unwrap_err()
                .to_string();
            assert!(err.contains("info=notalevel"), "{}", err);
        }

        #[test]
        fn json_layer_emits_one_object_per_line_with_span_fields() {
            let buf = Buf::default();
            emit(buf.clone(), LogFormat::Json);
            let lines = buf.lines();
            assert_eq!(lines.len(), 2, "{:?}", lines);
            let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(first["level"], "INFO");
            assert_eq!(first["message"], "hello");
            assert_eq!(first["span"]["name"], "call");
            assert_eq!(first["span"]["uuid"], "u1");
            assert_eq!(first["span"]["call_id"], "c1");
            assert_eq!(first["span"]["trunk"], "t1", "recorded after creation");
            assert_eq!(first["span"]["direction"], "outbound");
            let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
            assert_eq!(second["level"], "WARN");
            assert_eq!(second["target"], "security");
        }

        #[test]
        fn text_layer_prefixes_span_context_without_ansi() {
            let buf = Buf::default();
            emit(buf.clone(), LogFormat::Text);
            let lines = buf.lines();
            assert_eq!(lines.len(), 2, "{:?}", lines);
            assert!(
                lines[0].contains("call{uuid=\"u1\" call_id=\"c1\""),
                "{}",
                lines[0]
            );
            assert!(lines[0].contains("trunk=\"t1\""), "{}", lines[0]);
            assert!(lines[0].ends_with("hello"), "{}", lines[0]);
            assert!(!lines[0].contains('\u{1b}'), "no ANSI");
        }
    }
}
