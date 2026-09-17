//! Background maintenance: a periodic sweep of the in-memory tables that
//! otherwise grow with lifetime traffic — per-IP DoS state, digest nonces,
//! expired registrations, fail2ban strike windows and per-user rate
//! windows. A spoofed-source UDP scan must never turn into unbounded
//! memory on a 2 GB box, and the gauges it exports make growth visible in
//! Grafana long before it is fatal.

use crate::auth::DigestAuthenticator;
use crate::dos::DosProtector;
use crate::metrics::SbcMetrics;
use crate::register::Registrar;
use crate::security::SecurityManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info};

/// Configuration for the maintenance sweeper
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Interval between sweeps (default: 60 s)
    pub sweep_interval: Duration,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self { sweep_interval: Duration::from_secs(60) }
    }
}

/// What one sweep removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    pub dos_entries: usize,
    pub nonces: usize,
    pub registrations: usize,
    pub bans: usize,
    pub ban_windows: usize,
    pub rate_windows: usize,
}

impl SweepReport {
    pub fn total(&self) -> usize {
        self.dos_entries + self.nonces + self.registrations + self.bans + self.ban_windows + self.rate_windows
    }
}

/// Background maintenance sweeper
pub struct MaintenanceTask {
    dos: Arc<DosProtector>,
    auth: Option<Arc<DigestAuthenticator>>,
    registrar: Arc<dyn Registrar>,
    security: Arc<SecurityManager>,
    metrics: Arc<SbcMetrics>,
    config: MaintenanceConfig,
}

impl MaintenanceTask {
    pub fn new(
        dos: Arc<DosProtector>,
        auth: Option<Arc<DigestAuthenticator>>,
        registrar: Arc<dyn Registrar>,
        security: Arc<SecurityManager>,
        metrics: Arc<SbcMetrics>,
        config: MaintenanceConfig,
    ) -> Self {
        Self { dos, auth, registrar, security, metrics, config }
    }

    /// Spawn the sweeper task.
    pub fn start(self) -> MaintenanceHandle {
        let task = tokio::spawn(async move {
            let mut ticker = interval(self.config.sweep_interval);
            ticker.tick().await; // consume the immediate first tick
            info!("Started maintenance sweeper (interval: {:?})", self.config.sweep_interval);
            loop {
                ticker.tick().await;
                self.sweep().await;
            }
        });
        MaintenanceHandle { task }
    }

    /// One sweep: prune every table, then refresh the size gauges.
    /// Public so tests can drive it without waiting for the interval.
    pub async fn sweep(&self) -> SweepReport {
        let report = SweepReport {
            dos_entries: self.dos.cleanup_expired().await,
            nonces: match &self.auth {
                Some(auth) => auth.cleanup_nonces().await,
                None => 0,
            },
            registrations: self.registrar.cleanup_expired().await.unwrap_or(0) as usize,
            bans: self.security.bans.cleanup_expired(),
            ban_windows: self.security.bans.prune_stale_windows(),
            rate_windows: self.security.user_limits.prune_idle_windows(),
        };

        self.metrics.set_dos_tracked_ips(self.dos.tracked_ips().await as u64);
        let nonces = match &self.auth {
            Some(auth) => auth.active_nonces().await as u64,
            None => 0,
        };
        self.metrics.set_auth_nonces(nonces);
        // count() runs after cleanup_expired, so expired bindings no longer inflate it
        self.metrics.set_active_registrations(self.registrar.count().await);

        if report.total() > 0 {
            debug!("Maintenance sweep: {:?}", report);
        }
        report
    }
}

/// Handle to the background sweeper
pub struct MaintenanceHandle {
    task: tokio::task::JoinHandle<()>,
}

impl MaintenanceHandle {
    /// Abort the sweeper
    pub fn abort(&self) {
        self.task.abort();
        info!("Aborted maintenance sweeper");
    }

    /// Wait for the sweeper to finish (it only does on abort)
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dos::RateLimitConfig;
    use crate::register::InMemoryRegistrar;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn task(auth: Option<Arc<DigestAuthenticator>>) -> MaintenanceTask {
        MaintenanceTask::new(
            Arc::new(DosProtector::new(RateLimitConfig::default())),
            auth,
            Arc::new(InMemoryRegistrar::new()),
            Arc::new(SecurityManager::new(Default::default())),
            Arc::new(SbcMetrics::new()),
            MaintenanceConfig::default(),
        )
    }

    #[tokio::test]
    async fn sweep_on_empty_tables_removes_nothing_and_zeroes_gauges() {
        let t = task(None);
        let report = t.sweep().await;
        assert_eq!(report, SweepReport::default());
        assert_eq!(t.metrics.dos_tracked_ips.load(Ordering::Relaxed), 0);
        assert_eq!(t.metrics.auth_nonces.load(Ordering::Relaxed), 0);
        assert_eq!(t.metrics.active_registrations.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn sweep_refreshes_gauges_from_live_tables() {
        let auth = Arc::new(DigestAuthenticator::new("sip.example.com", HashMap::new()));
        let t = task(Some(auth.clone()));
        for _ in 0..3 {
            let _ = auth.generate_challenge().await;
        }
        for ip in ["203.0.113.5:5060", "203.0.113.6:5060"] {
            let _ = t.dos.check_addr(ip.parse().unwrap()).await;
        }
        let report = t.sweep().await;
        assert_eq!(report.nonces, 0, "fresh nonces are kept");
        assert_eq!(t.metrics.auth_nonces.load(Ordering::Relaxed), 3);
        assert_eq!(t.metrics.dos_tracked_ips.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn sweeper_task_starts_and_aborts() {
        let handle = task(None).start();
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.abort();
        handle.join().await;
    }
}
