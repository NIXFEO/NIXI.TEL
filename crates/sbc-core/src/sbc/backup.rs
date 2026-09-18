//! Store backups: the shared runner behind `POST /api/v1/backup` and the
//! periodic timer. A backup is a `VACUUM INTO` copy written by
//! `ConfigStore::backup_to` (consistent snapshot, the live store keeps
//! serving), followed by a prune to `keep` copies. One `Mutex<()>` makes
//! the API and the timer take turns.
use crate::events::{event_ts, EventBus, SbcEvent};
use crate::metrics::SbcMetrics;
use sbc_storage::{BackupInfo, ConfigStore};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// `[database]` backup settings, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPolicy {
    pub dir: PathBuf,
    /// None: the timer is off (manual backups still work).
    pub interval: Option<Duration>,
    /// 0: never prune.
    pub keep: usize,
}

#[derive(Debug)]
pub enum BackupError {
    /// Another backup (API or timer) is running.
    Busy,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct BackupReport {
    pub info: BackupInfo,
    pub pruned: Vec<PathBuf>,
}

/// One backup + prune, with metrics, log and event.
pub async fn run_backup(
    store: &ConfigStore,
    policy: &BackupPolicy,
    metrics: &SbcMetrics,
    events: &EventBus,
    lock: &Mutex<()>,
) -> Result<BackupReport, BackupError> {
    let Ok(_guard) = lock.try_lock() else {
        return Err(BackupError::Busy);
    };
    match store.backup_to(&policy.dir).await {
        Ok(info) => {
            metrics.record_store_backup(info.bytes);
            let pruned = match sbc_storage::prune_backups(&policy.dir, policy.keep).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("Store backup: prune failed: {}", e);
                    Vec::new()
                }
            };
            info!(
                "Store backup written: {} ({} bytes, {} ms, {} pruned)",
                info.path.display(),
                info.bytes,
                info.took_ms,
                pruned.len()
            );
            Ok(BackupReport { info, pruned })
        }
        Err(e) => {
            metrics.inc_store_backup_failure();
            warn!("Store backup failed: {}", e);
            events.publish(SbcEvent::Alert {
                level: "warning".into(),
                kind: "backup_failed".into(),
                detail: e.to_string(),
                ts: event_ts(),
            });
            Err(BackupError::Failed(e.to_string()))
        }
    }
}

/// Delay before the next timer run: the remainder of `interval` since the
/// newest backup, at least a minute after boot; a minute when none exists
/// or the newest is older than the interval.
pub fn next_run_after(newest: Option<SystemTime>, now: SystemTime, interval: Duration) -> Duration {
    let floor = Duration::from_secs(60);
    match newest {
        Some(t) => {
            let age = now.duration_since(t).unwrap_or(Duration::ZERO);
            interval.saturating_sub(age).max(floor)
        }
        None => floor,
    }
}

/// The periodic backup task; None when the policy has no interval.
pub fn spawn_backup_timer(
    store: Arc<ConfigStore>,
    policy: Arc<BackupPolicy>,
    metrics: Arc<SbcMetrics>,
    events: EventBus,
    lock: Arc<Mutex<()>>,
) -> Option<JoinHandle<()>> {
    metrics.set_store_backups(policy.interval);
    // Seed the last-success gauge from what is on disk before deciding
    // whether to run a timer: with `backup_interval_hours = 0` the
    // dashboard would otherwise read "never" after every restart even
    // though `POST /api/v1/backup` copies exist.
    let newest = sbc_storage::newest_backup(&policy.dir);
    if let Some((path, mtime)) = &newest {
        let secs = mtime
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        metrics.record_store_backup_at(secs, bytes);
    }
    let Some(interval) = policy.interval else {
        info!("Store backups: timer disabled (backup_interval_hours = 0)");
        return None;
    };
    let mut delay = next_run_after(newest.map(|(_, t)| t), SystemTime::now(), interval);
    info!(
        "Store backups: every {} h into {} (keep {}), first in {} s",
        interval.as_secs() / 3600,
        policy.dir.display(),
        policy.keep,
        delay.as_secs()
    );
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            let _ = run_backup(&store, &policy, &metrics, &events, &lock).await;
            delay = interval;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_run_waits_for_the_remaining_interval() {
        let now = SystemTime::now();
        let day = Duration::from_secs(86400);
        let d = next_run_after(Some(now - Duration::from_secs(3600)), now, day);
        assert!(
            d > Duration::from_secs(82000) && d <= Duration::from_secs(82800),
            "{:?}",
            d
        );
    }

    #[test]
    fn next_run_is_soon_when_stale_or_missing() {
        let now = SystemTime::now();
        let day = Duration::from_secs(86400);
        assert_eq!(next_run_after(None, now, day), Duration::from_secs(60));
        assert_eq!(
            next_run_after(Some(now - Duration::from_secs(3 * 86400)), now, day),
            Duration::from_secs(60)
        );
    }

    #[tokio::test]
    async fn run_backup_writes_prunes_and_refuses_concurrency() {
        let dir = std::env::temp_dir().join(format!("sbc-backup-{}", uuid::Uuid::new_v4()));
        let store = ConfigStore::open(dir.join("live.db").to_str().unwrap())
            .await
            .unwrap();
        let policy = BackupPolicy {
            dir: dir.join("backups"),
            interval: None,
            keep: 1,
        };
        let metrics = SbcMetrics::new();
        let events = EventBus::new();
        let lock = Mutex::new(());
        let first = run_backup(&store, &policy, &metrics, &events, &lock)
            .await
            .unwrap();
        assert!(first.pruned.is_empty());
        let second = run_backup(&store, &policy, &metrics, &events, &lock)
            .await
            .unwrap();
        assert_eq!(second.pruned, vec![first.info.path.clone()], "keep 1");
        assert!(
            metrics
                .store_backup_last_success_time
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
        let held = lock.lock().await;
        assert!(matches!(
            run_backup(&store, &policy, &metrics, &events, &lock).await,
            Err(BackupError::Busy)
        ));
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
