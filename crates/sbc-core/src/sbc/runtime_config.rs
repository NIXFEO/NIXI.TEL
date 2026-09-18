//! The running configuration and the outcome of reloads, shared with the
//! management API (`GET /api/v1/config`, `POST /api/v1/reload`).
//!
//! `effective` is what runs: on a successful reload the reload-class keys
//! of the loaded file are overlaid on it while restart-class keys keep
//! their boot value (`config_diff(effective, last_loaded)` names them).
use crate::config::{overlay_reload_keys, SbcConfig};
use serde::Serialize;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReloadSource {
    Boot,
    Sighup,
    Api,
}

/// What one reload did.
#[derive(Debug, Clone, Serialize)]
pub struct ReloadReport {
    pub ts: u64,
    pub source: ReloadSource,
    pub ok: bool,
    pub error: Option<String>,
    /// Reload-class keys whose effective value changed.
    pub applied: Vec<String>,
    /// Restart-class keys the loaded file changed but that cannot apply.
    pub restart_required: Vec<String>,
    /// The store was re-hydrated (false on a TOML-only box).
    pub hydrated: bool,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub boot: SbcConfig,
    pub effective: SbcConfig,
    pub last_loaded: SbcConfig,
    pub path: Option<String>,
    pub loaded_at: u64,
    pub source: ReloadSource,
    pub last_reload: Option<ReloadReport>,
}

pub struct RuntimeConfig {
    snapshot: RwLock<Snapshot>,
    generation: tokio::sync::watch::Sender<u64>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl RuntimeConfig {
    pub fn new(boot: SbcConfig, path: Option<String>) -> Self {
        Self {
            snapshot: RwLock::new(Snapshot {
                effective: boot.clone(),
                last_loaded: boot.clone(),
                boot,
                path,
                loaded_at: now(),
                source: ReloadSource::Boot,
                last_reload: None,
            }),
            generation: tokio::sync::watch::channel(0).0,
        }
    }

    pub fn set_path(&self, path: impl Into<String>) {
        self.snapshot.write().unwrap().path = Some(path.into());
    }

    pub fn config_path(&self) -> Option<String> {
        self.snapshot.read().unwrap().path.clone()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.read().unwrap().clone()
    }

    pub fn effective(&self) -> SbcConfig {
        self.snapshot.read().unwrap().effective.clone()
    }

    pub fn boot(&self) -> SbcConfig {
        self.snapshot.read().unwrap().boot.clone()
    }

    pub fn last_reload(&self) -> Option<ReloadReport> {
        self.snapshot.read().unwrap().last_reload.clone()
    }

    /// Record a reload: on success the loaded file becomes `last_loaded`
    /// and its reload-class keys the new `effective`. Always bumps the
    /// generation so `POST /api/v1/reload` can wait for the outcome.
    pub fn record_reload(&self, report: ReloadReport, loaded: Option<SbcConfig>) {
        {
            let mut s = self.snapshot.write().unwrap();
            if report.ok {
                if let Some(new) = loaded {
                    s.effective = overlay_reload_keys(&s.effective, &new);
                    s.last_loaded = new;
                    s.loaded_at = report.ts;
                    s.source = report.source;
                }
            }
            s.last_reload = Some(report);
        }
        self.generation.send_modify(|g| *g += 1);
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.generation.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_reload_updates_effective_and_bumps_generation() {
        let rc = RuntimeConfig::new(SbcConfig::default(), None);
        let mut rx = rc.subscribe();
        assert_eq!(*rx.borrow_and_update(), 0);
        let mut loaded = SbcConfig::default();
        loaded.security.rtp_timeout = 45;
        loaded.management.api_port = 1;
        rc.record_reload(
            ReloadReport {
                ts: 10,
                source: ReloadSource::Api,
                ok: true,
                error: None,
                applied: vec!["security.rtp_timeout".into()],
                restart_required: vec!["management.api_port".into()],
                hydrated: true,
            },
            Some(loaded),
        );
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), 1);
        let s = rc.snapshot();
        assert_eq!(s.effective.security.rtp_timeout, 45);
        assert_eq!(
            s.effective.management.api_port,
            SbcConfig::default().management.api_port,
            "restart keys keep the boot value"
        );
        assert_eq!(s.last_loaded.management.api_port, 1);
        assert_eq!(s.source, ReloadSource::Api);
        assert_eq!(s.loaded_at, 10);

        rc.record_reload(
            ReloadReport {
                ts: 11,
                source: ReloadSource::Sighup,
                ok: false,
                error: Some("parse".into()),
                applied: vec![],
                restart_required: vec![],
                hydrated: false,
            },
            None,
        );
        assert_eq!(*rx.borrow_and_update(), 2);
        let s = rc.snapshot();
        assert_eq!(s.effective.security.rtp_timeout, 45, "unchanged on failure");
        assert_eq!(s.source, ReloadSource::Api);
        assert_eq!(s.last_reload.unwrap().error.as_deref(), Some("parse"));
    }
}
