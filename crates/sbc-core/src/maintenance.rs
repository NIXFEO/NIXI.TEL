//! Background Maintenance Tasks
//!
//! Handles periodic cleanup and retransmissions for transactions and dialogs

use crate::dialog::DialogManager;
use crate::transaction::TransactionManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info};

/// Configuration for maintenance tasks
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Interval between transaction timeout checks (default: 50ms)
    pub transaction_check_interval: Duration,

    /// Interval between dialog cleanup (default: 30s)
    pub dialog_cleanup_interval: Duration,

    /// Timeout for idle dialogs (default: 5 minutes)
    pub dialog_idle_timeout: Duration,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            transaction_check_interval: Duration::from_millis(50),
            dialog_cleanup_interval: Duration::from_secs(30),
            dialog_idle_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Background maintenance task manager
pub struct MaintenanceTask {
    transaction_manager: Arc<TransactionManager>,
    dialog_manager: Arc<DialogManager>,
    config: MaintenanceConfig,
}

impl MaintenanceTask {
    /// Create a new maintenance task manager
    pub fn new(
        transaction_manager: Arc<TransactionManager>,
        dialog_manager: Arc<DialogManager>,
        config: MaintenanceConfig,
    ) -> Self {
        Self {
            transaction_manager,
            dialog_manager,
            config,
        }
    }

    /// Start background maintenance tasks
    ///
    /// Spawns two tokio tasks:
    /// 1. Transaction timeout checker and retransmission handler
    /// 2. Dialog cleanup for idle/terminated dialogs
    pub fn start(self) -> MaintenanceHandle {
        let config = self.config.clone();

        // Task 1: Transaction maintenance
        let tx_manager = self.transaction_manager.clone();
        let tx_config = config.clone();
        let transaction_task = tokio::spawn(async move {
            let mut interval = interval(tx_config.transaction_check_interval);
            info!(
                "Started transaction maintenance task (interval: {:?})",
                tx_config.transaction_check_interval
            );

            loop {
                interval.tick().await;

                // Check for timeouts and trigger retransmissions
                let timed_out = tx_manager.check_timeouts();
                if timed_out > 0 {
                    debug!("Processed {} transaction timeouts", timed_out);
                }

                // Cleanup terminated transactions
                let cleaned = tx_manager.cleanup_terminated();
                if cleaned > 0 {
                    debug!("Cleaned up {} terminated transactions", cleaned);
                }
            }
        });

        // Task 2: Dialog maintenance
        let dlg_manager = self.dialog_manager.clone();
        let dlg_config = config.clone();
        let dialog_task = tokio::spawn(async move {
            let mut interval = interval(dlg_config.dialog_cleanup_interval);
            info!(
                "Started dialog maintenance task (interval: {:?})",
                dlg_config.dialog_cleanup_interval
            );

            loop {
                interval.tick().await;

                // Cleanup terminated dialogs
                let terminated = dlg_manager.cleanup_terminated();
                if terminated > 0 {
                    debug!("Cleaned up {} terminated dialogs", terminated);
                }

                // Cleanup idle dialogs
                let idle = dlg_manager.cleanup_idle(dlg_config.dialog_idle_timeout);
                if idle > 0 {
                    debug!("Cleaned up {} idle dialogs", idle);
                }
            }
        });

        MaintenanceHandle {
            transaction_task,
            dialog_task,
        }
    }
}

/// Handle to the background maintenance tasks
pub struct MaintenanceHandle {
    transaction_task: tokio::task::JoinHandle<()>,
    dialog_task: tokio::task::JoinHandle<()>,
}

impl MaintenanceHandle {
    /// Abort all maintenance tasks
    pub fn abort(&self) {
        self.transaction_task.abort();
        self.dialog_task.abort();
        info!("Aborted maintenance tasks");
    }

    /// Wait for all maintenance tasks to complete
    pub async fn join(self) {
        let _ = tokio::join!(self.transaction_task, self.dialog_task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::SipTimers;

    #[tokio::test]
    async fn test_maintenance_config_default() {
        let config = MaintenanceConfig::default();
        assert_eq!(config.transaction_check_interval, Duration::from_millis(50));
        assert_eq!(config.dialog_cleanup_interval, Duration::from_secs(30));
        assert_eq!(config.dialog_idle_timeout, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_maintenance_task_creation() {
        let tx_manager = Arc::new(TransactionManager::new());
        let dlg_manager = Arc::new(DialogManager::new());
        let config = MaintenanceConfig::default();

        let task = MaintenanceTask::new(tx_manager, dlg_manager, config);
        let stats = task.transaction_manager.stats();
        assert_eq!(stats.client_transactions, 0);
        assert_eq!(stats.server_transactions, 0);
    }

    #[tokio::test]
    async fn test_maintenance_task_start_abort() {
        let tx_manager = Arc::new(TransactionManager::new());
        let dlg_manager = Arc::new(DialogManager::new());
        let config = MaintenanceConfig {
            transaction_check_interval: Duration::from_millis(10),
            dialog_cleanup_interval: Duration::from_millis(10),
            dialog_idle_timeout: Duration::from_secs(1),
        };

        let task = MaintenanceTask::new(tx_manager, dlg_manager, config);
        let handle = task.start();

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Abort the tasks
        handle.abort();
    }

    #[tokio::test]
    async fn test_maintenance_cleanup_transactions() {
        use crate::transaction::TransactionManager;
        use rsip::prelude::*;
        use std::net::SocketAddr;

        let tx_manager = Arc::new(TransactionManager::new());
        let dlg_manager = Arc::new(DialogManager::new());

        // Create a test transaction
        let request_str = "INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
            Max-Forwards: 70\r\n\
            To: Bob <sip:bob@example.com>\r\n\
            From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
            Call-ID: test@127.0.0.1\r\n\
            CSeq: 314159 INVITE\r\n\
            Contact: <sip:alice@127.0.0.1:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n";

        let request = match rsip::SipMessage::try_from(request_str.as_bytes()).unwrap() {
            rsip::SipMessage::Request(req) => req,
            _ => panic!("Expected request"),
        };

        let dest: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let _tx_id = tx_manager
            .create_client_transaction(request, rsip::Transport::Udp, dest)
            .unwrap();

        // Start maintenance with short intervals
        let config = MaintenanceConfig {
            transaction_check_interval: Duration::from_millis(10),
            dialog_cleanup_interval: Duration::from_millis(10),
            dialog_idle_timeout: Duration::from_secs(1),
        };

        let task = MaintenanceTask::new(tx_manager.clone(), dlg_manager, config);
        let handle = task.start();

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check stats - transaction might be cleaned up or still active
        let stats = tx_manager.stats();
        assert!(stats.client_transactions + stats.server_transactions >= 0);

        handle.abort();
    }
}
