//! Dialog Manager
//!
//! Manages multiple active dialogs

use crate::dialog::dialog::{Dialog, DialogId, DialogState};
use crate::{Error, Result};
use dashmap::DashMap;
use rsip::{Request, Response};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Dialog Manager
pub struct DialogManager {
    /// Active dialogs (keyed by DialogId)
    dialogs: Arc<DashMap<DialogId, Dialog>>,
}

impl DialogManager {
    /// Create a new dialog manager
    pub fn new() -> Self {
        Self {
            dialogs: Arc::new(DashMap::new()),
        }
    }

    /// Create a new dialog from INVITE/200 OK (UAC side)
    pub fn create_dialog_uac(
        &self,
        request: &Request,
        response: &Response,
        initial_seq: u32,
    ) -> Result<DialogId> {
        let dialog = Dialog::new_uac(request, response, initial_seq)?;
        let id = dialog.id.clone();

        self.dialogs.insert(id.clone(), dialog);
        info!("Created UAC dialog: {}", id.as_string());

        Ok(id)
    }

    /// Create a new dialog from INVITE/200 OK (UAS side)
    pub fn create_dialog_uas(&self, request: &Request, response: &Response) -> Result<DialogId> {
        let dialog = Dialog::new_uas(request, response)?;
        let id = dialog.id.clone();

        self.dialogs.insert(id.clone(), dialog);
        info!("Created UAS dialog: {}", id.as_string());

        Ok(id)
    }

    /// Get a dialog by ID
    pub fn get_dialog(&self, id: &DialogId) -> Option<Dialog> {
        self.dialogs.get(id).map(|entry| entry.value().clone())
    }

    /// Update dialog state
    pub fn set_dialog_state(&self, id: &DialogId, state: DialogState) -> Result<()> {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            entry.set_state(state);
            debug!("Dialog {} state updated to {:?}", id.as_string(), state);
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Dialog not found: {}",
                id.as_string()
            )))
        }
    }

    /// Increment local sequence number
    pub fn increment_local_seq(&self, id: &DialogId) -> Result<u32> {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            let seq = entry.increment_local_seq();
            debug!(
                "Dialog {} local CSeq incremented to {}",
                id.as_string(),
                seq
            );
            Ok(seq)
        } else {
            Err(Error::Dialog(format!(
                "Dialog not found: {}",
                id.as_string()
            )))
        }
    }

    /// Update remote sequence number
    pub fn update_remote_seq(&self, id: &DialogId, seq: u32) -> Result<()> {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            entry.update_remote_seq(seq)?;
            debug!(
                "Dialog {} remote CSeq updated to {}",
                id.as_string(),
                seq
            );
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Dialog not found: {}",
                id.as_string()
            )))
        }
    }

    /// Terminate a dialog
    pub fn terminate_dialog(&self, id: &DialogId) -> Result<()> {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            entry.set_state(DialogState::Terminated);
            info!("Dialog {} terminated", id.as_string());
            Ok(())
        } else {
            Err(Error::Dialog(format!(
                "Dialog not found: {}",
                id.as_string()
            )))
        }
    }

    /// Remove a dialog
    pub fn remove_dialog(&self, id: &DialogId) -> Option<Dialog> {
        if let Some((_, dialog)) = self.dialogs.remove(id) {
            info!("Removed dialog: {}", id.as_string());
            Some(dialog)
        } else {
            None
        }
    }

    /// Cleanup terminated dialogs
    pub fn cleanup_terminated(&self) -> usize {
        let mut cleaned = 0;

        self.dialogs.retain(|id, dialog| {
            if dialog.is_terminated() {
                info!("Cleaning up terminated dialog: {}", id.as_string());
                cleaned += 1;
                false
            } else {
                true
            }
        });

        if cleaned > 0 {
            debug!("Cleaned up {} terminated dialogs", cleaned);
        }

        cleaned
    }

    /// Cleanup idle dialogs (older than timeout)
    pub fn cleanup_idle(&self, idle_timeout: std::time::Duration) -> usize {
        let mut cleaned = 0;

        self.dialogs.retain(|id, dialog| {
            if dialog.idle_time() > idle_timeout {
                warn!(
                    "Cleaning up idle dialog: {} (idle for {:?})",
                    id.as_string(),
                    dialog.idle_time()
                );
                cleaned += 1;
                false
            } else {
                true
            }
        });

        if cleaned > 0 {
            debug!("Cleaned up {} idle dialogs", cleaned);
        }

        cleaned
    }

    /// Get statistics
    pub fn stats(&self) -> DialogStats {
        let total = self.dialogs.len();
        let mut early = 0;
        let mut confirmed = 0;
        let mut terminated = 0;

        for entry in self.dialogs.iter() {
            match entry.state {
                DialogState::Early => early += 1,
                DialogState::Confirmed => confirmed += 1,
                DialogState::Terminated => terminated += 1,
            }
        }

        DialogStats {
            total,
            early,
            confirmed,
            terminated,
        }
    }

    /// Check if dialog exists
    pub fn has_dialog(&self, id: &DialogId) -> bool {
        self.dialogs.contains_key(id)
    }

    /// Get all dialog IDs
    pub fn get_all_dialog_ids(&self) -> Vec<DialogId> {
        self.dialogs.iter().map(|entry| entry.key().clone()).collect()
    }
}

impl Default for DialogManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Dialog statistics
#[derive(Debug, Clone)]
pub struct DialogStats {
    pub total: usize,
    pub early: usize,
    pub confirmed: usize,
    pub terminated: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::prelude::*;

    fn create_test_invite() -> Request {
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

        match rsip::SipMessage::try_from(request_str.as_bytes()).unwrap() {
            rsip::SipMessage::Request(req) => req,
            _ => panic!("Expected request"),
        }
    }

    fn create_test_200ok(to_tag: &str) -> Response {
        let response_str = format!(
            "SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n\
            To: Bob <sip:bob@example.com>;tag={}\r\n\
            From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
            Call-ID: test@127.0.0.1\r\n\
            CSeq: 314159 INVITE\r\n\
            Contact: <sip:bob@192.168.1.1:5060>\r\n\
            Content-Length: 0\r\n\
            \r\n",
            to_tag
        );

        match rsip::SipMessage::try_from(response_str.as_bytes()).unwrap() {
            rsip::SipMessage::Response(resp) => resp,
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn test_dialog_manager_creation() {
        let manager = DialogManager::new();
        let stats = manager.stats();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.confirmed, 0);
    }

    #[test]
    fn test_create_uac_dialog() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let result = manager.create_dialog_uac(&invite, &response, 1);
        assert!(result.is_ok());

        let stats = manager.stats();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.confirmed, 1);
    }

    #[test]
    fn test_create_uas_dialog() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let result = manager.create_dialog_uas(&invite, &response);
        assert!(result.is_ok());

        let stats = manager.stats();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.confirmed, 1);
    }

    #[test]
    fn test_terminate_dialog() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let dialog_id = manager.create_dialog_uac(&invite, &response, 1).unwrap();
        assert!(manager.has_dialog(&dialog_id));

        let result = manager.terminate_dialog(&dialog_id);
        assert!(result.is_ok());

        let dialog = manager.get_dialog(&dialog_id).unwrap();
        assert!(dialog.is_terminated());
    }

    #[test]
    fn test_cleanup_terminated() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let dialog_id = manager.create_dialog_uac(&invite, &response, 1).unwrap();
        manager.terminate_dialog(&dialog_id).unwrap();

        let cleaned = manager.cleanup_terminated();
        assert_eq!(cleaned, 1);

        let stats = manager.stats();
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn test_increment_local_seq() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let dialog_id = manager.create_dialog_uac(&invite, &response, 1).unwrap();

        let seq = manager.increment_local_seq(&dialog_id).unwrap();
        assert_eq!(seq, 2);

        let seq = manager.increment_local_seq(&dialog_id).unwrap();
        assert_eq!(seq, 3);
    }

    #[test]
    fn test_update_remote_seq() {
        let manager = DialogManager::new();
        let invite = create_test_invite();
        let response = create_test_200ok("987654321");

        let dialog_id = manager.create_dialog_uas(&invite, &response).unwrap();

        // Initial remote_seq is 314159 from the INVITE CSeq
        // So we need to use higher values
        let result = manager.update_remote_seq(&dialog_id, 314160);
        assert!(result.is_ok());

        let result = manager.update_remote_seq(&dialog_id, 314161);
        assert!(result.is_ok());

        // Out of order should fail
        let result = manager.update_remote_seq(&dialog_id, 314150);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_dialogs() {
        let manager = DialogManager::new();

        // Create multiple dialogs with different Call-IDs
        for i in 0..5 {
            let request_str = format!(
                "INVITE sip:bob@example.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{}\r\n\
                Max-Forwards: 70\r\n\
                To: Bob <sip:bob@example.com>\r\n\
                From: Alice <sip:alice@example.com>;tag=tag{}\r\n\
                Call-ID: call{}@127.0.0.1\r\n\
                CSeq: 1 INVITE\r\n\
                Contact: <sip:alice@127.0.0.1:5060>\r\n\
                Content-Length: 0\r\n\
                \r\n",
                i, i, i
            );

            let response_str = format!(
                "SIP/2.0 200 OK\r\n\
                Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{}\r\n\
                To: Bob <sip:bob@example.com>;tag=totag{}\r\n\
                From: Alice <sip:alice@example.com>;tag=tag{}\r\n\
                Call-ID: call{}@127.0.0.1\r\n\
                CSeq: 1 INVITE\r\n\
                Contact: <sip:bob@192.168.1.1:5060>\r\n\
                Content-Length: 0\r\n\
                \r\n",
                i, i, i, i
            );

            let invite = match rsip::SipMessage::try_from(request_str.as_bytes()).unwrap() {
                rsip::SipMessage::Request(req) => req,
                _ => panic!("Expected request"),
            };

            let response = match rsip::SipMessage::try_from(response_str.as_bytes()).unwrap() {
                rsip::SipMessage::Response(resp) => resp,
                _ => panic!("Expected response"),
            };

            manager.create_dialog_uac(&invite, &response, 1).unwrap();
        }

        let stats = manager.stats();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.confirmed, 5);

        let ids = manager.get_all_dialog_ids();
        assert_eq!(ids.len(), 5);
    }
}
