//! Transaction Manager (RFC 3261 Section 17)
//!
//! Manages all client and server transactions

use crate::transaction::state_machine::{
    ClientTransaction, ServerTransaction,
    TransactionId,
};
use crate::transaction::timers::SipTimers;
use crate::{Error, Result};
use dashmap::DashMap;
use rsip::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Transaction Manager
pub struct TransactionManager {
    /// Active client transactions
    client_transactions: Arc<DashMap<TransactionId, ClientTransaction>>,

    /// Active server transactions
    server_transactions: Arc<DashMap<TransactionId, ServerTransaction>>,

    /// SIP timers configuration
    #[allow(dead_code)]
    timers: SipTimers,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new() -> Self {
        Self {
            client_transactions: Arc::new(DashMap::new()),
            server_transactions: Arc::new(DashMap::new()),
            timers: SipTimers::new(),
        }
    }

    /// Create a new client transaction
    pub fn create_client_transaction(
        &self,
        request: Request,
        transport: rsip::Transport,
        dest: SocketAddr,
    ) -> Result<TransactionId> {
        let id = TransactionId::from_request(&request)?;

        let mut transaction = ClientTransaction::new(id.clone(), request, transport, dest);
        transaction.start()?;

        self.client_transactions.insert(id.clone(), transaction);

        info!("Created client transaction: {}", id.as_str());
        Ok(id)
    }

    /// Create a new server transaction
    pub fn create_server_transaction(
        &self,
        request: Request,
        transport: rsip::Transport,
        source: SocketAddr,
    ) -> Result<TransactionId> {
        let id = TransactionId::from_request(&request)?;

        let transaction = ServerTransaction::new(id.clone(), request, transport, source);

        self.server_transactions.insert(id.clone(), transaction);

        info!("Created server transaction: {}", id.as_str());
        Ok(id)
    }

    /// Handle response for client transaction
    pub fn handle_client_response(
        &self,
        transaction_id: &TransactionId,
        response: Response,
    ) -> Result<()> {
        if let Some(mut transaction) = self.client_transactions.get_mut(transaction_id) {
            transaction.handle_response(response)?;
            debug!(
                "Client transaction {} state: {:?}",
                transaction_id.as_str(),
                transaction.state
            );
        } else {
            warn!(
                "Received response for unknown client transaction: {}",
                transaction_id.as_str()
            );
        }
        Ok(())
    }

    /// Send response from server transaction
    pub fn send_server_response(
        &self,
        transaction_id: &TransactionId,
        response: Response,
    ) -> Result<()> {
        if let Some(mut transaction) = self.server_transactions.get_mut(transaction_id) {
            transaction.send_response(response)?;
            debug!(
                "Server transaction {} state: {:?}",
                transaction_id.as_str(),
                transaction.state
            );
        } else {
            return Err(Error::Transaction(format!(
                "Server transaction not found: {}",
                transaction_id.as_str()
            )));
        }
        Ok(())
    }

    /// Handle ACK for server transaction
    pub fn handle_server_ack(&self, transaction_id: &TransactionId) -> Result<()> {
        if let Some(mut transaction) = self.server_transactions.get_mut(transaction_id) {
            transaction.handle_ack()?;
        }
        Ok(())
    }

    /// Cleanup terminated transactions
    pub fn cleanup_terminated(&self) -> usize {
        let mut cleaned = 0;

        // Cleanup client transactions
        self.client_transactions
            .retain(|id, transaction| {
                if transaction.is_terminated() {
                    info!("Cleaning up terminated client transaction: {}", id.as_str());
                    cleaned += 1;
                    false
                } else {
                    true
                }
            });

        // Cleanup server transactions
        self.server_transactions
            .retain(|id, transaction| {
                if transaction.is_terminated() {
                    info!("Cleaning up terminated server transaction: {}", id.as_str());
                    cleaned += 1;
                    false
                } else {
                    true
                }
            });

        if cleaned > 0 {
            debug!("Cleaned up {} terminated transactions", cleaned);
        }

        cleaned
    }

    /// Check timeouts for all transactions
    pub fn check_timeouts(&self) -> usize {
        let mut timedout = 0;

        // Check client transaction timeouts
        for mut entry in self.client_transactions.iter_mut() {
            if entry.check_timeout() {
                timedout += 1;
            }
        }

        // Check server transaction timeouts
        for mut entry in self.server_transactions.iter_mut() {
            if entry.check_timeout() {
                timedout += 1;
            }
        }

        if timedout > 0 {
            debug!("{} transactions timed out", timedout);
        }

        timedout
    }

    /// Get statistics
    pub fn stats(&self) -> TransactionStats {
        TransactionStats {
            client_transactions: self.client_transactions.len(),
            server_transactions: self.server_transactions.len(),
        }
    }

    /// Check if client transaction exists
    pub fn has_client_transaction(&self, id: &TransactionId) -> bool {
        self.client_transactions.contains_key(id)
    }

    /// Check if server transaction exists
    pub fn has_server_transaction(&self, id: &TransactionId) -> bool {
        self.server_transactions.contains_key(id)
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction statistics
#[derive(Debug, Clone)]
pub struct TransactionStats {
    pub client_transactions: usize,
    pub server_transactions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::prelude::*;

    fn create_test_request() -> Request {
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

    #[test]
    fn test_transaction_manager_creation() {
        let manager = TransactionManager::new();
        let stats = manager.stats();
        assert_eq!(stats.client_transactions, 0);
        assert_eq!(stats.server_transactions, 0);
    }

    #[test]
    fn test_create_client_transaction() {
        let manager = TransactionManager::new();
        let request = create_test_request();
        let dest = "127.0.0.1:5060".parse().unwrap();

        let result = manager.create_client_transaction(request, rsip::Transport::Udp, dest);
        assert!(result.is_ok());

        let stats = manager.stats();
        assert_eq!(stats.client_transactions, 1);
    }

    #[test]
    fn test_create_server_transaction() {
        let manager = TransactionManager::new();
        let request = create_test_request();
        let source = "127.0.0.1:5060".parse().unwrap();

        let result = manager.create_server_transaction(request, rsip::Transport::Udp, source);
        assert!(result.is_ok());

        let stats = manager.stats();
        assert_eq!(stats.server_transactions, 1);
    }

    #[test]
    fn test_cleanup_terminated() {
        let manager = TransactionManager::new();
        let stats = manager.stats();
        assert_eq!(stats.client_transactions, 0);

        // Initially no transactions to clean
        let cleaned = manager.cleanup_terminated();
        assert_eq!(cleaned, 0);
    }
}
