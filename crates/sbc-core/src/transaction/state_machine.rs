//! Transaction State Machines (RFC 3261 Section 17)
//!
//! Implements both client and server transaction state machines for:
//! - INVITE transactions (with ACK handling)
//! - Non-INVITE transactions

use crate::{Error, Result};
use rsip::{Method, Request, Response, StatusCode};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Transaction identifier (Via branch parameter)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(pub String);

impl TransactionId {
    /// Create from Via branch parameter
    pub fn from_branch(branch: &str) -> Self {
        Self(branch.to_string())
    }

    /// Create from Request (extracts from top Via)
    pub fn from_request(req: &Request) -> Result<Self> {
        use rsip::prelude::*;

        // Get top Via header
        let via_header = req
            .headers()
            .iter()
            .find(|h| matches!(h, rsip::Header::Via(_)))
            .ok_or_else(|| Error::Parse("Missing Via header".to_string()))?;

        // Extract branch parameter
        let via_str = via_header.to_string();
        if let Some(branch_start) = via_str.find("branch=") {
            let branch = &via_str[branch_start + 7..];
            let branch = branch.split(';').next().unwrap_or(branch);

            // RFC 3261: branch must start with z9hG4bK for RFC 3261 transactions
            if branch.starts_with("z9hG4bK") {
                return Ok(Self(branch.to_string()));
            }
        }

        Err(Error::Parse(
            "Invalid or missing branch parameter".to_string(),
        ))
    }

    /// Get the string value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Client transaction state (RFC 3261 Section 17.1)
#[derive(Debug, Clone, PartialEq)]
pub enum ClientTransactionState {
    /// Initial state (before sending request)
    Initial,

    /// INVITE Client: Calling state (waiting for response)
    Calling,

    /// INVITE Client: Proceeding state (received 1xx)
    Proceeding,

    /// INVITE Client: Completed state (received final response, waiting for ACK timeout)
    Completed,

    /// Non-INVITE Client: Trying state (request sent, waiting for response)
    Trying,

    /// Transaction terminated
    Terminated,
}

/// Server transaction state (RFC 3261 Section 17.2)
#[derive(Debug, Clone, PartialEq)]
pub enum ServerTransactionState {
    /// Initial state (just received request)
    Initial,

    /// INVITE Server: Proceeding state (sent 1xx)
    Proceeding,

    /// INVITE Server: Completed state (sent final response, waiting for ACK)
    Completed,

    /// INVITE Server: Confirmed state (received ACK)
    Confirmed,

    /// Non-INVITE Server: Trying state (processing request)
    Trying,

    /// Transaction terminated
    Terminated,
}

/// Transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// INVITE transaction (special handling for ACK)
    Invite,

    /// Non-INVITE transaction (BYE, REGISTER, OPTIONS, etc.)
    NonInvite,
}

impl TransactionType {
    /// Determine transaction type from method
    pub fn from_method(method: &Method) -> Self {
        match method {
            Method::Invite => Self::Invite,
            _ => Self::NonInvite,
        }
    }
}

/// Client transaction (RFC 3261 Section 17.1)
pub struct ClientTransaction {
    /// Transaction ID (Via branch)
    pub id: TransactionId,

    /// Transaction type
    pub transaction_type: TransactionType,

    /// Current state
    pub state: ClientTransactionState,

    /// Original request
    pub request: Request,

    /// Last response received (if any)
    pub last_response: Option<Response>,

    /// Transport used (for retransmissions)
    pub transport: rsip::Transport,

    /// Destination address
    pub dest: std::net::SocketAddr,

    /// Creation time
    pub created_at: Instant,

    /// Last state change time
    pub last_state_change: Instant,

    /// Retransmission count
    pub retransmit_count: u32,

    /// Channel for sending events
    event_tx: Option<mpsc::UnboundedSender<TransactionEvent>>,
}

impl ClientTransaction {
    /// Create a new client transaction
    pub fn new(
        id: TransactionId,
        request: Request,
        transport: rsip::Transport,
        dest: std::net::SocketAddr,
    ) -> Self {
        let transaction_type = TransactionType::from_method(&request.method);
        let now = Instant::now();

        Self {
            id,
            transaction_type,
            state: ClientTransactionState::Initial,
            request,
            last_response: None,
            transport,
            dest,
            created_at: now,
            last_state_change: now,
            retransmit_count: 0,
            event_tx: None,
        }
    }

    /// Set event channel
    pub fn set_event_channel(&mut self, tx: mpsc::UnboundedSender<TransactionEvent>) {
        self.event_tx = Some(tx);
    }

    /// Transition to a new state
    fn transition_to(&mut self, new_state: ClientTransactionState) {
        if self.state != new_state {
            debug!(
                "Client transaction {} state: {:?} -> {:?}",
                self.id.as_str(),
                self.state,
                new_state
            );
            self.state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    /// Start the transaction (send initial request)
    pub fn start(&mut self) -> Result<()> {
        match self.transaction_type {
            TransactionType::Invite => {
                self.transition_to(ClientTransactionState::Calling);
                info!("Started INVITE client transaction {}", self.id.as_str());
            }
            TransactionType::NonInvite => {
                self.transition_to(ClientTransactionState::Trying);
                info!(
                    "Started non-INVITE client transaction {}",
                    self.id.as_str()
                );
            }
        }
        Ok(())
    }

    /// Handle received response
    pub fn handle_response(&mut self, response: Response) -> Result<()> {
        let status_code = response.status_code.clone();
        self.last_response = Some(response);

        match self.transaction_type {
            TransactionType::Invite => self.handle_invite_response(status_code),
            TransactionType::NonInvite => self.handle_non_invite_response(status_code),
        }
    }

    /// Handle INVITE response (RFC 3261 Section 17.1.1)
    fn handle_invite_response(&mut self, status_code: StatusCode) -> Result<()> {
        match self.state {
            ClientTransactionState::Calling | ClientTransactionState::Proceeding => {
                if status_code.code() >= 100 && status_code.code() < 200 {
                    // 1xx provisional response
                    self.transition_to(ClientTransactionState::Proceeding);
                    debug!("Received provisional response: {}", status_code);
                } else if status_code.code() >= 200 && status_code.code() < 300 {
                    // 2xx success - transaction completes, dialog layer handles ACK
                    self.transition_to(ClientTransactionState::Terminated);
                    info!("Received 2xx response, transaction terminates");
                } else if status_code.code() >= 300 {
                    // 3xx-6xx final response
                    self.transition_to(ClientTransactionState::Completed);
                    info!("Received final error response: {}", status_code);
                    // ACK will be generated
                }
            }
            ClientTransactionState::Completed => {
                // Retransmitted response, ignore
                debug!("Ignoring retransmitted response in Completed state");
            }
            _ => {
                warn!("Unexpected response in state: {:?}", self.state);
            }
        }
        Ok(())
    }

    /// Handle non-INVITE response (RFC 3261 Section 17.1.2)
    fn handle_non_invite_response(&mut self, status_code: StatusCode) -> Result<()> {
        match self.state {
            ClientTransactionState::Trying | ClientTransactionState::Proceeding => {
                if status_code.code() >= 100 && status_code.code() < 200 {
                    // 1xx provisional response
                    self.transition_to(ClientTransactionState::Proceeding);
                    debug!("Received provisional response: {}", status_code);
                } else {
                    // Final response (2xx-6xx)
                    self.transition_to(ClientTransactionState::Completed);
                    info!("Received final response: {}", status_code);
                }
            }
            _ => {
                warn!("Unexpected response in state: {:?}", self.state);
            }
        }
        Ok(())
    }

    /// Check if transaction should be terminated due to timeout
    pub fn check_timeout(&mut self) -> bool {
        let elapsed = self.last_state_change.elapsed();

        match self.state {
            ClientTransactionState::Completed => {
                // Timer D for INVITE (>= 32s for unreliable transport)
                // Timer K for non-INVITE (T4 = 5s)
                let timeout = match self.transaction_type {
                    TransactionType::Invite => {
                        if matches!(self.transport, rsip::Transport::Udp) {
                            Duration::from_secs(32) // Timer D
                        } else {
                            Duration::from_secs(0) // Immediate for reliable
                        }
                    }
                    TransactionType::NonInvite => Duration::from_secs(5), // Timer K (T4)
                };

                if elapsed >= timeout {
                    self.transition_to(ClientTransactionState::Terminated);
                    true
                } else {
                    false
                }
            }
            ClientTransactionState::Calling => {
                // Timer B (64*T1 = 32s for INVITE)
                if elapsed >= Duration::from_secs(32) {
                    self.transition_to(ClientTransactionState::Terminated);
                    warn!("INVITE client transaction timeout (Timer B)");
                    true
                } else {
                    false
                }
            }
            ClientTransactionState::Trying => {
                // Timer F (64*T1 = 32s for non-INVITE)
                if elapsed >= Duration::from_secs(32) {
                    self.transition_to(ClientTransactionState::Terminated);
                    warn!("Non-INVITE client transaction timeout (Timer F)");
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Check if transaction is terminated
    pub fn is_terminated(&self) -> bool {
        self.state == ClientTransactionState::Terminated
    }
}

/// Server transaction (RFC 3261 Section 17.2)
pub struct ServerTransaction {
    /// Transaction ID (Via branch)
    pub id: TransactionId,

    /// Transaction type
    pub transaction_type: TransactionType,

    /// Current state
    pub state: ServerTransactionState,

    /// Original request
    pub request: Request,

    /// Last response sent (if any)
    pub last_response: Option<Response>,

    /// Transport used
    pub transport: rsip::Transport,

    /// Source address (where to send responses)
    pub source: std::net::SocketAddr,

    /// Creation time
    pub created_at: Instant,

    /// Last state change time
    pub last_state_change: Instant,

    /// Retransmission count
    pub retransmit_count: u32,
}

impl ServerTransaction {
    /// Create a new server transaction
    pub fn new(
        id: TransactionId,
        request: Request,
        transport: rsip::Transport,
        source: std::net::SocketAddr,
    ) -> Self {
        let transaction_type = TransactionType::from_method(&request.method);
        let now = Instant::now();

        Self {
            id,
            transaction_type,
            state: ServerTransactionState::Initial,
            request,
            last_response: None,
            transport,
            source,
            created_at: now,
            last_state_change: now,
            retransmit_count: 0,
        }
    }

    /// Transition to a new state
    fn transition_to(&mut self, new_state: ServerTransactionState) {
        if self.state != new_state {
            debug!(
                "Server transaction {} state: {:?} -> {:?}",
                self.id.as_str(),
                self.state,
                new_state
            );
            self.state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    /// Send a response
    pub fn send_response(&mut self, response: Response) -> Result<()> {
        let status_code = response.status_code.clone();
        self.last_response = Some(response);

        match self.transaction_type {
            TransactionType::Invite => self.handle_invite_send(status_code),
            TransactionType::NonInvite => self.handle_non_invite_send(status_code),
        }
    }

    /// Handle INVITE response sending (RFC 3261 Section 17.2.1)
    fn handle_invite_send(&mut self, status_code: StatusCode) -> Result<()> {
        if status_code.code() >= 100 && status_code.code() < 200 {
            // 1xx provisional response
            self.transition_to(ServerTransactionState::Proceeding);
            debug!("Sent provisional response: {}", status_code);
        } else if status_code.code() >= 200 && status_code.code() < 300 {
            // 2xx success - pass to TU, no state change (handled by dialog)
            info!("Sent 2xx response, transaction remains for retransmissions");
        } else {
            // 3xx-6xx final response
            self.transition_to(ServerTransactionState::Completed);
            info!("Sent final error response: {}", status_code);
        }
        Ok(())
    }

    /// Handle non-INVITE response sending (RFC 3261 Section 17.2.2)
    fn handle_non_invite_send(&mut self, status_code: StatusCode) -> Result<()> {
        if status_code.code() >= 100 && status_code.code() < 200 {
            // 1xx provisional response
            self.transition_to(ServerTransactionState::Proceeding);
            debug!("Sent provisional response: {}", status_code);
        } else {
            // Final response (2xx-6xx)
            self.transition_to(ServerTransactionState::Completed);
            info!("Sent final response: {}", status_code);
        }
        Ok(())
    }

    /// Handle received ACK (for INVITE transactions)
    pub fn handle_ack(&mut self) -> Result<()> {
        if self.transaction_type == TransactionType::Invite
            && self.state == ServerTransactionState::Completed
        {
            self.transition_to(ServerTransactionState::Confirmed);
            info!("Received ACK, transaction confirmed");
        }
        Ok(())
    }

    /// Check if transaction should be terminated due to timeout
    pub fn check_timeout(&mut self) -> bool {
        let elapsed = self.last_state_change.elapsed();

        match self.state {
            ServerTransactionState::Completed => {
                // Timer H for INVITE (64*T1 = 32s) - waiting for ACK
                if self.transaction_type == TransactionType::Invite {
                    if elapsed >= Duration::from_secs(32) {
                        self.transition_to(ServerTransactionState::Terminated);
                        warn!("INVITE server transaction timeout waiting for ACK (Timer H)");
                        return true;
                    }
                } else {
                    // Timer J for non-INVITE (64*T1 = 32s)
                    if elapsed >= Duration::from_secs(32) {
                        self.transition_to(ServerTransactionState::Terminated);
                        return true;
                    }
                }
            }
            ServerTransactionState::Confirmed => {
                // Timer I (T4 = 5s for unreliable, 0 for reliable)
                let timeout = if matches!(self.transport, rsip::Transport::Udp) {
                    Duration::from_secs(5)
                } else {
                    Duration::from_secs(0)
                };

                if elapsed >= timeout {
                    self.transition_to(ServerTransactionState::Terminated);
                    return true;
                }
            }
            _ => {}
        }

        false
    }

    /// Check if transaction is terminated
    pub fn is_terminated(&self) -> bool {
        self.state == ServerTransactionState::Terminated
    }
}

/// Transaction event (for upper layers)
#[derive(Debug, Clone)]
pub enum TransactionEvent {
    /// Response received on client transaction
    ResponseReceived {
        transaction_id: TransactionId,
        response: Response,
    },

    /// Request received on server transaction
    RequestReceived {
        transaction_id: TransactionId,
        request: Request,
    },

    /// Transaction timeout
    Timeout { transaction_id: TransactionId },

    /// Transaction terminated
    Terminated { transaction_id: TransactionId },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_id_from_branch() {
        let branch = "z9hG4bK776asdhds";
        let id = TransactionId::from_branch(branch);
        assert_eq!(id.as_str(), branch);
    }

    #[test]
    fn test_transaction_type_from_method() {
        assert_eq!(
            TransactionType::from_method(&Method::Invite),
            TransactionType::Invite
        );
        assert_eq!(
            TransactionType::from_method(&Method::Bye),
            TransactionType::NonInvite
        );
    }
}
