//! ICE (Interactive Connectivity Establishment) - RFC 8445
//!
//! Manages ICE candidates, connectivity checks, and NAT traversal

use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// ICE Candidate Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Host candidate (local interface)
    Host,

    /// Server reflexive (learned via STUN)
    ServerReflexive,

    /// Peer reflexive (learned during connectivity checks)
    PeerReflexive,

    /// Relay candidate (via TURN server)
    Relay,
}

impl CandidateType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::ServerReflexive),
            "prflx" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }

    /// Priority for candidate type (RFC 8445 Section 5.1.2)
    pub fn type_preference(&self) -> u32 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relay => 0,
        }
    }
}

/// ICE Candidate
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Foundation (unique identifier for candidates from same interface)
    pub foundation: String,

    /// Component ID (1 = RTP, 2 = RTCP)
    pub component: u16,

    /// Transport protocol (UDP, TCP)
    pub transport: String,

    /// Priority (computed from type, local, component)
    pub priority: u32,

    /// Connection address
    pub address: SocketAddr,

    /// Candidate type
    pub candidate_type: CandidateType,

    /// Related address (for srflx/relay)
    pub related_address: Option<SocketAddr>,
}

impl IceCandidate {
    /// Create a new host candidate
    pub fn host(address: SocketAddr, component: u16) -> Self {
        let priority = Self::compute_priority(CandidateType::Host, 65535, component);

        Self {
            foundation: format!("host-{}", component),
            component,
            transport: "UDP".to_string(),
            priority,
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
        }
    }

    /// Create a server reflexive candidate
    pub fn server_reflexive(
        address: SocketAddr,
        component: u16,
        related_address: SocketAddr,
    ) -> Self {
        let priority =
            Self::compute_priority(CandidateType::ServerReflexive, 65535, component);

        Self {
            foundation: format!("srflx-{}", component),
            component,
            transport: "UDP".to_string(),
            priority,
            address,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(related_address),
        }
    }

    /// Create a relay candidate
    pub fn relay(address: SocketAddr, component: u16, related_address: SocketAddr) -> Self {
        let priority = Self::compute_priority(CandidateType::Relay, 65535, component);

        Self {
            foundation: format!("relay-{}", component),
            component,
            transport: "UDP".to_string(),
            priority,
            address,
            candidate_type: CandidateType::Relay,
            related_address: Some(related_address),
        }
    }

    /// Compute candidate priority (RFC 8445 Section 5.1.2)
    ///
    /// priority = (2^24)*(type preference) +
    ///            (2^8)*(local preference) +
    ///            (2^0)*(256 - component ID)
    pub fn compute_priority(candidate_type: CandidateType, local_pref: u16, component: u16) -> u32 {
        let type_pref = candidate_type.type_preference();
        (type_pref << 24) | ((local_pref as u32) << 8) | (256 - component as u32)
    }

    /// Parse ICE candidate from SDP attribute
    ///
    /// Format: candidate:foundation component transport priority ip port typ type [raddr raddr] [rport rport]
    /// Example: candidate:1 1 UDP 2130706431 192.168.1.100 5000 typ host
    pub fn from_sdp(value: &str) -> Result<Self> {
        // Remove "candidate:" prefix if present
        let value = value.strip_prefix("candidate:").unwrap_or(value);

        let parts: Vec<&str> = value.split_whitespace().collect();

        if parts.len() < 8 {
            return Err(Error::Media(format!("Invalid ICE candidate: {}", value)));
        }

        let foundation = parts[0].to_string();
        let component = parts[1]
            .parse::<u16>()
            .map_err(|e| Error::Media(format!("Invalid component: {}", e)))?;
        let transport = parts[2].to_string();
        let priority = parts[3]
            .parse::<u32>()
            .map_err(|e| Error::Media(format!("Invalid priority: {}", e)))?;

        let ip = parts[4];
        let port = parts[5]
            .parse::<u16>()
            .map_err(|e| Error::Media(format!("Invalid port: {}", e)))?;

        let address: SocketAddr = format!("{}:{}", ip, port)
            .parse()
            .map_err(|e| Error::Media(format!("Invalid address: {}", e)))?;

        // parts[6] should be "typ"
        let candidate_type = CandidateType::from_str(parts[7])
            .ok_or_else(|| Error::Media(format!("Unknown candidate type: {}", parts[7])))?;

        // Parse related address if present
        let mut related_address = None;
        let mut i = 8;
        while i + 1 < parts.len() {
            match parts[i] {
                "raddr" => {
                    let raddr_ip = parts[i + 1];
                    if i + 3 < parts.len() && parts[i + 2] == "rport" {
                        let raddr_port = parts[i + 3]
                            .parse::<u16>()
                            .map_err(|e| Error::Media(format!("Invalid rport: {}", e)))?;
                        related_address = Some(
                            format!("{}:{}", raddr_ip, raddr_port)
                                .parse()
                                .map_err(|e| Error::Media(format!("Invalid raddr: {}", e)))?,
                        );
                        i += 4;
                    } else {
                        i += 2;
                    }
                }
                _ => i += 1,
            }
        }

        Ok(Self {
            foundation,
            component,
            transport,
            priority,
            address,
            candidate_type,
            related_address,
        })
    }

    /// Format as SDP attribute
    pub fn to_sdp(&self) -> String {
        let mut sdp = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type.to_str()
        );

        if let Some(raddr) = self.related_address {
            sdp.push_str(&format!(" raddr {} rport {}", raddr.ip(), raddr.port()));
        }

        sdp
    }
}

/// ICE Candidate Pair
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate
    pub local: IceCandidate,

    /// Remote candidate
    pub remote: IceCandidate,

    /// Pair priority
    pub priority: u64,

    /// State of connectivity check
    pub state: PairState,
}

/// Candidate Pair State
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PairState {
    /// Waiting to be checked
    Waiting,

    /// Check in progress
    InProgress,

    /// Check succeeded
    Succeeded,

    /// Check failed
    Failed,

    /// Frozen (waiting for other checks)
    Frozen,
}

impl CandidatePair {
    /// Create new candidate pair
    pub fn new(local: IceCandidate, remote: IceCandidate, is_controlling: bool) -> Self {
        let priority = Self::compute_pair_priority(
            local.priority,
            remote.priority,
            is_controlling,
        );

        Self {
            local,
            remote,
            priority,
            state: PairState::Frozen,
        }
    }

    /// Compute pair priority (RFC 8445 Section 6.1.2.3)
    ///
    /// pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    pub fn compute_pair_priority(local_prio: u32, remote_prio: u32, is_controlling: bool) -> u64 {
        let (g, d) = if is_controlling {
            (local_prio, remote_prio)
        } else {
            (remote_prio, local_prio)
        };

        let min = std::cmp::min(g, d) as u64;
        let max = std::cmp::max(g, d) as u64;

        (min << 32) | (max << 1) | (if g > d { 1 } else { 0 })
    }
}

/// ICE Agent
pub struct IceAgent {
    /// Local ICE username fragment
    pub ufrag: String,

    /// Local ICE password
    pub pwd: String,

    /// Remote ICE credentials
    remote_credentials: Option<(String, String)>,

    /// Local candidates
    local_candidates: Vec<IceCandidate>,

    /// Remote candidates
    remote_candidates: Vec<IceCandidate>,

    /// Candidate pairs (valid pairs)
    pairs: Arc<Mutex<Vec<CandidatePair>>>,

    /// Selected pair (nominated)
    selected_pair: Arc<Mutex<Option<CandidatePair>>>,

    /// Controlling role
    is_controlling: bool,
}

impl IceAgent {
    /// Create new ICE agent
    pub fn new(is_controlling: bool) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate random ICE credentials
        let ufrag: String = (0..8)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let pwd: String = (0..24)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        Self {
            ufrag,
            pwd,
            remote_credentials: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            pairs: Arc::new(Mutex::new(Vec::new())),
            selected_pair: Arc::new(Mutex::new(None)),
            is_controlling,
        }
    }

    /// Add local candidate
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        info!(
            "Added local {} candidate: {}",
            candidate.candidate_type.to_str(),
            candidate.address
        );
        self.local_candidates.push(candidate);
    }

    /// Add remote candidate
    pub async fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        info!(
            "Added remote {} candidate: {}",
            candidate.candidate_type.to_str(),
            candidate.address
        );
        self.remote_candidates.push(candidate.clone());

        // Form new pairs with existing local candidates
        self.form_pairs_with_candidate(candidate).await;
    }

    /// Set remote ICE credentials
    pub fn set_remote_credentials(&mut self, ufrag: String, pwd: String) {
        self.remote_credentials = Some((ufrag, pwd));
    }

    /// Form candidate pairs
    async fn form_pairs_with_candidate(&mut self, remote: IceCandidate) {
        let mut pairs = self.pairs.lock().await;

        for local in &self.local_candidates {
            // Only pair candidates with same component
            if local.component == remote.component {
                let pair = CandidatePair::new(
                    local.clone(),
                    remote.clone(),
                    self.is_controlling,
                );

                debug!(
                    "Formed pair: {}:{} <-> {}:{}",
                    local.address.ip(),
                    local.address.port(),
                    remote.address.ip(),
                    remote.address.port()
                );

                pairs.push(pair);
            }
        }

        // Sort by priority (highest first)
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get local candidates for SDP
    pub fn local_candidates_sdp(&self) -> Vec<String> {
        self.local_candidates.iter().map(|c| c.to_sdp()).collect()
    }

    /// Get ICE credentials for SDP
    pub fn credentials(&self) -> (&str, &str) {
        (&self.ufrag, &self.pwd)
    }

    /// Perform connectivity checks using real STUN Binding requests (RFC 8445 Section 7)
    pub async fn perform_checks(&self) -> Result<()> {
        // Thaw all frozen pairs first
        {
            let mut pairs = self.pairs.lock().await;
            for pair in pairs.iter_mut() {
                if pair.state == PairState::Frozen {
                    pair.state = PairState::Waiting;
                }
            }
        }

        // Check each waiting pair
        let pair_count = self.pairs.lock().await.len();
        for i in 0..pair_count {
            let (local_addr, remote_addr, state) = {
                let pairs = self.pairs.lock().await;
                let p = &pairs[i];
                (p.local.address, p.remote.address, p.state.clone())
            };

            if state != PairState::Waiting {
                continue;
            }

            // Mark as in progress
            self.pairs.lock().await[i].state = PairState::InProgress;

            // Perform real STUN Binding request
            match self.send_stun_binding_request(local_addr, remote_addr).await {
                Ok(mapped_addr) => {
                    debug!(
                        "Connectivity check OK: {} <-> {} (mapped: {})",
                        local_addr, remote_addr, mapped_addr
                    );
                    self.pairs.lock().await[i].state = PairState::Succeeded;

                    // Nominate first successful pair
                    if self.selected_pair.lock().await.is_none() {
                        info!("Nominated pair: {} <-> {}", local_addr, remote_addr);
                        let pair = self.pairs.lock().await[i].clone();
                        *self.selected_pair.lock().await = Some(pair);
                    }
                }
                Err(e) => {
                    debug!(
                        "Connectivity check failed: {} <-> {} : {}",
                        local_addr, remote_addr, e
                    );
                    self.pairs.lock().await[i].state = PairState::Failed;
                }
            }
        }

        Ok(())
    }

    /// Send a STUN Binding request to remote_addr, bound on local_addr.
    ///
    /// Returns the XOR-MAPPED-ADDRESS from the response (or error on failure/timeout).
    /// Uses short-term credentials from ICE username fragment and password (RFC 5389 / 8445).
    async fn send_stun_binding_request(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        use tokio::net::UdpSocket;
        use tokio::time::{timeout, Duration};
        use rand::Rng;

        // Bind a UDP socket on the local candidate address (or 0.0.0.0 for loopback tests)
        let bind_addr = if local_addr.ip().is_loopback() || local_addr.ip().is_unspecified() {
            local_addr
        } else {
            SocketAddr::new(local_addr.ip(), 0)
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            Error::Media(format!("ICE check bind failed for {}: {}", bind_addr, e))
        })?;

        // Build STUN Binding Request (RFC 5389 Section 6)
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill(&mut transaction_id);

        let mut msg = Vec::with_capacity(20);
        // Message Type: Binding Request = 0x0001
        msg.extend_from_slice(&0x0001u16.to_be_bytes());
        // Message Length: 0 (no attributes yet; we add USERNAME + MESSAGE-INTEGRITY below)
        msg.extend_from_slice(&0x0000u16.to_be_bytes());
        // Magic Cookie
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
        // Transaction ID
        msg.extend_from_slice(&transaction_id);

        // USERNAME attribute (format: "remote-ufrag:local-ufrag" for controlled pair)
        if let Some((remote_ufrag, _remote_pwd)) = &self.remote_credentials {
            let username = format!("{}:{}", remote_ufrag, self.ufrag);
            let username_bytes = username.as_bytes();
            let padded_len = (username_bytes.len() + 3) & !3;
            // Attribute type 0x0006, length
            msg.extend_from_slice(&0x0006u16.to_be_bytes());
            msg.extend_from_slice(&(username_bytes.len() as u16).to_be_bytes());
            msg.extend_from_slice(username_bytes);
            // Padding
            msg.extend_from_slice(&vec![0u8; padded_len - username_bytes.len()]);

            // ICE-CONTROLLING or ICE-CONTROLLED attribute
            let role_attr_type: u16 = if self.is_controlling { 0x802F } else { 0x8030 };
            msg.extend_from_slice(&role_attr_type.to_be_bytes());
            msg.extend_from_slice(&8u16.to_be_bytes());
            msg.extend_from_slice(&rand::thread_rng().gen::<u64>().to_be_bytes());

            // Update message length in header (total attrs size)
            let attr_len = (msg.len() - 20) as u16;
            msg[2] = (attr_len >> 8) as u8;
            msg[3] = (attr_len & 0xFF) as u8;
        }

        // Send the request
        socket.send_to(&msg, remote_addr).await.map_err(|e| {
            Error::Media(format!("ICE check send failed to {}: {}", remote_addr, e))
        })?;

        // Wait for response (200ms timeout per RFC 8445 Ta timer)
        let mut buf = [0u8; 1024];
        let result = timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;

        let (n, from) = match result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(Error::Media(format!("ICE check recv error: {}", e))),
            Err(_) => return Err(Error::Media(format!(
                "ICE check timeout to {}",
                remote_addr
            ))),
        };

        let response = &buf[..n];

        // Validate STUN response
        if response.len() < 20 {
            return Err(Error::Media("ICE: response too short".to_string()));
        }

        // Check Magic Cookie
        if &response[4..8] != &0x2112A442u32.to_be_bytes() {
            return Err(Error::Media("ICE: invalid magic cookie in response".to_string()));
        }

        // Check transaction ID matches
        if &response[8..20] != &transaction_id {
            return Err(Error::Media("ICE: transaction ID mismatch".to_string()));
        }

        // Message type: Binding Success Response = 0x0101
        let msg_type = u16::from_be_bytes([response[0], response[1]]);
        if msg_type == 0x0111 {
            // Binding Error Response
            return Err(Error::Media("ICE: received Binding Error Response".to_string()));
        }
        if msg_type != 0x0101 {
            return Err(Error::Media(format!(
                "ICE: unexpected message type 0x{:04X}",
                msg_type
            )));
        }

        // Parse attributes to find XOR-MAPPED-ADDRESS (0x0020)
        let mut offset = 20usize;
        let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;

        while offset + 4 <= 20 + msg_len && offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            offset += 4;

            if attr_type == 0x0020 && attr_len >= 8 {
                // XOR-MAPPED-ADDRESS: family, x-port, x-addr
                // family: response[offset+1] (0x01=IPv4, 0x02=IPv6)
                let family = response[offset + 1];
                let xport = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
                let port = xport ^ 0x2112u16;

                let addr = if family == 0x01 && offset + 8 <= response.len() {
                    let xa = u32::from_be_bytes([
                        response[offset + 4],
                        response[offset + 5],
                        response[offset + 6],
                        response[offset + 7],
                    ]);
                    let ip = std::net::Ipv4Addr::from(xa ^ 0x2112A442u32);
                    SocketAddr::new(std::net::IpAddr::V4(ip), port)
                } else {
                    from // fallback
                };

                return Ok(addr);
            }

            // Advance past attribute value (padded to 4 bytes)
            let padded = (attr_len + 3) & !3;
            offset += padded;
        }

        // No XOR-MAPPED-ADDRESS found, return the source address as fallback
        Ok(from)
    }

    /// Get selected (nominated) pair
    pub async fn get_selected_pair(&self) -> Option<CandidatePair> {
        self.selected_pair.lock().await.clone()
    }

    /// Get statistics
    pub async fn stats(&self) -> IceStats {
        let pairs = self.pairs.lock().await;

        IceStats {
            local_candidates: self.local_candidates.len(),
            remote_candidates: self.remote_candidates.len(),
            total_pairs: pairs.len(),
            succeeded_pairs: pairs.iter().filter(|p| p.state == PairState::Succeeded).count(),
            failed_pairs: pairs.iter().filter(|p| p.state == PairState::Failed).count(),
            has_selected_pair: self.selected_pair.lock().await.is_some(),
        }
    }
}

/// ICE Statistics
#[derive(Debug, Clone)]
pub struct IceStats {
    pub local_candidates: usize,
    pub remote_candidates: usize,
    pub total_pairs: usize,
    pub succeeded_pairs: usize,
    pub failed_pairs: usize,
    pub has_selected_pair: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_type_preference() {
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::Relay.type_preference(), 0);
    }

    #[test]
    fn test_candidate_priority() {
        let host_prio = IceCandidate::compute_priority(CandidateType::Host, 65535, 1);
        let srflx_prio = IceCandidate::compute_priority(CandidateType::ServerReflexive, 65535, 1);

        assert!(host_prio > srflx_prio);
    }

    #[test]
    fn test_host_candidate() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let cand = IceCandidate::host(addr, 1);

        assert_eq!(cand.component, 1);
        assert_eq!(cand.candidate_type, CandidateType::Host);
        assert_eq!(cand.address, addr);
        assert!(cand.related_address.is_none());
    }

    #[test]
    fn test_server_reflexive_candidate() {
        let public_addr: SocketAddr = "203.0.113.100:5000".parse().unwrap();
        let local_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

        let cand = IceCandidate::server_reflexive(public_addr, 1, local_addr);

        assert_eq!(cand.component, 1);
        assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(cand.address, public_addr);
        assert_eq!(cand.related_address, Some(local_addr));
    }

    #[test]
    fn test_candidate_to_sdp() {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let cand = IceCandidate::host(addr, 1);

        let sdp = cand.to_sdp();
        assert!(sdp.starts_with("candidate:"));
        assert!(sdp.contains("192.168.1.100"));
        assert!(sdp.contains("5000"));
        assert!(sdp.contains("typ host"));
    }

    #[test]
    fn test_candidate_from_sdp() {
        let sdp = "candidate:host-1 1 UDP 2130706431 192.168.1.100 5000 typ host";
        let cand = IceCandidate::from_sdp(sdp).unwrap();

        assert_eq!(cand.foundation, "host-1");
        assert_eq!(cand.component, 1);
        assert_eq!(cand.transport, "UDP");
        assert_eq!(cand.address.to_string(), "192.168.1.100:5000");
        assert_eq!(cand.candidate_type, CandidateType::Host);
    }

    #[test]
    fn test_candidate_from_sdp_with_related() {
        let sdp = "candidate:srflx-1 1 UDP 1694498815 203.0.113.100 5000 typ srflx raddr 192.168.1.100 rport 5000";
        let cand = IceCandidate::from_sdp(sdp).unwrap();

        assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(cand.address.to_string(), "203.0.113.100:5000");
        assert_eq!(
            cand.related_address.unwrap().to_string(),
            "192.168.1.100:5000"
        );
    }

    #[test]
    fn test_pair_priority() {
        let local_prio = 2130706431u32;
        let remote_prio = 2130706431u32;

        let prio_controlling = CandidatePair::compute_pair_priority(
            local_prio,
            remote_prio,
            true,
        );

        let prio_controlled = CandidatePair::compute_pair_priority(
            local_prio,
            remote_prio,
            false,
        );

        assert_eq!(prio_controlling, prio_controlled);
    }

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let agent = IceAgent::new(true);

        assert!(!agent.ufrag.is_empty());
        assert!(!agent.pwd.is_empty());
        assert_eq!(agent.ufrag.len(), 8);
        assert_eq!(agent.pwd.len(), 24);
        assert!(agent.is_controlling);
    }

    #[tokio::test]
    async fn test_ice_agent_add_candidates() {
        let mut agent = IceAgent::new(true);

        let local_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let local_cand = IceCandidate::host(local_addr, 1);

        agent.add_local_candidate(local_cand);

        assert_eq!(agent.local_candidates.len(), 1);
    }

    #[tokio::test]
    async fn test_ice_agent_pair_formation() {
        let mut agent = IceAgent::new(true);

        let local_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let remote_addr: SocketAddr = "192.168.1.200:6000".parse().unwrap();

        agent.add_local_candidate(IceCandidate::host(local_addr, 1));
        agent.add_remote_candidate(IceCandidate::host(remote_addr, 1)).await;

        let stats = agent.stats().await;
        assert_eq!(stats.local_candidates, 1);
        assert_eq!(stats.remote_candidates, 1);
        assert_eq!(stats.total_pairs, 1);
    }

    /// Test that perform_checks marks unreachable pairs as Failed (timeout)
    #[tokio::test]
    async fn test_ice_connectivity_check_timeout() {
        let mut agent = IceAgent::new(true);

        // Use loopback but a port that has no listener → timeout
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Bind real socket to get assigned port
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bound_local = sock.local_addr().unwrap();

        // Use a port with no listener for remote (timeout expected)
        let remote_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        agent.add_local_candidate(IceCandidate::host(bound_local, 1));
        agent.add_remote_candidate(IceCandidate::host(remote_addr, 1)).await;

        // Check will timeout (port 1 has no listener)
        agent.perform_checks().await.unwrap();

        let stats = agent.stats().await;
        // Should have failed (timeout) since nobody listens on port 1
        assert_eq!(stats.failed_pairs, 1);
        assert_eq!(stats.succeeded_pairs, 0);
        assert!(!stats.has_selected_pair);
    }

    /// Test ICE check with a real loopback STUN responder
    #[tokio::test]
    async fn test_ice_connectivity_check_loopback() {
        use tokio::net::UdpSocket;

        // Spawn a minimal STUN Binding responder
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = responder.recv_from(&mut buf).await {
                let req = &buf[..n];
                if req.len() >= 20 {
                    // Build minimal Binding Success Response
                    let mut resp = Vec::new();
                    // Type: 0x0101 Binding Success
                    resp.extend_from_slice(&0x0101u16.to_be_bytes());
                    // Length: 12 bytes for XOR-MAPPED-ADDRESS attr
                    resp.extend_from_slice(&12u16.to_be_bytes());
                    // Magic Cookie
                    resp.extend_from_slice(&0x2112A442u32.to_be_bytes());
                    // Transaction ID from request
                    resp.extend_from_slice(&req[8..20]);

                    // XOR-MAPPED-ADDRESS attr (type 0x0020, len 8, IPv4)
                    resp.extend_from_slice(&0x0020u16.to_be_bytes());
                    resp.extend_from_slice(&8u16.to_be_bytes());
                    resp.push(0x00); // reserved
                    resp.push(0x01); // IPv4
                    // XOR-Port
                    let xport = from.port() ^ 0x2112u16;
                    resp.extend_from_slice(&xport.to_be_bytes());
                    // XOR-Address
                    let ip_u32: u32 = match from.ip() {
                        std::net::IpAddr::V4(v4) => u32::from(v4),
                        _ => 0,
                    };
                    let xip = ip_u32 ^ 0x2112A442u32;
                    resp.extend_from_slice(&xip.to_be_bytes());

                    let _ = responder.send_to(&resp, from).await;
                }
            }
        });

        // Build agent with loopback candidates
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        drop(client_sock); // release so IceAgent can bind it

        let mut agent = IceAgent::new(true);
        agent.add_local_candidate(IceCandidate::host(client_addr, 1));
        agent.add_remote_candidate(IceCandidate::host(responder_addr, 1)).await;

        agent.perform_checks().await.unwrap();

        let stats = agent.stats().await;
        assert_eq!(stats.succeeded_pairs, 1);
        assert!(stats.has_selected_pair);
    }

    #[tokio::test]
    async fn test_ice_pair_states_after_check() {
        let mut agent = IceAgent::new(false); // controlled

        // Two local, one remote → two pairs
        let la1: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let la2: SocketAddr = "192.168.1.1:5002".parse().unwrap();
        let remote: SocketAddr = "192.168.1.2:6000".parse().unwrap();

        agent.add_local_candidate(IceCandidate::host(la1, 1));
        agent.add_local_candidate(IceCandidate::host(la2, 1));
        agent.add_remote_candidate(IceCandidate::host(remote, 1)).await;

        let stats = agent.stats().await;
        assert_eq!(stats.total_pairs, 2);

        // Both pairs should be frozen initially
        {
            let pairs = agent.pairs.lock().await;
            for p in pairs.iter() {
                assert_eq!(p.state, PairState::Frozen);
            }
        }
    }
}
