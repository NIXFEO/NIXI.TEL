//! Port Allocator for RTP/RTCP
//!
//! Manages a pool of UDP ports for RTP media streams.
//! RTP uses even ports, RTCP uses odd ports (RTP port + 1)

use crate::{Error, Result};
use std::collections::HashSet;
use std::ops::Range;
use std::sync::{Arc, Mutex};

/// Port Allocator for RTP/RTCP pairs
pub struct PortAllocator {
    /// Range of ports available for allocation
    port_range: Range<u16>,

    /// Currently allocated ports
    allocated: Arc<Mutex<HashSet<u16>>>,
}

/// Allocated RTP/RTCP port pair
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPair {
    /// RTP port (always even)
    pub rtp: u16,

    /// RTCP port (always RTP + 1, always odd)
    pub rtcp: u16,
}

impl PortAllocator {
    /// Create a new port allocator with default range (10000-20000)
    pub fn new() -> Self {
        Self::with_range(10000..20000)
    }

    /// Create a new port allocator with custom range
    pub fn with_range(port_range: Range<u16>) -> Self {
        Self {
            port_range,
            allocated: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Allocate a new RTP/RTCP port pair
    ///
    /// Returns a pair where RTP is even and RTCP is RTP+1
    pub fn allocate(&self) -> Result<PortPair> {
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;

        // Find an available even port
        for port in (self.port_range.start..self.port_range.end).step_by(2) {
            // Make sure port is even
            let rtp_port = if port % 2 == 0 { port } else { port + 1 };
            let rtcp_port = rtp_port + 1;

            // Check if both ports are available
            if !allocated.contains(&rtp_port)
                && !allocated.contains(&rtcp_port)
                && rtcp_port < self.port_range.end
            {
                allocated.insert(rtp_port);
                allocated.insert(rtcp_port);

                return Ok(PortPair {
                    rtp: rtp_port,
                    rtcp: rtcp_port,
                });
            }
        }

        Err(Error::Transport(
            "No available ports in range".to_string(),
        ))
    }

    /// Release a port pair
    pub fn release(&self, pair: PortPair) -> Result<()> {
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;

        allocated.remove(&pair.rtp);
        allocated.remove(&pair.rtcp);

        Ok(())
    }

    /// Get number of allocated port pairs
    pub fn allocated_count(&self) -> usize {
        self.allocated
            .lock()
            .map(|a| a.len() / 2)
            .unwrap_or(0)
    }

    /// Get number of available port pairs
    pub fn available_count(&self) -> usize {
        let total_ports = (self.port_range.end - self.port_range.start) as usize;
        let total_pairs = total_ports / 2;
        let allocated = self.allocated_count();
        total_pairs.saturating_sub(allocated)
    }

    /// Check if a specific port pair is allocated
    pub fn is_allocated(&self, pair: PortPair) -> bool {
        self.allocated
            .lock()
            .map(|a| a.contains(&pair.rtp) && a.contains(&pair.rtcp))
            .unwrap_or(false)
    }

    /// Clear all allocations
    pub fn clear(&self) -> Result<()> {
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;

        allocated.clear();
        Ok(())
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PortPair {
    /// Create a new port pair
    ///
    /// RTP port must be even, RTCP will be RTP + 1
    pub fn new(rtp: u16) -> Result<Self> {
        if rtp % 2 != 0 {
            return Err(Error::Transport(
                "RTP port must be even".to_string(),
            ));
        }

        Ok(Self {
            rtp,
            rtcp: rtp + 1,
        })
    }

    /// Check if this is a valid port pair
    pub fn is_valid(&self) -> bool {
        self.rtp % 2 == 0 && self.rtcp == self.rtp + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_creation() {
        let allocator = PortAllocator::new();
        assert_eq!(allocator.allocated_count(), 0);
        assert!(allocator.available_count() > 0);
    }

    #[test]
    fn test_allocate_port_pair() {
        let allocator = PortAllocator::new();

        let pair = allocator.allocate().unwrap();

        // Check RTP port is even
        assert_eq!(pair.rtp % 2, 0);

        // Check RTCP port is RTP + 1
        assert_eq!(pair.rtcp, pair.rtp + 1);

        // Check port is in range
        assert!(pair.rtp >= 10000);
        assert!(pair.rtp < 20000);

        assert_eq!(allocator.allocated_count(), 1);
    }

    #[test]
    fn test_allocate_multiple_pairs() {
        let allocator = PortAllocator::new();

        let pair1 = allocator.allocate().unwrap();
        let pair2 = allocator.allocate().unwrap();
        let pair3 = allocator.allocate().unwrap();

        // All pairs should be different
        assert_ne!(pair1.rtp, pair2.rtp);
        assert_ne!(pair1.rtp, pair3.rtp);
        assert_ne!(pair2.rtp, pair3.rtp);

        assert_eq!(allocator.allocated_count(), 3);
    }

    #[test]
    fn test_release_port_pair() {
        let allocator = PortAllocator::new();

        let pair = allocator.allocate().unwrap();
        assert_eq!(allocator.allocated_count(), 1);

        allocator.release(pair).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn test_release_and_reallocate() {
        let allocator = PortAllocator::with_range(10000..10010);

        // Allocate all available pairs (5 pairs in range 10000-10010)
        let pair1 = allocator.allocate().unwrap();
        let pair2 = allocator.allocate().unwrap();
        let pair3 = allocator.allocate().unwrap();
        let pair4 = allocator.allocate().unwrap();
        let pair5 = allocator.allocate().unwrap();

        assert_eq!(allocator.allocated_count(), 5);
        assert_eq!(allocator.available_count(), 0);

        // Release one pair
        allocator.release(pair3).unwrap();
        assert_eq!(allocator.allocated_count(), 4);
        assert_eq!(allocator.available_count(), 1);

        // Should be able to allocate again
        let pair6 = allocator.allocate().unwrap();
        assert_eq!(allocator.allocated_count(), 5);

        // The new pair should be the released one
        assert_eq!(pair6, pair3);
    }

    #[test]
    fn test_allocator_exhaustion() {
        let allocator = PortAllocator::with_range(10000..10004);

        // Allocate all available pairs (2 pairs: 10000/10001 and 10002/10003)
        let _pair1 = allocator.allocate().unwrap();
        let _pair2 = allocator.allocate().unwrap();

        // Next allocation should fail
        let result = allocator.allocate();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_allocated() {
        let allocator = PortAllocator::new();

        let pair = allocator.allocate().unwrap();

        assert!(allocator.is_allocated(pair));

        allocator.release(pair).unwrap();

        assert!(!allocator.is_allocated(pair));
    }

    #[test]
    fn test_clear() {
        let allocator = PortAllocator::new();

        allocator.allocate().unwrap();
        allocator.allocate().unwrap();
        allocator.allocate().unwrap();

        assert_eq!(allocator.allocated_count(), 3);

        allocator.clear().unwrap();

        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn test_port_pair_new() {
        let pair = PortPair::new(10000).unwrap();
        assert_eq!(pair.rtp, 10000);
        assert_eq!(pair.rtcp, 10001);
        assert!(pair.is_valid());
    }

    #[test]
    fn test_port_pair_new_odd_fails() {
        let result = PortPair::new(10001);
        assert!(result.is_err());
    }

    #[test]
    fn test_port_pair_is_valid() {
        let valid = PortPair {
            rtp: 10000,
            rtcp: 10001,
        };
        assert!(valid.is_valid());

        let invalid = PortPair {
            rtp: 10001,
            rtcp: 10002,
        };
        assert!(!invalid.is_valid());

        let invalid2 = PortPair {
            rtp: 10000,
            rtcp: 10003,
        };
        assert!(!invalid2.is_valid());
    }

    #[test]
    fn test_custom_range() {
        let allocator = PortAllocator::with_range(20000..30000);

        let pair = allocator.allocate().unwrap();

        assert!(pair.rtp >= 20000);
        assert!(pair.rtp < 30000);
    }
}
