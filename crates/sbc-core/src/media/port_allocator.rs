//! Port Allocator for RTP/RTCP
//!
//! Manages a pool of UDP ports for RTP media streams.
//! RTP uses even ports, RTCP uses odd ports (RTP port + 1).
//!
//! Allocation walks **forward** from a cursor and a released pair is held in
//! quarantine for `hold` before it can be handed out again. Reusing a pair
//! immediately (the previous behaviour: lowest free port first) means the
//! next call inherits whatever the previous peer is still sending to that
//! port — stray RTP that can latch an endpoint, refresh an inactivity timer
//! or be relayed as audio — and it races the relay task, which still owns
//! the bound sockets when `terminate_session` releases the pair.

use crate::{Error, Result};
use std::collections::{HashSet, VecDeque};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a released pair is held before it can be reused again in
/// production. Long enough to outlive a peer's retransmission burst, short
/// relative to the default 5000-pair range.
pub const DEFAULT_PORT_HOLD: Duration = Duration::from_secs(30);

/// Port Allocator for RTP/RTCP pairs
pub struct PortAllocator {
    /// Range of ports available for allocation
    port_range: Range<u16>,

    /// Ports that must not be handed out: in use, or in quarantine.
    allocated: Arc<Mutex<HashSet<u16>>>,

    /// Released pairs waiting out `hold`, oldest first.
    quarantine: Arc<Mutex<VecDeque<(PortPair, Instant)>>>,

    /// How long a released pair waits. `ZERO` disables quarantine (tests
    /// and small ranges).
    hold: Duration,

    /// Next RTP port to try, so allocation does not favour the pair that
    /// was freed a millisecond ago.
    cursor: Arc<Mutex<u16>>,

    /// Pairs handed out before their hold elapsed because the range was
    /// exhausted (an operator signal: the range is too small).
    forced: Arc<AtomicU64>,
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

    /// Create a new port allocator with custom range and **no**
    /// quarantine (immediate reuse).
    pub fn with_range(port_range: Range<u16>) -> Self {
        Self::with_range_and_hold(port_range, Duration::ZERO)
    }

    /// Create a new port allocator whose released pairs wait `hold` before
    /// they can be reused.
    pub fn with_range_and_hold(port_range: Range<u16>, hold: Duration) -> Self {
        let start = port_range.start;
        Self {
            port_range,
            allocated: Arc::new(Mutex::new(HashSet::new())),
            quarantine: Arc::new(Mutex::new(VecDeque::new())),
            hold,
            cursor: Arc::new(Mutex::new(start)),
            forced: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Allocate a new RTP/RTCP port pair
    ///
    /// Returns a pair where RTP is even and RTCP is RTP+1
    pub fn allocate(&self) -> Result<PortPair> {
        let now = Instant::now();
        self.sweep_quarantine(now)?;
        {
            let mut allocated = self
                .allocated
                .lock()
                .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
            let mut cursor = self
                .cursor
                .lock()
                .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;

            // One forward sweep from the cursor, wrapping once: a pair that
            // was just freed sits at the back of the queue, not the front.
            let first = Self::even_at_or_after(self.port_range.start);
            let start = Self::even_at_or_after((*cursor).max(self.port_range.start));
            let mut rtp_port = start;
            let mut wrapped = false;
            loop {
                if rtp_port.checked_add(1).is_none() || rtp_port + 1 >= self.port_range.end {
                    if wrapped {
                        break;
                    }
                    wrapped = true;
                    rtp_port = first;
                    continue;
                }
                let rtcp_port = rtp_port + 1;
                if !allocated.contains(&rtp_port) && !allocated.contains(&rtcp_port) {
                    allocated.insert(rtp_port);
                    allocated.insert(rtcp_port);
                    *cursor = rtp_port.saturating_add(2);
                    return Ok(PortPair {
                        rtp: rtp_port,
                        rtcp: rtcp_port,
                    });
                }
                if wrapped && rtp_port >= start {
                    break;
                }
                rtp_port += 2;
            }
        }

        // Nothing free: take the pair that has been in quarantine longest
        // rather than fail a call, and count it.
        let oldest = {
            let mut q = self
                .quarantine
                .lock()
                .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
            q.pop_front().map(|(pair, _)| pair)
        };
        if let Some(pair) = oldest {
            self.forced.fetch_add(1, Ordering::Relaxed);
            return Ok(pair);
        }
        Err(Error::Transport("No available ports in range".to_string()))
    }

    /// Give back the pairs whose hold has elapsed.
    fn sweep_quarantine(&self, now: Instant) -> Result<()> {
        let mut q = self
            .quarantine
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
        if q.is_empty() {
            return Ok(());
        }
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
        while let Some((pair, freed_at)) = q.front().copied() {
            if now.duration_since(freed_at) < self.hold {
                break;
            }
            q.pop_front();
            allocated.remove(&pair.rtp);
            allocated.remove(&pair.rtcp);
        }
        Ok(())
    }

    fn even_at_or_after(port: u16) -> u16 {
        if port.is_multiple_of(2) {
            port
        } else {
            port.saturating_add(1)
        }
    }

    /// Expire what is due. `allocate` does this itself; the 60 s sweeper
    /// calls it too, so the pool's reported state decays even when no
    /// call starts.
    pub fn sweep(&self) {
        let _ = self.sweep_quarantine(Instant::now());
    }

    /// Pairs waiting out their hold (swept first, so the count is live).
    pub fn quarantined_count(&self) -> usize {
        self.sweep();
        self.quarantine.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Pairs reused before their hold elapsed (range too small).
    pub fn forced_reuse_count(&self) -> u64 {
        self.forced.load(Ordering::Relaxed)
    }

    /// Release a port pair
    pub fn release(&self, pair: PortPair) -> Result<()> {
        if self.hold.is_zero() {
            let mut allocated = self
                .allocated
                .lock()
                .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
            allocated.remove(&pair.rtp);
            allocated.remove(&pair.rtcp);
            return Ok(());
        }
        // Stays "allocated" (nothing else may bind it) until its hold is up.
        let mut q = self
            .quarantine
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
        if !q.iter().any(|(p, _)| *p == pair) {
            q.push_back((pair, Instant::now()));
        }
        Ok(())
    }

    /// Get number of allocated port pairs
    pub fn allocated_count(&self) -> usize {
        self.allocated.lock().map(|a| a.len() / 2).unwrap_or(0)
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

    /// Clear all allocations (and the quarantine, and the cursor — a
    /// cursor left past the range would brick the allocator).
    pub fn clear(&self) -> Result<()> {
        let mut allocated = self
            .allocated
            .lock()
            .map_err(|e| Error::Transport(format!("Lock error: {}", e)))?;
        allocated.clear();
        if let Ok(mut q) = self.quarantine.lock() {
            q.clear();
        }
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = self.port_range.start;
        }
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
        if !rtp.is_multiple_of(2) {
            return Err(Error::Transport("RTP port must be even".to_string()));
        }

        Ok(Self { rtp, rtcp: rtp + 1 })
    }

    /// Check if this is a valid port pair
    pub fn is_valid(&self) -> bool {
        self.rtp.is_multiple_of(2) && self.rtcp == self.rtp + 1
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
        let _pair1 = allocator.allocate().unwrap();
        let _pair2 = allocator.allocate().unwrap();
        let pair3 = allocator.allocate().unwrap();
        let _pair4 = allocator.allocate().unwrap();
        let _pair5 = allocator.allocate().unwrap();

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

    /// A pair freed a moment ago must not be the next one handed out: the
    /// previous peer may still be sending to it.
    #[test]
    fn a_released_pair_waits_out_its_hold() {
        let allocator = PortAllocator::with_range_and_hold(10000..10010, Duration::from_secs(30));
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        assert_ne!(first, second);

        allocator.release(first).unwrap();
        assert_eq!(allocator.quarantined_count(), 1);
        // Still counted as unavailable while it waits.
        assert!(allocator.is_allocated(first));

        let next = allocator.allocate().unwrap();
        assert_ne!(next, first, "the freed pair was handed straight back");
        assert_ne!(next, second);
        assert_eq!(allocator.forced_reuse_count(), 0);
    }

    /// An exhausted range takes the oldest quarantined pair rather than
    /// failing the call, and says so.
    #[test]
    fn an_exhausted_range_forces_the_oldest_quarantined_pair() {
        let allocator = PortAllocator::with_range_and_hold(10000..10004, Duration::from_secs(30));
        let a = allocator.allocate().unwrap();
        let b = allocator.allocate().unwrap();
        assert!(allocator.allocate().is_err(), "range is full");

        allocator.release(a).unwrap();
        allocator.release(b).unwrap();
        let forced = allocator.allocate().unwrap();
        assert_eq!(forced, a, "the oldest quarantined pair comes first");
        assert_eq!(allocator.forced_reuse_count(), 1);
        assert_eq!(allocator.quarantined_count(), 1);
    }

    /// A hold of zero keeps the old behaviour (what the test harnesses and
    /// their 20-pair ranges rely on).
    #[test]
    fn a_zero_hold_reuses_immediately() {
        let allocator = PortAllocator::with_range(10000..10004);
        let a = allocator.allocate().unwrap();
        allocator.release(a).unwrap();
        assert_eq!(allocator.quarantined_count(), 0);
        assert!(!allocator.is_allocated(a));
        let again = allocator.allocate().unwrap();
        assert!(again == a || again.rtp == a.rtp + 2);
    }

    /// `clear()` must put the cursor back, or the allocator never finds a
    /// port again.
    #[test]
    fn clear_resets_the_cursor_and_the_quarantine() {
        let allocator = PortAllocator::with_range_and_hold(10000..10010, Duration::from_secs(30));
        for _ in 0..5 {
            allocator.allocate().unwrap();
        }
        assert!(allocator.allocate().is_err());
        allocator.clear().unwrap();
        assert_eq!(allocator.quarantined_count(), 0);
        let pair = allocator.allocate().unwrap();
        assert_eq!(pair.rtp, 10000, "allocation starts over");
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
