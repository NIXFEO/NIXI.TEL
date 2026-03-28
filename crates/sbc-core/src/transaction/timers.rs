//! SIP Transaction Timers (RFC 3261 Section 17)
//!
//! Implements all RFC 3261 timers for retransmissions and timeouts

use std::time::Duration;

/// SIP Timer values (RFC 3261 Section 17.1.1.1)
///
/// T1: RTT Estimate (default 500ms)
/// T2: Maximum retransmit interval for non-INVITE (default 4s)
/// T4: Maximum duration a message remains in network (default 5s)
#[derive(Debug, Clone, Copy)]
pub struct SipTimers {
    /// T1: RTT Estimate (500ms)
    pub t1: Duration,

    /// T2: Maximum retransmit interval (4s)
    pub t2: Duration,

    /// T4: Maximum duration message remains in network (5s)
    pub t4: Duration,
}

impl Default for SipTimers {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

impl SipTimers {
    /// Create new SIP timers with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Timer A: Initial INVITE retransmit interval (T1)
    /// Used for: INVITE request retransmissions in Calling state
    pub fn timer_a(&self) -> Duration {
        self.t1
    }

    /// Timer B: INVITE transaction timeout (64*T1 = 32s)
    /// Used for: Maximum time to wait for INVITE response
    pub fn timer_b(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer D: Wait time for response retransmits (>= 32s for unreliable, 0 for reliable)
    /// Used for: How long to stay in Completed state for INVITE client
    pub fn timer_d(&self, reliable_transport: bool) -> Duration {
        if reliable_transport {
            Duration::from_secs(0)
        } else {
            Duration::from_secs(32) // >= 32s for unreliable
        }
    }

    /// Timer E: Initial non-INVITE retransmit interval (T1)
    /// Used for: Non-INVITE request retransmissions in Trying state
    pub fn timer_e(&self) -> Duration {
        self.t1
    }

    /// Timer F: Non-INVITE transaction timeout (64*T1 = 32s)
    /// Used for: Maximum time to wait for non-INVITE response
    pub fn timer_f(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer G: Initial INVITE response retransmit interval (T1)
    /// Used for: INVITE response retransmissions in Completed state
    pub fn timer_g(&self) -> Duration {
        self.t1
    }

    /// Timer H: Wait time for ACK receipt (64*T1 = 32s)
    /// Used for: How long to wait for ACK after sending final response
    pub fn timer_h(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer I: Wait time for ACK retransmits (T4 = 5s for unreliable, 0 for reliable)
    /// Used for: How long to stay in Confirmed state
    pub fn timer_i(&self, reliable_transport: bool) -> Duration {
        if reliable_transport {
            Duration::from_secs(0)
        } else {
            self.t4
        }
    }

    /// Timer J: Wait time for non-INVITE response retransmits (64*T1 = 32s)
    /// Used for: How long to stay in Completed state for non-INVITE
    pub fn timer_j(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer K: Wait time for response retransmits (T4 = 5s)
    /// Used for: How long client stays in Completed state for non-INVITE
    pub fn timer_k(&self) -> Duration {
        self.t4
    }

    /// Calculate next retransmission interval (exponential backoff)
    /// Doubles each time up to T2 (4s)
    pub fn next_retransmit_interval(&self, current: Duration) -> Duration {
        let next = current * 2;
        if next > self.t2 {
            self.t2
        } else {
            next
        }
    }
}

/// Retransmission scheduler for transactions
#[derive(Debug, Clone)]
pub struct RetransmitScheduler {
    /// Current retransmit interval
    current_interval: Duration,

    /// Number of retransmissions sent
    retransmit_count: u32,

    /// Maximum retransmissions allowed
    max_retransmits: u32,

    /// SIP timers configuration
    timers: SipTimers,
}

impl RetransmitScheduler {
    /// Create new retransmit scheduler for INVITE client transaction
    pub fn new_invite_client() -> Self {
        let timers = SipTimers::new();
        Self {
            current_interval: timers.timer_a(),
            retransmit_count: 0,
            max_retransmits: 6, // Will reach Timer B (32s) after 6 retransmits
            timers,
        }
    }

    /// Create new retransmit scheduler for non-INVITE client transaction
    pub fn new_non_invite_client() -> Self {
        let timers = SipTimers::new();
        Self {
            current_interval: timers.timer_e(),
            retransmit_count: 0,
            max_retransmits: 10, // Exponential backoff with cap at T2
            timers,
        }
    }

    /// Create new retransmit scheduler for INVITE server transaction
    pub fn new_invite_server() -> Self {
        let timers = SipTimers::new();
        Self {
            current_interval: timers.timer_g(),
            retransmit_count: 0,
            max_retransmits: 6, // Will reach Timer H (32s)
            timers,
        }
    }

    /// Create new retransmit scheduler for non-INVITE server transaction
    pub fn new_non_invite_server() -> Self {
        let timers = SipTimers::new();
        Self {
            current_interval: timers.timer_e(),
            retransmit_count: 0,
            max_retransmits: 10,
            timers,
        }
    }

    /// Get current retransmit interval
    pub fn current_interval(&self) -> Duration {
        self.current_interval
    }

    /// Get number of retransmissions sent
    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    /// Check if should retransmit
    pub fn should_retransmit(&self) -> bool {
        self.retransmit_count < self.max_retransmits
    }

    /// Record a retransmission and calculate next interval
    pub fn record_retransmit(&mut self) {
        self.retransmit_count += 1;
        self.current_interval = self.timers.next_retransmit_interval(self.current_interval);
    }

    /// Reset the scheduler
    pub fn reset(&mut self) {
        self.retransmit_count = 0;
        self.current_interval = self.timers.timer_a();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timer_values() {
        let timers = SipTimers::default();
        assert_eq!(timers.t1, Duration::from_millis(500));
        assert_eq!(timers.t2, Duration::from_secs(4));
        assert_eq!(timers.t4, Duration::from_secs(5));
    }

    #[test]
    fn test_timer_a() {
        let timers = SipTimers::new();
        assert_eq!(timers.timer_a(), Duration::from_millis(500));
    }

    #[test]
    fn test_timer_b() {
        let timers = SipTimers::new();
        // 64 * 500ms = 32s
        assert_eq!(timers.timer_b(), Duration::from_secs(32));
    }

    #[test]
    fn test_timer_d_unreliable() {
        let timers = SipTimers::new();
        assert_eq!(timers.timer_d(false), Duration::from_secs(32));
    }

    #[test]
    fn test_timer_d_reliable() {
        let timers = SipTimers::new();
        assert_eq!(timers.timer_d(true), Duration::from_secs(0));
    }

    #[test]
    fn test_exponential_backoff() {
        let timers = SipTimers::new();

        let interval1 = Duration::from_millis(500);
        let interval2 = timers.next_retransmit_interval(interval1);
        assert_eq!(interval2, Duration::from_millis(1000));

        let interval3 = timers.next_retransmit_interval(interval2);
        assert_eq!(interval3, Duration::from_millis(2000));

        let interval4 = timers.next_retransmit_interval(interval3);
        assert_eq!(interval4, Duration::from_millis(4000)); // T2

        let interval5 = timers.next_retransmit_interval(interval4);
        assert_eq!(interval5, Duration::from_millis(4000)); // Capped at T2
    }

    #[test]
    fn test_retransmit_scheduler_invite() {
        let mut scheduler = RetransmitScheduler::new_invite_client();

        assert_eq!(scheduler.current_interval(), Duration::from_millis(500));
        assert_eq!(scheduler.retransmit_count(), 0);
        assert!(scheduler.should_retransmit());

        scheduler.record_retransmit();
        assert_eq!(scheduler.retransmit_count(), 1);
        assert_eq!(scheduler.current_interval(), Duration::from_millis(1000));
    }

    #[test]
    fn test_retransmit_scheduler_max_retransmits() {
        let mut scheduler = RetransmitScheduler::new_invite_client();

        for _ in 0..6 {
            assert!(scheduler.should_retransmit());
            scheduler.record_retransmit();
        }

        assert_eq!(scheduler.retransmit_count(), 6);
        assert!(!scheduler.should_retransmit());
    }

    #[test]
    fn test_retransmit_scheduler_reset() {
        let mut scheduler = RetransmitScheduler::new_invite_client();

        scheduler.record_retransmit();
        scheduler.record_retransmit();
        assert_eq!(scheduler.retransmit_count(), 2);

        scheduler.reset();
        assert_eq!(scheduler.retransmit_count(), 0);
        assert_eq!(scheduler.current_interval(), Duration::from_millis(500));
    }
}
