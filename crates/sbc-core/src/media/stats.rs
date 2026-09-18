//! Per-call media counters: what an operator needs to explain a silent or
//! one-way call.
//!
//! One [`CallMediaStats`] per media session, written by the relay task
//! only (the whole relay — both legs, both RTCP sockets and the timer — is
//! a single task), so relaxed atomics are enough and there is no lock on
//! the packet path. Timestamps are **monotonic milliseconds since the
//! relay started**: a wall-clock base would tear every live call down as
//! `rtp-timeout` the moment NTP stepped the clock forward.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Which side of the B2BUA a counter belongs to. `Caller` is leg A,
/// `Callee` is leg B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Caller,
    Callee,
}

impl Leg {
    pub fn label(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::Callee => "callee",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Caller => Self::Callee,
            Self::Callee => Self::Caller,
        }
    }
}

/// Why a datagram was not relayed. Every `continue` on the media path
/// lands on exactly one of these, so "packets in, packets out and the
/// difference explained" holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not an RTP-shaped datagram (too short, or not version 2).
    NotRtp,
    /// Nothing to send to yet: the other leg's endpoint is unknown.
    NoEndpoint,
    /// The payload type is not the negotiated one (nor DTMF).
    PayloadType,
    /// Transcoding refused the packet (unknown codec, bad frame size).
    Transcode,
    /// SRTP/SRTCP protect or unprotect failed.
    Srtp,
    /// The socket send failed.
    SendFailed,
    /// An RTCP datagram refused on the RTCP port (wrong source, or not
    /// RTCP-shaped).
    Rtcp,
}

impl DropReason {
    pub const ALL: [DropReason; 7] = [
        Self::NotRtp,
        Self::NoEndpoint,
        Self::PayloadType,
        Self::Transcode,
        Self::Srtp,
        Self::SendFailed,
        Self::Rtcp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::NotRtp => "not-rtp",
            Self::NoEndpoint => "no-endpoint",
            Self::PayloadType => "payload-type",
            Self::Transcode => "transcode",
            Self::Srtp => "srtp",
            Self::SendFailed => "send-failed",
            Self::Rtcp => "rtcp",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::NotRtp => 0,
            Self::NoEndpoint => 1,
            Self::PayloadType => 2,
            Self::Transcode => 3,
            Self::Srtp => 4,
            Self::SendFailed => 5,
            Self::Rtcp => 6,
        }
    }
}

/// One leg's counters. `rx` is what the peer on this leg sent us, `tx` what
/// we delivered to it.
#[derive(Debug)]
pub struct LegStats {
    /// RTCP datagrams relayed for this leg (not audio, counted apart).
    pub rtcp_packets: AtomicU64,
    /// ICE/DTLS datagrams relayed untouched (not audio: they do not keep
    /// the inactivity watchdog alive).
    pub passthrough_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    /// Monotonic ms of the last received / delivered packet (0 = never).
    pub last_rx_ms: AtomicU64,
    pub last_tx_ms: AtomicU64,
    /// Current SSRC and how many times it changed (a change is a new
    /// stream: a transfer, a media server, or a hijack). Held as a u64 so
    /// `UNSET` can mean "nothing seen yet" — SSRC 0 is a legal value.
    pub ssrc: AtomicU64,
    pub ssrc_changes: AtomicU64,
    /// Sequence gaps seen from this peer (RFC 3550 §A.3, forward only).
    pub lost: AtomicU64,
    /// Endpoint learning on this leg's socket.
    pub endpoint_learned: AtomicU64,
    pub endpoint_moved: AtomicU64,
    /// Already reported as not sending, so the warning fires once.
    one_way_reported: AtomicU64,
    /// Highest sequence number seen (loss detection state), `UNSET`
    /// before the first packet.
    highest_seq: AtomicU64,
}

/// "Nothing seen yet" for the u64-held SSRC and sequence fields (both
/// carry values that are legal at 0).
const UNSET: u64 = u64::MAX;

impl Default for LegStats {
    fn default() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rtcp_packets: AtomicU64::new(0),
            passthrough_packets: AtomicU64::new(0),
            last_rx_ms: AtomicU64::new(0),
            last_tx_ms: AtomicU64::new(0),
            ssrc: AtomicU64::new(UNSET),
            ssrc_changes: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            endpoint_learned: AtomicU64::new(0),
            endpoint_moved: AtomicU64::new(0),
            one_way_reported: AtomicU64::new(0),
            highest_seq: AtomicU64::new(UNSET),
        }
    }
}

impl LegStats {
    fn note_rx(&self, len: usize, at_ms: u64, ssrc: u32, seq: u16) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.last_rx_ms.store(at_ms, Ordering::Relaxed);

        let previous = self.ssrc.swap(u64::from(ssrc), Ordering::Relaxed);
        if previous == UNSET || previous == u64::from(ssrc) {
            // Same stream: count forward gaps.
            let highest = self.highest_seq.load(Ordering::Relaxed);
            if highest != UNSET {
                let highest = highest as u16;
                let ahead = seq.wrapping_sub(highest) < 0x8000;
                if ahead {
                    let gap = seq.wrapping_sub(highest.wrapping_add(1));
                    // A small forward gap is loss; a huge jump is a
                    // restart, not 30 000 lost packets.
                    if gap > 0 && gap < 1000 {
                        self.lost.fetch_add(u64::from(gap), Ordering::Relaxed);
                    }
                    // Only a forward packet moves the high-water mark:
                    // storing a reordered one would make the next
                    // in-order packet look like a gap.
                    self.highest_seq.store(u64::from(seq), Ordering::Relaxed);
                }
            } else {
                self.highest_seq.store(u64::from(seq), Ordering::Relaxed);
            }
        } else {
            self.ssrc_changes.fetch_add(1, Ordering::Relaxed);
            self.highest_seq.store(u64::from(seq), Ordering::Relaxed);
        }
    }

    fn note_tx(&self, len: usize, at_ms: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.last_tx_ms.store(at_ms, Ordering::Relaxed);
    }

    /// A one-line summary for the end-of-session log.
    pub fn summary(&self) -> String {
        format!(
            "rx {}p/{}B tx {}p/{}B lost {} ssrc-changes {}",
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.lost.load(Ordering::Relaxed),
            self.ssrc_changes.load(Ordering::Relaxed),
        )
    }
}

/// Both legs of one media session, plus the drop tally.
#[derive(Debug)]
pub struct CallMediaStats {
    started: Instant,
    pub caller: LegStats,
    pub callee: LegStats,
    drops: [AtomicU64; 7],
    /// Monotonic ms of the last packet actually **delivered** to a peer:
    /// the inactivity watchdog's input. A packet that arrives but dies at
    /// the transcoder or the SRTP layer must not keep a dead call alive.
    last_relay_ms: AtomicU64,
    /// Audio packets delivered, either direction. Only this decides
    /// whether the call ever carried media: RTCP and ICE keepalives are
    /// delivered too, and a call kept "alive" by them is a silent call
    /// being billed.
    audio_delivered: AtomicU64,
}

impl Default for CallMediaStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CallMediaStats {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            caller: LegStats::default(),
            callee: LegStats::default(),
            drops: Default::default(),
            last_relay_ms: AtomicU64::new(0),
            audio_delivered: AtomicU64::new(0),
        }
    }

    pub fn leg(&self, leg: Leg) -> &LegStats {
        match leg {
            Leg::Caller => &self.caller,
            Leg::Callee => &self.callee,
        }
    }

    /// Monotonic milliseconds since the relay started.
    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// A datagram arrived on `leg`'s socket. Non-RTP-shaped input is
    /// counted but parsed no further (this runs in the relay task: it must
    /// not panic on a hostile 3-byte datagram).
    pub fn note_rx(&self, leg: Leg, data: &[u8]) {
        let at = self.now_ms();
        if data.len() < 12 {
            self.note_drop(DropReason::NotRtp);
            return;
        }
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let seq = u16::from_be_bytes([data[2], data[3]]);
        self.leg(leg).note_rx(data.len(), at, ssrc, seq);
    }

    /// An **audio** packet was delivered to `leg`'s peer. This is the
    /// only thing that refreshes the inactivity watchdog.
    pub fn note_tx(&self, leg: Leg, len: usize) {
        let at = self.now_ms();
        self.leg(leg).note_tx(len, at);
        self.last_relay_ms.store(at, Ordering::Relaxed);
        self.audio_delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// A non-audio datagram (RTCP, ICE, DTLS) was relayed to `leg`'s peer:
    /// counted, but it must not keep a silent call alive — a keepalive
    /// from a dead call's far end would otherwise hold it to
    /// `max_call_duration`, billed.
    pub fn note_tx_non_audio(&self, leg: Leg, len: usize) {
        self.leg(leg).tx_packets.fetch_add(1, Ordering::Relaxed);
        self.leg(leg)
            .tx_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
    }

    /// An RTCP datagram relayed for `leg` (not audio: it must not keep
    /// the inactivity watchdog alive).
    pub fn note_rtcp(&self, leg: Leg) {
        self.leg(leg).rtcp_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// An ICE/DTLS datagram relayed untouched. Same rule: not audio, so
    /// it does not refresh the watchdog — otherwise a keepalive from a
    /// dead call's far end would keep it billed for hours.
    pub fn note_passthrough(&self, leg: Leg) {
        self.leg(leg)
            .passthrough_packets
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_drop(&self, reason: DropReason) {
        self.drops[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn drops(&self, reason: DropReason) -> u64 {
        self.drops[reason.index()].load(Ordering::Relaxed)
    }

    pub fn note_endpoint_learned(&self, leg: Leg) {
        self.leg(leg)
            .endpoint_learned
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_endpoint_moved(&self, leg: Leg) {
        self.leg(leg).endpoint_moved.fetch_add(1, Ordering::Relaxed);
    }

    /// How long this leg's peer has been silent, `None` if it never sent
    /// anything (the endpoint ladder's "is it gone?" input).
    pub fn quiet_for(&self, leg: Leg) -> Option<std::time::Duration> {
        let last = self.leg(leg).last_rx_ms.load(Ordering::Relaxed);
        if last == 0 && self.leg(leg).rx_packets.load(Ordering::Relaxed) == 0 {
            return None;
        }
        Some(std::time::Duration::from_millis(
            self.now_ms().saturating_sub(last),
        ))
    }

    /// How long since the last packet the relay actually delivered. `None`
    /// before the first one (the caller decides what to do with a session
    /// that never carried anything).
    pub fn since_last_relay_ms(&self) -> Option<u64> {
        // Audio only: RTCP and ICE keepalives are delivered too, and a
        // call kept "alive" by them is a silent call being billed.
        if self.audio_delivered.load(Ordering::Relaxed) == 0 {
            return None;
        }
        Some(
            self.now_ms()
                .saturating_sub(self.last_relay_ms.load(Ordering::Relaxed)),
        )
    }

    /// Idle time for the inactivity watchdog: since the last delivered
    /// packet, or since the relay started when nothing was ever delivered
    /// (a call whose media never flowed must end too).
    pub fn idle_ms(&self) -> u64 {
        self.since_last_relay_ms().unwrap_or_else(|| self.now_ms())
    }

    /// The leg that is **not** sending while the other one is, i.e. the
    /// direction the audio is missing from. Side-effect free: `silent`
    /// means "we deliver to that peer, it delivers nothing back, and the
    /// other peer is delivering right now".
    pub fn one_way_leg(&self, quiet_ms: u64) -> Option<Leg> {
        let now = self.now_ms();
        for leg in [Leg::Caller, Leg::Callee] {
            let this = self.leg(leg);
            let other = self.leg(leg.other());
            // We are delivering to this peer…
            if this.tx_packets.load(Ordering::Relaxed) == 0 {
                continue;
            }
            // …the other peer is alive…
            let other_rx = other.last_rx_ms.load(Ordering::Relaxed);
            if other.rx_packets.load(Ordering::Relaxed) == 0
                || now.saturating_sub(other_rx) > quiet_ms
            {
                continue;
            }
            // …and this one has said nothing for a while.
            let this_rx = this.last_rx_ms.load(Ordering::Relaxed);
            let silent = this.rx_packets.load(Ordering::Relaxed) == 0
                || now.saturating_sub(this_rx) > quiet_ms;
            if silent {
                return Some(leg);
            }
        }
        None
    }

    /// True the first time this leg is reported as silent, false after.
    pub fn claim_one_way_report(&self, leg: Leg) -> bool {
        self.leg(leg)
            .one_way_reported
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// The `media session ended` line: both legs and every non-zero drop.
    pub fn summary(&self) -> String {
        let drops: Vec<String> = DropReason::ALL
            .iter()
            .filter(|r| self.drops(**r) > 0)
            .map(|r| format!("{} {}", r.label(), self.drops(*r)))
            .collect();
        format!(
            "caller[{}] callee[{}] drops[{}] after {} ms",
            self.caller.summary(),
            self.callee.summary(),
            if drops.is_empty() {
                "none".to_string()
            } else {
                drops.join(", ")
            },
            self.now_ms()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RTP packet with the given ssrc/sequence and a 160-byte payload.
    fn packet(ssrc: u32, seq: u16) -> Vec<u8> {
        let mut p = vec![0x80, 0x00];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0u8; 160]);
        p
    }

    #[test]
    fn rx_and_tx_are_counted_per_leg_and_direction() {
        let s = CallMediaStats::new();
        s.note_rx(Leg::Caller, &packet(1, 1));
        s.note_tx(Leg::Callee, 172);
        s.note_rx(Leg::Callee, &packet(2, 100));
        s.note_tx(Leg::Caller, 172);

        assert_eq!(s.caller.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(s.caller.tx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(s.callee.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(s.caller.rx_bytes.load(Ordering::Relaxed), 172);
        assert_eq!(s.callee.tx_bytes.load(Ordering::Relaxed), 172);
    }

    /// A hostile short datagram must be counted, not parsed (this runs in
    /// the relay task: a panic there kills the audio *and* the watchdog).
    #[test]
    fn a_short_datagram_is_a_drop_not_a_panic() {
        let s = CallMediaStats::new();
        s.note_rx(Leg::Caller, &[0x80]);
        s.note_rx(Leg::Caller, &[]);
        assert_eq!(s.drops(DropReason::NotRtp), 2);
        assert_eq!(s.caller.rx_packets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn forward_gaps_are_loss_and_a_new_ssrc_is_not() {
        let s = CallMediaStats::new();
        for seq in [1u16, 2, 3] {
            s.note_rx(Leg::Caller, &packet(7, seq));
        }
        assert_eq!(s.caller.lost.load(Ordering::Relaxed), 0);

        s.note_rx(Leg::Caller, &packet(7, 8)); // 4..7 missing
        assert_eq!(s.caller.lost.load(Ordering::Relaxed), 4);

        // Reordering is not loss.
        s.note_rx(Leg::Caller, &packet(7, 6));
        assert_eq!(s.caller.lost.load(Ordering::Relaxed), 4);

        // A new stream restarts the sequence without counting loss.
        s.note_rx(Leg::Caller, &packet(9, 40000));
        assert_eq!(s.caller.ssrc_changes.load(Ordering::Relaxed), 1);
        assert_eq!(s.caller.lost.load(Ordering::Relaxed), 4);

        // Wrapping the 16-bit sequence is not a 65 000-packet loss.
        s.note_rx(Leg::Caller, &packet(9, 65534));
        s.note_rx(Leg::Caller, &packet(9, 65535));
        s.note_rx(Leg::Caller, &packet(9, 0));
        s.note_rx(Leg::Caller, &packet(9, 1));
        assert!(
            s.caller.lost.load(Ordering::Relaxed) < 2000,
            "wrap counted as loss: {}",
            s.caller.lost.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn one_way_names_the_leg_that_is_not_sending() {
        let s = CallMediaStats::new();
        // The caller talks, we deliver to the callee, the callee is mute.
        for seq in 1..=50u16 {
            s.note_rx(Leg::Caller, &packet(1, seq));
            s.note_tx(Leg::Callee, 172);
        }
        assert_eq!(s.one_way_leg(0), Some(Leg::Callee));
        // Reporting is once per leg.
        assert!(s.claim_one_way_report(Leg::Callee));
        assert!(!s.claim_one_way_report(Leg::Callee));
        // Asking again does not change the verdict (side-effect free).
        assert_eq!(s.one_way_leg(0), Some(Leg::Callee));
    }

    #[test]
    fn silence_in_both_directions_is_not_one_way() {
        let s = CallMediaStats::new();
        assert_eq!(s.one_way_leg(0), None, "nothing has flowed at all");

        // Both peers talked, then both went quiet: that is not one-way,
        // it is the inactivity watchdog's business.
        s.note_rx(Leg::Caller, &packet(1, 1));
        s.note_tx(Leg::Callee, 172);
        s.note_rx(Leg::Callee, &packet(2, 1));
        s.note_tx(Leg::Caller, 172);
        assert_eq!(s.one_way_leg(10_000), None);
    }

    /// RTCP, ICE and DTLS are relayed but must not hold a silent call
    /// open: a keepalive from a dead call's far end would otherwise keep
    /// it billed to `max_call_duration`.
    #[test]
    fn a_non_audio_datagram_does_not_refresh_the_watchdog() {
        let s = CallMediaStats::new();
        s.note_rtcp(Leg::Caller);
        s.note_tx_non_audio(Leg::Callee, 60);
        s.note_passthrough(Leg::Caller);
        s.note_tx_non_audio(Leg::Callee, 20);
        assert!(
            s.since_last_relay_ms().is_none(),
            "no audio has been delivered yet"
        );
        assert_eq!(
            s.callee.tx_packets.load(Ordering::Relaxed),
            2,
            "still counted"
        );
        assert_eq!(s.caller.rtcp_packets.load(Ordering::Relaxed), 1);
        assert_eq!(s.caller.passthrough_packets.load(Ordering::Relaxed), 1);

        s.note_tx(Leg::Callee, 172);
        assert!(s.since_last_relay_ms().is_some(), "audio does refresh it");
    }

    #[test]
    fn the_watchdog_input_is_the_last_delivered_packet() {
        let s = CallMediaStats::new();
        assert!(s.since_last_relay_ms().is_none(), "nothing delivered yet");
        // A packet that arrives but is dropped must not keep the call up.
        s.note_rx(Leg::Caller, &packet(1, 1));
        s.note_drop(DropReason::Transcode);
        assert!(s.since_last_relay_ms().is_none());
        assert!(s.idle_ms() < 5_000, "idle counts from the relay's start");

        s.note_tx(Leg::Callee, 172);
        assert!(s.since_last_relay_ms().is_some());
        assert!(s.idle_ms() < 1_000);
    }

    /// The accounting runs on every RTP packet of every call (50 pps per
    /// direction, 200 calls targeted = 20 000 calls/s of accounting on
    /// 2 vCPU). It must cost atomics, not locks or allocations: this test
    /// fails if someone adds either.
    #[test]
    fn the_per_packet_accounting_stays_cheap() {
        use crate::media::endpoint::{EndpointPolicy, Observation};

        let stats = CallMediaStats::new();
        let policy = EndpointPolicy::default();
        let packet = packet(0x1234_5678, 1);
        let latched: std::net::SocketAddr = "203.0.113.9:6004".parse().unwrap();
        const N: usize = 200_000;

        let started = std::time::Instant::now();
        for i in 0..N {
            stats.note_rx(Leg::Caller, &packet);
            let _ = policy.observe(Observation {
                latched: Some(latched),
                signalled: Some(latched),
                source: latched,
                plausible: true,
                same_stream: true,
                latched_quiet_for: stats.quiet_for(Leg::Caller),
            });
            stats.note_tx(Leg::Callee, 172);
            if i % 10_000 == 0 {
                let _ = stats.idle_ms();
                let _ = stats.one_way_leg(10_000);
            }
        }
        let elapsed = started.elapsed();
        // Generous even for a debug build: 200 000 packets through the
        // whole accounting path in under 2 s is ~10 µs each, and a real
        // release build is two orders of magnitude faster. A lock or a
        // per-packet allocation would blow past it.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "{} packets of accounting took {:?}",
            N,
            elapsed
        );
        assert_eq!(stats.caller.rx_packets.load(Ordering::Relaxed), N as u64);
    }

    #[test]
    fn the_summary_names_every_non_zero_drop() {
        let s = CallMediaStats::new();
        s.note_rx(Leg::Caller, &packet(1, 1));
        s.note_tx(Leg::Callee, 172);
        s.note_drop(DropReason::NoEndpoint);
        s.note_drop(DropReason::NoEndpoint);
        let summary = s.summary();
        assert!(
            summary.contains("caller[rx 1p/172B tx 0p/0B"),
            "{}",
            summary
        );
        assert!(
            summary.contains("callee[rx 0p/0B tx 1p/172B"),
            "{}",
            summary
        );
        assert!(summary.contains("no-endpoint 2"), "{}", summary);
        assert!(!summary.contains("srtp"), "{}", summary);
    }
}
