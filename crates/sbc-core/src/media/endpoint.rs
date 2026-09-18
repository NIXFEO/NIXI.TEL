//! Where a call's media is allowed to come from.
//!
//! The relay learns each peer's real RTP address from the first packet it
//! sends (the SDP address is often wrong behind NAT). That is necessary
//! and cannot change — but "learn from anyone, for ever" means any source
//! that reaches the port can take the stream over. This module is the
//! decision, as a pure function with an injected clock so it can be
//! tested exhaustively: [`EndpointPolicy::observe`] says whether a
//! datagram may latch the endpoint, move it, or neither.
//!
//! It ships in **count-only** mode first ([`Mode::Observe`]): every
//! verdict is counted, nothing is refused, and the counters say what the
//! real Genesys media path does before any call is at risk. Enforcement
//! ([`Mode::Moves`]) is a later, separate decision.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// How strictly a move is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Count the verdicts, refuse nothing (the deployable first step).
    #[default]
    Observe,
    /// Refuse a move with no evidence behind it.
    Moves,
}

/// Why a datagram was allowed to take (or keep) the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// It is the address the SDP signalled.
    Signalled,
    /// Same host as the signalled address, another port: NAT rebinding.
    SamePort,
    /// Same /24 as the signalled address: a clustered trunk's sibling.
    Sibling,
    /// It carries the SSRC of the stream we are already relaying.
    SameStream,
    /// The latched address has been silent long enough to be gone.
    Quiet,
    /// Nothing was latched yet, so the first plausible packet wins.
    First,
}

impl Match {
    pub fn label(self) -> &'static str {
        match self {
            Self::Signalled => "signalled",
            Self::SamePort => "same-host",
            Self::Sibling => "sibling",
            Self::SameStream => "same-stream",
            Self::Quiet => "quiet",
            Self::First => "first",
        }
    }
}

/// Why a move has no evidence behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Another host entirely, while the latched one is still sending.
    Foreign,
    /// The datagram is not RTP-shaped (it cannot latch anything).
    NotPlausible,
}

impl Reject {
    pub fn label(self) -> &'static str {
        match self {
            Self::Foreign => "foreign",
            Self::NotPlausible => "not-plausible",
        }
    }
}

/// What to do with the datagram's source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing was latched: take this source (`Match::First`).
    Latch(Match),
    /// It is the latched source already: nothing to do.
    Keep,
    /// Move the endpoint here, for this reason.
    Move(Match),
    /// In `Moves` mode the endpoint stays where it is; in `Observe` mode
    /// the move happens anyway and only the counter records it.
    Refuse(Reject),
}

/// The inputs a verdict needs, all cheap to read on the packet path.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// Where the relay currently sends this peer's audio.
    pub latched: Option<SocketAddr>,
    /// What the SDP said, kept from the session's start.
    pub signalled: Option<SocketAddr>,
    /// The datagram's source.
    pub source: SocketAddr,
    /// It has an RTP/RTCP header (`looks_like_rtp`).
    pub plausible: bool,
    /// Its SSRC is the one the latched stream was using.
    pub same_stream: bool,
    /// Since the latched address last sent anything. `None` = never.
    pub latched_quiet_for: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct EndpointPolicy {
    pub mode: Mode,
    /// How long the latched address must be silent before another source
    /// may take over without other evidence.
    pub quiet_period: Duration,
}

impl Default for EndpointPolicy {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            // Longer than any codec's comfort-noise gap, shorter than the
            // inactivity watchdog: a real peer that went away is gone.
            quiet_period: Duration::from_secs(5),
        }
    }
}

impl EndpointPolicy {
    /// The ladder. Pure: no clock, no I/O, no state.
    pub fn observe(&self, o: Observation) -> Verdict {
        if !o.plausible {
            return Verdict::Refuse(Reject::NotPlausible);
        }
        let Some(latched) = o.latched else {
            // First plausible packet wins, whoever sends it: the SDP
            // address is frequently wrong behind NAT, and refusing here
            // would break calls this SBC carries today.
            return Verdict::Latch(Match::First);
        };
        if latched == o.source {
            return Verdict::Keep;
        }
        if Some(o.source) == o.signalled {
            return Verdict::Move(Match::Signalled);
        }
        if let Some(signalled) = o.signalled {
            if signalled.ip() == o.source.ip() {
                return Verdict::Move(Match::SamePort);
            }
            if same_24(signalled.ip(), o.source.ip()) {
                return Verdict::Move(Match::Sibling);
            }
        }
        if latched.ip() == o.source.ip() {
            // The peer we learned, from another port: NAT rebinding.
            return Verdict::Move(Match::SamePort);
        }
        if o.same_stream {
            return Verdict::Move(Match::SameStream);
        }
        match o.latched_quiet_for {
            Some(quiet) if quiet >= self.quiet_period => Verdict::Move(Match::Quiet),
            _ => Verdict::Refuse(Reject::Foreign),
        }
    }

    /// Whether the relay should act on this verdict, given the mode. In
    /// `Observe` mode a refusal is counted but the old behaviour (move
    /// anyway) is kept, so shipping the counters changes no audio.
    pub fn applies(&self, verdict: Verdict) -> bool {
        match verdict {
            Verdict::Refuse(Reject::NotPlausible) => false,
            Verdict::Refuse(Reject::Foreign) => self.mode == Mode::Observe,
            _ => true,
        }
    }
}

/// Same IPv4 /24. IPv6 has no equivalent rule here: it falls through to
/// the other rungs (the trunk-proximity helpers elsewhere in the SBC are
/// IPv4-only too).
fn same_24(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn observation(latched: Option<&str>, source: &str) -> Observation {
        Observation {
            latched: latched.map(addr),
            signalled: Some(addr("203.0.113.9:6004")),
            source: addr(source),
            plausible: true,
            same_stream: false,
            latched_quiet_for: Some(Duration::ZERO),
        }
    }

    /// The property that makes this deployable: a call whose peer sends
    /// from an address the SDP never mentioned still works.
    #[test]
    fn the_first_plausible_packet_latches_from_anyone() {
        let p = EndpointPolicy::default();
        assert_eq!(
            p.observe(observation(None, "198.51.100.77:40000")),
            Verdict::Latch(Match::First)
        );
    }

    #[test]
    fn a_datagram_that_is_not_plausible_latches_nothing() {
        let p = EndpointPolicy::default();
        let o = Observation {
            plausible: false,
            ..observation(None, "203.0.113.9:6004")
        };
        assert_eq!(p.observe(o), Verdict::Refuse(Reject::NotPlausible));
        assert!(!p.applies(p.observe(o)), "never acted on, in any mode");
    }

    #[test]
    fn the_latched_peer_keeps_the_stream() {
        let p = EndpointPolicy::default();
        assert_eq!(
            p.observe(observation(Some("203.0.113.9:6004"), "203.0.113.9:6004")),
            Verdict::Keep
        );
    }

    /// A NATed phone that rebinds its port must not lose its audio.
    #[test]
    fn a_nat_port_change_keeps_the_stream() {
        let p = EndpointPolicy::default();
        assert_eq!(
            p.observe(observation(
                Some("198.51.100.77:40000"),
                "198.51.100.77:40001"
            )),
            Verdict::Move(Match::SamePort)
        );
    }

    /// A clustered trunk answers and sends media from sibling hosts.
    #[test]
    fn a_trunk_sibling_may_take_the_stream() {
        let p = EndpointPolicy::default();
        assert_eq!(
            p.observe(observation(Some("203.0.113.9:6004"), "203.0.113.11:6004")),
            Verdict::Move(Match::Sibling)
        );
    }

    #[test]
    fn the_signalled_address_always_wins() {
        let p = EndpointPolicy::default();
        assert_eq!(
            p.observe(observation(Some("198.51.100.77:40000"), "203.0.113.9:6004")),
            Verdict::Move(Match::Signalled)
        );
    }

    /// The hijack: another host, while the real peer is still sending.
    #[test]
    fn a_foreign_source_is_refused_while_the_peer_is_live() {
        let p = EndpointPolicy::default();
        let o = observation(Some("198.51.100.77:40000"), "192.0.2.66:5000");
        assert_eq!(p.observe(o), Verdict::Refuse(Reject::Foreign));
        // Count-only until the operator has the data: the audio follows
        // the old behaviour.
        assert!(p.applies(p.observe(o)));
        let enforcing = EndpointPolicy {
            mode: Mode::Moves,
            ..EndpointPolicy::default()
        };
        assert!(!enforcing.applies(enforcing.observe(o)));
    }

    /// Same stream from a new address: a media server took over.
    #[test]
    fn the_same_ssrc_may_move_the_endpoint() {
        let p = EndpointPolicy::default();
        let o = Observation {
            same_stream: true,
            ..observation(Some("198.51.100.77:40000"), "192.0.2.66:5000")
        };
        assert_eq!(p.observe(o), Verdict::Move(Match::SameStream));
    }

    /// Once the latched peer has been quiet long enough, anyone may take
    /// over: this is what lets a call recover after a re-INVITE the SBC
    /// did not see.
    #[test]
    fn a_quiet_endpoint_can_be_replaced() {
        let p = EndpointPolicy::default();
        let base = observation(Some("198.51.100.77:40000"), "192.0.2.66:5000");
        assert_eq!(
            p.observe(Observation {
                latched_quiet_for: Some(Duration::from_secs(4)),
                ..base
            }),
            Verdict::Refuse(Reject::Foreign),
            "4 s of silence is not enough"
        );
        assert_eq!(
            p.observe(Observation {
                latched_quiet_for: Some(Duration::from_secs(6)),
                ..base
            }),
            Verdict::Move(Match::Quiet)
        );
        assert_eq!(
            p.observe(Observation {
                latched_quiet_for: None,
                ..base
            }),
            Verdict::Refuse(Reject::Foreign),
            "never heard from: not evidence it is gone"
        );
    }

    /// Without a signalled address (no SDP, or a rejected stream) the
    /// ladder still works from the latched address alone.
    #[test]
    fn no_signalled_address_falls_through_to_the_other_rungs() {
        let p = EndpointPolicy::default();
        let o = Observation {
            signalled: None,
            ..observation(Some("198.51.100.77:40000"), "198.51.100.77:40002")
        };
        assert_eq!(p.observe(o), Verdict::Move(Match::SamePort));
    }

    #[test]
    fn ipv6_has_no_sibling_rule() {
        let p = EndpointPolicy::default();
        let o = Observation {
            signalled: Some(addr("[2001:db8::9]:6004")),
            ..observation(Some("[2001:db8::1]:6004"), "[2001:db8::66]:6004")
        };
        assert_eq!(p.observe(o), Verdict::Refuse(Reject::Foreign));
    }
}
