//! Client transactions (RFC 3261 §17.1): the requests this SBC sends over
//! **UDP** are retransmitted until they are answered.
//!
//! UDP loses datagrams, and nothing else in this SBC resends a request it
//! originated. Two consequences were real:
//!
//! - an INVITE the trunk never received was answered by nothing: the call
//!   failed at `call_setup_timeout` (or failed over at `invite_timeout`)
//!   although the trunk was perfectly healthy;
//! - a BYE the trunk never received left it with a session it believes is
//!   live — the OverMaxCall symptom in the interop notes, where the trunk
//!   eventually answers `486 Busy Here` to new calls.
//!
//! Timers, per the RFC: `T1` = 500 ms. An INVITE doubles its interval with
//! no cap until Timer B (64·T1 = 32 s); any other request doubles up to
//! `T2` = 4 s until Timer F (32 s). A response with the transaction's
//! branch stops it, and so does sending a CANCEL for it (the SBC has
//! already decided to abandon that attempt).
//!
//! TCP and TLS retransmit in the transport, so only UDP is tracked. ACK is
//! never tracked: it has no response, and a 2xx retransmission triggers a
//! fresh one.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

/// RFC 3261 §17.1.1.1.
pub const TIMER_T1: Duration = Duration::from_millis(500);
/// Cap on a non-INVITE's retransmission interval (§17.1.2.2).
pub const TIMER_T2: Duration = Duration::from_secs(4);
/// Timer B / Timer F: 64·T1. Past it the request has failed.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(32);
/// Hard cap on tracked transactions, so a flood cannot grow the map.
pub const MAX_ENTRIES: usize = 4096;

/// One request in flight.
struct ClientTx {
    raw: Vec<u8>,
    dest: SocketAddr,
    transport: rsip::Transport,
    /// INVITEs double without a cap, everything else stops at `T2`.
    is_invite: bool,
    next_at: Instant,
    interval: Duration,
    /// Timer B / F.
    give_up_at: Instant,
    attempts: u32,
    reply_tx: Option<UnboundedSender<Vec<u8>>>,
    /// For the log line only.
    what: String,
}

/// One retransmission to perform, as `due` hands it out.
pub(crate) struct DueRequest {
    /// What was being sent, for the log line.
    pub what: String,
    /// The original bytes: a retransmission is byte-identical, so the
    /// peer recognises it instead of treating it as a new request.
    pub raw: Vec<u8>,
    pub dest: SocketAddr,
    pub transport: rsip::Transport,
    pub reply_tx: Option<UnboundedSender<Vec<u8>>>,
    /// How many times this one has been resent (1 for the first resend).
    pub attempt: u32,
}

/// The transactions this SBC has in flight over UDP.
#[derive(Default)]
pub(crate) struct ClientTxCache {
    txs: Mutex<HashMap<String, ClientTx>>,
}

/// `branch|METHOD` — what a response carries back in its top Via and CSeq.
fn key(branch: &str, method: &str) -> String {
    format!("{}|{}", branch, method.to_ascii_uppercase())
}

/// The top Via's `branch` parameter of a raw message — the same reading
/// the rest of the SBC uses, so a transaction is keyed identically
/// wherever it is looked up.
fn via_branch(raw: &str) -> Option<String> {
    crate::sip_builder::top_via_branch(raw)
}

/// The `branch` parameter of one Via header *value* (`SIP/2.0/UDP
/// host;branch=z9hG4bK…`), for a message already parsed into headers.
/// A comma-folded Via carries the top one first, like `via_branch`.
pub(crate) fn branch_param(via_value: &str) -> Option<String> {
    let lower = via_value.to_ascii_lowercase();
    let pos = lower.find("branch=")?;
    let rest = &via_value[pos + "branch=".len()..];
    let end = rest
        .find(|c: char| [';', ','].contains(&c) || c.is_whitespace())
        .unwrap_or(rest.len());
    let branch = rest[..end].trim();
    (!branch.is_empty()).then(|| branch.to_string())
}

/// The method of a request's start line (`INVITE sip:… SIP/2.0`).
fn request_method(raw: &str) -> Option<String> {
    let first = raw.lines().next()?;
    if !first.ends_with("SIP/2.0") {
        return None;
    }
    let method = first.split_whitespace().next()?;
    if method.starts_with("SIP/") {
        return None; // a response
    }
    Some(method.to_ascii_uppercase())
}

impl ClientTxCache {
    /// Remember a request the SBC just sent, if it is one we must resend.
    /// Returns the key when the request is now tracked.
    pub(crate) fn record_sent(
        &self,
        what: &str,
        raw: &[u8],
        dest: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<UnboundedSender<Vec<u8>>>,
    ) -> Option<String> {
        if transport != rsip::Transport::Udp {
            return None; // TCP/TLS retransmit in the transport
        }
        let text = std::str::from_utf8(raw).ok()?;
        let method = request_method(text)?;
        // ACK has no response of its own; CANCEL is a request we do
        // retransmit, since its own 200/487 is what confirms it.
        if method == "ACK" {
            return None;
        }
        let branch = via_branch(text)?;
        let now = Instant::now();
        let mut txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        if txs.len() >= MAX_ENTRIES {
            txs.retain(|_, tx| tx.give_up_at > now);
            if txs.len() >= MAX_ENTRIES {
                return None;
            }
        }
        // Sending a CANCEL means this attempt is abandoned: stop resending
        // its INVITE.
        if method == "CANCEL" {
            txs.remove(&key(&branch, "INVITE"));
        }
        let k = key(&branch, &method);
        txs.insert(
            k.clone(),
            ClientTx {
                raw: raw.to_vec(),
                dest,
                transport,
                is_invite: method == "INVITE",
                next_at: now + TIMER_T1,
                interval: TIMER_T1,
                give_up_at: now + TRANSACTION_TIMEOUT,
                attempts: 0,
                reply_tx,
                what: what.to_string(),
            },
        );
        Some(k)
    }

    /// A response arrived: the transaction it answers stops retransmitting
    /// (§17.1.1.2 — even a provisional stops Timer A). Read from the
    /// parsed headers, so the dispatch path never re-serializes a message
    /// just to stop a timer. Returns true when something was tracking it.
    pub(crate) fn answered_parts(&self, branch: &str, cseq_method: &str) -> bool {
        let mut txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        txs.remove(&key(branch, cseq_method)).is_some()
    }

    /// Whether anything is in flight (cheap guard on the response path).
    pub(crate) fn is_empty(&self) -> bool {
        self.txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// The retransmissions due at `now`, with their next interval already
    /// armed. A transaction past Timer B/F is dropped and reported so the
    /// caller can log it once.
    pub(crate) fn due(&self, now: Instant) -> (Vec<DueRequest>, Vec<String>) {
        let mut out = Vec::new();
        let mut expired = Vec::new();
        let mut txs = self.txs.lock().unwrap_or_else(|e| e.into_inner());
        txs.retain(|_, tx| {
            if tx.give_up_at <= now {
                expired.push(format!("{} ({} attempts)", tx.what, tx.attempts));
                return false;
            }
            if tx.next_at <= now {
                tx.attempts += 1;
                tx.interval = if tx.is_invite {
                    tx.interval * 2
                } else {
                    (tx.interval * 2).min(TIMER_T2)
                };
                tx.next_at = now + tx.interval;
                out.push(DueRequest {
                    what: tx.what.clone(),
                    raw: tx.raw.clone(),
                    dest: tx.dest,
                    transport: tx.transport,
                    reply_tx: tx.reply_tx.clone(),
                    attempt: tx.attempts,
                });
            }
            true
        });
        (out, expired)
    }

    /// Tracked transactions: what shutdown reports as still unanswered,
    /// and what the tests count.
    pub(crate) fn len(&self) -> usize {
        self.txs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "203.0.113.9:5060".parse().unwrap()
    }

    fn invite(branch: &str) -> String {
        format!(
            "INVITE sip:bob@203.0.113.9 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.1:5060;branch={};rport\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>\r\n\
             Call-ID: c1\r\nCSeq: 2 INVITE\r\nContent-Length: 0\r\n\r\n",
            branch
        )
    }

    fn bye(branch: &str) -> String {
        format!(
            "BYE sip:bob@203.0.113.9 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 198.51.100.1:5060;branch={}\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>;tag=2\r\n\
             Call-ID: c1\r\nCSeq: 5 BYE\r\nContent-Length: 0\r\n\r\n",
            branch
        )
    }

    fn response(branch: &str, status: &str, method: &str) -> String {
        format!(
            "SIP/2.0 {}\r\nVia: SIP/2.0/UDP 198.51.100.1:5060;branch={}\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:b@y>;tag=2\r\n\
             Call-ID: c1\r\nCSeq: 2 {}\r\nContent-Length: 0\r\n\r\n",
            status, branch, method
        )
    }

    #[test]
    fn an_invite_is_retransmitted_with_a_doubling_interval() {
        let cache = ClientTxCache::default();
        let raw = invite("z9hG4bK1");
        assert!(cache
            .record_sent(
                "INVITE → trunk",
                raw.as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None
            )
            .is_some());
        let start = Instant::now();

        // Nothing is due before T1.
        assert!(cache.due(start).0.is_empty());
        // 500 ms, then 1 s, 2 s, 4 s, 8 s — no cap for an INVITE.
        for (i, expected) in [500u64, 1500, 3500, 7500, 15500].iter().enumerate() {
            let at = start + Duration::from_millis(*expected);
            let (due, expired) = cache.due(at);
            assert_eq!(due.len(), 1, "retransmission {} at {:?}", i + 1, at - start);
            assert_eq!(due[0].attempt, i as u32 + 1, "attempt counter");
            assert_eq!(due[0].raw, raw.as_bytes(), "byte-identical retransmission");
            assert!(expired.is_empty());
        }
        // Timer B: given up at 32 s, reported once.
        let (due, expired) = cache.due(start + Duration::from_secs(33));
        assert!(due.is_empty());
        assert_eq!(expired.len(), 1, "{:?}", expired);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_non_invite_interval_is_capped_at_t2() {
        let cache = ClientTxCache::default();
        cache
            .record_sent(
                "BYE → trunk",
                bye("z9hG4bKb").as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            )
            .expect("tracked");
        let start = Instant::now();
        // 0.5, 1, 2, 4, 4, 4 …
        let mut elapsed = 0u64;
        let mut intervals = Vec::new();
        for _ in 0..6 {
            // Step to just past the next fire time by walking in 100 ms steps.
            for _ in 0..100 {
                elapsed += 100;
                let (due, _) = cache.due(start + Duration::from_millis(elapsed));
                if !due.is_empty() {
                    intervals.push(elapsed);
                    break;
                }
            }
        }
        let gaps: Vec<u64> = intervals.windows(2).map(|w| w[1] - w[0]).collect();
        assert_eq!(
            gaps,
            vec![1000, 2000, 4000, 4000, 4000],
            "doubling then capped at T2: {:?}",
            intervals
        );
    }

    /// What `Sbc::dispatch` does with a response, from its raw text: read
    /// the top Via's branch and the CSeq method, then stop that timer.
    fn answer_with(cache: &ClientTxCache, raw: &str) -> bool {
        let msg = rsip::SipMessage::try_from(raw).expect("parses");
        let rsip::SipMessage::Response(r) = msg else {
            panic!("not a response")
        };
        use rsip::prelude::{HeadersExt, UntypedHeader};
        let via = r.via_header().expect("Via");
        let cseq = r.cseq_header().expect("CSeq");
        let branch = branch_param(via.value()).expect("branch");
        let method = cseq.value().split_whitespace().nth(1).expect("method");
        cache.answered_parts(&branch, &method.to_ascii_uppercase())
    }

    #[test]
    fn any_response_stops_the_retransmissions() {
        let cache = ClientTxCache::default();
        cache
            .record_sent(
                "INVITE → trunk",
                invite("z9hG4bK2").as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            )
            .expect("tracked");
        // A 100 Trying is enough (RFC 3261 §17.1.1.2: Timer A stops).
        assert!(answer_with(
            &cache,
            &response("z9hG4bK2", "100 Trying", "INVITE")
        ));
        assert_eq!(cache.len(), 0);
        assert!(cache
            .due(Instant::now() + Duration::from_secs(1))
            .0
            .is_empty());

        // A response for another branch or another method changes nothing.
        cache
            .record_sent(
                "INVITE → trunk",
                invite("z9hG4bK3").as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            )
            .expect("tracked");
        assert!(!answer_with(&cache, &response("other", "200 OK", "INVITE")));
        assert!(!answer_with(&cache, &response("z9hG4bK3", "200 OK", "BYE")));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_two_via_readings_agree() {
        // A request is keyed from its raw text, a response read from its
        // parsed headers: the two must extract the same branch, including
        // through a comma-folded Via where the top value comes first.
        let raw = invite("z9hG4bKtop");
        assert_eq!(via_branch(&raw).as_deref(), Some("z9hG4bKtop"));
        assert_eq!(
            branch_param("SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKtop;rport"),
            Some("z9hG4bKtop".to_string())
        );
        assert_eq!(
            branch_param(
                "SIP/2.0/UDP a:5060;branch=z9hG4bKtop,SIP/2.0/UDP b:5060;branch=z9hG4bKdown"
            ),
            Some("z9hG4bKtop".to_string()),
            "the top Via is the first value of a folded header"
        );
        assert_eq!(branch_param("SIP/2.0/UDP a:5060"), None);
        assert_eq!(branch_param("SIP/2.0/UDP a:5060;branch="), None);
    }

    #[test]
    fn cancelling_an_attempt_stops_its_invite() {
        let cache = ClientTxCache::default();
        cache
            .record_sent(
                "INVITE → trunk",
                invite("z9hG4bK4").as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            )
            .expect("tracked");
        let cancel = invite("z9hG4bK4")
            .replace("INVITE sip", "CANCEL sip")
            .replace("CSeq: 2 INVITE", "CSeq: 2 CANCEL");
        cache
            .record_sent(
                "CANCEL → trunk",
                cancel.as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            )
            .expect("the CANCEL itself is tracked");
        // The INVITE is gone, the CANCEL remains.
        let (due, _) = cache.due(Instant::now() + Duration::from_millis(600));
        assert_eq!(due.len(), 1);
        assert!(
            due[0].raw.starts_with(b"CANCEL "),
            "only the CANCEL is resent"
        );
    }

    #[test]
    fn reliable_transports_and_acks_are_not_tracked() {
        let cache = ClientTxCache::default();
        assert!(cache
            .record_sent(
                "INVITE → trunk",
                invite("z9hG4bK5").as_bytes(),
                addr(),
                rsip::Transport::Tcp,
                None
            )
            .is_none());
        assert!(cache
            .record_sent(
                "INVITE → trunk",
                invite("z9hG4bK6").as_bytes(),
                addr(),
                rsip::Transport::Tls,
                None
            )
            .is_none());
        let ack = invite("z9hG4bK7")
            .replace("INVITE sip", "ACK sip")
            .replace("CSeq: 2 INVITE", "CSeq: 2 ACK");
        assert!(cache
            .record_sent(
                "ACK → trunk",
                ack.as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None
            )
            .is_none());
        // A response is not a request.
        assert!(cache
            .record_sent(
                "200 → caller",
                response("z9hG4bK8", "200 OK", "INVITE").as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None
            )
            .is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn the_table_is_bounded() {
        let cache = ClientTxCache::default();
        for i in 0..(MAX_ENTRIES + 50) {
            cache.record_sent(
                "INVITE → trunk",
                invite(&format!("z9hG4bK{}", i)).as_bytes(),
                addr(),
                rsip::Transport::Udp,
                None,
            );
        }
        assert!(cache.len() <= MAX_ENTRIES, "tracked {}", cache.len());
    }

    #[test]
    fn a_branchless_or_malformed_message_is_ignored() {
        let cache = ClientTxCache::default();
        assert!(cache
            .record_sent(
                "x",
                b"INVITE sip:b SIP/2.0\r\nCSeq: 1 INVITE\r\n\r\n",
                addr(),
                rsip::Transport::Udp,
                None
            )
            .is_none());
        assert!(cache
            .record_sent("x", b"", addr(), rsip::Transport::Udp, None)
            .is_none());
        assert!(!cache.answered_parts("", "INVITE"), "no branch, no match");
    }
}
