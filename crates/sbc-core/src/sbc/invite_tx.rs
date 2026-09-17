//! INVITE server-transaction memory (RFC 3261 §17.2.1): a retransmitted
//! INVITE — the client did not see our 100 Trying, or our final was lost —
//! must get the last response again and nothing else. Without it every
//! UDP retransmission became a second call with its own media session.
//!
//! Every response the SBC sends toward an INVITE's sender is recorded here
//! from `Sbc::send_sip`, keyed by the transaction identity (top Via
//! branch, Call-ID, From tag, CSeq — §17.2.3). Entries live 32 s past
//! their final (Timer H/J territory) or 3 min while still pending.

use crate::topology::RawSipMessage;
use rsip::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

/// How long a completed transaction keeps replaying its final.
pub const FINAL_ABSORB: Duration = Duration::from_secs(32);
/// How long a transaction without a final is remembered.
pub const PENDING_ABSORB: Duration = Duration::from_secs(180);
/// Hard cap: an INVITE flood cannot outrun the sweeper.
pub const MAX_ENTRIES: usize = 10_000;
/// RFC 3261 §17.2.1 Timer G: first retransmission of a non-2xx final over
/// UDP, then doubling up to T2.
pub const TIMER_T1: Duration = Duration::from_millis(500);
pub const TIMER_T2: Duration = Duration::from_secs(4);
/// Retransmissions before giving up (≈ Timer H = 32 s: 0.5+1+2+4×6).
pub const MAX_RETRANSMITS: u32 = 9;

/// A non-2xx final the SBC generated over UDP: resent until the ACK.
struct Retransmit {
    dest: SocketAddr,
    transport: rsip::Transport,
    reply_tx: Option<UnboundedSender<Vec<u8>>>,
    next_at: Instant,
    interval: Duration,
    sent: u32,
}

struct TxEntry {
    last_response: Option<Vec<u8>>,
    first_seen: Instant,
    final_at: Option<Instant>,
    acked: bool,
    retransmit: Option<Retransmit>,
}

#[derive(Default)]
pub(crate) struct InviteTxCache {
    entries: Mutex<HashMap<String, TxEntry>>,
}

fn param_of(value: &str, name: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let needle = format!("{}=", name);
    let pos = lower.find(&needle)?;
    let rest = &value[pos + needle.len()..];
    let end = rest.find([';', ',', ' ', '>']).unwrap_or(rest.len());
    let v = rest[..end].trim();
    (!v.is_empty()).then(|| v.to_string())
}

fn key(branch: &str, call_id: &str, from_tag: &str, cseq: &str) -> String {
    format!("{}|{}|{}|{}", branch, call_id, from_tag, cseq)
}

impl InviteTxCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Transaction key of an incoming INVITE (None if it lacks the
    /// identifying headers — such a request is rejected upstream anyway).
    pub(crate) fn key_of_request(request: &rsip::Request) -> Option<String> {
        let via = request.headers.iter().find_map(|h| {
            let line = h.to_string();
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("via:") {
                Some(line[4..].trim().to_string())
            } else if lower.starts_with("v:") {
                Some(line[2..].trim().to_string())
            } else {
                None
            }
        })?;
        let branch = param_of(&via, "branch")?;
        let call_id = request.call_id_header().ok()?.value().to_string();
        let from_tag = param_of(request.from_header().ok()?.value(), "tag").unwrap_or_default();
        let cseq = request
            .cseq_header()
            .ok()?
            .value()
            .split_whitespace()
            .next()?
            .to_string();
        Some(key(&branch, &call_id, &from_tag, &cseq))
    }

    /// Transaction key of an outgoing response, when it answers an INVITE:
    /// (key, status). None for garbage or other methods.
    pub(crate) fn key_of_response(raw: &str) -> Option<(String, u16)> {
        if !raw.starts_with("SIP/2.0 ") {
            return None;
        }
        let msg = RawSipMessage::parse(raw).ok()?;
        let cseq_line = msg.header_values("cseq").into_iter().next()?;
        let mut parts = cseq_line.split_whitespace();
        let cseq = parts.next()?.to_string();
        if !parts.next()?.eq_ignore_ascii_case("INVITE") {
            return None;
        }
        let via = msg.header_values("via").into_iter().next()?;
        let branch = param_of(&via, "branch")?;
        let call_id = msg.header_values("call-id").into_iter().next()?;
        let from_tag = msg
            .header_values("from")
            .into_iter()
            .next()
            .and_then(|f| param_of(&f, "tag"))
            .unwrap_or_default();
        let status: u16 = raw.split_whitespace().nth(1)?.parse().ok()?;
        Some((key(&branch, &call_id, &from_tag, &cseq), status))
    }

    /// Register a transaction. `Err(last)` means it is already known
    /// (a retransmission): `last` is the response to replay, None while
    /// the first copy is still being processed.
    pub(crate) fn begin(&self, key: &str) -> Result<(), Option<Vec<u8>>> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = entries.get(key) {
            return Err(e.last_response.clone());
        }
        if entries.len() >= MAX_ENTRIES {
            // Evict the oldest entry rather than refuse: a flood must not
            // turn every legitimate INVITE into an unabsorbed one.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, e)| e.first_seen)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key.to_string(),
            TxEntry {
                last_response: None,
                first_seen: Instant::now(),
                final_at: None,
                acked: false,
                retransmit: None,
            },
        );
        Ok(())
    }

    /// Remember the last response sent for a transaction (called for
    /// every INVITE response the SBC emits). A non-2xx final over UDP is
    /// also armed for Timer G retransmission until its ACK (the UAC stops
    /// retransmitting the INVITE once it has our 100 Trying, so the absorb
    /// path alone cannot recover a lost final).
    pub(crate) fn record_sent(
        &self,
        key: &str,
        response: &[u8],
        status: u16,
        dest: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<UnboundedSender<Vec<u8>>>,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = entries.get_mut(key) {
            e.last_response = Some(response.to_vec());
            if status >= 200 && e.final_at.is_none() {
                e.final_at = Some(Instant::now());
            }
            if status >= 300
                && transport == rsip::Transport::Udp
                && !e.acked
                && e.retransmit.is_none()
            {
                e.retransmit = Some(Retransmit {
                    dest,
                    transport,
                    reply_tx,
                    next_at: Instant::now() + TIMER_T1,
                    interval: TIMER_T1,
                    sent: 0,
                });
            }
        }
    }

    /// The ACK for a transaction's final arrived: stop retransmitting.
    pub(crate) fn acked(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = entries.get_mut(key) {
            e.acked = true;
            e.retransmit = None;
        }
    }

    /// Finals whose Timer G fired: (bytes, dest, transport, channel).
    /// Each returned entry is rescheduled (interval doubling up to T2);
    /// after `MAX_RETRANSMITS` the entry gives up (Timer H).
    #[allow(clippy::type_complexity)]
    pub(crate) fn due_retransmissions(
        &self,
        now: Instant,
    ) -> Vec<(
        Vec<u8>,
        SocketAddr,
        rsip::Transport,
        Option<UnboundedSender<Vec<u8>>>,
    )> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for e in entries.values_mut() {
            let Some(r) = e.retransmit.as_mut() else {
                continue;
            };
            if r.next_at > now {
                continue;
            }
            if r.sent >= MAX_RETRANSMITS {
                e.retransmit = None;
                continue;
            }
            if let Some(data) = &e.last_response {
                out.push((data.clone(), r.dest, r.transport, r.reply_tx.clone()));
            }
            r.sent += 1;
            r.interval = (r.interval * 2).min(TIMER_T2);
            r.next_at = now + r.interval;
        }
        out
    }

    /// Finals still awaiting their ACK.
    #[cfg(test)]
    pub(crate) fn pending_retransmissions(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|e| e.retransmit.is_some())
            .count()
    }

    /// Drop transactions past their absorb window. Returns how many.
    pub(crate) fn prune(&self) -> usize {
        self.prune_at(Instant::now())
    }

    fn prune_at(&self, now: Instant) -> usize {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = entries.len();
        entries.retain(|_, e| match e.final_at {
            Some(f) => now.duration_since(f) < FINAL_ABSORB,
            None => now.duration_since(e.first_seen) < PENDING_ABSORB,
        });
        before - entries.len()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "INVITE sip:b@h SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKabc;rport\r\nFrom: <sip:a@h>;tag=t1\r\nTo: <sip:b@h>\r\nCall-ID: c1\r\nCSeq: 7 INVITE\r\nContent-Length: 0\r\n\r\n";
    const RESP: &str = "SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKabc;rport\r\nFrom: <sip:a@h>;tag=t1\r\nTo: <sip:b@h>;tag=x\r\nCall-ID: c1\r\nCSeq: 7 INVITE\r\nContent-Length: 0\r\n\r\n";

    fn req(raw: &str) -> rsip::Request {
        match rsip::SipMessage::try_from(raw.as_bytes().to_vec()).unwrap() {
            rsip::SipMessage::Request(r) => r,
            _ => panic!(),
        }
    }

    #[test]
    fn request_and_response_share_the_transaction_key() {
        let k = InviteTxCache::key_of_request(&req(INVITE)).unwrap();
        let (rk, status) = InviteTxCache::key_of_response(RESP).unwrap();
        assert_eq!(k, rk);
        assert_eq!(status, 486);
        assert_eq!(k, "z9hG4bKabc|c1|t1|7");
        let (_, provisional) =
            InviteTxCache::key_of_response(&RESP.replace("486 Busy Here", "100 Trying")).unwrap();
        assert_eq!(provisional, 100);
        assert!(
            InviteTxCache::key_of_response(&RESP.replace("7 INVITE", "7 BYE")).is_none(),
            "only INVITE responses are remembered"
        );
    }

    #[test]
    fn retransmissions_replay_the_last_response_then_expire() {
        let cache = InviteTxCache::new();
        let k = InviteTxCache::key_of_request(&req(INVITE)).unwrap();
        let dest: SocketAddr = "10.0.0.9:5060".parse().unwrap();
        assert!(cache.begin(&k).is_ok(), "first copy is new");
        assert_eq!(
            cache.begin(&k),
            Err(None),
            "retransmitted before any response"
        );
        cache.record_sent(
            &k,
            b"SIP/2.0 100 Trying\r\n\r\n",
            100,
            dest,
            rsip::Transport::Udp,
            None,
        );
        assert_eq!(
            cache.begin(&k),
            Err(Some(b"SIP/2.0 100 Trying\r\n\r\n".to_vec()))
        );
        assert_eq!(
            cache.pending_retransmissions(),
            0,
            "provisionals are not retransmitted"
        );
        cache.record_sent(&k, RESP.as_bytes(), 486, dest, rsip::Transport::Udp, None);
        assert_eq!(cache.begin(&k), Err(Some(RESP.as_bytes().to_vec())));
        assert_eq!(cache.prune_at(Instant::now() + Duration::from_secs(10)), 0);
        assert_eq!(
            cache.prune_at(Instant::now() + FINAL_ABSORB + Duration::from_secs(1)),
            1
        );
        assert!(
            cache.begin(&k).is_ok(),
            "same key after expiry is a new transaction"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn pending_transactions_expire_later_and_the_cache_is_capped() {
        let cache = InviteTxCache::new();
        cache.begin("pending").unwrap();
        assert_eq!(
            cache.prune_at(Instant::now() + FINAL_ABSORB + Duration::from_secs(1)),
            0
        );
        assert_eq!(
            cache.prune_at(Instant::now() + PENDING_ABSORB + Duration::from_secs(1)),
            1
        );
        for n in 0..MAX_ENTRIES + 5 {
            cache.begin(&format!("k{}", n)).unwrap();
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
    }

    #[test]
    fn non_2xx_finals_over_udp_are_retransmitted_until_acked() {
        let cache = InviteTxCache::new();
        let dest: SocketAddr = "10.0.0.9:5060".parse().unwrap();
        let t0 = Instant::now();
        cache.begin("tx").unwrap();
        cache.record_sent("tx", RESP.as_bytes(), 486, dest, rsip::Transport::Udp, None);
        assert_eq!(cache.pending_retransmissions(), 1);
        assert!(cache.due_retransmissions(t0).is_empty(), "not before T1");
        let due = cache.due_retransmissions(t0 + Duration::from_millis(600));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, RESP.as_bytes());
        assert_eq!(due[0].1, dest);
        assert!(
            cache
                .due_retransmissions(t0 + Duration::from_millis(900))
                .is_empty(),
            "interval doubled to 1 s"
        );
        assert_eq!(
            cache
                .due_retransmissions(t0 + Duration::from_millis(1700))
                .len(),
            1
        );
        cache.acked("tx");
        assert_eq!(cache.pending_retransmissions(), 0);
        assert!(cache
            .due_retransmissions(t0 + Duration::from_secs(60))
            .is_empty());

        // A second record of the same final does not re-arm after the ACK.
        cache.record_sent("tx", RESP.as_bytes(), 486, dest, rsip::Transport::Udp, None);
        assert_eq!(cache.pending_retransmissions(), 0);

        // Reliable transports are never retransmitted (Timer G is UDP only).
        cache.begin("tcp").unwrap();
        cache.record_sent(
            "tcp",
            RESP.as_bytes(),
            486,
            dest,
            rsip::Transport::Tcp,
            None,
        );
        assert_eq!(cache.pending_retransmissions(), 0);

        // Timer H: give up after MAX_RETRANSMITS.
        cache.begin("lost").unwrap();
        cache.record_sent(
            "lost",
            RESP.as_bytes(),
            487,
            dest,
            rsip::Transport::Udp,
            None,
        );
        let mut now = t0;
        let mut sent = 0;
        for _ in 0..40 {
            now += Duration::from_secs(4);
            sent += cache.due_retransmissions(now).len();
        }
        assert_eq!(sent, MAX_RETRANSMITS as usize);
        assert_eq!(cache.pending_retransmissions(), 0);
    }
}
