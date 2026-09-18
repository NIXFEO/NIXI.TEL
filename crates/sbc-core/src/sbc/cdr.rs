//! One teardown path for every way a call ends.
//!
//! `finish_call` is the only place that writes a CDR, updates the call
//! counters, publishes the `CallEnded` reason and releases the B2BUA entry,
//! so billing sees every call exactly once with its real cause and a
//! setup / answer / end window. `hangup_both_legs` is the wire side for the
//! teardowns the SBC initiates itself (max duration, shutdown, RTP timeout,
//! admin kick, setup timeout).

use super::*;
use crate::b2bua::CallUuid;
use crate::storage::CdrRecord;
use std::time::SystemTime;

/// Why a call ended. `disconnect_reason` is the CDR vocabulary; `sip_code`
/// the final status the caller's INVITE got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallOutcome {
    /// BYE from a peer (`by_caller`: the inbound leg hung up).
    NormalClearing { by_caller: bool },
    /// CANCEL from the caller before the answer.
    Cancelled,
    /// A final error relayed from the callee.
    Rejected { code: u16 },
    /// A final error the SBC generated itself (no route, unknown number,
    /// blocked destination, unreachable contact…).
    Refused { code: u16 },
    /// `security.max_call_duration` reached.
    MaxDuration,
    /// SIGTERM / SIGINT.
    Shutdown,
    /// The WS/WSS connection of one leg closed (`callee_died`: the callee's;
    /// a still-unanswered caller then got a 480).
    WsClosed { callee_died: bool },
    /// `DELETE /api/v1/calls/{uuid}`.
    AdminKick,
    /// The callee no longer has the dialog (481/408 to a refresh).
    DialogLost { status: u16 },
    /// No RTP for `security.rtp_timeout` seconds.
    RtpTimeout,
    /// No answer within `security.call_setup_timeout`.
    SetupTimeout,
    /// The SBC could not anchor the media (no RTP relay, no ports): the
    /// SDP already points at the SBC, so the call would be silent for its
    /// whole billed duration.
    MediaUnavailable,
}

impl CallOutcome {
    pub(crate) fn disconnect_reason(&self) -> String {
        match self {
            Self::NormalClearing { .. } => "normal-clearing".into(),
            Self::Cancelled => "cancelled".into(),
            Self::Rejected { code } | Self::Refused { code } => format!("rejected-{}", code),
            Self::MaxDuration => "timeout".into(),
            Self::Shutdown => "shutdown".into(),
            Self::WsClosed { .. } => "ws-closed".into(),
            Self::AdminKick => "admin-kick".into(),
            Self::DialogLost { .. } => "dialog-lost".into(),
            Self::RtpTimeout => "rtp-timeout".into(),
            Self::SetupTimeout => "setup-timeout".into(),
            Self::MediaUnavailable => "media-unavailable".into(),
        }
    }

    /// Final status the caller's INVITE transaction received (200 once the
    /// call was answered; None when the SBC sent no final, e.g. the caller's
    /// own connection died).
    pub(crate) fn sip_code(&self, answered: bool) -> Option<u16> {
        if answered {
            return Some(200);
        }
        match self {
            Self::Cancelled => Some(487),
            Self::Rejected { code } | Self::Refused { code } => Some(*code),
            Self::SetupTimeout => Some(408),
            Self::Shutdown | Self::MediaUnavailable => Some(503),
            Self::MaxDuration | Self::AdminKick => Some(480),
            Self::WsClosed { callee_died: true } => Some(480),
            Self::NormalClearing { .. }
            | Self::WsClosed { callee_died: false }
            | Self::DialogLost { .. }
            | Self::RtpTimeout => None,
        }
    }

    /// Reason header carried by the BYE/CANCEL the SBC sends for this outcome.
    pub(crate) fn reason_header(&self) -> Option<String> {
        match self {
            Self::MaxDuration => Some("Q.850;cause=16;text=\"Call duration exceeded\"".into()),
            Self::Shutdown => Some("Q.850;cause=16;text=\"Server shutdown\"".into()),
            Self::WsClosed { .. } => Some("SIP;cause=200;text=\"ws-closed\"".into()),
            Self::AdminKick => Some("SIP;cause=200;text=\"Administrative teardown\"".into()),
            Self::RtpTimeout => Some("Q.850;cause=16;text=\"RTP timeout\"".into()),
            Self::SetupTimeout => Some("SIP;cause=408;text=\"No answer\"".into()),
            Self::MediaUnavailable => {
                Some("Q.850;cause=47;text=\"No media resource available\"".into())
            }
            Self::DialogLost { status } => {
                Some(format!("SIP;cause={};text=\"Dialog lost\"", status))
            }
            Self::NormalClearing { .. }
            | Self::Cancelled
            | Self::Rejected { .. }
            | Self::Refused { .. } => None,
        }
    }

    /// Which side ended the call (CDR `hangup_by`).
    pub(crate) fn hangup_by(&self) -> &'static str {
        match self {
            Self::NormalClearing { by_caller: true } | Self::Cancelled => "caller",
            Self::NormalClearing { by_caller: false } => "callee",
            Self::Rejected { .. } => "callee",
            Self::Refused { .. } => "sbc",
            _ => "sbc",
        }
    }

    /// Final sent to a caller whose INVITE is still unanswered when the SBC
    /// hangs the call up on its own.
    pub(crate) fn pending_caller_code(&self) -> u16 {
        match self {
            Self::SetupTimeout => 408,
            Self::Shutdown | Self::MediaUnavailable => 503,
            _ => 480,
        }
    }
}

impl Sbc {
    /// Whether `source` is a trunk address or shares a /24 with one
    /// (clustered trunks answer and hang up from sibling hosts).
    pub(crate) async fn source_is_trunk_related(&self, source: SocketAddr) -> bool {
        let source_ip = source.ip().to_string();
        self.trunk_ips.read().await.iter().any(|tip| {
            tip == &source_ip || {
                let tip_prefix = tip.rsplit_once('.').map(|x| x.0);
                let src_prefix = source_ip.rsplit_once('.').map(|x| x.0);
                tip_prefix.is_some() && tip_prefix == src_prefix
            }
        })
    }
}

/// RFC 3261 §16.6 Timer C: how long an alerting callee may ring.
pub(crate) const TIMER_C: Duration = Duration::from_secs(180);

/// Status code of a raw response ("SIP/2.0 486 Busy Here" → 486).
pub(crate) fn status_code_of(raw: &str) -> Option<u16> {
    raw.split_whitespace().nth(1)?.parse().ok()
}

/// First value of header `name` (case-insensitive) on a request.
pub(crate) fn header_value(request: &Request, name: &str) -> Option<String> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    request.headers.iter().find_map(|h| {
        let line = h.to_string();
        line.get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(&prefix))
            .map(|_| line[prefix.len()..].trim().to_string())
    })
}

/// What the CDR needs, read under one lock hold.
struct CallSnapshot {
    call_id: String,
    caller: String,
    callee: String,
    started_wall: SystemTime,
    answered_at: Option<SystemTime>,
    is_webrtc: bool,
    codec: Option<String>,
    trunk_name: Option<String>,
    direction: &'static str,
    source_ip: String,
    peer_reason: Option<String>,
    media_session_id: Option<String>,
}

impl Sbc {
    /// Write the CDR, update the call counters and gauges, publish
    /// `CallEnded` with the real reason and release the call. Idempotent:
    /// a uuid that is already gone writes nothing (two paths may race, e.g.
    /// a WS close right after a BYE). Returns whether a call was ended.
    pub(crate) async fn finish_call(&mut self, uuid: &CallUuid, outcome: CallOutcome) -> bool {
        let snapshot = {
            let calls = self.b2bua.calls_locked().await;
            calls.get(uuid).map(|c| CallSnapshot {
                call_id: c.inbound.call_id.clone(),
                caller: c
                    .caller_number
                    .clone()
                    .unwrap_or_else(|| c.inbound.call_id.clone()),
                callee: c.callee_number.clone().unwrap_or_else(|| {
                    c.outbound
                        .as_ref()
                        .map(|l| l.call_id.clone())
                        .unwrap_or_default()
                }),
                started_wall: c.started_wall,
                answered_at: c.answered_at,
                is_webrtc: c.caller_is_webrtc,
                codec: c.codec.clone(),
                trunk_name: c.trunk_name.clone(),
                direction: c.direction(),
                source_ip: c.caller_source.ip().to_string(),
                peer_reason: c.peer_reason.clone(),
                media_session_id: c.media_session_id.clone(),
            })
        };
        let Some(s) = snapshot else {
            debug!(
                "finish_call({}): call {} already gone",
                outcome.disconnect_reason(),
                uuid
            );
            return false;
        };

        let ended = SystemTime::now();
        let answered = s.answered_at.is_some();
        let reason = outcome.disconnect_reason();
        let mut record = CdrRecord::new(s.call_id, s.caller, s.callee)
            .with_window(s.started_wall, s.answered_at, ended)
            .with_webrtc(s.is_webrtc)
            .with_disconnect_reason(&reason);
        record.codec = s.codec;
        record.trunk_id = s.trunk_name;
        record.uuid = uuid.clone();
        record.direction = s.direction.to_string();
        record.sip_code = outcome.sip_code(answered);
        record.source_ip = s.source_ip;
        record.reason = s.peer_reason.or_else(|| outcome.reason_header());
        record.hangup_by = outcome.hangup_by().to_string();

        // What the media plane actually carried, so billing can tell an
        // answered call that had audio from an answered silent one.
        let media = s
            .media_session_id
            .as_deref()
            .and_then(|id| self.media.call_media_stats(id));
        let mut flags: Vec<String> = Vec::new();
        match &media {
            None => flags.push("no-relay".to_string()),
            Some(stats) => {
                use crate::media::stats::Leg;
                let rx = |leg: Leg| {
                    stats
                        .leg(leg)
                        .rx_packets
                        .load(std::sync::atomic::Ordering::Relaxed)
                };
                let tx = |leg: Leg| {
                    stats
                        .leg(leg)
                        .tx_packets
                        .load(std::sync::atomic::Ordering::Relaxed)
                };
                record.rtp_tx_caller = tx(Leg::Caller);
                record.rtp_tx_callee = tx(Leg::Callee);
                if record.rtp_tx_caller == 0 && record.rtp_tx_callee == 0 {
                    flags.push("no-media".to_string());
                } else {
                    // `one-way-<leg>` names the side that never sent, the
                    // same convention as `sbc_media_one_way_calls_total`
                    // and `Leg::label()` — derived from it so the two
                    // cannot drift apart again.
                    for leg in [Leg::Caller, Leg::Callee] {
                        if rx(leg) == 0 {
                            flags.push(format!("one-way-{}", leg.label()));
                        }
                    }
                }
            }
        }
        record.media_flags = flags.join(",");
        if let Some(id) = s.media_session_id.as_deref() {
            self.media.forget_media_stats(id);
        }

        match self.cdr.insert(&record).await {
            Ok(outcome) => {
                // In store mode the writer stamps after the durable commit.
                if !self.cdr.has_store() {
                    self.metrics.record_cdr_written();
                }
                if outcome == crate::storage::CdrInsert::CacheOnly {
                    warn!(
                        "CDR {} kept in the memory cache only (writer queue full or closed)",
                        record.id
                    );
                }
                info!(
                    "CDR: {} → {} ({}, {} billable s of {} s, codec={}, trunk={}, sip={:?}, webrtc={})",
                    record.caller,
                    record.callee,
                    record.disconnect_reason,
                    record.billable_secs,
                    record.duration_secs,
                    record.codec.as_deref().unwrap_or("unknown"),
                    record.trunk_id.as_deref().unwrap_or("local"),
                    record.sip_code,
                    record.is_webrtc
                );
            }
            Err(e) => warn!("CDR recording failed ({}): {}", reason, e),
        }

        // Timing histograms and the per-trunk series; then release the
        // call from its trunk's active counter.
        if let Some(at) = s.answered_at {
            if let Ok(setup) = at.duration_since(s.started_wall) {
                self.metrics.observe_call_setup(setup.as_secs_f64());
            }
            self.metrics
                .observe_call_duration(record.billable_secs as f64);
        }
        if let Some(name) = record.trunk_id.as_deref() {
            self.metrics.inc_trunk_call(
                name,
                &record.direction,
                Self::trunk_outcome_label(&outcome, answered),
            );
        }
        self.count_call_on_trunk(uuid, None).await;

        if answered {
            self.metrics.inc_call_terminated();
        } else {
            self.metrics.inc_call_failed();
        }
        self.b2bua.terminate_call_with_reason(uuid, &reason).await;
        let stats = self.b2bua.stats().await;
        self.metrics.set_active_webrtc(stats.webrtc_calls as u64);
        self.metrics
            .set_allocated_ports(self.media.stats().allocated_ports as u64);
        true
    }

    /// Wire side of a teardown the SBC initiates: BYE (with `reason`) to
    /// each established leg, CANCEL to a callee whose INVITE is still
    /// pending, and a final (`outcome.pending_caller_code()`) to a caller
    /// whose INVITE the SBC never answered. State is untouched: call
    /// `finish_call` afterwards.
    pub(crate) async fn hangup_both_legs(&mut self, uuid: &CallUuid, outcome: &CallOutcome) {
        let (sbc_ip, sbc_port) = self
            .identity
            .as_ref()
            .map(|id| (id.public_ip.clone(), id.sip_port))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));
        let reason = outcome.reason_header();
        let pending_code = outcome.pending_caller_code();

        let plan = {
            let calls = self.b2bua.calls_locked().await;
            let Some(c) = calls.get(uuid) else { return };
            let toward_caller = c
                .dialog_info_toward_caller(&sbc_ip, sbc_port)
                .map(|d| crate::sip_builder::build_bye(&d, reason.as_deref()))
                .map(|m| ("BYE → caller", m))
                .or_else(|| {
                    c.final_toward_caller(pending_code, reason.as_deref())
                        .map(|m| ("final → caller", m))
                });
            let toward_callee = c
                .bye_toward_callee(&sbc_ip, sbc_port, reason.as_deref())
                .map(|m| ("BYE → callee", m))
                .or_else(|| {
                    c.invite_attempts
                        .last()
                        .and_then(|a| crate::sip_builder::build_cancel(&a.raw))
                        .map(|m| ("CANCEL → callee", m))
                });
            let callee_target = c
                .invite_attempts
                .last()
                .map(|a| (a.dest, a.transport))
                .or_else(|| c.callee_dest.map(|d| (d, c.callee_transport)));
            (
                toward_caller,
                c.caller_source,
                c.caller_transport,
                c.caller_reply_tx.clone(),
                toward_callee,
                callee_target,
                c.callee_reply_tx.clone(),
            )
        };
        let (
            toward_caller,
            caller_addr,
            caller_tp,
            caller_tx,
            toward_callee,
            callee_target,
            callee_tx,
        ) = plan;

        if let Some((what, msg)) = toward_caller {
            self.send_sip(
                what,
                msg.as_bytes(),
                caller_addr,
                caller_tp,
                caller_tx.as_ref(),
            )
            .await;
        }
        if let (Some((what, msg)), Some((dest, tp))) = (toward_callee, callee_target) {
            self.send_sip(what, msg.as_bytes(), dest, tp, callee_tx.as_ref())
                .await;
        }
    }
}

impl Sbc {
    /// Timer G: resend the non-2xx finals whose ACK has not arrived.
    pub(crate) async fn retransmit_finals(&self) {
        for (data, dest, transport, reply_tx) in self
            .invite_tx
            .due_retransmissions(std::time::Instant::now())
        {
            debug!(
                "Timer G: retransmitting a final → {} via {:?}",
                dest, transport
            );
            if let Err(e) = self
                .transport
                .reply(&data, dest, transport, reply_tx.as_ref())
                .await
            {
                debug!("Timer G retransmission → {} failed: {}", dest, e);
            }
        }
    }

    /// Requests we sent over UDP and have had no answer to (§17.1): resend
    /// them until Timer B/F. A lost INVITE otherwise fails a call on a
    /// healthy trunk, and a lost BYE leaves the trunk a session it thinks
    /// is live.
    pub(crate) async fn retransmit_requests(&self) {
        self.retransmit_requests_at(std::time::Instant::now()).await
    }

    /// Same, at an explicit instant — the tests advance the clock instead
    /// of sleeping for T1.
    pub(crate) async fn retransmit_requests_at(&self, now: std::time::Instant) {
        let (due, expired) = self.client_tx.due(now);
        for r in due {
            debug!(
                "Timer A/E: resending {} → {} (attempt {})",
                r.what, r.dest, r.attempt
            );
            if let Err(e) = self
                .transport
                .reply(&r.raw, r.dest, r.transport, r.reply_tx.as_ref())
                .await
            {
                debug!("Retransmission of {} → {} failed: {}", r.what, r.dest, e);
                self.metrics.inc_sip_send_failure(r.transport);
            } else {
                self.metrics.inc_request_retransmission();
            }
        }
        for what in expired {
            warn!(
                "Timer B/F: no answer to {} after {:?} — giving up on that request",
                what,
                crate::sbc::client_tx::TRANSACTION_TIMEOUT
            );
            self.metrics.inc_transaction_timeout();
        }
    }

    /// `DELETE /api/v1/calls/{uuid}`: end the queued calls on the wire and
    /// write their CDR ("admin-kick").
    pub(crate) async fn process_admin_kicks(&mut self) {
        for uuid in self.admin_kicks.drain() {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                let outcome = CallOutcome::AdminKick;
                self.hangup_both_legs(&uuid, &outcome).await;
                if self.finish_call(&uuid, outcome).await {
                    info!("Admin kick: call {} ended", &uuid[..8.min(uuid.len())]);
                } else {
                    debug!("Admin kick: call {} already gone", uuid);
                }
            }
            .instrument(span)
            .await;
        }
    }

    /// Relays that stopped on RTP inactivity: end their SIP dialogs (BYE
    /// both legs, CDR "rtp-timeout"), releasing the ports they held.
    pub(crate) async fn check_media_timeouts(&mut self) {
        let sessions = self.media.drain_timed_out();
        if sessions.is_empty() {
            return;
        }
        let uuids: Vec<(String, CallUuid)> = {
            let calls = self.b2bua.calls_locked().await;
            sessions
                .iter()
                .filter_map(|sid| {
                    calls
                        .values()
                        .find(|c| c.media_session_id.as_deref() == Some(sid.as_str()))
                        .map(|c| (sid.clone(), c.uuid.clone()))
                })
                .collect()
        };
        for (sid, uuid) in uuids {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                warn!(
                    "RTP timeout on media session {} — ending call {}",
                    sid,
                    &uuid[..8.min(uuid.len())]
                );
                let outcome = CallOutcome::RtpTimeout;
                self.hangup_both_legs(&uuid, &outcome).await;
                self.finish_call(&uuid, outcome).await;
            }
            .instrument(span)
            .await;
        }
    }

    /// Unanswered INVITEs: while the callee has not alerted (no >=180 yet),
    /// `security.call_setup_timeout` bounds a silent or 100-only trunk;
    /// once it alerts, RFC 3261 Timer C (3 min, restarted by every
    /// provisional) bounds the ringing. Then CANCEL toward the callee, 408
    /// to the caller, CDR "setup-timeout".
    pub(crate) async fn check_setup_timeouts(&mut self) {
        let limit = self.call_setup_timeout;
        let stale: Vec<CallUuid> = {
            let calls = self.b2bua.calls_locked().await;
            calls
                .values()
                .filter(|c| c.answered_at.is_none())
                .filter(|c| {
                    matches!(
                        c.state,
                        crate::b2bua::CallState::Initiated
                            | crate::b2bua::CallState::Proceeding
                            | crate::b2bua::CallState::Ringing
                    )
                })
                .filter(|c| match c.alerting_at {
                    None => c.started_at.elapsed() > limit,
                    Some(alerting) => alerting.elapsed() > TIMER_C,
                })
                .map(|c| c.uuid.clone())
                .collect()
        };
        for uuid in stale {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                warn!(
                    "Setup timeout: call {} unanswered after {}s — CANCEL + 408",
                    &uuid[..8.min(uuid.len())],
                    limit.as_secs()
                );
                if let Some(name) = self.silent_outbound_trunk_of(&uuid).await {
                    self.note_trunk_failure(&name, None);
                }
                let outcome = CallOutcome::SetupTimeout;
                self.hangup_both_legs(&uuid, &outcome).await;
                self.finish_call(&uuid, outcome).await;
            }
            .instrument(span)
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_vocabulary() {
        assert_eq!(
            CallOutcome::Rejected { code: 486 }.disconnect_reason(),
            "rejected-486"
        );
        assert_eq!(CallOutcome::Cancelled.sip_code(false), Some(487));
        assert_eq!(CallOutcome::Cancelled.sip_code(true), Some(200));
        assert_eq!(
            CallOutcome::WsClosed { callee_died: false }.sip_code(false),
            None
        );
        assert_eq!(
            CallOutcome::WsClosed { callee_died: true }.sip_code(false),
            Some(480)
        );
        assert_eq!(CallOutcome::Refused { code: 404 }.hangup_by(), "sbc");
        assert_eq!(CallOutcome::Rejected { code: 486 }.hangup_by(), "callee");
        assert_eq!(
            CallOutcome::Refused { code: 404 }.disconnect_reason(),
            "rejected-404"
        );
        assert_eq!(CallOutcome::Shutdown.pending_caller_code(), 503);
        assert_eq!(
            CallOutcome::NormalClearing { by_caller: false }.hangup_by(),
            "callee"
        );
        assert_eq!(CallOutcome::Cancelled.hangup_by(), "caller");
        assert_eq!(CallOutcome::RtpTimeout.hangup_by(), "sbc");
        assert_eq!(CallOutcome::SetupTimeout.sip_code(false), Some(408));
        assert!(CallOutcome::MaxDuration
            .reason_header()
            .unwrap()
            .contains("cause=16"));
    }

    #[test]
    fn status_and_header_helpers() {
        assert_eq!(status_code_of("SIP/2.0 486 Busy Here\r\n"), Some(486));
        assert_eq!(status_code_of("garbage"), None);
        let raw = "BYE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\nCall-ID: x\r\nCSeq: 2 BYE\r\nReason: Q.850;cause=16;text=\"Normal call clearing\"\r\nContent-Length: 0\r\n\r\n";
        let req = match rsip::SipMessage::try_from(raw.as_bytes().to_vec()).unwrap() {
            rsip::SipMessage::Request(r) => r,
            _ => panic!(),
        };
        assert_eq!(
            header_value(&req, "Reason").as_deref(),
            Some("Q.850;cause=16;text=\"Normal call clearing\"")
        );
        assert_eq!(header_value(&req, "X-Nope"), None);
    }
}
