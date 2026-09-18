//! Trunk state fed by real calls.
//!
//! The router already skips a trunk that is full (`max_concurrent_calls`)
//! or in cooldown (`TrunkState::can_accept_call`); this module is what
//! feeds that state and the per-trunk metrics from the calls themselves:
//! active-call counting (`count_call_on_trunk`), failures from real answers
//! (408/5xx/6xx, unanswered attempts, `503 Retry-After`) and success resets
//! on a 200 OK.
use super::cdr::CallOutcome;
use super::*;
use crate::b2bua::CallUuid;

impl Sbc {
    /// Make `trunk` the (only) trunk whose active-call counter includes
    /// this call; `None` releases it. Idempotent: a failover moves the
    /// call from one trunk to the next, `finish_call` releases it once.
    pub(crate) async fn count_call_on_trunk(&self, uuid: &CallUuid, trunk: Option<&str>) {
        let previous = {
            let mut calls = self.b2bua.calls_locked().await;
            let Some(call) = calls.get_mut(uuid) else {
                return;
            };
            if call.trunk_counted.as_deref() == trunk {
                return;
            }
            std::mem::replace(&mut call.trunk_counted, trunk.map(str::to_string))
        };
        if let Some(prev) = previous.as_deref() {
            self.trunk_manager
                .update_state_by_name(prev, |s| s.decrement_calls());
            self.publish_trunk_active(prev);
            if trunk.is_some() {
                // A failover: the attempt left this trunk for the next one.
                self.metrics.inc_trunk_call(prev, "outbound", "failover");
            }
        }
        if let Some(name) = trunk {
            self.trunk_manager
                .update_state_by_name(name, |s| s.increment_calls());
            self.publish_trunk_active(name);
        }
    }

    fn publish_trunk_active(&self, name: &str) {
        if let Some(s) = self.trunk_manager.state_by_name(name) {
            self.metrics
                .set_trunk_active_calls(name, u64::from(s.active_calls));
        }
    }

    /// The trunk this call's outbound leg is on (None for a call from a
    /// trunk to a local user: its answers are the user's, not a trunk's).
    pub(crate) async fn outbound_trunk_of(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.b2bua.calls_locked().await;
        let call = calls.get(uuid)?;
        if call.direction() == "inbound" {
            return None;
        }
        call.trunk_name.clone()
    }

    /// The outbound trunk of a call that got no answer at all (not even a
    /// 100 Trying): the one to strike when the attempt times out.
    pub(crate) async fn silent_outbound_trunk_of(&self, uuid: &CallUuid) -> Option<String> {
        let calls = self.b2bua.calls_locked().await;
        let call = calls.get(uuid)?;
        if call.direction() == "inbound" || call.callee_responded {
            return None;
        }
        call.trunk_name.clone()
    }

    /// A trunk failed a call attempt: a 408/500/502/503/504 final, a send
    /// failure, or no answer at all within `invite_timeout` /
    /// `call_setup_timeout`. Consecutive failures apply the cooldown
    /// ladder; a `503 Retry-After` parks the trunk for exactly that long.
    /// Becoming unavailable is published as a `trunk_health` event.
    pub(crate) fn note_trunk_failure(&self, name: &str, retry_after: Option<u64>) {
        let now = std::time::Instant::now();
        let before = self
            .trunk_manager
            .state_by_name(name)
            .map(|s| s.unavailable_for(now).is_some());
        let updated = self
            .trunk_manager
            .update_state_by_name(name, |s| match retry_after {
                Some(secs) => s.park_for(secs),
                None => s.record_trunk_failure(),
            });
        if !updated {
            return;
        }
        let Some(s) = self.trunk_manager.state_by_name(name) else {
            return;
        };
        match s.unavailable_for(now) {
            Some(left) => {
                let status = s.health_label(now);
                warn!(
                    "Trunk '{}': {} consecutive failure(s) — {} for {:?}, no new calls routed there",
                    name, s.consecutive_failures, status, left
                );
                if before == Some(false) {
                    self.events.publish(crate::events::SbcEvent::TrunkHealth {
                        trunk: name.to_string(),
                        status: status.to_string(),
                        consecutive_failures: s.consecutive_failures,
                        ts: crate::events::event_ts(),
                    });
                }
            }
            None => debug!(
                "Trunk '{}': failure {} (no cooldown yet)",
                name, s.consecutive_failures
            ),
        }
    }

    /// A trunk answered 200 OK: failures reset, the cooldown is lifted (a
    /// park the trunk asked for stays). Coming back is published.
    pub(crate) fn note_trunk_success(&self, name: &str) {
        let now = std::time::Instant::now();
        let was_cooling = self
            .trunk_manager
            .state_by_name(name)
            .is_some_and(|s| s.disabled_until.is_some_and(|u| u > now));
        self.trunk_manager
            .update_state_by_name(name, |s| s.record_success());
        if was_cooling {
            let still_parked = self
                .trunk_manager
                .state_by_name(name)
                .is_some_and(|s| s.unavailable_for(now).is_some());
            if !still_parked {
                info!("Trunk '{}': answered 200 OK — cooldown lifted", name);
                self.events.publish(crate::events::SbcEvent::TrunkHealth {
                    trunk: name.to_string(),
                    status: "up".to_string(),
                    consecutive_failures: 0,
                    ts: crate::events::event_ts(),
                });
            }
        }
    }

    /// `sbc_trunk_calls_total{outcome}` label of a finished call.
    pub(crate) fn trunk_outcome_label(outcome: &CallOutcome, answered: bool) -> &'static str {
        if answered {
            return "answered";
        }
        match outcome {
            CallOutcome::Cancelled => "cancelled",
            CallOutcome::SetupTimeout => "timeout",
            CallOutcome::Rejected { code } if !is_trunk_strike_code(*code) => "rejected",
            _ => "failed",
        }
    }
}

/// Finals that mean the *trunk* failed (RFC 3261 §21.4.9, §21.5): a
/// timeout, an internal error, a bad gateway, an unavailable service or a
/// gateway timeout. Everything else (486, 603, 404, 501, 6xx…) is the
/// callee's or the request's problem and never cools the trunk.
pub(crate) fn is_trunk_strike_code(status: u16) -> bool {
    matches!(status, 408 | 500 | 502 | 503 | 504)
}

/// `Retry-After` of a response, in seconds, when present and sane (1 s to
/// 1 h — RFC 3261 §20.33 allows a comment and `;duration`, ignored here).
pub(crate) fn retry_after_secs(raw: &str) -> Option<u64> {
    for line in raw.split("\r\n") {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("Retry-After") {
            continue;
        }
        let digits: String = value
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        return digits
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=3600).contains(s));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_parsed_and_bounded() {
        let raw = "SIP/2.0 503 Service Unavailable\r\nRetry-After: 120 (maintenance);duration=3600\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(retry_after_secs(raw), Some(120));
        assert_eq!(
            retry_after_secs("SIP/2.0 503 X\r\nretry-after: 0\r\n\r\n"),
            None,
            "0 is not a park"
        );
        assert_eq!(
            retry_after_secs("SIP/2.0 503 X\r\nRetry-After: 999999\r\n\r\n"),
            None,
            "a day-long park is refused"
        );
        assert_eq!(
            retry_after_secs("SIP/2.0 503 X\r\n\r\nRetry-After: 5"),
            None
        );
    }

    #[test]
    fn park_for_keeps_the_longer_cooldown_and_counts_a_failure() {
        let mut s = crate::routing::trunk::TrunkState::new(uuid::Uuid::new_v4());
        s.park_for(300);
        let long = s.parked_until.unwrap();
        s.park_for(10);
        assert_eq!(
            s.parked_until.unwrap(),
            long,
            "shorter park does not shorten"
        );
        assert_eq!((s.consecutive_failures, s.failed_calls), (2, 2));
        // A 200 OK lifts the failure cooldown but not a park the trunk asked for.
        s.record_trunk_failure();
        s.record_trunk_failure();
        s.record_trunk_failure();
        assert!(s.disabled_until.is_some(), "3 failures → cooldown");
        s.record_success();
        assert!(s.disabled_until.is_none());
        assert!(s.parked_until.is_some(), "the park survives a 200 OK");
        let now = std::time::Instant::now();
        assert_eq!(s.health_label(now), "parked");
        assert!(s.unavailable_for(now).is_some());
        // Only an operator re-enable (or expiry) forgives the park.
        s.clear_cooldowns();
        assert_eq!(s.health_label(now), "up");
        assert!(s.unavailable_for(now).is_none());
    }

    #[test]
    fn strike_set_is_the_trunk_failure_codes_only() {
        for code in [408, 500, 502, 503, 504] {
            assert!(is_trunk_strike_code(code), "{}", code);
        }
        for code in [404, 486, 487, 501, 505, 600, 603, 604, 606] {
            assert!(!is_trunk_strike_code(code), "{}", code);
        }
        assert_eq!(
            Sbc::trunk_outcome_label(&CallOutcome::Rejected { code: 486 }, false),
            "rejected"
        );
        assert_eq!(
            Sbc::trunk_outcome_label(&CallOutcome::Rejected { code: 503 }, false),
            "failed"
        );
        assert_eq!(
            Sbc::trunk_outcome_label(&CallOutcome::Refused { code: 404 }, false),
            "failed"
        );
        assert_eq!(
            Sbc::trunk_outcome_label(&CallOutcome::Rejected { code: 486 }, true),
            "answered"
        );
    }
}
