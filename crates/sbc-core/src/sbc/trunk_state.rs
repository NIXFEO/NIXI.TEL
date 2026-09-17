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
        if let Some(prev) = previous {
            self.trunk_manager
                .update_state_by_name(&prev, |s| s.decrement_calls());
            self.publish_trunk_active(&prev);
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

    /// A trunk failed a call attempt: 408/5xx/6xx, or no answer within
    /// `invite_timeout`. Consecutive failures apply the cooldown ladder;
    /// a `503 Retry-After` parks the trunk for exactly that long.
    pub(crate) fn note_trunk_failure(&self, name: &str, retry_after: Option<u64>) {
        let updated = self
            .trunk_manager
            .update_state_by_name(name, |s| match retry_after {
                Some(secs) => s.park_for(secs),
                None => s.record_trunk_failure(),
            });
        if !updated {
            return;
        }
        if let Some(s) = self.trunk_manager.state_by_name(name) {
            match s.disabled_until {
                Some(until) => warn!(
                    "Trunk '{}': {} consecutive failure(s) — no new calls routed there for {:?}",
                    name,
                    s.consecutive_failures,
                    until.saturating_duration_since(std::time::Instant::now())
                ),
                None => debug!(
                    "Trunk '{}': failure {} (no cooldown yet)",
                    name, s.consecutive_failures
                ),
            }
        }
    }

    /// A trunk answered 200 OK: failures reset, cooldown lifted.
    pub(crate) fn note_trunk_success(&self, name: &str) {
        self.trunk_manager
            .update_state_by_name(name, |s| s.record_success());
    }

    /// `sbc_trunk_calls_total{outcome}` label of a finished call.
    pub(crate) fn trunk_outcome_label(outcome: &CallOutcome, answered: bool) -> &'static str {
        if answered {
            return "answered";
        }
        match outcome {
            CallOutcome::Cancelled => "cancelled",
            CallOutcome::SetupTimeout => "timeout",
            _ => "failed",
        }
    }
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
        let long = s.disabled_until.unwrap();
        s.park_for(10);
        assert_eq!(
            s.disabled_until.unwrap(),
            long,
            "shorter park does not shorten"
        );
        assert_eq!((s.consecutive_failures, s.failed_calls), (2, 2));
        s.record_success();
        assert!(s.disabled_until.is_none());
    }
}
