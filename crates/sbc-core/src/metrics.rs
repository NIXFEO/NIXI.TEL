//! Prometheus Metrics + Health Checks
//!
//! Exposes SBC operational metrics for monitoring dashboards.
//! Compatible with Prometheus scraping format (text/plain).
//!
//! Conventions (keep them when adding a family):
//! - names are `sbc_<subject>_<unit>`; counters end in `_total` (the
//!   `counter!` macro appends it: pass the base name), timestamps in
//!   `_timestamp_seconds`, durations in `_seconds`;
//! - unlabelled series go through the `gauge!` / `counter!` macros;
//!   labelled families are hand-rendered from a map, sorted by label so
//!   the exposition is stable, with label values escaped by
//!   [`escape_label`];
//! - a labelled family is exported only for keys that exist (a trunk that
//!   never answered OPTIONS has no `sbc_trunk_up`), and one `# TYPE` line
//!   per family — a second one makes Prometheus reject the whole scrape;
//! - series derived from another manager's snapshot (trunk availability)
//!   are rendered by a free function the `/metrics` route appends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Upper bounds (seconds) of `sbc_call_setup_seconds`: INVITE forwarded →
/// final answer. Post-dial delay lives in the first buckets, ringing in the
/// last ones (Timer C caps it at 180 s).
pub const SETUP_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 180.0,
];
/// Upper bounds (seconds) of `sbc_call_duration_seconds`: answer → end.
pub const DURATION_BUCKETS: &[f64] = &[
    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 14400.0,
];

/// A fixed-bucket histogram rendered in the Prometheus text format
/// (cumulative `_bucket{le}` series, `+Inf`, `_sum`, `_count`). Lock-free:
/// one atomic per bucket.
pub struct Histogram {
    bounds: &'static [f64],
    buckets: Vec<AtomicU64>,
    sum_millis: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_millis: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record one observation in seconds (negative values count as 0).
    pub fn observe_secs(&self, secs: f64) {
        let secs = if secs.is_finite() && secs > 0.0 {
            secs
        } else {
            0.0
        };
        for (i, bound) in self.bounds.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_millis
            .fetch_add((secs * 1000.0).round() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        out.push_str(&format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            name, help, name
        ));
        for (i, bound) in self.bounds.iter().enumerate() {
            out.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                name,
                bound,
                self.buckets[i].load(Ordering::Relaxed)
            ));
        }
        let count = self.count();
        out.push_str(&format!("{}_bucket{{le=\"+Inf\"}} {}\n", name, count));
        out.push_str(&format!(
            "{}_sum {}\n",
            name,
            self.sum_millis.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        out.push_str(&format!("{}_count {}\n", name, count));
    }
}

/// Per-trunk series, keyed by trunk name. `None` gauges are not exported
/// (a trunk that never answered OPTIONS has no `sbc_trunk_up`; a trunk
/// without `register_with_trunk` has no `sbc_trunk_registered`).
#[derive(Debug, Default, Clone)]
pub struct TrunkSeries {
    pub up: Option<bool>,
    pub registered: Option<bool>,
    pub active_calls: u64,
    /// Finished calls by (direction, outcome): `answered`, `rejected` (the
    /// callee's answer: busy, declined, unknown number…), `failed` (the
    /// trunk's or the SBC's: 5xx, 408, no route), `cancelled`, `timeout`,
    /// `failover` (the attempt moved to the next trunk). Outbound ASR =
    /// answered / all, both on `direction="outbound"`.
    pub calls: HashMap<(String, &'static str), u64>,
}

/// All SBC counters and gauges
pub struct SbcMetrics {
    // ── Counters (monotonically increasing) ──────────────────────────────────
    /// Total SIP requests received
    pub sip_requests_total: Arc<AtomicU64>,

    /// SIP requests by method (INVITE, BYE, REGISTER, …)
    pub sip_requests_by_method: Arc<std::sync::Mutex<HashMap<String, u64>>>,

    /// Total SIP responses sent
    pub sip_responses_total: Arc<AtomicU64>,

    /// 4xx responses (auth errors, bad requests)
    pub sip_4xx_total: Arc<AtomicU64>,

    /// 5xx responses (server errors)
    pub sip_5xx_total: Arc<AtomicU64>,

    /// Total calls attempted
    pub calls_total: Arc<AtomicU64>,

    /// Total calls connected (200 OK received)
    pub calls_connected_total: Arc<AtomicU64>,

    /// Total calls failed (4xx/5xx/timeout)
    pub calls_failed_total: Arc<AtomicU64>,

    /// Total calls terminated (BYE)
    pub calls_terminated_total: Arc<AtomicU64>,

    /// Total auth challenges sent (401/407)
    pub auth_challenges_total: Arc<AtomicU64>,

    /// Total auth failures
    pub auth_failures_total: Arc<AtomicU64>,
    /// 401/407 re-challenges with stale=true (cached nonce, not an attack)
    pub auth_stale_challenges_total: Arc<AtomicU64>,

    /// Total RTP packets forwarded
    pub rtp_packets_total: Arc<AtomicU64>,

    /// Total SRTP packets encrypted
    pub srtp_encrypted_total: Arc<AtomicU64>,

    /// Total SRTP packets decrypted
    pub srtp_decrypted_total: Arc<AtomicU64>,

    /// Total transcoded RTP packets (Opus↔G.711, PCMU↔PCMA)
    pub transcoded_total: Arc<AtomicU64>,

    /// Total successful REGISTER requests
    pub registrations_total: Arc<AtomicU64>,

    /// Total INVITE rejected by anti-spam (unregistered source)
    pub spam_blocked_total: Arc<AtomicU64>,

    /// Total SIP messages with parse errors
    pub sip_parse_errors_total: Arc<AtomicU64>,

    /// Total DoS/rate-limited requests (503)
    pub dos_blocked_total: Arc<AtomicU64>,

    /// Total ACL denied requests
    pub acl_denied_total: Arc<AtomicU64>,

    /// Total fail2ban bans issued (auth-failure threshold reached)
    pub security_bans_total: Arc<AtomicU64>,

    /// Total packets/requests dropped because their source IP was banned
    pub security_ban_drops_total: Arc<AtomicU64>,

    /// Total calls blocked by destination rules (anti-IRSF)
    pub security_destination_blocked_total: Arc<AtomicU64>,

    /// Total calls rejected by per-user limits (concurrent + rate)
    pub security_user_limit_rejections_total: Arc<AtomicU64>,
    /// REGISTER/INVITE identities that did not match the authenticated source
    pub security_identity_mismatches_total: Arc<AtomicU64>,

    /// Total calls torn down by the RTP inactivity timeout (media stopped
    /// without a BYE — e.g. Jambonz-style callees). A rising rate signals
    /// one-way-audio or media-path problems.
    pub rtp_timeouts_total: Arc<AtomicU64>,

    /// Outbound INVITEs re-sent after a trunk's `422 Session Interval Too
    /// Small` (RFC 4028 §7.4). A steady rate means a trunk's Min-SE floor
    /// is above `[security] session_expires` — raise it to skip the round trip.
    pub session_timer_422_retries_total: Arc<AtomicU64>,

    /// SIP responses by status code (200, 401, 403, 486, 503 etc.)
    pub sip_responses_by_code: Arc<std::sync::Mutex<HashMap<u16, u64>>>,

    /// SIP messages the SBC could not send, by transport (udp/tcp/tls/ws/wss).
    /// Any non-zero rate means calls are ending in ghost sessions.
    pub sip_send_failures: Arc<std::sync::Mutex<HashMap<&'static str, u64>>>,

    // ── Gauges (current value) ────────────────────────────────────────────────
    /// Currently active calls
    pub active_calls: Arc<AtomicU64>,

    /// Currently active WebRTC calls
    pub active_webrtc_calls: Arc<AtomicU64>,

    /// Currently allocated RTP port pairs
    pub allocated_ports: Arc<AtomicU64>,

    /// Currently active SIP registrations
    pub active_registrations: Arc<AtomicU64>,

    /// Source IPs tracked by the DoS limiter (bounded by the sweeper + cap).
    pub dos_tracked_ips: Arc<AtomicU64>,

    /// Outstanding digest nonces (bounded by the sweeper + cap).
    pub auth_nonces: Arc<AtomicU64>,

    /// Unix timestamp (seconds) of the most recent CDR successfully written
    /// (0 = none since start). Lets monitoring alert when CDRs stop flowing —
    /// the failure mode where the CDR file silently went empty for weeks.
    pub last_cdr_written_time: Arc<AtomicU64>,

    /// Per-trunk gauges and counters (see [`TrunkSeries`]).
    pub trunks: Arc<std::sync::Mutex<HashMap<String, TrunkSeries>>>,
    /// Lines the non-blocking log writer dropped because stdout/journald
    /// did not keep up (sampled from the writer's counter).
    pub log_dropped_lines: Arc<AtomicU64>,
    /// 1 when the SQLite config store is open and hydrated.
    pub store_available: Arc<AtomicU64>,
    /// 1 when the backup timer runs.
    pub store_backups_enabled: Arc<AtomicU64>,
    /// The timer's interval (seconds), for the staleness alert.
    pub store_backup_interval_secs: Arc<AtomicU64>,
    /// Unix time of the last successful backup (0 = none known).
    pub store_backup_last_success_time: Arc<AtomicU64>,
    pub store_backup_last_bytes: Arc<AtomicU64>,
    pub store_backup_failures_total: Arc<AtomicU64>,
    /// INVITE forwarded → final answer, answered calls only.
    pub call_setup_seconds: Histogram,
    /// Answer → end (the billable window).
    pub call_duration_seconds: Histogram,
    /// Uptime start timestamp (Unix seconds)
    pub start_time: u64,
}

impl SbcMetrics {
    pub fn new() -> Self {
        Self {
            sip_requests_total: Arc::new(AtomicU64::new(0)),
            sip_requests_by_method: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sip_responses_total: Arc::new(AtomicU64::new(0)),
            sip_4xx_total: Arc::new(AtomicU64::new(0)),
            sip_5xx_total: Arc::new(AtomicU64::new(0)),
            calls_total: Arc::new(AtomicU64::new(0)),
            calls_connected_total: Arc::new(AtomicU64::new(0)),
            calls_failed_total: Arc::new(AtomicU64::new(0)),
            calls_terminated_total: Arc::new(AtomicU64::new(0)),
            auth_challenges_total: Arc::new(AtomicU64::new(0)),
            auth_failures_total: Arc::new(AtomicU64::new(0)),
            auth_stale_challenges_total: Arc::new(AtomicU64::new(0)),
            rtp_packets_total: Arc::new(AtomicU64::new(0)),
            srtp_encrypted_total: Arc::new(AtomicU64::new(0)),
            srtp_decrypted_total: Arc::new(AtomicU64::new(0)),
            transcoded_total: Arc::new(AtomicU64::new(0)),
            registrations_total: Arc::new(AtomicU64::new(0)),
            spam_blocked_total: Arc::new(AtomicU64::new(0)),
            sip_parse_errors_total: Arc::new(AtomicU64::new(0)),
            dos_blocked_total: Arc::new(AtomicU64::new(0)),
            acl_denied_total: Arc::new(AtomicU64::new(0)),
            security_bans_total: Arc::new(AtomicU64::new(0)),
            security_ban_drops_total: Arc::new(AtomicU64::new(0)),
            security_destination_blocked_total: Arc::new(AtomicU64::new(0)),
            security_user_limit_rejections_total: Arc::new(AtomicU64::new(0)),
            security_identity_mismatches_total: Arc::new(AtomicU64::new(0)),
            rtp_timeouts_total: Arc::new(AtomicU64::new(0)),
            session_timer_422_retries_total: Arc::new(AtomicU64::new(0)),
            sip_responses_by_code: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sip_send_failures: Arc::new(std::sync::Mutex::new(HashMap::new())),
            active_calls: Arc::new(AtomicU64::new(0)),
            active_webrtc_calls: Arc::new(AtomicU64::new(0)),
            allocated_ports: Arc::new(AtomicU64::new(0)),
            active_registrations: Arc::new(AtomicU64::new(0)),
            dos_tracked_ips: Arc::new(AtomicU64::new(0)),
            auth_nonces: Arc::new(AtomicU64::new(0)),
            last_cdr_written_time: Arc::new(AtomicU64::new(0)),
            trunks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            log_dropped_lines: Arc::new(AtomicU64::new(0)),
            store_available: Arc::new(AtomicU64::new(0)),
            store_backups_enabled: Arc::new(AtomicU64::new(0)),
            store_backup_interval_secs: Arc::new(AtomicU64::new(0)),
            store_backup_last_success_time: Arc::new(AtomicU64::new(0)),
            store_backup_last_bytes: Arc::new(AtomicU64::new(0)),
            store_backup_failures_total: Arc::new(AtomicU64::new(0)),
            call_setup_seconds: Histogram::new(SETUP_BUCKETS),
            call_duration_seconds: Histogram::new(DURATION_BUCKETS),
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        }
    }

    // ── Increment helpers ─────────────────────────────────────────────────────

    pub fn inc_sip_request(&self, method: &str) {
        self.sip_requests_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.sip_requests_by_method.lock() {
            *map.entry(method.to_uppercase()).or_insert(0) += 1;
        }
    }

    pub fn inc_sip_response(&self, code: u16) {
        self.sip_responses_total.fetch_add(1, Ordering::Relaxed);
        if (400..500).contains(&code) {
            self.sip_4xx_total.fetch_add(1, Ordering::Relaxed);
        }
        if (500..600).contains(&code) {
            self.sip_5xx_total.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut map) = self.sip_responses_by_code.lock() {
            *map.entry(code).or_insert(0) += 1;
        }
    }

    /// Count a SIP message the transport layer failed to send.
    pub fn inc_sip_send_failure(&self, transport: rsip::Transport) {
        let label = match transport {
            rsip::Transport::Udp => "udp",
            rsip::Transport::Tcp => "tcp",
            rsip::Transport::Tls => "tls",
            rsip::Transport::Ws => "ws",
            rsip::Transport::Wss => "wss",
            _ => "other",
        };
        if let Ok(mut map) = self.sip_send_failures.lock() {
            *map.entry(label).or_insert(0) += 1;
        }
    }

    pub fn inc_call_attempted(&self) {
        self.calls_total.fetch_add(1, Ordering::Relaxed);
        self.active_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_call_connected(&self) {
        self.calls_connected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_call_failed(&self) {
        self.calls_failed_total.fetch_add(1, Ordering::Relaxed);
        // Protect against underflow
        let prev = self.active_calls.load(Ordering::Relaxed);
        if prev > 0 {
            self.active_calls.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn inc_call_terminated(&self) {
        self.calls_terminated_total.fetch_add(1, Ordering::Relaxed);
        // Protect against underflow
        let prev = self.active_calls.load(Ordering::Relaxed);
        if prev > 0 {
            self.active_calls.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn inc_auth_challenge(&self) {
        self.auth_challenges_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_stale_challenge(&self) {
        self.auth_stale_challenges_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_failure(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rtp_packet(&self) {
        self.rtp_packets_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_srtp_encrypted(&self) {
        self.srtp_encrypted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_srtp_decrypted(&self) {
        self.srtp_decrypted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_registration(&self) {
        self.registrations_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_spam_blocked(&self) {
        self.spam_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_sip_parse_error(&self) {
        self.sip_parse_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dos_blocked(&self) {
        self.dos_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_acl_denied(&self) {
        self.acl_denied_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a fail2ban ban being issued.
    pub fn inc_security_ban(&self) {
        self.security_bans_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a packet/request dropped because its source is banned.
    pub fn inc_security_ban_drop(&self) {
        self.security_ban_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call blocked by destination rules (anti-IRSF).
    pub fn inc_security_destination_blocked(&self) {
        self.security_destination_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call rejected by per-user limits.
    pub fn inc_security_identity_mismatch(&self) {
        self.security_identity_mismatches_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_security_user_limit_rejection(&self) {
        self.security_user_limit_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call torn down by the RTP inactivity timeout.
    pub fn inc_rtp_timeout(&self) {
        self.rtp_timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count an INVITE re-sent after a 422 Session Interval Too Small.
    pub fn inc_session_timer_422_retry(&self) {
        self.session_timer_422_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Stamp the time a CDR was just written (Unix seconds, current time).
    pub fn set_log_dropped_lines(&self, n: u64) {
        self.log_dropped_lines.store(n, Ordering::Relaxed);
    }

    pub fn set_store_available(&self, on: bool) {
        self.store_available.store(u64::from(on), Ordering::Relaxed);
    }

    pub fn set_store_backups(&self, interval: Option<Duration>) {
        self.store_backups_enabled
            .store(u64::from(interval.is_some()), Ordering::Relaxed);
        self.store_backup_interval_secs.store(
            interval.map(|d| d.as_secs()).unwrap_or(0),
            Ordering::Relaxed,
        );
    }

    /// A backup succeeded now.
    pub fn record_store_backup(&self, bytes: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.record_store_backup_at(now, bytes);
    }

    /// Seed the last-success gauge from an existing file (survives restarts).
    pub fn record_store_backup_at(&self, unix_secs: u64, bytes: u64) {
        self.store_backup_last_success_time
            .store(unix_secs, Ordering::Relaxed);
        self.store_backup_last_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn inc_store_backup_failure(&self) {
        self.store_backup_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cdr_written(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.last_cdr_written_time.store(now, Ordering::Relaxed);
    }

    pub fn set_allocated_ports(&self, n: u64) {
        self.allocated_ports.store(n, Ordering::Relaxed);
    }

    pub fn set_dos_tracked_ips(&self, n: u64) {
        self.dos_tracked_ips.store(n, Ordering::Relaxed);
    }

    pub fn set_auth_nonces(&self, n: u64) {
        self.auth_nonces.store(n, Ordering::Relaxed);
    }

    pub fn set_active_registrations(&self, n: u64) {
        self.active_registrations.store(n, Ordering::Relaxed);
    }

    pub fn set_active_webrtc(&self, n: u64) {
        self.active_webrtc_calls.store(n, Ordering::Relaxed);
    }

    /// Uptime in seconds
    // ── Per-trunk series ─────────────────────────────────────────────────
    fn with_trunk<F: FnOnce(&mut TrunkSeries)>(&self, trunk: &str, f: F) {
        if let Ok(mut map) = self.trunks.lock() {
            f(map.entry(trunk.to_string()).or_default());
        }
    }

    /// OPTIONS health verdict: `Some(true)` up, `Some(false)` down, `None`
    /// unknown (the trunk never answered OPTIONS: passive monitoring only).
    pub fn set_trunk_up(&self, trunk: &str, up: Option<bool>) {
        self.with_trunk(trunk, |t| t.up = up);
    }

    /// Outbound REGISTER state, for trunks that register.
    pub fn set_trunk_registered(&self, trunk: &str, registered: Option<bool>) {
        self.with_trunk(trunk, |t| t.registered = registered);
    }

    pub fn set_trunk_active_calls(&self, trunk: &str, n: u64) {
        self.with_trunk(trunk, |t| t.active_calls = n);
    }

    /// One finished call (or moved attempt) on this trunk.
    pub fn inc_trunk_call(&self, trunk: &str, direction: &str, outcome: &'static str) {
        self.with_trunk(trunk, |t| {
            *t.calls.entry((direction.to_string(), outcome)).or_insert(0) += 1
        });
    }

    /// Forget a trunk's series (deleted through the API).
    pub fn remove_trunk(&self, trunk: &str) {
        if let Ok(mut map) = self.trunks.lock() {
            map.remove(trunk);
        }
    }

    pub fn trunk_series(&self, trunk: &str) -> Option<TrunkSeries> {
        self.trunks.lock().ok().and_then(|m| m.get(trunk).cloned())
    }

    pub fn observe_call_setup(&self, secs: f64) {
        self.call_setup_seconds.observe_secs(secs);
    }

    pub fn observe_call_duration(&self, secs: f64) {
        self.call_duration_seconds.observe_secs(secs);
    }

    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            .saturating_sub(self.start_time)
    }

    /// Render Prometheus text format
    ///
    /// Returns the full metrics page as a `String`.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        macro_rules! gauge {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        macro_rules! counter {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{}_total {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        // ── Uptime ────────────────────────────────────────────────────────────
        gauge!(
            "sbc_uptime_seconds",
            "SBC uptime in seconds",
            self.uptime_secs()
        );

        // ── Active gauges ─────────────────────────────────────────────────────
        gauge!(
            "sbc_active_calls",
            "Number of currently active calls",
            self.active_calls.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_active_webrtc_calls",
            "Number of currently active WebRTC calls",
            self.active_webrtc_calls.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_allocated_rtp_ports",
            "Number of currently allocated RTP port pairs",
            self.allocated_ports.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_active_registrations",
            "Number of currently active SIP registrations",
            self.active_registrations.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_dos_tracked_ips",
            "Source IPs tracked by the DoS limiter",
            self.dos_tracked_ips.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_auth_nonces",
            "Outstanding digest authentication nonces",
            self.auth_nonces.load(Ordering::Relaxed)
        );

        gauge!(
            "sbc_last_cdr_written_timestamp_seconds",
            "Unix time of the last CDR written (0 = none since start)",
            self.last_cdr_written_time.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_log_dropped_lines",
            "Log lines dropped by the non-blocking writer since start (journald/stdout back-pressure)",
            self.log_dropped_lines.load(Ordering::Relaxed)
        );

        // ── Config store ──────────────────────────────────────────────────────
        gauge!(
            "sbc_store_available",
            "SQLite config store open and hydrated (1) or missing (0)",
            self.store_available.load(Ordering::Relaxed)
        );
        gauge!(
            "sbc_store_backups_enabled",
            "Automatic store backups scheduled (1) or disabled (0)",
            self.store_backups_enabled.load(Ordering::Relaxed)
        );
        gauge!(
            "sbc_store_backup_interval_seconds",
            "Interval of the automatic store backups (0 when disabled)",
            self.store_backup_interval_secs.load(Ordering::Relaxed)
        );
        gauge!(
            "sbc_store_backup_last_success_timestamp_seconds",
            "Unix time of the last successful store backup (0 = none known)",
            self.store_backup_last_success_time.load(Ordering::Relaxed)
        );
        gauge!(
            "sbc_store_backup_last_bytes",
            "Size of the last successful store backup",
            self.store_backup_last_bytes.load(Ordering::Relaxed)
        );
        counter!(
            "sbc_store_backup_failures",
            "Store backups that failed (API or timer)",
            self.store_backup_failures_total.load(Ordering::Relaxed)
        );

        // ── SIP counters ──────────────────────────────────────────────────────
        counter!(
            "sbc_sip_requests",
            "Total SIP requests received",
            self.sip_requests_total.load(Ordering::Relaxed)
        );

        // Per-method counters
        if let Ok(map) = self.sip_requests_by_method.lock() {
            out.push_str("# HELP sbc_sip_requests_by_method Total SIP requests by method\n");
            out.push_str("# TYPE sbc_sip_requests_by_method counter\n");
            for (method, count) in map.iter() {
                out.push_str(&format!(
                    "sbc_sip_requests_by_method{{method=\"{}\"}} {}\n",
                    method, count
                ));
            }
        }

        counter!(
            "sbc_sip_responses",
            "Total SIP responses sent",
            self.sip_responses_total.load(Ordering::Relaxed)
        );

        // Per-code response counters
        if let Ok(map) = self.sip_responses_by_code.lock() {
            out.push_str("# HELP sbc_sip_responses_by_code Total SIP responses by status code\n");
            out.push_str("# TYPE sbc_sip_responses_by_code counter\n");
            for (code, count) in map.iter() {
                out.push_str(&format!(
                    "sbc_sip_responses_by_code{{code=\"{}\"}} {}\n",
                    code, count
                ));
            }
        }

        out.push_str("# HELP sbc_sip_send_failures_total SIP messages the SBC could not send, by transport\n");
        out.push_str("# TYPE sbc_sip_send_failures_total counter\n");
        if let Ok(map) = self.sip_send_failures.lock() {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort();
            for (transport, count) in entries {
                out.push_str(&format!(
                    "sbc_sip_send_failures_total{{transport=\"{}\"}} {}\n",
                    transport, count
                ));
            }
        }

        counter!(
            "sbc_sip_4xx",
            "Total SIP 4xx responses",
            self.sip_4xx_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_sip_5xx",
            "Total SIP 5xx responses",
            self.sip_5xx_total.load(Ordering::Relaxed)
        );

        // ── Call counters ─────────────────────────────────────────────────────
        counter!(
            "sbc_calls",
            "Total call attempts",
            self.calls_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_calls_connected",
            "Total calls successfully connected",
            self.calls_connected_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_calls_failed",
            "Total calls that failed",
            self.calls_failed_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_calls_terminated",
            "Total calls terminated via BYE",
            self.calls_terminated_total.load(Ordering::Relaxed)
        );

        // ── Auth counters ─────────────────────────────────────────────────────
        counter!(
            "sbc_auth_challenges",
            "Total authentication challenges issued",
            self.auth_challenges_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_auth_failures",
            "Total authentication failures",
            self.auth_failures_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_auth_stale_challenges",
            "Re-challenges with stale=true (client used an old nonce)",
            self.auth_stale_challenges_total.load(Ordering::Relaxed)
        );

        // ── Registration counters ───────────────────────────────────────────────
        counter!(
            "sbc_registrations",
            "Total successful REGISTER requests",
            self.registrations_total.load(Ordering::Relaxed)
        );

        // ── Security counters ──────────────────────────────────────────────────
        counter!(
            "sbc_spam_blocked",
            "Total INVITE rejected from unregistered sources",
            self.spam_blocked_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_sip_parse_errors",
            "Total SIP messages with parse errors (scanners)",
            self.sip_parse_errors_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_dos_blocked",
            "Total requests blocked by rate limiter (503)",
            self.dos_blocked_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_acl_denied",
            "Total requests denied by ACL rules",
            self.acl_denied_total.load(Ordering::Relaxed)
        );

        // ── Anti-fraud counters (fail2ban / IRSF / per-user limits) ────────────
        counter!(
            "sbc_security_bans",
            "Total fail2ban bans issued (auth-failure threshold reached)",
            self.security_bans_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_security_ban_drops",
            "Total requests dropped because their source IP was banned",
            self.security_ban_drops_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_security_destination_blocked",
            "Total calls blocked by destination rules (anti-IRSF)",
            self.security_destination_blocked_total
                .load(Ordering::Relaxed)
        );

        counter!(
            "sbc_security_user_limit_rejections",
            "Total calls rejected by per-user limits (concurrent + rate)",
            self.security_user_limit_rejections_total
                .load(Ordering::Relaxed)
        );

        counter!(
            "sbc_security_identity_mismatches",
            "Identities claimed by a source that is not entitled to them (REGISTER/INVITE)",
            self.security_identity_mismatches_total
                .load(Ordering::Relaxed)
        );

        counter!(
            "sbc_rtp_timeouts",
            "Total calls torn down by the RTP inactivity timeout",
            self.rtp_timeouts_total.load(Ordering::Relaxed)
        );

        counter!("sbc_session_timer_422_retries",
                 "Total outbound INVITEs re-sent after a trunk 422 Session Interval Too Small (RFC 4028)",
                 self.session_timer_422_retries_total.load(Ordering::Relaxed));

        // ── Per-trunk series ──────────────────────────────────────────────────
        if let Ok(map) = self.trunks.lock() {
            let mut names: Vec<&String> = map.keys().collect();
            names.sort();
            let mut ups = String::new();
            let mut regs = String::new();
            let mut actives = String::new();
            let mut calls = String::new();
            for name in names {
                let t = &map[name];
                let label = escape_label(name);
                if let Some(up) = t.up {
                    ups.push_str(&format!(
                        "sbc_trunk_up{{trunk=\"{}\"}} {}\n",
                        label,
                        u8::from(up)
                    ));
                }
                if let Some(r) = t.registered {
                    regs.push_str(&format!(
                        "sbc_trunk_registered{{trunk=\"{}\"}} {}\n",
                        label,
                        u8::from(r)
                    ));
                }
                actives.push_str(&format!(
                    "sbc_trunk_active_calls{{trunk=\"{}\"}} {}\n",
                    label, t.active_calls
                ));
                let mut outcomes: Vec<_> = t.calls.iter().collect();
                outcomes.sort();
                for ((direction, outcome), n) in outcomes {
                    calls.push_str(&format!(
                        "sbc_trunk_calls_total{{trunk=\"{}\",direction=\"{}\",outcome=\"{}\"}} {}\n",
                        label,
                        escape_label(direction),
                        outcome,
                        n
                    ));
                }
            }
            out.push_str("# HELP sbc_trunk_up Trunk answers OPTIONS (1) or stopped answering (0); absent when it never answered\n# TYPE sbc_trunk_up gauge\n");
            out.push_str(&ups);
            out.push_str("# HELP sbc_trunk_registered Outbound REGISTER to the trunk is current (1) or failing (0)\n# TYPE sbc_trunk_registered gauge\n");
            out.push_str(&regs);
            out.push_str("# HELP sbc_trunk_active_calls Calls currently on the trunk (both directions)\n# TYPE sbc_trunk_active_calls gauge\n");
            out.push_str(&actives);
            out.push_str("# HELP sbc_trunk_calls_total Finished calls per trunk by direction and outcome (answered, rejected, failed, cancelled, timeout, failover)\n# TYPE sbc_trunk_calls_total counter\n");
            out.push_str(&calls);
        }

        // ── Call timing histograms ────────────────────────────────────────────
        self.call_setup_seconds.render(
            &mut out,
            "sbc_call_setup_seconds",
            "INVITE forwarded to final answer, answered calls only",
        );
        self.call_duration_seconds.render(
            &mut out,
            "sbc_call_duration_seconds",
            "Answer to end of call (billable window)",
        );

        // ── Media counters ────────────────────────────────────────────────────
        counter!(
            "sbc_rtp_packets",
            "Total RTP packets forwarded",
            self.rtp_packets_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_srtp_encrypted",
            "Total SRTP packets encrypted",
            self.srtp_encrypted_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_srtp_decrypted",
            "Total SRTP packets decrypted",
            self.srtp_decrypted_total.load(Ordering::Relaxed)
        );

        counter!(
            "sbc_transcoded_packets",
            "Total RTP packets transcoded (Opus/G.711)",
            self.transcoded_total.load(Ordering::Relaxed)
        );

        out
    }
}

impl Default for SbcMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape a label value for the text exposition (backslash, quote, newline).
pub fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Trunk availability from a `TrunkManager` snapshot: `sbc_trunk_enabled`,
/// `sbc_trunk_available` (enabled and neither in cooldown nor parked: the
/// router will select it), `sbc_trunk_unavailable_seconds` (time left in
/// the cooldown/park) and `sbc_trunk_consecutive_failures`. Appended by
/// the `/metrics` route after [`SbcMetrics::render_prometheus`].
pub fn render_trunk_availability(
    stats: &[(
        crate::routing::TrunkConfig,
        crate::routing::trunk::TrunkState,
    )],
) -> String {
    let now = std::time::Instant::now();
    let mut rows: Vec<_> = stats.iter().collect();
    rows.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    let mut enabled = String::new();
    let mut available = String::new();
    let mut unavailable = String::new();
    let mut failures = String::new();
    for (cfg, state) in rows {
        let label = escape_label(&cfg.name);
        let left = state.unavailable_for(now);
        enabled.push_str(&format!(
            "sbc_trunk_enabled{{trunk=\"{}\"}} {}\n",
            label,
            u8::from(cfg.enabled)
        ));
        available.push_str(&format!(
            "sbc_trunk_available{{trunk=\"{}\"}} {}\n",
            label,
            u8::from(cfg.enabled && left.is_none())
        ));
        unavailable.push_str(&format!(
            "sbc_trunk_unavailable_seconds{{trunk=\"{}\"}} {}\n",
            label,
            left.map(|d| d.as_secs()).unwrap_or(0)
        ));
        failures.push_str(&format!(
            "sbc_trunk_consecutive_failures{{trunk=\"{}\"}} {}\n",
            label, state.consecutive_failures
        ));
    }
    let mut out = String::with_capacity(512);
    out.push_str("# HELP sbc_trunk_enabled Trunk enabled in the table (1) or disabled (0)\n# TYPE sbc_trunk_enabled gauge\n");
    out.push_str(&enabled);
    out.push_str("# HELP sbc_trunk_available Trunk selectable by the router: enabled, not in failure cooldown, not parked by a 503 Retry-After\n# TYPE sbc_trunk_available gauge\n");
    out.push_str(&available);
    out.push_str("# HELP sbc_trunk_unavailable_seconds Seconds left before the router selects the trunk again (0 when available)\n# TYPE sbc_trunk_unavailable_seconds gauge\n");
    out.push_str(&unavailable);
    out.push_str("# HELP sbc_trunk_consecutive_failures Consecutive call or probe failures (reset by a 200 OK or an OPTIONS answer)\n# TYPE sbc_trunk_consecutive_failures gauge\n");
    out.push_str(&failures);
    out
}

// ── Health check ───────────────────────────────────────────────────────────────

/// Health status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

impl HealthStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded(_) => "degraded",
            Self::Unhealthy(_) => "unhealthy",
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded(_))
    }
}

/// Aggregated health report
#[derive(Debug, Clone)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub uptime_secs: u64,
    pub active_calls: u64,
    pub checks: Vec<(String, HealthStatus)>,
}

impl HealthReport {
    /// Build from current metrics
    pub fn from_metrics(metrics: &SbcMetrics) -> Self {
        let mut checks = Vec::new();
        let active = metrics.active_calls.load(Ordering::Relaxed);

        // Check 1: call count sanity
        let call_check = if active < 10_000 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded(format!("High call load: {}", active))
        };
        checks.push(("call_capacity".to_string(), call_check));

        // Check 2: auth failure rate
        let auth_fail = metrics.auth_failures_total.load(Ordering::Relaxed);
        let auth_total = metrics.sip_requests_total.load(Ordering::Relaxed);
        let auth_check = if auth_total == 0 || auth_fail * 100 / auth_total.max(1) < 50 {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded(format!(
                "High auth failure rate: {}/{}",
                auth_fail, auth_total
            ))
        };
        checks.push(("auth_health".to_string(), auth_check));

        // Overall status: worst of all checks
        let status = checks
            .iter()
            .fold(HealthStatus::Healthy, |worst, (_, s)| match (&worst, s) {
                (_, HealthStatus::Unhealthy(m)) => HealthStatus::Unhealthy(m.clone()),
                (HealthStatus::Healthy, HealthStatus::Degraded(m)) => {
                    HealthStatus::Degraded(m.clone())
                }
                _ => worst,
            });

        Self {
            status,
            uptime_secs: metrics.uptime_secs(),
            active_calls: active,
            checks,
        }
    }

    /// Render as JSON string
    pub fn to_json(&self) -> String {
        let checks_json: String = self
            .checks
            .iter()
            .map(|(name, status)| {
                let detail = match status {
                    HealthStatus::Healthy => String::new(),
                    HealthStatus::Degraded(m) | HealthStatus::Unhealthy(m) => {
                        format!(", \"detail\": \"{}\"", m)
                    }
                };
                format!(
                    "{{\"name\": \"{}\", \"status\": \"{}\"{}}}",
                    name,
                    status.as_str(),
                    detail
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            "{{\"status\": \"{}\", \"uptime_seconds\": {}, \"active_calls\": {}, \"checks\": [{}]}}",
            self.status.as_str(),
            self.uptime_secs,
            self.active_calls,
            checks_json
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_are_cumulative_with_sum_and_count() {
        let h = Histogram::new(&[1.0, 5.0]);
        h.observe_secs(0.5);
        h.observe_secs(3.0);
        h.observe_secs(30.0);
        h.observe_secs(-1.0); // clamped to 0
        let mut out = String::new();
        h.render(&mut out, "t", "help");
        assert!(out.contains("# TYPE t histogram\n"), "{}", out);
        assert!(out.contains("t_bucket{le=\"1\"} 2\n"), "{}", out);
        assert!(out.contains("t_bucket{le=\"5\"} 3\n"), "{}", out);
        assert!(out.contains("t_bucket{le=\"+Inf\"} 4\n"), "{}", out);
        assert!(out.contains("t_sum 33.5\n"), "{}", out);
        assert!(out.contains("t_count 4\n"), "{}", out);
    }

    #[test]
    fn trunk_series_render_only_known_gauges() {
        let m = SbcMetrics::new();
        m.set_trunk_up("genesys", Some(true));
        m.set_trunk_active_calls("genesys", 3);
        m.inc_trunk_call("genesys", "outbound", "answered");
        m.inc_trunk_call("genesys", "outbound", "answered");
        m.inc_trunk_call("genesys", "outbound", "rejected");
        m.inc_trunk_call("genesys", "inbound", "failed");
        m.set_trunk_registered("cp\"aas", Some(false));
        let out = m.render_prometheus();
        assert!(
            out.contains("sbc_trunk_up{trunk=\"genesys\"} 1\n"),
            "{}",
            out
        );
        assert!(
            !out.contains("sbc_trunk_up{trunk=\"cp"),
            "unknown health is not exported"
        );
        assert!(
            out.contains("sbc_trunk_registered{trunk=\"cp\\\"aas\"} 0\n"),
            "{}",
            out
        );
        assert!(!out.contains("sbc_trunk_registered{trunk=\"genesys\""));
        assert!(out.contains("sbc_trunk_active_calls{trunk=\"genesys\"} 3\n"));
        assert!(out.contains(
            "sbc_trunk_calls_total{trunk=\"genesys\",direction=\"outbound\",outcome=\"answered\"} 2\n"
        ));
        assert!(out.contains(
            "sbc_trunk_calls_total{trunk=\"genesys\",direction=\"outbound\",outcome=\"rejected\"} 1\n"
        ));
        assert!(out.contains(
            "sbc_trunk_calls_total{trunk=\"genesys\",direction=\"inbound\",outcome=\"failed\"} 1\n"
        ));
        assert_eq!(out.matches("# TYPE sbc_trunk_up gauge").count(), 1);
        m.remove_trunk("cp\"aas");
        assert!(m.trunk_series("cp\"aas").is_none());
        assert!(m
            .render_prometheus()
            .contains("sbc_call_setup_seconds_bucket{le=\"+Inf\"} 0\n"));
    }

    #[test]
    fn trunk_availability_is_rendered_from_the_manager_snapshot() {
        let mut cfg = crate::routing::TrunkConfig::new("t1".into());
        cfg.enabled = true;
        let mut state = crate::routing::trunk::TrunkState::new(cfg.id);
        state.park_for(120);
        let mut off = crate::routing::TrunkConfig::new("t2".into());
        off.enabled = false;
        let off_state = crate::routing::trunk::TrunkState::new(off.id);
        let out = render_trunk_availability(&[(cfg, state), (off, off_state)]);
        assert!(
            out.contains("sbc_trunk_enabled{trunk=\"t1\"} 1\n"),
            "{}",
            out
        );
        assert!(
            out.contains("sbc_trunk_available{trunk=\"t1\"} 0\n"),
            "parked"
        );
        assert!(
            out.contains("sbc_trunk_unavailable_seconds{trunk=\"t1\"} 1"),
            "{}",
            out
        );
        assert!(out.contains("sbc_trunk_consecutive_failures{trunk=\"t1\"} 1\n"));
        assert!(out.contains("sbc_trunk_enabled{trunk=\"t2\"} 0\n"));
        assert!(
            out.contains("sbc_trunk_available{trunk=\"t2\"} 0\n"),
            "disabled"
        );
        assert_eq!(out.matches("# TYPE sbc_trunk_available gauge").count(), 1);
    }

    #[test]
    fn test_metrics_creation() {
        let m = SbcMetrics::new();
        assert_eq!(m.sip_requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.active_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_inc_sip_request() {
        let m = SbcMetrics::new();
        m.inc_sip_request("INVITE");
        m.inc_sip_request("INVITE");
        m.inc_sip_request("BYE");
        assert_eq!(m.sip_requests_total.load(Ordering::Relaxed), 3);

        let map = m.sip_requests_by_method.lock().unwrap();
        assert_eq!(map["INVITE"], 2);
        assert_eq!(map["BYE"], 1);
    }

    #[test]
    fn test_inc_sip_response() {
        let m = SbcMetrics::new();
        m.inc_sip_response(200);
        m.inc_sip_response(401);
        m.inc_sip_response(404);
        m.inc_sip_response(503);
        assert_eq!(m.sip_responses_total.load(Ordering::Relaxed), 4);
        assert_eq!(m.sip_4xx_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.sip_5xx_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_active_calls_gauge() {
        let m = SbcMetrics::new();
        m.inc_call_attempted();
        m.inc_call_attempted();
        assert_eq!(m.active_calls.load(Ordering::Relaxed), 2);
        m.inc_call_terminated();
        assert_eq!(m.active_calls.load(Ordering::Relaxed), 1);
        m.inc_call_failed();
        assert_eq!(m.active_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_uptime() {
        let m = SbcMetrics::new();
        // Uptime at creation should be 0 or 1 second
        assert!(m.uptime_secs() < 2);
    }

    #[test]
    fn test_render_prometheus() {
        let m = SbcMetrics::new();
        m.inc_sip_request("INVITE");
        m.inc_call_attempted();
        m.inc_auth_challenge();

        let output = m.render_prometheus();

        // Basic structure checks
        assert!(output.contains("# HELP sbc_uptime_seconds"));
        assert!(output.contains("# TYPE sbc_active_calls gauge"));
        assert!(output.contains("sbc_sip_requests_total"));
        assert!(output.contains("sbc_active_calls 1"));
        assert!(output.contains("sbc_auth_challenges_total 1"));
        assert!(output.contains("method=\"INVITE\""));
    }

    #[test]
    fn test_cdr_and_rtp_timeout_metrics() {
        let m = SbcMetrics::new();
        // Fresh metrics: no CDR yet, no timeouts.
        assert_eq!(m.last_cdr_written_time.load(Ordering::Relaxed), 0);

        m.inc_rtp_timeout();
        m.inc_rtp_timeout();
        m.record_cdr_written();

        assert_eq!(m.rtp_timeouts_total.load(Ordering::Relaxed), 2);
        assert!(m.last_cdr_written_time.load(Ordering::Relaxed) > 0);

        m.inc_session_timer_422_retry();
        assert_eq!(m.session_timer_422_retries_total.load(Ordering::Relaxed), 1);

        let output = m.render_prometheus();
        assert!(output.contains("sbc_rtp_timeouts_total 2"));
        m.set_dos_tracked_ips(7);
        m.set_auth_nonces(3);
        let output = m.render_prometheus();
        assert!(output.contains("# TYPE sbc_dos_tracked_ips gauge"));
        assert!(output.contains("sbc_dos_tracked_ips 7"));
        assert!(output.contains("sbc_auth_nonces 3"));
        assert!(output.contains("# TYPE sbc_session_timer_422_retries counter"));
        assert!(output.contains("sbc_session_timer_422_retries_total 1"));
        assert!(output.contains("# TYPE sbc_last_cdr_written_timestamp_seconds gauge"));
    }

    #[test]
    fn store_gauges_are_rendered() {
        let m = SbcMetrics::new();
        m.set_store_available(true);
        m.set_store_backups(Some(Duration::from_secs(86400)));
        m.record_store_backup(1234);
        m.inc_store_backup_failure();
        let out = m.render_prometheus();
        assert!(out.contains("sbc_store_available 1\n"), "{}", out);
        assert!(out.contains("sbc_store_backups_enabled 1\n"));
        assert!(out.contains("sbc_store_backup_interval_seconds 86400\n"));
        assert!(out.contains("sbc_store_backup_last_bytes 1234\n"));
        assert!(out.contains("sbc_store_backup_failures_total 1\n"));
        assert!(m.store_backup_last_success_time.load(Ordering::Relaxed) > 0);
        assert!(out.contains("sbc_log_dropped_lines_total 0\n"));
        m.set_log_dropped_lines(7);
        assert!(m
            .render_prometheus()
            .contains("sbc_log_dropped_lines_total 7\n"));
    }

    #[test]
    fn test_health_report_healthy() {
        let m = SbcMetrics::new();
        let report = HealthReport::from_metrics(&m);
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.status.is_ok());
    }

    #[test]
    fn test_health_report_json() {
        let m = SbcMetrics::new();
        let report = HealthReport::from_metrics(&m);
        let json = report.to_json();

        assert!(json.contains("\"status\": \"healthy\""));
        assert!(json.contains("\"uptime_seconds\""));
        assert!(json.contains("\"active_calls\""));
        assert!(json.contains("\"checks\""));
    }

    #[test]
    fn test_health_status_as_str() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded("x".to_string()).as_str(), "degraded");
        assert_eq!(
            HealthStatus::Unhealthy("y".to_string()).as_str(),
            "unhealthy"
        );
    }
}
