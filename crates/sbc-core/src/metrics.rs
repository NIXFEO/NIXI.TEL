//! Prometheus Metrics + Health Checks
//!
//! Exposes SBC operational metrics for monitoring dashboards.
//! Compatible with Prometheus scraping format (text/plain).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    /// Total calls torn down by the RTP inactivity timeout (media stopped
    /// without a BYE — e.g. Jambonz-style callees). A rising rate signals
    /// one-way-audio or media-path problems.
    pub rtp_timeouts_total: Arc<AtomicU64>,

    /// SIP responses by status code (200, 401, 403, 486, 503 etc.)
    pub sip_responses_by_code: Arc<std::sync::Mutex<HashMap<u16, u64>>>,

    // ── Gauges (current value) ────────────────────────────────────────────────

    /// Currently active calls
    pub active_calls: Arc<AtomicU64>,

    /// Currently active WebRTC calls
    pub active_webrtc_calls: Arc<AtomicU64>,

    /// Currently allocated RTP port pairs
    pub allocated_ports: Arc<AtomicU64>,

    /// Currently active SIP registrations
    pub active_registrations: Arc<AtomicU64>,

    /// Unix timestamp (seconds) of the most recent CDR successfully written
    /// (0 = none since start). Lets monitoring alert when CDRs stop flowing —
    /// the failure mode where the CDR file silently went empty for weeks.
    pub last_cdr_written_time: Arc<AtomicU64>,

    /// Uptime start timestamp (Unix seconds)
    pub start_time: u64,
}

impl SbcMetrics {
    pub fn new() -> Self {
        Self {
            sip_requests_total:      Arc::new(AtomicU64::new(0)),
            sip_requests_by_method:  Arc::new(std::sync::Mutex::new(HashMap::new())),
            sip_responses_total:     Arc::new(AtomicU64::new(0)),
            sip_4xx_total:           Arc::new(AtomicU64::new(0)),
            sip_5xx_total:           Arc::new(AtomicU64::new(0)),
            calls_total:             Arc::new(AtomicU64::new(0)),
            calls_connected_total:   Arc::new(AtomicU64::new(0)),
            calls_failed_total:      Arc::new(AtomicU64::new(0)),
            calls_terminated_total:  Arc::new(AtomicU64::new(0)),
            auth_challenges_total:   Arc::new(AtomicU64::new(0)),
            auth_failures_total:     Arc::new(AtomicU64::new(0)),
            rtp_packets_total:       Arc::new(AtomicU64::new(0)),
            srtp_encrypted_total:    Arc::new(AtomicU64::new(0)),
            srtp_decrypted_total:    Arc::new(AtomicU64::new(0)),
            transcoded_total:        Arc::new(AtomicU64::new(0)),
            registrations_total:     Arc::new(AtomicU64::new(0)),
            spam_blocked_total:      Arc::new(AtomicU64::new(0)),
            sip_parse_errors_total:  Arc::new(AtomicU64::new(0)),
            dos_blocked_total:       Arc::new(AtomicU64::new(0)),
            acl_denied_total:        Arc::new(AtomicU64::new(0)),
            security_bans_total:                 Arc::new(AtomicU64::new(0)),
            security_ban_drops_total:            Arc::new(AtomicU64::new(0)),
            security_destination_blocked_total:  Arc::new(AtomicU64::new(0)),
            security_user_limit_rejections_total: Arc::new(AtomicU64::new(0)),
            rtp_timeouts_total:      Arc::new(AtomicU64::new(0)),
            sip_responses_by_code:   Arc::new(std::sync::Mutex::new(HashMap::new())),
            active_calls:            Arc::new(AtomicU64::new(0)),
            active_webrtc_calls:     Arc::new(AtomicU64::new(0)),
            allocated_ports:         Arc::new(AtomicU64::new(0)),
            active_registrations:    Arc::new(AtomicU64::new(0)),
            last_cdr_written_time:   Arc::new(AtomicU64::new(0)),
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
        if (400..500).contains(&code) { self.sip_4xx_total.fetch_add(1, Ordering::Relaxed); }
        if (500..600).contains(&code) { self.sip_5xx_total.fetch_add(1, Ordering::Relaxed); }
        if let Ok(mut map) = self.sip_responses_by_code.lock() {
            *map.entry(code).or_insert(0) += 1;
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
        self.security_ban_drops_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call blocked by destination rules (anti-IRSF).
    pub fn inc_security_destination_blocked(&self) {
        self.security_destination_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call rejected by per-user limits.
    pub fn inc_security_user_limit_rejection(&self) {
        self.security_user_limit_rejections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a call torn down by the RTP inactivity timeout.
    pub fn inc_rtp_timeout(&self) {
        self.rtp_timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Stamp the time a CDR was just written (Unix seconds, current time).
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

    pub fn set_active_registrations(&self, n: u64) {
        self.active_registrations.store(n, Ordering::Relaxed);
    }

    pub fn set_active_webrtc(&self, n: u64) {
        self.active_webrtc_calls.store(n, Ordering::Relaxed);
    }

    /// Uptime in seconds
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
        gauge!("sbc_uptime_seconds",
               "SBC uptime in seconds",
               self.uptime_secs());

        // ── Active gauges ─────────────────────────────────────────────────────
        gauge!("sbc_active_calls",
               "Number of currently active calls",
               self.active_calls.load(Ordering::Relaxed));

        gauge!("sbc_active_webrtc_calls",
               "Number of currently active WebRTC calls",
               self.active_webrtc_calls.load(Ordering::Relaxed));

        gauge!("sbc_allocated_rtp_ports",
               "Number of currently allocated RTP port pairs",
               self.allocated_ports.load(Ordering::Relaxed));

        gauge!("sbc_active_registrations",
               "Number of currently active SIP registrations",
               self.active_registrations.load(Ordering::Relaxed));

        gauge!("sbc_last_cdr_written_timestamp_seconds",
               "Unix time of the last CDR written (0 = none since start)",
               self.last_cdr_written_time.load(Ordering::Relaxed));

        // ── SIP counters ──────────────────────────────────────────────────────
        counter!("sbc_sip_requests",
                 "Total SIP requests received",
                 self.sip_requests_total.load(Ordering::Relaxed));

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

        counter!("sbc_sip_responses",
                 "Total SIP responses sent",
                 self.sip_responses_total.load(Ordering::Relaxed));

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

        counter!("sbc_sip_4xx",
                 "Total SIP 4xx responses",
                 self.sip_4xx_total.load(Ordering::Relaxed));

        counter!("sbc_sip_5xx",
                 "Total SIP 5xx responses",
                 self.sip_5xx_total.load(Ordering::Relaxed));

        // ── Call counters ─────────────────────────────────────────────────────
        counter!("sbc_calls",
                 "Total call attempts",
                 self.calls_total.load(Ordering::Relaxed));

        counter!("sbc_calls_connected",
                 "Total calls successfully connected",
                 self.calls_connected_total.load(Ordering::Relaxed));

        counter!("sbc_calls_failed",
                 "Total calls that failed",
                 self.calls_failed_total.load(Ordering::Relaxed));

        counter!("sbc_calls_terminated",
                 "Total calls terminated via BYE",
                 self.calls_terminated_total.load(Ordering::Relaxed));

        // ── Auth counters ─────────────────────────────────────────────────────
        counter!("sbc_auth_challenges",
                 "Total authentication challenges issued",
                 self.auth_challenges_total.load(Ordering::Relaxed));

        counter!("sbc_auth_failures",
                 "Total authentication failures",
                 self.auth_failures_total.load(Ordering::Relaxed));

        // ── Registration counters ───────────────────────────────────────────────
        counter!("sbc_registrations",
                 "Total successful REGISTER requests",
                 self.registrations_total.load(Ordering::Relaxed));

        // ── Security counters ──────────────────────────────────────────────────
        counter!("sbc_spam_blocked",
                 "Total INVITE rejected from unregistered sources",
                 self.spam_blocked_total.load(Ordering::Relaxed));

        counter!("sbc_sip_parse_errors",
                 "Total SIP messages with parse errors (scanners)",
                 self.sip_parse_errors_total.load(Ordering::Relaxed));

        counter!("sbc_dos_blocked",
                 "Total requests blocked by rate limiter (503)",
                 self.dos_blocked_total.load(Ordering::Relaxed));

        counter!("sbc_acl_denied",
                 "Total requests denied by ACL rules",
                 self.acl_denied_total.load(Ordering::Relaxed));

        // ── Anti-fraud counters (fail2ban / IRSF / per-user limits) ────────────
        counter!("sbc_security_bans",
                 "Total fail2ban bans issued (auth-failure threshold reached)",
                 self.security_bans_total.load(Ordering::Relaxed));

        counter!("sbc_security_ban_drops",
                 "Total requests dropped because their source IP was banned",
                 self.security_ban_drops_total.load(Ordering::Relaxed));

        counter!("sbc_security_destination_blocked",
                 "Total calls blocked by destination rules (anti-IRSF)",
                 self.security_destination_blocked_total.load(Ordering::Relaxed));

        counter!("sbc_security_user_limit_rejections",
                 "Total calls rejected by per-user limits (concurrent + rate)",
                 self.security_user_limit_rejections_total.load(Ordering::Relaxed));

        counter!("sbc_rtp_timeouts",
                 "Total calls torn down by the RTP inactivity timeout",
                 self.rtp_timeouts_total.load(Ordering::Relaxed));

        // ── Media counters ────────────────────────────────────────────────────
        counter!("sbc_rtp_packets",
                 "Total RTP packets forwarded",
                 self.rtp_packets_total.load(Ordering::Relaxed));

        counter!("sbc_srtp_encrypted",
                 "Total SRTP packets encrypted",
                 self.srtp_encrypted_total.load(Ordering::Relaxed));

        counter!("sbc_srtp_decrypted",
                 "Total SRTP packets decrypted",
                 self.srtp_decrypted_total.load(Ordering::Relaxed));

        counter!("sbc_transcoded_packets",
                 "Total RTP packets transcoded (Opus/G.711)",
                 self.transcoded_total.load(Ordering::Relaxed));

        out
    }
}

impl Default for SbcMetrics {
    fn default() -> Self { Self::new() }
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
            Self::Healthy       => "healthy",
            Self::Degraded(_)   => "degraded",
            Self::Unhealthy(_)  => "unhealthy",
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
            HealthStatus::Degraded(format!("High auth failure rate: {}/{}", auth_fail, auth_total))
        };
        checks.push(("auth_health".to_string(), auth_check));

        // Overall status: worst of all checks
        let status = checks.iter().fold(HealthStatus::Healthy, |worst, (_, s)| {
            match (&worst, s) {
                (_, HealthStatus::Unhealthy(m)) => HealthStatus::Unhealthy(m.clone()),
                (HealthStatus::Healthy, HealthStatus::Degraded(m)) => HealthStatus::Degraded(m.clone()),
                _ => worst,
            }
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
        let checks_json: String = self.checks.iter()
            .map(|(name, status)| {
                let detail = match status {
                    HealthStatus::Healthy => String::new(),
                    HealthStatus::Degraded(m) | HealthStatus::Unhealthy(m) => {
                        format!(", \"detail\": \"{}\"", m)
                    }
                };
                format!("{{\"name\": \"{}\", \"status\": \"{}\"{}}}", name, status.as_str(), detail)
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

        let output = m.render_prometheus();
        assert!(output.contains("sbc_rtp_timeouts_total 2"));
        assert!(output.contains("# TYPE sbc_last_cdr_written_timestamp_seconds gauge"));
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
        assert_eq!(HealthStatus::Unhealthy("y".to_string()).as_str(), "unhealthy");
    }
}
