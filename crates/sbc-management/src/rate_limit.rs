//! Lightweight per-source-IP sliding-window rate limiter for the management
//! API, plus the source-IP derivation shared by the rate-limit and audit
//! middleware.
//!
//! Deliberately dependency-light: a `DashMap<IpAddr, VecDeque<Instant>>` keyed
//! by client IP, pruning timestamps older than the window on each hit. Memory
//! per active IP is bounded by the limit. This is enough to blunt brute-force
//! and scraping against the management surface without pulling in a heavier
//! governor stack.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::Request;
use dashmap::DashMap;

/// Fallback key used when no source IP can be derived (e.g. unit tests driving
/// the router via `oneshot`, which sets no `ConnectInfo`).
const UNKNOWN_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Sliding-window request limiter, cheaply cloneable (shares one map).
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<DashMap<IpAddr, VecDeque<Instant>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    /// `limit` requests allowed per `window` per source IP. A `limit` of 0
    /// disables limiting entirely.
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            limit,
            window,
        }
    }

    /// Per-minute convenience constructor.
    pub fn per_minute(limit: u32) -> Self {
        Self::new(limit as usize, Duration::from_secs(60))
    }

    /// Record a hit for `ip`. Returns `true` if the request is within budget,
    /// `false` if it should be rejected.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = Instant::now();
        let mut entry = self.inner.entry(ip).or_default();
        while let Some(&front) = entry.front() {
            if now.duration_since(front) >= self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= self.limit {
            false
        } else {
            entry.push_back(now);
            true
        }
    }
}

/// Derive the client IP for rate-limiting / audit.
///
/// Prefers `X-Real-IP`, then the first hop of `X-Forwarded-For` (set by a
/// trusted reverse proxy), then the TCP peer address from `ConnectInfo`.
/// Falls back to an unspecified address when nothing is available.
pub fn client_ip<B>(req: &Request<B>) -> IpAddr {
    if let Some(ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
    {
        return ip;
    }

    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|first| first.trim().parse().ok())
    {
        return ip;
    }

    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(UNKNOWN_IP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip), "4th request over a limit of 3 is rejected");
    }

    #[test]
    fn limits_are_per_ip() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        assert!(rl.check(a));
        assert!(!rl.check(a));
        assert!(rl.check(b), "a separate IP has its own budget");
    }

    #[test]
    fn zero_limit_disables() {
        let rl = RateLimiter::new(0, Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..1000 {
            assert!(rl.check(ip));
        }
    }

    #[test]
    fn window_expiry_frees_budget() {
        let rl = RateLimiter::new(1, Duration::from_millis(20));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.check(ip), "budget replenishes after the window elapses");
    }

    #[test]
    fn client_ip_prefers_x_real_ip() {
        let req = Request::builder()
            .header("x-real-ip", "198.51.100.10")
            .header("x-forwarded-for", "198.51.100.20, 10.0.0.1")
            .body(())
            .unwrap();
        assert_eq!(client_ip(&req), "198.51.100.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_uses_first_forwarded_hop() {
        let req = Request::builder()
            .header("x-forwarded-for", "198.51.100.20, 10.0.0.1")
            .body(())
            .unwrap();
        assert_eq!(client_ip(&req), "198.51.100.20".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_falls_back_to_unspecified() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(client_ip(&req), UNKNOWN_IP);
    }
}
