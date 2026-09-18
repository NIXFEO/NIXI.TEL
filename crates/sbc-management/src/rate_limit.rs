//! Lightweight per-source-IP sliding-window rate limiter for the management
//! API, plus the source-IP derivation shared by the rate-limit and audit
//! middleware.
//!
//! Deliberately dependency-light: a `DashMap<IpAddr, VecDeque<Instant>>` keyed
//! by client IP, pruning timestamps older than the window on each hit. Memory
//! per active IP is bounded by the limit, and the number of tracked IPs by
//! [`MAX_TRACKED_CLIENTS`] (idle entries are swept, then the least recently
//! seen is evicted) — the same discipline as the SIP-side tables, so a spray
//! from many sources cannot grow the map without bound. This is enough to
//! blunt brute-force and scraping against the management surface without
//! pulling in a heavier governor stack.

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

/// Most client IPs tracked at once. Past it, idle entries are dropped and
/// then the least recently seen one is evicted: the operator keeps working
/// during a spray from many addresses.
pub const MAX_TRACKED_CLIENTS: usize = 4096;

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
        if !self.inner.contains_key(&ip) && self.inner.len() >= MAX_TRACKED_CLIENTS {
            self.make_room(now);
        }
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

    /// Drop the entries whose window has fully elapsed; if that frees
    /// nothing, evict the least recently seen client.
    fn make_room(&self, now: Instant) {
        let window = self.window;
        self.inner.retain(|_, hits| {
            hits.back()
                .is_some_and(|last| now.duration_since(*last) < window)
        });
        if self.inner.len() < MAX_TRACKED_CLIENTS {
            return;
        }
        let oldest = self
            .inner
            .iter()
            .min_by_key(|e| e.value().back().copied().unwrap_or(now))
            .map(|e| *e.key());
        if let Some(ip) = oldest {
            self.inner.remove(&ip);
        }
    }

    /// Tracked client IPs (tests and diagnostics).
    pub fn tracked(&self) -> usize {
        self.inner.len()
    }
}

/// Proxies believed by `client_ip` (the nginx of INSTALL.md on loopback).
pub fn default_trusted_proxies() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    ]
}

/// Derive the client IP for rate limiting, audit and bans.
///
/// The TCP peer (`ConnectInfo`) is the client — unless it is one of
/// `trusted` (a reverse proxy), in which case `X-Real-IP`, else the
/// rightmost `X-Forwarded-For` hop that is not itself a trusted proxy, is
/// the client. Headers from an untrusted peer are ignored: anyone can send
/// them. Without a peer (unit tests driving the router with `oneshot`)
/// nothing is believed and the unspecified address is returned.
pub fn client_ip_with<B>(req: &Request<B>, trusted: &[IpAddr]) -> IpAddr {
    let Some(peer) = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
    else {
        return UNKNOWN_IP;
    };
    if !trusted.contains(&peer) {
        return peer;
    }
    if let Some(ip) = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_hop)
    {
        return ip;
    }
    if let Some(list) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let hops: Vec<IpAddr> = list.split(',').filter_map(parse_hop).collect();
        if let Some(ip) = hops.iter().rev().find(|h| !trusted.contains(h)) {
            return *ip;
        }
    }
    peer
}

/// `client_ip_with` trusting loopback only.
pub fn client_ip<B>(req: &Request<B>) -> IpAddr {
    client_ip_with(req, &default_trusted_proxies())
}

/// One hop of X-Forwarded-For / X-Real-IP: an IP, possibly with a port.
fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
        .or_else(|| {
            s.strip_prefix('[')
                .and_then(|r| r.split(']').next())
                .and_then(|h| h.parse().ok())
        })
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
    fn the_tracked_table_is_capped() {
        let rl = RateLimiter::new(5, Duration::from_secs(60));
        for n in 0..(MAX_TRACKED_CLIENTS as u32 + 200) {
            let ip = IpAddr::V4(Ipv4Addr::from(n.to_be_bytes()));
            assert!(rl.check(ip), "a fresh client must be allowed: {}", ip);
        }
        assert!(
            rl.tracked() <= MAX_TRACKED_CLIENTS,
            "tracked {} clients",
            rl.tracked()
        );
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

    fn with_peer(mut req: Request<()>, peer: &str) -> Request<()> {
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    #[test]
    fn headers_are_believed_only_from_a_trusted_proxy() {
        let req = Request::builder()
            .header("x-real-ip", "198.51.100.10")
            .header("x-forwarded-for", "198.51.100.20, 10.0.0.1")
            .body(())
            .unwrap();
        let via_nginx = with_peer(req, "127.0.0.1:40000");
        assert_eq!(
            client_ip(&via_nginx),
            "198.51.100.10".parse::<IpAddr>().unwrap(),
            "X-Real-IP from loopback nginx"
        );

        let req = Request::builder()
            .header("x-real-ip", "198.51.100.10")
            .header("x-forwarded-for", "198.51.100.20")
            .body(())
            .unwrap();
        let direct = with_peer(req, "203.0.113.5:40000");
        assert_eq!(
            client_ip(&direct),
            "203.0.113.5".parse::<IpAddr>().unwrap(),
            "an untrusted peer's headers are ignored"
        );
    }

    #[test]
    fn forwarded_for_takes_the_rightmost_untrusted_hop() {
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        // client → 203.0.113.9 (spoofable) → 10.0.0.1 (our proxy) → nginx (peer)
        let req = Request::builder()
            .header("x-forwarded-for", "1.2.3.4, 203.0.113.9, 10.0.0.1")
            .body(())
            .unwrap();
        let req = with_peer(req, "127.0.0.1:1");
        assert_eq!(
            client_ip_with(&req, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Every hop trusted: the peer itself
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.1")
            .body(())
            .unwrap();
        let req = with_peer(req, "127.0.0.1:1");
        assert_eq!(
            client_ip_with(&req, &trusted),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        // Hops with ports (some proxies) and garbage
        let req = Request::builder()
            .header("x-forwarded-for", "garbage, 203.0.113.5:1234")
            .body(())
            .unwrap();
        let req = with_peer(req, "127.0.0.1:1");
        assert_eq!(
            client_ip_with(&req, &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_falls_back_to_unspecified_without_a_peer() {
        let req = Request::builder()
            .header("x-real-ip", "198.51.100.10")
            .body(())
            .unwrap();
        assert_eq!(client_ip(&req), UNKNOWN_IP, "no peer: nothing is believed");
    }
}
