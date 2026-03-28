//! DoS Protection — Rate Limiting par IP
//!
//! Implémente un système de protection contre les attaques par déni de service :
//! - Rate limiting par IP (token bucket algorithm)
//! - Blacklist temporaire (IP bloquées automatiquement)
//! - Whitelist statique (IP toujours autorisées)
//! - Compteurs de violations
//! - Cleanup automatique des entrées expirées

use crate::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Configuration du rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requêtes par seconde autorisées par IP
    pub requests_per_second: u32,
    /// Rafale maximale autorisée (token bucket capacity)
    pub burst_size: u32,
    /// Durée de blacklist après trop de violations (secondes)
    pub blacklist_duration_secs: u64,
    /// Nombre de violations avant blacklist
    pub violations_before_blacklist: u32,
    /// Nettoyer les entrées inactives après N secondes
    pub cleanup_after_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 50,
            burst_size: 100,
            blacklist_duration_secs: 300, // 5 minutes
            violations_before_blacklist: 10,
            cleanup_after_secs: 600, // 10 minutes
        }
    }
}

impl RateLimitConfig {
    pub fn strict() -> Self {
        Self {
            requests_per_second: 10,
            burst_size: 20,
            blacklist_duration_secs: 600,
            violations_before_blacklist: 5,
            cleanup_after_secs: 300,
        }
    }

    pub fn permissive() -> Self {
        Self {
            requests_per_second: 200,
            burst_size: 500,
            blacklist_duration_secs: 60,
            violations_before_blacklist: 50,
            cleanup_after_secs: 1800,
        }
    }
}

/// État d'une IP dans le token bucket
#[derive(Debug)]
struct IpState {
    /// Tokens disponibles (max = burst_size)
    tokens: f64,
    /// Dernière fois qu'on a vérifié/rechargé les tokens
    last_refill: Instant,
    /// Nombre de violations (dépassements de rate)
    violations: u32,
    /// Blacklisté jusqu'à cet instant (None = pas blacklisté)
    blacklisted_until: Option<Instant>,
    /// Dernière activité (pour cleanup)
    last_seen: Instant,
}

impl IpState {
    fn new(burst_size: u32) -> Self {
        Self {
            tokens: burst_size as f64,
            last_refill: Instant::now(),
            violations: 0,
            blacklisted_until: None,
            last_seen: Instant::now(),
        }
    }

    /// Recharger les tokens selon le temps écoulé
    fn refill(&mut self, rate: f64, burst: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last_refill = now;
        self.last_seen = now;
    }

    /// Vérifier si l'IP est blacklistée
    fn is_blacklisted(&mut self) -> bool {
        if let Some(until) = self.blacklisted_until {
            if Instant::now() < until {
                return true;
            }
            // Blacklist expirée : reset
            self.blacklisted_until = None;
            self.violations = 0;
        }
        false
    }

    /// Consommer un token (retourne true si autorisé)
    fn consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Résultat d'une vérification de rate limit
#[derive(Debug, PartialEq)]
pub enum RateLimitResult {
    /// Requête autorisée
    Allowed,
    /// Requête bloquée (rate exceeded)
    RateLimited { violations: u32 },
    /// IP blacklistée
    Blacklisted { remaining_secs: u64 },
    /// IP en whitelist (toujours autorisée)
    Whitelisted,
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed | RateLimitResult::Whitelisted)
    }
}

/// Statistiques DoS globales
#[derive(Debug, Clone, Default)]
pub struct DosStats {
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub total_blacklisted: u64,
    pub active_tracked_ips: usize,
    pub blacklisted_ips: usize,
}

/// Gestionnaire de protection DoS
pub struct DosProtector {
    config: RateLimitConfig,
    /// État par IP
    ip_states: Arc<Mutex<HashMap<IpAddr, IpState>>>,
    /// Whitelist statique (jamais bloquées)
    whitelist: Arc<Vec<IpAddr>>,
    /// Compteurs globaux
    allowed_count: Arc<std::sync::atomic::AtomicU64>,
    blocked_count: Arc<std::sync::atomic::AtomicU64>,
    blacklisted_count: Arc<std::sync::atomic::AtomicU64>,
}

impl DosProtector {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_states: Arc::new(Mutex::new(HashMap::new())),
            whitelist: Arc::new(Vec::new()),
            allowed_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocked_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blacklisted_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn new_with_whitelist(config: RateLimitConfig, whitelist: Vec<IpAddr>) -> Self {
        Self {
            config,
            ip_states: Arc::new(Mutex::new(HashMap::new())),
            whitelist: Arc::new(whitelist),
            allowed_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blocked_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            blacklisted_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Vérifier si une adresse IP est autorisée à envoyer une requête
    pub async fn check(&self, addr: IpAddr) -> RateLimitResult {
        // Whitelist check
        if self.whitelist.contains(&addr) {
            self.allowed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RateLimitResult::Whitelisted;
        }

        let rate = self.config.requests_per_second as f64;
        let burst = self.config.burst_size as f64;
        let blacklist_dur = self.config.blacklist_duration_secs;
        let max_violations = self.config.violations_before_blacklist;

        let mut states = self.ip_states.lock().await;
        let state = states
            .entry(addr)
            .or_insert_with(|| IpState::new(self.config.burst_size));

        // Recharger les tokens
        state.refill(rate, burst);

        // Vérifier si blacklisté
        if state.is_blacklisted() {
            let remaining = state
                .blacklisted_until
                .map(|t| {
                    t.duration_since(Instant::now()).as_secs()
                })
                .unwrap_or(0);
            self.blacklisted_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RateLimitResult::Blacklisted { remaining_secs: remaining };
        }

        // Consommer un token
        if state.consume() {
            self.allowed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            RateLimitResult::Allowed
        } else {
            // Rate exceeded
            state.violations += 1;
            let violations = state.violations;

            // Blacklister si trop de violations
            if violations >= max_violations {
                let until = Instant::now() + Duration::from_secs(blacklist_dur);
                state.blacklisted_until = Some(until);
                warn!(
                    "IP {} blacklisted for {} seconds after {} violations",
                    addr, blacklist_dur, violations
                );
            } else {
                debug!("IP {} rate limited (violation {}/{})", addr, violations, max_violations);
            }

            self.blocked_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            RateLimitResult::RateLimited { violations }
        }
    }

    /// Vérifier depuis une SocketAddr
    pub async fn check_addr(&self, addr: SocketAddr) -> RateLimitResult {
        self.check(addr.ip()).await
    }

    /// Blacklister manuellement une IP
    pub async fn blacklist_ip(&self, addr: IpAddr, duration_secs: u64) {
        let mut states = self.ip_states.lock().await;
        let state = states
            .entry(addr)
            .or_insert_with(|| IpState::new(self.config.burst_size));
        state.blacklisted_until = Some(Instant::now() + Duration::from_secs(duration_secs));
        warn!("IP {} manually blacklisted for {} seconds", addr, duration_secs);
    }

    /// Débloquer une IP manuellement
    pub async fn unblacklist_ip(&self, addr: IpAddr) {
        let mut states = self.ip_states.lock().await;
        if let Some(state) = states.get_mut(&addr) {
            state.blacklisted_until = None;
            state.violations = 0;
            info!("IP {} unblacklisted", addr);
        }
    }

    /// Nettoyer les entrées inactives
    pub async fn cleanup_expired(&self) {
        let max_age = Duration::from_secs(self.config.cleanup_after_secs);
        let mut states = self.ip_states.lock().await;
        let before = states.len();
        states.retain(|_, state| {
            // Garder si blacklisté (même si inactif)
            if state.blacklisted_until.is_some() {
                return true;
            }
            // Supprimer si inactif depuis trop longtemps
            Instant::now().duration_since(state.last_seen) < max_age
        });
        let removed = before - states.len();
        if removed > 0 {
            debug!("DoS cleanup: removed {} stale IP entries", removed);
        }
    }

    /// Statistiques globales
    pub async fn stats(&self) -> DosStats {
        let states = self.ip_states.lock().await;
        let blacklisted = states
            .values()
            .filter(|s| s.blacklisted_until.map(|t| Instant::now() < t).unwrap_or(false))
            .count();

        DosStats {
            total_allowed: self.allowed_count.load(std::sync::atomic::Ordering::Relaxed),
            total_blocked: self.blocked_count.load(std::sync::atomic::Ordering::Relaxed),
            total_blacklisted: self.blacklisted_count.load(std::sync::atomic::Ordering::Relaxed),
            active_tracked_ips: states.len(),
            blacklisted_ips: blacklisted,
        }
    }

    /// Liste des IPs blacklistées
    pub async fn blacklisted_ips(&self) -> Vec<(IpAddr, u64)> {
        let states = self.ip_states.lock().await;
        let now = Instant::now();
        states
            .iter()
            .filter_map(|(ip, s)| {
                s.blacklisted_until.and_then(|t| {
                    if now < t {
                        Some((*ip, t.duration_since(now).as_secs()))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_ip(n: u8) -> IpAddr {
        format!("192.168.1.{}", n).parse().unwrap()
    }

    #[tokio::test]
    async fn test_dos_allows_normal_traffic() {
        let config = RateLimitConfig {
            requests_per_second: 100,
            burst_size: 10,
            ..Default::default()
        };
        let protector = DosProtector::new(config);

        // First 10 requests should be allowed (burst)
        let ip = test_ip(1);
        for _ in 0..10 {
            let result = protector.check(ip).await;
            assert!(result.is_allowed(), "Should be allowed within burst");
        }
    }

    #[tokio::test]
    async fn test_dos_blocks_excessive_traffic() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 3,
            violations_before_blacklist: 100, // High threshold to avoid blacklisting
            ..Default::default()
        };
        let protector = DosProtector::new(config);
        let ip = test_ip(2);

        // Exhaust the burst
        for _ in 0..3 {
            protector.check(ip).await;
        }

        // Next should be rate limited
        let result = protector.check(ip).await;
        assert_eq!(result, RateLimitResult::RateLimited { violations: 1 });
    }

    #[tokio::test]
    async fn test_dos_blacklists_after_violations() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            violations_before_blacklist: 3,
            blacklist_duration_secs: 60,
            ..Default::default()
        };
        let protector = DosProtector::new(config);
        let ip = test_ip(3);

        // Exhaust burst
        protector.check(ip).await;

        // Trigger violations
        for _ in 0..3 {
            protector.check(ip).await;
        }

        // Should be blacklisted now
        let result = protector.check(ip).await;
        assert!(matches!(result, RateLimitResult::Blacklisted { .. }));
    }

    #[tokio::test]
    async fn test_whitelist_always_allowed() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            ..Default::default()
        };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let protector = DosProtector::new_with_whitelist(config, vec![ip]);

        // Exhaust bucket
        protector.check(ip).await;
        protector.check(ip).await;

        // Whitelist should always pass
        for _ in 0..10 {
            let result = protector.check(ip).await;
            assert_eq!(result, RateLimitResult::Whitelisted);
        }
    }

    #[tokio::test]
    async fn test_manual_blacklist() {
        let protector = DosProtector::new(RateLimitConfig::default());
        let ip = test_ip(5);

        protector.blacklist_ip(ip, 300).await;

        let result = protector.check(ip).await;
        assert!(matches!(result, RateLimitResult::Blacklisted { .. }));
    }

    #[tokio::test]
    async fn test_manual_unblacklist() {
        let protector = DosProtector::new(RateLimitConfig::default());
        let ip = test_ip(6);

        protector.blacklist_ip(ip, 300).await;
        protector.unblacklist_ip(ip).await;

        let result = protector.check(ip).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 2,
            violations_before_blacklist: 100,
            ..Default::default()
        };
        let protector = DosProtector::new(config);
        let ip1 = test_ip(10);
        let ip2 = test_ip(11);

        // Exhaust ip1
        protector.check(ip1).await;
        protector.check(ip1).await;
        let blocked = protector.check(ip1).await;
        assert!(matches!(blocked, RateLimitResult::RateLimited { .. }));

        // ip2 should still be allowed
        let allowed = protector.check(ip2).await;
        assert!(allowed.is_allowed());
    }

    #[tokio::test]
    async fn test_dos_stats() {
        let protector = DosProtector::new(RateLimitConfig {
            burst_size: 2,
            requests_per_second: 1,
            violations_before_blacklist: 100,
            ..Default::default()
        });

        let ip = test_ip(20);
        protector.check(ip).await; // allowed
        protector.check(ip).await; // allowed (burst=2)
        protector.check(ip).await; // blocked

        let stats = protector.stats().await;
        assert_eq!(stats.total_allowed, 2);
        assert_eq!(stats.total_blocked, 1);
    }

    #[tokio::test]
    async fn test_blacklisted_ips_list() {
        let protector = DosProtector::new(RateLimitConfig::default());
        let ip1 = test_ip(30);
        let ip2 = test_ip(31);

        protector.blacklist_ip(ip1, 300).await;
        protector.blacklist_ip(ip2, 600).await;

        let list = protector.blacklisted_ips().await;
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|(ip, _)| ip == &ip1));
        assert!(list.iter().any(|(ip, _)| ip == &ip2));
    }

    #[tokio::test]
    async fn test_check_addr_with_socket_addr() {
        let protector = DosProtector::new(RateLimitConfig::default());
        let addr: SocketAddr = "192.168.1.100:5060".parse().unwrap();

        let result = protector.check_addr(addr).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limit_config_strict() {
        let config = RateLimitConfig::strict();
        assert!(config.requests_per_second < 50);
        assert!(config.violations_before_blacklist <= 10);
    }

    #[tokio::test]
    async fn test_rate_limit_config_permissive() {
        let config = RateLimitConfig::permissive();
        assert!(config.requests_per_second > 50);
        assert!(config.burst_size > 100);
    }
}
