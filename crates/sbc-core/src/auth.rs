//! SIP Digest Authentication - RFC 3261 Section 22 / RFC 7616
//!
//! Implements:
//!   - Challenge generation (401 Unauthorized / 407 Proxy Auth Required)
//!   - Credential verification (HA1 = MD5(user:realm:password))
//!   - Nonce management with replay protection
//!   - WWW-Authenticate / Authorization header parsing

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

/// MD5 digest (hex string, 32 chars)
fn md5_hex(input: &str) -> String {
    // Use a simple MD5 implementation via the md5 re-export in sha1/hmac dependencies
    // We compute MD5 manually using the well-known algorithm constants
    md5_compute(input.as_bytes())
}

/// Pure-Rust MD5 implementation (RFC 1321)
fn md5_compute(data: &[u8]) -> String {
    // Initial hash values
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Per-round shift amounts
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    // Precomputed table K[i] = floor(abs(sin(i+1)) * 2^32)
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Pre-processing: add bit '1', then zeros, then original length in bits
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 512-bit (64-byte) chunk
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let j = i * 4;
            *word = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64usize {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        a0.swap_bytes(),
        b0.swap_bytes(),
        c0.swap_bytes(),
        d0.swap_bytes()
    )
}

/// Compute HA1 = MD5(username:realm:password)
pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    md5_hex(&format!("{}:{}:{}", username, realm, password))
}

/// Compute HA2 = MD5(method:uri)
pub fn compute_ha2(method: &str, uri: &str) -> String {
    md5_hex(&format!("{}:{}", method, uri))
}

/// Compute response = MD5(HA1:nonce:HA2)   (RFC 2069 / no qop)
pub fn compute_response(ha1: &str, nonce: &str, ha2: &str) -> String {
    md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
}

/// Compute response with qop=auth: MD5(HA1:nonce:nc:cnonce:qop:HA2)
pub fn compute_response_auth(ha1: &str, nonce: &str, nc: &str, cnonce: &str, ha2: &str) -> String {
    md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2))
}

// =========================================================================
// Outbound Digest Auth — for authenticating TO trunks (407 challenge-response)
// =========================================================================

/// Parsed Proxy-Authenticate / WWW-Authenticate challenge from a trunk
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
}

impl DigestChallenge {
    /// Parse from a Proxy-Authenticate or WWW-Authenticate header value.
    /// e.g. `Digest realm="trunk.example.com", nonce="abc123", algorithm=MD5, qop="auth"`
    pub fn from_header(value: &str) -> Result<Self> {
        let value = value.trim();
        let value = value
            .strip_prefix("Digest ")
            .ok_or_else(|| Error::Parse("Challenge must start with 'Digest '".into()))?;

        let mut challenge = DigestChallenge {
            realm: String::new(),
            nonce: String::new(),
            algorithm: "MD5".to_string(),
            qop: None,
            opaque: None,
        };

        for part in value.split(',') {
            let part = part.trim();
            if let Some((key, val)) = part.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"');
                match key {
                    "realm" => challenge.realm = val.to_string(),
                    "nonce" => challenge.nonce = val.to_string(),
                    "algorithm" => challenge.algorithm = val.to_string(),
                    "qop" => challenge.qop = Some(val.to_string()),
                    "opaque" => challenge.opaque = Some(val.to_string()),
                    _ => {}
                }
            }
        }

        if challenge.realm.is_empty() || challenge.nonce.is_empty() {
            return Err(Error::Parse(
                "Incomplete Digest challenge (missing realm or nonce)".into(),
            ));
        }

        Ok(challenge)
    }
}

/// Generate a Proxy-Authorization (or Authorization) header value for outbound requests.
///
/// This is the client-side counterpart of DigestAuthenticator::verify().
/// Returns a complete header value like:
/// `Digest username="8933100005601", realm="trunk.example.com", nonce="abc",
///  uri="sip:0612345678@trunk.example.com", response="deadbeef...", algorithm=MD5`
pub fn generate_digest_response(
    username: &str,
    password: &str,
    challenge: &DigestChallenge,
    method: &str,     // "INVITE", "REGISTER"
    digest_uri: &str, // "sip:0612345678@trunk.example.com"
) -> String {
    let ha1 = compute_ha1(username, &challenge.realm, password);
    let ha2 = compute_ha2(method, digest_uri);

    let (response, nc_cnonce_qop) = if let Some(ref qop) = challenge.qop {
        if qop.contains("auth") {
            let cnonce = format!("{:08x}", rand::random::<u32>());
            let nc = "00000001";
            let resp = compute_response_auth(&ha1, &challenge.nonce, nc, &cnonce, &ha2);
            (resp, Some((nc.to_string(), cnonce, "auth".to_string())))
        } else {
            (compute_response(&ha1, &challenge.nonce, &ha2), None)
        }
    } else {
        (compute_response(&ha1, &challenge.nonce, &ha2), None)
    };

    let mut header = format!(
        r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", algorithm={}"#,
        username, challenge.realm, challenge.nonce, digest_uri, response, challenge.algorithm
    );

    if let Some((nc, cnonce, qop)) = nc_cnonce_qop {
        header.push_str(&format!(r#", qop={}, nc={}, cnonce="{}""#, qop, nc, cnonce));
    }

    if let Some(ref opaque) = challenge.opaque {
        header.push_str(&format!(r#", opaque="{}""#, opaque));
    }

    header
}

// =========================================================================
// Inbound Digest Auth — for verifying user REGISTER/INVITE credentials
// =========================================================================

/// Parsed Authorization / Proxy-Authorization header fields
#[derive(Debug, Clone, Default)]
pub struct DigestCredentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

impl DigestCredentials {
    /// Parse from Authorization header value
    /// e.g. `Digest username="alice", realm="example.com", nonce="abc", uri="sip:bob@example.com", response="xyz"`
    pub fn from_header(value: &str) -> Result<Self> {
        let value = value.trim();
        let value = value.strip_prefix("Digest ").ok_or_else(|| {
            Error::Parse("Authorization header must start with 'Digest '".to_string())
        })?;

        let mut creds = DigestCredentials {
            algorithm: "MD5".to_string(),
            ..Default::default()
        };

        for part in value.split(',') {
            let part = part.trim();
            if let Some((key, val)) = part.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"');
                match key {
                    "username" => creds.username = val.to_string(),
                    "realm" => creds.realm = val.to_string(),
                    "nonce" => creds.nonce = val.to_string(),
                    "uri" => creds.uri = val.to_string(),
                    "response" => creds.response = val.to_string(),
                    "algorithm" => creds.algorithm = val.to_string(),
                    "qop" => creds.qop = Some(val.to_string()),
                    "nc" => creds.nc = Some(val.to_string()),
                    "cnonce" => creds.cnonce = Some(val.to_string()),
                    _ => {}
                }
            }
        }

        if creds.username.is_empty()
            || creds.realm.is_empty()
            || creds.nonce.is_empty()
            || creds.response.is_empty()
        {
            return Err(Error::Parse("Incomplete Digest credentials".to_string()));
        }

        Ok(creds)
    }
}

/// Active nonce record
#[derive(Debug, Clone)]
struct NonceRecord {
    created_at: u64, // Unix timestamp (secs)
    use_count: u32,
    /// Highest nonce-count accepted with this nonce (qop=auth).
    last_nc: u32,
    /// Fingerprint of the request that used `last_nc`: a byte-identical
    /// retransmission (same fingerprint, same nc) is accepted again; a
    /// different request with the same nc is a replay.
    last_fingerprint: Option<u64>,
}

/// Why a Digest verification failed (RFC 3261 §22, RFC 7616 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    /// The nonce is unknown, expired or already consumed. The client's
    /// credentials may well be right (it cached an old challenge): answer
    /// a fresh challenge with `stale=true`. Never a fail2ban strike, never
    /// an oracle (an unknown nonce yields this whatever the digest).
    StaleNonce {
        user: String,
    },
    /// A known nonce presented again with a nonce-count that does not
    /// advance, by a different request: a captured Authorization replayed.
    Replay {
        user: String,
    },
    /// Known nonce, known user, wrong digest: wrong password.
    BadCredentials {
        user: String,
    },
    UnknownUser {
        user: String,
    },
    /// Not a parsable Digest header.
    Malformed,
}

impl AuthFailure {
    pub fn user(&self) -> Option<&str> {
        match self {
            Self::StaleNonce { user }
            | Self::Replay { user }
            | Self::BadCredentials { user }
            | Self::UnknownUser { user } => Some(user),
            Self::Malformed => None,
        }
    }

    /// Re-challenge with `stale=true` instead of rejecting. A replay is
    /// re-challenged too: only someone who knows the password can produce
    /// it, so it is never a brute force — and a legitimate client that
    /// resends an accepted Authorization from a new port (TCP reconnect,
    /// NAT rebinding) or keeps nc=00000001 must not be banned.
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::StaleNonce { .. } | Self::Replay { .. })
    }

    /// Counts toward the fail2ban window: a wrong password or an unknown
    /// user on a nonce we issued (never on a forged one).
    pub fn is_attack(&self) -> bool {
        matches!(self, Self::BadCredentials { .. } | Self::UnknownUser { .. })
    }
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleNonce { user } => write!(f, "stale or unknown nonce (user {})", user),
            Self::Replay { user } => write!(f, "replayed authorization (user {})", user),
            Self::BadCredentials { user } => write!(f, "wrong password (user {})", user),
            Self::UnknownUser { user } => write!(f, "unknown user {}", user),
            Self::Malformed => write!(f, "malformed Digest header"),
        }
    }
}

/// Digest Authenticator — generates challenges and verifies responses
pub struct DigestAuthenticator {
    /// Realm for this SBC
    pub realm: String,

    /// Active nonces (nonce → record)
    nonces: Arc<Mutex<HashMap<String, NonceRecord>>>,

    /// Nonce lifetime in seconds
    nonce_ttl: u64,

    /// User database: username → HA1 (pre-hashed)
    /// HA1 = MD5(username:realm:password)
    /// Protected by RwLock to allow hot-reload via SIGHUP.
    users: Arc<RwLock<HashMap<String, String>>>,
}

/// Upper bound on outstanding nonces (see `generate_challenge`).
pub const MAX_NONCES: usize = 100_000;

/// HA1 used to verify a digest for a user that does not exist, so the
/// computation (and the outcome on a foreign nonce) never reveals whether
/// the user exists.
const DUMMY_HA1: &str = "00000000000000000000000000000000";

impl DigestAuthenticator {
    /// Create with realm and a map of username → plain password
    pub fn new(realm: impl Into<String>, users: HashMap<String, String>) -> Self {
        let realm = realm.into();
        let ha1_map = Self::build_ha1_map(&realm, &users);

        Self {
            realm,
            nonces: Arc::new(Mutex::new(HashMap::new())),
            nonce_ttl: 300, // 5 minutes
            users: Arc::new(RwLock::new(ha1_map)),
        }
    }

    /// Pre-compute HA1 = MD5(username:realm:password) for each user
    fn build_ha1_map(realm: &str, users: &HashMap<String, String>) -> HashMap<String, String> {
        users
            .iter()
            .map(|(u, p)| (u.clone(), compute_ha1(u, realm, p)))
            .collect()
    }

    /// Hot-reload users from a new username → password map.
    /// Existing nonces remain valid so in-flight auth challenges still work.
    /// Returns (added, removed, total) counts.
    pub async fn reload_users(&self, users: &HashMap<String, String>) -> (usize, usize, usize) {
        let new_ha1 = Self::build_ha1_map(&self.realm, users);
        self.set_users_ha1(new_ha1).await
    }

    /// Hot-reload users from a pre-hashed username → HA1 map (SQLite path —
    /// the store never holds plaintext passwords).
    /// Returns (added, removed, total) counts.
    pub async fn set_users_ha1(&self, new_ha1: HashMap<String, String>) -> (usize, usize, usize) {
        let total = new_ha1.len();

        let mut current = self.users.write().await;
        let old_keys: std::collections::HashSet<_> = current.keys().cloned().collect();
        let new_keys: std::collections::HashSet<_> = new_ha1.keys().cloned().collect();

        let added = new_keys.difference(&old_keys).count();
        let removed = old_keys.difference(&new_keys).count();

        *current = new_ha1;
        (added, removed, total)
    }

    /// Generate a new nonce (cryptographically random)
    fn generate_nonce() -> String {
        use rand::Rng;
        let bytes: [u8; 16] = rand::thread_rng().gen();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    /// Generate a 401 WWW-Authenticate challenge header value
    pub async fn generate_challenge(&self) -> String {
        self.generate_challenge_with(false).await
    }

    /// Challenge with `stale=true` when the client's nonce was merely old
    /// (RFC 7616 §3.3): it retries with the same credentials at once.
    pub async fn generate_challenge_with(&self, stale: bool) -> String {
        let nonce = Self::generate_nonce();
        let record = NonceRecord {
            created_at: Self::now_secs(),
            use_count: 0,
            last_nc: 0,
            last_fingerprint: None,
        };
        let mut nonces = self.nonces.lock().await;
        if nonces.len() >= MAX_NONCES {
            // A challenge is minted per unauthenticated request: a scanner
            // can create them faster than the sweeper prunes. Evict the
            // expired, then the older half, before accepting a new one.
            let now = Self::now_secs();
            nonces.retain(|_, r| now.saturating_sub(r.created_at) <= self.nonce_ttl);
            if nonces.len() >= MAX_NONCES {
                nonces.retain(|_, r| now.saturating_sub(r.created_at) <= self.nonce_ttl / 2);
            }
            if nonces.len() >= MAX_NONCES {
                nonces.clear();
            }
            tracing::warn!(
                "Digest: nonce cap {} reached — evicted old challenges",
                MAX_NONCES
            );
        }
        nonces.insert(nonce.clone(), record);
        drop(nonces);

        format!(
            r#"Digest realm="{}", nonce="{}", algorithm=MD5, qop="auth"{}"#,
            self.realm,
            nonce,
            if stale { ", stale=true" } else { "" }
        )
    }

    /// Verify an Authorization header value against our user database.
    /// Returns the authenticated username, or why it failed.
    pub async fn verify(
        &self,
        auth_header: &str,
        method: &str,
    ) -> std::result::Result<String, AuthFailure> {
        self.verify_with(auth_header, method, None).await
    }

    /// `verify` with a fingerprint of the request carrying the header
    /// (Authorization value + source + Contact): a byte-identical UDP
    /// retransmission of an already-accepted request is accepted again
    /// instead of being called a replay.
    pub async fn verify_with(
        &self,
        auth_header: &str,
        method: &str,
        fingerprint: Option<u64>,
    ) -> std::result::Result<String, AuthFailure> {
        let creds =
            DigestCredentials::from_header(auth_header).map_err(|_| AuthFailure::Malformed)?;
        let user = creds.username.clone();

        // Digest first: the nonce state decides between "stale" and "wrong
        // password" only once we know whether the credentials were right.
        // An unknown user is computed against a dummy HA1 so the work (and
        // the answer on a nonce that is not ours) is the same as for a
        // known one: no username oracle.
        let ha1: Option<String> = self.users.read().await.get(&user).cloned();
        let ha2 = compute_ha2(method, &creds.uri);
        let qop_auth = creds.qop.as_deref() == Some("auth");
        let ha1_for_digest = ha1.as_deref().unwrap_or(DUMMY_HA1);
        let expected = if qop_auth {
            let nc = creds.nc.as_deref().unwrap_or("00000001");
            let cnonce = creds.cnonce.as_deref().unwrap_or("");
            compute_response_auth(ha1_for_digest, &creds.nonce, nc, cnonce, &ha2)
        } else {
            compute_response(ha1_for_digest, &creds.nonce, &ha2)
        };
        let digest_ok = ha1.is_some() && expected == creds.response;

        let mut nonces = self.nonces.lock().await;
        let now = Self::now_secs();
        let Some(record) = nonces.get_mut(&creds.nonce) else {
            // Not ours (restart, a cached challenge from long ago, or a
            // made-up nonce): re-challenge. Same answer whatever the digest
            // or the user, so a forged nonce tests neither passwords nor
            // usernames, and strikes nobody from a spoofed source.
            return Err(AuthFailure::StaleNonce { user });
        };
        if now.saturating_sub(record.created_at) > self.nonce_ttl {
            nonces.remove(&creds.nonce);
            return Err(if digest_ok {
                AuthFailure::StaleNonce { user }
            } else if ha1.is_none() {
                AuthFailure::UnknownUser { user }
            } else {
                AuthFailure::BadCredentials { user }
            });
        }
        if ha1.is_none() {
            return Err(AuthFailure::UnknownUser { user });
        }
        if !digest_ok {
            return Err(AuthFailure::BadCredentials { user });
        }

        // Replay protection (RFC 7616 §5.7): with qop=auth the nonce-count
        // must advance; a retransmission (same nc, same request) is fine.
        // Without qop the nonce is single-use.
        if qop_auth {
            let nc = creds
                .nc
                .as_deref()
                .and_then(|n| u32::from_str_radix(n.trim(), 16).ok())
                .ok_or_else(|| AuthFailure::StaleNonce { user: user.clone() })?;
            if nc > record.last_nc {
                record.last_nc = nc;
                record.last_fingerprint = fingerprint;
            } else if !(nc == record.last_nc
                && fingerprint.is_some()
                && fingerprint == record.last_fingerprint)
            {
                return Err(AuthFailure::Replay { user });
            }
        } else if record.use_count > 0 {
            return Err(AuthFailure::StaleNonce { user });
        }
        record.use_count += 1;
        Ok(user)
    }

    /// Test hook: age a nonce so the next use is stale.
    #[cfg(test)]
    pub async fn backdate_nonce(&self, nonce: &str, secs: u64) {
        if let Some(r) = self.nonces.lock().await.get_mut(nonce) {
            r.created_at = r.created_at.saturating_sub(secs);
        }
    }

    /// Remove expired nonces (run by the maintenance sweeper). Returns the
    /// number removed.
    pub async fn cleanup_nonces(&self) -> usize {
        let now = Self::now_secs();
        let mut nonces = self.nonces.lock().await;
        let before = nonces.len();
        nonces.retain(|_, r| now.saturating_sub(r.created_at) <= self.nonce_ttl);
        before - nonces.len()
    }

    /// Check if a username exists (for routing decisions)
    pub async fn user_exists(&self, username: &str) -> bool {
        let users = self.users.read().await;
        users.contains_key(username)
    }

    /// Number of active nonces
    pub async fn active_nonces(&self) -> usize {
        self.nonces.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth() -> DigestAuthenticator {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "secret123".to_string());
        users.insert("bob".to_string(), "pass456".to_string());
        DigestAuthenticator::new("example.com", users)
    }

    #[test]
    fn test_md5_known_value() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_ha1_computation() {
        // HA1("alice", "example.com", "secret") = MD5("alice:example.com:secret")
        let ha1 = compute_ha1("alice", "example.com", "secret");
        assert_eq!(ha1.len(), 32);
        // Deterministic
        assert_eq!(ha1, compute_ha1("alice", "example.com", "secret"));
        // Different password → different HA1
        assert_ne!(ha1, compute_ha1("alice", "example.com", "wrong"));
    }

    #[test]
    fn test_ha2_computation() {
        let ha2 = compute_ha2("INVITE", "sip:bob@example.com");
        assert_eq!(ha2.len(), 32);
        assert_ne!(ha2, compute_ha2("BYE", "sip:bob@example.com"));
    }

    #[test]
    fn test_response_computation() {
        let ha1 = compute_ha1("alice", "example.com", "secret");
        let ha2 = compute_ha2("INVITE", "sip:bob@example.com");
        let resp = compute_response(&ha1, "testNonce123", &ha2);
        assert_eq!(resp.len(), 32);
        // Same inputs → same response
        assert_eq!(resp, compute_response(&ha1, "testNonce123", &ha2));
        // Different nonce → different response
        assert_ne!(resp, compute_response(&ha1, "differentNonce", &ha2));
    }

    #[test]
    fn test_parse_digest_credentials() {
        let header = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="deadbeef00112233445566778899aabb""#;
        let creds = DigestCredentials::from_header(header).unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.realm, "example.com");
        assert_eq!(creds.nonce, "abc123");
        assert_eq!(creds.uri, "sip:bob@example.com");
    }

    #[test]
    fn test_parse_digest_credentials_with_qop() {
        let header = r#"Digest username="bob", realm="r", nonce="n", uri="sip:a@b", response="r", qop=auth, nc=00000001, cnonce="cc""#;
        let creds = DigestCredentials::from_header(header).unwrap();
        assert_eq!(creds.qop.as_deref(), Some("auth"));
        assert_eq!(creds.nc.as_deref(), Some("00000001"));
        assert_eq!(creds.cnonce.as_deref(), Some("cc"));
    }

    #[test]
    fn test_parse_invalid_credentials() {
        // Missing realm
        let result = DigestCredentials::from_header(
            r#"Digest username="x", nonce="n", uri="u", response="r""#,
        );
        assert!(result.is_err());

        // Not Digest scheme
        let result = DigestCredentials::from_header("Basic dXNlcjpwYXNz");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_challenge() {
        let auth = make_auth();
        let challenge = auth.generate_challenge().await;
        assert!(challenge.contains("Digest"));
        assert!(challenge.contains("example.com"));
        assert!(challenge.contains("nonce="));
        assert_eq!(auth.active_nonces().await, 1);

        // Each challenge generates unique nonce
        let ch2 = auth.generate_challenge().await;
        assert_ne!(challenge, ch2);
        assert_eq!(auth.active_nonces().await, 2);
    }

    #[tokio::test]
    async fn test_verify_correct_credentials() {
        let auth = make_auth();
        let challenge = auth.generate_challenge().await;

        // Extract nonce from challenge
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();

        // Compute correct response
        let ha1 = compute_ha1("alice", "example.com", "secret123");
        let ha2 = compute_ha2("INVITE", "sip:bob@example.com");
        let response = compute_response(&ha1, nonce, &ha2);

        let auth_header = format!(
            r#"Digest username="alice", realm="example.com", nonce="{}", uri="sip:bob@example.com", response="{}""#,
            nonce, response
        );

        let result = auth.verify(&auth_header, "INVITE").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "alice");
    }

    #[tokio::test]
    async fn test_verify_wrong_password() {
        let auth = make_auth();
        let challenge = auth.generate_challenge().await;
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();

        // Wrong password
        let ha1 = compute_ha1("alice", "example.com", "WRONGPASSWORD");
        let ha2 = compute_ha2("INVITE", "sip:bob@example.com");
        let response = compute_response(&ha1, nonce, &ha2);

        let auth_header = format!(
            r#"Digest username="alice", realm="example.com", nonce="{}", uri="sip:bob@example.com", response="{}""#,
            nonce, response
        );

        let result = auth.verify(&auth_header, "INVITE").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_unknown_nonce() {
        let auth = make_auth();

        let ha1 = compute_ha1("alice", "example.com", "secret123");
        let ha2 = compute_ha2("INVITE", "sip:x");
        let response = compute_response(&ha1, "fakefakenonce", &ha2);

        let auth_header = format!(
            r#"Digest username="alice", realm="example.com", nonce="fakefakenonce", uri="sip:x", response="{}""#,
            response
        );

        let result = auth.verify(&auth_header, "INVITE").await;
        assert_eq!(
            result,
            Err(AuthFailure::StaleNonce {
                user: "alice".into()
            }),
            "an unknown nonce is re-challenged, never punished"
        );
    }

    fn nonce_of(challenge: &str) -> String {
        challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string()
    }

    fn qop_header(nonce: &str, user: &str, password: &str, nc: &str, cnonce: &str) -> String {
        let ha1 = compute_ha1(user, "example.com", password);
        let ha2 = compute_ha2("REGISTER", "sip:example.com");
        let response = compute_response_auth(&ha1, nonce, nc, cnonce, &ha2);
        format!(
            r#"Digest username="{}", realm="example.com", nonce="{}", uri="sip:example.com", response="{}", algorithm=MD5, cnonce="{}", nc={}, qop=auth"#,
            user, nonce, response, cnonce, nc
        )
    }

    #[tokio::test]
    async fn stale_nonce_is_rechallenged_not_punished() {
        let auth = make_auth();
        let nonce = nonce_of(&auth.generate_challenge().await);
        auth.backdate_nonce(&nonce, 301).await;
        let header = qop_header(&nonce, "alice", "secret123", "00000001", "c1");
        assert_eq!(
            auth.verify(&header, "REGISTER").await,
            Err(AuthFailure::StaleNonce {
                user: "alice".into()
            })
        );
        // Expired nonce with a wrong digest is still a wrong password.
        let nonce = nonce_of(&auth.generate_challenge().await);
        auth.backdate_nonce(&nonce, 301).await;
        let header = qop_header(&nonce, "alice", "nope", "00000001", "c1");
        assert_eq!(
            auth.verify(&header, "REGISTER").await,
            Err(AuthFailure::BadCredentials {
                user: "alice".into()
            })
        );
        let challenge = auth.generate_challenge_with(true).await;
        assert!(challenge.ends_with(", stale=true"), "{}", challenge);
        assert!(!auth.generate_challenge().await.contains("stale"));

        // No username oracle: an unknown user on a forged nonce gets the
        // same answer as a known one, and never a strike.
        let header = qop_header("nobody-here", "nobody", "pw", "00000001", "c1");
        let forged = header.replace("nonce=\"nobody-here\"", "nonce=\"forged\"");
        assert_eq!(
            auth.verify(&forged, "REGISTER").await,
            Err(AuthFailure::StaleNonce {
                user: "nobody".into()
            })
        );
        // …but on a nonce we issued it is an unknown user (a strike).
        let nonce = nonce_of(&auth.generate_challenge().await);
        let header = qop_header(&nonce, "nobody", "pw", "00000001", "c1");
        assert_eq!(
            auth.verify(&header, "REGISTER").await,
            Err(AuthFailure::UnknownUser {
                user: "nobody".into()
            })
        );
    }

    #[tokio::test]
    async fn nonce_count_must_advance_except_for_retransmissions() {
        let auth = make_auth();
        let nonce = nonce_of(&auth.generate_challenge().await);
        let first = qop_header(&nonce, "alice", "secret123", "00000001", "c1");
        assert_eq!(
            auth.verify_with(&first, "REGISTER", Some(11)).await,
            Ok("alice".into())
        );
        // Byte-identical retransmission (same fingerprint): accepted again.
        assert_eq!(
            auth.verify_with(&first, "REGISTER", Some(11)).await,
            Ok("alice".into())
        );
        // Same nc from another request: replay.
        assert_eq!(
            auth.verify_with(&first, "REGISTER", Some(12)).await,
            Err(AuthFailure::Replay {
                user: "alice".into()
            })
        );
        // A lower nc: replay too.
        let lower = qop_header(&nonce, "alice", "secret123", "00000000", "c1");
        assert!(matches!(
            auth.verify_with(&lower, "REGISTER", Some(13)).await,
            Err(AuthFailure::Replay { .. })
        ));
        // The next count is fine.
        let second = qop_header(&nonce, "alice", "secret123", "00000002", "c2");
        assert_eq!(
            auth.verify_with(&second, "REGISTER", Some(14)).await,
            Ok("alice".into())
        );
        // Unparsable nc: re-challenge, no strike.
        let odd = qop_header(&nonce, "alice", "secret123", "zz", "c3");
        assert!(matches!(
            auth.verify_with(&odd, "REGISTER", Some(15)).await,
            Err(AuthFailure::StaleNonce { .. })
        ));
        assert!(!AuthFailure::StaleNonce { user: "a".into() }.is_attack());
        assert!(
            !AuthFailure::Replay { user: "a".into() }.is_attack(),
            "a replay proves the password is known: re-challenge, never ban"
        );
        assert!(AuthFailure::Replay { user: "a".into() }.is_stale());
        assert!(AuthFailure::BadCredentials { user: "a".into() }.is_attack());
        assert!(matches!(
            auth.verify("garbage", "REGISTER").await,
            Err(AuthFailure::Malformed)
        ));
    }

    #[tokio::test]
    async fn test_verify_unknown_user() {
        let auth = make_auth();
        let challenge = auth.generate_challenge().await;
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();

        let ha1 = compute_ha1("nobody", "example.com", "pass");
        let ha2 = compute_ha2("INVITE", "sip:x");
        let response = compute_response(&ha1, nonce, &ha2);

        let auth_header = format!(
            r#"Digest username="nobody", realm="example.com", nonce="{}", uri="sip:x", response="{}""#,
            nonce, response
        );

        let result = auth.verify(&auth_header, "INVITE").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nonce_cleanup() {
        let auth = make_auth();
        for _ in 0..5 {
            auth.generate_challenge().await;
        }
        assert_eq!(auth.active_nonces().await, 5);
        auth.cleanup_nonces().await;
        // All nonces are fresh (< TTL), so none should be removed
        assert_eq!(auth.active_nonces().await, 5);
    }

    // ── Outbound Digest Auth tests ────────────────────────────────────

    #[test]
    fn test_parse_digest_challenge() {
        let header =
            r#"Digest realm="trunk.example.com", nonce="abc123", algorithm=MD5, qop="auth""#;
        let challenge = DigestChallenge::from_header(header).unwrap();
        assert_eq!(challenge.realm, "trunk.example.com");
        assert_eq!(challenge.nonce, "abc123");
        assert_eq!(challenge.algorithm, "MD5");
        assert_eq!(challenge.qop.as_deref(), Some("auth"));
        assert!(challenge.opaque.is_none());
    }

    #[test]
    fn test_parse_digest_challenge_minimal() {
        let header = r#"Digest realm="example.com", nonce="xyz""#;
        let challenge = DigestChallenge::from_header(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert_eq!(challenge.nonce, "xyz");
        assert_eq!(challenge.algorithm, "MD5"); // default
        assert!(challenge.qop.is_none());
    }

    #[test]
    fn test_parse_digest_challenge_with_opaque() {
        let header = r#"Digest realm="test", nonce="n1", opaque="op123""#;
        let challenge = DigestChallenge::from_header(header).unwrap();
        assert_eq!(challenge.opaque.as_deref(), Some("op123"));
    }

    #[test]
    fn test_parse_digest_challenge_missing_realm() {
        let header = r#"Digest nonce="n1""#;
        assert!(DigestChallenge::from_header(header).is_err());
    }

    #[test]
    fn test_parse_digest_challenge_not_digest() {
        let header = "Basic dXNlcjpwYXNz";
        assert!(DigestChallenge::from_header(header).is_err());
    }

    #[test]
    fn test_generate_digest_response_no_qop() {
        let challenge = DigestChallenge {
            realm: "trunk.example.com".into(),
            nonce: "testnonce123".into(),
            algorithm: "MD5".into(),
            qop: None,
            opaque: None,
        };
        let result = generate_digest_response(
            "8933100005601",
            "ad42vg6fg",
            &challenge,
            "INVITE",
            "sip:0612345678@trunk.example.com",
        );
        assert!(result.starts_with("Digest "));
        assert!(result.contains(r#"username="8933100005601""#));
        assert!(result.contains(r#"realm="trunk.example.com""#));
        assert!(result.contains(r#"nonce="testnonce123""#));
        assert!(result.contains("response=\""));
        assert!(!result.contains("qop="));

        // Verify the response is a 32-char hex MD5 hash
        let resp = result
            .split("response=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(resp.len(), 32);
        assert!(resp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_digest_response_with_qop() {
        let challenge = DigestChallenge {
            realm: "trunk.example.com".into(),
            nonce: "testnonce123".into(),
            algorithm: "MD5".into(),
            qop: Some("auth".into()),
            opaque: None,
        };
        let result = generate_digest_response(
            "8933100005601",
            "ad42vg6fg",
            &challenge,
            "REGISTER",
            "sip:trunk.example.com",
        );
        assert!(result.contains("qop=auth"));
        assert!(result.contains("nc=00000001"));
        assert!(result.contains("cnonce=\""));
    }

    #[test]
    fn test_generate_digest_response_with_opaque() {
        let challenge = DigestChallenge {
            realm: "test".into(),
            nonce: "n".into(),
            algorithm: "MD5".into(),
            qop: None,
            opaque: Some("op123".into()),
        };
        let result = generate_digest_response("user", "pass", &challenge, "INVITE", "sip:x");
        assert!(result.contains(r#"opaque="op123""#));
    }

    #[test]
    fn test_generate_digest_response_verifiable() {
        // Verify that the generated response can be verified against manual computation
        let challenge = DigestChallenge {
            realm: "example.com".into(),
            nonce: "abc123".into(),
            algorithm: "MD5".into(),
            qop: None,
            opaque: None,
        };
        let result = generate_digest_response(
            "alice",
            "secret123",
            &challenge,
            "INVITE",
            "sip:bob@example.com",
        );

        // Manually compute expected response
        let ha1 = compute_ha1("alice", "example.com", "secret123");
        let ha2 = compute_ha2("INVITE", "sip:bob@example.com");
        let expected = compute_response(&ha1, "abc123", &ha2);

        assert!(result.contains(&format!("response=\"{}\"", expected)));
    }
}
