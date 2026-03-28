//! SRTP (Secure RTP) Support
//!
//! RFC 3711 - The Secure Real-time Transport Protocol (SRTP)
//!
//! Delegates real encryption to srtp_crypto.rs (AES-CM + HMAC-SHA1).

use crate::media::srtp_crypto::{derive_srtp_keys, SrtpCrypto};
use rand::Rng;
use crate::{Error, Result};
use std::fmt;

/// SRTP Crypto Suite
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoSuite {
    /// AES-128 CM with HMAC-SHA1 80-bit auth tag
    AesCm128HmacSha1_80,

    /// AES-128 CM with HMAC-SHA1 32-bit auth tag
    AesCm128HmacSha1_32,

    /// AES-256 CM with HMAC-SHA1 80-bit auth tag
    AesCm256HmacSha1_80,

    /// AES-256 CM with HMAC-SHA1 32-bit auth tag
    AesCm256HmacSha1_32,
}

impl CryptoSuite {
    /// Get master key length in bytes
    pub fn master_key_len(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => 16, // 128 bits
            Self::AesCm256HmacSha1_80 | Self::AesCm256HmacSha1_32 => 32, // 256 bits
        }
    }

    /// Get master salt length in bytes
    pub fn master_salt_len(&self) -> usize {
        14 // Always 112 bits for all suites
    }

    /// Get auth tag length in bytes
    pub fn auth_tag_len(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 | Self::AesCm256HmacSha1_80 => 10, // 80 bits
            Self::AesCm128HmacSha1_32 | Self::AesCm256HmacSha1_32 => 4,  // 32 bits
        }
    }

    /// Parse from SDP crypto attribute
    pub fn from_sdp_name(name: &str) -> Option<Self> {
        match name {
            "AES_CM_128_HMAC_SHA1_80" => Some(Self::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" => Some(Self::AesCm128HmacSha1_32),
            "AES_256_CM_HMAC_SHA1_80" => Some(Self::AesCm256HmacSha1_80),
            "AES_256_CM_HMAC_SHA1_32" => Some(Self::AesCm256HmacSha1_32),
            _ => None,
        }
    }

    /// Convert to SDP crypto attribute name
    pub fn to_sdp_name(&self) -> &'static str {
        match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
            Self::AesCm256HmacSha1_80 => "AES_256_CM_HMAC_SHA1_80",
            Self::AesCm256HmacSha1_32 => "AES_256_CM_HMAC_SHA1_32",
        }
    }
}

impl fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_sdp_name())
    }
}

/// SRTP Context - delegates to real AES-CM + HMAC-SHA1 implementation
pub struct SrtpContext {
    /// Master key (kept for key_params export)
    master_key: Vec<u8>,

    /// Master salt (kept for key_params export)
    master_salt: Vec<u8>,

    /// Crypto suite
    crypto_suite: CryptoSuite,

    /// Real crypto engine (derived from master key/salt via KDF)
    crypto: Option<SrtpCrypto>,
}

impl SrtpContext {
    /// Create new SRTP context with master key and salt
    pub fn new(master_key: Vec<u8>, master_salt: Vec<u8>, crypto_suite: CryptoSuite) -> Result<Self> {
        if master_key.len() != crypto_suite.master_key_len() {
            return Err(Error::Media(format!(
                "Invalid master key length: expected {}, got {}",
                crypto_suite.master_key_len(),
                master_key.len()
            )));
        }

        if master_salt.len() != crypto_suite.master_salt_len() {
            return Err(Error::Media(format!(
                "Invalid master salt length: expected {}, got {}",
                crypto_suite.master_salt_len(),
                master_salt.len()
            )));
        }

        // Derive session keys from master key/salt using RFC 3711 KDF
        let (cipher_key, auth_key, salt_key) = derive_srtp_keys(&master_key, &master_salt, 0)?;
        let auth_tag_len = crypto_suite.auth_tag_len();
        let crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, auth_tag_len)?;

        Ok(Self {
            master_key,
            master_salt,
            crypto_suite,
            crypto: Some(crypto),
        })
    }

    /// Create from base64-encoded key material (from SDP a=crypto: line)
    pub fn from_key_params(key_params: &str, crypto_suite: CryptoSuite) -> Result<Self> {
        let inline_prefix = "inline:";
        if !key_params.starts_with(inline_prefix) {
            return Err(Error::Media("Key params must start with 'inline:'".to_string()));
        }

        let base64_data = &key_params[inline_prefix.len()..];
        let decoded = base64::decode(base64_data)
            .map_err(|e| Error::Media(format!("Invalid base64 in key params: {}", e)))?;

        let key_len = crypto_suite.master_key_len();
        let salt_len = crypto_suite.master_salt_len();

        if decoded.len() < key_len + salt_len {
            return Err(Error::Media(format!(
                "Key material too short: expected {}, got {}",
                key_len + salt_len,
                decoded.len()
            )));
        }

        let master_key = decoded[..key_len].to_vec();
        let master_salt = decoded[key_len..key_len + salt_len].to_vec();

        Self::new(master_key, master_salt, crypto_suite)
    }

    /// Encrypt RTP packet — real AES-CM encryption + HMAC-SHA1 auth tag
    pub fn encrypt_rtp(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.crypto
            .as_mut()
            .ok_or_else(|| Error::Media("SRTP context not initialised".to_string()))?
            .encrypt_rtp(plaintext)
    }

    /// Decrypt SRTP packet — verifies HMAC-SHA1 auth tag, decrypts AES-CM
    pub fn decrypt_srtp(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.crypto
            .as_mut()
            .ok_or_else(|| Error::Media("SRTP context not initialised".to_string()))?
            .decrypt_srtp(ciphertext)
    }

    /// Get crypto suite
    pub fn crypto_suite(&self) -> CryptoSuite {
        self.crypto_suite
    }

    /// Clone this context for the send direction (creates fresh crypto state).
    /// Used for SDES-SRTP where the same key material is used in both directions.
    pub fn clone_for_send(&self) -> Self {
        Self::new(self.master_key.clone(), self.master_salt.clone(), self.crypto_suite)
            .expect("clone_for_send: same params that worked in new() should work again")
    }

    /// Export key material for SDP a=crypto: attribute
    pub fn to_key_params(&self) -> String {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&self.master_key);
        key_material.extend_from_slice(&self.master_salt);
        format!("inline:{}", base64::encode(&key_material))
    }
}

/// Parse SDP crypto attribute
///
/// Format: a=crypto:<tag> <crypto-suite> <key-params>
/// Example: a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj
pub fn parse_crypto_attribute(line: &str) -> Result<(u32, CryptoSuite, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(Error::Media("Invalid crypto attribute format".to_string()));
    }

    let tag = parts[0]
        .parse::<u32>()
        .map_err(|e| Error::Media(format!("Invalid crypto tag: {}", e)))?;

    let crypto_suite = CryptoSuite::from_sdp_name(parts[1])
        .ok_or_else(|| Error::Media(format!("Unsupported crypto suite: {}", parts[1])))?;

    let key_params = parts[2].to_string();

    Ok((tag, crypto_suite, key_params))
}

/// Generate random key material for SRTP (cryptographically secure)
pub fn generate_key_material(crypto_suite: CryptoSuite) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut master_key = vec![0u8; crypto_suite.master_key_len()];
    let mut master_salt = vec![0u8; crypto_suite.master_salt_len()];
    rng.fill(&mut master_key[..]);
    rng.fill(&mut master_salt[..]);
    (master_key, master_salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_suite_lengths() {
        assert_eq!(CryptoSuite::AesCm128HmacSha1_80.master_key_len(), 16);
        assert_eq!(CryptoSuite::AesCm128HmacSha1_80.master_salt_len(), 14);
        assert_eq!(CryptoSuite::AesCm128HmacSha1_80.auth_tag_len(), 10);
        assert_eq!(CryptoSuite::AesCm256HmacSha1_80.master_key_len(), 32);
        assert_eq!(CryptoSuite::AesCm256HmacSha1_80.auth_tag_len(), 10);
    }

    #[test]
    fn test_crypto_suite_from_sdp_name() {
        assert_eq!(
            CryptoSuite::from_sdp_name("AES_CM_128_HMAC_SHA1_80"),
            Some(CryptoSuite::AesCm128HmacSha1_80)
        );
        assert_eq!(CryptoSuite::from_sdp_name("INVALID"), None);
    }

    #[test]
    fn test_srtp_context_creation() {
        let master_key = vec![0u8; 16];
        let master_salt = vec![0u8; 14];
        let ctx = SrtpContext::new(master_key, master_salt, CryptoSuite::AesCm128HmacSha1_80);
        assert!(ctx.is_ok());
    }

    #[test]
    fn test_srtp_context_invalid_key_length() {
        let master_key = vec![0u8; 10]; // Too short
        let master_salt = vec![0u8; 14];
        let ctx = SrtpContext::new(master_key, master_salt, CryptoSuite::AesCm128HmacSha1_80);
        assert!(ctx.is_err());
    }

    #[test]
    fn test_key_params_round_trip() {
        let master_key = vec![1u8; 16];
        let master_salt = vec![2u8; 14];
        let ctx = SrtpContext::new(
            master_key.clone(),
            master_salt.clone(),
            CryptoSuite::AesCm128HmacSha1_80,
        ).unwrap();
        let key_params = ctx.to_key_params();
        assert!(key_params.starts_with("inline:"));

        let ctx2 = SrtpContext::from_key_params(&key_params, CryptoSuite::AesCm128HmacSha1_80).unwrap();
        assert_eq!(ctx2.master_key, master_key);
        assert_eq!(ctx2.master_salt, master_salt);
    }

    #[test]
    fn test_parse_crypto_attribute() {
        let line = "1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
        let result = parse_crypto_attribute(line);
        assert!(result.is_ok());
        let (tag, suite, key_params) = result.unwrap();
        assert_eq!(tag, 1);
        assert_eq!(suite, CryptoSuite::AesCm128HmacSha1_80);
        assert!(key_params.starts_with("inline:"));
    }

    #[test]
    fn test_encrypt_decrypt_real_aes_cm() {
        // Test avec une vraie paire clé/sel
        let master_key = vec![
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let master_salt = vec![
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
        ];

        let mut ctx_enc = SrtpContext::new(
            master_key.clone(), master_salt.clone(), CryptoSuite::AesCm128HmacSha1_80
        ).unwrap();
        let mut ctx_dec = SrtpContext::new(
            master_key, master_salt, CryptoSuite::AesCm128HmacSha1_80
        ).unwrap();

        // Build a minimal RTP packet (12-byte header + payload)
        let mut rtp = vec![
            0x80, 0x00, 0x00, 0x01, // V=2, PT=0, SEQ=1
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x00, 0x00, 0x00, 0x01, // SSRC=1
        ];
        rtp.extend_from_slice(b"Hello SRTP payload");

        let encrypted = ctx_enc.encrypt_rtp(&rtp).unwrap();
        // Encrypted packet is longer (has auth tag)
        assert!(encrypted.len() > rtp.len());

        let decrypted = ctx_dec.decrypt_srtp(&encrypted).unwrap();
        assert_eq!(decrypted, rtp, "Decrypt must recover original RTP packet");
    }
}
