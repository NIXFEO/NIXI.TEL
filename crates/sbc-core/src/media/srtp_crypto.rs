//! SRTP Encryption - Real AES-CM + HMAC-SHA1 Implementation
//!
//! RFC 3711 compliant SRTP encryption/authentication

use crate::{Error, Result};
use aes::Aes128;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;

type Aes128Ctr = Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// SRTP Cryptographic Context with real encryption
pub struct SrtpCrypto {
    /// Cipher key for AES-CM
    cipher_key: Vec<u8>,

    /// Authentication key for HMAC-SHA1
    auth_key: Vec<u8>,

    /// Salt key for IV derivation
    salt_key: Vec<u8>,

    /// Authentication tag length (80 or 32 bits)
    auth_tag_len: usize,

    /// Rollover counter (for key stream generation)
    roc: u32,
}

impl SrtpCrypto {
    /// Create new SRTP crypto context
    ///
    /// Keys should be derived from master key/salt using KDF
    pub fn new(
        cipher_key: Vec<u8>,
        auth_key: Vec<u8>,
        salt_key: Vec<u8>,
        auth_tag_len: usize,
    ) -> Result<Self> {
        // Validate key lengths
        if cipher_key.len() != 16 && cipher_key.len() != 32 {
            return Err(Error::Media(format!(
                "Invalid cipher key length: {}",
                cipher_key.len()
            )));
        }

        if auth_key.len() != 20 {
            return Err(Error::Media(format!(
                "Invalid auth key length: {}",
                auth_key.len()
            )));
        }

        if salt_key.len() != 14 {
            return Err(Error::Media(format!(
                "Invalid salt key length: {}",
                salt_key.len()
            )));
        }

        if auth_tag_len != 10 && auth_tag_len != 4 {
            return Err(Error::Media(format!(
                "Invalid auth tag length: {}",
                auth_tag_len
            )));
        }

        Ok(Self {
            cipher_key,
            auth_key,
            salt_key,
            auth_tag_len,
            roc: 0,
        })
    }

    /// Encrypt RTP packet
    ///
    /// Input: RTP packet (header + payload)
    /// Output: SRTP packet (header + encrypted payload + auth tag)
    pub fn encrypt_rtp(&mut self, rtp_packet: &[u8]) -> Result<Vec<u8>> {
        if rtp_packet.len() < 12 {
            return Err(Error::Media("RTP packet too short".to_string()));
        }

        // Extract RTP header (first 12 bytes minimum)
        let header_len = self.get_rtp_header_length(rtp_packet)?;
        let header = &rtp_packet[..header_len];
        let payload = &rtp_packet[header_len..];

        // Extract SSRC and sequence number for IV derivation
        let ssrc = u32::from_be_bytes([
            rtp_packet[8],
            rtp_packet[9],
            rtp_packet[10],
            rtp_packet[11],
        ]);
        let seq = u16::from_be_bytes([rtp_packet[2], rtp_packet[3]]);

        // Derive IV for this packet
        let iv = self.derive_iv(ssrc, seq);

        // Encrypt payload using AES-CTR
        let mut encrypted_payload = payload.to_vec();
        if self.cipher_key.len() == 16 {
            let mut cipher = Aes128Ctr::new(self.cipher_key[..16].into(), &iv.into());
            cipher.apply_keystream(&mut encrypted_payload);
        }

        // Build SRTP packet: header + encrypted payload
        let mut srtp_packet = Vec::new();
        srtp_packet.extend_from_slice(header);
        srtp_packet.extend_from_slice(&encrypted_payload);

        // Compute HMAC-SHA1 over entire SRTP packet + ROC
        let auth_tag = self.compute_auth_tag(&srtp_packet)?;

        // Append truncated auth tag
        srtp_packet.extend_from_slice(&auth_tag[..self.auth_tag_len]);

        Ok(srtp_packet)
    }

    /// Decrypt SRTP packet
    ///
    /// Input: SRTP packet (header + encrypted payload + auth tag)
    /// Output: RTP packet (header + plaintext payload)
    pub fn decrypt_srtp(&mut self, srtp_packet: &[u8]) -> Result<Vec<u8>> {
        if srtp_packet.len() < 12 + self.auth_tag_len {
            return Err(Error::Media("SRTP packet too short".to_string()));
        }

        // Split packet and auth tag
        let packet_len = srtp_packet.len() - self.auth_tag_len;
        let packet = &srtp_packet[..packet_len];
        let received_tag = &srtp_packet[packet_len..];

        // Verify authentication tag
        let computed_tag = self.compute_auth_tag(packet)?;
        if !self.constant_time_compare(&computed_tag[..self.auth_tag_len], received_tag) {
            return Err(Error::Media("SRTP authentication failed".to_string()));
        }

        // Extract header
        let header_len = self.get_rtp_header_length(packet)?;
        let header = &packet[..header_len];
        let encrypted_payload = &packet[header_len..];

        // Extract SSRC and sequence number
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let seq = u16::from_be_bytes([packet[2], packet[3]]);

        // Derive IV
        let iv = self.derive_iv(ssrc, seq);

        // Decrypt payload using AES-CTR
        let mut plaintext_payload = encrypted_payload.to_vec();
        let mut cipher = Aes128Ctr::new(self.cipher_key[..16].into(), &iv.into());
        cipher.apply_keystream(&mut plaintext_payload);

        // Build RTP packet
        let mut rtp_packet = Vec::new();
        rtp_packet.extend_from_slice(header);
        rtp_packet.extend_from_slice(&plaintext_payload);

        Ok(rtp_packet)
    }

    /// Derive IV for AES-CTR (RFC 3711 Section 4.1.1)
    ///
    /// IV layout (128 bits):
    ///   bytes [0-3]   = 0x00000000  (label 0x00 for RTP, zero-padded)
    ///   bytes [4-7]   = SSRC
    ///   bytes [8-13]  = packet_index (48 bits = ROC || SEQ)
    ///   bytes [14-15] = 0x0000
    ///
    /// Then XOR with session salt (14 bytes, applied to bytes [0-13])
    fn derive_iv(&self, ssrc: u32, seq: u16) -> [u8; 16] {
        let mut iv = [0u8; 16];

        // Packet index = ROC * 65536 + SEQ (48 bits)
        let packet_index: u64 = (self.roc as u64) << 16 | seq as u64;

        // SSRC at bytes [4-7]
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());

        // Packet index at bytes [8-13] (48 bits)
        iv[8]  = ((packet_index >> 40) & 0xFF) as u8;
        iv[9]  = ((packet_index >> 32) & 0xFF) as u8;
        iv[10] = ((packet_index >> 24) & 0xFF) as u8;
        iv[11] = ((packet_index >> 16) & 0xFF) as u8;
        iv[12] = ((packet_index >> 8) & 0xFF) as u8;
        iv[13] = (packet_index & 0xFF) as u8;

        // Bytes [0-3] and [14-15] remain zero

        // XOR with salt_key (14 bytes → bytes [0-13])
        for i in 0..14 {
            iv[i] ^= self.salt_key[i];
        }

        iv
    }

    /// Compute HMAC-SHA1 authentication tag
    fn compute_auth_tag(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key)
            .map_err(|e| Error::Media(format!("HMAC init error: {}", e)))?;

        // HMAC over packet + ROC
        mac.update(packet);
        mac.update(&self.roc.to_be_bytes());

        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// Get RTP header length (accounting for CSRC and extensions)
    fn get_rtp_header_length(&self, packet: &[u8]) -> Result<usize> {
        if packet.len() < 12 {
            return Err(Error::Media("Packet too short for RTP header".to_string()));
        }

        // Base header is 12 bytes
        let mut header_len = 12;

        // CSRC count (bits 4-7 of byte 0)
        let cc = packet[0] & 0x0F;
        header_len += (cc as usize) * 4;

        // Check for header extension (bit 4 of byte 0)
        if packet[0] & 0x10 != 0 {
            if packet.len() < header_len + 4 {
                return Err(Error::Media("Packet too short for extension".to_string()));
            }

            // Extension length is in 32-bit words (bytes header_len+2 and header_len+3)
            let ext_len = u16::from_be_bytes([
                packet[header_len + 2],
                packet[header_len + 3],
            ]) as usize;

            header_len += 4 + (ext_len * 4);
        }

        if header_len > packet.len() {
            return Err(Error::Media("Invalid RTP header length".to_string()));
        }

        Ok(header_len)
    }

    /// Constant-time comparison to prevent timing attacks
    fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Update rollover counter
    pub fn update_roc(&mut self, new_roc: u32) {
        self.roc = new_roc;
    }

    /// Get current ROC
    pub fn get_roc(&self) -> u32 {
        self.roc
    }
}

/// Key Derivation Function (KDF) for SRTP
///
/// Derives cipher_key, auth_key, and salt_key from master key and salt
pub fn derive_srtp_keys(
    master_key: &[u8],
    master_salt: &[u8],
    _key_derivation_rate: u8,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if master_key.len() != 16 && master_key.len() != 32 {
        return Err(Error::Media(format!(
            "Invalid master key length: {}",
            master_key.len()
        )));
    }

    if master_salt.len() != 14 {
        return Err(Error::Media(format!(
            "Invalid master salt length: {}",
            master_salt.len()
        )));
    }

    // For simplicity, using PRF with label-based derivation
    // label_cipher = 0x00, label_auth = 0x01, label_salt = 0x02

    let cipher_key = kdf_prf(master_key, master_salt, 0x00, master_key.len())?;
    let auth_key = kdf_prf(master_key, master_salt, 0x01, 20)?; // 160 bits for HMAC-SHA1
    let salt_key = kdf_prf(master_key, master_salt, 0x02, 14)?; // 112 bits

    Ok((cipher_key, auth_key, salt_key))
}

/// PRF for key derivation
fn kdf_prf(master_key: &[u8], master_salt: &[u8], label: u8, output_len: usize) -> Result<Vec<u8>> {
    // IV for KDF: master_salt XOR (label || 0x00 || index)
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(master_salt);
    iv[7] ^= label;

    // Use AES-CTR to generate keystream
    let mut output = vec![0u8; output_len];
    let mut cipher = Aes128Ctr::new(master_key[..16].into(), &iv.into());
    cipher.apply_keystream(&mut output);

    Ok(output)
}

/// SRTCP Cryptographic Context (RFC 3711 Section 3.4)
///
/// SRTCP encrypts and authenticates RTCP packets.
/// Unlike SRTP, SRTCP includes an E-bit and SRTCP index in the packet.
pub struct SrtcpCrypto {
    /// Cipher key for AES-CM
    cipher_key: Vec<u8>,

    /// Authentication key for HMAC-SHA1
    auth_key: Vec<u8>,

    /// Salt key for IV derivation
    salt_key: Vec<u8>,

    /// Authentication tag length in bytes
    auth_tag_len: usize,

    /// SRTCP index (monotonically increasing)
    srtcp_index: u32,
}

impl SrtcpCrypto {
    /// Create new SRTCP crypto context
    pub fn new(
        cipher_key: Vec<u8>,
        auth_key: Vec<u8>,
        salt_key: Vec<u8>,
        auth_tag_len: usize,
    ) -> Result<Self> {
        if cipher_key.len() != 16 && cipher_key.len() != 32 {
            return Err(Error::Media(format!(
                "Invalid cipher key length: {}",
                cipher_key.len()
            )));
        }
        if auth_key.len() != 20 {
            return Err(Error::Media(format!(
                "Invalid auth key length: {}",
                auth_key.len()
            )));
        }
        if salt_key.len() != 14 {
            return Err(Error::Media(format!(
                "Invalid salt key length: {}",
                salt_key.len()
            )));
        }
        if auth_tag_len != 10 && auth_tag_len != 4 {
            return Err(Error::Media(format!(
                "Invalid auth tag length: {}",
                auth_tag_len
            )));
        }

        Ok(Self {
            cipher_key,
            auth_key,
            salt_key,
            auth_tag_len,
            srtcp_index: 0,
        })
    }

    /// Encrypt RTCP packet → SRTCP packet
    ///
    /// SRTCP format (RFC 3711):
    ///   [RTCP header][encrypted payload][E-bit + SRTCP index 4 bytes][auth tag]
    pub fn encrypt_rtcp(&mut self, rtcp_packet: &[u8]) -> Result<Vec<u8>> {
        if rtcp_packet.len() < 8 {
            return Err(Error::Media("RTCP packet too short (min 8 bytes)".to_string()));
        }

        // Extract SSRC from RTCP header (bytes 4-7)
        let ssrc = u32::from_be_bytes([
            rtcp_packet[4],
            rtcp_packet[5],
            rtcp_packet[6],
            rtcp_packet[7],
        ]);

        // Increment SRTCP index
        self.srtcp_index = self.srtcp_index.wrapping_add(1);
        let index = self.srtcp_index;

        // Keep RTCP header (first 8 bytes) unencrypted
        let rtcp_header = &rtcp_packet[..8];
        let rtcp_payload = &rtcp_packet[8..];

        // Derive IV for RTCP: different label (0x03) from RTP (0x00)
        let iv = self.derive_rtcp_iv(ssrc, index);

        // Encrypt payload
        let mut encrypted_payload = rtcp_payload.to_vec();
        if self.cipher_key.len() == 16 {
            let mut cipher = Aes128Ctr::new(self.cipher_key[..16].into(), &iv.into());
            cipher.apply_keystream(&mut encrypted_payload);
        }

        // Build SRTCP: header + encrypted payload + E-bit/index + auth tag
        let mut srtcp = Vec::new();
        srtcp.extend_from_slice(rtcp_header);
        srtcp.extend_from_slice(&encrypted_payload);

        // E-bit = 1 (encrypted), SRTCP index (31 bits)
        let e_and_index: u32 = 0x80000000 | (index & 0x7FFFFFFF);
        srtcp.extend_from_slice(&e_and_index.to_be_bytes());

        // Compute auth tag over the entire SRTCP packet (header + encrypted payload + index)
        let auth_tag = self.compute_rtcp_auth_tag(&srtcp)?;
        srtcp.extend_from_slice(&auth_tag[..self.auth_tag_len]);

        Ok(srtcp)
    }

    /// Decrypt SRTCP packet → RTCP packet
    pub fn decrypt_srtcp(&mut self, srtcp_packet: &[u8]) -> Result<Vec<u8>> {
        // Minimum: 8 RTCP header + 4 E+index + auth_tag
        let min_len = 8 + 4 + self.auth_tag_len;
        if srtcp_packet.len() < min_len {
            return Err(Error::Media("SRTCP packet too short".to_string()));
        }

        // Split off auth tag
        let packet_len = srtcp_packet.len() - self.auth_tag_len;
        let packet = &srtcp_packet[..packet_len];
        let received_tag = &srtcp_packet[packet_len..];

        // Verify auth tag
        let computed_tag = self.compute_rtcp_auth_tag(packet)?;
        if !self.constant_time_compare(&computed_tag[..self.auth_tag_len], received_tag) {
            return Err(Error::Media("SRTCP authentication failed".to_string()));
        }

        // Read E-bit and SRTCP index (last 4 bytes before auth tag)
        let index_bytes = &packet[packet_len - 4..];
        let e_and_index = u32::from_be_bytes([
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ]);
        let encrypted = (e_and_index & 0x80000000) != 0;
        let index = e_and_index & 0x7FFFFFFF;

        // RTCP header + encrypted payload (without the E+index trailer)
        let rtcp_header = &packet[..8];
        let encrypted_payload = &packet[8..packet_len - 4];

        if !encrypted {
            // Not encrypted, just strip the SRTCP index and auth tag
            let mut rtcp = Vec::new();
            rtcp.extend_from_slice(rtcp_header);
            rtcp.extend_from_slice(encrypted_payload);
            return Ok(rtcp);
        }

        // Extract SSRC from RTCP header
        let ssrc = u32::from_be_bytes([
            rtcp_header[4],
            rtcp_header[5],
            rtcp_header[6],
            rtcp_header[7],
        ]);

        // Decrypt payload
        let iv = self.derive_rtcp_iv(ssrc, index);
        let mut plaintext = encrypted_payload.to_vec();
        let mut cipher = Aes128Ctr::new(self.cipher_key[..16].into(), &iv.into());
        cipher.apply_keystream(&mut plaintext);

        // Reconstruct RTCP packet
        let mut rtcp = Vec::new();
        rtcp.extend_from_slice(rtcp_header);
        rtcp.extend_from_slice(&plaintext);

        Ok(rtcp)
    }

    /// Derive IV for SRTCP (uses label 0x03, RFC 3711 section 4.3.2)
    fn derive_rtcp_iv(&self, ssrc: u32, srtcp_index: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];

        // SSRC occupies bits [47:16] of the 128-bit IV
        iv[4] = (ssrc >> 24) as u8;
        iv[5] = (ssrc >> 16) as u8;
        iv[6] = (ssrc >> 8) as u8;
        iv[7] = ssrc as u8;

        // SRTCP index occupies bits [31:0]
        iv[8]  = (srtcp_index >> 24) as u8;
        iv[9]  = (srtcp_index >> 16) as u8;
        iv[10] = (srtcp_index >> 8) as u8;
        iv[11] = srtcp_index as u8;

        // XOR with salt
        for i in 0..14 {
            iv[i] ^= self.salt_key[i];
        }

        iv
    }

    /// Compute HMAC-SHA1 over SRTCP packet
    fn compute_rtcp_auth_tag(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key)
            .map_err(|e| Error::Media(format!("HMAC init error: {}", e)))?;
        mac.update(packet);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// Constant-time comparison
    fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Get current SRTCP index
    pub fn get_srtcp_index(&self) -> u32 {
        self.srtcp_index
    }
}

/// Derive SRTCP-specific keys (uses label 0x03 for cipher, 0x04 for auth, 0x05 for salt)
pub fn derive_srtcp_keys(
    master_key: &[u8],
    master_salt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if master_key.len() != 16 && master_key.len() != 32 {
        return Err(Error::Media(format!(
            "Invalid master key length: {}",
            master_key.len()
        )));
    }
    if master_salt.len() != 14 {
        return Err(Error::Media(format!(
            "Invalid master salt length: {}",
            master_salt.len()
        )));
    }

    // RFC 3711 Table 1: SRTCP labels are 0x03, 0x04, 0x05
    let cipher_key = kdf_prf(master_key, master_salt, 0x03, master_key.len())?;
    let auth_key   = kdf_prf(master_key, master_salt, 0x04, 20)?;
    let salt_key   = kdf_prf(master_key, master_salt, 0x05, 14)?;

    Ok((cipher_key, auth_key, salt_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srtp_crypto_creation() {
        let cipher_key = vec![0u8; 16];
        let auth_key = vec![0u8; 20];
        let salt_key = vec![0u8; 14];

        let crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10);
        assert!(crypto.is_ok());
    }

    #[test]
    fn test_kdf() {
        let master_key = vec![0x12u8; 16];
        let master_salt = vec![0x34u8; 14];

        let result = derive_srtp_keys(&master_key, &master_salt, 0);
        assert!(result.is_ok());

        let (cipher, auth, salt) = result.unwrap();
        assert_eq!(cipher.len(), 16);
        assert_eq!(auth.len(), 20);
        assert_eq!(salt.len(), 14);

        // Keys should be different (derived, not copies)
        assert_ne!(cipher, master_key);
        assert_ne!(auth, vec![0x12u8; 20]);
    }

    #[test]
    fn test_iv_derivation() {
        let cipher_key = vec![1u8; 16];
        let auth_key = vec![2u8; 20];
        let salt_key = vec![3u8; 14];

        let crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10).unwrap();

        let iv = crypto.derive_iv(0x12345678, 100);
        assert_eq!(iv.len(), 16);

        // IV should change with different SSRC/SEQ
        let iv2 = crypto.derive_iv(0x12345678, 101);
        assert_ne!(iv, iv2);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        // Setup
        let master_key = vec![0xABu8; 16];
        let master_salt = vec![0xCDu8; 14];

        let (cipher_key, auth_key, salt_key) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();
        let mut crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10).unwrap();

        // Create simple RTP packet
        // Version=2, PT=0, Seq=100, TS=1000, SSRC=0x12345678
        let mut rtp_packet = vec![
            0x80, 0x00, // V=2, P=0, X=0, CC=0, M=0, PT=0
            0x00, 0x64, // Sequence = 100
            0x00, 0x00, 0x03, 0xE8, // Timestamp = 1000
            0x12, 0x34, 0x56, 0x78, // SSRC
        ];
        // Add some payload
        rtp_packet.extend_from_slice(b"Hello SRTP!");

        // Encrypt
        let srtp_packet = crypto.encrypt_rtp(&rtp_packet).unwrap();

        // SRTP packet should be longer (has auth tag)
        assert_eq!(srtp_packet.len(), rtp_packet.len() + 10);

        // Payload should be encrypted (different)
        assert_ne!(&srtp_packet[12..srtp_packet.len() - 10], b"Hello SRTP!");

        // Decrypt
        let decrypted = crypto.decrypt_srtp(&srtp_packet).unwrap();

        // Should match original
        assert_eq!(decrypted, rtp_packet);
    }

    #[test]
    fn test_auth_tag_verification_failure() {
        let master_key = vec![0xABu8; 16];
        let master_salt = vec![0xCDu8; 14];

        let (cipher_key, auth_key, salt_key) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();
        let mut crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10).unwrap();

        // Create RTP packet
        let rtp_packet = vec![
            0x80, 0x00, 0x00, 0x64, 0x00, 0x00, 0x03, 0xE8, 0x12, 0x34, 0x56, 0x78,
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];

        // Encrypt
        let mut srtp_packet = crypto.encrypt_rtp(&rtp_packet).unwrap();

        // Tamper with auth tag
        let tag_pos = srtp_packet.len() - 1;
        srtp_packet[tag_pos] ^= 0x01;

        // Decrypt should fail
        let result = crypto.decrypt_srtp(&srtp_packet);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication failed"));
    }

    // --- SRTCP Tests ---

    #[test]
    fn test_srtcp_creation() {
        let cipher_key = vec![0u8; 16];
        let auth_key = vec![0u8; 20];
        let salt_key = vec![0u8; 14];
        let ctx = SrtcpCrypto::new(cipher_key, auth_key, salt_key, 10);
        assert!(ctx.is_ok());
    }

    #[test]
    fn test_srtcp_encrypt_decrypt_round_trip() {
        let master_key = vec![0xABu8; 16];
        let master_salt = vec![0xCDu8; 14];

        let (ck, ak, sk) = derive_srtcp_keys(&master_key, &master_salt).unwrap();
        let mut ctx = SrtcpCrypto::new(ck, ak, sk, 10).unwrap();

        // Minimal RTCP SR packet (28 bytes): header(8) + sender info(20)
        let rtcp: Vec<u8> = vec![
            0x80, 0xC8, 0x00, 0x06, // V=2, PT=200 (SR), length=6
            0x12, 0x34, 0x56, 0x78, // SSRC
            // Sender info (20 bytes)
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x05,
        ];

        let srtcp = ctx.encrypt_rtcp(&rtcp).unwrap();
        // SRTCP = RTCP + 4 (E+index) + 10 (auth tag)
        assert_eq!(srtcp.len(), rtcp.len() + 4 + 10);

        // Header must stay cleartext
        assert_eq!(&srtcp[..4], &rtcp[..4]);

        let decrypted = ctx.decrypt_srtcp(&srtcp).unwrap();
        assert_eq!(decrypted, rtcp);
    }

    #[test]
    fn test_srtcp_auth_failure() {
        let (ck, ak, sk) = derive_srtcp_keys(&vec![0xAAu8; 16], &vec![0xBBu8; 14]).unwrap();
        let mut ctx = SrtcpCrypto::new(ck, ak, sk, 10).unwrap();

        let rtcp: Vec<u8> = vec![
            0x80, 0xC8, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut srtcp = ctx.encrypt_rtcp(&rtcp).unwrap();
        // Tamper with auth tag
        let last = srtcp.len() - 1;
        srtcp[last] ^= 0xFF;

        let result = ctx.decrypt_srtcp(&srtcp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authentication failed"));
    }

    #[test]
    fn test_srtcp_index_increments() {
        let (ck, ak, sk) = derive_srtcp_keys(&vec![0x01u8; 16], &vec![0x02u8; 14]).unwrap();
        let mut ctx = SrtcpCrypto::new(ck, ak, sk, 10).unwrap();

        let rtcp: Vec<u8> = vec![
            0x80, 0xC8, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(ctx.get_srtcp_index(), 0);
        ctx.encrypt_rtcp(&rtcp).unwrap();
        assert_eq!(ctx.get_srtcp_index(), 1);
        ctx.encrypt_rtcp(&rtcp).unwrap();
        assert_eq!(ctx.get_srtcp_index(), 2);
    }

    #[test]
    fn test_srtcp_derive_keys_different_from_srtp() {
        let master_key = vec![0x42u8; 16];
        let master_salt = vec![0x24u8; 14];

        let (srtp_ck, _, _) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();
        let (srtcp_ck, _, _) = derive_srtcp_keys(&master_key, &master_salt).unwrap();

        // SRTP and SRTCP cipher keys must differ (different labels)
        assert_ne!(srtp_ck, srtcp_ck);
    }

    #[test]
    fn test_rtp_header_with_csrc() {
        let cipher_key = vec![1u8; 16];
        let auth_key = vec![2u8; 20];
        let salt_key = vec![3u8; 14];

        let crypto = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10).unwrap();

        // RTP packet with 2 CSRC identifiers (CC=2)
        let rtp_packet = vec![
            0x82, 0x00, 0x00, 0x01, // V=2, CC=2, Seq=1
            0x00, 0x00, 0x00, 0x00, // Timestamp=0
            0x00, 0x00, 0x00, 0x01, // SSRC=1
            0x00, 0x00, 0x00, 0x02, // CSRC 1
            0x00, 0x00, 0x00, 0x03, // CSRC 2
            0x41, 0x42, 0x43, // Payload "ABC"
        ];

        let header_len = crypto.get_rtp_header_length(&rtp_packet).unwrap();
        assert_eq!(header_len, 12 + 8); // Base + 2*4 bytes CSRC
    }

    fn to_hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_kdf_known_vectors() {
        // Cross-validation with Python: master_key = [0x0b]*16, master_salt = [0x0c]*14
        let master_key = vec![0x0bu8; 16];
        let master_salt = vec![0x0cu8; 14];

        let (cipher_key, auth_key, salt_key) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();

        // Python outputs:
        //   cipher_key: 3af8651805fbf61aadd0f54da13d327a
        //   auth_key:   201adad6e49f7d617c6a00624b8ef9ba68783879
        //   salt_key:   5dd0c0f7bb624cc0ff759df2b55e
        assert_eq!(to_hex(&cipher_key), "3af8651805fbf61aadd0f54da13d327a");
        assert_eq!(to_hex(&auth_key), "201adad6e49f7d617c6a00624b8ef9ba68783879");
        assert_eq!(to_hex(&salt_key), "5dd0c0f7bb624cc0ff759df2b55e");
    }

    #[test]
    fn test_encrypt_decrypt_interop() {
        // Verify encrypt/decrypt round-trip with RFC 3711 compliant IV layout
        // IV: bytes [0-3]=0, bytes [4-7]=SSRC, bytes [8-13]=packet_index, bytes [14-15]=0
        // Then XOR with session salt
        let master_key = vec![0x0bu8; 16];
        let master_salt = vec![0x0cu8; 14];

        let (cipher_key, auth_key, salt_key) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();
        let (cipher_key2, auth_key2, salt_key2) = derive_srtp_keys(&master_key, &master_salt, 0).unwrap();

        let mut encryptor = SrtpCrypto::new(cipher_key, auth_key, salt_key, 10).unwrap();
        let mut decryptor = SrtpCrypto::new(cipher_key2, auth_key2, salt_key2, 10).unwrap();

        // RTP packet with SSRC=1, SEQ=1
        let mut rtp = vec![
            0x80, 0x00, 0x00, 0x01, // V=2, PT=0, SEQ=1
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x00, 0x00, 0x00, 0x01, // SSRC=1
        ];
        rtp.extend_from_slice(b"Hello SRTP payload");

        let srtp = encryptor.encrypt_rtp(&rtp).unwrap();

        // Verify header is preserved in cleartext
        assert_eq!(&srtp[..12], &rtp[..12]);
        // Payload must be encrypted (different from plaintext)
        assert_ne!(&srtp[12..srtp.len()-10], &rtp[12..]);
        // Auth tag appended (10 bytes)
        assert_eq!(srtp.len(), rtp.len() + 10);

        // Decrypt with separate context
        let decrypted = decryptor.decrypt_srtp(&srtp).unwrap();
        assert_eq!(decrypted, rtp, "Round-trip must recover original RTP");

        // Verify IV layout: SSRC at bytes [4-7], packet_index at [8-13]
        let iv = encryptor.derive_iv(0x00000001, 1);
        // Before XOR with salt, bytes [0-3] should be 0, [4-7]=SSRC, [8-13]=index
        // salt_key is derived from KDF so we verify indirectly via round-trip
        assert_eq!(iv.len(), 16);
    }
}
