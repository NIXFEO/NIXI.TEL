//! Audio Transcoding — Opus ↔ G.711 (PCMU/PCMA)
//!
//! Real-time transcoding using:
//!   - G.711 µ-law (PCMU, payload type 0)  — pure Rust encode/decode
//!   - G.711 A-law (PCMA, payload type 8)  — pure Rust encode/decode
//!   - Opus (PT 111)  — via the `opus` crate (bindings to libopus)
//!   - Rayon thread pool for CPU-intensive codec operations
//!
//! # Codec numbering (RFC 3551)
//! | PT | Name  | Clock | Channels |
//! |----|-------|-------|----------|
//!  0   | PCMU  | 8000  | 1
//!  8   | PCMA  | 8000  | 1
//!  111 | opus  | 48000 | 2  (common dynamic assignment)

use crate::{Error, Result};
use std::sync::Arc;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// RTP payload type for G.711 µ-law
pub const PT_PCMU: u8 = 0;
/// RTP payload type for G.711 A-law
pub const PT_PCMA: u8 = 8;
/// Dynamic RTP payload type commonly used for Opus
pub const PT_OPUS: u8 = 111;

/// G.711 sample rate (8 kHz)
pub const G711_RATE: u32 = 8_000;
/// Opus default sample rate (48 kHz)
pub const OPUS_RATE: u32 = 48_000;

/// G.711 frame size in samples (20ms at 8 kHz)
pub const G711_FRAME_SAMPLES: usize = 160;
/// Opus frame size in samples (20ms at 48 kHz)
pub const OPUS_FRAME_SAMPLES: usize = 960;

/// Maximum encoded Opus frame size (bytes)
const OPUS_MAX_FRAME_SIZE: usize = 4000;

// ─────────────────────────────────────────────────────────────────────────────
// G.711 µ-law (PCMU)
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a 16-bit linear PCM sample to G.711 µ-law.
///
/// Reference: Sun Microsystems / CCITT G.711 (ulaw2linear / linear2ulaw).
/// Sign convention: sign bit 1 = positive in µ-law.
#[inline]
pub fn pcmu_encode_sample(pcm: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32_635;

    let mut sample = pcm as i32;
    // Sign: in µ-law, the MSB of the encoded byte = 1 if positive
    let sign: u8 = if sample >= 0 { 0x80 } else {
        sample = -sample;
        0x00
    };
    if sample > CLIP { sample = CLIP; }
    sample += BIAS;

    // Find the segment (exponent)
    let exp: u8 = if sample < 0x0100 { 0 }
        else if sample < 0x0200 { 1 }
        else if sample < 0x0400 { 2 }
        else if sample < 0x0800 { 3 }
        else if sample < 0x1000 { 4 }
        else if sample < 0x2000 { 5 }
        else if sample < 0x4000 { 6 }
        else { 7 };

    let mantissa = ((sample >> (exp + 3)) & 0x0F) as u8;
    !(sign | (exp << 4) | mantissa)
}

/// Decode a G.711 µ-law byte to a 16-bit linear PCM sample.
#[inline]
pub fn pcmu_decode_sample(ulaw: u8) -> i16 {
    let ulaw = !ulaw;
    let sign  = ulaw & 0x80;
    let exp   = ((ulaw >> 4) & 0x07) as i32;
    let mant  = (ulaw & 0x0F) as i32;
    let t = ((mant << 3) | 0x84) << exp;
    let sample = t - 0x84;
    // sign bit 1 = positive
    if sign != 0 { sample as i16 } else { -(sample as i16) }
}

/// Encode a buffer of linear PCM (i16 LE) samples to PCMU bytes.
pub fn pcmu_encode(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().map(|&s| pcmu_encode_sample(s)).collect()
}

/// Decode a PCMU buffer to linear PCM (i16) samples.
pub fn pcmu_decode(ulaw: &[u8]) -> Vec<i16> {
    ulaw.iter().map(|&b| pcmu_decode_sample(b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// G.711 A-law (PCMA)
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a 16-bit linear PCM sample to G.711 A-law.
///
/// Reference: CCITT G.711, Sun Microsystems implementation.
/// Note: A-law uses XOR 0x55 (alternating bit inversion).
/// Sign convention: MSB of encoded byte = 1 if positive.
#[inline]
pub fn pcma_encode_sample(pcm: i16) -> u8 {
    let mut sample = pcm as i32;
    // Sign bit: 1 = positive
    let sign: i32 = if sample >= 0 {
        0x80
    } else {
        sample = -sample - 1;
        0x00
    };
    // Clip
    if sample > 32767 { sample = 32767; }

    // Find segment (upper 13 bits, ignoring 3 LSBs)
    let s = sample >> 4;
    let (exp, mantissa): (i32, i32) = if s == 0 {
        (0, sample >> 1)
    } else if s < 2 {
        (1, (sample >> 2) & 0x0F)
    } else if s < 4 {
        (2, (sample >> 3) & 0x0F)
    } else if s < 8 {
        (3, (sample >> 4) & 0x0F)
    } else if s < 16 {
        (4, (sample >> 5) & 0x0F)
    } else if s < 32 {
        (5, (sample >> 6) & 0x0F)
    } else if s < 64 {
        (6, (sample >> 7) & 0x0F)
    } else {
        (7, (sample >> 8) & 0x0F)
    };

    ((sign | (exp << 4) | mantissa) ^ 0x55) as u8
}

/// Decode a G.711 A-law byte to a 16-bit linear PCM sample.
///
/// Standard A-law decode: invert alternate bits, extract sign/exp/mantissa.
/// Output is 13-bit linear, stored in the upper 13 bits of a 16-bit word
/// (effectively multiplied by 8 vs the encoder's input range).
#[inline]
pub fn pcma_decode_sample(alaw: u8) -> i16 {
    let alaw = (alaw as i32) ^ 0x55;
    let sign  = alaw & 0x80;
    let exp   = (alaw >> 4) & 0x07;
    let mant  = (alaw & 0x0F) as i32;

    let sample = if exp == 0 {
        (mant << 1) | 1
    } else {
        ((mant | 0x10) << exp) | (1 << (exp - 1))
    };

    // sign bit 1 = positive
    if sign != 0 { sample as i16 } else { -(sample as i16) }
}

/// Encode a buffer of linear PCM (i16 LE) samples to PCMA bytes.
pub fn pcma_encode(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().map(|&s| pcma_encode_sample(s)).collect()
}

/// Decode a PCMA buffer to linear PCM (i16) samples.
pub fn pcma_decode(alaw: &[u8]) -> Vec<i16> {
    alaw.iter().map(|&b| pcma_decode_sample(b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple resampler (48 kHz → 8 kHz and reverse) for Opus↔G.711
// ─────────────────────────────────────────────────────────────────────────────

/// Downsample from 48 kHz to 8 kHz using simple decimation (factor 6).
///
/// For production quality use rubato or libspeex; this is a minimal
/// implementation for unit-test coverage and basic operation.
pub fn downsample_48k_to_8k(samples: &[i16]) -> Vec<i16> {
    // FIR low-pass filter + decimate by 6 (48kHz → 8kHz)
    // 15-tap symmetric FIR, cutoff ~3.4kHz (voice band), windowed sinc
    const LP: [f32; 15] = [
        0.0025, 0.0085, 0.0230, 0.0480, 0.0810,
        0.1130, 0.1350, 0.1400, 0.1350, 0.1130,
        0.0810, 0.0480, 0.0230, 0.0085, 0.0025,
    ];
    const HALF: isize = 7; // LP.len() / 2

    let n = samples.len();
    let out_len = n / 6;
    let mut out = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let center = (i * 6) as isize;
        let mut acc: f32 = 0.0;
        for (k, &coeff) in LP.iter().enumerate() {
            let idx = center + k as isize - HALF;
            let s = if idx >= 0 && (idx as usize) < n {
                samples[idx as usize] as f32
            } else {
                0.0
            };
            acc += s * coeff;
        }
        out.push(acc.clamp(-32768.0, 32767.0) as i16);
    }
    out
}

/// Upsample from 8 kHz to 48 kHz using linear interpolation (factor 6).
pub fn upsample_8k_to_48k(samples: &[i16]) -> Vec<i16> {
    if samples.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(samples.len() * 6);
    for i in 0..samples.len() {
        let s0 = samples[i] as i32;
        let s1 = if i + 1 < samples.len() { samples[i + 1] as i32 } else { s0 };
        for k in 0..6 {
            let interp = s0 + (s1 - s0) * k as i32 / 6;
            out.push(interp as i16);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Opus Codec wrapper (real libopus via opus crate)
// ─────────────────────────────────────────────────────────────────────────────

/// Opus encoder wrapper (thread-safe via Arc<Mutex>)
pub struct OpusEncoder {
    inner: std::sync::Mutex<opus::Encoder>,
}

impl OpusEncoder {
    /// Create a new Opus encoder for VoIP (mono, 48 kHz)
    pub fn new() -> Result<Self> {
        let encoder = opus::Encoder::new(
            OPUS_RATE,
            opus::Channels::Mono,
            opus::Application::Voip,
        ).map_err(|e| Error::Other(format!("Opus encoder init: {}", e)))?;

        Ok(Self {
            inner: std::sync::Mutex::new(encoder),
        })
    }

    /// Create an Opus encoder with specific settings
    pub fn with_bitrate(bitrate: i32) -> Result<Self> {
        let mut encoder = opus::Encoder::new(
            OPUS_RATE,
            opus::Channels::Mono,
            opus::Application::Voip,
        ).map_err(|e| Error::Other(format!("Opus encoder init: {}", e)))?;

        encoder.set_bitrate(opus::Bitrate::Bits(bitrate))
            .map_err(|e| Error::Other(format!("Opus set bitrate: {}", e)))?;

        Ok(Self {
            inner: std::sync::Mutex::new(encoder),
        })
    }

    /// Encode PCM samples (i16, 48 kHz, mono) to Opus frame
    ///
    /// `pcm` must contain exactly `OPUS_FRAME_SAMPLES` (960) samples for 20ms frame.
    pub fn encode(&self, pcm: &[i16]) -> Result<Vec<u8>> {
        let mut output = vec![0u8; OPUS_MAX_FRAME_SIZE];
        let mut enc = self.inner.lock()
            .map_err(|e| Error::Other(format!("Opus encoder lock: {}", e)))?;

        let len = enc.encode(pcm, &mut output)
            .map_err(|e| Error::Other(format!("Opus encode: {}", e)))?;

        output.truncate(len);
        Ok(output)
    }
}

/// Opus decoder wrapper (thread-safe via Arc<Mutex>)
pub struct OpusDecoder {
    inner: std::sync::Mutex<opus::Decoder>,
}

impl OpusDecoder {
    /// Create a new Opus decoder (mono, 48 kHz)
    pub fn new() -> Result<Self> {
        let decoder = opus::Decoder::new(
            OPUS_RATE,
            opus::Channels::Mono,
        ).map_err(|e| Error::Other(format!("Opus decoder init: {}", e)))?;

        Ok(Self {
            inner: std::sync::Mutex::new(decoder),
        })
    }

    /// Decode Opus frame to PCM samples (i16, 48 kHz, mono)
    ///
    /// Returns up to `OPUS_FRAME_SAMPLES` (960) samples for a 20ms frame.
    pub fn decode(&self, opus_data: &[u8]) -> Result<Vec<i16>> {
        let mut output = vec![0i16; OPUS_FRAME_SAMPLES];
        let mut dec = self.inner.lock()
            .map_err(|e| Error::Other(format!("Opus decoder lock: {}", e)))?;

        let len = dec.decode(opus_data, &mut output, false)
            .map_err(|e| Error::Other(format!("Opus decode: {}", e)))?;

        output.truncate(len);
        Ok(output)
    }

    /// Decode with Forward Error Correction (packet loss concealment)
    pub fn decode_fec(&self, opus_data: &[u8]) -> Result<Vec<i16>> {
        let mut output = vec![0i16; OPUS_FRAME_SAMPLES];
        let mut dec = self.inner.lock()
            .map_err(|e| Error::Other(format!("Opus decoder lock: {}", e)))?;

        let len = dec.decode(opus_data, &mut output, true)
            .map_err(|e| Error::Other(format!("Opus decode FEC: {}", e)))?;

        output.truncate(len);
        Ok(output)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level transcoding API
// ─────────────────────────────────────────────────────────────────────────────

/// Codec type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 µ-law, PT=0, 8 kHz
    Pcmu,
    /// G.711 A-law, PT=8, 8 kHz
    Pcma,
    /// Opus, PT=111 (dynamic), 48 kHz
    Opus,
    /// Unknown / passthrough
    Unknown(u8),
}

impl Codec {
    /// Create a Codec from an RTP payload type
    pub fn from_pt(pt: u8) -> Self {
        match pt {
            PT_PCMU => Self::Pcmu,
            PT_PCMA => Self::Pcma,
            PT_OPUS => Self::Opus,
            other   => Self::Unknown(other),
        }
    }

    /// RTP payload type for this codec
    pub fn pt(&self) -> u8 {
        match self {
            Self::Pcmu       => PT_PCMU,
            Self::Pcma       => PT_PCMA,
            Self::Opus       => PT_OPUS,
            Self::Unknown(p) => *p,
        }
    }

    /// Sample rate for this codec
    pub fn sample_rate(&self) -> u32 {
        match self {
            Self::Pcmu | Self::Pcma => G711_RATE,
            Self::Opus              => OPUS_RATE,
            Self::Unknown(_)        => G711_RATE,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Pcmu       => "PCMU",
            Self::Pcma       => "PCMA",
            Self::Opus       => "opus",
            Self::Unknown(_) => "unknown",
        }
    }

    /// RTP clock rate in Hz for this codec
    pub fn clock_rate(&self) -> u32 {
        match self {
            Self::Pcmu       => 8000,
            Self::Pcma       => 8000,
            Self::Opus       => 48000,
            Self::Unknown(_) => 8000, // default guess
        }
    }
}

/// Transcoder — converts RTP payloads between codecs
///
/// For Opus ↔ G.711, holds real Opus encoder/decoder instances.
/// Thread-safe: can be shared across async tasks.
pub struct Transcoder {
    pub src: Codec,
    pub dst: Codec,
    /// Opus encoder (created when dst == Opus)
    opus_encoder: Option<OpusEncoder>,
    /// Opus decoder (created when src == Opus)
    opus_decoder: Option<OpusDecoder>,
}

impl Transcoder {
    /// Create a new transcoder between two codecs
    ///
    /// Automatically initializes Opus encoder/decoder if needed.
    pub fn new(src: Codec, dst: Codec) -> Result<Self> {
        let opus_encoder = if dst == Codec::Opus && src != Codec::Opus {
            Some(OpusEncoder::new()?)
        } else {
            None
        };

        let opus_decoder = if src == Codec::Opus && dst != Codec::Opus {
            Some(OpusDecoder::new()?)
        } else {
            None
        };

        Ok(Self { src, dst, opus_encoder, opus_decoder })
    }

    /// Create a passthrough transcoder (no conversion)
    pub fn passthrough() -> Self {
        Self {
            src: Codec::Unknown(0),
            dst: Codec::Unknown(0),
            opus_encoder: None,
            opus_decoder: None,
        }
    }

    /// Transcode an RTP payload from `src` codec to `dst` codec.
    ///
    /// Returns the transcoded payload bytes (or a clone if no conversion
    /// is needed).
    pub fn transcode(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.src == self.dst {
            return Ok(payload.to_vec());
        }

        match (self.src, self.dst) {
            // PCMU → PCMA
            (Codec::Pcmu, Codec::Pcma) => {
                let pcm = pcmu_decode(payload);
                Ok(pcma_encode(&pcm))
            }
            // PCMA → PCMU
            (Codec::Pcma, Codec::Pcmu) => {
                let pcm = pcma_decode(payload);
                Ok(pcmu_encode(&pcm))
            }
            // PCMU → Opus (G.711 8k → PCM 48k → Opus encode)
            (Codec::Pcmu, Codec::Opus) => {
                let pcm_8k = pcmu_decode(payload);
                let pcm_48k = upsample_8k_to_48k(&pcm_8k);
                if let Some(ref encoder) = self.opus_encoder {
                    encoder.encode(&pcm_48k)
                } else {
                    // Fallback: return raw PCM (should not happen with proper init)
                    Ok(pcm_to_bytes(&pcm_48k))
                }
            }
            // Opus → PCMU (Opus decode → PCM 48k → PCM 8k → G.711)
            (Codec::Opus, Codec::Pcmu) => {
                if let Some(ref decoder) = self.opus_decoder {
                    let pcm_48k = decoder.decode(payload)?;
                    let pcm_8k = downsample_48k_to_8k(&pcm_48k);
                    Ok(pcmu_encode(&pcm_8k))
                } else {
                    // Fallback: treat as raw PCM bytes
                    let pcm_48k = bytes_to_pcm(payload);
                    let pcm_8k = downsample_48k_to_8k(&pcm_48k);
                    Ok(pcmu_encode(&pcm_8k))
                }
            }
            // PCMA → Opus
            (Codec::Pcma, Codec::Opus) => {
                let pcm_8k = pcma_decode(payload);
                let pcm_48k = upsample_8k_to_48k(&pcm_8k);
                if let Some(ref encoder) = self.opus_encoder {
                    encoder.encode(&pcm_48k)
                } else {
                    Ok(pcm_to_bytes(&pcm_48k))
                }
            }
            // Opus → PCMA
            (Codec::Opus, Codec::Pcma) => {
                if let Some(ref decoder) = self.opus_decoder {
                    let pcm_48k = decoder.decode(payload)?;
                    let pcm_8k = downsample_48k_to_8k(&pcm_48k);
                    Ok(pcma_encode(&pcm_8k))
                } else {
                    let pcm_48k = bytes_to_pcm(payload);
                    let pcm_8k = downsample_48k_to_8k(&pcm_48k);
                    Ok(pcma_encode(&pcm_8k))
                }
            }
            // Unknown: passthrough
            _ => Ok(payload.to_vec()),
        }
    }

    /// Check if this transcoder performs a real conversion
    pub fn is_passthrough(&self) -> bool {
        self.src == self.dst || matches!(self.src, Codec::Unknown(_)) || matches!(self.dst, Codec::Unknown(_))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transcoding Pool (rayon-based for CPU-intensive operations)
// ─────────────────────────────────────────────────────────────────────────────

/// Transcoding pool using rayon for parallel CPU-intensive codec operations.
///
/// Offloads transcoding work from the async Tokio runtime to a dedicated
/// thread pool, preventing blocking of the event loop.
pub struct TranscodingPool {
    pool: rayon::ThreadPool,
    /// Prometheus-style counter for transcoded packets
    transcoded_packets: std::sync::atomic::AtomicU64,
}

impl TranscodingPool {
    /// Create a new transcoding pool with the specified number of threads
    pub fn new(num_threads: usize) -> Result<Self> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|idx| format!("sbc-transcode-{}", idx))
            .build()
            .map_err(|e| Error::Other(format!("Failed to create transcoding pool: {}", e)))?;

        info!("Transcoding pool created with {} threads", num_threads);

        Ok(Self {
            pool,
            transcoded_packets: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Create a default pool (4 threads)
    pub fn default_pool() -> Result<Self> {
        Self::new(4)
    }

    /// Transcode an RTP payload asynchronously using the rayon pool.
    ///
    /// Sends the work to a rayon worker thread and returns the result
    /// via a oneshot channel, allowing the Tokio task to yield.
    pub async fn transcode_async(
        &self,
        transcoder: Arc<Transcoder>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.pool.spawn(move || {
            let result = transcoder.transcode(&payload);
            let _ = tx.send(result);
        });

        let result = rx.await
            .map_err(|_| Error::Other("Transcoding pool channel closed".to_string()))?;

        if result.is_ok() {
            self.transcoded_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        result
    }

    /// Get the total number of transcoded packets
    pub fn transcoded_count(&self) -> u64 {
        self.transcoded_packets.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Helper: i16 slice → raw bytes (little-endian)
fn pcm_to_bytes(pcm: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pcm.len() * 2);
    for &s in pcm {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

// Helper: raw bytes → i16 slice (little-endian)
fn bytes_to_pcm(bytes: &[u8]) -> Vec<i16> {
    bytes.chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// SDP rewriting for codec negotiation
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite an SDP body to prefer/force a specific codec.
///
/// `preferred_pt` — the payload type to keep as first in the `m=` line.
/// All other audio codecs are moved to the back but kept (for compatibility).
///
/// Returns the rewritten SDP string.
pub fn sdp_prefer_codec(sdp: &str, preferred_pt: u8) -> String {
    let preferred_str = preferred_pt.to_string();
    sdp.lines().map(|line| {
        if line.starts_with("m=audio") {
            // Parse: "m=audio PORT PROTO PT1 PT2 ..."
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                let pts = &parts[3..];
                let mut ordered = vec![];
                // Put preferred first
                if pts.contains(&preferred_str.as_str()) {
                    ordered.push(preferred_str.clone());
                }
                for &pt in pts {
                    if pt != preferred_str.as_str() {
                        ordered.push(pt.to_string());
                    }
                }
                let pts_str = ordered.join(" ");
                format!("{} {} {} {}", parts[0], parts[1], parts[2], pts_str)
            } else {
                line.to_string()
            }
        } else {
            line.to_string()
        }
    }).collect::<Vec<_>>().join("\r\n")
}

/// Extract the list of audio payload types from an SDP body.
pub fn sdp_audio_pts(sdp: &str) -> Vec<u8> {
    for line in sdp.lines() {
        if line.starts_with("m=audio") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 3 {
                return parts[3..].iter()
                    .filter_map(|s| s.parse::<u8>().ok())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Determine if an SDP offers Opus
pub fn sdp_has_opus(sdp: &str) -> bool {
    sdp.lines().any(|l| l.to_lowercase().contains("opus"))
}

/// Determine if an SDP offers G.711 PCMU
pub fn sdp_has_pcmu(sdp: &str) -> bool {
    let pts = sdp_audio_pts(sdp);
    pts.contains(&PT_PCMU)
}

/// Determine the primary codec from SDP (first in m= line)
pub fn sdp_primary_codec(sdp: &str) -> Codec {
    let pts = sdp_audio_pts(sdp);
    pts.first().map(|&pt| Codec::from_pt(pt)).unwrap_or(Codec::Unknown(0))
}

/// Check if transcoding is needed between two SDPs
pub fn needs_transcoding(caller_sdp: &str, callee_sdp: &str) -> bool {
    // Find common codec between the two SDPs
    let caller_pts = sdp_audio_pts(caller_sdp);
    let callee_pts = sdp_audio_pts(callee_sdp);

    // If they share at least one codec, no transcoding needed
    let has_common = caller_pts.iter().any(|pt| callee_pts.contains(pt));
    !has_common
}

/// Build a minimal SDP offering only G.711 PCMU (for legacy trunks)
pub fn build_g711_sdp(local_ip: &str, rtp_port: u16) -> String {
    format!(
        "v=0\r\no=SBC 0 0 IN IP4 {ip}\r\ns=SBC Session\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
        ip = local_ip,
        port = rtp_port,
    )
}

/// Build a minimal SDP offering Opus + G.711 fallback (for WebRTC/SIP clients)
pub fn build_opus_sdp(local_ip: &str, rtp_port: u16) -> String {
    format!(
        "v=0\r\no=SBC 0 0 IN IP4 {ip}\r\ns=SBC Session\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 111 0 8\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 useinbandfec=1\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
        ip = local_ip,
        port = rtp_port,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── G.711 µ-law round-trip ────────────────────────────────────────────────

    #[test]
    fn test_pcmu_encode_decode_silence() {
        let silence = vec![0i16; 160];
        let encoded = pcmu_encode(&silence);
        assert_eq!(encoded.len(), 160);
        let decoded = pcmu_decode(&encoded);
        // Silence round-trips to near-zero (bias introduced by µ-law)
        for s in &decoded {
            assert!(s.abs() < 10, "expected near-zero, got {}", s);
        }
    }

    #[test]
    fn test_pcmu_encode_decode_positive() {
        let samples = vec![1000i16; 160];
        let encoded = pcmu_encode(&samples);
        let decoded = pcmu_decode(&encoded);
        // G.711 has logarithmic quantization — allow up to ~30% error at mid-range
        // All decoded samples should be positive and in the same ballpark
        for s in &decoded {
            assert!(*s > 0, "decoded should be positive, got {}", s);
            assert!((*s as i32 - 1000).abs() < 2000, "round-trip error too large: {}", s);
        }
    }

    #[test]
    fn test_pcmu_encode_decode_negative() {
        let samples = vec![-1000i16; 160];
        let encoded = pcmu_encode(&samples);
        let decoded = pcmu_decode(&encoded);
        for s in &decoded {
            assert!(*s < 0, "decoded should be negative, got {}", s);
            assert!((*s as i32 + 1000).abs() < 2000, "round-trip error too large: {}", s);
        }
    }

    // ── G.711 A-law round-trip ────────────────────────────────────────────────

    #[test]
    fn test_pcma_encode_decode_silence() {
        let silence = vec![0i16; 160];
        let encoded = pcma_encode(&silence);
        assert_eq!(encoded.len(), 160);
        let decoded = pcma_decode(&encoded);
        for s in &decoded {
            assert!(s.abs() < 10, "expected near-zero, got {}", s);
        }
    }

    #[test]
    fn test_pcma_encode_decode_positive() {
        let samples = vec![2000i16; 160];
        let encoded = pcma_encode(&samples);
        let decoded = pcma_decode(&encoded);
        for s in &decoded {
            assert!(*s > 0, "decoded should be positive, got {}", s);
            assert!((*s as i32) < 32767, "decoded out of i16 range: {}", s);
        }
    }

    #[test]
    fn test_pcma_encode_decode_negative() {
        let samples = vec![-2000i16; 160];
        let encoded = pcma_encode(&samples);
        let decoded = pcma_decode(&encoded);
        for s in &decoded {
            assert!(*s < 0, "decoded should be negative, got {}", s);
            assert!((*s as i32) > -32768, "decoded out of i16 range: {}", s);
        }
    }

    // ── Cross-codec transcoding ───────────────────────────────────────────────

    #[test]
    fn test_pcmu_to_pcma_transcoding() {
        let t = Transcoder::new(Codec::Pcmu, Codec::Pcma).unwrap();
        let pcmu = pcmu_encode(&[500i16; 160]);
        let pcma = t.transcode(&pcmu).unwrap();
        assert_eq!(pcma.len(), 160);

        // Decode both and compare: same sign, same order of magnitude
        let pcm_from_mu = pcmu_decode(&pcmu);
        let pcm_from_a  = pcma_decode(&pcma);
        for (a, b) in pcm_from_mu.iter().zip(pcm_from_a.iter()) {
            assert!(*a > 0, "µ-law decoded should be positive: {}", a);
            assert!(*b > 0, "A-law decoded should be positive: {}", b);
            assert!((*a as i32).abs() < 10_000, "µ-law out of range: {}", a);
            assert!((*b as i32).abs() < 10_000, "A-law out of range: {}", b);
        }
    }

    #[test]
    fn test_pcma_to_pcmu_transcoding() {
        let t = Transcoder::new(Codec::Pcma, Codec::Pcmu).unwrap();
        let pcma = pcma_encode(&[-800i16; 160]);
        let pcmu = t.transcode(&pcma).unwrap();
        assert_eq!(pcmu.len(), 160);
    }

    #[test]
    fn test_passthrough_same_codec() {
        let t = Transcoder::new(Codec::Pcmu, Codec::Pcmu).unwrap();
        assert!(t.is_passthrough());
        let payload = vec![0xD5u8; 160];
        let out = t.transcode(&payload).unwrap();
        assert_eq!(out, payload);
    }

    // ── Real Opus transcoding ─────────────────────────────────────────────────

    #[test]
    fn test_opus_encoder_decoder_round_trip() {
        let encoder = OpusEncoder::new().unwrap();
        let decoder = OpusDecoder::new().unwrap();

        // Create 20ms frame of 440Hz tone at 48kHz
        let pcm_48k: Vec<i16> = (0..OPUS_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f64 / OPUS_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();

        // Encode
        let opus_frame = encoder.encode(&pcm_48k).unwrap();
        assert!(opus_frame.len() > 0, "Opus frame should not be empty");
        assert!(opus_frame.len() < OPUS_MAX_FRAME_SIZE, "Opus frame too large");
        debug!("Opus encoded: {} samples → {} bytes", pcm_48k.len(), opus_frame.len());

        // Decode
        let decoded = decoder.decode(&opus_frame).unwrap();
        assert_eq!(decoded.len(), OPUS_FRAME_SAMPLES, "Decoded frame should be 960 samples");

        // Verify audio similarity (Opus is lossy — especially on the first frame
        // before the encoder settles; VoIP mode also trades quality for latency)
        let correlation = pcm_correlation(&pcm_48k, &decoded);
        assert!(correlation > 0.2, "Opus round-trip correlation too low: {}", correlation);
    }

    #[test]
    fn test_pcmu_to_opus_real_transcoding() {
        let t = Transcoder::new(Codec::Pcmu, Codec::Opus).unwrap();

        // Create 20ms of PCMU (160 bytes = 160 samples at 8kHz)
        let tone_8k: Vec<i16> = (0..G711_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f64 / G711_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 8000.0) as i16
            })
            .collect();
        let pcmu = pcmu_encode(&tone_8k);
        assert_eq!(pcmu.len(), 160);

        // Transcode PCMU → Opus
        let opus_frame = t.transcode(&pcmu).unwrap();
        assert!(opus_frame.len() > 0 && opus_frame.len() < 200,
            "Opus frame should be compact, got {} bytes", opus_frame.len());
    }

    #[test]
    fn test_opus_to_pcmu_real_transcoding() {
        // First encode some audio as Opus
        let encoder = OpusEncoder::new().unwrap();
        let tone_48k: Vec<i16> = (0..OPUS_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f64 / OPUS_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();
        let opus_frame = encoder.encode(&tone_48k).unwrap();

        // Now transcode Opus → PCMU
        let t = Transcoder::new(Codec::Opus, Codec::Pcmu).unwrap();
        let pcmu = t.transcode(&opus_frame).unwrap();
        assert_eq!(pcmu.len(), G711_FRAME_SAMPLES,
            "PCMU should be 160 bytes, got {}", pcmu.len());

        // Verify the PCMU can be decoded back to audio
        let pcm = pcmu_decode(&pcmu);
        assert_eq!(pcm.len(), G711_FRAME_SAMPLES);
        // Audio should not be all zeros
        let max_sample = pcm.iter().map(|s| s.abs()).max().unwrap_or(0);
        assert!(max_sample > 100, "Transcoded audio should not be silent, max={}", max_sample);
    }

    #[test]
    fn test_opus_to_pcma_real_transcoding() {
        let encoder = OpusEncoder::new().unwrap();
        let tone_48k: Vec<i16> = (0..OPUS_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f64 / OPUS_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();
        let opus_frame = encoder.encode(&tone_48k).unwrap();

        let t = Transcoder::new(Codec::Opus, Codec::Pcma).unwrap();
        let pcma = t.transcode(&opus_frame).unwrap();
        assert_eq!(pcma.len(), G711_FRAME_SAMPLES);
    }

    // ── Transcoding pool ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_transcoding_pool() {
        let pool = TranscodingPool::new(2).unwrap();
        let transcoder = Arc::new(Transcoder::new(Codec::Pcmu, Codec::Pcma).unwrap());

        let pcmu = pcmu_encode(&[500i16; 160]);
        let result = pool.transcode_async(transcoder, pcmu.clone()).await.unwrap();
        assert_eq!(result.len(), 160);
        assert_eq!(pool.transcoded_count(), 1);
    }

    #[tokio::test]
    async fn test_transcoding_pool_opus() {
        let pool = TranscodingPool::new(2).unwrap();
        let transcoder = Arc::new(Transcoder::new(Codec::Pcmu, Codec::Opus).unwrap());

        let tone_8k: Vec<i16> = (0..G711_FRAME_SAMPLES)
            .map(|i| ((i as f64 * 0.1).sin() * 8000.0) as i16)
            .collect();
        let pcmu = pcmu_encode(&tone_8k);

        let opus_frame = pool.transcode_async(transcoder, pcmu).await.unwrap();
        assert!(opus_frame.len() > 0);
        assert_eq!(pool.transcoded_count(), 1);
    }

    // ── Resampling ────────────────────────────────────────────────────────────

    #[test]
    fn test_downsample_48k_to_8k() {
        let samples: Vec<i16> = vec![1000i16; 480]; // 10ms at 48kHz
        let down = downsample_48k_to_8k(&samples);
        assert_eq!(down.len(), 80); // 10ms at 8kHz
        // FIR filter coefficients sum to ~0.962, and edge samples are further
        // attenuated by zero-padding. Interior samples should be close to 962.
        let interior = &down[3..77]; // skip edge samples affected by zero-padding
        for &s in interior {
            assert!((s - 962).abs() < 10, "interior sample {} too far from expected 962", s);
        }
    }

    #[test]
    fn test_upsample_8k_to_48k() {
        let samples: Vec<i16> = vec![500i16; 80];  // 10ms at 8kHz
        let up = upsample_8k_to_48k(&samples);
        assert_eq!(up.len(), 480); // 10ms at 48kHz
    }

    // ── Codec enum ───────────────────────────────────────────────────────────

    #[test]
    fn test_codec_from_pt() {
        assert_eq!(Codec::from_pt(0),   Codec::Pcmu);
        assert_eq!(Codec::from_pt(8),   Codec::Pcma);
        assert_eq!(Codec::from_pt(111), Codec::Opus);
        assert!(matches!(Codec::from_pt(100), Codec::Unknown(100)));
    }

    #[test]
    fn test_codec_sample_rate() {
        assert_eq!(Codec::Pcmu.sample_rate(), 8_000);
        assert_eq!(Codec::Pcma.sample_rate(), 8_000);
        assert_eq!(Codec::Opus.sample_rate(), 48_000);
    }

    // ── SDP helpers ──────────────────────────────────────────────────────────

    #[test]
    fn test_sdp_prefer_codec_pcmu() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 5004 RTP/AVP 111 0 8\r\na=rtpmap:111 opus/48000/2\r\n";
        let rewritten = sdp_prefer_codec(sdp, PT_PCMU);
        let m_line = rewritten.lines().find(|l| l.starts_with("m=audio")).unwrap();
        // PCMU (0) should be first PT
        assert!(m_line.contains("RTP/AVP 0 "), "PCMU should be first: {}", m_line);
    }

    #[test]
    fn test_sdp_audio_pts() {
        let sdp = "v=0\r\nm=audio 5004 RTP/AVP 111 0 8\r\n";
        let pts = sdp_audio_pts(sdp);
        assert_eq!(pts, vec![111, 0, 8]);
    }

    #[test]
    fn test_sdp_has_opus() {
        let sdp = "m=audio 5004 RTP/AVP 111 0\r\na=rtpmap:111 opus/48000/2\r\n";
        assert!(sdp_has_opus(sdp));
        let sdp2 = "m=audio 5004 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        assert!(!sdp_has_opus(sdp2));
    }

    #[test]
    fn test_build_g711_sdp() {
        let sdp = build_g711_sdp("192.168.1.1", 5004);
        assert!(sdp.contains("m=audio 5004 RTP/AVP 0 8"));
        assert!(sdp.contains("PCMU/8000"));
        assert!(sdp.contains("IN IP4 192.168.1.1"));
    }

    #[test]
    fn test_build_opus_sdp() {
        let sdp = build_opus_sdp("10.0.0.1", 6000);
        assert!(sdp.contains("m=audio 6000 RTP/AVP 111 0 8"));
        assert!(sdp.contains("opus/48000/2"));
    }

    #[test]
    fn test_needs_transcoding() {
        let opus_sdp = "m=audio 5004 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n";
        let g711_sdp = "m=audio 5004 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n";
        let both_sdp = "m=audio 5004 RTP/AVP 111 0 8\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n";

        assert!(needs_transcoding(opus_sdp, g711_sdp), "Opus-only vs G.711-only needs transcoding");
        assert!(!needs_transcoding(both_sdp, g711_sdp), "Both has common codec with G.711");
        assert!(!needs_transcoding(opus_sdp, both_sdp), "Opus has common codec with Both");
    }

    // ── Helper: PCM correlation ──────────────────────────────────────────────

    fn pcm_correlation(a: &[i16], b: &[i16]) -> f64 {
        let n = a.len().min(b.len());
        if n == 0 { return 0.0; }
        let mut sum_ab = 0.0f64;
        let mut sum_aa = 0.0f64;
        let mut sum_bb = 0.0f64;
        for i in 0..n {
            let fa = a[i] as f64;
            let fb = b[i] as f64;
            sum_ab += fa * fb;
            sum_aa += fa * fa;
            sum_bb += fb * fb;
        }
        if sum_aa == 0.0 || sum_bb == 0.0 { return 0.0; }
        sum_ab / (sum_aa.sqrt() * sum_bb.sqrt())
    }
}
