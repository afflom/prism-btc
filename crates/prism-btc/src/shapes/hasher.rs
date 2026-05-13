//! `Sha256dHasher` — prism-btc's foundation `Hasher` implementation.
//!
//! ADR-010 defines the `Hasher` substitution-axis contract:
//! determinism, fixed output width, distinct identifier, idempotence
//! under truncation. The trait permits arbitrary Rust in the body —
//! foundation does not mandate that the body be a `PrimitiveOp`
//! composition. prism-btc, as the prism implementor, provides the body
//! as pure-Rust SHA-256d (see [`mod@crate::ops::sha256`] for the one-shot
//! algorithm; this hasher streams bytes through it).
//!
//! Used by foundation's pipeline at certificate-emission time to
//! compute the `ContentFingerprint` over the canonical CompileUnit
//! byte layout.

use uor_foundation::enforcement::Hasher;

use crate::ops::sha256::{sha256, SHA256_INITIAL_STATE};

/// Streaming SHA-256d. Maintains the inner-pass SHA-256 state online;
/// the outer pass is one-shot at finalize.
///
/// Heap-free: bookkeeping fits in a fixed-size struct (state + 64-byte
/// partial-block buffer + counters).
#[derive(Debug, Clone)]
pub struct Sha256dHasher {
    /// Running SHA-256 state of the *inner* pass.
    state: [u32; 8],
    /// Bytes accumulated since the last block compression.
    partial: [u8; 64],
    /// Active byte count in `partial` (always < 64).
    partial_len: u8,
    /// Total bytes folded so far (used in the FIPS-180-4 length pad).
    total_bytes: u64,
}

impl Sha256dHasher {
    fn compress_block(&mut self, block: &[u8; 64]) {
        // Reuses the same compression machinery as one-shot sha256.
        crate::ops::sha256::compress(&mut self.state, block);
    }
}

impl Hasher for Sha256dHasher {
    const OUTPUT_BYTES: usize = 32;

    fn initial() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            partial: [0u8; 64],
            partial_len: 0,
            total_bytes: 0,
        }
    }

    fn fold_byte(mut self, byte: u8) -> Self {
        self.partial[self.partial_len as usize] = byte;
        self.partial_len += 1;
        self.total_bytes = self.total_bytes.wrapping_add(1);
        if self.partial_len == 64 {
            let block = self.partial;
            self.compress_block(&block);
            self.partial_len = 0;
        }
        self
    }

    fn fold_bytes(mut self, bytes: &[u8]) -> Self {
        // Fast path: copy whole 64-byte chunks once the partial is empty.
        let mut i = 0;
        while i < bytes.len() {
            let need = 64 - self.partial_len as usize;
            let take = core::cmp::min(need, bytes.len() - i);
            self.partial[self.partial_len as usize..self.partial_len as usize + take]
                .copy_from_slice(&bytes[i..i + take]);
            self.partial_len += take as u8;
            self.total_bytes = self.total_bytes.wrapping_add(take as u64);
            i += take;
            if self.partial_len == 64 {
                let block = self.partial;
                self.compress_block(&block);
                self.partial_len = 0;
            }
        }
        self
    }

    fn finalize(mut self) -> [u8; 32] {
        // Inner-pass finalisation: pad with 0x80, zero-pad to 56 mod 64,
        // append big-endian 64-bit total bit length.
        let bit_len = self.total_bytes.wrapping_mul(8);
        // 0x80 sentinel.
        self.partial[self.partial_len as usize] = 0x80;
        self.partial_len += 1;
        // Pad zeroes; possibly need a second block.
        if self.partial_len > 56 {
            // Fill out current block, compress, then start a fresh padding block.
            for i in self.partial_len as usize..64 {
                self.partial[i] = 0;
            }
            let block = self.partial;
            self.compress_block(&block);
            self.partial = [0u8; 64];
            self.partial_len = 0;
        } else {
            for i in self.partial_len as usize..56 {
                self.partial[i] = 0;
            }
        }
        self.partial[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.partial;
        self.compress_block(&block);

        // Inner SHA-256 result.
        let mut inner = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            inner[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }

        // Outer pass: one-shot SHA-256 over the 32-byte inner result.
        // Internal byte order — the foundation's fingerprint slot is
        // opaque bytes; display-order reversal is a Bitcoin-protocol
        // concern, not a foundation concern.
        sha256(&inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_hasher_empty() {
        let out = Sha256dHasher::initial().finalize();
        // SHA-256d("") internal = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let expected: [u8; 32] = [
            0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
            0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
            0x5d, 0x4c, 0x94, 0x56,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn sha256d_hasher_streaming_equals_one_shot() {
        let bytes = b"prism-btc test vector for streaming";
        let one_shot = Sha256dHasher::initial().fold_bytes(bytes).finalize();
        let mut streaming = Sha256dHasher::initial();
        for &b in bytes.iter() {
            streaming = streaming.fold_byte(b);
        }
        assert_eq!(one_shot, streaming.finalize());
    }

    #[test]
    fn sha256d_hasher_against_oneshot_helper() {
        // The hasher must agree with the one-shot helper for the same input.
        use crate::ops::sha256::sha256d_internal;
        let bytes = b"abc";
        let from_hasher = Sha256dHasher::initial().fold_bytes(bytes).finalize();
        let from_one_shot = sha256d_internal(bytes);
        assert_eq!(from_hasher, from_one_shot);
    }
}
