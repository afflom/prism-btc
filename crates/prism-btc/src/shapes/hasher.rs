//! `Sha256dHasher` — prism-btc's σ-axis: Bitcoin's double-SHA-256, as a
//! foundation [`Hasher`] (ADR-007/ADR-010) **and** a uor-addr
//! [`AddrHash`](uor_addr::AddrHash) σ-axis.
//!
//! UOR-ADDR ships a pluggable σ-axis family (`sha256` / `blake3` /
//! `sha3-256` / `keccak256` / `sha512`), but Bitcoin's content address is
//! the *double* SHA-256 of the 80-byte header. prism-btc therefore
//! supplies its own σ-axis — `sha256d` — implementing both contracts:
//!
//! - [`Hasher`]`<32>` — the foundation σ-projection the catamorphism folds
//!   the carrier through to compute the content fingerprint. The blanket
//!   `impl<H: Hasher> AxisTuple for H` makes this the model's single
//!   hash axis (kernel 0).
//! - [`AddrHash`](uor_addr::AddrHash) — lets the **shared**
//!   [`AddressResolverTuple`](uor_addr::AddressResolverTuple) ψ-tower carry
//!   this axis: ψ₉ calls [`AddrHash::digest_carrier`] and formats the
//!   `sha256d:<64hex>` κ-label.
//!
//! ## Display-order finalize (Bitcoin PoW byte order)
//!
//! [`finalize`](Hasher::finalize) emits the digest in **Bitcoin display
//! order** (the conventional block-hash hex — most-significant byte
//! first), i.e. the byte-reverse of the internal SHA-256d. This is what
//! makes the cost-model commitment correct: foundation evaluates the
//! `TypedCommitment` on ψ₉'s κ-label output, and
//! [`LexicographicLessEqThreshold`](prism::pipeline::LexicographicLessEqThreshold)
//! does a big-endian unsigned compare. With display-order bytes (and the
//! target expressed in the same κ-label form), the comparison
//! `kappa_label ≤ target_label` is exactly Bitcoin's PoW relation
//! `block_hash ≤ target`. See [`crate::commitment`].

use prism::vocabulary::Hasher;
use uor_addr::hash::MAX_DIGEST_BYTES;
use uor_addr::AddrHash;

use crate::ops::sha256::{sha256, SHA256_INITIAL_STATE};

/// Streaming SHA-256d. Maintains the inner-pass SHA-256 state online; the
/// outer pass is one-shot at finalize, and the result is byte-reversed
/// into Bitcoin display order.
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
        crate::ops::sha256::compress(&mut self.state, block);
    }
}

impl Default for Sha256dHasher {
    fn default() -> Self {
        <Self as Hasher>::initial()
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
        self.partial[self.partial_len as usize] = 0x80;
        self.partial_len += 1;
        if self.partial_len > 56 {
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

        // Outer pass, then reverse into Bitcoin display order.
        let mut out = sha256(&inner);
        out.reverse();
        out
    }
}

impl AddrHash for Sha256dHasher {
    /// The κ-label algorithm token: `sha256d:<64hex>` (72 ASCII bytes).
    const LABEL_PREFIX: &'static str = "sha256d";
    const OUTPUT_BYTES: usize = 32;

    fn digest_carrier<const N: usize>(
        input: &prism::operation::TermValue<'_, N>,
    ) -> [u8; MAX_DIGEST_BYTES] {
        // Stream-fold the (possibly Borrowed/Stream) carrier through the
        // streaming σ-axis with bounded resident memory, then emit the
        // display-order digest. Mirrors uor-addr's `hash::stream` but binds
        // our double-SHA-256 axis.
        let mut h = <Sha256dHasher as Hasher>::initial();
        input.for_each_chunk(&mut |chunk| {
            // `Sha256dHasher: Default` (= `Hasher::initial`), so `take`
            // moves the running state out and leaves a fresh initial in
            // place; we fold the chunk into the moved-out state.
            let cur = core::mem::take(&mut h);
            h = cur.fold_bytes(chunk);
        });
        let digest = h.finalize();
        let mut out = [0u8; MAX_DIGEST_BYTES];
        out[..32].copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_hasher_empty_is_display_order() {
        let out = <Sha256dHasher as Hasher>::initial().finalize();
        // SHA-256d("") display order = reverse of
        // 5df6e0e2...5d4c9456 → 56944c5d...e2e0f65d.
        let expected: [u8; 32] = [
            0x56, 0x94, 0x4c, 0x5d, 0x3f, 0x98, 0x41, 0x3e, 0xf4, 0x5c, 0xf5, 0x45, 0x45, 0x53,
            0x81, 0x03, 0xcc, 0x9f, 0x29, 0x8e, 0x05, 0x75, 0x82, 0x0a, 0xd3, 0x59, 0x13, 0x76,
            0xe2, 0xe0, 0xf6, 0x5d,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn sha256d_hasher_matches_display_one_shot() {
        use crate::ops::sha256::sha256d_display;
        let bytes = b"prism-btc test vector for streaming";
        let from_hasher = <Sha256dHasher as Hasher>::initial()
            .fold_bytes(bytes)
            .finalize();
        assert_eq!(from_hasher, sha256d_display(bytes));
    }

    #[test]
    fn streaming_equals_one_shot() {
        let bytes = b"abc";
        let one_shot = <Sha256dHasher as Hasher>::initial()
            .fold_bytes(bytes)
            .finalize();
        let mut streaming = <Sha256dHasher as Hasher>::initial();
        for &b in bytes.iter() {
            streaming = streaming.fold_byte(b);
        }
        assert_eq!(one_shot, streaming.finalize());
    }
}
