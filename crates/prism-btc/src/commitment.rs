//! Cost-model commitment surface — re-exports of foundation's canonical
//! typed-commitment + observable-predicate primitives (wiki ADR-048 +
//! ADR-049, foundation 0.5.2) plus prism-btc-side helpers that lift
//! application-level constructs (the K-bit payload encoding, the
//! runtime Bitcoin target) into commitment shapes the foundation
//! `run_route` catamorphism evaluates.
//!
//! ## What lives here
//!
//! - Re-exports of the foundation cost-model surface that prism-btc
//!   apps consume: [`TypedCommitment`] (sealed trait), the three
//!   composition shapes ([`EmptyCommitment`], [`SingletonCommitment`],
//!   [`AndCommitment`]), and the five canonical
//!   [`ObservablePredicate`] impls ([`Stratum`], [`WalshHadamardParity`],
//!   [`UltrametricCloseTo`], [`AffineParity`], [`LexicographicLessEqThreshold`]).
//! - [`TargetCommitment`] — the foundation alias
//!   `SingletonCommitment<LexicographicLessEqThreshold>` realizing
//!   Bitcoin's `digest ≤ target` admission relation per ADR-040.
//! - [`leak_target`] / [`leak_reference`] / [`leak_frequency`] — helpers
//!   that promote runtime-derived 32-byte buffers (the per-block
//!   mining target, ultrametric reference points, parity frequencies)
//!   to `&'static [u8]` so the foundation predicates can carry them.
//!   Each helper leaks once per unique value; the `'static`-pinned
//!   bytes live for the process lifetime.
//! - [`payload_bit`] / [`payload_commitment_k2`] /
//!   [`payload_commitment_k4`] / [`payload_commitment_k8`] —
//!   const-generic builders that produce `AndCommitment` trees of
//!   `SingletonCommitment<AffineParity>` for the canonical
//!   K ∈ {1, 2, 4, 8} payload-bit conjunctions of the cost-model
//!   conformance suite (wiki QS-06 exemplar shape).
//!
//! ## Cost-model contract
//!
//! Every commitment exposed here is `Copy + Sealed` (sealed by
//! foundation per ADR-048), monomorphized per use site, and evaluated
//! inside the catamorphism via [`prism::pipeline::run_route`] — the
//! catamorphism consults `commitment.evaluate(kappa_label)` before
//! sealing the [`prism::seal::Grounded`] output. The Lean theorem
//! [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
//! applies at equality: expected template variations to land an
//! admitting κ-label equal `α⁻¹ × 2^bandwidth` where
//! `bandwidth = C::bandwidth_bits()` (wiki QS-06, ADR-047 U6).

extern crate alloc;

// ─── Foundation-published cost-model surface (re-exports) ───────────────

/// The sealed cost-model commitment trait (wiki ADR-048).
///
/// Foundation declares the trait, three composition impls
/// ([`EmptyCommitment`], [`SingletonCommitment`], [`AndCommitment`]),
/// and the canonical [`TargetCommitment`] alias. Applications compose
/// from this closed set — the seal prevents author-side `impl`s, so
/// every commitment shape an application can construct has a Lean
/// `Commitment.prf_prob_tight_wellFormed`-style theorem applying at
/// equality.
pub use prism::pipeline::TypedCommitment;

/// The five canonical observable-predicate impls (wiki ADR-049).
pub use prism::pipeline::{
    AffineParity, LexicographicLessEqThreshold, ObservablePredicate, Stratum, UltrametricCloseTo,
    WalshHadamardParity,
};

/// The three commitment-shape impls (wiki ADR-048).
pub use prism::pipeline::{AndCommitment, EmptyCommitment, SingletonCommitment};

/// Bitcoin's canonical search-cost commitment: `digest ≤ target` under
/// big-endian unsigned comparison (wiki ADR-040 +ADR-048). Foundation
/// alias for `SingletonCommitment<LexicographicLessEqThreshold>`.
pub use prism::pipeline::TargetCommitment;

// ─── Runtime → 'static byte-buffer helpers ──────────────────────────────

/// The κ-label form of a 32-byte Bitcoin target: `sha256d:<64hex>` — the
/// 72-byte ASCII threshold the commitment compares ψ₉'s κ-label output
/// against.
///
/// Because the σ-axis emits the digest in **display order** and both the
/// κ-label and this threshold are the same 72-byte ASCII width with the
/// same `sha256d:` prefix, the big-endian unsigned comparison
/// `LexicographicLessEqThreshold` performs reduces exactly to
/// `block_hash ≤ target` (equal-length lowercase-hex lexicographic order
/// is numeric order). `target` is in display order (big-endian), as
/// produced by [`crate::domain::Target::to_bytes`].
#[must_use]
pub fn target_label_bytes(target: [u8; 32]) -> [u8; 72] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 72];
    out[..7].copy_from_slice(b"sha256d");
    out[7] = b':';
    for (i, &byte) in target.iter().enumerate() {
        out[8 + 2 * i] = HEX[(byte >> 4) as usize];
        out[8 + 2 * i + 1] = HEX[(byte & 0x0F) as usize];
    }
    out
}

/// Promote a 32-byte mining target to the `&'static [u8]` κ-label-form
/// threshold the model's commitment names. Foundation's
/// [`LexicographicLessEqThreshold::target`] requires `&'static [u8]`
/// because the predicate is `Copy` and lives in the macro-emitted
/// `commitment()` body; the bytes must outlive every `run_route`
/// invocation that names this commitment.
///
/// Each unique target is leaked at most once per process. Bitcoin's
/// difficulty retarget every 2016 blocks bounds the leak rate to `O(1)`
/// per chain epoch. The implementation deduplicates against a global
/// registry so repeat calls with the same bytes return the same reference.
#[must_use]
pub fn leak_target(target: [u8; 32]) -> &'static [u8] {
    leak_bytes(&target_label_bytes(target))
}

/// Promote an ultrametric reference digest to `&'static [u8]`.
/// Deduplicates against the shared registry.
#[must_use]
pub fn leak_reference(bytes: [u8; 32]) -> &'static [u8] {
    leak_bytes(&bytes)
}

/// Promote a Walsh–Hadamard frequency mask to `&'static [u8]`.
/// Deduplicates against the shared registry.
#[must_use]
pub fn leak_frequency(bytes: [u8; 32]) -> &'static [u8] {
    leak_bytes(&bytes)
}

/// Promote an arbitrary byte sequence to a process-lifetime `&'static
/// [u8]`, deduplicating against a shared registry.
#[cfg(feature = "std")]
#[must_use]
pub fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    use std::sync::Mutex;
    use std::sync::OnceLock;

    static REGISTRY: OnceLock<
        Mutex<alloc::collections::BTreeMap<alloc::vec::Vec<u8>, &'static [u8]>>,
    > = OnceLock::new();

    let map = REGISTRY.get_or_init(|| Mutex::new(alloc::collections::BTreeMap::new()));
    let mut guard = map.lock().expect("byte-leak registry poisoned");
    if let Some(&pinned) = guard.get(bytes) {
        return pinned;
    }
    let boxed: alloc::boxed::Box<[u8]> = alloc::boxed::Box::from(bytes);
    let pinned: &'static [u8] = alloc::boxed::Box::leak(boxed);
    guard.insert(bytes.to_vec(), pinned);
    pinned
}

#[cfg(not(feature = "std"))]
#[must_use]
pub fn leak_bytes(_bytes: &[u8]) -> &'static [u8] {
    // The `&'static` registry pattern needs interior mutability behind a
    // Mutex; under `no_std` we cannot offer that without pulling in `spin`
    // or similar. Applications targeting `no_std` must supply their own
    // `&'static` byte sources (compile-time constants).
    panic!("leak_bytes is only available with the `std` feature; use a compile-time constant target in no_std builds");
}

// ─── Helpers for constructing common payload-commitment shapes ─────────
//
// Every helper returns a *concrete* `AndCommitment<…>` tree of
// `SingletonCommitment<AffineParity>` leaves — composing K bits into K
// disjoint single-bit predicates per wiki QS-06's K-fold exemplar.
// The return type is fully named (no `impl Trait`) so callers can
// thread the commitment into a `PrismModel<…, C>` declaration whose
// `C` slot pins the exact shape.

/// Single-bit payload commitment at bit index `bit_index`. Used as the
/// K=1 building block for higher-K conjunctions.
#[must_use]
pub fn payload_bit(bit_index: u32, expected: bool) -> SingletonCommitment<AffineParity> {
    SingletonCommitment {
        predicate: AffineParity {
            bit_index,
            expected,
        },
    }
}

/// Two-bit payload commitment: conjunction of two single-bit predicates
/// at bit indices `[0, 1]`.
pub type PayloadK2 =
    AndCommitment<SingletonCommitment<AffineParity>, SingletonCommitment<AffineParity>>;

/// Four-bit payload commitment: left-associative conjunction of four
/// single-bit predicates at bit indices `[0, 1, 2, 3]`.
pub type PayloadK4 = AndCommitment<
    AndCommitment<PayloadK2, SingletonCommitment<AffineParity>>,
    SingletonCommitment<AffineParity>,
>;

/// Eight-bit payload commitment: left-associative conjunction of eight
/// single-bit predicates at bit indices `[0..8)`.
pub type PayloadK8 = AndCommitment<
    AndCommitment<
        AndCommitment<PayloadK4, SingletonCommitment<AffineParity>>,
        SingletonCommitment<AffineParity>,
    >,
    AndCommitment<SingletonCommitment<AffineParity>, SingletonCommitment<AffineParity>>,
>;

/// Build a [`PayloadK2`] from two payload bits.
#[must_use]
pub fn payload_commitment_k2(bits: [bool; 2]) -> PayloadK2 {
    AndCommitment {
        left: payload_bit(0, bits[0]),
        right: payload_bit(1, bits[1]),
    }
}

/// Build a [`PayloadK4`] from four payload bits.
#[must_use]
pub fn payload_commitment_k4(bits: [bool; 4]) -> PayloadK4 {
    AndCommitment {
        left: AndCommitment {
            left: payload_commitment_k2([bits[0], bits[1]]),
            right: payload_bit(2, bits[2]),
        },
        right: payload_bit(3, bits[3]),
    }
}

/// Build a [`PayloadK8`] from eight payload bits.
#[must_use]
pub fn payload_commitment_k8(bits: [bool; 8]) -> PayloadK8 {
    let lower = payload_commitment_k4([bits[0], bits[1], bits[2], bits[3]]);
    AndCommitment {
        left: AndCommitment {
            left: AndCommitment {
                left: lower,
                right: payload_bit(4, bits[4]),
            },
            right: payload_bit(5, bits[5]),
        },
        right: AndCommitment {
            left: payload_bit(6, bits[6]),
            right: payload_bit(7, bits[7]),
        },
    }
}

// ─── Decode helpers — the receiver-side of the typed payload channel ────

/// Decode a K-bit payload from a κ-label digest, reading bit positions
/// `[0..K)` per foundation's [`AffineParity`] convention
/// (`byte_idx = bit_index / 8`, `bit_off = bit_index % 8`).
#[must_use]
pub fn decode_payload<const K: usize>(digest: &[u8]) -> [bool; K] {
    let mut out = [false; K];
    let mut i = 0;
    while i < K {
        out[i] = prism::uor_foundation::pipeline::single_bit_value(digest, i as u32);
        i += 1;
    }
    out
}

/// Convenience: build a [`TargetCommitment`] from raw target bytes
/// already promoted to `&'static [u8]`. Equivalent to `SingletonCommitment
/// { predicate: LexicographicLessEqThreshold { target } }`.
#[must_use]
pub fn target_commitment(target: &'static [u8]) -> TargetCommitment {
    SingletonCommitment {
        predicate: LexicographicLessEqThreshold { target },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_commitment_admits_threshold_neighborhood() {
        // The commitment compares ψ₉'s κ-label output against the
        // κ-label-form threshold; equal-length lowercase-hex lexicographic
        // order is numeric order, so target `0xff..ff` admits every block.
        let target = leak_target([0xff; 32]);
        let cmt = target_commitment(target);
        let low = target_label_bytes([0x00; 32]); // sha256d:0000…00
        let high = target_label_bytes([0xff; 32]); // sha256d:ffff…ff
        assert!(cmt.evaluate(&low));
        assert!(cmt.evaluate(&high));
        assert_eq!(cmt.predicate_count(), 1);
    }

    #[test]
    fn target_commitment_rejects_block_above_threshold() {
        // Threshold admits only block hashes ≤ 0x0fff…ff (leading nibble 0).
        let target = leak_target({
            let mut t = [0xffu8; 32];
            t[0] = 0x0f;
            t
        });
        let cmt = target_commitment(target);
        // A block hash with a high byte of 0x10 exceeds the threshold.
        let above = target_label_bytes({
            let mut h = [0x00u8; 32];
            h[0] = 0x10;
            h
        });
        assert!(!cmt.evaluate(&above));
        // A block hash with leading zero byte is admitted.
        let below = target_label_bytes([0x00; 32]);
        assert!(cmt.evaluate(&below));
    }

    #[test]
    fn payload_k2_round_trip() {
        let cmt = payload_commitment_k2([true, false]);
        // Construct a digest where bit 0 = 1, bit 1 = 0: byte 0 = 0b...01.
        let mut digest = [0u8; 32];
        digest[0] = 0b0000_0001;
        assert!(cmt.evaluate(&digest));
        let decoded: [bool; 2] = decode_payload(&digest);
        assert_eq!(decoded, [true, false]);
    }

    #[test]
    fn payload_k4_round_trip() {
        let bits = [true, false, true, true];
        let cmt = payload_commitment_k4(bits);
        let mut digest = [0u8; 32];
        digest[0] = 0b0000_1101; // bits 0,2,3 set; bit 1 clear
        assert!(cmt.evaluate(&digest));
        let decoded: [bool; 4] = decode_payload(&digest);
        assert_eq!(decoded, bits);
    }

    #[test]
    fn payload_k8_bandwidth_is_eight_bits() {
        let cmt = payload_commitment_k8([false; 8]);
        assert!((cmt.bandwidth_bits() - 8.0).abs() < 1e-9);
        assert_eq!(cmt.predicate_count(), 8);
    }

    #[test]
    fn and_commitment_composes_two_thresholds() {
        // ADR-047 U6 bandwidth-additivity: `block_hash ≤ t1 AND ≤ t2`.
        // Both predicates see the κ-label byte sequence ψ₉ emits.
        let t1 = leak_target([0xff; 32]);
        let t2 = leak_target({
            let mut t = [0xffu8; 32];
            t[0] = 0x7f;
            t
        });
        let composed = AndCommitment {
            left: target_commitment(t1),
            right: target_commitment(t2),
        };
        // Block hash 0x00..00 ≤ both thresholds.
        assert!(composed.evaluate(&target_label_bytes([0x00; 32])));
        // Block hash 0x80..00 ≤ t1 but > t2 ⇒ rejected by the conjunction.
        let mut h = [0x00u8; 32];
        h[0] = 0x80;
        assert!(!composed.evaluate(&target_label_bytes(h)));
    }

    #[test]
    fn leak_target_deduplicates_repeat_calls() {
        let a = leak_target([0xaa; 32]);
        let b = leak_target([0xaa; 32]);
        // Same bytes leak to the same registry slot.
        assert_eq!(a.as_ptr(), b.as_ptr());
        let c = leak_target([0xbb; 32]);
        assert_ne!(a.as_ptr(), c.as_ptr());
    }
}
