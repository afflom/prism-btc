//! Generic typed-commitment surface — re-exports of foundation's
//! canonical [`TypedCommitment`] catalog (wiki ADR-048 + ADR-049,
//! foundation 0.5.2) and prism-btc's const-generic K-fold payload
//! commitment builders for the QS-06 exemplar shape.
//!
//! **No Bitcoin admission code here.** The previous design embedded
//! `digest ≤ target` into the kernel's `BitcoinAddressModel` via a
//! `TargetCommitment` alias plus a thread-local target slot and a
//! `&'static [u8]` leak registry. The kernel no longer embeds
//! admission — `BitcoinAddressModel` binds `EmptyCommitment` in the
//! 5th slot and emits κ-labels unconditionally — so the target
//! infrastructure (`TargetCommitment`, `target_label_bytes`,
//! `leak_target`, `leak_bytes`, the static-registry, the thread-local
//! slot) is gone. What remains is the **generic** typed-commitment
//! machinery, available for any host (Bitcoin or otherwise) that
//! wants to compose typed admission gates over its own κ-labels.
//!
//! ## What lives here
//!
//! - The foundation cost-model surface re-exports: [`TypedCommitment`]
//!   (sealed trait), the three composition shapes ([`EmptyCommitment`],
//!   [`SingletonCommitment`], [`AndCommitment`]), and the five canonical
//!   [`ObservablePredicate`] impls ([`Stratum`], [`WalshHadamardParity`],
//!   [`UltrametricCloseTo`], [`AffineParity`],
//!   [`LexicographicLessEqThreshold`]).
//! - [`payload_bit`] / [`payload_commitment_k2`] /
//!   [`payload_commitment_k4`] / [`payload_commitment_k8`] —
//!   const-generic builders that produce `AndCommitment` trees of
//!   `SingletonCommitment<AffineParity>` for the canonical
//!   K ∈ {1, 2, 4, 8} payload-bit conjunctions of the cost-model
//!   conformance suite (wiki QS-06 exemplar shape).
//! - [`decode_payload`] — the receiver-side inverse: read K bits at the
//!   matching canonical positions from a digest.
//!
//! ## Cost-model contract
//!
//! Every commitment exposed here is `Copy + Sealed` (sealed by
//! foundation per ADR-048). The Lean theorem
//! [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
//! applies at equality over any composed shape: expected template
//! variations to land an admitting κ-label equal
//! `α⁻¹ × 2^bandwidth_bits()`. Hosts that want PoW admission compose
//! the relevant predicates themselves and observe their digests
//! against the resulting `TypedCommitment::evaluate`.

// ─── Foundation-published cost-model surface (re-exports) ───────────────

/// The sealed cost-model commitment trait (wiki ADR-048).
///
/// Foundation declares the trait, three composition impls
/// ([`EmptyCommitment`], [`SingletonCommitment`], [`AndCommitment`]).
/// Applications compose from this closed set — the seal prevents
/// author-side `impl`s, so every commitment shape an application can
/// construct has a Lean `Commitment.prf_prob_tight_wellFormed`-style
/// theorem applying at equality.
pub use prism::pipeline::TypedCommitment;

/// The five canonical observable-predicate impls (wiki ADR-049).
pub use prism::pipeline::{
    AffineParity, LexicographicLessEqThreshold, ObservablePredicate, Stratum, UltrametricCloseTo,
    WalshHadamardParity,
};

/// The three commitment-shape impls (wiki ADR-048).
pub use prism::pipeline::{AndCommitment, EmptyCommitment, SingletonCommitment};

// ─── Helpers for constructing common payload-commitment shapes ─────────
//
// Every helper returns a *concrete* `AndCommitment<…>` tree of
// `SingletonCommitment<AffineParity>` leaves — composing K bits into K
// disjoint single-bit predicates per wiki QS-06's K-fold exemplar.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_k2_round_trip() {
        let cmt = payload_commitment_k2([true, false]);
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
        digest[0] = 0b0000_1101;
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
}
