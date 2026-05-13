//! Typed mining commitments — prism's zero-cost commitment surface.
//!
//! prism's contract is that the operational cost of a typed commitment
//! equals its declared bandwidth — at equality, not as an upper bound
//! (Lean theorem
//! [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)).
//! For that contract to be real rather than aspirational, the runtime
//! cannot decide *which* predicates to evaluate at mining time. Every
//! commitment is monomorphized to a compile-time-known typed structure
//! with zero runtime allocation, zero dynamic dispatch, and bounded
//! loops the compiler can unroll.
//!
//! This module provides:
//!
//! - [`TypedCommitment`] — the substrate-level zero-cost commitment
//!   surface. Every implementor is `wellFormed` *by construction* —
//!   the Lean theorem's hypothesis is discharged at the type level
//!   (no runtime disjointness check needed).
//! - [`EmptyCommitment`] — the no-commitment case;
//!   `mine_with(_, _, EmptyCommitment)` is equivalent to bare
//!   [`crate::mine`].
//! - [`PayloadCommitment<K>`] — K-bit application payload encoded as
//!   K parity constraints on K disjoint single-bit ω-frequencies.
//!   Pairwise-disjoint supports by construction; bandwidth = K bits.
//!
//! Applications that need other commitment shapes implement
//! [`TypedCommitment`] directly. The `wellFormed`-by-construction
//! discipline is the implementor's responsibility (typically discharged
//! via const-generic bounds or invariant fields).

use crate::pipeline::Predicate;

/// Substrate-level zero-cost commitment surface. Every implementor is
/// `wellFormed` by construction — its [`Self::accept_prob`] is the
/// **tight** PRF acceptance probability, not an upper bound.
///
/// # Zero-cost contract
///
/// Implementors must compile to: stack-allocated `Copy` types, no heap
/// allocation, no dynamic dispatch, no runtime-unknown loop bounds.
/// The monomorphized [`Self::evaluate`] at any concrete `C: TypedCommitment`
/// is the typed-iso surface's realization of prism's zero-runtime-movement
/// contract. The Lean theorem
/// [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
/// applies to each monomorphization individually.
pub trait TypedCommitment: Copy {
    /// Total bandwidth (in bits) the commitment encodes per κ-label.
    /// Equal to `−log₂(accept_prob())` by U6.
    fn bandwidth_bits(&self) -> f64;

    /// PRF acceptance probability under the random-oracle baseline.
    /// Equal to the product of per-predicate acceptances; **tight**
    /// (Lean: `prf_prob_tight_wellFormed`).
    fn accept_prob(&self) -> f64;

    /// Evaluate the commitment on a digest. Returns `true` iff every
    /// underlying predicate accepts. Monomorphized per concrete `C`.
    fn evaluate(&self, digest: &[u8; 32]) -> bool;

    /// Number of typed predicates Conjunction'd in this commitment.
    fn predicate_count(&self) -> usize;

    /// True iff the commitment imposes no constraint beyond admission
    /// (equivalent to [`EmptyCommitment`]).
    #[inline]
    fn is_empty(&self) -> bool {
        self.predicate_count() == 0
    }
}

/// The empty commitment — `mine_with(_, _, EmptyCommitment)` is
/// equivalent to bare [`crate::mine`]. Bandwidth: 0 bits. Acceptance
/// probability: 1.
///
/// Direct correspondence to the Lean `Commitment.empty` (the empty
/// list of predicates).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmptyCommitment;

impl TypedCommitment for EmptyCommitment {
    #[inline]
    fn bandwidth_bits(&self) -> f64 {
        0.0
    }

    #[inline]
    fn accept_prob(&self) -> f64 {
        1.0
    }

    #[inline]
    fn evaluate(&self, _digest: &[u8; 32]) -> bool {
        true
    }

    #[inline]
    fn predicate_count(&self) -> usize {
        0
    }
}

/// K-bit payload commitment. Encodes K application bits as K parity
/// constraints on K disjoint single-bit ω-frequencies (the digest's
/// low K bits, LSB-numbered: bit `i` = bit `i % 8` of byte `31 - i / 8`).
/// Bandwidth: K bits. Pairwise-disjoint supports by construction —
/// `wellFormed` discharged at the type level.
///
/// # Channel semantics
///
/// - Sender: calls [`Self::from_bits`] with K payload bits and invokes
///   [`crate::mine_with`] on a candidate template; the produced κ-label
///   carries the K bits in its low-bit positions.
/// - Receiver: reads the κ-label from the published block and calls
///   [`Self::decode`] to recover the K bits.
/// - Bandwidth: K bits per κ-label, by U6 Joint-Probability
///   Multiplicativity.
/// - Cost: under PRF baseline, expected `α^-1 × 2^K` template
///   variations per commit-admitting κ-label (Lean theorem
///   `prf_prob_tight_wellFormed`, at equality not as an upper bound).
///
/// # Construction
///
/// Use [`Self::from_bits`] to encode `[bool; K]` payload bits;
/// `K ≤ 256` (saturates at the digest width). The commitment is
/// `wellFormed` by construction — bit `i` reads bit `i` of the digest,
/// so the K predicates have pairwise-disjoint single-bit supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadCommitment<const K: usize> {
    expected: [u32; K],
}

impl<const K: usize> PayloadCommitment<K> {
    /// Encode `K` payload bits into the commitment. Bit `i` of the
    /// payload constrains bit `i` of the digest (LSB-numbered).
    ///
    /// # Panics
    ///
    /// Panics if `K > 256` (the digest width — saturating constructor
    /// would silently truncate the payload).
    #[inline]
    #[must_use]
    pub fn from_bits(bits: [bool; K]) -> Self {
        assert!(K <= 256, "PayloadCommitment<K>: K must be ≤ 256");
        let mut expected = [0u32; K];
        let mut i = 0;
        while i < K {
            expected[i] = bits[i] as u32;
            i += 1;
        }
        Self { expected }
    }

    /// Decode K payload bits from a digest (the receiver-side
    /// counterpart of [`Self::from_bits`]). For any digest produced
    /// by a successful `mine_with` against this commitment, the
    /// decoded bits equal the encoded bits.
    #[inline]
    #[must_use]
    pub fn decode(digest: &[u8; 32]) -> [bool; K] {
        let mut bits = [false; K];
        let mut i = 0;
        while i < K {
            bits[i] = read_digest_bit(digest, i) != 0;
            i += 1;
        }
        bits
    }

    /// The K typed predicates this commitment decomposes into. Useful
    /// for diagnostic inspection and Lean-correspondence cross-checks;
    /// the monomorphized [`Self::evaluate`] does **not** allocate this
    /// array (the predicate set is inlined).
    #[must_use]
    pub fn predicates(&self) -> [Predicate; K] {
        let mut preds = [Predicate::Parity {
            omega: [0u8; 32],
            expected: 0,
        }; K];
        let mut i = 0;
        while i < K {
            preds[i] = Predicate::Parity {
                omega: single_bit_omega(i),
                expected: self.expected[i],
            };
            i += 1;
        }
        preds
    }
}

impl<const K: usize> TypedCommitment for PayloadCommitment<K> {
    #[inline]
    fn bandwidth_bits(&self) -> f64 {
        K as f64
    }

    #[inline]
    fn accept_prob(&self) -> f64 {
        if K == 0 {
            1.0
        } else if K <= 127 {
            1.0 / ((1u128 << K) as f64)
        } else {
            // K ≥ 128: still well-defined as a real number, computed
            // multiplicatively. Practical commitments stay far below this.
            (2.0_f64).powi(-(K as i32))
        }
    }

    #[inline]
    fn evaluate(&self, digest: &[u8; 32]) -> bool {
        let mut i = 0;
        while i < K {
            if read_digest_bit(digest, i) != self.expected[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    #[inline]
    fn predicate_count(&self) -> usize {
        K
    }
}

/// Read the `i`-th bit of the digest, LSB-numbered (`i = 0` = bit 0
/// of byte 31; `i = 255` = bit 7 of byte 0). Matches the bit ordering
/// used by [`crate::ultrametric_valuation`] and the low-bits-mask
/// convention.
#[inline]
fn read_digest_bit(digest: &[u8; 32], i: usize) -> u32 {
    debug_assert!(i < 256, "digest bit index out of range");
    let byte_idx = 31 - i / 8;
    let bit_idx = i % 8;
    u32::from((digest[byte_idx] >> bit_idx) & 1)
}

/// Build a 32-byte ω with a single bit set at digest-bit index `i`
/// (LSB-numbered, matching [`read_digest_bit`]). Used by
/// [`PayloadCommitment::predicates`] for diagnostic decomposition.
#[inline]
#[must_use]
fn single_bit_omega(i: usize) -> [u8; 32] {
    debug_assert!(i < 256, "ω bit index out of range");
    let mut omega = [0u8; 32];
    let byte_idx = 31 - i / 8;
    let bit_idx = i % 8;
    omega[byte_idx] = 1u8 << bit_idx;
    omega
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_commitment_admits_every_digest() {
        let c = EmptyCommitment;
        assert!(c.evaluate(&[0u8; 32]));
        assert!(c.evaluate(&[0xff; 32]));
        assert_eq!(c.bandwidth_bits(), 0.0);
        assert_eq!(c.accept_prob(), 1.0);
        assert_eq!(c.predicate_count(), 0);
        assert!(c.is_empty());
    }

    #[test]
    fn payload_commitment_round_trips() {
        // Sender encodes 8 bits; receiver decodes them off a digest
        // that satisfies the commitment.
        let bits = [true, false, true, true, false, false, true, false];
        let c = PayloadCommitment::<8>::from_bits(bits);

        let mut digest = [0u8; 32];
        digest[31] = 0b0100_1101; // bits: 1, 0, 1, 1, 0, 0, 1, 0 (LSB first)

        assert!(c.evaluate(&digest));
        assert_eq!(PayloadCommitment::<8>::decode(&digest), bits);
    }

    #[test]
    fn payload_commitment_rejects_mismatched_bits() {
        let bits = [true, false, true, false];
        let c = PayloadCommitment::<4>::from_bits(bits);

        let mut digest = [0u8; 32];
        digest[31] = 0b0000_0101; // bits 1, 0, 1, 0 — matches
        assert!(c.evaluate(&digest));

        digest[31] = 0b0000_0100; // bits 0, 0, 1, 0 — bit 0 mismatch
        assert!(!c.evaluate(&digest));
    }

    #[test]
    fn payload_commitment_bandwidth_equals_k() {
        assert_eq!(PayloadCommitment::<0>::from_bits([]).bandwidth_bits(), 0.0);
        assert_eq!(
            PayloadCommitment::<1>::from_bits([true]).bandwidth_bits(),
            1.0
        );
        assert_eq!(
            PayloadCommitment::<16>::from_bits([true; 16]).bandwidth_bits(),
            16.0
        );
    }

    #[test]
    fn payload_commitment_accept_prob_is_two_to_the_minus_k() {
        assert_eq!(PayloadCommitment::<0>::from_bits([]).accept_prob(), 1.0);
        assert_eq!(PayloadCommitment::<1>::from_bits([true]).accept_prob(), 0.5);
        assert_eq!(
            PayloadCommitment::<4>::from_bits([true; 4]).accept_prob(),
            1.0 / 16.0
        );
        assert_eq!(
            PayloadCommitment::<10>::from_bits([true; 10]).accept_prob(),
            1.0 / 1024.0
        );
    }

    #[test]
    fn payload_predicates_match_underlying_parity_semantics() {
        // Decomposing PayloadCommitment into its underlying Predicate
        // array should agree with evaluating each Predicate individually.
        let bits = [true, false, false, true, true];
        let c = PayloadCommitment::<5>::from_bits(bits);
        let preds = c.predicates();
        assert_eq!(preds.len(), 5);

        let mut digest = [0u8; 32];
        digest[31] = 0b0001_1001; // bits 1, 0, 0, 1, 1 (LSB first) — matches `bits`

        // Commitment accepts.
        assert!(c.evaluate(&digest));
        // Every constituent predicate also accepts (round-trip
        // verification: the typed-commitment's monomorphized evaluation
        // matches the per-Predicate evaluation).
        for pred in &preds {
            assert!(pred.evaluate(&digest));
        }
    }

    #[test]
    fn payload_predicates_have_disjoint_supports_by_construction() {
        // PayloadCommitment<K> uses K disjoint single-bit ω-frequencies
        // — `wellFormed` by construction. Cross-check via the existing
        // Support algebra: every pair of decomposed predicates is
        // pairwise-disjoint.
        let c = PayloadCommitment::<8>::from_bits([true; 8]);
        let preds = c.predicates();
        for i in 0..preds.len() {
            for j in (i + 1)..preds.len() {
                let s_i = preds[i].support();
                let s_j = preds[j].support();
                assert!(
                    s_i.is_disjoint_from(&s_j),
                    "PayloadCommitment<K> predicates at positions {i} and {j} have overlapping supports"
                );
            }
        }
    }
}
