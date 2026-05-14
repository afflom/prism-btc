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

    /// Compose this commitment with `other` via [`AndCommitment`].
    ///
    /// The resulting commitment admits a digest iff both `self` and
    /// `other` admit it. Bandwidth is additive (`self.bandwidth +
    /// other.bandwidth`) — strictly when the underlying observables
    /// are admission-orthogonal in the semantic-field cost model
    /// (`ANALYSIS.md` §3 U3). `accept_prob` is multiplicative.
    ///
    /// Used by [`crate::mine_with`] to compose the base admission
    /// relation (now represented as [`TargetCommitment`]) with
    /// application-declared typed payload commitments.
    #[inline]
    fn and<Other: TypedCommitment>(self, other: Other) -> AndCommitment<Self, Other> {
        AndCommitment::new(self, other)
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

// ─── TargetCommitment — base admission as a typed commitment ───────────

/// The base Bitcoin admission relation `σ(header) ≤ target`, expressed
/// as a [`TypedCommitment`] so the prism cost model attributes it
/// uniformly with §14 payload commitments.
///
/// # Why this exists
///
/// Before this surface, `mine_with` composed two gates: the
/// [`crate::pipeline::mine`] target check and the
/// [`TypedCommitment::evaluate`] payload check. The base admission
/// (≈77 bits at mainnet difficulty) lived outside the typed-commitment
/// surface, so the Lean theorem
/// [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
/// applied only to the *increment* B beyond admission, not to the
/// unified K + B commitment. That was a cost-model conformance gap:
/// prism's contract says `operational = declared at equality`, but
/// only the B bits were typed-surface-declared.
///
/// `TargetCommitment` closes the gap. Its bandwidth equals
/// `−log₂(target_u256 / 2^256)` (≈77 at mainnet, ≈1 at regtest with
/// `0x207fffff`); its `accept_prob` is `target_u256 / 2^256`; its
/// `evaluate` is the existing [`crate::Target::is_satisfied_by_bytes`].
/// `mine_with` now composes `TargetCommitment(target).and(commitment)`
/// as a **single typed admission gate**, and the prism contract
/// applies to the full K + B bound at equality.
///
/// # Cost-model attribution
///
/// Admission is now an observable at L_inference, evaluated once per
/// ψ-pipeline traversal. The substrate-level σ-projection cost (one
/// canonical-hash-axis invocation) is unchanged; the **attribution**
/// moves from the host boundary into the typed surface.
///
/// # Limitations of this surface
///
/// `TargetCommitment` lifts admission into the cost model at the API
/// layer. The substrate move — making ψ_9 commitment-parametric, so
/// the admission relation is consumed *inside* the ψ-pipeline rather
/// than checked at its output — requires `PrismModel`'s arity to
/// grow a 5th type parameter and is upstream foundation work
/// (ADR proposal pending). Until then, the κ-derivation in ψ_9
/// remains fixed (`H(task)[0..4]` LE) and the typed admission gate
/// is evaluated at the boundary of [`crate::pipeline::mine_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCommitment {
    target_bytes: [u8; 32],
}

impl TargetCommitment {
    /// Construct from a [`crate::Target`]. The 32-byte big-endian
    /// (display-order) threshold is stored as the commitment's
    /// admission shape.
    #[inline]
    #[must_use]
    pub fn new(target: crate::Target) -> Self {
        Self {
            target_bytes: target.to_bytes(),
        }
    }

    /// The 32-byte threshold (display order). Useful for diagnostic
    /// inspection; the commitment's authoritative state.
    #[inline]
    #[must_use]
    pub fn threshold_bytes(&self) -> &[u8; 32] {
        &self.target_bytes
    }
}

impl From<crate::Target> for TargetCommitment {
    #[inline]
    fn from(target: crate::Target) -> Self {
        Self::new(target)
    }
}

impl TypedCommitment for TargetCommitment {
    /// `−log₂(target_u256 / 2^256)`. For a target with the leading
    /// 1-bit at position `255 − lz`, this is approximately `lz` plus
    /// the contribution of the mantissa. Tight to `f64` precision
    /// (~52 bits of mantissa).
    #[inline]
    fn bandwidth_bits(&self) -> f64 {
        let p = self.accept_prob();
        if p <= 0.0 {
            f64::INFINITY
        } else {
            -p.log2()
        }
    }

    /// `target_u256 / 2^256`. Computed from a 64-bit mantissa anchored
    /// at the leading 1-bit of the threshold; the omitted tail
    /// contributes at most 2^-64 of relative error, well below `f64`
    /// epsilon for realistic targets.
    #[inline]
    fn accept_prob(&self) -> f64 {
        target_bytes_accept_prob(&self.target_bytes)
    }

    /// The existing admission relation: digest `≤` threshold in
    /// 32-byte display-order lexicographic comparison
    /// ([`crate::Target::is_satisfied_by_bytes`]).
    #[inline]
    fn evaluate(&self, digest: &[u8; 32]) -> bool {
        digest <= &self.target_bytes
    }

    /// `TargetCommitment` is a single typed admission predicate.
    #[inline]
    fn predicate_count(&self) -> usize {
        1
    }
}

/// Compute `target_u256 / 2^256` as an `f64` to ~52 bits of mantissa
/// precision. Tight for the leading 64 bits of the threshold; the
/// trailing 192 bits contribute at most one `f64` ulp.
#[inline]
fn target_bytes_accept_prob(target_bytes: &[u8; 32]) -> f64 {
    // Count leading zero bits to locate the leading 1-bit.
    let mut lz = 0u32;
    for &b in target_bytes.iter() {
        if b == 0 {
            lz += 8;
        } else {
            lz += b.leading_zeros();
            break;
        }
    }
    if lz == 256 {
        return 0.0;
    }
    // Anchor a 64-bit mantissa at the leading-zero byte boundary.
    let leading_byte_idx = (lz / 8) as usize;
    let mut mantissa_u64: u64 = 0;
    let mut i = 0;
    while i < 8 {
        let idx = leading_byte_idx + i;
        let byte = if idx < 32 { target_bytes[idx] } else { 0 };
        mantissa_u64 = (mantissa_u64 << 8) | (byte as u64);
        i += 1;
    }
    // mantissa_u64 represents 64 contiguous bits starting at byte
    // leading_byte_idx. accept_prob ≈ mantissa_u64 · 2^(−8·leading_byte_idx − 64).
    let scale_exp = -((leading_byte_idx as i32) * 8 + 64);
    (mantissa_u64 as f64) * (2f64).powi(scale_exp)
}

// ─── AndCommitment — conjunction of two typed commitments ──────────────

/// Conjunction of two [`TypedCommitment`]s. Admits a digest iff both
/// component commitments admit. Bandwidth is **additive** when the
/// component supports are admission-orthogonal (`ANALYSIS.md` §3 U3,
/// §4 U6); `accept_prob` is always multiplicative under PRF baseline.
///
/// Used by [`crate::mine_with`] to compose [`TargetCommitment`] (the
/// base admission relation) with any application-declared payload
/// commitment. The composition is monomorphized — no heap, no
/// dynamic dispatch — so the prism zero-cost contract continues to
/// apply per-monomorphization.
///
/// # Bandwidth orthogonality
///
/// `AndCommitment` reports `A.bandwidth_bits() + B.bandwidth_bits()`,
/// which is exact when the underlying observables are
/// admission-orthogonal. The cryptanalysis battery (`ANALYSIS.md` §3)
/// verifies this for the §14 predicate families (Parity at disjoint
/// frequencies, StratumEq, PAdicEq at canonical primes,
/// UltrametricCloseTo) and pairwise admission independence with
/// target admission. Callers composing predicates whose supports
/// overlap should treat the reported bandwidth as an upper bound, not
/// a tight equality. The Lean theorem
/// [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
/// applies at equality only for the orthogonal case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndCommitment<A, B> {
    pub a: A,
    pub b: B,
}

impl<A: TypedCommitment, B: TypedCommitment> AndCommitment<A, B> {
    /// Build a conjunction from two commitments. Both must be `Copy`
    /// (enforced by the [`TypedCommitment`] supertrait).
    #[inline]
    #[must_use]
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: TypedCommitment, B: TypedCommitment> TypedCommitment for AndCommitment<A, B> {
    #[inline]
    fn bandwidth_bits(&self) -> f64 {
        self.a.bandwidth_bits() + self.b.bandwidth_bits()
    }

    #[inline]
    fn accept_prob(&self) -> f64 {
        self.a.accept_prob() * self.b.accept_prob()
    }

    #[inline]
    fn evaluate(&self, digest: &[u8; 32]) -> bool {
        self.a.evaluate(digest) && self.b.evaluate(digest)
    }

    #[inline]
    fn predicate_count(&self) -> usize {
        self.a.predicate_count() + self.b.predicate_count()
    }
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

    // ─── TargetCommitment — base admission in the typed surface ────────

    #[test]
    fn target_commitment_evaluates_identically_to_target() {
        // For any digest, TargetCommitment::evaluate must match the
        // Target::is_satisfied_by_bytes that the host boundary uses
        // today. Genesis target: 0x1d00ffff.
        let target = crate::Target::new(crate::Target::GENESIS_NBITS);
        let c = TargetCommitment::from(target);

        // A digest with many leading zeros must admit at genesis.
        let mut genesis = [0u8; 32];
        genesis[5] = 0x19;
        genesis[6] = 0xd6;
        genesis[7] = 0x68;
        assert_eq!(c.evaluate(&genesis), target.is_satisfied_by_bytes(&genesis));

        // A non-admitting digest must be rejected by both.
        let too_large = [0xff; 32];
        assert_eq!(
            c.evaluate(&too_large),
            target.is_satisfied_by_bytes(&too_large)
        );
        assert!(!c.evaluate(&too_large));
    }

    #[test]
    fn target_commitment_predicate_count_is_one() {
        let c = TargetCommitment::from(crate::Target::new(crate::Target::GENESIS_NBITS));
        assert_eq!(c.predicate_count(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn target_commitment_bandwidth_matches_leading_zero_difficulty() {
        // nBits = 0x20010000: mantissa = 0x010000, exp = 0x20 → target =
        // 0x010000 * 256^(0x20 - 3) = 2^16 * 2^232 = 2^248.
        // accept_prob = 2^-8, bandwidth = 8.
        let target = crate::Target::new(0x20_01_00_00);
        let c = TargetCommitment::from(target);
        let bw = c.bandwidth_bits();
        assert!((bw - 8.0).abs() < 1e-9, "expected bandwidth ≈ 8, got {bw}");
        let p = c.accept_prob();
        assert!(
            (p - (1.0 / 256.0)).abs() < 1e-15,
            "expected accept_prob ≈ 1/256, got {p}"
        );
    }

    #[test]
    fn target_commitment_mainnet_difficulty_bandwidth_in_expected_range() {
        // nBits 0x1d00ffff (network-defining minimum-difficulty mainnet
        // target) decodes to ≈ 2^224 — about 32 leading zero bits — so
        // bandwidth should land in [28, 36].
        let target = crate::Target::new(0x1d_00_ff_ff);
        let c = TargetCommitment::from(target);
        let bw = c.bandwidth_bits();
        assert!(
            (28.0..36.0).contains(&bw),
            "mainnet-minimum-difficulty bandwidth out of expected range: {bw}"
        );
    }

    // ─── AndCommitment — composition ───────────────────────────────────

    #[test]
    fn and_commitment_with_empty_is_identity() {
        // A.and(EmptyCommitment) must behave identically to A — Empty
        // contributes 0 bandwidth and accept_prob = 1.
        let payload = PayloadCommitment::<3>::from_bits([true, false, true]);
        let composed = payload.and(EmptyCommitment);
        assert_eq!(composed.bandwidth_bits(), payload.bandwidth_bits());
        assert_eq!(composed.accept_prob(), payload.accept_prob());
        assert_eq!(composed.predicate_count(), payload.predicate_count());

        let mut digest = [0u8; 32];
        digest[31] = 0b0000_0101; // bits 1, 0, 1 matches the payload
        assert!(composed.evaluate(&digest));
        assert_eq!(composed.evaluate(&digest), payload.evaluate(&digest));
    }

    #[test]
    fn and_commitment_bandwidth_is_additive_for_disjoint_payloads() {
        // Two PayloadCommitments at distinct K windows ⇒ additive
        // bandwidth, multiplicative accept_prob.
        let a = PayloadCommitment::<5>::from_bits([true; 5]);
        let b = PayloadCommitment::<3>::from_bits([false; 3]);
        let composed = a.and(b);
        assert_eq!(composed.bandwidth_bits(), 5.0 + 3.0);
        assert_eq!(composed.accept_prob(), (1.0 / 32.0) * (1.0 / 8.0));
        assert_eq!(composed.predicate_count(), 5 + 3);
    }

    #[test]
    fn and_commitment_rejects_when_either_rejects() {
        let a = PayloadCommitment::<2>::from_bits([true, false]);
        let b = PayloadCommitment::<2>::from_bits([true, true]);
        let composed = a.and(b);
        // a expects bits 1, 0; b expects bits 1, 1. They disagree on
        // bit 1, so no digest can satisfy both.
        let mut digest = [0u8; 32];
        digest[31] = 0b01;
        assert!(a.evaluate(&digest));
        assert!(!b.evaluate(&digest));
        assert!(!composed.evaluate(&digest));

        digest[31] = 0b11;
        assert!(!a.evaluate(&digest));
        assert!(b.evaluate(&digest));
        assert!(!composed.evaluate(&digest));
    }

    #[test]
    fn target_commitment_composed_with_payload_evaluates_both_gates() {
        // TargetCommitment.and(PayloadCommitment) is one typed
        // admission gate covering K + B bits in the cost model.
        let target = crate::Target::new(crate::Target::GENESIS_NBITS);
        let target_c = TargetCommitment::from(target);
        let payload = PayloadCommitment::<4>::from_bits([true, false, true, false]);
        let composed = target_c.and(payload);

        let expected_bw = target_c.bandwidth_bits() + payload.bandwidth_bits();
        assert!((composed.bandwidth_bits() - expected_bw).abs() < 1e-9);

        // A digest that admits target but mismatches payload → reject.
        let mut bad_payload = [0u8; 32];
        bad_payload[31] = 0b1111;
        assert!(target_c.evaluate(&bad_payload));
        assert!(!payload.evaluate(&bad_payload));
        assert!(!composed.evaluate(&bad_payload));

        // A digest that admits both → accept.
        let mut good = [0u8; 32];
        good[31] = 0b0101;
        assert!(target_c.evaluate(&good));
        assert!(payload.evaluate(&good));
        assert!(composed.evaluate(&good));
    }
}
