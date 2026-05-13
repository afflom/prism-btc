//! prism-btc's public entry point — the ψ-pipeline mining inference
//! per architecture §5, §6.
//!
//! 1. The host assembles a [`MiningTask`] from a [`BlockHeader`] and a
//!    [`Target`] (76-byte `TemplatePrefix` + 32-byte `Target`).
//! 2. [`BitcoinMiningModel::forward`] invokes the ψ-chain verb
//!    ([`crate::verbs::mining_inference`]) end-to-end via foundation's
//!    catamorphism. The catamorphism dispatches each resolver-bound
//!    ψ-Term through [`crate::resolvers::BitcoinResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::resolvers::BitcoinKInvariantResolver`]) structurally
//!    κ-derives the four nonce-byte sites from the typed `MiningTask`
//!    via the canonical hash axis (one σ-projection — deterministic,
//!    no enumeration). The 80-byte wire-format Bitcoin header is the
//!    κ-label.
//! 4. [`mine`] enforces the **admission relation** at the host
//!    boundary: it recomputes the σ-projection on the wire-format
//!    header and checks `σ(header) ≤ target`. If admission holds,
//!    [`mine`] returns [`MiningOutcome`]; otherwise it returns
//!    [`MiningFailure::DidNotAdmit`] and the host (architecture §7)
//!    varies the template-derived `MiningTask` and retries.
//!
//! **Fail-closed contract.** `mine()` returns `Ok(MiningOutcome)` only
//! when the κ-derived wire-format header satisfies the host-supplied
//! `target`. The ψ-pipeline produces one structural candidate per
//! `MiningTask`; the admission relation is the boundary's
//! responsibility, not the pipeline's.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::diagnostics::{take_resolution_state, ResolutionState};
use crate::domain::{
    p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at, BlockHeader, MiningTag,
    MiningWitness, Target, TriadicCoords,
};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::sha256::sha256d_display;
use crate::resolvers::BitcoinResolverTuple;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// The result of a successful [`mine`] invocation. The 80-byte
/// wire-format Bitcoin header carried by `witness.output_bytes()` is
/// guaranteed to satisfy the host-supplied target — `mine()` only
/// returns `Ok(MiningOutcome)` when admission holds.
pub struct MiningOutcome {
    /// Foundation-sealed `Grounded<MiningResult, MiningTag>`; its
    /// `output_bytes()` are the 80-byte wire-format Bitcoin header.
    pub witness: MiningWitness,
    /// The κ-derived nonce (canonical Bitcoin LE, bytes 76..80 of the
    /// κ-label).
    pub nonce: u32,
    /// SHA-256d of the wire-format header in display order.
    pub digest: [u8; 32],
    /// Digest's triadic coordinates.
    pub coords: TriadicCoords,
    /// Diagnostic state from ψ_9's structural κ-derivation. See
    /// [`crate::diagnostics`].
    pub resolution: ResolutionState,
}

/// Failure modes from [`mine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// The ψ-pipeline produced a wire-format header candidate via
    /// ψ_9's structural κ-derivation, but its σ-projection did not
    /// satisfy the host-supplied target. The host boundary
    /// (architecture §7) varies the template-derived `MiningTask`
    /// (extranonce roll → distinct prefix → distinct κ-derivation)
    /// and retries.
    DidNotAdmit,
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed `MiningTask`
    /// inputs — the ψ-pipeline is total over the typed input
    /// surface.
    PipelineFailure,
}

/// **prism-btc's public entry point** — one ψ-pipeline mining
/// inference per `(prefix, target)`.
///
/// Builds a [`MiningTask`] from `(header, target)`, invokes
/// `BitcoinMiningModel::forward` (which always produces a κ-label
/// candidate for well-formed inputs), and enforces the admission
/// relation `σ(header) ≤ target` at the host boundary.
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — the κ-derived wire-format
///   header's σ-projection did not satisfy `target`. The structural
///   admission relation has no inhabitant for this typed input under
///   ψ_9's κ-derivation; the host varies the template and retries.
/// - [`MiningFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable in normal flow.
pub fn mine(header: &BlockHeader, target: Target) -> Result<MiningOutcome, MiningFailure> {
    let prefix = crate::ops::header::serialize_prefix(header);
    let target_bytes = target.to_bytes();
    let task = MiningTask::new(prefix, target_bytes);

    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .map_err(|_| MiningFailure::PipelineFailure)?;

    // The κ-label IS the wire-format Bitcoin header (architecture §6).
    let header_bytes = grounded.output_bytes();
    if header_bytes.len() != 80 {
        return Err(MiningFailure::PipelineFailure);
    }

    // Bitcoin's nonce field is bytes 76..80, little-endian.
    let nonce = u32::from_le_bytes([
        header_bytes[76],
        header_bytes[77],
        header_bytes[78],
        header_bytes[79],
    ]);

    let mut header_array = [0u8; 80];
    header_array.copy_from_slice(header_bytes);
    let digest = sha256d_display(&header_array);

    // Host-boundary admission relation: ψ_9 produced this κ-candidate
    // structurally; the boundary checks whether σ(header) ≤ target.
    // Fail-closed: mine() returns Ok only when admission genuinely
    // holds.
    if !target.is_satisfied_by_bytes(&digest) {
        return Err(MiningFailure::DidNotAdmit);
    }

    // Drain the diagnostic channel ψ_9 wrote on its way out. Under
    // `no_std` the channel does not exist; reconstruct from the
    // outcome.
    let resolution = take_resolution_state().unwrap_or(ResolutionState {
        free_rank: 0,
        derived_nonce: nonce,
    });

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
        resolution,
    })
}

// ─── UOR-optimal mining: Conjunction'd typed commitment ────────────────
//
// The σ-Projection Hardening Principle's U6 Bandwidth-Additivity
// (ANALYSIS.md §4.1, §5.5) makes the substrate's `type:Conjunction`
// primitive a typed information channel over the σ-projection: K
// independent 1-bit predicates encode K bits of structural commitment
// in the κ-label at expected `2^K × α^-1` template variations, where
// α is the bare admission probability. The types and entry point
// below operationalize this channel at the host boundary of
// prism-btc.

/// A typed predicate over the κ-label's 32-byte content-address.
///
/// Each variant is one of the UOR observable families that the
/// cryptanalysis battery (ANALYSIS.md §3) confirmed
/// admission-orthogonal under PRF. Composing K predicates under a
/// [`MiningCommitment`] declares a Conjunction'd boundary
/// commitment with bandwidth equal to the sum of per-predicate
/// `bandwidth_bits` (ANALYSIS.md §5 — U6 Bandwidth-Additivity).
#[derive(Debug, Clone, Copy)]
pub enum Predicate {
    /// Walsh–Hadamard parity at a bit-mask frequency.
    /// `walsh_hadamard_parity_at(digest, &omega) == expected`.
    /// Single-bit `omega` reads one digest bit; multi-bit `omega`
    /// commits to the parity of bits at the masked positions.
    /// PRF probability: `1/2`. Bandwidth: 1 bit.
    Parity {
        /// Frequency mask `ω`.
        omega: [u8; 32],
        /// Expected parity value: `0` (even popcount of `digest ∧ ω`) or `1` (odd).
        expected: u32,
    },

    /// Stratum (2-adic valuation) equals exactly `k`.
    /// `TriadicCoords::from_hash(digest).stratum == k`.
    /// PRF probability: `2^-(k+1)` (bit k set, bits 0..k zero).
    /// Bandwidth: `k + 1` bits.
    StratumEq {
        /// Required 2-adic valuation.
        k: u32,
    },

    /// `p`-adic valuation equals exactly `k` for prime `p`.
    /// `p_adic_valuation(digest, p) == k`.
    /// PRF probability: `(p − 1)/p^(k+1)`.
    /// Bandwidth: `(k + 1)·log₂(p) − log₂(p − 1)` bits (real-valued).
    PAdicEq {
        /// Prime base `p`.
        p: u64,
        /// Required p-adic valuation.
        k: u32,
    },

    /// Ultrametric closeness to a reference digest: the digest
    /// shares at least `k` low bits with `reference`, i.e.
    /// `ultrametric_valuation(digest, &reference) >= k`.
    /// PRF probability: `2^-k`. Bandwidth: `k` bits.
    UltrametricCloseTo {
        /// Reference digest the commitment is measured against.
        reference: [u8; 32],
        /// Minimum 2-adic valuation of the XOR-difference.
        k: u32,
    },
}

impl Predicate {
    /// Evaluate the predicate on a digest. Returns `true` iff the
    /// predicate's typed structural condition holds.
    #[must_use]
    pub fn evaluate(&self, digest: &[u8; 32]) -> bool {
        match self {
            Self::Parity { omega, expected } => {
                walsh_hadamard_parity_at(digest, omega) == *expected
            }
            Self::StratumEq { k } => TriadicCoords::from_hash(digest).stratum == *k,
            Self::PAdicEq { p, k } => p_adic_valuation(digest, *p) == *k,
            Self::UltrametricCloseTo { reference, k } => {
                ultrametric_valuation(digest, reference) >= *k
            }
        }
    }

    /// PRF bandwidth (in bits) — `−log₂(P(predicate satisfied))`
    /// under the random-oracle baseline. The Conjunction of K
    /// independent predicates has total bandwidth equal to the sum
    /// of per-predicate `bandwidth_bits` (U6 Bandwidth-Additivity).
    #[must_use]
    pub fn bandwidth_bits(&self) -> f64 {
        match self {
            // P = 1/2  →  −log₂(1/2) = 1
            Self::Parity { .. } => 1.0,
            // P = 2^-(k+1)  →  bandwidth = k + 1
            Self::StratumEq { k } => (*k as f64) + 1.0,
            // P = (p − 1)/p^(k+1)  →  bandwidth = (k+1)·log₂(p) − log₂(p − 1)
            Self::PAdicEq { p, k } => {
                let p_f = *p as f64;
                ((*k as f64) + 1.0) * p_f.log2() - (p_f - 1.0).log2()
            }
            // P = 2^-k  →  bandwidth = k
            Self::UltrametricCloseTo { k, .. } => *k as f64,
        }
    }

    /// The predicate's algebraic **support** — which manifold region
    /// it reads. Two predicates with disjoint supports are jointly
    /// independent under the random-oracle baseline (ANALYSIS.md §4.1
    /// U2 joint-independence); composing them under a [`MiningCommitment`]
    /// produces a Conjunction whose [`MiningCommitment::bandwidth_bits`]
    /// is **tight** rather than an upper bound (U6).
    ///
    /// Per-variant supports:
    ///
    /// - `Parity { ω, .. }`: `Support::BitSet(ω)` — the parity reads
    ///   the digest bits at the positions set in `ω`.
    /// - `StratumEq { k }`: `Support::BitSet(low_bits_mask(k + 1))` —
    ///   the predicate constrains bits 0..k of the 256-bit BE integer
    ///   (bits 0..k−1 must be zero AND bit k must be set).
    /// - `UltrametricCloseTo { k, .. }`: `Support::BitSet(low_bits_mask(k))`
    ///   — the predicate constrains the low `k` bits of the digest.
    /// - `PAdicEq { p: 2, k }`: same as `StratumEq { k }` (the 2-adic
    ///   valuation is the stratum); canonicalized to `BitSet`.
    /// - `PAdicEq { p, .. }` for `p ≥ 3`: `Support::Modular { p }`
    ///   — the predicate reads the digest's residue class mod `p^*`;
    ///   independent from any `BitSet` support and from any other
    ///   `Modular { q }` with `q ≠ p`.
    #[must_use]
    pub fn support(&self) -> Support {
        match self {
            Self::Parity { omega, .. } => Support::BitSet(*omega),
            Self::StratumEq { k } => Support::BitSet(low_bits_mask(*k + 1)),
            Self::UltrametricCloseTo { k, .. } => Support::BitSet(low_bits_mask(*k)),
            // PAdicEq{p=2} ≡ StratumEq{k}: canonicalize to BitSet so
            // mixed compositions check correctly.
            Self::PAdicEq { p: 2, k } => Support::BitSet(low_bits_mask(*k + 1)),
            Self::PAdicEq { p, .. } => Support::Modular { p: *p },
        }
    }
}

/// Algebraic support of a [`Predicate`] — the manifold region it
/// reads. Two supports are **disjoint** iff predicates with these
/// supports are jointly independent under the PRF baseline.
///
/// - `BitSet(a)` ⊥ `BitSet(b)` iff `a & b == 0` (bit-disjoint masks).
/// - `Modular { p }` ⊥ `BitSet(_)` iff `p ≠ 2` (a prime ≥ 3 is
///   coprime with any bit-pattern read from the digest).
/// - `Modular { p₁ }` ⊥ `Modular { p₂ }` iff `p₁ ≠ p₂` (distinct
///   primes are coprime moduli).
///
/// `PAdicEq { p: 2, k }` is canonicalized to `BitSet(low_bits_mask(k+1))`
/// at [`Predicate::support`] so its independence with bit-set
/// predicates is checked correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Bit-position support: the predicate reads bits at positions
    /// where `mask` has bits set (in LSB-numbered integer view of
    /// the 256-bit digest).
    BitSet([u8; 32]),
    /// Modular support: the predicate reads the digest's residue
    /// mod `p` (and higher powers). For two `Modular` supports to
    /// be disjoint, their `p` values must be distinct primes.
    Modular {
        /// Prime modulus base. Must be `≥ 3` (the `p = 2` case is
        /// canonicalized to [`Support::BitSet`] by [`Predicate::support`]).
        p: u64,
    },
}

impl Support {
    /// Returns `true` iff `self` and `other` are algebraically
    /// disjoint — i.e. predicates with these supports are jointly
    /// independent under the random-oracle baseline (ANALYSIS.md
    /// §4.1 U2). When all pairs of supports in a [`MiningCommitment`]
    /// are disjoint, [`MiningCommitment::bandwidth_bits`] is a tight
    /// bound on the PRF mining cost; non-disjoint supports make it
    /// an upper bound.
    #[must_use]
    pub fn is_disjoint_from(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BitSet(a), Self::BitSet(b)) => a.iter().zip(b.iter()).all(|(x, y)| x & y == 0),
            (Self::BitSet(_), Self::Modular { p }) | (Self::Modular { p }, Self::BitSet(_)) => {
                *p != 2
            }
            (Self::Modular { p: p1 }, Self::Modular { p: p2 }) => *p1 != *p2,
        }
    }
}

/// Construct a `[u8; 32]` bit-mask with the `n` lowest-position bits
/// set. Bit `i` (LSB-numbered, `i = 0` is bit 0 of byte 31) is set
/// iff `i < n`. Saturates at `n = 256`.
#[inline]
#[must_use]
fn low_bits_mask(n: u32) -> [u8; 32] {
    let mut mask = [0u8; 32];
    let n = (n as usize).min(256);
    let full_bytes = n / 8;
    let extra_bits = n % 8;
    let mut i = 0;
    while i < full_bytes {
        mask[31 - i] = 0xff;
        i += 1;
    }
    if extra_bits > 0 && full_bytes < 32 {
        mask[31 - full_bytes] = (1u8 << extra_bits) - 1;
    }
    mask
}

/// Errors from [`MiningCommitment::try_add_predicate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentError {
    /// The new predicate's support overlaps the existing predicate at
    /// `existing_index`. U6 Bandwidth-Additivity (ANALYSIS.md §4.1,
    /// §5.5) requires pairwise-disjoint supports for
    /// [`MiningCommitment::bandwidth_bits`] to be a tight bound on
    /// PRF mining cost rather than an upper bound.
    OverlappingSupport {
        /// Index (in the commitment's predicate list) of the existing
        /// predicate whose support overlaps the new one.
        existing_index: usize,
    },
}

/// A typed boundary commitment — a Conjunction of K independent
/// typed predicates evaluated on the κ-label's display-order digest.
/// [`mine_with_commitment`] returns `Ok` only when both the admission
/// relation AND every predicate in the commitment hold.
///
/// **Channel semantics** (ANALYSIS.md §5.4):
///
/// - *Sender* — the application that declares the commitment.
/// - *Channel* — the σ-projection over candidate templates
///   (`prism_btc::mine`'s structural inference per `MiningTask`).
/// - *Receiver* — any party reading the κ-label and re-evaluating
///   the declared predicates on it.
/// - *Bandwidth* — `commitment.bandwidth_bits()` bits per κ-label,
///   computed as the sum of per-predicate bandwidth contributions
///   (U6 Bandwidth-Additivity).
/// - *Cost* — expected `α^-1 × 2^bandwidth_bits` template variations
///   per commit-admitting κ-label, where α is the bare admission
///   probability (PRF baseline per U6).
///
/// The substrate's [`uor_foundation::pipeline::ConstraintRef::Conjunction`]
/// variant provides the compile-time analogue for commitments fixed
/// at type-definition time; [`MiningCommitment`] is the runtime
/// surface that lets applications declare commitments per-session.
#[derive(Debug, Clone, Default)]
pub struct MiningCommitment {
    predicates: Vec<Predicate>,
}

impl MiningCommitment {
    /// An empty commitment — `mine_with_commitment` reduces exactly
    /// to [`mine`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Append a Walsh–Hadamard parity predicate at frequency `omega`
    /// with the given expected parity (`0` or `1`). Bandwidth: 1 bit.
    #[must_use]
    pub fn add_parity(self, omega: [u8; 32], expected: u32) -> Self {
        self.add_predicate(Predicate::Parity { omega, expected })
    }

    /// Append a stratum-equality predicate: the digest's 2-adic
    /// valuation must equal `k`. Bandwidth: `k + 1` bits.
    #[must_use]
    pub fn add_stratum_eq(self, k: u32) -> Self {
        self.add_predicate(Predicate::StratumEq { k })
    }

    /// Append a p-adic-equality predicate: the digest's `p`-adic
    /// valuation must equal `k`. Bandwidth: `(k+1)·log₂(p) − log₂(p−1)`
    /// bits (real-valued for `p > 2`).
    ///
    /// # Panics
    ///
    /// Panics if `p < 2`.
    #[must_use]
    pub fn add_p_adic_eq(self, p: u64, k: u32) -> Self {
        assert!(p >= 2, "p-adic predicate requires p ≥ 2");
        self.add_predicate(Predicate::PAdicEq { p, k })
    }

    /// Append an ultrametric-closeness predicate: the digest must
    /// share at least `k` low bits with `reference` (equivalently,
    /// the 2-adic valuation of `digest ⊕ reference` is `≥ k`).
    /// Bandwidth: `k` bits.
    #[must_use]
    pub fn add_ultrametric_close_to(self, reference: [u8; 32], k: u32) -> Self {
        self.add_predicate(Predicate::UltrametricCloseTo { reference, k })
    }

    /// Append an arbitrary [`Predicate`], enforcing that its support
    /// is disjoint from every existing predicate's support.
    ///
    /// # Panics
    ///
    /// Panics if the new predicate's support overlaps an existing
    /// predicate's support — that would break U6 Bandwidth-Additivity's
    /// independence requirement and cause [`Self::bandwidth_bits`] to
    /// over-state the actual PRF mining cost. Use
    /// [`Self::try_add_predicate`] to handle overlap dynamically.
    #[must_use]
    pub fn add_predicate(self, predicate: Predicate) -> Self {
        match self.try_add_predicate(predicate) {
            Ok(c) => c,
            Err(CommitmentError::OverlappingSupport { existing_index }) => panic!(
                "MiningCommitment::add_predicate: new predicate has overlapping support \
                 with existing predicate at index {existing_index}; U6 Bandwidth-Additivity \
                 requires pairwise-disjoint supports for `bandwidth_bits()` to be a tight \
                 cost contract. Use try_add_predicate to handle this dynamically."
            ),
        }
    }

    /// Append an arbitrary [`Predicate`], returning `Err` if its
    /// support overlaps any existing predicate's support.
    ///
    /// On success, the returned commitment satisfies the invariant
    /// that all pairwise supports are disjoint — making
    /// [`Self::bandwidth_bits`] a **tight** bound on PRF mining cost
    /// (U6 Bandwidth-Additivity holds with equality under the
    /// random-oracle baseline).
    ///
    /// # Errors
    ///
    /// [`CommitmentError::OverlappingSupport`] — names the index of
    /// the existing predicate whose support overlaps the new one.
    pub fn try_add_predicate(mut self, predicate: Predicate) -> Result<Self, CommitmentError> {
        let new_support = predicate.support();
        for (existing_index, existing) in self.predicates.iter().enumerate() {
            if !new_support.is_disjoint_from(&existing.support()) {
                return Err(CommitmentError::OverlappingSupport { existing_index });
            }
        }
        self.predicates.push(predicate);
        Ok(self)
    }

    /// Total PRF bandwidth (in bits) the commitment encodes per
    /// κ-label — the sum of per-predicate `bandwidth_bits` per U6
    /// Bandwidth-Additivity. The expected mining cost is
    /// `α^-1 × 2^bandwidth_bits` template variations.
    #[must_use]
    pub fn bandwidth_bits(&self) -> f64 {
        self.predicates.iter().map(Predicate::bandwidth_bits).sum()
    }

    /// Number of predicates Conjunction'd in the commitment. For
    /// commitments composed only of [`Predicate::Parity`] this
    /// equals [`bandwidth_bits`](Self::bandwidth_bits) (integer);
    /// for the richer surface the two diverge.
    #[must_use]
    pub fn predicate_count(&self) -> usize {
        self.predicates.len()
    }

    /// True iff the commitment has zero predicates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    /// Evaluate every predicate in the Conjunction on a digest.
    /// Returns `true` iff all predicates hold.
    #[must_use]
    pub fn evaluate(&self, digest: &[u8; 32]) -> bool {
        self.predicates.iter().all(|p| p.evaluate(digest))
    }

    /// Borrow the contained predicates.
    #[must_use]
    pub fn predicates(&self) -> &[Predicate] {
        &self.predicates
    }
}

/// Mine with a Conjunction'd typed commitment on the κ-label.
///
/// Returns `Ok(MiningOutcome)` iff the structural κ-derivation:
///
/// 1. produces a wire-format header satisfying the admission
///    relation `σ(header) ≤ target`, AND
/// 2. satisfies every predicate in `commitment`.
///
/// The boundary check is the fail-closed gate (architecture §6) for
/// both axes; the caller need not re-verify either. From the host's
/// perspective the function behaves like [`mine`] but with the
/// additional Conjunction'd predicates folded into the boundary
/// admission relation.
///
/// **Cost.** Per U6 Bandwidth-Additivity (ANALYSIS.md §4.1, §5.5),
/// expected template variations to land a commit-admitting κ-label
/// is `α^-1 × 2^B` where α is the bare admission probability and B
/// is `commitment.bandwidth_bits()`. The substrate's Conjunction
/// primitive makes the composition free at the typed-iso surface;
/// the σ-projection enforces the cryptographic `2^B` cost.
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — the structural κ-candidate
///   either failed the admission relation or any predicate in
///   `commitment`. The host should vary the template and retry.
/// - [`MiningFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable for well-formed
///   `MiningTask` inputs.
pub fn mine_with_commitment(
    header: &BlockHeader,
    target: Target,
    commitment: &MiningCommitment,
) -> Result<MiningOutcome, MiningFailure> {
    let outcome = mine(header, target)?;
    if !commitment.evaluate(&outcome.digest) {
        return Err(MiningFailure::DidNotAdmit);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Bits, MerkleRoot, Timestamp, Version};

    fn permissive_header(timestamp: u32) -> BlockHeader {
        BlockHeader {
            version: Version(1),
            prev_hash: [0u8; 32],
            merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
            timestamp: Timestamp(timestamp),
            bits: Bits(0x207fffff),
        }
    }

    #[test]
    fn empty_commitment_matches_bare_mine() {
        // With zero predicates the commitment is the identity:
        // mine_with_commitment Ok ⇔ mine Ok, and the outcomes
        // agree byte-for-byte.
        let target = Target::new(0x207fffff);
        let empty = MiningCommitment::empty();

        for ts in 0u32..16 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            match (
                mine(&header, target),
                mine_with_commitment(&header, target, &empty),
            ) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.digest, b.digest);
                    assert_eq!(a.nonce, b.nonce);
                }
                (Err(_), Err(_)) => {}
                (a, b) => panic!(
                    "mine vs mine_with_commitment disagreed: a={:?} b={:?}",
                    a.is_ok(),
                    b.is_ok()
                ),
            }
        }
    }

    #[test]
    fn parity_predicate_reads_single_bit() {
        // ω with a single bit set reads that bit's value.
        let mut omega = [0u8; 32];
        omega[15] = 0b0010_0000; // bit 5 of byte 15
        let want_set = Predicate::Parity { omega, expected: 1 };
        let want_clear = Predicate::Parity { omega, expected: 0 };

        let mut digest_set = [0u8; 32];
        digest_set[15] = 0b0010_0000;
        let digest_clear = [0u8; 32];

        assert!(want_set.evaluate(&digest_set));
        assert!(!want_set.evaluate(&digest_clear));
        assert!(!want_clear.evaluate(&digest_set));
        assert!(want_clear.evaluate(&digest_clear));
        assert!((want_set.bandwidth_bits() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn stratum_eq_predicate_matches_2_adic_valuation() {
        // bit 3 of byte 31 set, lower bits zero ⇒ stratum == 3.
        let mut digest = [0u8; 32];
        digest[31] = 0b0000_1000;
        let pred = Predicate::StratumEq { k: 3 };
        assert!(pred.evaluate(&digest));
        assert!(!Predicate::StratumEq { k: 2 }.evaluate(&digest));
        // bandwidth(StratumEq{k}) = k + 1
        assert!((pred.bandwidth_bits() - 4.0).abs() < 1e-12);
    }

    #[test]
    fn p_adic_eq_predicate_matches_p_adic_valuation() {
        // 9 = 3² ⇒ v_3(9) = 2.
        let mut digest = [0u8; 32];
        digest[31] = 9;
        let pred = Predicate::PAdicEq { p: 3, k: 2 };
        assert!(pred.evaluate(&digest));
        assert!(!Predicate::PAdicEq { p: 3, k: 1 }.evaluate(&digest));
        // P(v_3 = 2) = 2/27  →  bandwidth = log₂(27/2) ≈ 3.755
        let bw = pred.bandwidth_bits();
        assert!((bw - (27.0_f64 / 2.0).log2()).abs() < 1e-9);
    }

    #[test]
    fn ultrametric_close_to_predicate() {
        let mut digest = [0u8; 32];
        digest[31] = 0xff;
        let mut reference = [0u8; 32];
        reference[31] = 0xf0;
        // digest ⊕ reference = 0x0f at byte 31, all-zero elsewhere
        // ⇒ low 4 bits differ at the LSB byte → no shared low bits at all.
        // Wait — XOR is 0x0f (bits 0,1,2,3 set), so v_2 = 0 (bit 0 set).
        // UltrametricCloseTo {k: 0} = "share ≥ 0 low bits" — always true.
        assert!(Predicate::UltrametricCloseTo { reference, k: 0 }.evaluate(&digest));
        // k = 1 requires bit 0 of XOR = 0, but bit 0 of 0x0f is 1, so fails.
        assert!(!Predicate::UltrametricCloseTo { reference, k: 1 }.evaluate(&digest));

        // bandwidth(UltrametricCloseTo{k}) = k
        let pred = Predicate::UltrametricCloseTo { reference, k: 5 };
        assert!((pred.bandwidth_bits() - 5.0).abs() < 1e-12);
    }

    #[test]
    fn commitment_bandwidth_is_additive_over_disjoint_supports() {
        // U6 Bandwidth-Additivity (ANALYSIS.md §4.1, §5.5) is a
        // TIGHT bound when supports are pairwise-disjoint; the
        // typed-iso surface enforces that invariant via
        // `add_predicate` / `try_add_predicate` (architecture §14.2).
        let mut high_omega = [0u8; 32];
        high_omega[8] = 0b0000_0001; // bit 0 of byte 8 — far from byte-31 low bits

        let c = MiningCommitment::empty()
            .add_parity(high_omega, 1) // 1 bit, BitSet at byte 8
            .add_stratum_eq(3) // 4 bits, BitSet on low bits of byte 31
            .add_p_adic_eq(3, 0); // ≈0.585 bits, Modular {p=3}
        assert_eq!(c.predicate_count(), 3);
        assert!(!c.is_empty());
        let expected = 1.0 + 4.0 + (3.0_f64 / 2.0).log2();
        assert!((c.bandwidth_bits() - expected).abs() < 1e-12);

        let empty = MiningCommitment::empty();
        assert_eq!(empty.predicate_count(), 0);
        assert!((empty.bandwidth_bits()).abs() < 1e-12);
        assert!(empty.is_empty());
    }

    #[test]
    fn predicate_support_canonicalizes_p_adic_2_to_bit_set() {
        // PAdicEq{p=2, k} ≡ StratumEq{k}: both read the low (k+1)
        // bits of the digest. Their supports must be equal so mixed
        // compositions correctly identify them as dependent.
        let p_adic_2 = Predicate::PAdicEq { p: 2, k: 3 };
        let stratum = Predicate::StratumEq { k: 3 };
        assert_eq!(p_adic_2.support(), stratum.support());
    }

    #[test]
    fn support_bit_set_overlap_is_dependent() {
        let mut mask_a = [0u8; 32];
        mask_a[31] = 0b0000_1100; // bits 2, 3
        let mut mask_b = [0u8; 32];
        mask_b[31] = 0b0000_1010; // bits 1, 3 — overlap at bit 3
        let a = Support::BitSet(mask_a);
        let b = Support::BitSet(mask_b);
        assert!(!a.is_disjoint_from(&b));
        assert!(!b.is_disjoint_from(&a));
    }

    #[test]
    fn support_disjoint_bit_sets_are_independent() {
        let mut mask_a = [0u8; 32];
        mask_a[5] = 0xff;
        let mut mask_b = [0u8; 32];
        mask_b[20] = 0xff;
        assert!(Support::BitSet(mask_a).is_disjoint_from(&Support::BitSet(mask_b)));
    }

    #[test]
    fn support_modular_distinct_primes_are_disjoint() {
        let a = Support::Modular { p: 3 };
        let b = Support::Modular { p: 5 };
        assert!(a.is_disjoint_from(&b));
        // Same prime → dependent.
        assert!(!a.is_disjoint_from(&Support::Modular { p: 3 }));
    }

    #[test]
    fn support_modular_p3_independent_of_bit_set() {
        // PAdicEq{p≥3} is independent from any BitSet (cross-family).
        let mut mask = [0u8; 32];
        mask[31] = 0x0f;
        let bit = Support::BitSet(mask);
        let modular = Support::Modular { p: 3 };
        assert!(bit.is_disjoint_from(&modular));
        assert!(modular.is_disjoint_from(&bit));
    }

    #[test]
    fn try_add_predicate_rejects_overlapping_support() {
        // Adding a predicate whose support overlaps an existing one
        // returns Err with the offending existing index.
        let c = MiningCommitment::empty().add_stratum_eq(3); // bits 0..3 of byte 31
        let result = c.try_add_predicate(Predicate::UltrametricCloseTo {
            reference: [0u8; 32],
            k: 2,
        }); // bits 0..1 — overlaps stratum's bits 0,1
        assert_eq!(
            result.err(),
            Some(CommitmentError::OverlappingSupport { existing_index: 0 })
        );
    }

    #[test]
    fn try_add_predicate_accepts_disjoint_support() {
        let c = MiningCommitment::empty().add_stratum_eq(3);
        let result = c.try_add_predicate(Predicate::PAdicEq { p: 5, k: 0 });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().predicate_count(), 2);
    }

    #[test]
    #[should_panic(expected = "overlapping support")]
    fn add_predicate_panics_on_overlapping_support() {
        // The infallible builder panics on overlap. Match against the
        // panic message's "overlapping support" substring.
        let _ = MiningCommitment::empty()
            .add_stratum_eq(3)
            .add_ultrametric_close_to([0u8; 32], 2);
    }

    #[test]
    fn commitment_evaluates_conjunction_of_mixed_predicates() {
        // Mix two predicate families and verify Conjunction = AND of
        // per-predicate evaluations.
        let mut omega = [0u8; 32];
        omega[8] = 0b0000_0001;
        let c = MiningCommitment::empty()
            .add_parity(omega, 1) // bit 0 of byte 8 = 1
            .add_stratum_eq(2); // bit 2 of byte 31 = 1, lower zero

        let mut both_hold = [0u8; 32];
        both_hold[8] = 0b0000_0001;
        both_hold[31] = 0b0000_0100; // bit 2 set, lower bits zero
        assert!(c.evaluate(&both_hold));

        // Same digest minus the parity bit ⇒ only stratum holds.
        let mut only_stratum = [0u8; 32];
        only_stratum[31] = 0b0000_0100;
        assert!(!c.evaluate(&only_stratum));

        // Same digest minus the stratum requirement ⇒ only parity holds.
        let mut only_parity = [0u8; 32];
        only_parity[8] = 0b0000_0001;
        assert!(!c.evaluate(&only_parity));
    }

    #[test]
    fn mine_with_commitment_admits_when_predicates_hold() {
        // For a permissive target and an empty commitment we should
        // find an admitting κ-label within a small variation window.
        let target = Target::new(0x207fffff);
        let empty = MiningCommitment::empty();
        let mut found = false;
        for ts in 0u32..32 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if mine_with_commitment(&header, target, &empty).is_ok() {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "permissive target must admit with empty commitment within 32 variations"
        );
    }
}
