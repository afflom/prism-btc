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

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::commitment::TypedCommitment as _;
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
    /// Canonical UOR property landscape of the κ-label — triadic
    /// coordinates (`observables.coords`: stratum + spectrum) plus
    /// p-adic valuations at the canonical small-prime set
    /// [`crate::observables::CANONICAL_PRIMES`]. The **receiver-side**
    /// typed lens. Always computed; stack-resident.
    pub observables: crate::observables::KappaObservables,
    /// Diagnostic state from ψ_9's structural κ-derivation. See
    /// [`crate::diagnostics`].
    pub resolution: ResolutionState,
}

/// Failure modes from [`mine`] and [`mine_with`].
///
/// The receiver-side typed lens [`crate::observables::KappaObservables`]
/// is **total** — present on both `Ok(MiningOutcome)` and on
/// `DidNotAdmit`. Every ψ-pipeline inference exposes its candidate's
/// UOR property landscape, whether or not it admits. Host loops can
/// aggregate these into a [`crate::campaign::CampaignStats`]
/// observatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// The ψ-pipeline produced a wire-format header candidate via
    /// ψ_9's structural κ-derivation, but its σ-projection did not
    /// satisfy the host-supplied target (or, in [`mine_with`], the
    /// admitted candidate did not satisfy the typed commitment).
    /// The host boundary (architecture §7) varies the template-derived
    /// `MiningTask` (extranonce roll → distinct prefix → distinct
    /// κ-derivation) and retries.
    ///
    /// The candidate's typed property landscape is carried in
    /// `observables` — the receiver-side lens is total, not
    /// admission-only. This is the structural visibility prism-btc
    /// gives the host over every mining attempt.
    DidNotAdmit {
        /// The non-admitting κ-label's UOR property decomposition.
        observables: crate::observables::KappaObservables,
        /// The κ-derived nonce of this candidate (canonical LE).
        nonce: u32,
        /// SHA-256d of the candidate wire-format header.
        digest: [u8; 32],
    },
    /// Defensive: foundation's catamorphism or a resolver returned a
    /// shape violation. Unreachable for well-formed `MiningTask`
    /// inputs — the ψ-pipeline is total over the typed input
    /// surface. The conformance suite (CM-1) pins this unreachability
    /// across a wide range of synthetic mainnet-difficulty inputs.
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
    // mine() is the degenerate case of mine_with() at zero application
    // payload: the single typed admission gate is TargetCommitment.
    // Bare-target semantics are preserved exactly —
    // TargetCommitment::evaluate is Target::is_satisfied_by_bytes — and
    // the prism cost model now attributes admission as a typed
    // observable at L_inference rather than as a separate host-boundary
    // gate. See `mine_with` for the full composed entry.
    forward_and_check(
        header,
        target,
        crate::commitment::TargetCommitment::from(target),
    )
}

/// Run the ψ-pipeline on a [`BlockHeader`], κ-derive the wire-format
/// header at ψ_9, and admit iff the digest satisfies the typed
/// commitment `gate`.
///
/// This is the unified admission path: both [`mine`] (gate =
/// [`crate::commitment::TargetCommitment`]) and [`mine_with`] (gate =
/// `TargetCommitment` composed via
/// [`crate::commitment::AndCommitment`] with the application's typed
/// payload) flow through here, so the cost-model attribution is
/// uniform: admission is **one `TypedCommitment::evaluate` call** at
/// L_inference, not a separate boundary check sitting outside the
/// typed surface.
///
/// `target` is still threaded through because ψ_9 reads the target
/// bytes from the `MiningTask` carrier as part of the κ-derivation
/// input. The commitment-parametric `PrismModel` ADR (upstream
/// foundation work) will remove this redundancy by giving ψ_9 the
/// typed gate directly; the cost-model attribution then collapses
/// entirely into the ψ-pipeline.
fn forward_and_check<C: crate::commitment::TypedCommitment>(
    header: &BlockHeader,
    target: Target,
    gate: C,
) -> Result<MiningOutcome, MiningFailure> {
    let prefix = crate::ops::header::serialize_prefix(header);
    let target_bytes = target.to_bytes();
    let task = MiningTask::new(prefix, target_bytes);

    // Foundation 0.4.6 (ADR-048): PrismModel's 5-position form. The
    // 5th parameter is `C: TypedCommitment`, the substrate-level
    // cost-model commitment slot the catamorphism evaluates against
    // the κ-label inside `run_route`. BitcoinMiningModel pins
    // C = EmptyCommitment because Bitcoin's protocol admission
    // (digest ≤ target byte threshold) is not a foundation-side
    // `ObservablePredicate` — it's checked at the prism-btc boundary
    // by `forward_and_check`'s `gate.evaluate(&digest)` call.
    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        uor_foundation::pipeline::EmptyCommitment,
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

    // Single typed admission gate. The cost model attributes admission
    // to one `TypedCommitment::evaluate` invocation at L_inference,
    // covering both the base admission relation (carried by
    // TargetCommitment) and any composed application payload
    // (carried by AndCommitment). Fail-closed: forward_and_check()
    // returns Ok only when the unified commitment admits.
    if !gate.evaluate(&digest) {
        return Err(MiningFailure::DidNotAdmit {
            observables: crate::observables::KappaObservables::from_digest(&digest),
            nonce,
            digest,
        });
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
        observables: crate::observables::KappaObservables::from_digest(&digest),
        resolution,
    })
}

// ─── UOR-optimal mining: typed predicates ──────────────────────────────
//
// The σ-Projection Hardening Principle's U6 Joint-Probability
// Multiplicativity (ANALYSIS.md §4.1, §5.5) makes typed predicates a
// first-class observable surface on the κ-label: each Predicate names
// one UOR observable family the cryptanalysis battery confirmed
// admission-orthogonal under PRF. The types below are the primitives;
// they're consumed by [`crate::commitment::TypedCommitment`]
// implementors (the zero-cost commitment surface) and by individual
// predicate diagnostics / cryptanalysis tests.

/// A typed predicate over the κ-label's 32-byte content-address.
///
/// Each variant is one of the UOR observable families that the
/// cryptanalysis battery (ANALYSIS.md §3) confirmed
/// admission-orthogonal under PRF. Used as the primitive building
/// block for [`crate::commitment::TypedCommitment`] implementors and
/// for individual-predicate cryptanalysis (`examples/uor_cryptanalysis.rs`
/// §I + §J).
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
    ///
    /// `f64`-valued for ergonomic comparison; the **exact** rational
    /// counterpart is [`Self::accept_prob_rational`] (the direct
    /// correspondence point to `Predicate.acceptProb : Rat` in
    /// `prism-btc-lean/PrismBtc/CommitmentChannel.lean`).
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

    /// Exact PRF acceptance probability as a rational pair
    /// `(numerator, denominator)`. Direct correspondence point to
    /// `Predicate.acceptProb : Rat` in
    /// `prism-btc-lean/PrismBtc/CommitmentChannel.lean` (§1).
    ///
    /// Per-variant:
    ///
    /// - `Parity` → `(1, 2)` — Pr = 1/2
    /// - `StratumEq { k }` → `(1, 2^(k+1))` — Pr = 1/2^(k+1)
    /// - `PAdicEq { p, k }` → `(p − 1, p^(k+1))` — Pr = (p−1)/p^(k+1)
    /// - `UltrametricCloseTo { k }` → `(1, 2^k)` — Pr = 1/2^k
    ///   (`(1, 1)` when `k = 0`).
    ///
    /// The pair is **not reduced** — `(2, 4)` and `(1, 2)` are both
    /// valid representations of probability 1/2. The empirical
    /// `examples/uor_cryptanalysis.rs` §I (U1 marginal-calibration)
    /// uses this surface as the gold-standard acceptance rate.
    ///
    /// # Panics
    ///
    /// Panics if the denominator overflows `u128`. Realistic
    /// predicate parameters never trigger this — `StratumEq { k }`
    /// is well-defined for `k ≤ 126`, `UltrametricCloseTo { k }` for
    /// `k ≤ 127`, and `PAdicEq { p, k }` while `p^(k+1) ≤ u128::MAX`
    /// (e.g., `p = 3, k ≤ 80`).
    #[must_use]
    pub fn accept_prob_rational(&self) -> (u128, u128) {
        match self {
            Self::Parity { .. } => (1, 2),
            Self::StratumEq { k } => {
                let den = 1u128
                    .checked_shl(*k + 1)
                    .expect("StratumEq{k} k+1 exceeds u128::BITS - 1");
                (1, den)
            }
            Self::PAdicEq { p, k } => {
                let p128 = u128::from(*p);
                let den = p128
                    .checked_pow(*k + 1)
                    .expect("PAdicEq{p,k} p^(k+1) overflows u128");
                (p128 - 1, den)
            }
            Self::UltrametricCloseTo { k, .. } => {
                let den = 1u128
                    .checked_shl(*k)
                    .expect("UltrametricCloseTo{k} k exceeds u128::BITS - 1");
                (1, den)
            }
        }
    }

    /// PRF acceptance probability as an `f64`. Equivalent to
    /// `2f64.powf(-self.bandwidth_bits())`; equal to
    /// `num as f64 / den as f64` of [`Self::accept_prob_rational`]
    /// (modulo `f64` rounding for `PAdicEq { p ≥ 3 }` whose exact
    /// value is irrational in log-space but rational in
    /// probability-space).
    #[must_use]
    pub fn accept_prob(&self) -> f64 {
        let (num, den) = self.accept_prob_rational();
        (num as f64) / (den as f64)
    }

    /// The predicate's algebraic **support** — which manifold region
    /// it reads. Two predicates with disjoint supports are jointly
    /// independent under the random-oracle baseline (ANALYSIS.md §4.1
    /// U2 joint-independence). [`crate::commitment::TypedCommitment`]
    /// implementors discharge the `wellFormed` invariant by construction
    /// (typically at the type level via the const-generic shape of
    /// their predicate decomposition); this method is exposed for
    /// runtime diagnostic / cryptanalysis use only — the typed
    /// commitment hot path does not call it.
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
    /// §4.1 U2). `TypedCommitment` implementors discharge this
    /// invariant at the type level by construction; this method is
    /// retained for diagnostic / cryptanalysis use.
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

/// Mine with a typed `TypedCommitment` on the κ-label.
///
/// Returns `Ok(MiningOutcome)` iff the structural κ-derivation
/// produces a wire-format header that satisfies the **single typed
/// admission gate**
/// `TargetCommitment::from(target).and(commitment)`. The gate
/// composes the base admission relation `σ(header) ≤ target` (now
/// represented as a typed commitment) with the application's
/// declared payload `commitment`, so the prism cost model attributes
/// admission uniformly: K + B bits of declared bandwidth at L_inference,
/// one `TypedCommitment::evaluate` invocation per ψ-pipeline traversal.
///
/// **Zero-cost contract.** This entry is monomorphized per concrete
/// `C: TypedCommitment` at every call site — there is no `Vec<Predicate>`
/// allocation, no dynamic dispatch, no runtime decision about which
/// predicates to evaluate. The commitment's `wellFormed` invariant
/// (Lean: `Commitment.wellFormed`) is discharged at the type level by
/// the `TypedCommitment` impl, so the Lean theorem
/// `Commitment.prf_prob_tight_wellFormed` applies at equality:
/// expected template variations to land an admitting+committed κ-label
/// is exactly `2^(K + B)` where `K = TargetCommitment.bandwidth_bits()`
/// and `B = commitment.bandwidth_bits()` — assuming the supports are
/// admission-orthogonal (cryptanalysis-confirmed for the §14
/// predicate families; `ARCHITECTURE.md` §14, `ANALYSIS.md` §3).
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — the structural κ-candidate
///   failed the unified admission gate (either the base target,
///   the typed commitment, or both — the gate evaluates them as one).
///   The host should vary the template (extranonce roll, timestamp
///   bump) and retry.
/// - [`MiningFailure::PipelineFailure`] — defensive variant for
///   substrate-level shape violations; unreachable for well-formed
///   `MiningTask` inputs.
pub fn mine_with<C: crate::commitment::TypedCommitment>(
    header: &BlockHeader,
    target: Target,
    commitment: C,
) -> Result<MiningOutcome, MiningFailure> {
    // The unified typed admission gate: base target + application
    // payload composed via `AndCommitment`. One `evaluate()` call
    // covers both. The prism contract `operational = declared at
    // equality` applies to the full K + B bandwidth at this gate.
    let gate = crate::commitment::TargetCommitment::from(target).and(commitment);
    forward_and_check(header, target, gate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{EmptyCommitment, PayloadCommitment};
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
    fn mine_with_empty_commitment_matches_bare_mine() {
        // With EmptyCommitment the typed entry is the identity:
        // mine_with Ok ⇔ mine Ok, and the outcomes agree byte-for-byte.
        // EmptyCommitment monomorphizes to a no-op; the typed-iso
        // surface adds zero runtime cost over bare mine.
        let target = Target::new(0x207fffff);

        for ts in 0u32..16 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            match (
                mine(&header, target),
                mine_with(&header, target, EmptyCommitment),
            ) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.digest, b.digest);
                    assert_eq!(a.nonce, b.nonce);
                }
                (Err(_), Err(_)) => {}
                (a, b) => panic!(
                    "mine vs mine_with(EmptyCommitment) disagreed: a={:?} b={:?}",
                    a.is_ok(),
                    b.is_ok()
                ),
            }
        }
    }

    #[test]
    fn mine_with_typed_commitment_admits_when_satisfied() {
        // For a permissive target and EmptyCommitment we should find
        // an admitting κ-label within a small variation window.
        let target = Target::new(0x207fffff);
        let mut found = false;
        for ts in 0u32..32 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if mine_with(&header, target, EmptyCommitment).is_ok() {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "permissive target must admit with EmptyCommitment within 32 variations"
        );
    }

    #[test]
    fn mine_with_payload_commitment_finds_block_carrying_payload() {
        // A 1-bit PayloadCommitment doubles the expected cost over bare
        // admission. At regtest target (~50% admission) the joint
        // probability is ~25%, well-admittable within the small
        // template-variation window. The found block's digest carries
        // the encoded payload bit at position 0.
        let target = Target::new(0x207fffff);
        let commitment = PayloadCommitment::<1>::from_bits([true]);
        for ts in 0u32..64 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if let Ok(outcome) = mine_with(&header, target, commitment) {
                // Decoder round-trips: digest carries the payload bit
                // at the position the commitment encodes.
                let decoded = PayloadCommitment::<1>::decode(&outcome.digest);
                assert_eq!(decoded, [true]);
                return;
            }
        }
        panic!("permissive target × 1-bit payload commitment must admit within 64 variations");
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
    fn predicate_accept_prob_rational_per_variant() {
        // Direct correspondence to `Predicate.acceptProb : Rat` in the
        // Lean model — every variant's PRF acceptance is an exact
        // rational covering the formal claim.
        assert_eq!(
            Predicate::Parity {
                omega: [0u8; 32],
                expected: 0
            }
            .accept_prob_rational(),
            (1, 2)
        );
        assert_eq!(Predicate::StratumEq { k: 0 }.accept_prob_rational(), (1, 2));
        assert_eq!(
            Predicate::StratumEq { k: 5 }.accept_prob_rational(),
            (1, 64)
        );
        // PAdicEq{p=2,k} ≡ StratumEq{k} probability-wise.
        assert_eq!(
            Predicate::PAdicEq { p: 2, k: 3 }.accept_prob_rational(),
            (1, 16)
        );
        // PAdicEq{p=3,k=0}: Pr = 2/3.
        assert_eq!(
            Predicate::PAdicEq { p: 3, k: 0 }.accept_prob_rational(),
            (2, 3)
        );
        // PAdicEq{p=3,k=1}: Pr = 2/9.
        assert_eq!(
            Predicate::PAdicEq { p: 3, k: 1 }.accept_prob_rational(),
            (2, 9)
        );
        // PAdicEq{p=5,k=2}: Pr = 4/125.
        assert_eq!(
            Predicate::PAdicEq { p: 5, k: 2 }.accept_prob_rational(),
            (4, 125)
        );
        // UltrametricCloseTo{k=0} ↦ Pr = 1 (every digest qualifies).
        assert_eq!(
            Predicate::UltrametricCloseTo {
                reference: [0u8; 32],
                k: 0
            }
            .accept_prob_rational(),
            (1, 1)
        );
        assert_eq!(
            Predicate::UltrametricCloseTo {
                reference: [0u8; 32],
                k: 8
            }
            .accept_prob_rational(),
            (1, 256)
        );
    }

    #[test]
    fn predicate_accept_prob_matches_bandwidth_bits_inverse() {
        // accept_prob() should equal 2^(-bandwidth_bits()) within
        // f64 rounding for every variant.
        let cases = [
            Predicate::Parity {
                omega: [0u8; 32],
                expected: 0,
            },
            Predicate::StratumEq { k: 0 },
            Predicate::StratumEq { k: 10 },
            Predicate::PAdicEq { p: 2, k: 5 },
            Predicate::PAdicEq { p: 3, k: 2 },
            Predicate::PAdicEq { p: 5, k: 1 },
            Predicate::PAdicEq { p: 7, k: 0 },
            Predicate::UltrametricCloseTo {
                reference: [0u8; 32],
                k: 0,
            },
            Predicate::UltrametricCloseTo {
                reference: [0u8; 32],
                k: 8,
            },
        ];
        for pred in cases {
            let from_rational = pred.accept_prob();
            let from_bandwidth = 2f64.powf(-pred.bandwidth_bits());
            let rel_err = (from_rational - from_bandwidth).abs() / from_rational;
            assert!(
                rel_err < 1e-12,
                "accept_prob/bandwidth_bits mismatch for {pred:?}: \
                 rational={from_rational}, bandwidth-derived={from_bandwidth}"
            );
        }
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
}
