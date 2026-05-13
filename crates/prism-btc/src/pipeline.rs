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
    walsh_hadamard_parity_at, BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords,
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

/// Walsh–Hadamard parity commitment at a bit-mask frequency.
///
/// The predicate evaluates to `true` on a digest `d` iff
/// `walsh_hadamard_parity_at(d, &omega) == expected`. With a
/// single-bit `omega`, the commitment reads the value of one digest
/// bit; with multi-bit `omega`, it commits to the parity of the
/// digest's bits at the masked positions. The full WH spectrum has
/// `2^256` frequencies; one [`ParityCommitment`] picks one.
///
/// Under the σ-Projection Hardening Principle's marginal-uniformity
/// condition (ANALYSIS.md §4.1 U1), each parity commitment has
/// independent satisfaction probability 1/2 on a uniformly random
/// digest, and K of them compose under U2/U6 to a Bernoulli(2⁻ᴷ)
/// joint event.
#[derive(Debug, Clone, Copy)]
pub struct ParityCommitment {
    /// Frequency mask `ω` — the bit positions whose parity is
    /// committed.
    pub omega: [u8; 32],
    /// Expected parity value: `0` (even popcount) or `1` (odd).
    pub expected: u32,
}

impl ParityCommitment {
    /// Construct a parity commitment at frequency `omega` with the
    /// given expected parity.
    #[inline]
    #[must_use]
    pub fn new(omega: [u8; 32], expected: u32) -> Self {
        Self { omega, expected }
    }

    /// Evaluate the predicate on a digest.
    #[inline]
    #[must_use]
    pub fn evaluate(&self, digest: &[u8; 32]) -> bool {
        walsh_hadamard_parity_at(digest, &self.omega) == self.expected
    }
}

/// A typed boundary commitment — a Conjunction of K independent
/// 1-bit predicates evaluated on the κ-label's display-order digest.
/// [`mine_with_commitment`] returns `Ok` only when both the admission
/// relation AND every predicate in the commitment hold.
///
/// **Channel semantics** (ANALYSIS.md §5.4):
///
/// - *Sender* — the application that declares K predicates.
/// - *Channel* — the σ-projection over candidate templates
///   (`prism_btc::mine`'s structural inference per `MiningTask`).
/// - *Receiver* — any party reading the κ-label and re-evaluating
///   the declared predicates on it.
/// - *Bandwidth* — `K` bits per κ-label (`commitment.bandwidth()`).
/// - *Cost* — expected `2^K × α^-1` template variations per
///   commit-admitting κ-label, where α is the bare admission
///   probability (PRF baseline per U6).
///
/// The substrate's [`uor_foundation::pipeline::ConstraintRef::Conjunction`]
/// variant provides the compile-time analogue for commitments fixed
/// at type-definition time; [`MiningCommitment`] is the runtime
/// surface that lets applications declare commitments per-session.
#[derive(Debug, Clone, Default)]
pub struct MiningCommitment {
    predicates: Vec<ParityCommitment>,
}

impl MiningCommitment {
    /// An empty commitment — `mine_with_commitment` reduces exactly
    /// to [`mine`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Append a Walsh–Hadamard parity predicate at frequency `omega`
    /// with the given expected parity (0 or 1). Returns `self` for
    /// builder-style chaining.
    #[must_use]
    pub fn add_parity(mut self, omega: [u8; 32], expected: u32) -> Self {
        self.predicates.push(ParityCommitment::new(omega, expected));
        self
    }

    /// Append a pre-built [`ParityCommitment`].
    #[must_use]
    pub fn push(mut self, commitment: ParityCommitment) -> Self {
        self.predicates.push(commitment);
        self
    }

    /// Number of independent 1-bit predicates in the commitment —
    /// equals the bandwidth (in bits) encoded per κ-label per U6
    /// Bandwidth-Additivity.
    #[must_use]
    pub fn bandwidth(&self) -> usize {
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
    pub fn predicates(&self) -> &[ParityCommitment] {
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
/// is `α^-1 × 2^K` where α is the bare admission probability and K
/// is `commitment.bandwidth()`. The substrate's Conjunction primitive
/// makes the K-fold composition free at the typed-iso surface; the
/// σ-projection enforces the cryptographic `2^K` cost.
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
    fn parity_commitment_reads_single_bit() {
        // ω with a single bit set reads that bit's value.
        let mut omega = [0u8; 32];
        omega[15] = 0b0010_0000; // bit 5 of byte 15
        let want_set = ParityCommitment::new(omega, 1);
        let want_clear = ParityCommitment::new(omega, 0);

        let mut digest_set = [0u8; 32];
        digest_set[15] = 0b0010_0000;
        let digest_clear = [0u8; 32];

        assert!(want_set.evaluate(&digest_set));
        assert!(!want_set.evaluate(&digest_clear));
        assert!(!want_clear.evaluate(&digest_set));
        assert!(want_clear.evaluate(&digest_clear));
    }

    #[test]
    fn commitment_bandwidth_counts_predicates() {
        let c = MiningCommitment::empty()
            .add_parity([1u8; 32], 0)
            .add_parity([2u8; 32], 1)
            .add_parity([3u8; 32], 0);
        assert_eq!(c.bandwidth(), 3);
        assert!(!c.is_empty());

        let empty = MiningCommitment::empty();
        assert_eq!(empty.bandwidth(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn commitment_evaluates_conjunction() {
        let mut omega_a = [0u8; 32];
        omega_a[8] = 0b0000_0001;
        let mut omega_b = [0u8; 32];
        omega_b[16] = 0b0001_0000;
        let c = MiningCommitment::empty()
            .add_parity(omega_a, 1)
            .add_parity(omega_b, 0);

        // digest where both predicates hold
        let mut both_hold = [0u8; 32];
        both_hold[8] = 0b0000_0001; // ω_a parity = 1 ✓
                                    // ω_b parity = 0 from all-zero ✓
        assert!(c.evaluate(&both_hold));

        // digest where only ω_a holds
        let mut only_a = [0u8; 32];
        only_a[8] = 0b0000_0001;
        only_a[16] = 0b0001_0000; // ω_b parity = 1 ✗
        assert!(!c.evaluate(&only_a));
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
