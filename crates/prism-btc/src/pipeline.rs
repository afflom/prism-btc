//! prism-btc's public entry point — the ψ-pipeline mining inference
//! per architecture §5, §6.
//!
//! 1. The host assembles a [`MiningTask`] from a [`BlockHeader`] and a
//!    [`Target`] (76-byte `TemplatePrefix` + 32-byte `Target`).
//! 2. [`mine`] promotes the target bytes to `&'static [u8]` via
//!    [`crate::commitment::leak_target`], publishes them on a
//!    thread-local slot, and invokes `BitcoinMiningModel::forward`
//!    ([`crate::model::BitcoinMiningModel`]).
//! 3. Foundation's [`prism::pipeline::run_route`] drives the catamorphism
//!    end-to-end — the ψ-chain verb ([`crate::verbs::mining_inference`])
//!    is dispatched through [`crate::resolvers::BitcoinResolverTuple`].
//! 4. The terminal ψ_9 resolver
//!    ([`crate::resolvers::BitcoinKInvariantResolver`]) structurally
//!    κ-derives a 4-byte nonce from the typed `MiningTask` via the
//!    canonical hash axis, reconstructs the 80-byte wire-format header
//!    from `(template_prefix, nonce)`, and emits the 32-byte
//!    `SHA-256d` of that header as the κ-label. One canonical-hash-
//!    axis projection plus one SHA-256d evaluation — deterministic,
//!    no enumeration. The 32-byte digest IS the κ-label foundation's
//!    `LexicographicLessEqThreshold` predicate consumes.
//! 5. **Foundation's `run_route` consults the model's `C: TypedCommitment`
//!    on the κ-label.** `BitcoinMiningModel` binds `C = TargetCommitment`
//!    per wiki ADR-040 + ADR-048, so admission (`digest ≤ target` under
//!    big-endian unsigned comparison) is evaluated **inside the
//!    catamorphism** directly on the κ-label digest. On non-admission,
//!    run_route returns `PipelineFailure::ShapeViolation`; on
//!    admission it returns a sealed
//!    [`prism::seal::Grounded<MiningResult>`].
//!
//! **Cost-model conformance.** Admission is one
//! [`prism::pipeline::TypedCommitment::evaluate`] invocation inside
//! `run_route` — the catamorphism's typed-bandwidth admission gate per
//! wiki QS-06. The Lean theorem
//! [`Commitment.prf_prob_tight_wellFormed`](../../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
//! applies at equality: expected template variations equal
//! `α⁻¹ × 2^bandwidth` where `bandwidth = TargetCommitment::bandwidth_bits()`
//! (here `α⁻¹` is the structural admission rate of ψ_9's κ-derivation
//! and `2^bandwidth ≈ 1/target_accept_prob`).
//!
//! **Fail-closed contract.** `mine()` returns `Ok(MiningOutcome)` only
//! when foundation's `run_route` admits — there is no host-boundary
//! gate retrying admission outside the typed-iso surface.

use core::cell::Cell;

use crate::diagnostics::{take_resolution_state, ResolutionState};
use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::sha256::sha256d_display;

/// The result of a successful [`mine`] invocation. The 32-byte
/// `SHA-256d` digest carried by `witness.output_bytes()` is guaranteed
/// to satisfy the host-supplied target — `mine()` only returns
/// `Ok(MiningOutcome)` when foundation's `run_route` admits.
pub struct MiningOutcome {
    /// Foundation-sealed `Grounded<MiningResult, MiningTag>`; its
    /// `output_bytes()` are the 32-byte SHA-256d κ-label (the natural
    /// cost-model κ-label per wiki ADR-048/049).
    pub witness: MiningWitness,
    /// The κ-derived nonce (canonical Bitcoin LE).
    pub nonce: u32,
    /// SHA-256d of the wire-format header in display order — the
    /// κ-label.
    pub digest: [u8; 32],
    /// The 80-byte wire-format Bitcoin header reconstructed from
    /// `(template_prefix, nonce)`. Provided here for the host-boundary
    /// `submitblock` path (architecture §7): the ψ-pipeline's κ-label
    /// is now the 32-byte digest, but the bitcoind boundary needs the
    /// wire-format bytes to assemble the final block.
    pub wire_format_header: [u8; 80],
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

/// Failure modes from [`mine`].
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
    /// ψ_9's structural κ-derivation, but the `TargetCommitment` did
    /// not admit it inside foundation's `run_route` — i.e. the
    /// κ-label's σ-projection digest did not satisfy the
    /// target under `LexicographicLessEqThreshold`.
    /// The host (architecture §7) varies the template-derived
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
    /// shape violation **before** the commitment-evaluation stage.
    /// Unreachable for well-formed `MiningTask` inputs — the
    /// ψ-pipeline is total over the typed input surface. The
    /// conformance suite (CM-2) pins this unreachability across a
    /// wide range of synthetic mainnet-difficulty inputs.
    PipelineFailure,
}

// ─── Thread-local target slot ──────────────────────────────────────────
//
// Foundation's `LexicographicLessEqThreshold::target` requires
// `&'static [u8]`. The macro-emitted `BitcoinMiningModel::forward`
// constructs the commitment via `fn commitment() -> TargetCommitment {
// crate::commitment::target_commitment(current_thread_target()) }` —
// so we publish the active target on a thread-local slot before
// invoking forward. `mine()` writes the slot once per call;
// concurrent miners on independent threads have independent slots.

thread_local! {
    static THREAD_TARGET: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
}

/// Set the thread-local active target. Idempotent — repeated calls with
/// the same bytes resolve to the same `&'static [u8]` via
/// [`crate::commitment::leak_target`]'s registry.
///
/// Public entry [`mine`] calls this automatically; callers who invoke
/// `BitcoinMiningModel::forward` directly (or who use foundation's
/// `run_route` with their own derived `PrismModel`) must call this
/// first so the model's `fn commitment()` body can read the target
/// from the thread-local slot.
pub fn set_thread_target(target: &Target) {
    let pinned = crate::commitment::leak_target(target.to_bytes());
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Like [`set_thread_target`] but takes raw bytes — useful for tests
/// that construct a [`MiningTask`] directly without a [`Target`].
pub fn set_thread_target_bytes(bytes: [u8; 32]) {
    let pinned = crate::commitment::leak_target(bytes);
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Read the thread-local active target. Panics if no target has been
/// set — every entry point sets the target before invoking
/// `BitcoinMiningModel::forward`, so reaching the panic path indicates
/// a misuse (a direct `forward()` call without a target preface).
#[must_use]
pub fn current_thread_target() -> &'static [u8] {
    THREAD_TARGET.with(|cell| {
        cell.get()
            .expect("prism-btc: no active target on this thread; call mine() / set_thread_target() before forward()")
    })
}

/// **prism-btc's public entry point** — one ψ-pipeline mining
/// inference per `(prefix, target)`.
///
/// Builds a [`MiningTask`] from `(header, target)`, publishes the
/// target on the thread-local commitment slot, and invokes
/// `BitcoinMiningModel::forward`. Admission is evaluated **inside**
/// foundation's `run_route` via the model's pinned `C = TargetCommitment`
/// (wiki ADR-048).
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — foundation's `run_route` reported
///   `PipelineFailure::ShapeViolation` at the `commitment/TypedCommitment`
///   stage, meaning the κ-derived wire-format header's σ-projection
///   did not satisfy `target`. The host varies the template and
///   retries.
/// - [`MiningFailure::PipelineFailure`] — foundation's `run_route`
///   reported a shape violation *before* the commitment stage
///   (substrate-level). Unreachable in normal flow.
pub fn mine(header: &BlockHeader, target: Target) -> Result<MiningOutcome, MiningFailure> {
    set_thread_target(&target);

    let prefix = crate::ops::header::serialize_prefix(header);
    let task = MiningTask::new(prefix, target.to_bytes());

    // BitcoinMiningModel::forward delegates to run_route::<H, B, A, M, R, TargetCommitment>
    // (see `crate::model`). run_route evaluates the commitment on the κ-label after
    // the resolver chain emits it; admission failure surfaces here as a
    // PipelineFailure::ShapeViolation with the commitment-violation IRI, which
    // we classify into DidNotAdmit below.
    use prism::pipeline::PrismModel;
    use prism::vocabulary::DefaultHostTypes;

    let pipeline_result = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        crate::shapes::bounds::PrismBtcBounds,
        crate::shapes::hasher::Sha256dHasher,
        crate::resolvers::BitcoinResolverTuple<crate::shapes::hasher::Sha256dHasher>,
        crate::commitment::TargetCommitment,
    >>::forward(task);

    match pipeline_result {
        Ok(grounded) => {
            // The κ-label IS the 32-byte SHA-256d digest in Bitcoin
            // display order (wiki ADR-048/049 cost-model surface).
            let digest_bytes = grounded.output_bytes();
            if digest_bytes.len() != 32 {
                return Err(MiningFailure::PipelineFailure);
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(digest_bytes);
            // Drain ψ_9's diagnostic channel to recover the κ-derived
            // nonce so we can reconstruct the wire-format header for
            // the host-boundary `submitblock` path. The channel is
            // populated by ψ_9 immediately before run_route invokes
            // the commitment, so it's guaranteed to be present on
            // the Ok arm (under `std`).
            let resolution = take_resolution_state().unwrap_or(ResolutionState {
                free_rank: 0,
                derived_nonce: 0,
            });
            let nonce = resolution.derived_nonce;
            let wire_format_header = crate::ops::header::serialize_header(header, nonce);
            Ok(MiningOutcome {
                witness: grounded.tag::<MiningTag>(),
                nonce,
                digest,
                wire_format_header,
                observables: crate::observables::KappaObservables::from_digest(&digest),
                resolution,
            })
        }
        Err(failure) => {
            // Classify the failure: a commitment-violation surfaces the
            // DidNotAdmit arm; any earlier substrate violation is
            // PipelineFailure. Foundation tags the commitment violation
            // with the `https://uor.foundation/commitment/TypedCommitment/VIOLATED`
            // shape IRI; we match on that to disambiguate.
            let is_commitment_violation = matches!(
                &failure,
                prism::pipeline::PipelineFailure::ShapeViolation { report }
                    if report.shape_iri == "https://uor.foundation/commitment/TypedCommitment/VIOLATED"
            );
            if !is_commitment_violation {
                // Drain any partial diagnostic state to keep the channel
                // empty for the next call.
                let _ = take_resolution_state();
                return Err(MiningFailure::PipelineFailure);
            }
            // Reconstruct the non-admitting κ-label digest. The
            // κ-derivation is deterministic in the typed input, so we
            // re-derive the candidate via the thread-local diagnostic
            // channel ψ_9 wrote on its way out. If the diagnostic channel
            // isn't available (no_std), we fall back to recomputing the
            // header from the resolved nonce.
            let resolution = take_resolution_state();
            let nonce = resolution.as_ref().map_or(0u32, |r| r.derived_nonce);
            let header_array = crate::ops::header::serialize_header(header, nonce);
            let digest = sha256d_display(&header_array);
            Err(MiningFailure::DidNotAdmit {
                observables: crate::observables::KappaObservables::from_digest(&digest),
                nonce,
                digest,
            })
        }
    }
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
    fn mine_admits_within_a_few_template_variations_for_permissive_target() {
        // The permissive regtest target (~50% admission) must yield an
        // admitting κ-label within a small window of template variations.
        let target = Target::new(0x207fffff);
        let mut admitted = false;
        for ts in 0u32..32 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if mine(&header, target).is_ok() {
                admitted = true;
                break;
            }
        }
        assert!(admitted, "permissive target must admit within 32 variations");
    }

    #[test]
    fn mine_emits_thirty_two_byte_digest_kappa_label_on_admit() {
        let target = Target::new(0x207fffff);
        for ts in 0u32..64 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if let Ok(outcome) = mine(&header, target) {
                // κ-label is the 32-byte SHA-256d digest (wiki
                // ADR-048/049 cost-model surface).
                assert_eq!(outcome.witness.output_bytes().len(), 32);
                // Wire-format header is provided on the side for the
                // bitcoind boundary's `submitblock` path.
                assert_eq!(outcome.wire_format_header.len(), 80);
                return;
            }
        }
        panic!("permissive target must admit somewhere in the variation window");
    }

    #[test]
    fn mine_did_not_admit_carries_kappa_observables() {
        // A highly restrictive target must produce a DidNotAdmit
        // outcome for some templates; the receiver-side lens is total.
        let mut nbits = [0u8; 4];
        // nBits with very few leading zeros — restrictive target.
        nbits.copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        let target = Target::new(u32::from_le_bytes(nbits));
        let mut saw_failure = false;
        for ts in 0u32..32 {
            let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
            if let Err(MiningFailure::DidNotAdmit {
                observables,
                digest,
                ..
            }) = mine(&header, target)
            {
                // Observable lens is consistent with the digest.
                assert_eq!(
                    observables,
                    crate::observables::KappaObservables::from_digest(&digest)
                );
                saw_failure = true;
                break;
            }
        }
        assert!(
            saw_failure,
            "restrictive target must yield DidNotAdmit at some template variation"
        );
    }
}
