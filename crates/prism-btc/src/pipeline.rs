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

use crate::diagnostics::{take_resolution_state, ResolutionState};
use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
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
