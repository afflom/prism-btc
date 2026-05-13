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
//!    ([`crate::resolvers::BitcoinKInvariantResolver`]) implements the
//!    framework's iterative-resolution discipline (wiki
//!    `iterative-resolution.md`): walks the W32 nonce ring until the
//!    structural admission relation lands, pins the four nonce-byte
//!    sites, and emits the **κ-label** — 80 bytes that ARE the
//!    wire-format Bitcoin header by construction.
//! 4. [`mine`] returns [`MiningOutcome`] on success. The resolver
//!    guarantees admission on `Ok`; from the host's perspective
//!    `mine()` is one structural inference per `(prefix, target)`.
//!
//! **Fail-closed contract.** `mine()` returns `Ok(MiningOutcome)` only
//! when the κ-derived wire-format header satisfies the host-supplied
//! `target`. When the W32 ring is walked end-to-end without
//! admission, the resolver returns the canonical
//! `InhabitanceImpossibilityWitness` (surfaced through
//! [`MiningFailure::PipelineFailure`]); the host boundary varies the
//! template-derived `MiningTask` (extranonce roll) and retries.

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

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
    /// The admitting nonce (canonical Bitcoin LE, bytes 76..80 of the
    /// κ-label).
    pub nonce: u32,
    /// SHA-256d of the wire-format header in display order.
    pub digest: [u8; 32],
    /// Digest's triadic coordinates.
    pub coords: TriadicCoords,
}

/// Failure modes from [`mine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// Foundation's catamorphism or a resolver returned a shape
    /// violation. The canonical instance for prism-btc is the
    /// `NONCE_FIBER_EXHAUSTED` impossibility-witness the ψ_9
    /// resolver emits when the W32 ring is walked end-to-end without
    /// admission — the host boundary varies the template-derived
    /// `MiningTask` (extranonce roll) and retries.
    PipelineFailure,
}

/// **prism-btc's public entry point** — one ψ-pipeline mining
/// inference per `(prefix, target)`.
///
/// Builds a [`MiningTask`] from `(header, target)`, invokes
/// `BitcoinMiningModel::forward`, and returns the [`MiningOutcome`]
/// whose witness's `output_bytes()` are the wire-format Bitcoin
/// header. The resolver chain's iterative-resolution loop (wiki
/// `iterative-resolution.md`) walks the W32 nonce ring internally and
/// returns on first admission; the resolved nonce is the structurally-
/// derived solution to the admission constraint set, not the result of
/// host-boundary enumeration.
///
/// # Errors
///
/// Returns [`MiningFailure::PipelineFailure`] when the catamorphism
/// or a resolver returns a shape violation — canonically, the ψ_9
/// resolver's `InhabitanceImpossibilityWitness` after walking the
/// full W32 ring without admission for the host-supplied `(prefix,
/// target)`.
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

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
    })
}
