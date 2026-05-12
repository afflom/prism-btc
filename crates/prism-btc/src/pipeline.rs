//! prism-btc's public entry point — the ψ-pipeline mining inference
//! per architecture §5, §6.
//!
//! 1. The host assembles a [`MiningTask`] from a [`BlockHeader`] and a
//!    [`Target`] (76-byte `TemplatePrefix` + 32-byte `Target`).
//! 2. [`BitcoinMiningModel::forward`] invokes the ψ-chain verb
//!    ([`crate::verbs::mining_inference`]) end-to-end via foundation
//!    0.4.5's catamorphism. The catamorphism dispatches each
//!    resolver-bound ψ-Term through
//!    [`crate::resolvers::BitcoinResolverTuple`].
//! 3. The terminal ψ_9 resolver
//!    ([`crate::resolvers::BitcoinKInvariantResolver`]) emits the
//!    **κ-label** — 80 bytes that ARE the wire-format Bitcoin header
//!    by construction (architecture §6 bit-identicality contract).
//! 4. [`mine`] computes the block-hash digest from the κ-label and
//!    returns [`MiningOutcome`].

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::sha256::sha256d_display;
use crate::resolvers::BitcoinResolverTuple;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// The result of a [`mine`] invocation.
///
/// - `witness` — the foundation-sealed `Grounded<MiningResult, MiningTag>`
///   the ψ-pipeline catamorphism minted; its `output_bytes()` carry the
///   80-byte κ-label = wire-format Bitcoin header.
/// - `nonce` — the resolved nonce extracted from κ-label bytes 76..80
///   (canonical Bitcoin little-endian).
/// - `digest` — the SHA-256d block-hash digest of the wire-format
///   header, in display order.
/// - `coords` — the digest's triadic coordinates.
/// - `admits` — whether the wire-format header's digest satisfies the
///   host-supplied target lexicographically. The structural ψ-pipeline
///   is pure-parametric (no enumeration, no search); the κ-label is
///   the deterministic content-addressed projection of the typed input.
///   For permissive targets this is reliably `true`; for restrictive
///   targets the host boundary may iterate over template-derived
///   `MiningTask` variations (architecture §7) before an admitting
///   header is found.
pub struct MiningOutcome {
    pub witness: MiningWitness,
    pub nonce: u32,
    pub digest: [u8; 32],
    pub coords: TriadicCoords,
    pub admits: bool,
}

/// Failure modes from [`mine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// Foundation's catamorphism rejected the typed input or a
    /// resolver returned a shape violation.
    PipelineFailure,
}

/// **prism-btc's public entry point** — the ψ-pipeline mining inference.
///
/// Builds a [`MiningTask`] from `(header, target)`, invokes
/// `BitcoinMiningModel::forward` (which drives the ψ-pipeline through
/// foundation's catamorphism), and returns the [`MiningOutcome`] whose
/// `witness.output_bytes()` are the wire-format Bitcoin header.
///
/// # Errors
///
/// Returns [`MiningFailure::PipelineFailure`] when the catamorphism
/// evaluation rejects the typed input or a resolver returns a shape
/// violation. The ψ-pipeline itself is deterministic and parametric;
/// pipeline rejection means foundation's typed-iso surface invariants
/// were violated, which should not happen for well-formed `(header,
/// target)` inputs.
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
    let admits = target.is_satisfied_by_bytes(&digest);

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
        admits,
    })
}
