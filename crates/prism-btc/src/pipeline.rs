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
//! 4. [`mine`] verifies the κ-derived header admits the host-supplied
//!    target and, on admission, returns the [`MiningOutcome`]. When
//!    the κ-label doesn't admit, [`mine`] returns
//!    [`MiningFailure::DidNotAdmit`] — the host boundary (architecture
//!    §7) varies the template-derived `MiningTask` (extranonce roll,
//!    timestamp slack, transaction-set selection) and retries until an
//!    admitting κ-label lands.
//!
//! **Fail-closed contract.** `mine()` never returns a `MiningOutcome`
//! whose `digest` does not satisfy the host-supplied `Target`. Valid
//! input either produces a valid mined-block header or surfaces a
//! `DidNotAdmit` for the host to handle.

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::sha256::sha256d_display;
use crate::resolvers::BitcoinResolverTuple;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// The result of a successful [`mine`] invocation. The wire-format
/// 80-byte Bitcoin header carried by `witness.output_bytes()` is
/// guaranteed to satisfy the host-supplied target — `mine()` only
/// returns `Ok(MiningOutcome)` when admission holds.
pub struct MiningOutcome {
    /// Foundation-sealed `Grounded<MiningResult, MiningTag>`; its
    /// `output_bytes()` are the 80-byte wire-format Bitcoin header.
    pub witness: MiningWitness,
    /// The resolved nonce (canonical Bitcoin LE, bytes 76..80 of the
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
    /// Foundation's catamorphism rejected the typed input or a
    /// resolver returned a shape violation.
    PipelineFailure,
    /// The ψ-pipeline ran end-to-end and produced a deterministic
    /// 80-byte wire-format header, but the host-supplied target was
    /// not satisfied by that header's digest. The host boundary
    /// (architecture §7) varies the template-derived `MiningTask`
    /// (extranonce roll, timestamp slack, transaction-set selection)
    /// and retries `mine()` with the new input.
    DidNotAdmit,
}

/// **prism-btc's public entry point** — one ψ-pipeline mining
/// inference per call.
///
/// Builds a [`MiningTask`] from `(header, target)`, invokes
/// `BitcoinMiningModel::forward`, and returns the [`MiningOutcome`]
/// **only** when the κ-derived wire-format header admits the
/// host-supplied target.
///
/// # Errors
///
/// - [`MiningFailure::PipelineFailure`] — foundation's catamorphism
///   or a resolver returned a shape violation.
/// - [`MiningFailure::DidNotAdmit`] — the ψ-pipeline produced a
///   wire-format header whose digest did not satisfy the target. The
///   host boundary varies the typed input and retries.
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

    if !target.is_satisfied_by_bytes(&digest) {
        return Err(MiningFailure::DidNotAdmit);
    }

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
    })
}
