//! prism-btc's public entry point — drives the ψ-pipeline mining
//! inference through foundation 0.4.2's catamorphism (architecture §4,
//! §5, §6).
//!
//! 1. The host assembles a [`MiningTask`] from a [`BlockHeader`] and a
//!    [`Target`] (76-byte `TemplatePrefix` + 32-byte `Target`).
//! 2. [`BitcoinMiningModel::forward`] is invoked (wiki ADR-020's 4-axis
//!    typed-iso surface: `HostTypes × HostBounds × Hasher × ResolverTuple`).
//!    Foundation's `pipeline::run_route → pipeline::evaluate_term_tree`
//!    walks the ψ-chain verb arena
//!    ([`crate::verbs::mining_inference`]) dispatching each ψ-Term
//!    through [`crate::resolvers::BitcoinResolverTuple`].
//! 3. The terminal ψ_9 resolver emits the **label** — the 32-byte
//!    output that the `Grounded<MiningResult>::output_bytes()` carries
//!    per ADR-028.
//! 4. [`mine`] decodes the label into a resolved `Nonce`, assembles the
//!    wire-format header, and returns the [`MiningOutcome`].
//!
//! **Bit-identicality (architecture §6).** The label IS the wire-format
//! Bitcoin block bytes once the foundation amendments named in
//! architecture §9.1 land (`AxisProjectionObservable` +
//! `LexicographicLessEqBound`) and the structural admission relation
//! moves from architecture-named to closed-`ConstraintRef`-declared on
//! `MiningResult::CONSTRAINTS`. Until then, the label is the
//! structural content-address the ψ-pipeline emits — the architectural
//! pathway is in place; the resolvers' wire-format-correct mapping is
//! tracked upstream.

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::header::{serialize_header, serialize_prefix};
use crate::ops::sha256::sha256d_display;
use crate::resolvers::BitcoinResolverTuple;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// The result of a successful [`mine`] invocation.
///
/// `witness` is the foundation-sealed `Grounded<MiningResult, MiningTag>`
/// the ψ-pipeline catamorphism minted; its `output_bytes()` carry the
/// label (the terminal ψ_9 output, architecture §4). `nonce`, `digest`,
/// and `coords` are derived host-side observables.
pub struct MiningOutcome {
    pub witness: MiningWitness,
    pub nonce: u32,
    pub digest: [u8; 32],
    pub coords: TriadicCoords,
}

/// Failure modes from [`mine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// Foundation rejected the input (shape violation, resolver gap,
    /// etc.) during catamorphism evaluation. `PipelineFailure` covers
    /// both genuine shape violations and the resolver-absent /
    /// foundation-gap cases named in architecture §9.
    PipelineFailure,
    /// The ψ-pipeline produced a label, but the label's bytes did not
    /// decode to a wire-format-valid Bitcoin block under the
    /// host-supplied template. With the foundation amendments named in
    /// architecture §9.1 still pending, this is the expected failure
    /// mode for non-trivial templates.
    LabelDoesNotDecodeToWireFormat,
}

/// **prism-btc's public entry point** — the ψ-pipeline mining inference
/// per architecture §5.
///
/// Builds a [`MiningTask`] from `(header, target)`, invokes
/// `BitcoinMiningModel::forward`, decodes the resolved nonce from the
/// label, and reconstructs the wire-format header bytes.
///
/// # Errors
///
/// - [`MiningFailure::PipelineFailure`] when the catamorphism evaluation
///   rejects the typed input or a resolver returns a shape violation.
/// - [`MiningFailure::LabelDoesNotDecodeToWireFormat`] when the
///   ψ-pipeline emits a label whose decoded `(header, nonce)` is not
///   wire-format-valid against the host's target. See architecture §9.1
///   for the foundation amendment that closes this gap.
pub fn mine(header: &BlockHeader, target: Target) -> Result<MiningOutcome, MiningFailure> {
    let prefix = serialize_prefix(header);
    let target_bytes = target.to_bytes();
    let task = MiningTask::new(prefix, target_bytes);

    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .map_err(|_| MiningFailure::PipelineFailure)?;

    // The label is the terminal ψ_9 output (32 bytes, architecture §2.2).
    // Decode the resolved nonce from the leading 4 bytes.
    let label = grounded.output_bytes();
    if label.len() < 4 {
        return Err(MiningFailure::PipelineFailure);
    }
    let nonce = u32::from_le_bytes([label[0], label[1], label[2], label[3]]);

    let header_bytes = serialize_header(header, nonce);
    let digest = sha256d_display(&header_bytes);

    if !target.is_satisfied_by_bytes(&digest) {
        return Err(MiningFailure::LabelDoesNotDecodeToWireFormat);
    }

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
    })
}

/// Re-derive the foundation-sealed witness for a permissive template
/// without external bitcoind orchestration.
///
/// Convenience surface for tests and downstream consumers. Currently
/// returns a witness for a permissive-target template; with the
/// foundation amendments of architecture §9.1, this will return the
/// foundation-sealed witness for a wire-format-valid Bitcoin block.
pub fn block_hash_grounded() -> Result<MiningWitness, MiningFailure> {
    let merkle: [u8; 32] = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    let header = BlockHeader {
        version: crate::domain::Version(1),
        prev_hash: [0u8; 32],
        merkle_root: crate::domain::MerkleRoot::from_bytes(merkle),
        timestamp: crate::domain::Timestamp(1231006505),
        bits: crate::domain::Bits(0x1d00ffff),
    };
    let outcome = mine(&header, Target::new(0x207fffff))?;
    Ok(outcome.witness)
}
