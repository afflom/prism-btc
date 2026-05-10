//! prism-btc's mining pipeline: drives the W32 search end-to-end
//! through foundation 0.4.1's catamorphism via
//! [`BitcoinMiningModel::forward`].
//!
//! The mining inference is one structural commitment in prism
//! vocabulary. There is no implementor-side search loop:
//!
//! 1. The host assembles a [`MiningTask`] from a [`BlockHeader`] and a
//!    [`Target`] (76-byte prefix + 32-byte target threshold).
//! 2. [`BitcoinMiningModel::forward`] is the foundation typed-iso
//!    surface (ADR-020). Its `Route` invokes the
//!    [`crate::verbs::nonce_fiber_traversal`] verb whose body is
//!    `first_admit(witt_domain::W32, |nonce| hash(concat(input.prefix, nonce)) <= input.target)`
//!    (ADR-026 G16, ADR-034 Mechanism 2).
//! 3. `pipeline::run_route` invokes `pipeline::evaluate_term_tree`
//!    (ADR-029). Foundation's `Term::FirstAdmit` fold-rule iterates
//!    `nonce` ascending from 0 to 2^32, evaluates the predicate per
//!    fiber visit (the candidate threaded via
//!    `FIRST_ADMIT_IDX_NAME_INDEX`), short-circuits on the first
//!    non-zero predicate result, and returns a 6-byte coproduct
//!    `(disc, idx_bytes)` for W32 (1 discriminant + 5 BE idx bytes).
//! 4. The Grounded carries the coproduct on `output_bytes` (ADR-028).
//!    [`mine`] parses it: byte 0 is the discriminant (admitted vs.
//!    exhausted); bytes 1..6 are the admitting idx padded to 5 BE
//!    bytes (the high byte is zero for W32; bytes 2..6 carry the
//!    4-byte nonce).
//! 5. On admission, [`mine`] reconstructs the 80-byte canonical
//!    wire-format header (`prefix‖nonce`) and computes the block-hash
//!    digest in display order via
//!    [`crate::ops::sha256::sha256d_display`] — the same algorithm
//!    body `Sha256dHasher` invokes inside the typed-iso surface.

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
use crate::model::{BitcoinMiningModel, MiningTask};
use crate::ops::header::{serialize_header, serialize_prefix};
use crate::ops::sha256::sha256d_display;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// The result of a successful [`mine`] invocation.
///
/// `witness` is the foundation-sealed `Grounded<MiningResult, MiningTag>`
/// the typed-iso pipeline minted (whose `output_bytes` carry the
/// `(disc, nonce)` coproduct value); `nonce`, `digest`, and `coords`
/// are derived host-side observables.
pub struct MiningOutcome {
    pub witness: MiningWitness,
    pub nonce: u32,
    pub digest: [u8; 32],
    pub coords: TriadicCoords,
}

/// Failure modes from [`mine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// All 2^32 fiber points evaluated; no nonce admitted.
    NoMatch,
    /// Foundation rejected the input (shape violation, etc.).
    PipelineFailure,
}

/// **prism-btc's public entry point** — the mining inference task per
/// architecture §5.
///
/// Runs the foundation 0.4.1 catamorphism over the
/// [`crate::verbs::nonce_fiber_traversal`] verb's term arena. The
/// search runs through prism's typed-iso surface end-to-end; there is
/// no implementor-side W32 loop.
pub fn mine(header: &BlockHeader, target: Target) -> Result<MiningOutcome, MiningFailure> {
    let prefix = serialize_prefix(header);
    let target_bytes = target.to_bytes();
    let task = MiningTask::new(prefix, target_bytes);

    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
    >>::forward(task)
    .map_err(|_| MiningFailure::PipelineFailure)?;

    // Foundation 0.4.1 `Term::FirstAdmit` returns a 6-byte coproduct
    // for W32 (the cycle size 2^32 needs 5 BE bytes + 1 disc):
    //   byte 0:    discriminant (0x01 admitted, 0x00 exhausted)
    //   bytes 1..6: admitting idx padded to 5 bytes BE (the high byte
    //               is always 0 for W32 — nonce values are u32, so
    //               bytes 2..6 carry the canonical 4-byte nonce).
    let result_bytes = grounded.output_bytes();
    if result_bytes.len() != 6 {
        return Err(MiningFailure::PipelineFailure);
    }
    if result_bytes[0] != 0x01 {
        return Err(MiningFailure::NoMatch);
    }

    let nonce = u32::from_be_bytes([
        result_bytes[2],
        result_bytes[3],
        result_bytes[4],
        result_bytes[5],
    ]);

    // Reconstruct the admitted 80-byte header and derive the block hash
    // in display order. `sha256d_display` is the same `Sha256dHasher`
    // algorithm body the catamorphism invokes inside `Term::AxisInvocation`,
    // so this digest agrees bit-for-bit with what the typed-iso evaluator
    // produced on its admitting iteration.
    let header_bytes = serialize_header(header, nonce);
    let digest = sha256d_display(&header_bytes);

    Ok(MiningOutcome {
        witness: grounded.tag::<MiningTag>(),
        nonce,
        digest,
        coords: TriadicCoords::from_hash(&digest),
    })
}

/// Re-derive the foundation-sealed witness for a known canonical
/// header without external bitcoind orchestration.
///
/// Convenience surface for tests and downstream consumers that want a
/// `MiningWitness` against a known input. Calls [`mine`] with a
/// permissive target so the foundation evaluator admits immediately
/// at the first nonce.
pub fn block_hash_grounded() -> MiningWitness {
    // Bitcoin genesis-shaped header (version=1, etc.). Permissive target
    // ⇒ FirstAdmit returns at nonce=0; we don't need the genesis nonce
    // for this typed-iso witness.
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
    let outcome = mine(&header, Target::new(0x207fffff)).expect("permissive target admits");
    outcome.witness
}
