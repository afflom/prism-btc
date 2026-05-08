//! prism-btc's mining pipeline: traverses the W32 fiber over a (prefix,
//! target) pair, mints the foundation-sealed shape `Grounded` on
//! admission, returns the (witness, nonce, digest).
//!
//! The architecture's `mine()` entry point. Foundation 0.3.2 provides the
//! sealed `Grounded` mint via `PrismModel::forward` (which delegates to
//! `pipeline::run_route` per ADR-022 D5); prism-btc provides the W32
//! traversal that finds the admitting fiber point.

use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

use crate::domain::{BlockHeader, MiningTag, MiningWitness, Target, TriadicCoords};
use crate::model::{BitcoinMiningModel, MiningInput};
use crate::ops::header::serialize_header;
use crate::ops::traversal::{traverse_sequential, Cancel, Cancelled, FiberOutcome};
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// Mint the prism-btc shape `Grounded` for an admitted (header, nonce)
/// pair via foundation's typed-iso pipeline.
///
/// The 80-byte canonical wire-format header is wrapped in
/// [`MiningInput`] and passed to `BitcoinMiningModel::forward`, which
/// delegates to `pipeline::run_route` (ADR-022 D5). Three things
/// happen:
///
/// 1. `Sha256dHasher` folds the 80 input bytes to derive the
///    input-binding's `content_address` (ADR-023).
/// 2. Foundation 0.3.3's catamorphism evaluator runs the route's term
///    tree (`hash(input)`, lowered to `Term::HasherProjection`) and
///    attaches the result as the Grounded's `output_bytes` (ADR-028,
///    ADR-029).
/// 3. `pipeline::run` folds the canonical CompileUnit metadata through
///    `Sha256dHasher` to compute `ContentFingerprint` and
///    `unit_address`.
///
/// The 32-byte Bitcoin block hash in display order is on
/// [`MiningOutcome::digest`], computed by prism-btc's runtime
/// (`sha256d_display`) using the same `Sha256dHasher` algorithm body
/// the foundation evaluator invokes inside `HasherProjection`. The
/// evaluator's `output_bytes` carries `Sha256dHasher` of the input
/// prefix that fits in foundation's `TERM_VALUE_MAX_BYTES = 32`
/// per-value ceiling.
fn mint_witness(header_bytes: [u8; 80]) -> MiningWitness {
    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
    >>::forward(MiningInput(header_bytes))
    .expect(
        "BitcoinMiningModel::forward is infallible against well-formed inputs (\
         MAX_BYTES <= ROUTE_INPUT_BUFFER_BYTES, identity route, const-validated \
         arena); a failure here indicates foundation drift",
    );
    grounded.tag::<MiningTag>()
}

/// The result of a successful `mine` invocation.
#[derive(Debug)]
pub struct MiningOutcome {
    pub witness: MiningWitness,
    pub nonce: u32,
    pub digest: [u8; 32],
    pub coords: TriadicCoords,
}

/// Failure modes from `mine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// All 2^32 fiber points evaluated; none satisfied the target.
    NoMatch,
    /// The boundary cancelled the in-flight traversal.
    Cancelled,
}

/// **prism-btc's public entry point** — the mining inference task per
/// architecture §5.
pub fn mine(
    header: &BlockHeader,
    target: Target,
    cancel: &dyn Cancel,
) -> Result<MiningOutcome, MiningFailure> {
    let prefix = crate::ops::header::serialize_prefix(header);
    let target_bytes = target.to_bytes();

    let outcome = traverse_sequential(&prefix, &target_bytes, cancel)
        .map_err(|Cancelled| MiningFailure::Cancelled)?;

    match outcome {
        FiberOutcome::Admitted { nonce, digest } => {
            let header_bytes = serialize_header(header, nonce);
            Ok(MiningOutcome {
                witness: mint_witness(header_bytes),
                nonce,
                digest,
                coords: TriadicCoords::from_hash(&digest),
            })
        }
        FiberOutcome::Exhausted => Err(MiningFailure::NoMatch),
    }
}

/// Parallel variant — partitions the W32 ring across `threads`
/// workers in the natural coset partition; first-finder wins.
#[cfg(feature = "std")]
pub fn mine_parallel(
    header: &BlockHeader,
    target: Target,
    threads: usize,
    cancel: &(dyn Cancel + Sync),
) -> Result<MiningOutcome, MiningFailure> {
    use crate::ops::traversal::traverse_parallel;
    let prefix = crate::ops::header::serialize_prefix(header);
    let target_bytes = target.to_bytes();

    let outcome = traverse_parallel(&prefix, &target_bytes, threads, cancel)
        .map_err(|Cancelled| MiningFailure::Cancelled)?;

    match outcome {
        FiberOutcome::Admitted { nonce, digest } => {
            let header_bytes = serialize_header(header, nonce);
            Ok(MiningOutcome {
                witness: mint_witness(header_bytes),
                nonce,
                digest,
                coords: TriadicCoords::from_hash(&digest),
            })
        }
        FiberOutcome::Exhausted => Err(MiningFailure::NoMatch),
    }
}

/// Re-derive the foundation-sealed witness for the canonical genesis
/// header (Bitcoin block 0). Carries no fiber traversal — produces the
/// `Grounded` directly via `BitcoinMiningModel::forward` over the genesis
/// 80-byte header bytes.
pub fn block_hash_grounded() -> MiningWitness {
    // Bitcoin genesis: version=1, prev_hash=0, merkle=…, time=1231006505,
    // bits=0x1d00ffff, nonce=2083236893.
    let merkle: [u8; 32] = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&1u32.to_le_bytes());
    header[36..68].copy_from_slice(&merkle);
    header[68..72].copy_from_slice(&1231006505u32.to_le_bytes());
    header[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
    header[76..80].copy_from_slice(&2083236893u32.to_le_bytes());
    mint_witness(header)
}
