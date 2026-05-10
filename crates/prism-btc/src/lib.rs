//! prism-btc — the prism implementor for Bitcoin proof-of-work.
//!
//! Mining inference end-to-end through prism's typed-iso surface
//! (foundation 0.4.1):
//!
//! - **Input shape**: [`MiningTask`] — the 108-byte
//!   `partition_product` of [`TemplatePrefixShape`] (76 bytes) and
//!   [`TargetShape`] (32 bytes), with field access (`input.prefix`,
//!   `input.target`) admitted by ADR-033 G20.
//! - **Output shape**: [`MiningResult`] — the 5-byte coproduct
//!   `(disc, idx_bytes)` foundation's `Term::FirstAdmit` evaluator
//!   produces (ADR-034 Mechanism 2).
//! - **Route**: `nonce_fiber_traversal(input)`, invoking the
//!   [`crate::verbs::nonce_fiber_traversal`] verb whose body is the
//!   wiki's intended structural form
//!   `first_admit(witt_domain::W32, |nonce| hash(concat(input.prefix, nonce)) <= input.target)`.
//! - **Application axis**: [`Sha256dHasher`] (pure-Rust SHA-256d),
//!   promoted to a 1-tuple `AxisTuple` via foundation's blanket
//!   `impl<H: Hasher> AxisTuple for H` (ADR-030).
//!
//! Calling [`mine`] builds a [`MiningTask`] and invokes
//! [`BitcoinMiningModel::forward`]; foundation's catamorphism
//! evaluates the verb's term arena. `Term::FirstAdmit` iterates
//! `nonce` ascending from 0 to 2^32, evaluates the predicate per
//! fiber visit (with the candidate threaded via
//! `FIRST_ADMIT_IDX_NAME_INDEX`), and short-circuits on the first
//! non-zero predicate result. The Grounded's `output_bytes` carries
//! the 5-byte admission coproduct (ADR-028); [`mine`] parses it,
//! reconstructs the admitted 80-byte header, and returns
//! [`MiningOutcome`] with the block-hash digest in display order
//! (computed via the same `Sha256dHasher` algorithm body the
//! catamorphism invoked).
//!
//! There is no implementor-side search loop. Foundation drives the
//! W32 fiber walk through the typed-iso surface end-to-end.
//!
//! See [`ARCHITECTURE.md`](https://github.com/afflom/prism-btc/blob/main/ARCHITECTURE.md)
//! for the normative specification.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod domain;
pub mod model;
pub mod ops;
pub mod pipeline;
pub mod shapes;
pub mod verbs;

// Public façade.
pub use domain::{
    Bits, BlockHash, BlockHeader, MerkleRoot, MiningTag, MiningWitness, Target, Timestamp,
    TriadicCoords, Version,
};
pub use model::{
    BitcoinMiningModel, BitcoinMiningRoute, MiningResult, MiningTask, TargetShape,
    TemplatePrefixShape,
};
pub use pipeline::{block_hash_grounded, mine, MiningFailure, MiningOutcome};
pub use shapes::{PrismBtcBounds, Sha256dHasher};

// Layer-3 verb declaration (wiki ADR-024). `nonce_fiber_traversal_term_arena()`
// returns the verb's structural term-tree fragment foundation evaluates.
pub use verbs::{nonce_fiber_traversal, nonce_fiber_traversal_term_arena};

// Wire-format helpers — used by the bitcoind boundary in prism-btc-node
// to assemble the final 80-byte block bytes.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
