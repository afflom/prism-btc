//! prism-btc — the prism implementor for Bitcoin proof-of-work.
//!
//! Real-time structural inference, expressed as a foundation 0.3.4
//! `PrismModel<H, B, A>`: the input shape is the 80-byte canonical
//! Bitcoin block header ([`MiningInput`]); the output shape is
//! foundation's `ConstrainedTypeInput`; the route is `hash(input)`,
//! lowered by `prism_model!` to a `Term::HasherProjection` over the
//! input variable; the application `Hasher` is [`Sha256dHasher`]
//! (pure-Rust SHA-256d).
//!
//! prism-btc owns the W32 nonce-fiber traversal that finds the
//! admitting fiber point ([`mine`], [`mine_parallel`]). On admission,
//! the 80-byte header is wrapped in [`MiningInput`] and fed through
//! `BitcoinMiningModel::forward`, which delegates to foundation's
//! `pipeline::run_route`. Foundation 0.3.4's catamorphism evaluator
//! (ADR-029) carries the full 80-byte input through the per-value
//! buffer (`TERM_VALUE_MAX_BYTES = 4096`) and folds it through
//! `Sha256dHasher`; the resulting 32-byte digest is attached to the
//! `Grounded` as `output_bytes` (ADR-028). The `Grounded`'s
//! `content_fingerprint` and `unit_address` identify the typed-iso
//! path under `(DefaultHostTypes, PrismBtcBounds, Sha256dHasher)`.
//!
//! **The Grounded's `output_bytes` IS the Bitcoin block hash** in the
//! Hasher's internal byte order; reversed, it is the canonical block
//! hash in display order. [`MiningOutcome::digest`] carries the same
//! digest in display order as a convenience for callers consuming the
//! protocol-level hash; both come from the same `Sha256dHasher` body.
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
pub use model::{BitcoinMiningModel, BitcoinMiningRoute, MiningInput};
pub use pipeline::{block_hash_grounded, mine, MiningFailure, MiningOutcome};
pub use shapes::{PrismBtcBounds, Sha256dHasher};

#[cfg(feature = "std")]
pub use pipeline::mine_parallel;

// Layer-3 verb declarations (wiki ADR-024). `nonce_fiber_traversal_term_arena()`
// returns the verb's structural term-tree fragment; the runtime that evaluates
// it is `ops::traversal` per ADR-026 G16's three-way responsibility split.
pub use verbs::{nonce_fiber_traversal, nonce_fiber_traversal_term_arena};

// Cancel hooks for tip-watcher-driven aborts.
pub use ops::traversal::{Cancel, Cancelled, FiberOutcome, NeverCancel};

#[cfg(feature = "std")]
pub use ops::traversal::traverse_parallel;

// Wire-format helpers — used by the bitcoind boundary in prism-btc-node
// to assemble the final 80-byte block bytes.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
