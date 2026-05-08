//! prism-btc — the prism implementor for Bitcoin proof-of-work.
//!
//! Real-time structural inference, expressed as a foundation 0.3.3
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
//! `pipeline::run_route`. Foundation 0.3.3's catamorphism evaluator
//! (ADR-029) runs the term tree against the input and attaches the
//! evaluated digest as the `Grounded`'s `output_bytes` (ADR-028); the
//! `Grounded`'s `content_fingerprint` and `unit_address` continue to
//! identify the typed-iso path under
//! `(DefaultHostTypes, PrismBtcBounds, Sha256dHasher)`.
//!
//! Foundation 0.3.3 caps `pipeline::TermValue` at 32 bytes, so the
//! evaluator's `output_bytes` is `Sha256dHasher` over the 32-byte
//! input prefix. The full block hash (over all 80 header bytes, in
//! display order) is carried on [`MiningOutcome::digest`], computed by
//! prism-btc's runtime ([`crate::ops::sha256::sha256d_display`]) using
//! the same `Sha256dHasher` algorithm body the foundation evaluator
//! invokes — so when foundation lifts the per-value ceiling, the
//! typed-iso surface will carry the full block hash automatically.
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

// Cancel hooks for tip-watcher-driven aborts.
pub use ops::traversal::{Cancel, Cancelled, FiberOutcome, NeverCancel};

#[cfg(feature = "std")]
pub use ops::traversal::traverse_parallel;

// Wire-format helpers — used by the bitcoind boundary in prism-btc-node
// to assemble the final 80-byte block bytes.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
