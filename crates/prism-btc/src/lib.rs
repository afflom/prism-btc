//! prism-btc — the prism implementor for Bitcoin proof-of-work.
//!
//! Mining inference end-to-end through prism's typed-iso surface
//! (foundation 0.4.5). The mining transform is the ψ-pipeline
//! (wiki ADR-035) applied to Bitcoin's typed feature hierarchy
//! (architecture §2); the catamorphism dispatches each resolver-bound
//! ψ-stage through [`resolvers::BitcoinResolverTuple`] (ADR-036). No
//! σ-enumeration anywhere — see [`ARCHITECTURE.md`] for the normative
//! pure-prism specification.
//!
//! ## Quick reference
//!
//! - [`mine`] — the public entry point: builds a [`MiningTask`] and
//!   invokes [`BitcoinMiningModel::forward`].
//! - [`BitcoinMiningModel`] — `PrismModel<HostTypes, HostBounds, Hasher,
//!   ResolverTuple>` whose route is `mining_inference(input)`.
//! - [`MiningTask`] — `partition_product(TemplatePrefix, Target)`,
//!   108 W8 sites.
//! - [`MiningResult`] — the ψ-pipeline label (32 W8 sites).
//! - [`Sha256dHasher`] — the canonical hash axis (content-addressing
//!   primitive).
//! - [`PrismBtcBounds`] — the `HostBounds` profile (`WITT_LEVEL_MAX_BITS = 32`).
//!
//! [`ARCHITECTURE.md`]: https://github.com/afflom/prism-btc/blob/main/ARCHITECTURE.md

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod domain;
pub mod model;
pub mod ops;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod verbs;

// Public façade — typed surface.
pub use domain::{
    Bits, BlockHash, BlockHeader, MerkleRoot, MiningTag, MiningWitness, Target, Timestamp,
    TriadicCoords, Version,
};
pub use model::{BitcoinMiningModel, BitcoinMiningRoute, MiningResult, MiningTask, TemplatePrefix};
pub use pipeline::{mine, MiningFailure, MiningOutcome};
pub use resolvers::{
    BitcoinChainComplexResolver, BitcoinCochainComplexResolver, BitcoinCohomologyGroupResolver,
    BitcoinHomologyGroupResolver, BitcoinHomotopyGroupResolver, BitcoinKInvariantResolver,
    BitcoinNerveResolver, BitcoinPostnikovResolver, BitcoinResolverTuple,
};
pub use shapes::{PrismBtcBounds, Sha256dHasher};

// Layer-3 verb declaration (wiki ADR-024). `mining_inference_term_arena()`
// returns the ψ-chain term-tree fragment foundation evaluates.
pub use verbs::{mining_inference, VERB_TERMS_MINING_INFERENCE};

// Wire-format helpers — boundary-only, not part of the ψ-pipeline
// transform. Used by prism-btc-node to assemble wire-format block bytes
// for `submitblock`.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
