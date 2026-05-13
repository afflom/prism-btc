//! prism-btc — the prism implementor for Bitcoin proof-of-work.
//!
//! Mining inference end-to-end through prism's typed-iso surface. The
//! mining transform is the k-invariant branch of the ψ-pipeline
//! (wiki ADR-035) applied to Bitcoin's typed feature hierarchy
//! (architecture §2, §4); foundation's catamorphism dispatches each
//! resolver-bound ψ-stage through [`resolvers::BitcoinResolverTuple`]
//! (ADR-036). No σ-enumeration in the verb body — see
//! [`ARCHITECTURE.md`] for the normative pure-prism specification.
//!
//! ## Quick reference
//!
//! - [`mine`] — the public entry point: builds a [`MiningTask`] and
//!   invokes [`BitcoinMiningModel::forward`].
//! - [`BitcoinMiningModel`] — `PrismModel<HostTypes, HostBounds, Hasher,
//!   ResolverTuple>` whose route is `mining_inference(input)`.
//! - [`MiningTask`] — `partition_product(TemplatePrefix, Target)`,
//!   108 W8 sites.
//! - [`MiningResult`] — the ψ-pipeline label (80 W8 sites — the
//!   wire-format Bitcoin header width).
//! - [`Sha256dHasher`] — the canonical hash axis (content-addressing
//!   primitive).
//! - [`PrismBtcBounds`] — the `HostBounds` profile (`WITT_LEVEL_MAX_BITS = 32`).
//! - [`ResolutionState`] / [`take_resolution_state`] — diagnostic
//!   surface for ψ_9's structural κ-derivation
//!   ([`diagnostics`] module).
//! - [`mine_with_commitment`] / [`MiningCommitment`] /
//!   [`Predicate`] — UOR-optimal mining: typed Conjunction
//!   commitment on the κ-label (architecture §14). The
//!   [`Predicate`] enum covers Walsh-Hadamard parity, stratum
//!   equality, p-adic equality, and ultrametric closeness — each a
//!   typed observable on the content-addressed manifold.
//! - [`Support`] / [`CommitmentError`] — the algebraic-support
//!   type and the error returned by [`MiningCommitment::try_add_predicate`]
//!   when a new predicate's support overlaps an existing one. The
//!   typed builders enforce support-disjointness, making
//!   [`MiningCommitment::bandwidth_bits`] a tight cost contract by
//!   construction (U6 Bandwidth-Additivity, architecture §14.2).
//! - [`ultrametric_valuation`] / [`walsh_hadamard_parity_at`] /
//!   [`p_adic_valuation`] — UOR observable surface on the content-
//!   addressed manifold (ANALYSIS.md §1.3).
//!
//! [`ARCHITECTURE.md`]: https://github.com/afflom/prism-btc/blob/main/ARCHITECTURE.md

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod diagnostics;
pub mod domain;
pub mod model;
pub mod ops;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod verbs;

// Public façade — typed surface.
pub use diagnostics::{take_resolution_state, ResolutionState};
pub use domain::{
    p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at, Bits, BlockHash,
    BlockHeader, MerkleRoot, MiningTag, MiningWitness, Target, Timestamp, TriadicCoords, Version,
};
pub use model::{BitcoinMiningModel, BitcoinMiningRoute, MiningResult, MiningTask, TemplatePrefix};
pub use pipeline::{
    mine, mine_with_commitment, CommitmentError, MiningCommitment, MiningFailure, MiningOutcome,
    Predicate, Support,
};
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
