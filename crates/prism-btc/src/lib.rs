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
//!   invokes [`BitcoinMiningModel`]'s `PrismModel::forward` impl.
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
//! - [`mine_with`] / [`TypedCommitment`] / [`EmptyCommitment`] /
//!   [`PayloadCommitment`] / [`TargetCommitment`] / [`AndCommitment`]
//!   — UOR-optimal mining: prism's **zero-cost typed commitment
//!   surface** (architecture §14). Every commitment is monomorphized
//!   per use site — no `Vec`, no dynamic dispatch, no runtime
//!   allocation, no runtime disjointness check. `wellFormed` is
//!   discharged at the type level by the typed commitment's
//!   invariants; the Lean theorem
//!   `Commitment.prf_prob_tight_wellFormed` applies at equality
//!   (declared bandwidth = operational PRF cost, not an upper bound).
//!   The base admission relation `σ(header) ≤ target` is itself a
//!   `TypedCommitment` ([`TargetCommitment`]); [`mine_with`]
//!   composes it with the application payload via
//!   [`AndCommitment`], so the cost model attributes admission as
//!   one typed observable at L_inference rather than as a separate
//!   host-boundary gate. (The substrate move — commitment-parametric
//!   ψ_9 — requires an upstream `PrismModel` arity bump and is
//!   foundation-side ADR work.)
//! - [`Predicate`] / [`Support`] — the primitive typed-predicate
//!   enum (Parity, StratumEq, PAdicEq, UltrametricCloseTo) and its
//!   algebraic-support type. Used by [`TypedCommitment`] implementors
//!   as the building blocks and by individual-predicate cryptanalysis
//!   (`examples/uor_cryptanalysis.rs` §I + §J).
//! - [`KappaObservables`] / [`ExtendedObservables`] — the **receiver-
//!   side** typed lens (architecture §14, ANALYSIS.md §5). The lens is
//!   **total**: every [`MiningOutcome`] carries one, and every
//!   [`MiningFailure::DidNotAdmit`] carries one too. Applications with
//!   custom observables use the const-generic [`ExtendedObservables`].
//! - [`CampaignStats`] — session-level aggregate observatory. Folds
//!   every per-attempt [`KappaObservables`] into stack-allocated
//!   histograms (stratum / spectrum / p-adic at primes {3,5,7}),
//!   tracks empirical α, and converges to the target's theoretical
//!   α at large N. This is what makes mainnet's `α ≈ 2⁻⁷⁷` search
//!   legible — the operator gets typed visibility into a session
//!   that would otherwise be opaque. See `CONFORMANCE.md` §CM.
//! - [`ultrametric_valuation`] / [`walsh_hadamard_parity_at`] /
//!   [`p_adic_valuation`] — UOR observable surface on the content-
//!   addressed manifold (ANALYSIS.md §1.3).
//!
//! [`ARCHITECTURE.md`]: https://github.com/afflom/prism-btc/blob/main/ARCHITECTURE.md

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod campaign;
pub mod commitment;
pub mod diagnostics;
pub mod domain;
pub mod model;
pub mod observables;
pub mod ops;
pub mod pipeline;
pub mod resolvers;
pub mod shapes;
pub mod verbs;

// Public façade — typed surface.
pub use campaign::{CampaignStats, PADIC_BINS, STRATUM_BINS};
pub use commitment::{
    AndCommitment, EmptyCommitment, PayloadCommitment, TargetCommitment, TypedCommitment,
};
pub use diagnostics::{take_resolution_state, ResolutionState};
pub use domain::{
    p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at, Bits, BlockHash,
    BlockHeader, MerkleRoot, MiningTag, MiningWitness, Target, Timestamp, TriadicCoords, Version,
};
pub use model::{BitcoinMiningModel, BitcoinMiningRoute, MiningResult, MiningTask, TemplatePrefix};
pub use observables::{ExtendedObservables, KappaObservables, CANONICAL_PRIMES};
pub use pipeline::{mine, mine_with, MiningFailure, MiningOutcome, Predicate, Support};
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
