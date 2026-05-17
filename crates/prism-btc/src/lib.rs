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
//!   Admission (`digest ≤ target` under big-endian unsigned
//!   comparison) is evaluated **inside foundation's `run_route`** via
//!   the model's pinned [`TargetCommitment`].
//! - [`BitcoinMiningModel`] — `PrismModel<HostTypes, HostBounds, Hasher,
//!   ResolverTuple, TargetCommitment>` (wiki ADR-048 5-position form;
//!   foundation 0.4.12). The 5th slot is the cost-model commitment
//!   surface; pinning it at [`TargetCommitment`] = foundation alias
//!   `SingletonCommitment<LexicographicLessEqThreshold>` (wiki
//!   ADR-040) makes Bitcoin's admission relation a typed predicate
//!   evaluated inside the catamorphism per wiki QS-06.
//! - [`MiningTask`] — `partition_product(TemplatePrefix, Target)`,
//!   108 W8 sites.
//! - [`MiningResult`] — the ψ-pipeline label (32 W8 sites — the
//!   SHA-256d digest, the natural cost-model κ-label per wiki
//!   ADR-048/049).
//! - [`Sha256dHasher`] — the canonical hash axis (content-addressing
//!   primitive).
//! - [`PrismBtcBounds`] — the `HostBounds` profile (`WITT_LEVEL_MAX_BITS = 32`).
//! - [`ResolutionState`] / [`take_resolution_state`] — diagnostic
//!   surface for ψ_9's structural κ-derivation
//!   ([`diagnostics`] module).
//! - **Cost-model commitment surface** —
//!   [`TypedCommitment`] / [`EmptyCommitment`] / [`SingletonCommitment`] /
//!   [`AndCommitment`] / [`TargetCommitment`] (wiki ADR-048) and the five
//!   canonical [`ObservablePredicate`] impls
//!   [`Stratum`] / [`WalshHadamardParity`] / [`UltrametricCloseTo`] /
//!   [`AffineParity`] / [`LexicographicLessEqThreshold`] (wiki ADR-049)
//!   are re-exported from foundation. Every commitment shape is
//!   `Copy + Sealed`, monomorphized per use site — no `Vec`, no
//!   dynamic dispatch, no runtime allocation. The Lean theorem
//!   `Commitment.prf_prob_tight_wellFormed` applies at equality
//!   (declared bandwidth = operational PRF cost, not an upper bound).
//!   Application authors who want K-fold typed payload commitments
//!   compose them with prism-btc's [`payload_commitment_k2`] /
//!   [`payload_commitment_k4`] / [`payload_commitment_k8`] helpers
//!   (each producing an [`AndCommitment`] tree of
//!   `SingletonCommitment<AffineParity>` leaves per wiki QS-06's
//!   K-fold exemplar) and declare a derived [`prism::pipeline::PrismModel`]
//!   with the composed `C` shape.
//! - [`leak_target`] / [`leak_reference`] / [`leak_frequency`] —
//!   helpers that promote runtime-derived 32-byte buffers to
//!   `&'static [u8]` (foundation's predicate fields require `'static`
//!   bytes since predicates are `Copy`). The registry deduplicates;
//!   repeated calls with the same bytes return the same pinned
//!   reference.
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

// Cost-model commitment surface — foundation's canonical
// `TypedCommitment` (wiki ADR-048) plus the five `ObservablePredicate`
// impls (wiki ADR-049), all re-exported through prism-btc for
// applications that want to declare derived `PrismModel<…, C>`s
// composing `TargetCommitment` with additional typed payload
// predicates.
pub use commitment::{
    decode_payload, leak_frequency, leak_reference, leak_target, payload_bit,
    payload_commitment_k2, payload_commitment_k4, payload_commitment_k8, target_commitment,
    AffineParity, AndCommitment, EmptyCommitment, LexicographicLessEqThreshold,
    ObservablePredicate, PayloadK2, PayloadK4, PayloadK8, SingletonCommitment, Stratum,
    TargetCommitment, TypedCommitment, UltrametricCloseTo, WalshHadamardParity,
};
pub use diagnostics::{take_resolution_state, ResolutionState};
pub use domain::{
    p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at, Bits, BlockHash,
    BlockHeader, MerkleRoot, MiningTag, MiningWitness, Target, Timestamp, TriadicCoords, Version,
};
pub use model::{BitcoinMiningModel, BitcoinMiningRoute, MiningResult, MiningTask, TemplatePrefix};
pub use observables::{ExtendedObservables, KappaObservables, CANONICAL_PRIMES};
pub use pipeline::{
    current_thread_target, mine, set_thread_target, set_thread_target_bytes, MiningFailure,
    MiningOutcome,
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
