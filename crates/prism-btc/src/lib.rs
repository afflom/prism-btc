//! prism-btc — Bitcoin proof-of-work as a **UOR-ADDR realization**.
//!
//! prism-btc content-addresses Bitcoin block headers through uor-addr's
//! shared addressing surface (ADR-031 / ADR-036 / ADR-060): a block
//! header is the canonical-form input, the `sha256d` σ-axis is the
//! content-addressing primitive, and the κ-label ψ₉ emits —
//! `sha256d:<64hex>` — is the conventional Bitcoin block hash. The
//! difficulty target is the cost-model commitment (ADR-048): foundation
//! evaluates `kappa_label ≤ target_label` inside `run_route`, which is
//! exactly Bitcoin's PoW relation `block_hash ≤ target`. The replayable
//! TC-05 [`AddressWitness`] the outcome carries **is** the proof-of-work
//! witness — the catamorphism's seal. See [`ARCHITECTURE.md`].
//!
//! ## Quick reference
//!
//! - [`mine`] / [`mine_at`] — the public entry points. [`mine`] scans the
//!   nonce space for an admitting block hash; [`mine_at`] does one
//!   inference at a given nonce. Both serialize the header to its 80-byte
//!   wire form, wrap it in a [`BlockHeaderCarrier`], and run
//!   [`BitcoinAddressModel`]; admission is evaluated **inside foundation's
//!   `run_route`** via the pinned [`TargetCommitment`].
//! - [`BitcoinAddressModel`] — `PrismModel<DefaultHostTypes, PrismBtcBounds,
//!   Sha256dHasher, uor_addr::AddressResolverTuple<Sha256dHasher>,
//!   TargetCommitment>`. It binds uor-addr's **shared, format-independent**
//!   ψ-tower (prism-btc carries no resolver code) and the difficulty
//!   commitment in the ADR-048 5th slot.
//! - [`BlockHeaderCarrier`] — the ADR-060 borrowed canonical-form input
//!   handle over the 80-byte serialized header.
//! - [`BlockAddressLabel`] — the ψ-pipeline output shape: the 72-byte
//!   `sha256d:<64hex>` κ-label (72 disjoint `Site` constraints).
//! - [`Sha256dHasher`] — the `sha256d` σ-axis (double-SHA-256, display-order
//!   finalize); a foundation `Hasher<32>` **and** a [`uor_addr::AddrHash`].
//! - [`PrismBtcBounds`] — the `HostBounds` profile (alias for the shared
//!   [`uor_addr::AddrBounds`]).
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
pub mod composition;
pub mod domain;
pub mod model;
pub mod observables;
pub mod ops;
pub mod pipeline;
pub mod shapes;

/// Re-export of [`uor_addr`] — the UOR-ADDR standard-library surface
/// prism-btc realizes. Downstream crates reach the shared addressing
/// vocabulary (`AddressResolverTuple`, `AddrBounds`, `AddrHash`,
/// `AddressOutcome`/`AddressWitness`, `KappaLabel`) and the ADR-061
/// `composition` framework through this re-export.
pub use uor_addr;

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
pub use domain::{
    p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at, Bits, BlockHash,
    BlockHeader, MerkleRoot, MiningWitness, Target, Timestamp, TriadicCoords, Version,
};
pub use model::{
    block_address_inference, BitcoinAddressModel, BitcoinAddressRoute, BlockAddressLabel,
    BlockHeaderCarrier, BLOCK_ADDRESS_LABEL_BYTES, HEADER_BYTES,
    VERB_TERMS_BLOCK_ADDRESS_INFERENCE,
};
pub use observables::{ExtendedObservables, KappaObservables, CANONICAL_PRIMES};
pub use pipeline::{
    current_thread_target, mine, mine_at, set_thread_target, set_thread_target_bytes,
    MiningFailure, MiningOutcome,
};
pub use shapes::{PrismBtcBounds, Sha256dHasher};

// The shared UOR-ADDR outcome surface, re-exported for downstream use.
pub use uor_addr::{AddressOutcome, AddressWitness, KappaLabel};

// The ADR-061 composition framework for the `sha256d` axis — prism-btc's
// reference realization (the five categorical operations + the ordered
// product + Bitcoin merkle as iterated composition).
pub use composition::{
    block_label_from_digest, compose_e6_filtration, compose_e7_augmentation, compose_e8_embedding,
    compose_f4_quotient, compose_g2_product, compose_ordered_product, merkle_root,
    CompositionFailure, CompositionOutcome,
};

// Wire-format helpers — boundary-only, not part of the ψ-pipeline
// transform. Used by prism-btc-node to assemble wire-format block bytes
// for `submitblock`.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
