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
//! ## The laws
//!
//! Every public body of this crate is a witness to these five axioms.
//! The crate carries no search algorithm, no value‑returning procedure
//! that bypasses re‑derivation, and no shared mutable state at its
//! public surface.
//!
//! - **L1 — identity is content.** Every typed output of the kernel is
//!   the `sha256d:<64hex>` κ‑label of canonical bytes. Block hashes are
//!   not values held by the host; they are addresses minted by the
//!   ψ‑tower from canonical input.
//! - **L2 — operate only on canonical forms.** The kernel admits
//!   recognition only of the ADR‑060 carrier
//!   ([`BlockHeaderCarrier`]) — the borrowed 80‑byte wire‑format
//!   header. Field‑level [`BlockHeader`]s are host‑side ergonomics
//!   that must be serialized to canonical form before they cross the
//!   typed surface.
//! - **L3 — the seal is memory.** A [`MiningOutcome`] is a projection
//!   of `(witness, wire_format_header)`: every field it exposes is
//!   derivable from those two by re‑running the σ‑axis. The kernel
//!   stores no shadow state beyond what the witness already certifies.
//! - **L4 — every output passes through the substrate.** Each κ‑label
//!   the kernel emits is sealed by foundation's
//!   [`BitcoinAddressModel`] (or by one of the six composition models
//!   in [`composition`]) via the shared
//!   [`AddressResolverTuple`](uor_addr::AddressResolverTuple). prism‑btc
//!   carries no resolver code and no parallel σ‑axis.
//! - **L5 — verify by re‑derivation.** Every value the kernel hands
//!   back can be re‑checked by replaying the κ‑derivation:
//!   [`AddressWitness::verify`] re‑certifies the sealed κ‑label, and
//!   [`sha256d_display`] re‑derives the 32‑byte digest from the wire
//!   bytes. No value is trusted on production; every value is
//!   re‑derivable.
//!
//! ## Quick reference
//!
//! - [`mine_at`] — the kernel's sole admission‑recognition entry. One
//!   inference at a given nonce: serializes the header to its 80‑byte
//!   wire form, wraps it in a [`BlockHeaderCarrier`], and asks
//!   foundation's `run_route` to recognize it under the pinned
//!   [`TargetCommitment`]. **The kernel does not search**; if no nonce
//!   in the host's stream admits, the host varies its stream
//!   (extranonce / timestamp / next template) and re‑recognizes.
//! - [`recognize_under`] — scope a target threshold around a closure
//!   that drives [`BitcoinAddressModel`]'s `forward` directly (V&V tests
//!   that exercise the ψ‑pipeline without an admission relation).
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
pub use pipeline::{mine_at, recognize_under, recognize_under_bytes, MiningFailure, MiningOutcome};
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
