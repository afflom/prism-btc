//! prism-btc — **Bitcoin block-address derivation** as a UOR-ADDR
//! realization.
//!
//! prism-btc content-addresses Bitcoin block headers through uor-addr's
//! shared addressing surface (ADR-031 / ADR-036 / ADR-060): an 80-byte
//! wire-format header is the canonical-form input, the `sha256d` σ-axis
//! is the content-addressing primitive, and the κ-label ψ₉ emits —
//! `sha256d:<64hex>` — is the conventional Bitcoin block hash. The
//! replayable TC-05 [`AddressWitness`] the outcome carries is the
//! catamorphism's seal, re-derivable offline without re-invoking the
//! σ-axis.
//!
//! **The kernel is κ-derivation only.** It does **not** embed PoW
//! admission, does **not** carry a target threshold, does **not** loop
//! over nonce candidates, does **not** present mining as a kernel
//! operation. Bitcoin's `block_hash ≤ target` relation is a
//! **protocol-level observation** on the κ-label — host code that wants
//! to mine reads the κ-label's 32-byte digest and compares it to a
//! target directly. The legacy "mining loop" lives entirely in the
//! protocol code that operates on the addresses this kernel emits;
//! it is **not** wrapped, renamed, or relocated inside prism-btc.
//!
//! ## The laws
//!
//! Every public body of this crate is a witness to these axioms.
//!
//! - **L1 — identity is content.** Every typed output of the kernel is
//!   the `sha256d:<64hex>` κ‑label of canonical bytes. Block hashes are
//!   not values the kernel holds; they are addresses minted by the
//!   ψ‑tower from canonical input.
//! - **L2 — operate only on canonical forms.** The kernel admits one
//!   input shape — the borrowed 80‑byte ADR‑060 wire-format header,
//!   wrapped in [`BlockHeaderCarrier`]. Field‑level [`BlockHeader`]s
//!   are host‑side ergonomics; the host serializes them to canonical
//!   form via [`serialize_header`] before they cross the typed surface.
//! - **L3 — the seal is memory.** An [`AddressOutcome`] is the
//!   κ-label + its witness, period. No eagerly-cached projections;
//!   the host re-derives whatever it needs (digest, observables,
//!   admission against a target) from the κ-label and the
//!   canonical-form input it certifies.
//! - **L4 — every output passes through the substrate.** Each κ‑label
//!   the kernel emits is sealed by foundation's
//!   [`BitcoinAddressModel`] (or by one of the six composition models
//!   in [`composition`]) via the shared
//!   [`AddressResolverTuple`](uor_addr::AddressResolverTuple). prism‑btc
//!   carries no resolver code and no parallel σ‑axis.
//! - **L5 — verify by re‑derivation.** Every value the kernel hands
//!   back is re‑checkable by replaying the κ‑derivation:
//!   [`AddressWitness::verify`] re‑certifies the sealed κ‑label, and
//!   [`sha256d_display`] re‑derives the 32‑byte digest from the wire
//!   bytes. No value is trusted on production; every value is
//!   re‑derivable.
//! - **L6 — admission is not a kernel concept.** Bitcoin's PoW
//!   admission relation `block_hash ≤ target`, and any other typed
//!   commitment a protocol layers over a κ-label, is **observation on
//!   the address**, not part of the addressing. The kernel exposes the
//!   commitment-shape catalog ([`TypedCommitment`], the predicates,
//!   the K-fold builders) so hosts can construct admission gates over
//!   their own κ-labels; but [`BitcoinAddressModel`] itself binds
//!   `EmptyCommitment` and emits κ-labels unconditionally. Mining is
//!   what protocol code does with addresses.
//!
//! ## Quick reference
//!
//! - [`address_block`] — **the kernel's only entry, and its entire
//!   public admission body.** Given 80 canonical-form wire bytes,
//!   returns the sealed `sha256d:<64hex>` κ-label + witness. One
//!   ψ-pipeline evaluation per call. The ψ-pipeline is total over
//!   well-formed carriers (no `Result`, no failure mode). PoW search
//!   lives in protocol code that calls this per candidate; the kernel
//!   is search-free by construction.
//! - [`BitcoinAddressModel`] —
//!   `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher,
//!   AddressResolverTuple<Sha256dHasher>, EmptyCommitment>`. Binds
//!   uor-addr's shared, format-independent ψ-tower and emits κ-labels
//!   unconditionally — admission is not embedded.
//! - [`BlockHeaderCarrier`] — the ADR-060 borrowed canonical-form
//!   input handle over the 80-byte serialized header.
//! - [`BlockAddressLabel`] — the ψ-pipeline output shape: the 72-byte
//!   `sha256d:<64hex>` κ-label (72 disjoint `Site` constraints).
//! - [`Sha256dHasher`] — the `sha256d` σ-axis (double-SHA-256,
//!   display-order finalize); a foundation `Hasher<32>` and a
//!   [`uor_addr::AddrHash`].
//! - [`KappaObservables`] / [`ExtendedObservables`] — the
//!   **receiver-side** typed lens on a digest: triadic coordinates
//!   (stratum, spectrum), p-adic valuations. Hosts derive these from a
//!   digest as the orthogonal/cyclic coordinate to the κ-label's
//!   extremal/longest-path coordinate (the TROPICAL framing).
//! - **Generic typed-commitment surface** (`commitment` module) —
//!   [`TypedCommitment`] / [`EmptyCommitment`] / [`SingletonCommitment`] /
//!   [`AndCommitment`] and the five canonical [`ObservablePredicate`]
//!   impls ([`Stratum`] / [`WalshHadamardParity`] /
//!   [`UltrametricCloseTo`] / [`AffineParity`] /
//!   [`LexicographicLessEqThreshold`]) re-exported from foundation, plus
//!   the K-fold payload commitment helpers
//!   ([`payload_commitment_k2`] / [`payload_commitment_k4`] /
//!   [`payload_commitment_k8`]). All `Copy + Sealed`. Hosts compose
//!   typed admission gates over their own κ-labels; the Lean theorem
//!   `Commitment.prf_prob_tight_wellFormed` applies at equality.
//! - [`CampaignStats`] — host-side observatory: folds per-attempt
//!   observables + digest into a stack-resident histogram-aggregate.
//!   Useful for hosts that want typed visibility into a mining session.
//! - [`composition`] — the ADR-061 composition framework realized
//!   for `sha256d`: the five categorical operations + the ordered
//!   product + Bitcoin's merkle root as the iterated-composition
//!   Kleene closure.
//! - [`ultrametric_valuation`] / [`walsh_hadamard_parity_at`] /
//!   [`p_adic_valuation`] — UOR observable surface on the
//!   content-addressed manifold.

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
/// prism-btc realizes.
pub use uor_addr;

// Receiver-side observatory.
pub use campaign::{CampaignStats, PADIC_BINS, STRATUM_BINS};

// Generic typed-commitment surface (foundation re-exports + K-fold
// payload commitment helpers). Bitcoin-specific admission code (the
// previous TargetCommitment alias + leak-registry + target_label_bytes
// infrastructure) has been removed — admission is not a kernel concept.
pub use commitment::{
    decode_payload, payload_bit, payload_commitment_k2, payload_commitment_k4,
    payload_commitment_k8, AffineParity, AndCommitment, EmptyCommitment,
    LexicographicLessEqThreshold, ObservablePredicate, PayloadK2, PayloadK4, PayloadK8,
    SingletonCommitment, Stratum, TypedCommitment, UltrametricCloseTo, WalshHadamardParity,
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
pub use pipeline::{address_block, BlockAddress};
pub use shapes::{PrismBtcBounds, Sha256dHasher};

// The shared UOR-ADDR outcome surface.
pub use uor_addr::{AddressOutcome, AddressWitness, KappaLabel};

// ADR-061 composition framework for the `sha256d` axis — the five
// categorical operations + the ordered product + merkle root as the
// iterated-composition Kleene closure.
pub use composition::{
    block_label_from_digest, compose_e6_filtration, compose_e7_augmentation, compose_e8_embedding,
    compose_f4_quotient, compose_g2_product, compose_ordered_product, merkle_root,
    CompositionFailure, CompositionOutcome,
};

// Wire-format helpers — boundary-only, for host code that needs to
// assemble or hash wire-format header / merkle bytes.
pub use ops::header::{serialize_header, serialize_prefix, splice_nonce};
pub use ops::merkle::merkle_root_internal;
pub use ops::sha256::{sha256, sha256d_display, sha256d_internal};
