//! The **Bitcoin addressing realization** of UOR-ADDR — prism-btc's
//! `PrismModel<H, B, A, R, C>` declaration (ADR-020 + ADR-036 + ADR-048).
//!
//! Per the user-confirmed architecture, prism-btc is a UOR-ADDR
//! realization in the exact mould of [`uor_addr::json`] /
//! [`uor_addr::variant::storage`]: it binds the **shared**
//! [`AddressResolverTuple`](uor_addr::AddressResolverTuple) ψ-tower and the
//! shared [`AddrBounds`](uor_addr::AddrBounds) profile, and supplies only
//! three realization-specific pieces:
//!
//! 1. [`BlockHeaderCarrier`] — the ADR-060 canonical-form input handle.
//!    Its `as_binding_value` yields the 80-byte serialized Bitcoin header
//!    as a borrowed [`TermValue`](prism::operation::TermValue) carrier;
//!    canonicalization (wire serialization) happens at the host boundary,
//!    not in a resolver.
//! 2. [`crate::shapes::hasher::Sha256dHasher`] — the `sha256d` σ-axis
//!    (double-SHA-256, display-order finalize).
//! 3. [`crate::commitment::TargetCommitment`] — the cost-model commitment
//!    (ADR-048 5th parameter): Bitcoin's difficulty target as a
//!    `SingletonCommitment<LexicographicLessEqThreshold>` over the κ-label
//!    form (see [`crate::commitment`]).
//!
//! The κ-label ψ₉ emits is `sha256d:<64hex>` — exactly the conventional
//! Bitcoin block hash, in display order. Foundation evaluates the
//! commitment on that κ-label; admission `kappa_label ≤ target_label` is
//! Bitcoin's PoW relation `block_hash ≤ target`. The replayable
//! [`AddressWitness`](uor_addr::AddressWitness) the outcome carries **is**
//! the proof-of-work witness.

use prism::pipeline::{
    output_shape, prism_model, ConstrainedTypeShape, ConstraintRef, IntoBindingValue,
    PartitionProductFields,
};
use prism::vocabulary::DefaultHostTypes;

use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

// Bring the verb's term-arena const into scope so `prism_model!`'s
// closure-body grammar can splice the verb fragment at compile time
// (ADR-024), exactly as uor-addr's realizations do. Re-exported so the
// crate facade can surface the Layer-3 verb.
pub use self::verbs::{block_address_inference, VERB_TERMS_BLOCK_ADDRESS_INFERENCE};

/// The serialized-header byte width (Bitcoin wire format, ADR-060
/// canonical form).
pub const HEADER_BYTES: usize = 80;

/// The `sha256d` κ-label ASCII byte width: `len("sha256d") + 1 + 2 × 32 =
/// 72`. The output shape declares exactly this many `Site` constraints.
pub const BLOCK_ADDRESS_LABEL_BYTES: usize = 7 + 1 + 2 * 32;

// ─── Input handle: BlockHeaderCarrier (ADR-060 borrowed carrier) ─────────

/// Borrowed canonical-form Bitcoin block-header handle (ADR-060 borrowed
/// carrier). A thin, `Copy` borrow of the 80-byte wire-format header
/// bytes; `as_binding_value` returns the `Borrowed` carrier zero-copy. The
/// host's [`crate::pipeline::mine`] builds it from a
/// [`crate::domain::BlockHeader`] + candidate nonce via
/// [`crate::ops::header::serialize_header`].
#[derive(Clone, Copy, Debug)]
pub struct BlockHeaderCarrier<'a>(&'a [u8]);

impl<'a> BlockHeaderCarrier<'a> {
    /// Wrap an 80-byte wire-format header as a model input handle.
    #[must_use]
    pub fn new(header_bytes: &'a [u8]) -> Self {
        Self(header_bytes)
    }

    /// Borrow the wire-format header bytes.
    #[must_use]
    pub fn header_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl ConstrainedTypeShape for BlockHeaderCarrier<'_> {
    const IRI: &'static str = "https://prism.btc/shape/BlockHeader";
    const SITE_COUNT: usize = 1;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for BlockHeaderCarrier<'_> {}

impl<'a> IntoBindingValue<'a> for BlockHeaderCarrier<'a> {
    fn as_binding_value<const INLINE_BYTES: usize>(
        &self,
    ) -> prism::operation::TermValue<'a, INLINE_BYTES> {
        prism::operation::TermValue::borrowed(self.0)
    }
}

impl PartitionProductFields for BlockHeaderCarrier<'_> {
    /// The canonical Bitcoin header field decomposition (offset, length):
    /// version(4) ‖ prev_hash(32) ‖ merkle_root(32) ‖ timestamp(4) ‖
    /// bits(4) ‖ nonce(4).
    const FIELDS: &'static [(u32, u32)] = &[
        (0, 4),   // version
        (4, 32),  // prev_hash
        (36, 32), // merkle_root
        (68, 4),  // timestamp
        (72, 4),  // bits
        (76, 4),  // nonce
    ];
    const FIELD_NAMES: &'static [&'static str] = &[
        "version",
        "prev_hash",
        "merkle_root",
        "timestamp",
        "bits",
        "nonce",
    ];
}

// ─── Output shape: BlockAddressLabel (the sha256d κ-label) ───────────────

static SHA256D_SITES: [ConstraintRef; BLOCK_ADDRESS_LABEL_BYTES] =
    uor_addr::label::site_constraints::<BLOCK_ADDRESS_LABEL_BYTES>();

// `BlockAddressLabel` — the ψ-pipeline κ-label: the 72-byte ASCII
// `sha256d:<64hex>` block address (the conventional Bitcoin block hash in
// display order). The output space is π₀-only: 72 disjoint `Site`
// constraints, one per wire-format byte position (χ(N(C)) = 72 =
// SITE_COUNT, βₖ = 0 for k ≥ 1).
output_shape! {
    pub struct BlockAddressLabel;
    impl ConstrainedTypeShape for BlockAddressLabel {
        const IRI: &'static str = "https://prism.btc/addr/BlockAddressLabel/sha256d";
        const SITE_COUNT: usize = BLOCK_ADDRESS_LABEL_BYTES;
        const CONSTRAINTS: &'static [ConstraintRef] = &SHA256D_SITES;
    }
}

// ─── Layer-3 verb (ADR-024 / ADR-035 canonical k-invariants branch) ──────

/// The κ-derivation verb. Identical four-ψ composition to every UOR-ADDR
/// realization (`k_invariants ∘ homotopy_groups ∘ postnikov_tower ∘
/// nerve`); ψ₁–ψ₈ thread the borrowed header carrier through unchanged and
/// ψ₉ folds it through the `sha256d` σ-axis to emit the κ-label.
pub mod verbs {
    use super::{BlockAddressLabel, BlockHeaderCarrier};
    use prism::pipeline::verb;

    verb! {
        pub fn block_address_inference(input: BlockHeaderCarrier<'_>) -> BlockAddressLabel {
            k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
        }
    }
}

// ─── The PrismModel ──────────────────────────────────────────────────────

// ADR-048 pins `PrismModel`'s 5th type parameter to the cost-model
// commitment. `BitcoinAddressModel` binds `C = TargetCommitment` — the
// alias for `SingletonCommitment<LexicographicLessEqThreshold>` realizing
// Bitcoin's `block_hash ≤ target` admission relation (ADR-040).
//
// Foundation's `run_route` evaluates the commitment on ψ₉'s κ-label output
// bytes: if `kappa_label ≤ target_label` fails, run_route returns
// `PipelineFailure::ShapeViolation` and seals no `Grounded`. The per-call
// target κ-label is published on a thread-local slot by
// [`crate::pipeline::set_thread_target`] before each `forward()`.
prism_model! {
    pub struct BitcoinAddressModel;
    pub struct BitcoinAddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        uor_addr::AddressResolverTuple<Sha256dHasher>,
        crate::commitment::TargetCommitment
    > for BitcoinAddressModel {
        type Input = BlockHeaderCarrier<'a>;
        type Output = BlockAddressLabel;
        type Route = BitcoinAddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            block_address_inference(input)
        }
        fn commitment() -> crate::commitment::TargetCommitment {
            crate::commitment::target_commitment(crate::pipeline::current_thread_target())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_carrier_fields_match_canonical_layout() {
        assert_eq!(
            <BlockHeaderCarrier as PartitionProductFields>::FIELDS,
            &[(0, 4), (4, 32), (36, 32), (68, 4), (72, 4), (76, 4)]
        );
        assert_eq!(
            <BlockHeaderCarrier as PartitionProductFields>::FIELD_NAMES,
            &[
                "version",
                "prev_hash",
                "merkle_root",
                "timestamp",
                "bits",
                "nonce"
            ]
        );
    }

    #[test]
    fn block_address_label_site_count_matches_kappa_label_width() {
        // sha256d:<64hex> = 7 + 1 + 64 = 72 sites.
        assert_eq!(<BlockAddressLabel as ConstrainedTypeShape>::SITE_COUNT, 72);
        assert_eq!(BLOCK_ADDRESS_LABEL_BYTES, 72);
    }

    #[test]
    fn block_address_label_carries_disjoint_site_constraints() {
        let cs = <BlockAddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
        assert_eq!(cs.len(), 72);
        for (i, c) in cs.iter().enumerate() {
            match c {
                ConstraintRef::Site { position } => assert_eq!(*position, i as u32),
                _ => panic!("expected Site constraint at index {i}"),
            }
        }
    }
}
