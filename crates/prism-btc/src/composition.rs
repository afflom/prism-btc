//! **The ADR-061 composition framework, realized for the `sha256d`
//! σ-axis** — prism-btc's reference implementation.
//!
//! UOR-ADDR's [`composition`](uor_addr::composition) module ships the five
//! categorical operations on the Atlas image inside E₈ (`g2` / `f4` / `e6`
//! / `e7` / `e8`) for the five standard σ-axes (`sha256` … `sha512`). It
//! **cannot** compose Bitcoin block/transaction addresses: those carry the
//! `sha256d` axis, which uor-addr's composition rejects
//! ([`CompositionFailure::OperandSigmaAxisMismatch`]). This module is the
//! reference realization of ADR-061 for `sha256d`.
//!
//! Each operation takes one or two operand κ-labels (`sha256d:<64hex>`,
//! produced by [`crate::mine_at`] or [`block_label_from_digest`]) and mints a
//! new `sha256d` κ-label for the composed object by:
//!
//! 1. **canonicalize** — apply the operation's byte-level discipline
//!    (ADR-061 §(3)) to the operand digests;
//! 2. **ground** — fold the canonical form through the shared
//!    [`AddressResolverTuple`] ψ-tower
//!    bound to [`Sha256dHasher`], via a per-operation
//!    [`PrismModel`](prism::pipeline::PrismModel) whose output IRI records
//!    the operation's provenance (ADR-001 / ADR-017 typed-iso).
//!
//! | op | algebraic structure (framework) | byte-level discipline (realization) |
//! |----|----------------------------------|-------------------------------------|
//! | [`compose_g2_product`] | commutative binary product | lex-min-first concatenation |
//! | [`compose_f4_quotient`] | ± involution quotient | bitwise-complement lex-min |
//! | [`compose_e6_filtration`] | 2-class degree partition (8:1) | `first_byte mod 9` degree tag |
//! | [`compose_e7_augmentation`] | S₄-orbit (24-element) equivalence | quarter-permutation lex-min |
//! | [`compose_e8_embedding`] | identity relation | identity on canonical-form bytes |
//! | [`compose_ordered_product`] | **non-commutative** binary product | ordered `left ‖ right` concatenation |
//!
//! ## Bitcoin merkle as iterated composition
//!
//! Bitcoin's transaction merkle tree is the **ordered** (order-sensitive)
//! binary product — distinct from ADR-061's commutative `g2`. This module
//! provides it as [`compose_ordered_product`] and folds it into
//! [`merkle_root`], expressing the merkle root as iterated composition over
//! the `sha256d` axis.
//!
//! Note on byte order: composition operates on **display-order**
//! κ-labels (the σ-axis emits display order; see
//! [`Sha256dHasher`]), so
//! [`merkle_root`] is the display-order κ-label algebra. The byte-exact
//! Bitcoin **protocol** merkle root (internal byte order, the bytes that
//! go into the header's `merkle_root` field) is
//! [`crate::ops::merkle::merkle_root_internal`].

extern crate alloc;

use alloc::vec::Vec;

use prism::pipeline::{
    output_shape, prism_model, ConstrainedTypeShape, ConstraintRef, IntoBindingValue,
    PartitionProductFields,
};
use prism::vocabulary::DefaultHostTypes;
use uor_addr::{AddressOutcome, AddressResolverTuple, KappaLabel};

use crate::model::BLOCK_ADDRESS_LABEL_BYTES;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// κ-label byte width for the `sha256d` axis (`sha256d:<64hex>` = 72).
const LABEL: usize = BLOCK_ADDRESS_LABEL_BYTES;

/// The σ-axis token every operand must carry (CA-3 σ-axis homogeneity).
pub const SHA256D_AXIS: &str = "sha256d";

/// The composed-address result — the same owned outcome surface every
/// UOR-ADDR realization returns: the `sha256d` κ-label + replayable TC-05
/// witness.
pub type CompositionOutcome = AddressOutcome<LABEL, 32>;

/// Failure modes from the composition operations (mirrors
/// [`uor_addr::composition::CompositionFailure`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionFailure {
    /// An operand is not a well-formed κ-label (no `:` separator, or an
    /// odd-length / non-lowercase-hex digest body).
    MalformedOperand,
    /// An operand's σ-axis is not `sha256d` (CA-3 σ-axis homogeneity).
    OperandSigmaAxisMismatch {
        /// The σ-axis the operation expects (`sha256d`).
        expected_axis: &'static str,
        /// The σ-axis the offending operand carries.
        operand_axis: &'static str,
    },
    /// Defensive: foundation's catamorphism returned a shape violation.
    /// Unreachable for well-formed operands.
    PipelineFailure,
}

// ─── Input carrier (ADR-060 borrowed carrier over canonical-form bytes) ──

/// The composition input carrier — a borrow of the canonicalize
/// discipline's output, flowing through the ψ-tower as a `Borrowed`
/// carrier.
#[derive(Clone, Copy, Debug)]
pub struct CompositionCarrier<'a>(&'a [u8]);

impl<'a> CompositionCarrier<'a> {
    /// Wrap canonical-form bytes as a model input handle.
    #[must_use]
    pub fn new(canonical_bytes: &'a [u8]) -> Self {
        Self(canonical_bytes)
    }

    /// Borrow the canonical-form bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl ConstrainedTypeShape for CompositionCarrier<'_> {
    const IRI: &'static str = "https://prism.btc/addr/composition/CompositionCarrier";
    const SITE_COUNT: usize = 1;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for CompositionCarrier<'_> {}

impl<'a> IntoBindingValue<'a> for CompositionCarrier<'a> {
    fn as_binding_value<const INLINE_BYTES: usize>(
        &self,
    ) -> prism::operation::TermValue<'a, INLINE_BYTES> {
        prism::operation::TermValue::borrowed(self.0)
    }
}

impl PartitionProductFields for CompositionCarrier<'_> {
    const FIELDS: &'static [(u32, u32)] = &[];
    const FIELD_NAMES: &'static [&'static str] = &[];
}

// ─── Per-operation output shapes + verbs + models ────────────────────────

static COMP_SITES: [ConstraintRef; LABEL] = uor_addr::label::site_constraints::<LABEL>();

/// Emit one composition operation's `output_shape!` (with provenance IRI),
/// κ-derivation `verb!`, and `prism_model!` binding the shared `sha256d`
/// ψ-tower + [`EmptyCommitment`](prism::pipeline::EmptyCommitment).
macro_rules! comp_op {
    (label: $label:ident, iri: $iri:literal, verb: $verb:ident, model: $model:ident, route: $route:ident) => {
        output_shape! {
            pub struct $label;
            impl ConstrainedTypeShape for $label {
                const IRI: &'static str = $iri;
                const SITE_COUNT: usize = LABEL;
                const CONSTRAINTS: &'static [ConstraintRef] = &COMP_SITES;
            }
        }

        prism::pipeline::verb! {
            pub fn $verb(input: CompositionCarrier<'_>) -> $label {
                k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
            }
        }

        prism_model! {
            pub struct $model;
            pub struct $route;
            impl PrismModel<
                DefaultHostTypes,
                PrismBtcBounds,
                Sha256dHasher,
                AddressResolverTuple<Sha256dHasher>,
                prism::pipeline::EmptyCommitment
            > for $model {
                type Input = CompositionCarrier<'a>;
                type Output = $label;
                type Route = $route;
                fn route(input: Self::Input) -> Self::Output {
                    $verb(input)
                }
            }
        }
    };
}

comp_op!(
    label: CompositionLabelG2,
    iri: "https://prism.btc/addr/composition/g2-product/sha256d",
    verb: compose_g2_inference,
    model: CompositionModelG2,
    route: CompositionRouteG2
);
comp_op!(
    label: CompositionLabelF4,
    iri: "https://prism.btc/addr/composition/f4-quotient/sha256d",
    verb: compose_f4_inference,
    model: CompositionModelF4,
    route: CompositionRouteF4
);
comp_op!(
    label: CompositionLabelE6,
    iri: "https://prism.btc/addr/composition/e6-filtration/sha256d",
    verb: compose_e6_inference,
    model: CompositionModelE6,
    route: CompositionRouteE6
);
comp_op!(
    label: CompositionLabelE7,
    iri: "https://prism.btc/addr/composition/e7-augmentation/sha256d",
    verb: compose_e7_inference,
    model: CompositionModelE7,
    route: CompositionRouteE7
);
comp_op!(
    label: CompositionLabelE8,
    iri: "https://prism.btc/addr/composition/e8-embedding/sha256d",
    verb: compose_e8_inference,
    model: CompositionModelE8,
    route: CompositionRouteE8
);
comp_op!(
    label: CompositionLabelOrdered,
    iri: "https://prism.btc/addr/composition/ordered-product/sha256d",
    verb: compose_ordered_inference,
    model: CompositionModelOrdered,
    route: CompositionRouteOrdered
);

// ─── Canonicalize disciplines (ADR-061 §(3), ported for sha256d) ─────────

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        _ => None,
    }
}

fn hex_lo(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => unreachable!("nibble is `& 0x0F`"),
    }
}

/// Decode an operand κ-label's raw 32-byte digest, validating its σ-axis
/// is `sha256d`.
fn decode_operand(operand: &KappaLabel<LABEL>) -> Result<[u8; 32], CompositionFailure> {
    let axis = operand
        .sigma_axis()
        .ok_or(CompositionFailure::MalformedOperand)?;
    require_sha256d(axis)?;
    let hex_digest = operand
        .sigma_axis_digest_hex()
        .ok_or(CompositionFailure::MalformedOperand)?;
    if hex_digest.len() != 64 {
        return Err(CompositionFailure::MalformedOperand);
    }
    let bytes = hex_digest.as_bytes();
    let mut raw = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or(CompositionFailure::MalformedOperand)?;
        let lo = hex_nibble(pair[1]).ok_or(CompositionFailure::MalformedOperand)?;
        raw[i] = (hi << 4) | lo;
    }
    Ok(raw)
}

fn require_sha256d(axis: &str) -> Result<(), CompositionFailure> {
    if axis == SHA256D_AXIS {
        Ok(())
    } else {
        let static_axis = match axis {
            "sha256" => "sha256",
            "blake3" => "blake3",
            "sha3-256" => "sha3-256",
            "keccak256" => "keccak256",
            "sha512" => "sha512",
            _ => return Err(CompositionFailure::MalformedOperand),
        };
        Err(CompositionFailure::OperandSigmaAxisMismatch {
            expected_axis: SHA256D_AXIS,
            operand_axis: static_axis,
        })
    }
}

/// Re-emit `sha256d:<lowercase-hex>` canonical-form bytes from a raw digest.
fn emit_canonical(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SHA256D_AXIS.len() + 1 + 2 * raw.len());
    out.extend_from_slice(SHA256D_AXIS.as_bytes());
    out.push(b':');
    for &byte in raw {
        out.push(hex_lo(byte >> 4));
        out.push(hex_lo(byte & 0x0F));
    }
    out
}

const DEGREE_5_TAG: u8 = 0x05;
const DEGREE_6_TAG: u8 = 0x06;

const S4_PERMUTATIONS: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

// ─── Public composition operations ───────────────────────────────────────

/// Build a `sha256d:<64hex>` κ-label from a 32-byte display-order block
/// hash. Inverse of [`KappaLabel::sigma_axis_digest_hex`] for this axis.
#[must_use]
pub fn block_label_from_digest(display_digest: &[u8; 32]) -> KappaLabel<LABEL> {
    let bytes = crate::commitment::target_label_bytes(*display_digest);
    KappaLabel::from_bytes(&bytes).expect("sha256d κ-label is 72 ASCII bytes by construction")
}

/// **CS-G2** — commutative binary product (lex-min-first concatenation of
/// the two operand κ-labels). `compose_g2_product(a, b)` and
/// `compose_g2_product(b, a)` yield byte-identical composed κ-labels.
///
/// # Errors
/// [`CompositionFailure`] if either operand is malformed or carries a
/// non-`sha256d` axis.
pub fn compose_g2_product(
    left: &KappaLabel<LABEL>,
    right: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    require_sha256d(
        left.sigma_axis()
            .ok_or(CompositionFailure::MalformedOperand)?,
    )?;
    require_sha256d(
        right
            .sigma_axis()
            .ok_or(CompositionFailure::MalformedOperand)?,
    )?;
    let (l, r) = (left.as_bytes(), right.as_bytes());
    let mut canon = Vec::with_capacity(2 * LABEL);
    if l <= r {
        canon.extend_from_slice(l);
        canon.extend_from_slice(r);
    } else {
        canon.extend_from_slice(r);
        canon.extend_from_slice(l);
    }
    ground::<CompositionModelG2>(&canon)
}

/// **CS-F4** — ± involution quotient: the lex-min of `{raw, !raw}`,
/// re-emitted as a `sha256d` canonical form, then ground.
///
/// # Errors
/// [`CompositionFailure`] if the operand is malformed or non-`sha256d`.
pub fn compose_f4_quotient(
    operand: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    let raw = decode_operand(operand)?;
    let complement: [u8; 32] = core::array::from_fn(|i| !raw[i]);
    let canon_raw = if raw <= complement { raw } else { complement };
    ground::<CompositionModelF4>(&emit_canonical(&canon_raw))
}

/// **CS-E6** — degree-partition filtration: prepend a one-byte degree tag
/// (`first_raw_byte mod 9`: `0x05` for `0..=7`, `0x06` for `8`) to the
/// operand κ-label bytes, then ground.
///
/// # Errors
/// [`CompositionFailure`] if the operand is malformed or non-`sha256d`.
pub fn compose_e6_filtration(
    operand: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    let raw = decode_operand(operand)?;
    let tag = match raw[0] % 9 {
        0..=7 => DEGREE_5_TAG,
        _ => DEGREE_6_TAG,
    };
    let mut canon = Vec::with_capacity(1 + LABEL);
    canon.push(tag);
    canon.extend_from_slice(operand.as_bytes());
    ground::<CompositionModelE6>(&canon)
}

/// **CS-E7** — S₄-orbit augmentation: partition the raw digest into 4
/// quarters, take the lex-min over the 24 quarter-permutations, re-emit and
/// ground.
///
/// # Errors
/// [`CompositionFailure`] if the operand is malformed or non-`sha256d`.
pub fn compose_e7_augmentation(
    operand: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    let raw = decode_operand(operand)?;
    let q = raw.len() / 4; // 8
    let quarters: [&[u8]; 4] = [
        &raw[0..q],
        &raw[q..2 * q],
        &raw[2 * q..3 * q],
        &raw[3 * q..],
    ];
    let mut canon: Option<Vec<u8>> = None;
    for perm in S4_PERMUTATIONS.iter() {
        let mut candidate = Vec::with_capacity(raw.len());
        for &idx in perm.iter() {
            candidate.extend_from_slice(quarters[idx]);
        }
        match &canon {
            None => canon = Some(candidate),
            Some(current) if candidate < *current => canon = Some(candidate),
            _ => {}
        }
    }
    let canon_raw = canon.expect("S4_PERMUTATIONS is non-empty");
    ground::<CompositionModelE7>(&emit_canonical(&canon_raw))
}

/// **CS-E8** — direct embedding (identity on canonical-form bytes). The
/// composed κ-label is distinguished from the operand by realization-IRI
/// provenance, not by digest bytes.
///
/// # Errors
/// [`CompositionFailure`] if the operand is malformed or non-`sha256d`.
pub fn compose_e8_embedding(
    operand: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    require_sha256d(
        operand
            .sigma_axis()
            .ok_or(CompositionFailure::MalformedOperand)?,
    )?;
    ground::<CompositionModelE8>(operand.as_bytes())
}

/// **Ordered binary product** (prism-btc's non-commutative composition) —
/// concatenate the two operands' raw digests **in order** (`left ‖
/// right`), then ground. This is the Bitcoin merkle-node combiner; unlike
/// [`compose_g2_product`] it is order-sensitive.
///
/// # Errors
/// [`CompositionFailure`] if either operand is malformed or non-`sha256d`.
pub fn compose_ordered_product(
    left: &KappaLabel<LABEL>,
    right: &KappaLabel<LABEL>,
) -> Result<CompositionOutcome, CompositionFailure> {
    let l = decode_operand(left)?;
    let r = decode_operand(right)?;
    let mut canon = Vec::with_capacity(64);
    canon.extend_from_slice(&l);
    canon.extend_from_slice(&r);
    ground::<CompositionModelOrdered>(&canon)
}

/// **Bitcoin merkle root as iterated composition.** The structural
/// recurrence on the canonical-form definition:
///
/// > `merkle_root([root]) = root`
/// > `merkle_root(leaves) = merkle_root(pair_up(leaves))`
///
/// where `pair_up` folds each adjacent pair with
/// [`compose_ordered_product`], duplicating the last element when the
/// arity is odd (Bitcoin's discipline). The base case is a one-leaf
/// tree; the recursive case is a level descent on the structural form,
/// not a procedural while-loop with mutable level state.
///
/// This is the display-order κ-label algebra; for the byte-exact
/// protocol merkle root (internal byte order) see
/// [`crate::ops::merkle::merkle_root_internal`].
///
/// # Errors
/// [`CompositionFailure::MalformedOperand`] if `leaves` is empty, or any
/// operand is malformed / non-`sha256d`.
pub fn merkle_root(leaves: &[KappaLabel<LABEL>]) -> Result<KappaLabel<LABEL>, CompositionFailure> {
    match leaves {
        [] => Err(CompositionFailure::MalformedOperand),
        [root] => Ok(*root),
        more => {
            let next: Vec<KappaLabel<LABEL>> = more
                .chunks(2)
                .map(|pair| {
                    let (left, right) = match pair {
                        [l, r] => (l, r),
                        [l] => (l, l),
                        _ => unreachable!("chunks(2) yields slices of length 1 or 2"),
                    };
                    compose_ordered_product(left, right).map(|out| out.address)
                })
                .collect::<Result<_, _>>()?;
            merkle_root(&next)
        }
    }
}

/// Ground canonical-form bytes through composition model `M`, extracting
/// the owned [`CompositionOutcome`].
fn ground<M>(canonical: &[u8]) -> Result<CompositionOutcome, CompositionFailure>
where
    M: GroundComposition,
{
    M::ground(canonical)
}

/// Internal trait letting [`ground`] dispatch to a per-operation model's
/// inherent `forward`. Implemented by the `comp_models!`-emitted models.
trait GroundComposition {
    fn ground(canonical: &[u8]) -> Result<CompositionOutcome, CompositionFailure>;
}

macro_rules! impl_ground {
    ($model:ident) => {
        impl GroundComposition for $model {
            fn ground(canonical: &[u8]) -> Result<CompositionOutcome, CompositionFailure> {
                use prism::pipeline::PrismModel;
                let grounded = $model::forward(CompositionCarrier::new(canonical))
                    .map_err(|_| CompositionFailure::PipelineFailure)?;
                AddressOutcome::<LABEL, 32>::from_grounded(&grounded)
                    .map_err(|_| CompositionFailure::PipelineFailure)
            }
        }
    };
}

impl_ground!(CompositionModelG2);
impl_ground!(CompositionModelF4);
impl_ground!(CompositionModelE6);
impl_ground!(CompositionModelE7);
impl_ground!(CompositionModelE8);
impl_ground!(CompositionModelOrdered);

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(byte: u8) -> KappaLabel<LABEL> {
        block_label_from_digest(&[byte; 32])
    }

    #[test]
    fn g2_is_commutative() {
        let a = leaf(0x11);
        let b = leaf(0x22);
        let ab = compose_g2_product(&a, &b).expect("g2");
        let ba = compose_g2_product(&b, &a).expect("g2");
        assert_eq!(ab.address, ba.address, "CS-G2 is commutative");
        // The composed κ-label is itself a well-formed sha256d address.
        assert!(ab.address.starts_with("sha256d:"));
        assert_eq!(ab.witness.verify().expect("replays"), ab.address);
    }

    #[test]
    fn ordered_product_is_not_commutative() {
        let a = leaf(0x11);
        let b = leaf(0x22);
        let ab = compose_ordered_product(&a, &b).expect("ordered");
        let ba = compose_ordered_product(&b, &a).expect("ordered");
        assert_ne!(
            ab.address, ba.address,
            "the ordered product is order-sensitive (Bitcoin merkle node)"
        );
    }

    #[test]
    fn e8_embedding_grounds_to_well_formed_label() {
        let a = leaf(0x00);
        let out = compose_e8_embedding(&a).expect("e8");
        assert!(out.address.starts_with("sha256d:"));
        assert_eq!(out.witness.verify().expect("replays"), out.address);
    }

    #[test]
    fn merkle_single_leaf_is_grounded_leaf() {
        // A one-leaf tree: Bitcoin returns the leaf itself as the root.
        let a = leaf(0x42);
        let root = merkle_root(&[a]).expect("merkle");
        assert_eq!(root, a);
    }

    #[test]
    fn merkle_three_leaves_duplicates_last() {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves).expect("merkle");
        // Level 1: node(1,2), node(3,3). Level 2: node(node12, node33).
        let n12 = compose_ordered_product(&leaves[0], &leaves[1])
            .unwrap()
            .address;
        let n33 = compose_ordered_product(&leaves[2], &leaves[2])
            .unwrap()
            .address;
        let expected = compose_ordered_product(&n12, &n33).unwrap().address;
        assert_eq!(root, expected);
    }

    #[test]
    fn rejects_non_sha256d_axis() {
        // A sha256 (single) κ-label must be rejected by the sha256d ops.
        let foreign = KappaLabel::<LABEL>::from_bytes(
            b"sha2566:0000000000000000000000000000000000000000000000000000000000000000",
        );
        // `sha2566` is 72 bytes but not a real axis → MalformedOperand on decode.
        if let Ok(lbl) = foreign {
            assert!(matches!(
                compose_e8_embedding(&lbl),
                Err(CompositionFailure::MalformedOperand)
                    | Err(CompositionFailure::OperandSigmaAxisMismatch { .. })
            ));
        }
    }
}
