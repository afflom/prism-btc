//! `BitcoinMiningModel` — prism-btc's `PrismModel<H, B, A>` declaration.
//!
//! The mining inference is end-to-end prism: foundation 0.4.1's
//! catamorphism evaluates the `nonce_fiber_traversal` verb's term
//! arena, drives the W32 fiber search via `Term::FirstAdmit`
//! (ADR-034 Mechanism 2), and emits the admitting nonce. There is no
//! implementor-side search loop.
//!
//! ## Shape topology
//!
//! - [`TemplatePrefixShape`] — 76 W8 sites, the canonical 76-byte
//!   template prefix `version‖prev_hash‖merkle_root‖timestamp‖bits`.
//! - [`TargetShape`] — 32 W8 sites, the lexicographic target threshold
//!   (decoded from the template's compact `nBits` field via
//!   [`crate::domain::Target::to_bytes`]).
//! - [`MiningTask`] — the partition_product of the two factors per
//!   ADR-026 G17. 108 W8 sites laid out as `prefix(76) ‖ target(32)`.
//!   Implements [`uor_foundation::pipeline::PartitionProductFields`]
//!   so the closure-body grammar's field-access form (ADR-033 G20)
//!   resolves `input.prefix` and `input.target` at proc-macro time.
//! - [`MiningResult`] — 5 W8 sites, the FirstAdmit coproduct return
//!   value: byte 0 is the discriminant (`0x01` admitted, `0x00`
//!   exhausted), bytes 1..5 are the admitting nonce in big-endian.
//!
//! ## Route
//!
//! `BitcoinMiningModel`'s route invokes the
//! [`crate::verbs::nonce_fiber_traversal`] verb, whose body is the
//! wiki's intended structural form
//! `first_admit(witt_domain::W32, |nonce| hash(concat(input.prefix, nonce)) <= input.target)`.
//! Foundation 0.4.1's catamorphism evaluates this end-to-end.

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::pipeline::{
    ConstrainedTypeShape, ConstraintRef, IntoBindingValue, PartitionProductFields,
};
use uor_foundation::{DefaultHostTypes, ViolationKind};
use uor_foundation_sdk::{output_shape, prism_model};

use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

// Bring the verb's term-arena const into scope so `prism_model!`'s
// closure-body grammar can splice the verb fragment at compile time
// per ADR-024 verb-call form. The macro emits a const reference to
// `VERB_TERMS_NONCE_FIBER_TRAVERSAL` and to the marker fn
// `nonce_fiber_traversal`; both are emitted by the `verb!` macro in
// [`crate::verbs`] and need to be in scope.
#[allow(unused_imports)]
// referenced by `prism_model!`'s closure-body grammar at expansion time.
use crate::verbs::{nonce_fiber_traversal, VERB_TERMS_NONCE_FIBER_TRAVERSAL};

// ----- Factor shapes -----

/// 76-byte canonical template prefix:
/// `version‖prev_hash‖merkle_root‖timestamp‖bits`.
///
/// Type-level marker. Runtime data flows through [`MiningTask`]'s
/// 108-byte payload at offset 0.
pub struct TemplatePrefixShape;

impl ConstrainedTypeShape for TemplatePrefixShape {
    const IRI: &'static str = "https://prism.btc/shape/TemplatePrefix";
    const SITE_COUNT: usize = 76;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    /// 76 bytes = 608 bits ≫ 64 — saturates per ADR-032.
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for TemplatePrefixShape {}

impl IntoBindingValue for TemplatePrefixShape {
    const MAX_BYTES: usize = 76;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        // Type-level marker only; data is carried by `MiningTask`.
        Ok(0)
    }
}

/// 32-byte lexicographic mining target.
///
/// Type-level marker. Runtime data flows through [`MiningTask`]'s
/// 108-byte payload at offset 76.
pub struct TargetShape;

impl ConstrainedTypeShape for TargetShape {
    const IRI: &'static str = "https://prism.btc/shape/Target";
    const SITE_COUNT: usize = 32;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    /// 32 bytes = 256 bits ≫ 64 — saturates per ADR-032.
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for TargetShape {}

impl IntoBindingValue for TargetShape {
    const MAX_BYTES: usize = 32;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

// ----- The model's input: a partition_product carrying both factors -----

/// The mining inference's input: a 108-byte payload carrying the
/// 76-byte template prefix concatenated with the 32-byte lexicographic
/// target.
///
/// Hand-rolled `ConstrainedTypeShape` + `IntoBindingValue` +
/// `PartitionProductFields` impls (rather than via `partition_product!`)
/// because the SDK macro emits a unit struct without a runtime data
/// carrier; this struct holds the actual byte payload that
/// [`uor_foundation::pipeline::run_route`] folds through `Sha256dHasher`
/// at evaluation time.
///
/// `PartitionProductFields` declares the per-factor offset/length
/// table the closure-body grammar's field-access form (ADR-033 G20)
/// indexes into: `prefix` resolves to bytes `[0..76)`, `target` to
/// `[76..108)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningTask(pub [u8; 108]);

impl MiningTask {
    /// Buffer-violation IRI emitted when foundation's pipeline hands
    /// `into_binding_bytes` a too-small buffer (which it shouldn't, by
    /// `run_route`'s invariant).
    const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
        shape_iri: "https://prism.btc/shape/MiningTask",
        constraint_iri: "https://prism.btc/shape/MiningTask/maxBytes",
        property_iri: "https://prism.btc/shape/MiningTask/byteCount",
        expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
        min_count: 108,
        max_count: 108,
        kind: ViolationKind::ValueCheck,
    };

    /// Construct a mining task from a 76-byte template prefix and a
    /// 32-byte target threshold.
    pub fn new(prefix: [u8; 76], target: [u8; 32]) -> Self {
        let mut bytes = [0u8; 108];
        bytes[..76].copy_from_slice(&prefix);
        bytes[76..].copy_from_slice(&target);
        Self(bytes)
    }

    /// Borrow the 76-byte template-prefix portion.
    #[inline]
    pub fn prefix(&self) -> &[u8; 76] {
        // SAFETY: layout is fixed; first 76 bytes are the prefix.
        unsafe { &*(self.0[..76].as_ptr() as *const [u8; 76]) }
    }

    /// Borrow the 32-byte target portion.
    #[inline]
    pub fn target_bytes(&self) -> &[u8; 32] {
        unsafe { &*(self.0[76..].as_ptr() as *const [u8; 32]) }
    }
}

impl ConstrainedTypeShape for MiningTask {
    const IRI: &'static str = "https://prism.btc/shape/MiningTask";
    const SITE_COUNT: usize = 108;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    /// 108 bytes = 864 bits ≫ 64 — saturates per ADR-032.
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for MiningTask {}

impl IntoBindingValue for MiningTask {
    const MAX_BYTES: usize = 108;

    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if out.len() < 108 {
            return Err(Self::BUFFER_VIOLATION);
        }
        out[..108].copy_from_slice(&self.0);
        Ok(108)
    }
}

impl PartitionProductFields for MiningTask {
    /// Per-factor `(byte_offset, byte_length)` pairs. ADR-033 G20's
    /// field-access form indexes here.
    const FIELDS: &'static [(u32, u32)] = &[(0, 76), (76, 32)];
    /// Per-factor names matching the closure-body grammar's
    /// `input.<name>` form.
    const FIELD_NAMES: &'static [&'static str] = &["prefix", "target"];
}

// ----- The model's output: the FirstAdmit coproduct value -----

// 6-byte coproduct returned by foundation's `Term::FirstAdmit`
// fold-rule (ADR-034 Mechanism 2):
//   - Byte 0:    discriminant. `0x01` ⇒ admitting nonce found;
//                `0x00` ⇒ W32 exhausted without admission.
//   - Bytes 1..6: the admitting nonce in big-endian, padded to 5 bytes
//                 because `witt_domain::W32::CYCLE_SIZE = 2^32` needs
//                 5 bytes to represent (foundation's FirstAdmit
//                 evaluator picks `idx_byte_width` from the smallest
//                 unsigned representation of N). The high byte
//                 (`bytes[1]`) is always 0 for W32 nonces — actual
//                 nonce bytes are in `bytes[2..6]`.
output_shape! {
    pub struct MiningResult;
    impl ConstrainedTypeShape for MiningResult {
        const IRI: &'static str = "https://prism.btc/shape/MiningResult";
        const SITE_COUNT: usize = 6;
        const CONSTRAINTS: &'static [ConstraintRef] = &[];
    }
}

// ----- The PrismModel -----
//
// `prism_model!` emits:
// - `pub struct BitcoinMiningModel;`
// - `pub struct BitcoinMiningRoute;`
// - the seal + `FoundationClosed` + `PrismModel` impls
// - `forward(input)` body = `pipeline::run_route::<H, B, A, Self>(input)`
//
// The route body invokes the `nonce_fiber_traversal` verb. The verb's
// term-tree fragment is spliced at compile time per ADR-024. Foundation
// 0.4.1's catamorphism evaluates the spliced arena: `Term::FirstAdmit`
// iterates `nonce` ascending from 0 to 2^32 (per the W32 domain's
// `CYCLE_SIZE`), evaluates the predicate
// `hash(concat(input.prefix, nonce)) <= input.target` per fiber visit,
// and short-circuits on the first non-zero predicate result. The
// catamorphism returns the 5-byte coproduct `(disc, nonce_bytes)`,
// attached to the `Grounded<MiningResult>`'s `output_bytes` per
// ADR-028.
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher> for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            nonce_fiber_traversal(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_foundation::pipeline::PrismModel;

    fn easy_task() -> MiningTask {
        // Minimal valid prefix: version=1, rest zero.
        let mut prefix = [0u8; 76];
        prefix[0..4].copy_from_slice(&1u32.to_le_bytes());
        // Easy target: all 0xff (any digest admits).
        let target = [0xffu8; 32];
        MiningTask::new(prefix, target)
    }

    #[test]
    fn into_binding_bytes_writes_one_oh_eight() {
        let task = easy_task();
        let mut out = [0u8; 108];
        let written = task.into_binding_bytes(&mut out).expect("buffer fits");
        assert_eq!(written, 108);
    }

    #[test]
    fn forward_returns_admitted_coproduct_for_easy_target() {
        let task = easy_task();
        let grounded = <BitcoinMiningModel as PrismModel<
            DefaultHostTypes,
            PrismBtcBounds,
            Sha256dHasher,
        >>::forward(task)
        .expect("forward succeeds");
        // Foundation 0.4.1's FirstAdmit returns a 6-byte coproduct
        // for W32 (the cycle size 2^32 needs 5 bytes BE plus 1 disc):
        //   byte 0:    disc = 0x01 (admitted) or 0x00 (exhausted)
        //   bytes 1..6: admitting nonce padded to 5 bytes (high byte 0)
        let bytes = grounded.output_bytes();
        assert_eq!(bytes.len(), 6);
        assert_eq!(
            bytes[0], 0x01,
            "predicate `hash(...) <= 0xff..ff` admits at idx=0"
        );
    }

    #[test]
    fn partition_product_fields_index_layout() {
        // ADR-033 G20 indexes by FIELDS' (offset, length) pairs.
        assert_eq!(
            <MiningTask as PartitionProductFields>::FIELDS,
            &[(0, 76), (76, 32)]
        );
        assert_eq!(
            <MiningTask as PartitionProductFields>::FIELD_NAMES,
            &["prefix", "target"]
        );
    }
}
