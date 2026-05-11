//! `BitcoinMiningModel` — prism-btc's `PrismModel<H, B, A, R>` declaration
//! (wiki ADR-020 + ADR-036; architecture §5).
//!
//! The mining inference is end-to-end prism: foundation 0.4.2's
//! catamorphism evaluates the ψ-chain verb arena
//! ([`crate::verbs::mining_inference`]) dispatching each resolver-bound
//! ψ-Term through [`crate::resolvers::BitcoinResolverTuple`]. There is
//! no σ-enumeration, no FirstAdmit-shaped search, no algorithmic body
//! in prism-btc; the model declares the typed feature hierarchy and the
//! parametric tensor-algebra composition that observes it.
//!
//! ## Typed feature hierarchy (architecture §2)
//!
//! - [`TemplatePrefix`] — `partition_product(Version, PrevHash,
//!   MerkleRoot, Timestamp, Bits)` (76 W8 sites).
//! - [`MiningTask`] — `partition_product(TemplatePrefix, Target)`
//!   (108 W8 sites). The PrismModel's `Input` type.
//! - [`MiningResult`] — the ψ-pipeline label (32 W8 sites). The
//!   PrismModel's `Output` type.

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::pipeline::{
    ConstrainedTypeShape, ConstraintRef, IntoBindingValue, PartitionProductFields,
};
use uor_foundation::{DefaultHostTypes, ViolationKind};
use uor_foundation_sdk::{output_shape, prism_model};

use crate::resolvers::BitcoinResolverTuple;
use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

// Bring the verb's term-arena const + marker fn into scope so
// `prism_model!`'s closure-body grammar can splice the verb fragment at
// compile time per ADR-024.
#[allow(unused_imports)]
use crate::verbs::{mining_inference, VERB_TERMS_MINING_INFERENCE};

// ─── Composite feature: TemplatePrefix ──────────────────────────────────

/// The 76-byte template-prefix composite:
/// `partition_product(Version, PrevHash, MerkleRoot, Timestamp, Bits)`
/// (architecture §2.2).
///
/// `PartitionProductFields` declares the per-factor `(offset, length)`
/// table that the closure-body grammar's `input.<field>` form indexes
/// into (ADR-033 G20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplatePrefix(pub [u8; 76]);

impl TemplatePrefix {
    const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
        shape_iri: "https://prism.btc/shape/TemplatePrefix",
        constraint_iri: "https://prism.btc/shape/TemplatePrefix/maxBytes",
        property_iri: "https://prism.btc/shape/TemplatePrefix/byteCount",
        expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
        min_count: 76,
        max_count: 76,
        kind: ViolationKind::ValueCheck,
    };

    /// Construct from the canonical Bitcoin field decomposition.
    #[must_use]
    pub fn new(
        version: [u8; 4],
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: [u8; 4],
        bits: [u8; 4],
    ) -> Self {
        let mut bytes = [0u8; 76];
        bytes[0..4].copy_from_slice(&version);
        bytes[4..36].copy_from_slice(&prev_hash);
        bytes[36..68].copy_from_slice(&merkle_root);
        bytes[68..72].copy_from_slice(&timestamp);
        bytes[72..76].copy_from_slice(&bits);
        Self(bytes)
    }
}

impl ConstrainedTypeShape for TemplatePrefix {
    const IRI: &'static str = "https://prism.btc/shape/TemplatePrefix";
    const SITE_COUNT: usize = 76;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for TemplatePrefix {}

impl IntoBindingValue for TemplatePrefix {
    const MAX_BYTES: usize = 76;
    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if out.len() < 76 {
            return Err(Self::BUFFER_VIOLATION);
        }
        out[..76].copy_from_slice(&self.0);
        Ok(76)
    }
}

impl PartitionProductFields for TemplatePrefix {
    const FIELDS: &'static [(u32, u32)] = &[
        (0, 4),   // version
        (4, 32),  // prev_hash
        (36, 32), // merkle_root
        (68, 4),  // timestamp
        (72, 4),  // bits
    ];
    const FIELD_NAMES: &'static [&'static str] =
        &["version", "prev_hash", "merkle_root", "timestamp", "bits"];
}

// ─── Composite feature: MiningTask ──────────────────────────────────────

/// The PrismModel's `Input`: a 108-byte payload carrying the
/// `TemplatePrefix` followed by the 32-byte `Target` threshold
/// (architecture §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningTask(pub [u8; 108]);

impl MiningTask {
    const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
        shape_iri: "https://prism.btc/shape/MiningTask",
        constraint_iri: "https://prism.btc/shape/MiningTask/maxBytes",
        property_iri: "https://prism.btc/shape/MiningTask/byteCount",
        expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
        min_count: 108,
        max_count: 108,
        kind: ViolationKind::ValueCheck,
    };

    /// Construct from a `TemplatePrefix`'s 76 bytes and a `Target`'s 32
    /// bytes.
    #[must_use]
    pub fn new(prefix: [u8; 76], target: [u8; 32]) -> Self {
        let mut bytes = [0u8; 108];
        bytes[..76].copy_from_slice(&prefix);
        bytes[76..].copy_from_slice(&target);
        Self(bytes)
    }

    /// Borrow the 76-byte `TemplatePrefix` portion.
    #[inline]
    #[must_use]
    pub fn prefix(&self) -> &[u8; 76] {
        // SAFETY: layout pinned by PartitionProductFields.
        unsafe { &*(self.0[..76].as_ptr() as *const [u8; 76]) }
    }

    /// Borrow the 32-byte `Target` portion.
    #[inline]
    #[must_use]
    pub fn target_bytes(&self) -> &[u8; 32] {
        unsafe { &*(self.0[76..].as_ptr() as *const [u8; 32]) }
    }
}

impl ConstrainedTypeShape for MiningTask {
    const IRI: &'static str = "https://prism.btc/shape/MiningTask";
    const SITE_COUNT: usize = 108;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
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
    const FIELDS: &'static [(u32, u32)] = &[(0, 76), (76, 32)];
    const FIELD_NAMES: &'static [&'static str] = &["prefix", "target"];
}

// ─── Output shape: MiningResult ─────────────────────────────────────────

// The ψ-pipeline label (architecture §4). Site count = 32, matching the
// canonical hash axis's output width (`Sha256dHasher::OUTPUT_BYTES`) —
// the structural projection emitted by the terminal ψ_9 resolver
// (`BitcoinKInvariantResolver`).
//
// **Bit-identicality contract (architecture §6).** Once the foundation
// amendments named in architecture §9.1 land
// (`AxisProjectionObservable` + `LexicographicLessEqBound`), the
// `CONSTRAINTS` slot below will encode the structural admission
// relation between `Header` and `Target`, and the ψ-pipeline's
// resolvers will produce a label whose bytes decode to a wire-format-
// valid Bitcoin block (the resolved `Nonce` plus the host-boundary-
// assembled `Block`). Until then, the label is the structural
// content-address of the typed input under the canonical hash axis,
// and the host boundary (`prism-btc-node`) materializes the resolved
// `Header` from this label.
output_shape! {
    pub struct MiningResult;
    impl ConstrainedTypeShape for MiningResult {
        const IRI: &'static str = "https://prism.btc/shape/MiningResult";
        const SITE_COUNT: usize = 32;
        const CONSTRAINTS: &'static [ConstraintRef] = &[];
    }
}

// ─── The PrismModel ─────────────────────────────────────────────────────

prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_task() -> MiningTask {
        let mut prefix = [0u8; 76];
        prefix[0..4].copy_from_slice(&1u32.to_le_bytes());
        let target = [0xffu8; 32];
        MiningTask::new(prefix, target)
    }

    #[test]
    fn template_prefix_fields_match_canonical_layout() {
        // 76 bytes split as version(4) || prev_hash(32) || merkle_root(32)
        //   || timestamp(4) || bits(4).
        assert_eq!(
            <TemplatePrefix as PartitionProductFields>::FIELDS,
            &[(0, 4), (4, 32), (36, 32), (68, 4), (72, 4)]
        );
        assert_eq!(
            <TemplatePrefix as PartitionProductFields>::FIELD_NAMES,
            &["version", "prev_hash", "merkle_root", "timestamp", "bits"]
        );
    }

    #[test]
    fn mining_task_fields_match_canonical_layout() {
        assert_eq!(
            <MiningTask as PartitionProductFields>::FIELDS,
            &[(0, 76), (76, 32)]
        );
        assert_eq!(
            <MiningTask as PartitionProductFields>::FIELD_NAMES,
            &["prefix", "target"]
        );
    }

    #[test]
    fn into_binding_bytes_writes_one_oh_eight() {
        let task = sample_task();
        let mut out = [0u8; 108];
        let written = task.into_binding_bytes(&mut out).expect("buffer fits");
        assert_eq!(written, 108);
    }

    #[test]
    fn mining_result_site_count_matches_hash_axis_width() {
        // Architecture §2.2: MiningResult's 32 W8 sites are the canonical
        // hash axis output width.
        assert_eq!(<MiningResult as ConstrainedTypeShape>::SITE_COUNT, 32);
    }
}
