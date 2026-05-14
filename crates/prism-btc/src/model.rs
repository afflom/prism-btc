//! `BitcoinMiningModel` — prism-btc's `PrismModel<H, B, A, R>` declaration
//! (wiki ADR-020 + ADR-036; architecture §5).
//!
//! The mining inference is end-to-end prism: foundation's catamorphism
//! evaluates the ψ-chain verb arena
//! ([`crate::verbs::mining_inference`]) dispatching each resolver-bound
//! ψ-Term through [`crate::resolvers::BitcoinResolverTuple`]. There is
//! no σ-enumeration, no FirstAdmit-shaped search, no algorithmic body
//! in prism-btc's verb arena; the model declares the typed feature
//! hierarchy and the parametric tensor-algebra composition that
//! observes it.
//!
//! ## Typed feature hierarchy (architecture §2)
//!
//! - [`TemplatePrefix`] — `partition_product(Version, PrevHash,
//!   MerkleRoot, Timestamp, Bits)` (76 W8 sites).
//! - [`MiningTask`] — `partition_product(TemplatePrefix, Target)`
//!   (108 W8 sites). The PrismModel's `Input` type.
//! - [`MiningResult`] — the ψ-pipeline label (80 W8 sites — the
//!   wire-format Bitcoin header width). The PrismModel's `Output` type.

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

// The ψ-pipeline label (architecture §4). Site count = 80 — exactly
// the wire-format Bitcoin header byte width
// (`version‖prev_hash‖merkle_root‖timestamp‖bits‖nonce`).
// The terminal ψ_9 resolver ([`crate::resolvers::BitcoinKInvariantResolver`])
// emits an 80-byte κ-label whose bytes ARE the wire-format Bitcoin
// header by construction (architecture §6 bit-identicality contract).
//
// `MiningResult::CONSTRAINTS` algebraically encodes the wire-format
// Bitcoin header's structural admission relation using foundation's
// closed `ConstraintRef` catalog (architecture §2.3). The encoding is
// **template-invariant**: a compile-time `&'static [ConstraintRef]`
// declaring the algebraic shape of valid Bitcoin headers; the runtime
// `(prefix, target)` parameterize specific values that the ψ-pipeline's
// resolver chain materializes into the κ-label.
//
// **Algebraic-closure encoded** (architecture §2.3, IT_7d): the
// framework's canonical completeness criterion is χ(N(C)) = SITE_COUNT
// and β_k = 0 for k ≥ 1. `MiningResult` declares 80 disjoint `Site`
// constraints — one per wire-format-header byte position. Each
// constraint pins exactly one site; site supports are pairwise
// disjoint; the constraint nerve N(C) is 80 isolated vertices with no
// higher simplices. Therefore:
//
//   β_0 = 80,    β_k = 0 for k ≥ 1
//   χ(N(C)) = β_0 - β_1 + … = 80 = SITE_COUNT
//
// — the IT_7d algebraic-closure criterion is satisfied at the
// declaration level. The wiki's iterative-resolution discipline
// (`iterative-resolution.md`) converges in n - χ(N(C)) = 0 residual
// rank: each ψ-stage's progression pins free sites, and at the
// terminal ψ_9 stage all 80 sites are pinned — the leading 76 by
// the host-supplied template, the trailing 4 by ψ_9's structural
// κ-derivation via the canonical hash axis.
output_shape! {
    pub struct MiningResult;
    impl ConstrainedTypeShape for MiningResult {
        const IRI: &'static str = "https://prism.btc/shape/MiningResult";
        const SITE_COUNT: usize = 80;
        const CONSTRAINTS: &'static [ConstraintRef] = &[
            // 80 disjoint Site constraints — one per wire-format header
            // byte position (positions 0..80). Each constraint pins
            // exactly its site; the nerve is 80 isolated vertices
            // (β_0 = 80, β_k = 0 for k ≥ 1, χ = 80 = SITE_COUNT —
            // IT_7d algebraic-closure satisfied).
            //
            // Sites 0..76 are template-pinned (the host-supplied
            // prefix bytes); sites 76..80 are κ-pinned (the ψ_9
            // resolver's structural κ-derivation via the canonical
            // hash axis projects the typed MiningTask and pins the
            // four nonce bytes). Both mechanisms terminate at the
            // same fixed point: 80 sites pinned ⇒ FreeRank = 0 ⇒
            // convergence.
            ConstraintRef::Site { position: 0 },
            ConstraintRef::Site { position: 1 },
            ConstraintRef::Site { position: 2 },
            ConstraintRef::Site { position: 3 },
            ConstraintRef::Site { position: 4 },
            ConstraintRef::Site { position: 5 },
            ConstraintRef::Site { position: 6 },
            ConstraintRef::Site { position: 7 },
            ConstraintRef::Site { position: 8 },
            ConstraintRef::Site { position: 9 },
            ConstraintRef::Site { position: 10 },
            ConstraintRef::Site { position: 11 },
            ConstraintRef::Site { position: 12 },
            ConstraintRef::Site { position: 13 },
            ConstraintRef::Site { position: 14 },
            ConstraintRef::Site { position: 15 },
            ConstraintRef::Site { position: 16 },
            ConstraintRef::Site { position: 17 },
            ConstraintRef::Site { position: 18 },
            ConstraintRef::Site { position: 19 },
            ConstraintRef::Site { position: 20 },
            ConstraintRef::Site { position: 21 },
            ConstraintRef::Site { position: 22 },
            ConstraintRef::Site { position: 23 },
            ConstraintRef::Site { position: 24 },
            ConstraintRef::Site { position: 25 },
            ConstraintRef::Site { position: 26 },
            ConstraintRef::Site { position: 27 },
            ConstraintRef::Site { position: 28 },
            ConstraintRef::Site { position: 29 },
            ConstraintRef::Site { position: 30 },
            ConstraintRef::Site { position: 31 },
            ConstraintRef::Site { position: 32 },
            ConstraintRef::Site { position: 33 },
            ConstraintRef::Site { position: 34 },
            ConstraintRef::Site { position: 35 },
            ConstraintRef::Site { position: 36 },
            ConstraintRef::Site { position: 37 },
            ConstraintRef::Site { position: 38 },
            ConstraintRef::Site { position: 39 },
            ConstraintRef::Site { position: 40 },
            ConstraintRef::Site { position: 41 },
            ConstraintRef::Site { position: 42 },
            ConstraintRef::Site { position: 43 },
            ConstraintRef::Site { position: 44 },
            ConstraintRef::Site { position: 45 },
            ConstraintRef::Site { position: 46 },
            ConstraintRef::Site { position: 47 },
            ConstraintRef::Site { position: 48 },
            ConstraintRef::Site { position: 49 },
            ConstraintRef::Site { position: 50 },
            ConstraintRef::Site { position: 51 },
            ConstraintRef::Site { position: 52 },
            ConstraintRef::Site { position: 53 },
            ConstraintRef::Site { position: 54 },
            ConstraintRef::Site { position: 55 },
            ConstraintRef::Site { position: 56 },
            ConstraintRef::Site { position: 57 },
            ConstraintRef::Site { position: 58 },
            ConstraintRef::Site { position: 59 },
            ConstraintRef::Site { position: 60 },
            ConstraintRef::Site { position: 61 },
            ConstraintRef::Site { position: 62 },
            ConstraintRef::Site { position: 63 },
            ConstraintRef::Site { position: 64 },
            ConstraintRef::Site { position: 65 },
            ConstraintRef::Site { position: 66 },
            ConstraintRef::Site { position: 67 },
            ConstraintRef::Site { position: 68 },
            ConstraintRef::Site { position: 69 },
            ConstraintRef::Site { position: 70 },
            ConstraintRef::Site { position: 71 },
            ConstraintRef::Site { position: 72 },
            ConstraintRef::Site { position: 73 },
            ConstraintRef::Site { position: 74 },
            ConstraintRef::Site { position: 75 },
            ConstraintRef::Site { position: 76 },
            ConstraintRef::Site { position: 77 },
            ConstraintRef::Site { position: 78 },
            ConstraintRef::Site { position: 79 },
        ];
    }
}

// ─── The PrismModel ─────────────────────────────────────────────────────

// Foundation 0.4.6 (ADR-048) extends `PrismModel` with a 5th type
// parameter `C: TypedCommitment` — the substrate-level cost-model
// commitment slot the catamorphism evaluates against the κ-label
// immediately after the resolver chain emits it. We pin
// `C = EmptyCommitment` here: the base admission relation
// `σ(header) ≤ target` is *Bitcoin protocol*, not a foundation-side
// observable predicate (target-comparison is not an
// `ObservablePredicate` — the closed catalog covers stratum, parity,
// ultrametric closeness, affine parity), so it lives in
// `pipeline::forward_and_check`'s wrapper. Application-tier payload
// commitments compose via prism-btc's open `TypedCommitment` (see
// `crate::commitment`). This 5-position form pins the substrate
// acknowledgment that ψ_9 is now commitment-aware upstream — the
// previously-documented residual upstream move is closed.
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        uor_foundation::pipeline::EmptyCommitment
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
    fn mining_result_site_count_matches_wire_format_header_width() {
        // Architecture §2.2: MiningResult's 80 W8 sites are exactly the
        // wire-format Bitcoin header width.
        assert_eq!(<MiningResult as ConstrainedTypeShape>::SITE_COUNT, 80);
    }

    #[test]
    fn mining_result_carries_eighty_disjoint_site_constraints() {
        // Architecture §2.3 + IT_7d algebraic-closure: 80 disjoint
        // `Site` constraints, one per wire-format header byte. The
        // constraint nerve N(C) has 80 isolated vertices (β_0 = 80,
        // β_k = 0 for k ≥ 1, χ = 80 = SITE_COUNT — IT_7d satisfied).
        let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
        assert_eq!(cs.len(), 80, "80 Site constraints (algebraic-closure)");
        for c in cs {
            assert!(
                matches!(c, ConstraintRef::Site { .. }),
                "every constraint is a Site constraint"
            );
        }
    }

    #[test]
    fn mining_result_constraints_pin_every_wire_format_site() {
        // Architecture §2.3: each Site constraint pins exactly one
        // wire-format-header byte position; positions span [0, 80)
        // disjointly so site supports are pairwise disjoint and the
        // nerve has no 1-simplices.
        let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
        let positions: Vec<u32> = cs
            .iter()
            .filter_map(|c| match c {
                ConstraintRef::Site { position } => Some(*position),
                _ => None,
            })
            .collect();
        assert_eq!(positions.len(), 80, "80 Site constraints");
        for (i, &p) in positions.iter().enumerate() {
            assert_eq!(p, i as u32, "Site_{i} pins position {i}");
        }
    }
}
