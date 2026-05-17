//! `BitcoinMiningModel` — prism-btc's `PrismModel<H, B, A, R, C>`
//! declaration (wiki ADR-020 + ADR-036 + ADR-048; architecture §5).
//! The 5-position `C` slot is pinned at `EmptyCommitment` — see the
//! note beside the `prism_model!` invocation below.
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
//! - [`MiningResult`] — the ψ-pipeline label (32 W8 sites — the
//!   SHA-256d digest of the wire-format Bitcoin header). The
//!   PrismModel's `Output` type. The 32-byte width is the natural
//!   cost-model κ-label per wiki ADR-048/049: foundation's
//!   `LexicographicLessEqThreshold` predicate (re-exported through
//!   [`crate::commitment`]) compares the κ-label's byte sequence to
//!   the target, so `MiningResult` is the digest the admission
//!   relation evaluates — not the 80-byte wire form.

use prism::pipeline::{
    output_shape, prism_model, ConstrainedTypeShape, ConstraintRef, IntoBindingValue,
    PartitionProductFields, ShapeViolation, ViolationKind,
};
use prism::vocabulary::DefaultHostTypes;

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

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for TemplatePrefix {}

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

impl prism::uor_foundation::pipeline::__sdk_seal::Sealed for MiningTask {}

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

// The ψ-pipeline label (architecture §4). Site count = 32 — the
// SHA-256d digest width (the natural cost-model κ-label per wiki
// ADR-048/049). The terminal ψ_9 resolver
// ([`crate::resolvers::BitcoinKInvariantResolver`]) emits a 32-byte
// κ-label that IS `SHA-256d(wire_format_header)` in Bitcoin display
// order — exactly the byte sequence foundation's
// `LexicographicLessEqThreshold` predicate compares against the
// target.
//
// `MiningResult::CONSTRAINTS` algebraically encodes the digest's
// structural admission relation using foundation's closed
// `ConstraintRef` catalog (architecture §2.3). The encoding is
// **template-invariant**: a compile-time `&'static [ConstraintRef]`
// declaring the algebraic shape of valid digests; the runtime
// `(prefix, target)` parameterize specific values that the ψ-pipeline's
// resolver chain materializes into the κ-label.
//
// **Algebraic-closure encoded** (architecture §2.3, IT_7d): the
// framework's canonical completeness criterion is χ(N(C)) = SITE_COUNT
// and β_k = 0 for k ≥ 1. `MiningResult` declares 32 disjoint `Site`
// constraints — one per digest byte position. Each constraint pins
// exactly one site; site supports are pairwise disjoint; the
// constraint nerve N(C) is 32 isolated vertices with no higher
// simplices. Therefore:
//
//   β_0 = 32,    β_k = 0 for k ≥ 1
//   χ(N(C)) = β_0 - β_1 + … = 32 = SITE_COUNT
//
// — the IT_7d algebraic-closure criterion is satisfied at the
// declaration level. The wiki's iterative-resolution discipline
// (`iterative-resolution.md`) converges in n - χ(N(C)) = 0 residual
// rank: ψ_9 pins all 32 digest sites simultaneously by computing
// `SHA-256d(reconstructed_wire_format_header)` over the typed input
// (the 4-byte nonce is structurally κ-derived from the canonical hash
// axis; the resulting 80-byte wire-format header is hashed to yield
// the 32-byte κ-label).
output_shape! {
    pub struct MiningResult;
    impl ConstrainedTypeShape for MiningResult {
        const IRI: &'static str = "https://prism.btc/shape/MiningResult";
        const SITE_COUNT: usize = 32;
        const CONSTRAINTS: &'static [ConstraintRef] = &[
            // 32 disjoint Site constraints — one per digest byte
            // position (positions 0..32). Each constraint pins exactly
            // its site; the nerve is 32 isolated vertices
            // (β_0 = 32, β_k = 0 for k ≥ 1, χ = 32 = SITE_COUNT —
            // IT_7d algebraic-closure satisfied).
            //
            // All 32 sites are κ-pinned by the ψ_9 resolver's
            // structural κ-derivation: the typed `MiningTask`
            // reconstructs an 80-byte wire-format header internally
            // (via the canonical hash axis to derive the 4-byte
            // nonce), then `SHA-256d` over that wire-format header
            // simultaneously pins all 32 digest bytes. FreeRank drops
            // from 32 to 0 in this single terminal stage.
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
        ];
    }
}

// ─── The PrismModel ─────────────────────────────────────────────────────

// Foundation 0.4.12 (ADR-048) pins `PrismModel`'s 5th type parameter
// to the cost-model commitment surface. `BitcoinMiningModel` binds
// `C = TargetCommitment` — the foundation-canonical alias for
// `SingletonCommitment<LexicographicLessEqThreshold>` realizing
// Bitcoin's `digest ≤ target` admission relation per ADR-040.
//
// Foundation's [`run_route`] evaluates the commitment immediately
// after ψ_9 emits the κ-label: if the κ-label fails admission,
// run_route returns `PipelineFailure::ShapeViolation` and the
// catamorphism does not seal a `Grounded<MiningResult>`. Bitcoin's
// admission relation is therefore evaluated **inside the typed-iso
// surface**, not at the host boundary — closing the cost-model gap
// flagged in foundation ≤ 0.4.11.
//
// The per-call target bytes come from a thread-local set by
// [`crate::pipeline::set_thread_target`] before each `forward()`
// invocation. Foundation's [`LexicographicLessEqThreshold::target`]
// requires `&'static [u8]` (the predicate is `Copy`), so target
// bytes are leaked into a process-lifetime registry by
// [`crate::commitment::leak_target`]. Bitcoin's difficulty
// retarget every 2016 blocks bounds the registry size to O(epochs).
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        crate::commitment::TargetCommitment
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
        fn commitment() -> crate::commitment::TargetCommitment {
            crate::commitment::target_commitment(crate::pipeline::current_thread_target())
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
    fn mining_result_site_count_matches_digest_width() {
        // Architecture §2.2: MiningResult's 32 W8 sites are exactly the
        // SHA-256d digest width — the natural cost-model κ-label per
        // wiki ADR-048/049 (foundation's LexicographicLessEqThreshold
        // compares the κ-label byte sequence to the target).
        assert_eq!(<MiningResult as ConstrainedTypeShape>::SITE_COUNT, 32);
    }

    #[test]
    fn mining_result_carries_thirty_two_disjoint_site_constraints() {
        // Architecture §2.3 + IT_7d algebraic-closure: 32 disjoint
        // `Site` constraints, one per digest byte. The constraint
        // nerve N(C) has 32 isolated vertices (β_0 = 32, β_k = 0 for
        // k ≥ 1, χ = 32 = SITE_COUNT — IT_7d satisfied).
        let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
        assert_eq!(cs.len(), 32, "32 Site constraints (algebraic-closure)");
        for c in cs {
            assert!(
                matches!(c, ConstraintRef::Site { .. }),
                "every constraint is a Site constraint"
            );
        }
    }

    #[test]
    fn mining_result_constraints_pin_every_digest_site() {
        // Architecture §2.3: each Site constraint pins exactly one
        // digest byte position; positions span [0, 32) disjointly so
        // site supports are pairwise disjoint and the nerve has no
        // 1-simplices.
        let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
        let positions: Vec<u32> = cs
            .iter()
            .filter_map(|c| match c {
                ConstraintRef::Site { position } => Some(*position),
                _ => None,
            })
            .collect();
        assert_eq!(positions.len(), 32, "32 Site constraints");
        for (i, &p) in positions.iter().enumerate() {
            assert_eq!(p, i as u32, "Site_{i} pins position {i}");
        }
    }
}
