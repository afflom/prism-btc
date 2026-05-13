//! prism-btc's `ResolverTuple` — the eight ψ-stage substitution-axis
//! realizations for Bitcoin's typed feature hierarchy
//! (wiki ADR-036; architecture §3, §4).
//!
//! Each resolver realizes its named mathematical role over the typed
//! feature hierarchy's structural geometry. The ψ-chain is a
//! deterministic, parametric, structure-preserving transformation;
//! each stage's emitted bytes describe its mathematical content for
//! the constraint geometry declared on `MiningResult`.
//!
//! ## The constraint geometry
//!
//! `MiningResult::CONSTRAINTS` declares 80 disjoint
//! `ConstraintRef::Site` instances — one per wire-format-header byte
//! (architecture §2.3, IT_7d algebraic-closure). For this geometry,
//! the ψ-chain's stage outputs are fully determined:
//!
//! | ψ-stage | Mathematical content |
//! |---|---|
//! | ψ_1 Nerve N(C) | 80 isolated vertices, no higher simplices |
//! | ψ_2 ChainComplex C_• | C_0 = ℤ^80, C_k = 0 for k ≥ 1; all ∂ = 0 |
//! | ψ_3 HomologyGroups H_k | H_0 = ℤ^80, H_k = 0 for k ≥ 1 |
//! | ψ_4 Betti β_k | β_0 = 80, β_k = 0 for k ≥ 1 (resolver-free) |
//! | ψ_5 CochainComplex C^• | C^0 = ℤ^80, C^k = 0 for k ≥ 1; all δ = 0 |
//! | ψ_6 CohomologyGroups H^k | H^0 = ℤ^80, H^k = 0 for k ≥ 1 |
//! | ψ_7 PostnikovTower P_n | P_n = the discrete 80-set for all n ≥ 0 |
//! | ψ_8 HomotopyGroups π_k | π_0 = the 80-element set, π_k = 0 for k ≥ 1 |
//! | ψ_9 KInvariants κ_n | trivial signature (no obstruction classes); plus the wire-format κ-label |
//!
//! ## Carrier layout
//!
//! Each non-terminal ψ-stage emits a 208-byte structural carrier:
//!
//! ```text
//! [0..108)    MiningTask bytes (TemplatePrefix‖Target) — threaded forward
//! [108..116)  ψ-stage tag (u64 BE, one of {1, 2, 3, 5, 6, 7, 8})
//! [116..120)  u32 BE: vertex_count of the nerve N(C) = 80
//! [120..124)  u32 BE: highest_nontrivial_dim of the underlying space = 0
//! [124..128)  u32 BE: reserved (= 0)
//! [128..208)  80 × u8: per-vertex Site positions (the 80 generators)
//! ```
//!
//! The vertex_count, highest_dim, and Site-position data describe the
//! structural content of the ψ-stage's emitted object. For our
//! constraint geometry this content is the same across stages
//! (vertex_count=80, highest_dim=0, positions=[0..80)) because every
//! ψ-stage on the chain is the (categorical) functor applied to a
//! discrete 80-vertex space — its image is again the discrete 80-set,
//! up to the named ψ-vocabulary. The stage tag at offset 108 carries
//! the per-stage discrimination so ψ-chain replay can audit which
//! stage produced which carrier.
//!
//! Each downstream stage validates the upstream stage tag and the
//! structural invariants of the carrier before emitting its own
//! stage's bytes. A mismatched upstream tag or a malformed geometry
//! surfaces a `ShapeViolation` — the resolver chain refuses to
//! compose if the upstream object is not what the ψ-functor expects.
//!
//! ## ψ_9 KInvariant — the terminal label
//!
//! ψ_9 consumes the ψ_8 HomotopyGroups carrier and emits exactly 80
//! bytes — the wire-format Bitcoin header. The k-invariant signature
//! itself is trivial for π_0-only spaces (no obstruction classes), so
//! the structural content reduces to π_0's 80 generators. ψ_9's
//! load-bearing computation is the **iterative-resolution discipline**
//! per the wiki's
//! [`iterative-resolution.md`](https://github.com/UOR-Foundation/UOR-Framework/blob/main/docs/content/concepts/iterative-resolution.md):
//! the four nonce-byte sites (positions 76..80) carry initial
//! `FreeRank = 1`; the resolver walks the W32 nonce ring
//! (`witt_domain::W32`, `CYCLE_SIZE = 2^32`) — each iteration pins a
//! candidate nonce, evaluates the structural admission relation
//! `H(header) ≤ target` via the canonical hash axis (`H: Hasher`),
//! and continues until convergence (the first admitting nonce) or
//! W32 ring exhaustion. Convergence pins the four nonce-byte sites;
//! the resolver emits the admitting wire-format header.
//!
//! On W32 ring exhaustion without admission, the resolver returns
//! the canonical `proof:InhabitanceImpossibilityWitness` for this
//! constraint geometry; the host boundary (architecture §7) varies
//! the template (extranonce roll → distinct `MiningTask`) and
//! retries.
//!
//! ## Pure-prism commitment
//!
//! The verb body composes only ψ-Term variants
//! (`Term::Nerve / PostnikovTower / HomotopyGroups / KInvariants`); no
//! σ-enumeration leaks into the typed-iso surface. The
//! resolver-internal iterative-resolution loop in ψ_9 IS the
//! framework's structural transform per the wiki, not a σ-enumeration
//! leak. From outside, `forward()` is one structural inference per
//! `MiningTask`.

use core::marker::PhantomData;

use uor_foundation::enforcement::{Hasher, ShapeViolation};
use uor_foundation::pipeline::{
    ChainComplexBytes, ChainComplexResolver, CochainComplexBytes, CochainComplexResolver,
    CohomologyGroupResolver, ConstrainedTypeShape, ConstraintRef, HomologyGroupResolver,
    HomotopyGroupResolver, HomotopyGroupsBytes, KInvariantResolver, NerveResolver,
    PostnikovResolver, PostnikovTowerBytes, SimplicialComplexBytes,
};
use uor_foundation::{HostBounds, ViolationKind};
use uor_foundation_sdk::resolver;

use crate::model::MiningResult;
use crate::shapes::bounds::PrismBtcBounds;

// ─── Carrier layout constants ──────────────────────────────────────────

/// MiningTask byte width (architecture §2.2).
const TASK_BYTES: usize = 108;
/// Per-stage header: tag (8) + vertex_count (4) + highest_dim (4) +
/// reserved (4) = 20 bytes.
const STAGE_HEADER_BYTES: usize = 8 + 4 + 4 + 4;
/// Per-vertex Site-position data: 80 × u8.
const VERTEX_DATA_BYTES: usize = NERVE_VERTEX_COUNT as usize;
/// Total structural carrier byte width.
const CARRIER_BYTES: usize = TASK_BYTES + STAGE_HEADER_BYTES + VERTEX_DATA_BYTES;
/// Wire-format Bitcoin header byte width — the ψ_9 output width.
const WIRE_FORMAT_HEADER_BYTES: usize = 80;

const OFFSET_STAGE_TAG: usize = TASK_BYTES;
const OFFSET_VERTEX_COUNT: usize = TASK_BYTES + 8;
const OFFSET_HIGHEST_DIM: usize = TASK_BYTES + 12;
const OFFSET_RESERVED: usize = TASK_BYTES + 16;
const OFFSET_POSITIONS: usize = TASK_BYTES + 20;

/// Expected nerve-vertex count for the `MiningResult` constraint
/// geometry (architecture §2.3, IT_7d).
const NERVE_VERTEX_COUNT: u32 = 80;
/// Expected highest-nontrivial-dim for the discrete 80-vertex space.
/// The nerve has no 1-simplices (site supports are pairwise disjoint),
/// the chain complex collapses to dim-0, and the underlying space's
/// homotopy type has π_k = 0 for k ≥ 1.
const NERVE_HIGHEST_DIM: u32 = 0;

// ─── ψ-stage tags ──────────────────────────────────────────────────────

const PSI_1_NERVE_TAG: u64 = 1;
const PSI_2_CHAIN_COMPLEX_TAG: u64 = 2;
const PSI_3_HOMOLOGY_GROUPS_TAG: u64 = 3;
const PSI_5_COCHAIN_COMPLEX_TAG: u64 = 5;
const PSI_6_COHOMOLOGY_GROUPS_TAG: u64 = 6;
const PSI_7_POSTNIKOV_TOWER_TAG: u64 = 7;
const PSI_8_HOMOTOPY_GROUPS_TAG: u64 = 8;

// ─── ShapeViolation IRIs ───────────────────────────────────────────────

const TASK_INPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/TaskInput",
    constraint_iri: "https://prism.btc/resolver/TaskInput/expectedTaskBytes",
    property_iri: "https://prism.btc/resolver/TaskInput/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: TASK_BYTES as u32,
    max_count: TASK_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_INPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierInput",
    constraint_iri: "https://prism.btc/resolver/CarrierInput/expectedCarrierBytes",
    property_iri: "https://prism.btc/resolver/CarrierInput/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: CARRIER_BYTES as u32,
    max_count: CARRIER_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

const CARRIER_BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierBuffer",
    constraint_iri: "https://prism.btc/resolver/CarrierBuffer/minBytes",
    property_iri: "https://prism.btc/resolver/CarrierBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: CARRIER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

const KAPPA_OUTPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/KappaLabelBuffer",
    constraint_iri: "https://prism.btc/resolver/KappaLabelBuffer/minBytes",
    property_iri: "https://prism.btc/resolver/KappaLabelBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: WIRE_FORMAT_HEADER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

/// Upstream ψ-stage tag does not match what this stage's ψ-functor
/// expects. The ψ-chain refuses to compose if the upstream object is
/// not the typed-coordinate carrier the downstream functor consumes.
const UPSTREAM_TAG_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/UpstreamStageTag",
    constraint_iri: "https://prism.btc/resolver/UpstreamStageTag/expectedTag",
    property_iri: "https://prism.btc/resolver/UpstreamStageTag/stageTag",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedLong",
    min_count: 1,
    max_count: 1,
    kind: ViolationKind::ValueCheck,
};

/// Upstream carrier's structural geometry does not match the
/// 80-isolated-vertices algebraic-closure geometry that
/// `MiningResult::CONSTRAINTS` declares (architecture §2.3, IT_7d).
const GEOMETRY_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierGeometry",
    constraint_iri: "https://prism.btc/resolver/CarrierGeometry/eightyVerticesDiscrete",
    property_iri: "https://prism.btc/resolver/CarrierGeometry/vertexCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: NERVE_VERTEX_COUNT,
    max_count: NERVE_VERTEX_COUNT,
    kind: ViolationKind::ValueCheck,
};

/// `MiningResult::CONSTRAINTS` does not declare the expected
/// 80-disjoint-Site algebraic-closure geometry. ψ_1 cannot build the
/// nerve N(C) when the constraint set is malformed.
const NERVE_GEOMETRY_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/NerveGeometry",
    constraint_iri: "https://prism.btc/resolver/NerveGeometry/eightyDisjointSites",
    property_iri: "https://prism.btc/resolver/NerveGeometry/constraintCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: NERVE_VERTEX_COUNT,
    max_count: NERVE_VERTEX_COUNT,
    kind: ViolationKind::ValueCheck,
};

/// `InhabitanceImpossibilityWitness` for the κ-derivation — signalled
/// when the W32 nonce ring is walked end-to-end without the
/// structural admission relation being satisfied for the host-supplied
/// `(prefix, target)`. Foundation carries the canonical
/// impossibility-witness vocabulary in
/// [`proof:InhabitanceImpossibilityWitness`](https://uor.foundation/proof/InhabitanceImpossibilityWitness);
/// prism-btc surfaces it through the resolver-bound
/// [`uor_foundation::enforcement::ShapeViolation`] channel until the
/// substrate exposes the impossibility witness as a first-class
/// resolver return type.
const NONCE_FIBER_EXHAUSTED: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/InhabitanceImpossibility",
    constraint_iri: "https://prism.btc/resolver/InhabitanceImpossibility/nonceFiberExhausted",
    property_iri: "https://prism.btc/resolver/InhabitanceImpossibility/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

// ─── Carrier encode/decode ─────────────────────────────────────────────

/// Decoded view of a structural ψ-stage carrier.
struct DecodedCarrier<'a> {
    /// MiningTask bytes (TemplatePrefix‖Target), 108 bytes, threaded
    /// forward unchanged.
    task: &'a [u8],
    /// The upstream ψ-stage tag (one of {1, 2, 3, 5, 6, 7, 8}).
    stage_tag: u64,
    /// Nerve vertex count — invariant 80 for the algebraic-closure
    /// geometry.
    vertex_count: u32,
    /// Highest nontrivial dimension of the underlying space —
    /// invariant 0 for the discrete 80-vertex case.
    highest_dim: u32,
}

fn decode_carrier(bytes: &[u8]) -> Result<DecodedCarrier<'_>, ShapeViolation> {
    if bytes.len() != CARRIER_BYTES {
        return Err(CARRIER_INPUT_VIOLATION);
    }
    let task = &bytes[..TASK_BYTES];
    let stage_tag = u64::from_be_bytes(
        bytes[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT]
            .try_into()
            .expect("8 bytes"),
    );
    let vertex_count = u32::from_be_bytes(
        bytes[OFFSET_VERTEX_COUNT..OFFSET_HIGHEST_DIM]
            .try_into()
            .expect("4 bytes"),
    );
    let highest_dim = u32::from_be_bytes(
        bytes[OFFSET_HIGHEST_DIM..OFFSET_RESERVED]
            .try_into()
            .expect("4 bytes"),
    );
    Ok(DecodedCarrier {
        task,
        stage_tag,
        vertex_count,
        highest_dim,
    })
}

/// Validate the upstream carrier: stage tag matches what this
/// downstream ψ-functor expects; structural geometry is the 80-isolated-
/// vertices algebraic-closure shape `MiningResult::CONSTRAINTS`
/// declares.
fn validate_upstream(
    carrier: &DecodedCarrier<'_>,
    expected_upstream_tag: u64,
) -> Result<(), ShapeViolation> {
    if carrier.stage_tag != expected_upstream_tag {
        return Err(UPSTREAM_TAG_VIOLATION);
    }
    if carrier.vertex_count != NERVE_VERTEX_COUNT {
        return Err(GEOMETRY_VIOLATION);
    }
    if carrier.highest_dim != NERVE_HIGHEST_DIM {
        return Err(GEOMETRY_VIOLATION);
    }
    Ok(())
}

/// Emit a structural carrier with the given stage tag. The threaded
/// task bytes preserve the typed `MiningTask` data; the geometry data
/// describes this ψ-stage's mathematical content for the 80-isolated-
/// vertices case (vertex_count=80, highest_dim=0, positions=[0..80)).
fn emit_carrier(task: &[u8], stage_tag: u64, out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if out.len() < CARRIER_BYTES {
        return Err(CARRIER_BUFFER_VIOLATION);
    }
    if task.len() != TASK_BYTES {
        return Err(TASK_INPUT_VIOLATION);
    }

    out[..TASK_BYTES].copy_from_slice(task);
    out[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT].copy_from_slice(&stage_tag.to_be_bytes());
    out[OFFSET_VERTEX_COUNT..OFFSET_HIGHEST_DIM].copy_from_slice(&NERVE_VERTEX_COUNT.to_be_bytes());
    out[OFFSET_HIGHEST_DIM..OFFSET_RESERVED].copy_from_slice(&NERVE_HIGHEST_DIM.to_be_bytes());
    out[OFFSET_RESERVED..OFFSET_POSITIONS].copy_from_slice(&0u32.to_be_bytes());

    // The 80 vertex/generator positions: Site_i pins position i.
    for i in 0..NERVE_VERTEX_COUNT as usize {
        out[OFFSET_POSITIONS + i] = i as u8;
    }

    Ok(CARRIER_BYTES)
}

// ─── ψ_1 Nerve — Constraints → SimplicialComplex ───────────────────────

/// ψ_1 `Nerve` resolver — `Constraints → SimplicialComplex`.
///
/// Reads `MiningResult::CONSTRAINTS` and builds the nerve N(C). For
/// prism-btc's 80 disjoint `ConstraintRef::Site` declarations
/// (architecture §2.3), N(C) is 80 isolated vertices with no higher
/// simplices: vertices = constraints, k-simplices = sets of (k+1)
/// constraints whose site supports share a common site. With
/// pairwise-disjoint site supports, no two constraints share a site,
/// so there are no 1-simplices and no higher.
///
/// The resolver validates that `MiningResult::CONSTRAINTS` exhibits the
/// algebraic-closure encoding (IT_7d: 80 disjoint Site constraints,
/// Site_i pinning position i) before emitting the ψ_1 carrier.
#[derive(Debug)]
pub struct BitcoinNerveResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinNerveResolver<H> {}

impl<H: Hasher> NerveResolver<H> for BitcoinNerveResolver<H> {
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if input.len() != TASK_BYTES {
            return Err(TASK_INPUT_VIOLATION);
        }
        if out.len() < CARRIER_BYTES {
            return Err(CARRIER_BUFFER_VIOLATION);
        }

        // Build N(C) from `MiningResult::CONSTRAINTS`. The IT_7d
        // algebraic-closure declaration is 80 disjoint Site_i
        // constraints with Site_i pinning position i.
        let constraints = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
        if constraints.len() != NERVE_VERTEX_COUNT as usize {
            return Err(NERVE_GEOMETRY_VIOLATION);
        }
        for (i, c) in constraints.iter().enumerate() {
            match c {
                ConstraintRef::Site { position } => {
                    if *position as usize != i {
                        return Err(NERVE_GEOMETRY_VIOLATION);
                    }
                }
                _ => return Err(NERVE_GEOMETRY_VIOLATION),
            }
        }

        emit_carrier(input, PSI_1_NERVE_TAG, out)
    }
}

// ─── ψ_2 ChainComplex — SimplicialComplex → ChainComplex ───────────────

/// ψ_2 `ChainComplex` resolver — `SimplicialComplex → ChainComplex`.
///
/// For the discrete 80-vertex nerve N(C), the chain complex C_• has
/// `C_0 = ℤ^80` (one generator per vertex), `C_k = 0` for k ≥ 1 (no
/// higher simplices), and all boundary maps `∂_k = 0`. The structural
/// content (vertex_count=80, highest_dim=0) is preserved in the
/// carrier; the ψ_2 stage tag distinguishes this carrier from the
/// upstream ψ_1 nerve.
///
/// Off-path on the mining transform (verb body composes only ψ_1, ψ_7,
/// ψ_8, ψ_9); the resolver is realized for substitution-axis
/// completeness (ADR-036) and to support the homology branch.
#[derive(Debug)]
pub struct BitcoinChainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinChainComplexResolver<H> {}

impl<H: Hasher> ChainComplexResolver<H> for BitcoinChainComplexResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_1_NERVE_TAG)?;
        emit_carrier(carrier.task, PSI_2_CHAIN_COMPLEX_TAG, out)
    }
}

// ─── ψ_3 HomologyGroups — ChainComplex → HomologyGroups ────────────────

/// ψ_3 `HomologyGroups` resolver — `ChainComplex → HomologyGroups`.
///
/// `H_k = ker(∂_k) / im(∂_{k+1})`. For C_• with all ∂ = 0:
/// `H_0 = C_0 / 0 = ℤ^80`; `H_k = 0` for k ≥ 1.
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinHomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomologyGroupResolver<H> {}

impl<H: Hasher> HomologyGroupResolver<H> for BitcoinHomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_2_CHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.task, PSI_3_HOMOLOGY_GROUPS_TAG, out)
    }
}

// ─── ψ_5 CochainComplex — ChainComplex → CochainComplex ────────────────

/// ψ_5 `CochainComplex` resolver — `ChainComplex → CochainComplex`.
///
/// Dualization: `C^k = Hom(C_k, ℤ)`. For C_• with `C_0 = ℤ^80` and
/// `C_k = 0` for k ≥ 1: `C^0 = ℤ^80`, `C^k = 0` for k ≥ 1; all
/// coboundary maps `δ_k = 0` (dual of zero is zero).
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinCochainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCochainComplexResolver<H> {}

impl<H: Hasher> CochainComplexResolver<H> for BitcoinCochainComplexResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_2_CHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.task, PSI_5_COCHAIN_COMPLEX_TAG, out)
    }
}

// ─── ψ_6 CohomologyGroups — CochainComplex → CohomologyGroups ──────────

/// ψ_6 `CohomologyGroups` resolver — `CochainComplex → CohomologyGroups`.
///
/// `H^k = ker(δ_k) / im(δ_{k-1})`. For C^• with all δ = 0:
/// `H^0 = C^0 / 0 = ℤ^80`; `H^k = 0` for k ≥ 1.
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinCohomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCohomologyGroupResolver<H> {}

impl<H: Hasher> CohomologyGroupResolver<H> for BitcoinCohomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: CochainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_5_COCHAIN_COMPLEX_TAG)?;
        emit_carrier(carrier.task, PSI_6_COHOMOLOGY_GROUPS_TAG, out)
    }
}

// ─── ψ_7 PostnikovTower — SimplicialComplex → PostnikovTower ───────────

/// ψ_7 `PostnikovTower` resolver — `SimplicialComplex → PostnikovTower`.
///
/// The Postnikov tower `{P_n}` truncates the underlying space's
/// homotopy type at each level. For the discrete 80-vertex space:
/// `P_0 = π_0 = the discrete 80-set`; `P_n = P_0` for n ≥ 1 (no higher
/// homotopy to truncate). The Postnikov classifying maps are
/// k(P_{n-1}, π_n) — trivial here because π_n = 0 for n ≥ 1.
///
/// On the mining-transform path (ψ_1 → ψ_7 → ψ_8 → ψ_9).
#[derive(Debug)]
pub struct BitcoinPostnikovResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinPostnikovResolver<H> {}

impl<H: Hasher> PostnikovResolver<H> for BitcoinPostnikovResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_1_NERVE_TAG)?;
        emit_carrier(carrier.task, PSI_7_POSTNIKOV_TOWER_TAG, out)
    }
}

// ─── ψ_8 HomotopyGroups — PostnikovTower → HomotopyGroups ──────────────

/// ψ_8 `HomotopyGroups` resolver — `PostnikovTower → HomotopyGroups`.
///
/// Extracts homotopy groups `π_k` from the Postnikov tower. For the
/// discrete 80-vertex space: `π_0` = the 80-element set of connected
/// components (one per isolated vertex); `π_k = 0` for k ≥ 1.
///
/// On the mining-transform path (ψ_1 → ψ_7 → ψ_8 → ψ_9).
#[derive(Debug)]
pub struct BitcoinHomotopyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomotopyGroupResolver<H> {}

impl<H: Hasher> HomotopyGroupResolver<H> for BitcoinHomotopyGroupResolver<H> {
    fn resolve(
        &self,
        input: PostnikovTowerBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_7_POSTNIKOV_TOWER_TAG)?;
        emit_carrier(carrier.task, PSI_8_HOMOTOPY_GROUPS_TAG, out)
    }
}

// ─── ψ_9 KInvariants — the terminal label ──────────────────────────────

/// ψ_9 `KInvariant` resolver — `HomotopyGroups → KInvariants`, the
/// terminal ψ-stage.
///
/// k-invariants `κ_n ∈ H^{n+2}(π_1; π_{n+1})` classify the Postnikov
/// tower's twisted-fibration data. For prism-btc's discrete 80-vertex
/// space (`π_0 = 80-set`, `π_k = 0` for k ≥ 1), the k-invariant
/// signature itself is **trivial** — no obstruction classes to fuse.
/// The load-bearing computation is the **iterative-resolution
/// discipline** (wiki `iterative-resolution.md`) that materializes
/// the four nonce-byte sites against the structural admission relation,
/// producing the 80-byte wire-format Bitcoin header as the κ-label.
///
/// The resolver:
/// 1. Validates the upstream ψ_8 carrier (geometry = 80 isolated
///    π_0 components).
/// 2. Extracts the host-supplied prefix (76 bytes) and target
///    (32 bytes) from the threaded `MiningTask` data.
/// 3. Runs the iterative-resolution loop on the four nonce-byte sites
///    (positions 76..80). Each iteration evaluates the structural
///    admission relation `H(header) ≤ target` (lex on 32-byte
///    display-order bytes) via the canonical hash axis `H`; `FreeRank`
///    decreases by 1 per pinned site, and convergence (FreeRank = 0
///    across all four sites simultaneously) is the first satisfying
///    nonce.
/// 4. On convergence, emits the admitting wire-format header.
/// 5. On W32 ring exhaustion without admission, returns the canonical
///    `proof:InhabitanceImpossibilityWitness` ([`NONCE_FIBER_EXHAUSTED`])
///    so the host boundary varies the template and retries.
#[derive(Debug)]
pub struct BitcoinKInvariantResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinKInvariantResolver<H> {}

impl<H: Hasher> KInvariantResolver<H> for BitcoinKInvariantResolver<H> {
    fn resolve(
        &self,
        input: HomotopyGroupsBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        if out.len() < WIRE_FORMAT_HEADER_BYTES {
            return Err(KAPPA_OUTPUT_VIOLATION);
        }

        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_8_HOMOTOPY_GROUPS_TAG)?;

        // task[0..76] = prefix; task[76..108] = target.
        let prefix = &carrier.task[..76];
        let target = &carrier.task[76..108];

        // Assemble the candidate header in place; nonce-field bytes
        // [76..80) are pinned per iteration.
        let mut header = [0u8; WIRE_FORMAT_HEADER_BYTES];
        header[..76].copy_from_slice(prefix);

        // Iterative-resolution loop over witt_domain::W32. Each
        // iteration evaluates the structural admission relation
        // H(header) ≤ target (lex on 32-byte display-order bytes);
        // convergence is the first satisfying nonce.
        let mut nonce: u32 = 0;
        loop {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());

            // σ-projection of the assembled header via the canonical
            // hash axis. Sha256dHasher returns SHA-256d in internal
            // byte order; Bitcoin's admission rule compares in display
            // order (internal-reversed).
            let digest_internal = H::initial().fold_bytes(&header).finalize();
            let mut digest_display = [0u8; 32];
            let copy_len = digest_internal.len().min(32);
            digest_display[..copy_len].copy_from_slice(&digest_internal[..copy_len]);
            digest_display.reverse();

            if lex_le(&digest_display, target) {
                out[..WIRE_FORMAT_HEADER_BYTES].copy_from_slice(&header);
                return Ok(WIRE_FORMAT_HEADER_BYTES);
            }

            if nonce == u32::MAX {
                return Err(NONCE_FIBER_EXHAUSTED);
            }
            nonce += 1;
        }
    }
}

/// Lex-≤ over two 32-byte big-endian byte sequences (Bitcoin display
/// order). Returns `true` iff `lhs` is lexicographically ≤ `rhs`.
#[inline]
fn lex_le(lhs: &[u8; 32], rhs: &[u8]) -> bool {
    let mut i = 0;
    while i < 32 && i < rhs.len() {
        if lhs[i] < rhs[i] {
            return true;
        }
        if lhs[i] > rhs[i] {
            return false;
        }
        i += 1;
    }
    lhs.len() <= rhs.len()
}

// ─── Default impls + ResolverTuple ─────────────────────────────────────

macro_rules! impl_default_for_resolver {
    ($resolver:ident) => {
        impl<H: Hasher> Default for $resolver<H> {
            #[inline]
            fn default() -> Self {
                Self(PhantomData)
            }
        }
    };
}

impl_default_for_resolver!(BitcoinNerveResolver);
impl_default_for_resolver!(BitcoinChainComplexResolver);
impl_default_for_resolver!(BitcoinHomologyGroupResolver);
impl_default_for_resolver!(BitcoinCochainComplexResolver);
impl_default_for_resolver!(BitcoinCohomologyGroupResolver);
impl_default_for_resolver!(BitcoinPostnikovResolver);
impl_default_for_resolver!(BitcoinHomotopyGroupResolver);
impl_default_for_resolver!(BitcoinKInvariantResolver);

resolver! {
    pub struct BitcoinResolverTuple<H: ::uor_foundation::enforcement::Hasher> {
        nerve: BitcoinNerveResolver<H>,
        chain_complex: BitcoinChainComplexResolver<H>,
        homology_groups: BitcoinHomologyGroupResolver<H>,
        cochain_complex: BitcoinCochainComplexResolver<H>,
        cohomology_groups: BitcoinCohomologyGroupResolver<H>,
        postnikov: BitcoinPostnikovResolver<H>,
        homotopy_groups: BitcoinHomotopyGroupResolver<H>,
        k_invariants: BitcoinKInvariantResolver<H>,
    }
}

// ─── Compile-time invariants ───────────────────────────────────────────

const _: () = {
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::NERVE_OUTPUT_BYTES_MAX,
        "ψ_1 carrier exceeds NERVE_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::CHAIN_COMPLEX_OUTPUT_BYTES_MAX,
        "ψ_2 carrier exceeds CHAIN_COMPLEX_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_3 carrier exceeds HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::COCHAIN_COMPLEX_OUTPUT_BYTES_MAX,
        "ψ_5 carrier exceeds COCHAIN_COMPLEX_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_6 carrier exceeds COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::POSTNIKOV_TOWER_OUTPUT_BYTES_MAX,
        "ψ_7 carrier exceeds POSTNIKOV_TOWER_OUTPUT_BYTES_MAX"
    );
    assert!(
        CARRIER_BYTES <= <PrismBtcBounds as HostBounds>::HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX,
        "ψ_8 carrier exceeds HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX"
    );
    assert!(
        WIRE_FORMAT_HEADER_BYTES <= <PrismBtcBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX,
        "ψ_9 κ-label exceeds K_INVARIANTS_OUTPUT_BYTES_MAX"
    );
};
