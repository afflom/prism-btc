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
//! `MiningResult::CONSTRAINTS` declares 32 disjoint
//! `ConstraintRef::Site` instances — one per digest byte
//! (architecture §2.3, IT_7d algebraic-closure). For this geometry,
//! the ψ-chain's stage outputs are fully determined:
//!
//! | ψ-stage | Mathematical content |
//! |---|---|
//! | ψ_1 Nerve N(C) | 32 isolated vertices, no higher simplices |
//! | ψ_2 ChainComplex C_• | C_0 = ℤ^32, C_k = 0 for k ≥ 1; all ∂ = 0 |
//! | ψ_3 HomologyGroups H_k | H_0 = ℤ^32, H_k = 0 for k ≥ 1 |
//! | ψ_4 Betti β_k | β_0 = 32, β_k = 0 for k ≥ 1 (resolver-free) |
//! | ψ_5 CochainComplex C^• | C^0 = ℤ^32, C^k = 0 for k ≥ 1; all δ = 0 |
//! | ψ_6 CohomologyGroups H^k | H^0 = ℤ^32, H^k = 0 for k ≥ 1 |
//! | ψ_7 PostnikovTower P_n | P_n = the discrete 32-set for all n ≥ 0 |
//! | ψ_8 HomotopyGroups π_k | π_0 = the 32-element set, π_k = 0 for k ≥ 1 |
//! | ψ_9 KInvariants κ_n | trivial signature (no obstruction classes); plus the 32-byte digest κ-label |
//!
//! ## Carrier layout
//!
//! Each non-terminal ψ-stage emits a 160-byte structural carrier:
//!
//! ```text
//! [0..108)    MiningTask bytes (TemplatePrefix‖Target) — threaded forward
//! [108..116)  ψ-stage tag (u64 BE, one of {1, 2, 3, 5, 6, 7, 8})
//! [116..120)  u32 BE: vertex_count of the nerve N(C) = 32
//! [120..124)  u32 BE: highest_nontrivial_dim of the underlying space = 0
//! [124..128)  u32 BE: reserved (= 0)
//! [128..160)  32 × u8: per-vertex Site positions (the 32 generators)
//! ```
//!
//! The vertex_count, highest_dim, and Site-position data describe the
//! structural content of the ψ-stage's emitted object. For our
//! constraint geometry this content is the same across stages
//! (vertex_count=32, highest_dim=0, positions=[0..32)) because every
//! ψ-stage on the chain is the (categorical) functor applied to a
//! discrete 32-vertex space — its image is again the discrete 32-set,
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
//! ψ_9 consumes the ψ_8 HomotopyGroups carrier and emits exactly 32
//! bytes — `SHA-256d(wire_format_header)` in Bitcoin display order.
//! This 32-byte digest IS the cost-model κ-label foundation's
//! `LexicographicLessEqThreshold` predicate compares against the
//! target (wiki ADR-048/049). The k-invariant signature itself is
//! trivial for π_0-only spaces (no obstruction classes), so the
//! structural content reduces to π_0's 32 generators. ψ_9's
//! load-bearing computation is the **structural κ-derivation**:
//!
//! 1. Project the typed `MiningTask` via the canonical hash axis to a
//!    32-byte content-address; the leading four bytes (canonical
//!    Bitcoin little-endian) yield the κ-nonce.
//! 2. Reconstruct the 80-byte wire-format Bitcoin header internally
//!    from `(template_prefix, κ-nonce)`.
//! 3. Compute `SHA-256d` over the wire-format header in display order
//!    — the 32-byte digest is the κ-label.
//!
//! One canonical-hash-axis projection plus one SHA-256d evaluation
//! per `forward()`. Deterministic in the typed input, no enumeration,
//! no search.
//!
//! The wiki's iterative-resolution discipline converges at the
//! terminal ψ-stage for every well-formed `MiningTask`: `FreeRank`
//! over `MiningResult` drops from 32 (all digest sites unpinned) to
//! 0 (all 32 digest sites pinned by the SHA-256d evaluation) in this
//! one stage. The resolver returns `Ok` with the digest κ-label.
//!
//! Whether the κ-label satisfies the host-supplied target is the
//! **admission relation** — evaluated inside foundation's `run_route`
//! via the model's pinned `C = TargetCommitment`
//! (`LexicographicLessEqThreshold` compares the κ-label byte sequence
//! to the target). On non-admission `run_route` returns
//! `PipelineFailure::ShapeViolation`, which
//! [`crate::pipeline::mine`] classifies as
//! [`crate::pipeline::MiningFailure::DidNotAdmit`]; the host
//! (architecture §7) varies the template-derived `MiningTask`
//! (extranonce roll → distinct prefix → distinct κ-derivation) and
//! retries.
//!
//! ## Pure-prism commitment
//!
//! The verb body composes only ψ-Term variants
//! (`Term::Nerve / PostnikovTower / HomotopyGroups / KInvariants`); no
//! σ-enumeration leaks into the typed-iso surface, and none of the
//! resolver bodies enumerate either. From outside, `forward()` is
//! one structural inference per `MiningTask` — the ψ-pipeline maps
//! typed input to κ-label by structural transformation, never by
//! search.

use core::marker::PhantomData;

use prism::pipeline::{
    resolver, ChainComplexResolver, CochainComplexResolver, CohomologyGroupResolver,
    ConstrainedTypeShape, ConstraintRef, HomologyGroupResolver, HomotopyGroupResolver,
    KInvariantResolver, NerveResolver, PostnikovResolver, ShapeViolation, ViolationKind,
};
use prism::uor_foundation::pipeline::{
    ChainComplexBytes, CochainComplexBytes, HomotopyGroupsBytes, PostnikovTowerBytes,
    SimplicialComplexBytes,
};
use prism::vocabulary::{Hasher, HostBounds};

use crate::diagnostics::{record as record_resolution, ResolutionState};
use crate::model::MiningResult;
use crate::ops::header::splice_nonce;
use crate::ops::sha256::sha256d_display;
use crate::shapes::bounds::PrismBtcBounds;

// ─── Carrier layout constants ──────────────────────────────────────────

/// MiningTask byte width (architecture §2.2).
const TASK_BYTES: usize = 108;
/// Per-stage header: tag (8) + vertex_count (4) + highest_dim (4) +
/// reserved (4) = 20 bytes.
const STAGE_HEADER_BYTES: usize = 8 + 4 + 4 + 4;
/// Per-vertex Site-position data: 32 × u8.
const VERTEX_DATA_BYTES: usize = NERVE_VERTEX_COUNT as usize;
/// Total structural carrier byte width.
const CARRIER_BYTES: usize = TASK_BYTES + STAGE_HEADER_BYTES + VERTEX_DATA_BYTES;
/// SHA-256d digest byte width — the ψ_9 κ-label width and the natural
/// cost-model κ-label per wiki ADR-048/049 (foundation's
/// `LexicographicLessEqThreshold` predicate compares this byte
/// sequence against the target).
const DIGEST_BYTES: usize = 32;
/// Wire-format Bitcoin header byte width — the intermediate ψ_9
/// reconstructs internally before hashing to the κ-label digest.
const WIRE_FORMAT_HEADER_BYTES: usize = 80;

/// Length of the constant tail of every non-terminal ψ-stage's
/// carrier: vertex_count (4) + highest_dim (4) + reserved (4) +
/// per-vertex Site positions (`NERVE_VERTEX_COUNT`).
const CARRIER_GEOMETRY_TAIL_BYTES: usize = 12 + VERTEX_DATA_BYTES;

const OFFSET_STAGE_TAG: usize = TASK_BYTES;
const OFFSET_VERTEX_COUNT: usize = TASK_BYTES + 8;
const OFFSET_HIGHEST_DIM: usize = TASK_BYTES + 12;
const OFFSET_RESERVED: usize = TASK_BYTES + 16;

/// Expected nerve-vertex count for the `MiningResult` constraint
/// geometry (architecture §2.3, IT_7d).
const NERVE_VERTEX_COUNT: u32 = 32;
/// Expected highest-nontrivial-dim for the discrete 32-vertex space.
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
    min_count: DIGEST_BYTES as u32,
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
/// 32-isolated-vertices algebraic-closure geometry that
/// `MiningResult::CONSTRAINTS` declares (architecture §2.3, IT_7d).
const GEOMETRY_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierGeometry",
    constraint_iri: "https://prism.btc/resolver/CarrierGeometry/thirtyTwoVerticesDiscrete",
    property_iri: "https://prism.btc/resolver/CarrierGeometry/vertexCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#unsignedInt",
    min_count: NERVE_VERTEX_COUNT,
    max_count: NERVE_VERTEX_COUNT,
    kind: ViolationKind::ValueCheck,
};

// ─── Compile-time validation of MiningResult::CONSTRAINTS ──────────────

// The 32-disjoint-Site algebraic-closure shape (IT_7d, architecture
// §2.3) is a compile-time invariant of `MiningResult`. We assert it
// here so the runtime carrier emit never re-validates: any malformed
// CONSTRAINTS declaration fails the build before reaching ψ_1.
const _: () = {
    let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
    assert!(
        cs.len() == NERVE_VERTEX_COUNT as usize,
        "MiningResult::CONSTRAINTS must declare exactly 32 Site instances (IT_7d algebraic-closure)"
    );
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            ConstraintRef::Site { position } => {
                assert!(
                    position as usize == i,
                    "MiningResult::CONSTRAINTS: Site_i must pin position i for i ∈ [0, 32)"
                );
            }
            _ => panic!(
                "MiningResult::CONSTRAINTS may only contain ConstraintRef::Site instances under the IT_7d algebraic-closure encoding"
            ),
        }
        i += 1;
    }
};

// ─── Const carrier-tail template ───────────────────────────────────────

/// The constant geometry tail of every non-terminal ψ-stage's carrier.
/// Layout: `vertex_count (4) ‖ highest_dim (4) ‖ reserved (4) ‖
/// vertex_positions (32)`. Computed once at compile time; emitted
/// byte-identically by every stage's `emit_carrier` call (only the
/// task bytes and the 8-byte stage tag vary per stage). Lifting these
/// bytes to a const eliminates per-emit field-write arithmetic and a
/// runtime `for i in 0..32` loop.
const CARRIER_GEOMETRY_TAIL: [u8; CARRIER_GEOMETRY_TAIL_BYTES] = {
    let mut t = [0u8; CARRIER_GEOMETRY_TAIL_BYTES];
    let vc = NERVE_VERTEX_COUNT.to_be_bytes();
    t[0] = vc[0];
    t[1] = vc[1];
    t[2] = vc[2];
    t[3] = vc[3];
    // highest_dim @ [4..8) and reserved @ [8..12) are zero-init.
    let mut i = 0;
    while i < VERTEX_DATA_BYTES {
        t[12 + i] = i as u8;
        i += 1;
    }
    t
};

// ─── Carrier encode/decode ─────────────────────────────────────────────

/// Decoded view of a structural ψ-stage carrier.
struct DecodedCarrier<'a> {
    /// MiningTask bytes (TemplatePrefix‖Target), 108 bytes, threaded
    /// forward unchanged.
    task: &'a [u8],
    /// The upstream ψ-stage tag (one of {1, 2, 3, 5, 6, 7, 8}).
    stage_tag: u64,
    /// Nerve vertex count — invariant 32 for the algebraic-closure
    /// geometry.
    vertex_count: u32,
    /// Highest nontrivial dimension of the underlying space —
    /// invariant 0 for the discrete 32-vertex case.
    highest_dim: u32,
}

#[inline]
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
/// downstream ψ-functor expects; structural geometry is the 32-isolated-
/// vertices algebraic-closure shape `MiningResult::CONSTRAINTS`
/// declares.
#[inline]
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
/// (vertex_count = 32, highest_dim = 0, positions = [0..32)) lives in
/// [`CARRIER_GEOMETRY_TAIL`] as a compile-time constant and is bit-
/// copied into the carrier as-is. The runtime cost per emit is three
/// `copy_from_slice` calls — two bounds-checks plus the moves — no
/// per-byte loop and no per-field arithmetic.
#[inline]
fn emit_carrier(task: &[u8], stage_tag: u64, out: &mut [u8]) -> Result<usize, ShapeViolation> {
    if out.len() < CARRIER_BYTES {
        return Err(CARRIER_BUFFER_VIOLATION);
    }
    if task.len() != TASK_BYTES {
        return Err(TASK_INPUT_VIOLATION);
    }

    out[..TASK_BYTES].copy_from_slice(task);
    out[OFFSET_STAGE_TAG..OFFSET_VERTEX_COUNT].copy_from_slice(&stage_tag.to_be_bytes());
    out[OFFSET_VERTEX_COUNT..CARRIER_BYTES].copy_from_slice(&CARRIER_GEOMETRY_TAIL);

    Ok(CARRIER_BYTES)
}

// ─── ψ_1 Nerve — Constraints → SimplicialComplex ───────────────────────

/// ψ_1 `Nerve` resolver — `Constraints → SimplicialComplex`.
///
/// Builds N(C) for `MiningResult::CONSTRAINTS`. For prism-btc's 32
/// disjoint `ConstraintRef::Site` declarations (architecture §2.3),
/// N(C) is 32 isolated vertices with no higher simplices: vertices =
/// constraints, k-simplices = sets of (k+1) constraints whose site
/// supports share a common site; pairwise-disjoint site supports
/// produce no 1-simplices and no higher.
///
/// The 32-disjoint-Site algebraic-closure shape is a compile-time
/// invariant of `MiningResult` — asserted at module load by the
/// `const _: () = { … }` block above. The runtime resolver body
/// emits the ψ_1 carrier directly without re-validating; any
/// malformed CONSTRAINTS declaration fails the build before the
/// resolver ever runs.
#[derive(Debug)]
pub struct BitcoinNerveResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinNerveResolver<H> {}

impl<H: Hasher> NerveResolver<H> for BitcoinNerveResolver<H> {
    #[inline]
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if input.len() != TASK_BYTES {
            return Err(TASK_INPUT_VIOLATION);
        }
        emit_carrier(input, PSI_1_NERVE_TAG, out)
    }
}

// ─── ψ_2 ChainComplex — SimplicialComplex → ChainComplex ───────────────

/// ψ_2 `ChainComplex` resolver — `SimplicialComplex → ChainComplex`.
///
/// For the discrete 32-vertex nerve N(C), the chain complex C_• has
/// `C_0 = ℤ^32` (one generator per vertex), `C_k = 0` for k ≥ 1 (no
/// higher simplices), and all boundary maps `∂_k = 0`. The structural
/// content (vertex_count=32, highest_dim=0) is preserved in the
/// carrier; the ψ_2 stage tag distinguishes this carrier from the
/// upstream ψ_1 nerve.
///
/// Off-path on the mining transform (verb body composes only ψ_1, ψ_7,
/// ψ_8, ψ_9); the resolver is realized for substitution-axis
/// completeness (ADR-036) and to support the homology branch.
#[derive(Debug)]
pub struct BitcoinChainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinChainComplexResolver<H>
{
}

impl<H: Hasher> ChainComplexResolver<H> for BitcoinChainComplexResolver<H> {
    #[inline]
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
/// `H_0 = C_0 / 0 = ℤ^32`; `H_k = 0` for k ≥ 1.
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinHomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinHomologyGroupResolver<H>
{
}

impl<H: Hasher> HomologyGroupResolver<H> for BitcoinHomologyGroupResolver<H> {
    #[inline]
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
/// Dualization: `C^k = Hom(C_k, ℤ)`. For C_• with `C_0 = ℤ^32` and
/// `C_k = 0` for k ≥ 1: `C^0 = ℤ^32`, `C^k = 0` for k ≥ 1; all
/// coboundary maps `δ_k = 0` (dual of zero is zero).
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinCochainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinCochainComplexResolver<H>
{
}

impl<H: Hasher> CochainComplexResolver<H> for BitcoinCochainComplexResolver<H> {
    #[inline]
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
/// `H^0 = C^0 / 0 = ℤ^32`; `H^k = 0` for k ≥ 1.
///
/// Off-path on the mining transform.
#[derive(Debug)]
pub struct BitcoinCohomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinCohomologyGroupResolver<H>
{
}

impl<H: Hasher> CohomologyGroupResolver<H> for BitcoinCohomologyGroupResolver<H> {
    #[inline]
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
/// homotopy type at each level. For the discrete 32-vertex space:
/// `P_0 = π_0 = the discrete 32-set`; `P_n = P_0` for n ≥ 1 (no higher
/// homotopy to truncate). The Postnikov classifying maps are
/// k(P_{n-1}, π_n) — trivial here because π_n = 0 for n ≥ 1.
///
/// On the mining-transform path (ψ_1 → ψ_7 → ψ_8 → ψ_9).
#[derive(Debug)]
pub struct BitcoinPostnikovResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinPostnikovResolver<H>
{
}

impl<H: Hasher> PostnikovResolver<H> for BitcoinPostnikovResolver<H> {
    #[inline]
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
/// discrete 32-vertex space: `π_0` = the 32-element set of connected
/// components (one per isolated vertex); `π_k = 0` for k ≥ 1.
///
/// On the mining-transform path (ψ_1 → ψ_7 → ψ_8 → ψ_9).
#[derive(Debug)]
pub struct BitcoinHomotopyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinHomotopyGroupResolver<H>
{
}

impl<H: Hasher> HomotopyGroupResolver<H> for BitcoinHomotopyGroupResolver<H> {
    #[inline]
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
/// tower's twisted-fibration data. For prism-btc's discrete 32-vertex
/// space (`π_0 = 32-set`, `π_k = 0` for k ≥ 1), the k-invariant
/// signature itself is **trivial** — no obstruction classes to fuse.
/// The terminal ψ-stage's load-bearing computation is the **structural
/// κ-derivation** producing the cost-model κ-label.
///
/// **The κ-derivation.**
///
/// 1. Project the typed `MiningTask` via the canonical hash axis
///    (`H: Hasher` — the substitution-axis selection per ADR-030)
///    to a 32-byte content-address; the leading four bytes (in
///    canonical Bitcoin little-endian) are the κ-nonce.
/// 2. Reconstruct the 80-byte wire-format Bitcoin header internally
///    from `(template_prefix, κ-nonce)`.
/// 3. Compute `SHA-256d` over the wire-format header in display order
///    — the 32-byte digest IS the κ-label.
///
/// This is the natural cost-model κ-label per wiki ADR-048/049:
/// foundation's `LexicographicLessEqThreshold` predicate compares the
/// κ-label byte sequence against the target, so emitting the digest
/// directly closes the cost-model conformance gap (Bitcoin admission
/// is now expressible inside the typed-iso surface). One canonical-
/// hash-axis projection plus one SHA-256d evaluation total per
/// `forward()` — deterministic in the typed input, no enumeration,
/// no search. The wiki's iterative-resolution discipline converges
/// here: all 32 digest sites pin simultaneously to the SHA-256d
/// evaluation; `FreeRank` over `MiningResult` drops from 32 to 0 in
/// this single terminal stage.
///
/// **The resolver always succeeds** for well-formed `MiningTask`
/// inputs: every typed input produces a digest κ-label. Whether that
/// κ-label satisfies the host-supplied `target` is the **admission
/// relation**, evaluated inside foundation's `run_route` via the
/// model's pinned `C = TargetCommitment`. On non-admission `run_route`
/// returns `PipelineFailure::ShapeViolation`, which
/// [`crate::pipeline::mine`] classifies as
/// [`crate::pipeline::MiningFailure::DidNotAdmit`]; the host
/// (architecture §7) varies the template-derived `MiningTask` and
/// retries.
#[derive(Debug)]
pub struct BitcoinKInvariantResolver<H>(PhantomData<H>);

impl<H: Hasher> prism::uor_foundation::pipeline::__sdk_seal::Sealed
    for BitcoinKInvariantResolver<H>
{
}

impl<H: Hasher> KInvariantResolver<H> for BitcoinKInvariantResolver<H> {
    #[inline]
    fn resolve(
        &self,
        input: HomotopyGroupsBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        if out.len() < DIGEST_BYTES {
            return Err(KAPPA_OUTPUT_VIOLATION);
        }

        let carrier = decode_carrier(input.as_bytes())?;
        validate_upstream(&carrier, PSI_8_HOMOTOPY_GROUPS_TAG)?;

        // task[0..76] = prefix; task[76..108] = target.
        let prefix_slice = &carrier.task[..76];
        let mut prefix = [0u8; 76];
        prefix.copy_from_slice(prefix_slice);

        // Step 1 — structural κ-derivation: project the typed
        // MiningTask to a 32-byte content-address via the canonical
        // hash axis; bytes [0..4) become the κ-nonce in Bitcoin LE.
        let derivation = H::initial().fold_bytes(carrier.task).finalize();
        let nonce_bytes: [u8; 4] = [derivation[0], derivation[1], derivation[2], derivation[3]];
        let derived_nonce = u32::from_le_bytes(nonce_bytes);

        // Step 2 — reconstruct the 80-byte wire-format header from
        // `(prefix, derived_nonce)`.
        let wire_format_header: [u8; WIRE_FORMAT_HEADER_BYTES] =
            splice_nonce(&prefix, derived_nonce);

        // Step 3 — compute SHA-256d(wire_format_header) in Bitcoin
        // display order; this 32-byte digest IS the κ-label.
        let digest = sha256d_display(&wire_format_header);

        // Emit the 32-byte κ-label digest.
        out[..DIGEST_BYTES].copy_from_slice(&digest);

        record_resolution(ResolutionState {
            free_rank: 0,
            derived_nonce,
        });

        Ok(DIGEST_BYTES)
    }
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
    pub struct BitcoinResolverTuple<H: ::prism::vocabulary::Hasher> {
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
        DIGEST_BYTES <= <PrismBtcBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX,
        "ψ_9 κ-label exceeds K_INVARIANTS_OUTPUT_BYTES_MAX"
    );
};
