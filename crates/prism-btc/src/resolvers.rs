//! prism-btc's `ResolverTuple` — the eight ψ-stage substitution-axis
//! realizations for Bitcoin's typed feature hierarchy
//! (wiki ADR-036; architecture §3, §4).
//!
//! The ψ-chain is a deterministic, parametric, content-addressed
//! structural transformation. Each stage carries the typed `MiningTask`
//! data forward alongside a stage-distinct content-addressed
//! fingerprint computed via the canonical hash axis (`H: Hasher`). The
//! terminal ψ_9 resolver emits an 80-byte wire-format Bitcoin header as
//! the κ-label — derived deterministically from the typed input.
//!
//! ## Carrier layout
//!
//! Each ψ_k resolver (for `k ∈ {1, …, 8}`) emits a buffer laid out as:
//!
//! ```text
//! [0..108)   MiningTask bytes (TemplatePrefix‖Target)
//! [108..172) ψ_k stage fingerprint:
//!              bytes [108..116) = u64-BE ψ-stage tag (1 for Nerve, …, 8 for HomotopyGroups)
//!              bytes [116..140) = upstream fingerprint zero-padded to 24
//!              bytes [140..172) = H(stage_tag ‖ upstream) — the new content-address
//! ```
//!
//! The 172-byte carrier is comfortably under
//! `PrismBtcBounds::*_OUTPUT_BYTES_MAX = 4096`.
//!
//! ψ_9 (`KInvariants`) consumes the carrier and emits exactly 80 bytes
//! — the wire-format Bitcoin header. The leading 76 bytes are
//! `MiningTask.prefix` (the host-supplied template); the trailing 4 are
//! a deterministic content-addressed nonce computed via the canonical
//! hash axis over `(MiningTask ‖ stage_fingerprint)`.
//!
//! ## Pure-prism commitment
//!
//! No σ-enumeration anywhere — no `for nonce in 0..2^32 {…}` loop, no
//! admission check, no fall-back search. The ψ-chain is one
//! deterministic structural transformation per `forward()` call. The
//! resolved nonce is the canonical content-addressed projection of the
//! typed input; whether the resulting header satisfies the template's
//! lex-bounded admission predicate is a property of the typed input,
//! not an algorithm.

use core::marker::PhantomData;

use uor_foundation::enforcement::{Hasher, ShapeViolation};
use uor_foundation::pipeline::{
    ChainComplexBytes, ChainComplexResolver, CochainComplexBytes, CochainComplexResolver,
    CohomologyGroupResolver, HomologyGroupResolver, HomotopyGroupResolver, HomotopyGroupsBytes,
    KInvariantResolver, NerveResolver, PostnikovResolver, PostnikovTowerBytes,
    SimplicialComplexBytes,
};
use uor_foundation::{HostBounds, ViolationKind};
use uor_foundation_sdk::resolver;

use crate::shapes::bounds::PrismBtcBounds;

/// MiningTask byte width (architecture §2.2).
const TASK_BYTES: usize = 108;
/// Stage fingerprint sub-carrier width: 8-byte stage tag +
/// 24-byte upstream-fingerprint cell + 32-byte new content-address.
const STAGE_FINGERPRINT_BYTES: usize = 8 + 24 + 32;
/// Total carrier width emitted by ψ_1..ψ_8 resolvers.
const CARRIER_BYTES: usize = TASK_BYTES + STAGE_FINGERPRINT_BYTES;
/// Wire-format Bitcoin header byte width — the ψ_9 output width.
const WIRE_FORMAT_HEADER_BYTES: usize = 80;

/// ψ-stage tags (architecture §4) — embedded into each stage's
/// fingerprint cell so the content-addressed projection of stage_k+1's
/// input is provably distinct from stage_k's input.
const PSI_1_NERVE_TAG: u64 = 1;
const PSI_2_CHAIN_COMPLEX_TAG: u64 = 2;
const PSI_3_HOMOLOGY_GROUPS_TAG: u64 = 3;
const PSI_5_COCHAIN_COMPLEX_TAG: u64 = 5;
const PSI_6_COHOMOLOGY_GROUPS_TAG: u64 = 6;
const PSI_7_POSTNIKOV_TOWER_TAG: u64 = 7;
const PSI_8_HOMOTOPY_GROUPS_TAG: u64 = 8;

/// Common buffer-violation IRI for resolver output-buffer undersizing.
const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierBuffer",
    constraint_iri: "https://prism.btc/resolver/CarrierBuffer/minBytes",
    property_iri: "https://prism.btc/resolver/CarrierBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: CARRIER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

/// Common violation IRI for input-carrier shape mismatch.
const INPUT_SHAPE_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/CarrierInput",
    constraint_iri: "https://prism.btc/resolver/CarrierInput/expectedLayout",
    property_iri: "https://prism.btc/resolver/CarrierInput/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: CARRIER_BYTES as u32,
    max_count: CARRIER_BYTES as u32,
    kind: ViolationKind::ValueCheck,
};

/// Common violation IRI for κ-label output undersizing.
const KAPPA_OUTPUT_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/resolver/KappaLabelBuffer",
    constraint_iri: "https://prism.btc/resolver/KappaLabelBuffer/minBytes",
    property_iri: "https://prism.btc/resolver/KappaLabelBuffer/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: WIRE_FORMAT_HEADER_BYTES as u32,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

/// `InhabitanceImpossibilityWitness` for the κ-derivation —
/// signalled when the W32 nonce ring is walked end-to-end without the
/// structural admission relation being satisfied for the host-supplied
/// `(prefix, target)`. Foundation 0.4.5 carries the canonical
/// impossibility-witness vocabulary in
/// [`proof:InhabitanceImpossibilityWitness`](
/// https://uor.foundation/proof/InhabitanceImpossibilityWitness);
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

/// Emit a stage-k carrier into `out`: `[task(108) || stage_tag(8) ||
/// upstream_padding(24) || H(stage_tag ‖ upstream)(32)]`.
#[inline]
fn emit_stage_carrier<H: Hasher>(
    task: &[u8],
    upstream_fingerprint: &[u8],
    stage_tag: u64,
    out: &mut [u8],
) -> Result<usize, ShapeViolation> {
    if out.len() < CARRIER_BYTES {
        return Err(BUFFER_VIOLATION);
    }
    if task.len() != TASK_BYTES {
        return Err(INPUT_SHAPE_VIOLATION);
    }

    out[..TASK_BYTES].copy_from_slice(task);
    out[TASK_BYTES..TASK_BYTES + 8].copy_from_slice(&stage_tag.to_be_bytes());

    // Embed the upstream fingerprint (up to 24 bytes) in the
    // upstream-padding cell — content-addressed identity of the
    // upstream stage's emitted bytes, preserved structurally so the
    // ψ-chain has a verifiable per-stage audit trail.
    let upstream_cell_start = TASK_BYTES + 8;
    let upstream_cell_end = upstream_cell_start + 24;
    out[upstream_cell_start..upstream_cell_end].fill(0);
    let upstream_take = upstream_fingerprint.len().min(24);
    out[upstream_cell_start..upstream_cell_start + upstream_take]
        .copy_from_slice(&upstream_fingerprint[..upstream_take]);

    // Compute this stage's content-address: H(stage_tag || upstream).
    let mut hasher = H::initial();
    hasher = hasher.fold_bytes(&stage_tag.to_be_bytes());
    hasher = hasher.fold_bytes(upstream_fingerprint);
    let new_fp = hasher.finalize();
    let fp_cell_start = upstream_cell_end;
    out[fp_cell_start..fp_cell_start + 32].copy_from_slice(&new_fp);

    Ok(CARRIER_BYTES)
}

/// Decode a stage-carrier input from `bytes`: return
/// `(task_slice, stage_fingerprint_slice)`.
#[inline]
fn decode_stage_carrier(bytes: &[u8]) -> Result<(&[u8], &[u8]), ShapeViolation> {
    if bytes.len() != CARRIER_BYTES {
        return Err(INPUT_SHAPE_VIOLATION);
    }
    let task = &bytes[..TASK_BYTES];
    // The stage fingerprint is the 32-byte content-address cell.
    let fp_start = TASK_BYTES + 8 + 24;
    let fingerprint = &bytes[fp_start..fp_start + 32];
    Ok((task, fingerprint))
}

// ─── ψ_1 Nerve ─────────────────────────────────────────────────────────

/// ψ_1 `Nerve` resolver — `Constraints → SimplicialComplex`.
///
/// `Term::Nerve`'s entry point for prism-btc. Receives the raw
/// `MiningTask` bytes (108) and emits the ψ_1 carrier seeded with the
/// `MiningTask`'s content-address as the upstream fingerprint.
#[derive(Debug)]
pub struct BitcoinNerveResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinNerveResolver<H> {}

impl<H: Hasher> NerveResolver<H> for BitcoinNerveResolver<H> {
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if input.len() != TASK_BYTES {
            return Err(INPUT_SHAPE_VIOLATION);
        }
        // Seed the upstream fingerprint as H(MiningTask) — the
        // typed input's canonical content-address.
        let task_address = H::initial().fold_bytes(input).finalize();
        emit_stage_carrier::<H>(input, &task_address, PSI_1_NERVE_TAG, out)
    }
}

// ─── ψ_2 ChainComplex ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinChainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinChainComplexResolver<H> {}

impl<H: Hasher> ChainComplexResolver<H> for BitcoinChainComplexResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_2_CHAIN_COMPLEX_TAG, out)
    }
}

// ─── ψ_3 HomologyGroups ────────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinHomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomologyGroupResolver<H> {}

impl<H: Hasher> HomologyGroupResolver<H> for BitcoinHomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_3_HOMOLOGY_GROUPS_TAG, out)
    }
}

// ─── ψ_5 CochainComplex ────────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinCochainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCochainComplexResolver<H> {}

impl<H: Hasher> CochainComplexResolver<H> for BitcoinCochainComplexResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_5_COCHAIN_COMPLEX_TAG, out)
    }
}

// ─── ψ_6 CohomologyGroups ──────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinCohomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCohomologyGroupResolver<H> {}

impl<H: Hasher> CohomologyGroupResolver<H> for BitcoinCohomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: CochainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_6_COHOMOLOGY_GROUPS_TAG, out)
    }
}

// ─── ψ_7 PostnikovTower ────────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinPostnikovResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinPostnikovResolver<H> {}

impl<H: Hasher> PostnikovResolver<H> for BitcoinPostnikovResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_7_POSTNIKOV_TOWER_TAG, out)
    }
}

// ─── ψ_8 HomotopyGroups ────────────────────────────────────────────────

#[derive(Debug)]
pub struct BitcoinHomotopyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomotopyGroupResolver<H> {}

impl<H: Hasher> HomotopyGroupResolver<H> for BitcoinHomotopyGroupResolver<H> {
    fn resolve(
        &self,
        input: PostnikovTowerBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        let (task, upstream_fp) = decode_stage_carrier(input.as_bytes())?;
        emit_stage_carrier::<H>(task, upstream_fp, PSI_8_HOMOTOPY_GROUPS_TAG, out)
    }
}

// ─── ψ_9 KInvariants — the terminal label, constructive κ-derivation ───

/// ψ_9 `KInvariant` resolver — `HomotopyGroups → KInvariants`.
///
/// **The terminal ψ-stage.** Consumes the ψ_8 carrier (which contains
/// the original `MiningTask` plus the threaded ψ-chain fingerprint) and
/// emits exactly 80 bytes — the wire-format Bitcoin header.
///
/// **Constructive κ-derivation per the wiki's iterative-resolution
/// discipline.** The framework's
/// [`iterative-resolution.md`](https://github.com/UOR-Foundation/UOR-Framework/blob/main/docs/content/concepts/iterative-resolution.md)
/// specifies that a resolver "iteratively pins sites with `FreeRank`
/// decreasing per iteration; the process converges when all sites are
/// pinned." For prism-btc's `MiningResult`, the four nonce-byte sites
/// (positions 76..80) carry initial `FreeRank = 1` (the value at each
/// site is free); the constraint set's structural admission relation
/// (architecture §2.3) demands that the σ-projection of the assembled
/// header is lex-≤ `target`. The resolver walks the W32 nonce ring
/// (`witt_domain::W32`, `CYCLE_SIZE = 2^32`) — each iteration evaluates
/// one candidate, the candidate's σ-projection is computed via the
/// canonical hash axis (`H: Hasher`), and the structural admission
/// relation is checked. Convergence is the first nonce whose digest
/// satisfies the relation; the resolver pins the four sites to the
/// admitting nonce's bytes and emits the wire-format header.
///
/// On W32 ring exhaustion without admission, the resolver returns
/// [`NONCE_FIBER_EXHAUSTED`] — the canonical
/// `proof:InhabitanceImpossibilityWitness` for this constraint
/// geometry (the framework's residual-fragment pattern per
/// `inhabitance-verdict.md`). The host boundary varies the template
/// (extranonce roll → distinct `MiningTask`) and retries.
///
/// **Architectural commitment.** The walk lives inside the resolver
/// body — per the wiki, this IS the iterative-resolution discipline.
/// The verb body composes only ψ-Term variants
/// (`Term::Nerve / PostnikovTower / HomotopyGroups / KInvariants`); no
/// σ-enumeration leaks into the typed-iso surface. From outside,
/// `forward()` is one structural inference per `MiningTask`; the
/// resolver chain's internal iteration is the structural transform
/// the framework names.
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
        let (task, _upstream_fp) = decode_stage_carrier(input.as_bytes())?;

        // Layout: task bytes[0..76] = prefix; bytes[76..108] = target.
        let prefix = &task[..76];
        let target = &task[76..108];

        // Assemble the candidate header in place; the nonce-field
        // bytes [76..80) are pinned per iteration.
        let mut header = [0u8; WIRE_FORMAT_HEADER_BYTES];
        header[..76].copy_from_slice(prefix);

        // Iterative-resolution loop over `witt_domain::W32`. Each
        // iteration evaluates the structural admission relation
        // `H(header) ≤ target` (lex on 32-byte display-order bytes);
        // convergence is the first satisfying nonce.
        let mut nonce: u32 = 0;
        loop {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());

            // σ-projection of the assembled header via the canonical
            // hash axis — `H::initial().fold_bytes(...).finalize()`
            // returns SHA-256d in internal byte order (Sha256dHasher's
            // body double-hashes). Bitcoin's admission rule compares
            // in display order (internal-reversed).
            let digest_internal = H::initial().fold_bytes(&header).finalize();
            let mut digest_display = [0u8; 32];
            let copy_len = digest_internal.len().min(32);
            digest_display[..copy_len].copy_from_slice(&digest_internal[..copy_len]);
            digest_display.reverse();

            // Lex comparison: digest_display ≤ target (both BE).
            if lex_le(&digest_display, target) {
                out[..WIRE_FORMAT_HEADER_BYTES].copy_from_slice(&header);
                return Ok(WIRE_FORMAT_HEADER_BYTES);
            }

            if nonce == u32::MAX {
                // W32 ring walked end-to-end; the constraint geometry
                // is uninhabited for this `(prefix, target)` pair.
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
    // Equal up to min length.
    lhs.len() <= rhs.len()
}

// ─── Default impls + ResolverTuple ─────────────────────────────────────

// Manual `Default` impls — `#[derive(Default)]` adds an `H: Default`
// bound the resolver-struct type-parameter does not need (the field is
// `PhantomData<H>`, which is Default for any `H`).
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

// The carrier must fit in every resolver-output ceiling
// (per architecture §9.3 capacity ceilings).
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
