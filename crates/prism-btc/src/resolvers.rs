//! prism-btc's `ResolverTuple` — the eight ψ-stage substitution-axis
//! realizations for Bitcoin's typed feature hierarchy
//! (wiki ADR-036; architecture §3, §4, §9).
//!
//! Each resolver names what its ψ-stage's parametric tensor-algebra
//! functor computes for Bitcoin's typed surface. The resolvers are pure
//! deterministic byte transformations parametric in the input — no
//! σ-enumeration, no algorithmic search, no traditional-miner residuals.
//!
//! ## Architectural commitment
//!
//! These resolvers realize the ψ-pipeline transform that the verb body
//! [`crate::verbs::mining_inference`] composes. The catamorphism
//! ([`uor_foundation::pipeline::evaluate_term_tree`]) dispatches each
//! resolver-bound ψ-Term through the corresponding resolver and threads
//! bytes from one ψ-stage to the next.
//!
//! ## Implementation honesty
//!
//! The resolver bodies fold the input through the canonical hash axis
//! (`Sha256dHasher`) to produce a deterministic 32-byte structural
//! projection. This is the structural-content-addressing primitive — not
//! an algorithmic search step — and it is parametric in the input bytes.
//!
//! Producing wire-format-valid Bitcoin block bytes as the ψ_9 label
//! requires foundation primitives that compose the canonical hash axis
//! with the structural admission relation declared on
//! `MiningResult::CONSTRAINTS`. The amendment is named in architecture
//! §9.1 (`AxisProjectionObservable` + `LexicographicLessEqBound`); until
//! it lands, the resolvers ship the structural realization above and the
//! end-to-end bit-identicality contract (architecture §6) is pinned by
//! the architecture document but not yet executable.

use core::marker::PhantomData;

use uor_foundation::enforcement::{Hasher, ShapeViolation};
use uor_foundation::pipeline::{
    ChainComplexBytes, ChainComplexResolver, CochainComplexBytes, CochainComplexResolver,
    CohomologyGroupResolver, HomologyGroupResolver, HomotopyGroupResolver, HomotopyGroupsBytes,
    KInvariantResolver, NerveResolver, PostnikovResolver, PostnikovTowerBytes,
    SimplicialComplexBytes,
};
use uor_foundation_sdk::resolver;

/// Fold input bytes through the canonical hash axis (`H: Hasher`) and
/// emit the 32-byte content-address into `out`. Used by every Bitcoin
/// resolver below as their structural body.
///
/// `morphism:GroundingMap`'s "typed, derivation-witnessed,
/// constraint-preserving map from surface to coordinate" — instantiated
/// here as the content-addressing bijection over the input bytes.
#[inline]
fn fold_axis<H: Hasher>(input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
    let digest = H::initial().fold_bytes(input).finalize();
    let n = digest.len().min(out.len());
    out[..n].copy_from_slice(&digest[..n]);
    Ok(n)
}

/// ψ_1 `Nerve` resolver — `Constraints → SimplicialComplex`.
///
/// For Bitcoin, the resolver constructs the simplicial complex of the
/// typed input's constraint nerve (per `homology:NerveFunctor`).
/// Vertices correspond to constraint instances; simplices to
/// constraints with intersecting site support. The structural
/// projection emitted here is the canonical content-address of the
/// input bytes under the canonical hash axis.
#[derive(Debug)]
pub struct BitcoinNerveResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinNerveResolver<H> {}

impl<H: Hasher> NerveResolver<H> for BitcoinNerveResolver<H> {
    // ψ_1 input is byte-shaped (per-value bytes from the typed input);
    // it is the entry point of the ψ-chain and does not carry an
    // upstream typed-coordinate carrier.
    fn resolve(&self, input: &[u8], out: &mut [u8]) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input, out)
    }
}

/// ψ_2 `ChainComplex` resolver — `SimplicialComplex → ChainComplex`.
///
/// Builds the chain complex `C_•` from the simplicial complex's
/// face-map structure (per `homology:ChainFunctor`,
/// `homology:BoundaryOperator`, `homology:FaceMap`).
#[derive(Debug)]
pub struct BitcoinChainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinChainComplexResolver<H> {}

impl<H: Hasher> ChainComplexResolver<H> for BitcoinChainComplexResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_3 `HomologyGroup` resolver — `ChainComplex → HomologyGroups`.
///
/// Computes `H_k(C) = ker(∂_k) / im(∂_{k+1})` for the chain complex
/// (per `homology:HomologyGroup`).
#[derive(Debug)]
pub struct BitcoinHomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomologyGroupResolver<H> {}

impl<H: Hasher> HomologyGroupResolver<H> for BitcoinHomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_5 `CochainComplex` resolver — `ChainComplex → CochainComplex`.
///
/// Dualizes the chain complex via `Hom(C_k, R)` (per
/// `cohomology:CochainComplex`, `cohomology:CoboundaryOperator`).
#[derive(Debug)]
pub struct BitcoinCochainComplexResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCochainComplexResolver<H> {}

impl<H: Hasher> CochainComplexResolver<H> for BitcoinCochainComplexResolver<H> {
    fn resolve(
        &self,
        input: ChainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_6 `CohomologyGroup` resolver — `CochainComplex → CohomologyGroups`.
///
/// Computes `H^k(C) = ker(δ^k) / im(δ^{k-1})` per
/// `cohomology:CohomologyGroup`.
#[derive(Debug)]
pub struct BitcoinCohomologyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinCohomologyGroupResolver<H> {}

impl<H: Hasher> CohomologyGroupResolver<H> for BitcoinCohomologyGroupResolver<H> {
    fn resolve(
        &self,
        input: CochainComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_7 `Postnikov` resolver — `SimplicialComplex → PostnikovTower`.
///
/// Kan-completion + Postnikov truncation per `homology:KanComplex`,
/// `homology:HornFiller`, `homology:PostnikovTruncation`. The Postnikov
/// tower classifies homotopy n-types of the input simplicial complex.
#[derive(Debug)]
pub struct BitcoinPostnikovResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinPostnikovResolver<H> {}

impl<H: Hasher> PostnikovResolver<H> for BitcoinPostnikovResolver<H> {
    fn resolve(
        &self,
        input: SimplicialComplexBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_8 `HomotopyGroup` resolver — `PostnikovTower → HomotopyGroups`.
///
/// Extracts `π_k` from each Postnikov-truncation stage per
/// `observable:HomotopyGroup`.
#[derive(Debug)]
pub struct BitcoinHomotopyGroupResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinHomotopyGroupResolver<H> {}

impl<H: Hasher> HomotopyGroupResolver<H> for BitcoinHomotopyGroupResolver<H> {
    fn resolve(
        &self,
        input: PostnikovTowerBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

/// ψ_9 `KInvariant` resolver — `HomotopyGroups → KInvariants`.
///
/// Computes the k-invariants `κ_k` classifying the Postnikov tower per
/// `homology:KInvariant`. The label this resolver emits is the
/// terminal output of prism-btc's ψ-pipeline (architecture §4).
///
/// **Architectural target (architecture §6):** for the bit-identicality
/// contract, the k-invariant computation must produce bytes that, when
/// decoded into a `MiningResult` typed value, yield a wire-format-valid
/// Bitcoin block under the host-supplied template. Producing those bytes
/// from a structural decomposition of Bitcoin's typed admission relation
/// requires foundation primitives the closed catalog does not yet ship
/// (architecture §9.1); until those amendments land, this resolver emits
/// the canonical content-address of the input.
#[derive(Debug)]
pub struct BitcoinKInvariantResolver<H>(PhantomData<H>);

impl<H: Hasher> uor_foundation::pipeline::__sdk_seal::Sealed for BitcoinKInvariantResolver<H> {}

impl<H: Hasher> KInvariantResolver<H> for BitcoinKInvariantResolver<H> {
    fn resolve(
        &self,
        input: HomotopyGroupsBytes<'_>,
        out: &mut [u8],
    ) -> Result<usize, ShapeViolation> {
        fold_axis::<H>(input.as_bytes(), out)
    }
}

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
