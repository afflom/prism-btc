//! `PrismBtcBounds` — prism-btc's `HostBounds` selection
//! (wiki ADR-018, ADR-037; architecture §3, §9.4).
//!
//! ADR-037 makes the catamorphism's 24-constant capacity profile
//! `HostBounds`-parametric: the per-ψ-stage output ceilings, the route
//! input/output buffer sizes, the nerve/Betti/Jacobian array caps, and
//! the constraint-conjunction/affine-coefficient ceilings. This module
//! declares prism-btc's binding ceiling.

use uor_foundation::HostBounds;

/// prism-btc's capacity profile.
///
/// The first four are prism-btc-specific selections (architecture §3);
/// the remainder are ADR-037 ceilings that prism-btc tracks the
/// foundation defaults on. As prism-btc's hierarchical feature
/// decomposition grows (architecture §9.4), the nerve / chain-complex /
/// resolver-output ceilings rise here without changing the verb body or
/// the model declaration.
///
/// - `FINGERPRINT_MIN_BYTES = 32` — matches SHA-256 output width.
/// - `FINGERPRINT_MAX_BYTES = 32` — fixed; one Hasher (`Sha256dHasher`).
/// - `TRACE_MAX_EVENTS = 64` — small constant; one event per stage
///   transition, not per fiber visit.
/// - `WITT_LEVEL_MAX_BITS = 32` — Bitcoin's `Nonce` field is W32; the
///   typed surface's algebra is W32-bounded.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrismBtcBounds;

impl HostBounds for PrismBtcBounds {
    // prism-btc-specific (architecture §3):
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS: usize = 64;
    const WITT_LEVEL_MAX_BITS: u32 = 32;

    // ADR-037 catamorphism ceilings — track foundation defaults except
    // where prism-btc's algebraic-closure encoding (architecture §2.3,
    // IT_7d: χ(N(C)) = SITE_COUNT, β_k = 0) demands a wider constraint
    // geometry. The wire-format Bitcoin header's 80-site `MiningResult`
    // implies a constraint nerve over up to 80 vertices; the algebraic-
    // closure expressibility scales with these caps. This declaration
    // is the application-side binding ceiling.
    const TERM_VALUE_MAX_BYTES: usize = 4096;
    const AXIS_OUTPUT_BYTES_MAX: usize = 4096;
    const FOLD_UNROLL_THRESHOLD: usize = 8;
    const BETTI_DIMENSION_MAX: usize = 80;
    const NERVE_CONSTRAINTS_MAX: usize = 128;
    const NERVE_SITES_MAX: usize = 80;
    const JACOBIAN_SITES_MAX: usize = 80;
    const RECURSION_TRACE_DEPTH_MAX: usize = 16;
    const OP_CHAIN_DEPTH_MAX: usize = 8;
    const AFFINE_COEFFS_MAX: usize = 80;
    const CONJUNCTION_TERMS_MAX: usize = 128;
    const ROUTE_INPUT_BUFFER_BYTES: usize = 4096;
    const ROUTE_OUTPUT_BUFFER_BYTES: usize = 4096;
    const UNFOLD_ITERATIONS_MAX: usize = 256;

    // ADR-037 per-ψ-stage resolver-output ceilings.
    const NERVE_OUTPUT_BYTES_MAX: usize = 4096;
    const CHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const COCHAIN_COMPLEX_OUTPUT_BYTES_MAX: usize = 4096;
    const COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const POSTNIKOV_TOWER_OUTPUT_BYTES_MAX: usize = 4096;
    const HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX: usize = 4096;
    const K_INVARIANTS_OUTPUT_BYTES_MAX: usize = 4096;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_constants_match_architecture_section_3() {
        assert_eq!(<PrismBtcBounds as HostBounds>::FINGERPRINT_MIN_BYTES, 32);
        assert_eq!(<PrismBtcBounds as HostBounds>::FINGERPRINT_MAX_BYTES, 32);
        assert_eq!(<PrismBtcBounds as HostBounds>::TRACE_MAX_EVENTS, 64);
        assert_eq!(<PrismBtcBounds as HostBounds>::WITT_LEVEL_MAX_BITS, 32);
    }

    #[test]
    fn psi_stage_output_ceilings_are_uniform_and_match_term_value_max() {
        // ADR-037: each ψ-stage's resolver-output ceiling caps that
        // stage's emitted byte serialization. prism-btc binds them all
        // to TERM_VALUE_MAX_BYTES so the catamorphism's per-fold-rule
        // scratch buffer is the limit, not a per-ψ-stage idiosyncrasy.
        let v = <PrismBtcBounds as HostBounds>::TERM_VALUE_MAX_BYTES;
        assert_eq!(<PrismBtcBounds as HostBounds>::NERVE_OUTPUT_BYTES_MAX, v);
        assert_eq!(
            <PrismBtcBounds as HostBounds>::CHAIN_COMPLEX_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::HOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::COCHAIN_COMPLEX_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::COHOMOLOGY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::POSTNIKOV_TOWER_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::HOMOTOPY_GROUPS_OUTPUT_BYTES_MAX,
            v
        );
        assert_eq!(
            <PrismBtcBounds as HostBounds>::K_INVARIANTS_OUTPUT_BYTES_MAX,
            v
        );
    }
}
