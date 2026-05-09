//! Layer-3 verb declarations (wiki ADR-024 three-layer closure).
//!
//! prism-btc, as the implementation crate, declares its domain-specific
//! verbs here. Per ADR-024:
//!
//! > Layer 3 — Implementation closure. Carrier: each implementation's
//! > verb set — named, reusable compositions of prism operators applied
//! > to substrate primitives, declared by the implementation for use
//! > within its own routes [...] Implementation introduces no new
//! > operators, only new named compositions.
//!
//! The verbs below are the architectural commitment that names the
//! mining inference's structure. Each is declared via `verb!` with a
//! closure body composed from G1–G19 (substrate-level forms G1–G11 +
//! prism operators G12–G19, plus the 0.3.6 substrate amendments
//! `concat` and the byte-comparison binary operators `<=`, `<`, `>=`,
//! `>` per ADR-013/TR-08).
//!
//! ## What's here
//!
//! - [`nonce_fiber_traversal`] — the W32 search. Body is the wiki's
//!   intended structural form
//!   `first_admit(WittLevel::W32, |nonce| hash(concat(input, nonce)) <= input)`
//!   (ADR-026 G16 + G19 + 0.3.6 amendments). The runtime that
//!   evaluates this declaration is
//!   [`crate::ops::traversal::traverse_sequential`] (sequential) and
//!   [`crate::ops::traversal::traverse_parallel`] (parallel coset
//!   partition over the W32 ring), per ADR-026 G16's three-way
//!   responsibility split.
//!
//! ## Conformance against the wiki
//!
//! ADR-026 G16 (`first_admit`'s three-way runtime responsibility)
//! splits the search across all three layers:
//!
//! - **Substrate** owns the structural primitives: `Term::Recurse`
//!   for bounded recursion (ADR-029 evaluator: foundation 0.3.6
//!   recursive); `Term::HasherProjection` for `hash(...)`;
//!   `Term::Application(Concat, [a, b])` for byte-sequence packing;
//!   `Term::Application(Le, [a, b])` for byte-level lexicographic
//!   comparison; `WittLevel::W32` for the domain's cardinality.
//! - **Prism** owns `first_admit` as the typed declaration form. The
//!   `uor-foundation-sdk` lowering emits `Term::Recurse { measure:
//!   Literal(256), base: Literal(0), step: <predicate> }`. The 256
//!   measure is symbolic per the SDK comment ("the macro doesn't
//!   introspect <DomainTy as ConstrainedTypeShape> at proc-macro time
//!   […] let implementations override per ADR-024"); the
//!   implementation runtime owns the actual cardinality.
//! - **Implementation** owns the runtime traversal. The conformance
//!   test (ADR-026 G16): the runtime produces the same first-admitting
//!   index a reference sequential traversal would. prism-btc's
//!   [`crate::ops::traversal::traverse_sequential`] IS the reference
//!   sequential traversal over `Z/(2^32)Z` for the (W32,
//!   target-admission) pair — the conformance test is satisfied
//!   trivially.
//!
//! ## What 0.3.6 closes vs what remains implementor-evaluated
//!
//! Foundation 0.3.6 + SDK 0.3.6 close gaps prism-btc had against
//! 0.3.4:
//!
//! 1. The byte-comparison primitive `Le` is in `PrimitiveOp` and the
//!    binary `<=` operator is admitted in the closure-body grammar
//!    (ADR-013/TR-08 substrate amendment); so the predicate's
//!    "digest ≤ target" comparison is now in prism vocabulary.
//! 2. The `Concat` primitive is in `PrimitiveOp` and the
//!    `concat(...)` keyword is admitted in the closure-body grammar;
//!    so `serialize_with_nonce(prefix, nonce)` is expressible as
//!    `concat(input, nonce)` (the runtime layout-orders bytes per
//!    Bitcoin's wire format).
//! 3. `Term::Recurse`'s evaluator iterates N times (N =
//!    `bytes_to_u64_be` of the measure); this is the recursive fold
//!    ADR-029 mandates.
//!
//! What remains an implementor responsibility per ADR-026 G16:
//!
//! - The SDK's `first_admit` lowering emits `Literal(256)` at `W8`
//!   for the measure. Foundation's evaluator reads it as 0 (W8
//!   truncates 256→0), so the structural arena alone iterates 0
//!   times. The implementation runtime ([`crate::ops::traversal`])
//!   walks the W32 ring in canonical successor order with the
//!   conformant cardinality `2^32`.
//! - The closure-body grammar has no general field-access operator
//!   for product-of-shapes inputs; the `<=` comparison's right
//!   operand is `input` (the whole binding) rather than a target
//!   sub-field. The runtime extracts (prefix, target) from the input
//!   per Bitcoin's wire format and applies the comparison
//!   semantically.
//!
//! When foundation amends the SDK to (a) introspect the domain's
//! `cycle_size()` for the measure literal at proc-macro time, and
//! (b) admit field-access projections for product-of-shapes inputs,
//! the verb's runtime can be retired in favor of foundation's
//! evaluator end-to-end without changing the verb declaration.

use uor_foundation_sdk::verb;

use crate::model::MiningInput;

verb! {
    pub fn nonce_fiber_traversal(input: MiningInput) -> MiningInput {
        first_admit(uor_foundation::WittLevel::W32, |nonce| {
            hash(concat(input, nonce)) <= input
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_foundation::enforcement::Term;
    use uor_foundation::PrimitiveOp;

    #[test]
    fn verb_term_arena_is_emitted_and_nonempty() {
        // ADR-024 commits the implementation to declaring its verbs as
        // `&'static [Term]` fragments. The accessor returns that fragment.
        let arena = nonce_fiber_traversal_term_arena();
        assert!(
            !arena.is_empty(),
            "verb term arena must contain the structural form"
        );
    }

    #[test]
    fn verb_arena_contains_a_recurse_node() {
        // ADR-026 G16: `first_admit` lowers to `Term::Recurse`.
        let arena = nonce_fiber_traversal_term_arena();
        let has_recurse = arena.iter().any(|t| matches!(t, Term::Recurse { .. }));
        assert!(
            has_recurse,
            "first_admit lowering must emit a Term::Recurse per ADR-026 G16"
        );
    }

    #[test]
    fn verb_arena_contains_a_hasher_projection() {
        // ADR-026 G19: `hash(...)` lowers to `Term::HasherProjection`.
        let arena = nonce_fiber_traversal_term_arena();
        let has_hasher = arena
            .iter()
            .any(|t| matches!(t, Term::HasherProjection { .. }));
        assert!(
            has_hasher,
            "hash(...) lowering must emit a Term::HasherProjection per ADR-026 G19"
        );
    }

    #[test]
    fn verb_arena_contains_concat_application() {
        // ADR-013/TR-08 (foundation 0.3.6): `concat(a, b)` lowers to
        // `Term::Application(Concat, [a, b])`. Pin that the verb body's
        // structural commitment to byte-sequence packing is in the
        // emitted arena.
        let arena = nonce_fiber_traversal_term_arena();
        let has_concat = arena.iter().any(|t| {
            matches!(
                t,
                Term::Application {
                    operator: PrimitiveOp::Concat,
                    ..
                }
            )
        });
        assert!(
            has_concat,
            "concat(...) lowering must emit a Term::Application(Concat, ...) per ADR-013/TR-08"
        );
    }

    #[test]
    fn verb_arena_contains_le_application() {
        // ADR-013/TR-08 (foundation 0.3.6): the binary `<=` operator
        // lowers to `Term::Application(Le, [lhs, rhs])`. Pin that the
        // predicate's admission comparison is structurally committed.
        let arena = nonce_fiber_traversal_term_arena();
        let has_le = arena.iter().any(|t| {
            matches!(
                t,
                Term::Application {
                    operator: PrimitiveOp::Le,
                    ..
                }
            )
        });
        assert!(
            has_le,
            "<= lowering must emit a Term::Application(Le, ...) per ADR-013/TR-08"
        );
    }
}
