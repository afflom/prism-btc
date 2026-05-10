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
//! prism operators G12–G19, including the `concat` keyword and the
//! byte-comparison binary operators `<=`, `<`, `>=`, `>` per
//! ADR-013/TR-08).
//!
//! ## What's here
//!
//! - [`nonce_fiber_traversal`] — the W32 search. Body is the wiki's
//!   intended structural form
//!   `first_admit(witt_domain::W32, |nonce| hash(concat(input, nonce)) <= input)`
//!   (ADR-026 G16 + G19, ADR-013/TR-08 amendments). The runtime that
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
//!   for bounded recursion (ADR-029 recursive evaluator);
//!   `Term::AxisInvocation` against the canonical hash axis for
//!   `hash(...)` (ADR-030); `Term::Application(Concat, [a, b])` for
//!   byte-sequence packing; `Term::Application(Le, [a, b])` for
//!   byte-level lexicographic comparison; `witt_domain::W32` for the
//!   domain's cardinality (ADR-032: `CYCLE_SIZE = 2^32`).
//! - **Prism** owns `first_admit` as the typed declaration form. The
//!   `uor-foundation-sdk` lowering reads
//!   `<witt_domain::W32 as ConstrainedTypeShape>::CYCLE_SIZE` at the
//!   consumer's compile time (ADR-032) and emits
//!   `Term::Recurse { measure: Literal(2^32 @ W64),
//!                    base:    Literal(0),
//!                    step:    <predicate term tree> }`.
//! - **Implementation** owns the runtime traversal. The conformance
//!   test (ADR-026 G16): the runtime produces the same first-admitting
//!   index a reference sequential traversal would. prism-btc's
//!   [`crate::ops::traversal::traverse_sequential`] IS the reference
//!   sequential traversal over `Z/(2^32)Z` for the (W32,
//!   target-admission) pair — the conformance test is satisfied
//!   trivially.
//!
//! ## Why the implementation runtime is still needed
//!
//! Foundation 0.4.0 closed two SDK proc-macro-time gaps from 0.3.6:
//! `CYCLE_SIZE` introspection (ADR-032) makes the descent measure
//! load-bearing at proc-macro time, and `PartitionProductFields`
//! (ADR-033) admits field-access projections. With these, foundation
//! drives the recursion 2^32 times per the recursive `Term::Recurse`
//! fold-rule (ADR-029).
//!
//! What foundation 0.4.0 does NOT yet do:
//!
//! - Bind `idx_ident` (the `nonce` closure parameter in the predicate
//!   body) to the iteration counter. The SDK source comment is explicit:
//!   *"Foundation binds idx_ident to the measure root for now; the
//!   structural declaration is what matters per ADR-024."* The predicate
//!   therefore evaluates to a constant per iteration; the iteration
//!   index never enters the predicate's term tree.
//! - Short-circuit on admission. `Term::Recurse` always iterates the
//!   full `CYCLE_SIZE` and returns the final accumulator; there is no
//!   fold-rule that says "stop when the step's value indicates admit."
//!
//! Per ADR-026 G16's three-way split, both gaps fall to the
//! implementation runtime: the runtime threads the actual nonce
//! through the σ-projection per fiber visit, tests admission, and
//! halts at the first admitting nonce.

use uor_foundation_sdk::verb;

use crate::model::MiningInput;

verb! {
    pub fn nonce_fiber_traversal(input: MiningInput) -> MiningInput {
        first_admit(uor_foundation::pipeline::witt_domain::W32, |nonce| {
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
    fn verb_arena_contains_a_canonical_hash_axis_invocation() {
        // ADR-026 G19 + ADR-030: `hash(...)` lowers to
        // `Term::AxisInvocation { axis_index: 0, kernel_id: 0, .. }` —
        // the canonical hash axis (HashAxis::KERNEL_HASH = 0). The
        // blanket `impl<H: Hasher> AxisTuple for H` routes the (0, 0)
        // dispatch through `Sha256dHasher`.
        let arena = nonce_fiber_traversal_term_arena();
        let has_canonical_hash = arena.iter().any(|t| {
            matches!(
                t,
                Term::AxisInvocation {
                    axis_index: 0,
                    kernel_id: 0,
                    ..
                }
            )
        });
        assert!(
            has_canonical_hash,
            "hash(...) lowering must emit a Term::AxisInvocation against \
             the canonical hash axis per ADR-026 G19 + ADR-030"
        );
    }

    #[test]
    fn verb_arena_contains_concat_application() {
        // ADR-013/TR-08: `concat(a, b)` lowers to
        // `Term::Application(Concat, [a, b])`.
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
        // ADR-013/TR-08: the binary `<=` operator lowers to
        // `Term::Application(Le, [lhs, rhs])`.
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
