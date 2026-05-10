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
//! - **Substrate** owns the structural primitives:
//!   `Term::FirstAdmit` for bounded ascending search with
//!   admission short-circuit (ADR-034 Mechanism 2);
//!   `Term::AxisInvocation` against the canonical hash axis for
//!   `hash(...)` (ADR-030); `Term::Application(Concat, [a, b])` for
//!   byte-sequence packing; `Term::Application(Le, [a, b])` for
//!   byte-level lexicographic comparison; `witt_domain::W32` for the
//!   domain's cardinality (ADR-032: `CYCLE_SIZE = 2^32`).
//! - **Prism** owns `first_admit` as the typed declaration form. The
//!   `uor-foundation-sdk` lowering reads
//!   `<witt_domain::W32 as ConstrainedTypeShape>::CYCLE_SIZE` at the
//!   consumer's compile time (ADR-032) and emits
//!   `Term::FirstAdmit { domain_size_index, predicate_index }` with
//!   `idx_ident` bound to the foundation-fixed
//!   `FIRST_ADMIT_IDX_NAME_INDEX` placeholder, which the catamorphism
//!   threads to the candidate iteration index per ADR-034 Mechanism 2.
//! - **Implementation** owns the runtime traversal. The conformance
//!   test (ADR-026 G16): the runtime produces the same first-admitting
//!   index a reference sequential traversal would. prism-btc's
//!   [`crate::ops::traversal::traverse_sequential`] IS the reference
//!   sequential traversal — the conformance test is satisfied
//!   trivially.
//!
//! ## Foundation 0.4.1 closes the architectural gap (ADR-034)
//!
//! Foundation 0.4.1 ships ADR-034's two mechanisms — both closing the
//! prior delegations to the implementation runtime:
//!
//! - **Mechanism 1**: `recurse(measure, base, |self, idx| step)`
//!   admits a 2-parameter step closure where the second parameter is
//!   the iteration counter (bound via `RECURSE_IDX_NAME_INDEX`).
//! - **Mechanism 2**: `first_admit(<domain>, |idx| pred)` lowers to
//!   `Term::FirstAdmit { domain_size_index, predicate_index }`. The
//!   evaluator iterates `idx` ascending from 0 to N (read from the
//!   domain's `CYCLE_SIZE`), evaluates the predicate per fiber visit
//!   with the candidate `idx` threaded via
//!   `FIRST_ADMIT_IDX_NAME_INDEX`, and **short-circuits on the first
//!   non-zero predicate result**. The result is a coproduct value:
//!   `(disc=0x01, idx_bytes)` on admission, `(disc=0x00, padding)` on
//!   exhaustion.
//!
//! With ADR-034 Mechanism 2, foundation's catamorphism evaluates the
//! W32 search end-to-end through the verb's term arena. The
//! implementation runtime ([`crate::ops::traversal`]) is no longer
//! load-bearing for structural correctness; it remains as an
//! **optional ADR-026 G16 override** for parallel coset-partition
//! traversal and external cancellation hooks (the substrate-side
//! `Term::FirstAdmit` evaluator does not yet expose either).

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
    fn verb_arena_contains_a_first_admit_node() {
        // ADR-026 G16 + ADR-034 Mechanism 2 (foundation 0.4.1):
        // `first_admit` lowers to `Term::FirstAdmit`, a dedicated
        // bounded-search variant whose evaluator iterates `idx`
        // ascending from 0 to N (= domain's CYCLE_SIZE) and
        // short-circuits on the first non-zero predicate result.
        // Earlier substrates (0.3.x – 0.4.0) lowered to `Term::Recurse`
        // and required the implementation runtime to drive the search;
        // 0.4.1 closes that delegation by making the search a
        // first-class catamorphism fold-rule.
        let arena = nonce_fiber_traversal_term_arena();
        let has_first_admit = arena.iter().any(|t| matches!(t, Term::FirstAdmit { .. }));
        assert!(
            has_first_admit,
            "first_admit lowering must emit a Term::FirstAdmit per ADR-034 Mechanism 2"
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
