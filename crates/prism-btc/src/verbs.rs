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
//! The verb below is the architectural commitment that names the
//! mining inference's structure. It is declared via `verb!` with a
//! closure body composed from G1–G19 (substrate-level forms G1–G11 +
//! prism operators G12–G19, including the `concat` keyword and the
//! byte-comparison binary operators `<=`, `<`, `>=`, `>` per
//! ADR-013/TR-08).
//!
//! ## What's here
//!
//! - [`nonce_fiber_traversal`] — the W32 search. Body is the wiki's
//!   intended structural form
//!   `first_admit(witt_domain::W32, |nonce| hash(concat(input.prefix, nonce)) <= input.target)`
//!   (ADR-026 G16 + G19, ADR-013/TR-08, ADR-033 G20, ADR-034
//!   Mechanism 2). Foundation 0.4.1's catamorphism evaluates this
//!   end-to-end through `Term::FirstAdmit`'s ascending-with-short-circuit
//!   fold-rule. There is no implementor-side runtime override.
//!
//! ## Conformance against the wiki
//!
//! ADR-026 G16 split:
//!
//! - **Substrate** owns the structural primitives:
//!   `Term::FirstAdmit` (ADR-034 M2) for ascending search with
//!   admission short-circuit; `Term::AxisInvocation` against the
//!   canonical hash axis (ADR-030) for `hash(...)`; `PrimitiveOp::Concat`
//!   for byte-sequence packing; `PrimitiveOp::Le` for byte-level
//!   lexicographic comparison; `witt_domain::W32` for the domain's
//!   cardinality (ADR-032: `CYCLE_SIZE = 2^32`); `Term::ProjectField`
//!   (ADR-033 G20) for partition-product field access.
//! - **Prism** owns `first_admit` as the typed declaration form. The
//!   `uor-foundation-sdk` lowering reads
//!   `<witt_domain::W32 as ConstrainedTypeShape>::CYCLE_SIZE`
//!   (ADR-032) and emits
//!   `Term::FirstAdmit { domain_size_index, predicate_index }`,
//!   threading the candidate `idx` through the predicate via
//!   `FIRST_ADMIT_IDX_NAME_INDEX`.
//! - **Implementation** owns the `verb!` declaration above; the
//!   structural commitment names the mining inference in prism
//!   vocabulary. Foundation's catamorphism evaluates the verb's
//!   term-tree fragment when [`crate::model::BitcoinMiningModel::forward`]
//!   is invoked.

use uor_foundation_sdk::verb;

use crate::model::{MiningResult, MiningTask};

verb! {
    pub fn nonce_fiber_traversal(input: MiningTask) -> MiningResult {
        first_admit(uor_foundation::pipeline::witt_domain::W32, |nonce| {
            hash(concat(input.prefix, nonce)) <= input.target
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
        // ADR-026 G16 + ADR-034 Mechanism 2: `first_admit` lowers to
        // `Term::FirstAdmit`, the dedicated bounded-search variant
        // whose evaluator iterates `idx` ascending and short-circuits
        // on the first non-zero predicate result.
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
        // the canonical hash axis. The blanket
        // `impl<H: Hasher> AxisTuple for H` routes the (0, 0) dispatch
        // through `Sha256dHasher`.
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

    /// Foundation 0.4.1 evaluates the verb's term arena end-to-end.
    /// `Term::FirstAdmit` iterates `idx` ascending through the W32
    /// domain, threads the candidate via `FIRST_ADMIT_IDX_NAME_INDEX`,
    /// and short-circuits on the first non-zero predicate result. This
    /// test pins that the verb's structural form is foundation-evaluable
    /// against an actual `Sha256dHasher` axis dispatch.
    #[test]
    fn verb_arena_evaluates_through_foundation_catamorphism() {
        use crate::shapes::hasher::Sha256dHasher;
        use uor_foundation::pipeline::evaluate_term_tree;

        let arena = nonce_fiber_traversal_term_arena();
        // Permissive target ⇒ `Le(hash(...), target)` admits at idx=0.
        let mut prefix = [0u8; 76];
        prefix[0] = 0x01;
        let target = [0xffu8; 32];
        let task = MiningTask::new(prefix, target);

        let result = evaluate_term_tree::<Sha256dHasher>(arena, &task.0)
            .expect("verb arena must be foundation-evaluable per ADR-029 + ADR-034 M2");

        let bytes = result.bytes();
        assert_eq!(
            bytes.len(),
            6,
            "FirstAdmit emits (disc, idx_bytes) of 6 bytes for W32 (cycle 2^32 needs 5 BE bytes)"
        );
        assert_eq!(
            bytes[0], 0x01,
            "predicate `hash(...) <= 0xff..ff` admits at idx=0; FirstAdmit returns disc=0x01"
        );
    }
}
