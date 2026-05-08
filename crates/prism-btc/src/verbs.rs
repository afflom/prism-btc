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
//! prism operators G12–G19). The verb's term-tree fragment is the
//! structural declaration; how the implementation evaluates it
//! (sequential, parallel, optimised) is the implementation's choice
//! per ADR-026's three-way responsibility split.
//!
//! ## What's here
//!
//! - [`nonce_fiber_traversal`] — the W32 search. Body is
//!   `first_admit(WittLevel::W32, |nonce| hash(input))` (ADR-026 G16 +
//!   G19). The runtime that evaluates this declaration is
//!   [`crate::ops::traversal::traverse_sequential`] (sequential) and
//!   [`crate::ops::traversal::traverse_parallel`] (parallel coset
//!   partition over the W32 ring).
//!
//! ## Conformance against the wiki
//!
//! ADR-026 G16 (`first_admit`'s three-way runtime responsibility) splits
//! the search across all three layers:
//!
//! - **Substrate** owns the structural primitives (`Term::Application`
//!   over `PrimitiveOp::Succ` for the ring's successor structure;
//!   `WittLevel` ceiling for the domain's cardinality;
//!   `Term::HasherProjection` for the predicate's `hash(...)` form).
//! - **Prism** owns the operator `first_admit` as the typed declaration
//!   form (`uor-foundation-sdk`'s `verb!` lowering produces the
//!   `Term::Recurse`-backed structural arena per ADR-026 G16's lowering
//!   rule).
//! - **Implementation** owns the runtime traversal that evaluates the
//!   declaration. The conformance test (ADR-026 G16): the runtime
//!   produces the same first-admitting index a reference sequential
//!   traversal would. prism-btc's `traverse_sequential` is, in fact,
//!   the reference sequential traversal — it trivially passes.
//!
//! ## Closure-body grammar limits in SDK 0.3.4
//!
//! The wiki's intended verb body for `nonce_fiber_traversal` is
//!
//! ```text
//! first_admit(WittLevel::W32, |nonce| {
//!     hash(serialize_with_nonce(prefix, nonce)) <= target
//! })
//! ```
//!
//! SDK 0.3.4's closure-body grammar (ADR-022 D3 G1–G11 + ADR-026
//! G12–G19) admits `first_admit` (G16) and `hash` (G19) but does not
//! yet admit:
//!
//! - The lexicographic byte comparison `<=` — there is no comparison
//!   operator in G1–G19.
//! - Byte-level packing / concatenation of `prefix || nonce` into the
//!   80-byte canonical wire-format header — no shift / concat
//!   `PrimitiveOp` is in the substrate (closest is `xor` over a
//!   common Witt-level operand pair).
//!
//! The body below uses `hash(input)` as the structural form — the
//! abstract "σ-projection of the verb's input." The implementation
//! runtime ([`crate::ops::traversal`]) realises the full predicate
//! `hash(serialize_with_nonce(prefix, nonce)) ≤ target` per ADR-026
//! G16's three-way split.
//!
//! When foundation amends the SDK closure-body grammar to admit
//! comparison operators and substrate to admit the byte-packing
//! primitives, the body can be tightened to the wiki's full form
//! without changes to the runtime — the runtime is already the
//! reference sequential traversal the architecture asks for.

use uor_foundation_sdk::verb;

use crate::model::MiningInput;

verb! {
    pub fn nonce_fiber_traversal(input: MiningInput) -> MiningInput {
        first_admit(uor_foundation::WittLevel::W32, |nonce| hash(input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_foundation::enforcement::Term;

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
        // ADR-026 G16 specifies that `first_admit` lowers to a
        // `Term::Recurse`-backed structural form. Pin that the SDK
        // emitted exactly that variant for our verb.
        let arena = nonce_fiber_traversal_term_arena();
        let has_recurse = arena.iter().any(|t| matches!(t, Term::Recurse { .. }));
        assert!(
            has_recurse,
            "first_admit lowering must emit a Term::Recurse per ADR-026 G16"
        );
    }

    #[test]
    fn verb_arena_contains_a_hasher_projection() {
        // The predicate body `hash(input)` lowers to
        // `Term::HasherProjection` per ADR-026 G19. Pin that.
        let arena = nonce_fiber_traversal_term_arena();
        let has_hasher = arena
            .iter()
            .any(|t| matches!(t, Term::HasherProjection { .. }));
        assert!(
            has_hasher,
            "hash(...) lowering must emit a Term::HasherProjection per ADR-026 G19"
        );
    }
}
