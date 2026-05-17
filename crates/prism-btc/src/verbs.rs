//! prism-btc's ψ-chain mining verb (wiki ADR-024, ADR-035, ADR-036;
//! architecture §4).
//!
//! The mining inference is the **k-invariant branch** of the ψ-pipeline
//! applied to a `MiningTask`:
//!
//! ```text
//! MiningTask
//!    ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
//!    ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
//!    ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
//!    ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
//! MiningResult — the label
//! ```
//!
//! k-invariants `κ_k` are the universal classifying invariants of the
//! Postnikov tower, and the typed-iso surface of a wire-format-valid
//! Bitcoin block is naturally characterized by its k-invariant
//! signature. Foundation's catamorphism evaluates the chain end-to-end
//! via the application's `ResolverTuple`
//! ([`crate::resolvers::BitcoinResolverTuple`]).
//!
//! ## Conformance against the wiki
//!
//! ADR-024: the verb composes only foundation operators and existing
//! verbs — no new primitives. Each ψ-stage is a `Term::*` variant
//! emitted by the SDK from the closure-body grammar (G21–G29). ADR-035
//! commits the catamorphism to fold-rules that dispatch through
//! ADR-036's `ResolverTuple` for the eight resolver-bound stages
//! (ψ_4 Betti is resolver-free; not on this branch).
//!
//! ## What this verb deliberately is not
//!
//! - **Not** `first_admit(W32, |nonce| hash(...) <= target)`. That is
//!   the σ-enumeration form retired per the pure-prism architecture
//!   commitment (architecture §12). The mining transform is structural;
//!   there is no enumeration anywhere in the verb body.
//! - **Not** an algorithm. The verb body composes parametric
//!   tensor-algebra functors. The catamorphism evaluates the
//!   composition; the resolvers realize each functor's structural
//!   transformation for Bitcoin's typed feature hierarchy.

use prism::pipeline::verb;

use crate::model::{MiningResult, MiningTask};

verb! {
    pub fn mining_inference(input: MiningTask) -> MiningResult {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism::operation::{PrimitiveOp, Term};

    #[test]
    fn verb_term_arena_is_emitted_and_nonempty() {
        let arena = mining_inference_term_arena();
        assert!(
            !arena.is_empty(),
            "verb term arena must contain the ψ-chain composition"
        );
    }

    #[test]
    fn verb_arena_contains_psi_1_nerve() {
        let arena = mining_inference_term_arena();
        assert!(
            arena.iter().any(|t| matches!(t, Term::Nerve { .. })),
            "ψ_1 (Nerve) Term variant must be present per ADR-035 + architecture §4"
        );
    }

    #[test]
    fn verb_arena_contains_psi_7_postnikov_tower() {
        let arena = mining_inference_term_arena();
        assert!(
            arena
                .iter()
                .any(|t| matches!(t, Term::PostnikovTower { .. })),
            "ψ_7 (PostnikovTower) Term variant must be present per ADR-035 + architecture §4"
        );
    }

    #[test]
    fn verb_arena_contains_psi_8_homotopy_groups() {
        let arena = mining_inference_term_arena();
        assert!(
            arena
                .iter()
                .any(|t| matches!(t, Term::HomotopyGroups { .. })),
            "ψ_8 (HomotopyGroups) Term variant must be present per ADR-035 + architecture §4"
        );
    }

    #[test]
    fn verb_arena_contains_psi_9_k_invariants() {
        let arena = mining_inference_term_arena();
        assert!(
            arena.iter().any(|t| matches!(t, Term::KInvariants { .. })),
            "ψ_9 (KInvariants) Term variant must be present per ADR-035 + architecture §4"
        );
    }

    #[test]
    fn verb_arena_contains_no_sigma_residuals() {
        // Pure-prism commitment (architecture §12): no σ-enumeration in
        // the verb body. The arena must contain none of FirstAdmit, Le,
        // Concat, or AxisInvocation. The canonical hash axis is consumed
        // by resolvers (architecture §3) — never by the verb body's term
        // composition.
        //
        // Foundation's SDK enforces this discipline at proc-macro
        // expansion time (architecture §9.1); any future regression to a
        // σ-residual form would fail at compile time. This test pins the
        // emitted-arena invariant as a belt-and-suspenders check against
        // SDK-emission anomalies.
        let arena = mining_inference_term_arena();
        let has_first_admit = arena.iter().any(|t| matches!(t, Term::FirstAdmit { .. }));
        let has_axis_invocation = arena
            .iter()
            .any(|t| matches!(t, Term::AxisInvocation { .. }));
        let has_le_or_concat = arena.iter().any(|t| {
            matches!(
                t,
                Term::Application {
                    operator: PrimitiveOp::Le
                        | PrimitiveOp::Concat
                        | PrimitiveOp::Lt
                        | PrimitiveOp::Ge
                        | PrimitiveOp::Gt,
                    ..
                }
            )
        });
        assert!(
            !has_first_admit,
            "FirstAdmit is a σ-enumeration residual — must not appear in the pure-prism verb body"
        );
        assert!(
            !has_axis_invocation,
            "AxisInvocation belongs in resolvers, not in the verb body's composition"
        );
        assert!(
            !has_le_or_concat,
            "byte-comparison/concat ops are σ-residuals — admission is structural per architecture §2.3"
        );
    }
}
