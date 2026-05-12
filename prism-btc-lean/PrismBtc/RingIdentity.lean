import UOR.Enforcement

/-!
# Ring Identity: neg(bnot(x)) = succ(x)

The core algebraic identity of Z/(2^n)Z:
  `-(~~~x) = x + 1`

Proved at two Witt levels used by Bitcoin types:
- W8  (Z/(2^8)Z)  — per-byte hash ring — exhaustive via `decide` (256 values)
- W32 (Z/(2^32)Z) — nonce ring         — symbolic via `omega` + `simp`

Division of labor with the Rust implementation:
- The architectural commitment is that prism-btc's ψ-pipeline composes
  only foundation's PrimitiveOp closure (ADR-013) and the canonical
  ψ-chain Term variants (ADR-035); the ring identity is the load-
  bearing algebraic fact behind ADR-013's closure soundness.
- These Lean theorems cover the universal statement; foundation's
  conformance suite + the verb-arena V&V tests
  (`crates/prism-btc/tests/verification.rs` §1) pin the structural
  invariants at the application level.
-/

-- Exhaustive proof for UInt8 (W8 level) — 256 values, decidable by computation
theorem neg_bnot_eq_succ_u8 (x : UInt8) : -(~~~x) = x + 1 := by decide

-- Symbolic proof for UInt32 (W32 level) — omega handles Z/(2^32)Z modular arithmetic
theorem neg_bnot_eq_succ_u32 (x : UInt32) : -(~~~x) = x + 1 := by
  simp [UInt32.neg_def, UInt32.complement_def]
  omega
