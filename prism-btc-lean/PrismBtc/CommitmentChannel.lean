/-!
# Commitment Channel Protocol

prism-btc's UOR-optimal mining surface (architecture §14, ANALYSIS.md
§5) lifts the substrate's `type:Conjunction` primitive into the
runtime `MiningCommitment` type. This file formalizes the algebraic
core of the typed channel:

* A `Predicate` is a Boolean function over digests, plus a
  non-negative bandwidth contribution in bits, plus an algebraic
  `Support` naming the manifold region it reads.
* A `Commitment` is a `List Predicate` — their Conjunction.
* `evaluate` is the AND of per-predicate evaluations.
* `bandwidthBits` is the sum of per-predicate bandwidth contributions.
* `Support.disjoint` names when two supports are jointly independent
  under the random-oracle baseline.
* `Commitment.wellFormed` asserts pairwise-disjoint supports — the
  invariant that the Rust typed-iso surface enforces at
  `MiningCommitment::add_predicate` time (architecture §14.2).
* **U6 Bandwidth-Additivity** is the algebraic identity that
  bandwidth is preserved under commitment concatenation.

These match the Rust types in `prism_btc::Predicate`,
`prism_btc::Support`, and `prism_btc::MiningCommitment`
(`crates/prism-btc/src/pipeline.rs`). The probabilistic PRF
interpretation of `bandwidthBits` is informal; the additivity proved
here is purely algebraic. The `wellFormed` invariant is what makes
the PRF interpretation a tight bound rather than an upper bound.
-/

namespace PrismBtc.CommitmentChannel

/-- Abstract digest type. In the Rust implementation this is `[u8; 32]`. -/
abbrev Digest := List Bool

/-- Algebraic support of a predicate — the manifold region it reads.

    Two supports are **disjoint** iff predicates with these supports
    are jointly independent under the PRF baseline:

    * `bitSet a` ⊥ `bitSet b` iff the bit-masks are bit-disjoint.
    * `modular p` ⊥ `bitSet _` iff `p ≠ 2` (a prime ≥ 3 is coprime
      with any bit-pattern read from a uniform digest).
    * `modular p₁` ⊥ `modular p₂` iff `p₁ ≠ p₂` (distinct primes are
      coprime moduli). -/
inductive Support where
  | bitSet (mask : Nat) : Support
  | modular (p : Nat) : Support
  deriving DecidableEq

namespace Support

/-- Disjointness check for two supports. Models the Rust function
    `prism_btc::Support::is_disjoint_from`. -/
def disjoint : Support → Support → Bool
  | .bitSet a, .bitSet b => Nat.land a b = 0
  | .bitSet _, .modular p => decide (p ≠ 2)
  | .modular p, .bitSet _ => decide (p ≠ 2)
  | .modular p₁, .modular p₂ => decide (p₁ ≠ p₂)

/-- Disjointness is symmetric: `a ⊥ b ↔ b ⊥ a`. -/
theorem disjoint_symm (a b : Support) : disjoint a b = disjoint b a := by
  cases a <;> cases b <;> simp [disjoint, Nat.land_comm]

end Support

/-- A typed predicate: Boolean function on digests, plus a bandwidth
    contribution in bits, plus its algebraic support. Mirrors
    `prism_btc::Predicate`. -/
structure Predicate where
  /-- Boolean evaluation. -/
  evaluate : Digest → Bool
  /-- PRF bandwidth contribution (bits encoded per κ-label when this
      predicate is included in a Conjunction). -/
  bandwidthBits : Nat
  /-- Algebraic support — the manifold region the predicate reads. -/
  support : Support

/-- A commitment is a list of predicates — their Conjunction. -/
abbrev Commitment := List Predicate

namespace Commitment

/-- The empty commitment. -/
def empty : Commitment := []

/-- Evaluate a commitment on a digest: AND of per-predicate evaluations. -/
def evaluate (c : Commitment) (d : Digest) : Bool :=
  c.all (·.evaluate d)

/-- Total bandwidth (sum of per-predicate contributions in bits). -/
def bandwidthBits (c : Commitment) : Nat :=
  c.foldr (fun p acc => p.bandwidthBits + acc) 0

/-- The empty commitment evaluates to `true` on every digest. -/
theorem evaluate_empty (d : Digest) : evaluate empty d = true := by
  simp [empty, evaluate]

/-- The empty commitment has zero bandwidth. -/
theorem bandwidth_empty : bandwidthBits empty = 0 := by
  simp [empty, bandwidthBits]

/-- Bandwidth of a `cons` decomposes additively: head + tail. -/
theorem bandwidth_cons (p : Predicate) (c : Commitment) :
    bandwidthBits (p :: c) = p.bandwidthBits + bandwidthBits c := by
  simp [bandwidthBits]

/-- Evaluation of a `cons` decomposes as: head AND tail. -/
theorem evaluate_cons (p : Predicate) (c : Commitment) (d : Digest) :
    evaluate (p :: c) d = (p.evaluate d && evaluate c d) := by
  simp [evaluate]

/-- **U6 Bandwidth-Additivity** (ANALYSIS.md §4.1, §5.5). Bandwidth is
    additive over commitment concatenation:
    `bw(c₁ ++ c₂) = bw(c₁) + bw(c₂)`.

    This is the formal counterpart of the σ-Projection Hardening
    Principle's sixth condition: composing K typed predicates under
    Conjunction yields a commitment whose bandwidth is the sum of
    per-predicate contributions. The substrate's `type:Conjunction`
    primitive realizes this composition at the typed-iso surface;
    the σ-projection enforces the proportional `2^bw` PRF cost. -/
theorem bandwidth_append (c₁ c₂ : Commitment) :
    bandwidthBits (c₁ ++ c₂) = bandwidthBits c₁ + bandwidthBits c₂ := by
  induction c₁ with
  | nil =>
    simp [bandwidth_empty, empty]
  | cons p ps ih =>
    simp [bandwidthBits, ih, Nat.add_assoc]

/-- Evaluation distributes over concatenation as Boolean AND. -/
theorem evaluate_append (c₁ c₂ : Commitment) (d : Digest) :
    evaluate (c₁ ++ c₂) d = (evaluate c₁ d && evaluate c₂ d) := by
  induction c₁ with
  | nil =>
    simp [evaluate, empty]
  | cons p ps ih =>
    simp [evaluate, ih, Bool.and_assoc]

/-- The empty commitment is the right identity of concatenation under
    evaluation. -/
theorem evaluate_append_empty (c : Commitment) (d : Digest) :
    evaluate (c ++ empty) d = evaluate c d := by
  simp [empty, evaluate]

/-- The empty commitment is the right identity of concatenation under
    bandwidth. -/
theorem bandwidth_append_empty (c : Commitment) :
    bandwidthBits (c ++ empty) = bandwidthBits c := by
  rw [bandwidth_append, bandwidth_empty]

/-- `wellFormed c` holds iff every pair of predicates in `c` has
    disjoint supports. This is the invariant the Rust typed-iso
    surface enforces via `MiningCommitment::add_predicate`
    (architecture §14.2): a commitment that builds successfully via
    `add_predicate` automatically satisfies `wellFormed`.

    When `wellFormed` holds, U6 Bandwidth-Additivity is a **tight**
    bound on PRF mining cost (`α⁻¹ · 2^bandwidthBits`); when it
    fails, the algebraic identity still holds but the probabilistic
    interpretation is only an upper bound. -/
def wellFormed (c : Commitment) : Prop :=
  ∀ i j, i < c.length → j < c.length → i ≠ j →
    Support.disjoint (c.get ⟨i, by assumption⟩).support
                     (c.get ⟨j, by assumption⟩).support = true

/-- The empty commitment is trivially well-formed (no pairs to check). -/
theorem wellFormed_empty : wellFormed empty := by
  intro i j hi _ _
  simp [empty] at hi

/-- A singleton commitment is well-formed (no pairs to check). -/
theorem wellFormed_singleton (p : Predicate) : wellFormed [p] := by
  intro i j hi hj hij
  -- i, j < 1 means both are 0, contradicting i ≠ j.
  interval_cases i <;> interval_cases j <;> contradiction

end Commitment

end PrismBtc.CommitmentChannel
