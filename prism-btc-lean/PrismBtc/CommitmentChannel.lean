/-!
# Commitment Channel Protocol

prism-btc's UOR-optimal mining surface (architecture §14, ANALYSIS.md
§5) lifts the substrate's `type:Conjunction` primitive into the
runtime `MiningCommitment` type. This file formalizes the algebraic
core of the typed channel:

* A `Predicate` is a Boolean function over digests plus a non-negative
  bandwidth contribution in bits.
* A `Commitment` is a `List Predicate` — their Conjunction.
* `evaluate` is the AND of per-predicate evaluations.
* `bandwidthBits` is the sum of per-predicate bandwidth contributions.
* **U6 Bandwidth-Additivity** is the algebraic identity that bandwidth
  is preserved under commitment concatenation.

These match the Rust types in `prism_btc::Predicate` and
`prism_btc::MiningCommitment` (`crates/prism-btc/src/pipeline.rs`).
The probabilistic PRF interpretation of `bandwidthBits` is informal;
the additivity proved here is purely algebraic and applies to any
non-negative bandwidth function. (For the Rust `PAdicEq` variant the
bandwidth is a real number; the integer model here suffices for the
discrete additivity claim — the proof generalizes verbatim to `Real`.)
-/

namespace PrismBtc.CommitmentChannel

/-- Abstract digest type. In the Rust implementation this is `[u8; 32]`;
    here we model it as an arbitrary type because the Conjunction
    algebra is parametric over what predicates read. -/
abbrev Digest := List Bool

/-- A typed predicate: a Boolean function on digests plus a bandwidth
    contribution in bits. Mirrors `prism_btc::Predicate`. -/
structure Predicate where
  /-- Boolean evaluation. -/
  evaluate : Digest → Bool
  /-- PRF bandwidth contribution (bits encoded per κ-label when this
      predicate is included in a Conjunction). -/
  bandwidthBits : Nat

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

/-- Evaluation distributes over concatenation as Boolean AND:
    `evaluate (c₁ ++ c₂) d = evaluate c₁ d && evaluate c₂ d`.

    The Conjunction of two commitments evaluates to the AND of their
    individual evaluations — the algebraic statement that
    `type:Conjunction` is a monoid under list-concatenation with the
    empty commitment as identity. -/
theorem evaluate_append (c₁ c₂ : Commitment) (d : Digest) :
    evaluate (c₁ ++ c₂) d = (evaluate c₁ d && evaluate c₂ d) := by
  induction c₁ with
  | nil =>
    simp [evaluate, empty]
  | cons p ps ih =>
    simp [evaluate, ih, Bool.and_assoc]

/-- The empty commitment is the right identity of concatenation under
    evaluation: `evaluate (c ++ []) d = evaluate c d`. -/
theorem evaluate_append_empty (c : Commitment) (d : Digest) :
    evaluate (c ++ empty) d = evaluate c d := by
  simp [empty, evaluate]

/-- The empty commitment is the right identity of concatenation under
    bandwidth: `bandwidthBits (c ++ []) = bandwidthBits c`. -/
theorem bandwidth_append_empty (c : Commitment) :
    bandwidthBits (c ++ empty) = bandwidthBits c := by
  rw [bandwidth_append, bandwidth_empty]

end Commitment

end PrismBtc.CommitmentChannel
