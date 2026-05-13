/-!
# Commitment Channel Protocol

prism-btc's UOR-optimal mining surface (architecture §14, ANALYSIS.md
§5) lifts the substrate's `type:Conjunction` primitive into a
zero-cost, monomorphized typed commitment in Rust
(`prism_btc::TypedCommitment` and its implementors
`EmptyCommitment`, `PayloadCommitment<K>`, plus user-defined impls).
This file formalizes the algebraic core of the typed channel:

* A `Predicate` is a Boolean function over digests, plus its
  **acceptance probability** under the PRF baseline (as an exact
  rational), plus an algebraic `Support` naming the manifold region
  it reads.
* A `Commitment` is a `List Predicate` — their Conjunction.
* `evaluate` is the AND of per-predicate evaluations.
* `acceptProb` is the **product** of per-predicate acceptance
  probabilities (multiplicative under list concatenation).
* `Support.disjoint` names when two supports are jointly independent
  under the random-oracle baseline.
* `Commitment.wellFormed` asserts pairwise-disjoint supports — the
  invariant that every Rust `TypedCommitment` implementor discharges
  at the *type level* by construction (architecture §14.2).
* **U6 Joint-Probability Multiplicativity** is the algebraic identity
  that acceptance probability is preserved under commitment
  concatenation as a product. Its log-space form is the **U6
  Bandwidth-Additivity** in informal architecture text:
  `bandwidth_bits = -log₂ acceptProb`.

**Probability-space, not log-space.** The earlier model carried
bandwidth as a `Nat`; that representation faithfully covered three
of the four Rust `Predicate` variants but **mis-modelled**
`PAdicEq { p, k }` for primes `p ≥ 3`, whose bandwidth
`(k+1)·log₂(p) − log₂(p−1)` is irrational. Switching to acceptance
probability as a rational closes this gap: every Predicate variant's
acceptance probability is an exact rational —

* `Parity` → `1/2`
* `StratumEq { k }` → `1 / 2^(k+1)`
* `PAdicEq { p, k }` → `(p−1) / p^(k+1)`
* `UltrametricCloseTo { k }` → `1 / 2^k`

— and the U6 identity becomes a clean product over a `Rat`-valued
monoid, faithful to all four variants.

These match the Rust types in `prism_btc::Predicate`,
`prism_btc::Support` (`crates/prism-btc/src/pipeline.rs`), and the
substrate-level zero-cost commitment surface
`prism_btc::TypedCommitment` (`crates/prism-btc/src/commitment.rs`).
The Rust runtime carries no `Vec<Predicate>` — every typed
commitment is a monomorphized compile unit (`EmptyCommitment`,
`PayloadCommitment<K>`, or any user-defined `TypedCommitment` impl).
The `Commitment := List Predicate` in this file is the *algebraic
specification* of the typed surface — every Rust monomorphization
corresponds to a particular Lean list, and the tight-bound theorem
covers all of them via the quantifier over the structure.

The receiver-side typed lens is `prism_btc::KappaObservables` /
`ExtendedObservables<N_PAR, N_REF>` (`crates/prism-btc/src/observables.rs`),
together with the sender-side `TypedCommitment` realizing the
sender ↔ receiver duality (ANALYSIS.md §5.4).

The exact rational acceptance probability is
`Predicate::accept_prob_rational() -> (u128, u128)`, the direct
correspondence point to `Predicate.acceptProb : Rat` in this file;
`bandwidth_bits() -> f64` is the engineering surface (related by
`2^(-bandwidth_bits) = num/den`).
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

/-- A typed predicate: Boolean function on digests, plus its **PRF
    acceptance probability** as an exact rational, plus its
    algebraic support. Mirrors `prism_btc::Predicate`.

    The Rust user-facing surface exposes `bandwidth_bits() -> f64`
    (the engineering view) and `accept_prob_rational() -> (u128, u128)`
    (the exact rational, the direct correspondence point to this field).
    `acceptProb` is the formal counterpart of the rational pair. -/
structure Predicate where
  /-- Boolean evaluation. -/
  evaluate : Digest → Bool
  /-- PRF acceptance probability:
      `Pr[evaluate (uniform digest) = true] = acceptProb`. The exact
      rational covers all four Rust `Predicate` variants. -/
  acceptProb : Rat
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

/-- Joint PRF acceptance probability of a commitment: the **product**
    of per-predicate acceptance probabilities. Empty commitment ↦ 1
    (matches the Rust convention `mine_with(_, _, EmptyCommitment) ≡ mine()`). -/
def acceptProb (c : Commitment) : Rat :=
  c.foldr (fun p acc => p.acceptProb * acc) 1

/-- The empty commitment evaluates to `true` on every digest. -/
theorem evaluate_empty (d : Digest) : evaluate empty d = true := by
  simp [empty, evaluate]

/-- The empty commitment has acceptance probability 1. -/
theorem acceptProb_empty : acceptProb empty = 1 := by
  simp [empty, acceptProb]

/-- Acceptance probability of a `cons` decomposes multiplicatively:
    head · tail. -/
theorem acceptProb_cons (p : Predicate) (c : Commitment) :
    acceptProb (p :: c) = p.acceptProb * acceptProb c := by
  simp [acceptProb]

/-- Evaluation of a `cons` decomposes as: head AND tail. -/
theorem evaluate_cons (p : Predicate) (c : Commitment) (d : Digest) :
    evaluate (p :: c) d = (p.evaluate d && evaluate c d) := by
  simp [evaluate]

/-- **U6 Joint-Probability Multiplicativity** (ANALYSIS.md §4.1, §5.5).
    Acceptance probability is multiplicative over commitment
    concatenation:
    `acceptProb (c₁ ++ c₂) = acceptProb c₁ * acceptProb c₂`.

    This is the formal counterpart of the σ-Projection Hardening
    Principle's sixth condition: composing K typed predicates under
    Conjunction yields a commitment whose joint acceptance equals the
    product of per-predicate acceptances under the PRF baseline. The
    equivalent log-space statement (the historical "Bandwidth-
    Additivity" framing) is `bandwidth = Σ -log₂ acceptProb_i`. -/
theorem acceptProb_append (c₁ c₂ : Commitment) :
    acceptProb (c₁ ++ c₂) = acceptProb c₁ * acceptProb c₂ := by
  induction c₁ with
  | nil =>
    simp [acceptProb_empty, empty]
  | cons p ps ih =>
    simp [acceptProb, ih, mul_assoc]

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
    acceptance probability. -/
theorem acceptProb_append_empty (c : Commitment) :
    acceptProb (c ++ empty) = acceptProb c := by
  rw [acceptProb_append, acceptProb_empty, mul_one]

/-- `wellFormed c` holds iff every pair of predicates in `c` has
    disjoint supports. This is the invariant the Rust typed-iso
    surface discharges *at the type level* via the structural
    invariants of each `TypedCommitment` implementor (architecture
    §14.2): `EmptyCommitment` is vacuously well-formed;
    `PayloadCommitment<K>` uses K parities at K *distinct*
    single-bit ω-frequencies, so its supports are pairwise-disjoint
    by indexing; user-defined `TypedCommitment` impls discharge
    `wellFormed` via their own type-level invariants. The runtime
    does not check.

    When `wellFormed` holds, the multiplicative U6 identity is a
    **tight** PRF acceptance probability (§2 `prf_prob_tight_wellFormed`);
    when it fails, the algebraic identity still holds but the
    probabilistic interpretation is only an upper bound on declared
    bandwidth. -/
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

/-- Destructuring a `wellFormed (p :: ps)` hypothesis: the head `p` is
    support-disjoint from every predicate in the tail `ps`. Every
    Rust `TypedCommitment` implementor's type-level invariant
    (architecture §14.2) is precisely this property: each predicate
    in the typed decomposition is support-disjoint from the others
    by construction. -/
theorem wellFormed.head_disjoint
    {p : Predicate} {ps : Commitment} (h : wellFormed (p :: ps)) :
    ∀ i (hi : i < ps.length),
        Support.disjoint p.support (ps.get ⟨i, hi⟩).support = true := by
  intro i hi
  have h0 : 0 < (p :: ps).length := by simp
  have hi1 : i + 1 < (p :: ps).length := by simp; omega
  have hne : (0 : Nat) ≠ i + 1 := by omega
  have key := h 0 (i + 1) h0 hi1 hne
  simpa using key

/-- Destructuring a `wellFormed (p :: ps)` hypothesis: the tail `ps` is
    itself well-formed. -/
theorem wellFormed.tail
    {p : Predicate} {ps : Commitment} (h : wellFormed (p :: ps)) :
    wellFormed ps := by
  intro i j hi hj hij
  have hi1 : i + 1 < (p :: ps).length := by simp; omega
  have hj1 : j + 1 < (p :: ps).length := by simp; omega
  have hne : i + 1 ≠ j + 1 := by omega
  have key := h (i + 1) (j + 1) hi1 hj1 hne
  simpa using key

end Commitment

/-! ## §2 PRF baseline — random-oracle interpretation of acceptance probability

The §1 identity `acceptProb_append` is purely algebraic (a fold over
`List.append`). To upgrade it to a **tight bound on PRF mining cost** —
the operational claim that appears in ANALYSIS.md §5.5 and
architecture §14.1 — we axiomatize the two assumptions the operational
claim rests on:

* **U1 (marginal uniformity)** — each typed Predicate's `acceptProb`
  exactly matches its PRF acceptance rate: under uniform-random
  digests, `Pr[p.evaluate d = true] = p.acceptProb`.
* **U2 (joint independence)** — when a Predicate's algebraic support
  is disjoint from every Predicate in a commitment, its evaluation
  is *probabilistically independent* of the commitment's joint
  evaluation under the PRF baseline (joint probability factors).

U1 + U2 are calibration assumptions on the σ-projection (SHA-256d).
The 10-section cryptanalysis battery in
`examples/uor_cryptanalysis.rs` (ANALYSIS.md §3) provides the
empirical witness:

* §I (`section_i_u1_marginal_calibration`) tests U1 at each Predicate
  variant — Parity, StratumEq, PAdicEq{p=3}, UltrametricCloseTo —
  comparing observed acceptance against the variant's claimed
  `accept_prob_rational()` under the random-oracle baseline.
* §J (`section_j_u2_joint_independence`) tests U2 on disjoint-support
  Predicate pairs across the BitSet × BitSet, BitSet × Modular, and
  Modular × Modular regimes; also reports a non-disjoint negative
  control to show the independence claim is non-vacuous.

We treat U1 + U2 as axioms here and prove the structural consequence.

Once U1 + U2 are axioms, the main theorem `prf_prob_tight_wellFormed`
follows by structural induction on the commitment list. **Without
`wellFormed`**, the U2 axiom does not fire at the inductive step —
exactly the failure mode every `TypedCommitment` implementor forecloses
at the type level (architecture §14.2). -/

namespace PRF

/-- PRF acceptance probability for a Boolean digest function. The
    probability that a uniform-random digest `d` satisfies `f` is,
    by convention, `prob f`. Carried as `Rat` so all four Rust
    `Predicate` variants are covered exactly (including
    `PAdicEq { p, k }` whose probability `(p−1)/p^(k+1)` is rational
    but whose log₂ is irrational for `p ≥ 3`). -/
axiom prob : (Digest → Bool) → Rat

/-- (Trivial-predicate calibration) The always-true predicate has
    acceptance probability 1: every digest satisfies it. -/
axiom prob_true : prob (fun _ : Digest => true) = 1

/-- **U1 (marginal uniformity)** — each typed Predicate's `acceptProb`
    calibrates its PRF acceptance: under uniform-random digests,
    `Pr[p.evaluate d = true] = p.acceptProb`.

    This is the calibration claim on the σ-projection (SHA-256d):
    every Predicate the runtime admits — `Parity`, `StratumEq`,
    `PAdicEq`, `UltrametricCloseTo` — produces a Boolean accepter
    whose PRF rate equals the rational its
    `Predicate::accept_prob_rational()` declares. Empirically
    witnessed by `examples/uor_cryptanalysis.rs` §I. -/
axiom prob_predicate (p : Predicate) :
    prob p.evaluate = p.acceptProb

/-- **U2 (joint independence)** — when a Predicate's algebraic support
    is disjoint from every Predicate in a commitment, its PRF
    acceptance is independent of the commitment's joint acceptance:
    joint probability factors.

    Equivalent factored statement:
    `Pr[p.evaluate d ∧ c.evaluate d] = Pr[p.evaluate d] · Pr[c.evaluate d]`
    whenever `p.support` is disjoint from every predicate-support in `c`.
    Empirically witnessed by `examples/uor_cryptanalysis.rs` §J. -/
axiom prob_cons_independent (p : Predicate) (c : Commitment) :
    (∀ i (hi : i < c.length),
        Support.disjoint p.support (c.get ⟨i, hi⟩).support = true) →
    prob (fun d => p.evaluate d && Commitment.evaluate c d) =
      prob p.evaluate * prob (Commitment.evaluate c)

end PRF

namespace Commitment

/-- `evaluate (p :: ps)` is functionally
    `fun d => p.evaluate d && evaluate ps d`. The fn-level form of
    `evaluate_cons` — useful when rewriting under `PRF.prob`. -/
theorem evaluate_cons_fn (p : Predicate) (ps : Commitment) :
    evaluate (p :: ps) = fun d => p.evaluate d && evaluate ps d := by
  funext d
  exact evaluate_cons p ps d

/-- **U6, tight form** — the PRF-acceptance identity for well-formed
    commitments. Algebraic multiplicativity (`acceptProb_append`)
    lifts from a purely structural identity to an operational claim:
    under U1 + U2, a `wellFormed` commitment's PRF acceptance
    probability is exactly its declared `acceptProb`.

    Statement: `Pr[c.evaluate d = true] = acceptProb c` — the
    expected-trial cost claim of architecture §14.1 (`1 / acceptProb c`
    = `2^bandwidth_bits c`) is realized **at equality**, not as an
    upper bound.

    **Why `wellFormed` is load-bearing.** The U2 axiom (joint
    independence under disjoint supports) fires at the inductive step
    only when the head predicate is support-disjoint from the tail.
    For a not-well-formed commitment, predicate evaluations can
    correlate and `acceptProb c` no longer matches the actual PRF
    acceptance rate — the Rust typed-iso surface forecloses this
    regime at the type level: every `TypedCommitment` implementor's
    invariant (built-in or user-defined) discharges `wellFormed`
    by construction (architecture §14.2). -/
theorem prf_prob_tight_wellFormed (c : Commitment) (h : wellFormed c) :
    PRF.prob (evaluate c) = acceptProb c := by
  induction c with
  | nil =>
    show PRF.prob (evaluate empty) = acceptProb empty
    rw [show evaluate empty = (fun _ : Digest => true) from rfl,
        PRF.prob_true, acceptProb_empty]
  | cons p ps ih =>
    have disj : ∀ i (hi : i < ps.length),
        Support.disjoint p.support (ps.get ⟨i, hi⟩).support = true :=
      wellFormed.head_disjoint h
    have wf_ps : wellFormed ps := wellFormed.tail h
    rw [evaluate_cons_fn,
        PRF.prob_cons_independent p ps disj,
        PRF.prob_predicate,
        ih wf_ps,
        acceptProb_cons]

end Commitment

end PrismBtc.CommitmentChannel
