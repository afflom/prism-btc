# prism-btc — Verification & Validation

> **Scope.** This document records what prism-btc verifies and how.
> The V&V suite is reproducible via `just vv` across six axes:
> architecture (fmt + clippy --all-targets + unit + integration
> tests), the dedicated V&V test module, the conformance suite
> (cost-model scaling — see [`CONFORMANCE.md`](CONFORMANCE.md)),
> rustdoc (broken intra-doc links denied), Lean proofs, and a regtest
> end-to-end run.

prism-btc's V&V covers six axes. Each axis has a concrete reproducible
artifact in the repo.

## §1 Architectural conformance — `cargo test --release`

The verb arena, model declarations, and substrate-bindings carry
compile-time invariants the test surface re-asserts at runtime. 68
unit tests across the prism-btc crate's modules:

- **`crates/prism-btc/src/verbs.rs::tests`** (6 tests) — the verb
  arena's structural shape: non-empty; contains ψ_1 Nerve, ψ_7
  PostnikovTower, ψ_8 HomotopyGroups, ψ_9 KInvariants; contains zero
  σ-residuals (no `Term::FirstAdmit`, no `Term::AxisInvocation`, no
  byte-comparison or `Concat` ops in the verb body). The substrate's
  proc-macro discipline (ADR-035) enforces the latter at compile
  time; these runtime assertions are defense-in-depth.

- **`crates/prism-btc/src/model.rs::tests`** (6 tests) — the typed
  feature hierarchy: `TemplatePrefix`'s 76-byte layout
  (`version‖prev_hash‖merkle_root‖timestamp‖bits`); `MiningTask`'s
  108-byte partition_product layout; `MiningResult`'s 80 W8 sites
  (wire-format header width); `IntoBindingValue` 108-byte projection;
  CONSTRAINTS' 80 disjoint Site instances spanning [0, 80).

- **`crates/prism-btc/src/shapes/bounds.rs::tests`** (2 tests) —
  `PrismBtcBounds`' prism-btc-specific constants
  (`FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64`,
  `WITT_LEVEL_MAX_BITS = 32`) and the uniformity of the
  per-ψ-stage output ceilings.

- **`crates/prism-btc/src/shapes/hasher.rs::tests`** (3 tests) —
  `Sha256dHasher` streaming-vs-one-shot equivalence and FIPS-180-4
  vector matching.

- **`crates/prism-btc/src/domain.rs::tests`** (13 tests) —
  `Bits ↔ Target` round-trip, `Target::is_satisfied_by_bytes`
  monotonicity, `TriadicCoords` projection; UOR manifold
  observables: `ultrametric_valuation` semantics (low/high bit
  positions, equal-address case), `walsh_hadamard_parity_at`
  (all-ones = spectrum, disjoint mask = zero), `p_adic_valuation`
  for primes 2, 3, 5 plus the zero-digest u128-cap edge case.

- **`crates/prism-btc/src/ops/*::tests`** (9 tests) — pure-Rust
  SHA-256 / SHA-256d against FIPS-180-4 vectors; merkle reduction
  against rust-bitcoin reference; canonical 80-byte header
  serialization round-trip.

- **`crates/prism-btc/src/pipeline.rs::tests`** (14 tests) — the
  UOR-optimal mining surface (architecture §14):
  - `mine_with(EmptyCommitment)` ≡ bare `mine` (zero-cost identity
    on the typed surface).
  - `mine_with(PayloadCommitment::<K>)` finds an admitting κ-label
    whose decoded bits round-trip the encoded payload.
  - Predicate primitives: `Predicate::Parity` reads a single bit
    (bandwidth 1); `Predicate::StratumEq{k}` matches the 2-adic
    stratum (bandwidth `k+1`); `Predicate::PAdicEq{p, k}` matches
    the p-adic valuation (bandwidth `(k+1)·log₂p − log₂(p−1)`);
    `Predicate::UltrametricCloseTo{r, k}` matches the 2-adic
    distance (bandwidth `k`).
  - Acceptance-probability surface (the Lean correspondence):
    `Predicate::accept_prob_rational` returns the exact rational
    Pr per variant — `Parity`→`(1,2)`, `StratumEq{k}`→`(1, 2^(k+1))`,
    `PAdicEq{p,k}`→`(p-1, p^(k+1))`, `UltrametricCloseTo{k}`→`(1, 2^k)`;
    `accept_prob` (f64) matches `2^(-bandwidth_bits)` to relative
    1e-12.
  - Support algebra (§14.2): `PAdicEq{p=2}` canonicalizes to
    `BitSet`; `BitSet ⊥ BitSet` iff bit-disjoint; same-byte
    overlap is detected as dependent; distinct-byte `BitSet`s are
    independent; `Modular{p₁} ⊥ Modular{p₂}` iff `p₁ ≠ p₂`;
    `Modular{p≥3} ⊥ BitSet(_)` always. (Retained as the
    diagnostic / cryptanalysis surface — typed commitments
    discharge `wellFormed` at the type level, not via this check.)

- **`crates/prism-btc/src/commitment.rs::tests`** (7 tests) — prism's
  zero-cost typed commitment surface:
  - `EmptyCommitment` admits every digest; bandwidth 0;
    `accept_prob` 1.
  - `PayloadCommitment<K>::from_bits` + `::decode` round-trip on a
    matching digest; mismatched bits are rejected.
  - Bandwidth scales as `K`; acceptance probability scales as
    `2^-K`.
  - Decomposition into `[Predicate; K]` agrees with the
    monomorphized `evaluate` (sender ↔ predicate-primitive
    consistency).
  - `PayloadCommitment<K>` predicates have pairwise-disjoint
    supports by *construction* — `wellFormed` discharged at the
    type level.

- **`crates/prism-btc/src/observables.rs::tests`** (3 tests) — the
  receiver-side typed lens:
  - `KappaObservables::from_digest` decodes the canonical landscape
    (stratum, spectrum, p-adic valuations at `CANONICAL_PRIMES =
    {2, 3, 5, 7}`); `p_adic_at(2)` agrees with `coords.stratum`.
  - **Round-trip identity**: for every `Predicate` variant,
    `pred.evaluate(d) == ExtendedObservables::from_digest(d, ωs,
    refs).satisfies(&pred, d)` — the sender ↔ receiver consistency
    pinned algebraically.
  - `ExtendedObservables::<0, 0>` is a valid instantiation
    (canonical-only lens; the const-generic shape covers
    the zero-extension case).

The [`crate::diagnostics`](crates/prism-btc/src/diagnostics.rs)
module exposes ψ_9's structural κ-derivation state
(`ResolutionState`, `take_resolution_state`); its behaviour is
pinned by the §2 V&V tests below (rows 15–17).

## §2 V&V suite — `crates/prism-btc/tests/verification.rs`

17 tests that pin the load-bearing architectural properties. 5
additional integration tests in `crates/prism-btc/tests/integration.rs`
exercise the typed-iso surface end-to-end. Module docstrings carry the
per-test rationale.

| # | Test | Property |
|---|---|---|
| 1 | `v_verb_arena_composes_only_psi_stages_no_sigma_residuals` | Pure-prism commitment: verb body contains only ψ-Terms + Variable/Literal scaffolding |
| 2 | `v_verb_arena_implements_the_k_invariant_branch` | ψ_1 → ψ_7 → ψ_8 → ψ_9 — the canonical mining transform (architecture §4) |
| 3 | `v_mine_admits_in_one_call_against_a_permissive_target` | Cryptographic re-derivation: `mine()` is one-shot for permissive targets; `outcome.digest` = SHA-256d(wire-format header) and admits |
| 4 | `v_mine_outcome_digest_actually_satisfies_target_across_inputs` | Fail-closed across the input space: every `Ok` outcome's digest genuinely satisfies the target |
| 5 | `v_psi_pipeline_is_pure_function_of_typed_input` | Determinism: 5 repetitions of the same `MiningTask` produce byte-identical κ-labels |
| 6 | `v_kappa_label_is_distinct_for_distinct_typed_inputs` | Distinctness: 64 distinct inputs produce 64 distinct κ-labels (collision-free in the wire-format header as a whole) |
| 7 | `v_kappa_label_is_wire_format_header_byte_for_byte` | Bit-identicality: κ-label = `serialize_header(host_header, resolved_nonce)` byte-for-byte |
| 8 | `v_kappa_label_preserves_the_host_supplied_prefix` | ψ-pipeline preserves the template prefix; only the nonce field is derived |
| 9 | `v_model_declarations_invariant_across_network_byte_thresholds` | Network-invariance: same model + same verb arena across regtest/signet/testnet/testnet4/mainnet `bits` values |
| 10 | `v_compile_unit_fingerprint_identifies_the_typed_iso_path` | TC-03 typed-iso path-singularity: distinct inputs share CompileUnit fingerprint (the path, not the input) |
| 11 | `v_mining_result_constraints_have_eighty_disjoint_site_instances` | Algebraic-closure encoding: 80 disjoint `ConstraintRef::Site` instances (IT_7d) |
| 12 | `v_constraint_nerve_is_eighty_isolated_vertices_no_higher_simplices` | Constraint-nerve geometry: β_0 = 80, β_k = 0 for k ≥ 1, χ = 80 = SITE_COUNT |
| 13 | `v_constraint_site_supports_span_the_full_wire_format_header` | Site supports cover [0, 80) — every wire-format-header byte pinned by one Site constraint |
| 14 | `v_prism_btc_bounds_declare_algebraic_closure_target` | `PrismBtcBounds` declares the algebraic-closure ceilings (compile-time assertion) |
| 15 | `v_mine_outcome_carries_kappa_derivation_state` | `MiningOutcome.resolution` carries `free_rank = 0` (terminal-stage convergence) and `derived_nonce` matching the κ-derived nonce on the wire-format header |
| 16 | `v_mine_drains_thread_local_diagnostic_channel` | `mine()` drains the thread-local diagnostic channel as part of returning the outcome — a subsequent `take_resolution_state()` returns `None` |
| 17 | `v_forward_records_resolution_state_for_inspection` | Direct `forward()` callers (not via `mine()`) inspect ψ_9's state via `take_resolution_state()` — ψ_9 records state on every invocation |

Run: `cargo test --release -p prism-btc --test verification`.

## §3 Conformance suite — `crates/prism-btc/tests/{conformance,mainnet}.rs`

19 conformance tests validating that prism's zero-cost runtime model
scales arbitrarily over K (commitment bandwidth), α (admission
probability), and the full range of legitimate mainnet inputs. See
[`CONFORMANCE.md`](CONFORMANCE.md) for the normative per-invariant
statements; tests are ID'd against it.

| Class | Count | What it asserts |
|---|---|---|
| **CS** (structural) | 6 | No `Vec<Predicate>` / `dyn TypedCommitment` / `Box<dyn …>` / legacy `MiningCommitment`-era identifiers in `src/`; `TypedCommitment: Copy` enforced; `Predicate` enum fixed at four variants; `MiningOutcome.observables` always present. |
| **CD** (dynamic) | 3 | `mine_with(EmptyCommitment) ≡ mine` byte-for-byte; `PayloadCommitment<K>` round-trips at K ∈ {0,1,2,4,8}; `MiningOutcome.observables` agrees with the per-primitive `TriadicCoords::from_hash` / `p_adic_valuation` computation. |
| **CP** (probabilistic scaling) | 3 | `α⁻¹ × 2^K` cost identity holds within ±30% (≈4σ at N=200) across (a) K-sweep over four decades [0..12] at fixed α, (b) α-sweep over four decades [2⁻¹..2⁻¹²] at fixed K=2, (c) compound K × α decompositions of the same product. |
| **CM** (mainnet readiness) | 6 | `Target::new(nBits)` accepts every mainnet-difficulty value in the chain's history; `mine()` produces well-formed 80-byte κ-labels on synthetic mainnet inputs (`PipelineFailure` unreachable across 400 attempts × 8 difficulty levels); aggregate `CampaignStats` matches PRF baseline at N=10⁴ (χ² goodness-of-fit on stratum + spectrum at α=0.001); empirical α converges to theoretical α at N=10⁴ within ±5%; campaign is consistent under cooperative interruption. |
| **CN** + **CL** | (cross-ref) | Network-invariance (CN-1…4) cross-referenced to V&V §2 + host-loop §5; Lean-formal (CL-1…4) cross-referenced to §4 below. |

Plus 1 negative-conformance witness (`MiningFailure::DidNotAdmit`
carries the receiver-side typed lens — observables + nonce + digest —
making the lens total, not admission-only).

The **total receiver-side typed lens** is the load-bearing extension
that enables the CM class: every ψ-pipeline inference exposes its
candidate's typed property landscape via
`MiningFailure::DidNotAdmit { observables, nonce, digest }` so a host
loop accumulates a [`prism_btc::CampaignStats`] aggregate over the
entire session. At mainnet's `α ≈ 2⁻⁷⁷` this gives the operator typed
visibility into a search that would otherwise be opaque.

Run: `just conformance` (or `cargo test --release -p prism-btc --test
conformance --test mainnet`). Wall-clock ≈ 6 seconds total (3s
scaling tests + 0.2s mainnet observatory).

## §4 Formal proofs — `prism-btc-lean/`

Lean 4 proofs of foundational algebraic identities prism-btc depends on:

| File | Theorem | Status |
|---|---|---|
| `RingIdentity.lean` | `−(¬x) = x + 1` (the W8 / W32 ring identity) | proved |
| `TriadicCoords.lean` | Stratum / spectrum bounds; satisfies-target antitonicity | proved |
| `ShapeConstraint.lean` | Target satisfaction monotonicity; leading-zeros → stratum bound | proved |
| `FreeRankProtocol.lean` | FreeRank decreases monotonically under refinement | proved |
| `ConvergenceProtocol.lean` | σ-projection identity + ψ-vs-σ distinction (load-bearing for ADR-035) | proved |
| `CommitmentChannel.lean` §1 | U6 Joint-Probability Multiplicativity: Conjunction is monoidal over commitment concatenation; `acceptProb` (multiplicative) and `evaluate` (Boolean AND) distribute over append; `Support.disjoint` symmetry; `Commitment.wellFormed` invariant of the Rust typed-iso surface (architecture §14). The `Predicate.acceptProb : Rat` field faithfully covers all four Rust variants (including `PAdicEq{p≥3}` whose log-space bandwidth is irrational). | proved |
| `CommitmentChannel.lean` §2 | **PRF tight-acceptance theorem** (`prf_prob_tight_wellFormed`): under U1 (marginal-uniformity) + U2 (joint-independence under disjoint supports), a `wellFormed` commitment's PRF acceptance probability equals its declared `acceptProb` at equality, not as an upper bound — the operational form of U6 (ANALYSIS.md §5.5, architecture §14.1). U1 + U2 axioms are empirically witnessed by `examples/uor_cryptanalysis.rs` §I + §J at α=0.001. | proved |

Run: `just verify` (= `cd prism-btc-lean && lake update && lake build`).
Build is green against `leanprover/lean4:v4.16.0`.

## §5 Production host loop — `crates/prism-btc-node/`

**Host-loop unit tests** (`crates/prism-btc-node/src/lib.rs::tests`, 4
tests) — pin the extranonce-roll invariants without requiring
bitcoind:

- `extranonce_roll_produces_distinct_merkle_roots` — distinct
  extranonce values produce distinct merkle roots (and hence distinct
  `MiningTask` prefixes, distinct κ-derivations). Same-extranonce
  rebuilds are byte-identical (deterministic host loop).
- `extranonce_roll_holds_non_merkle_header_fields_constant` — only
  the merkle root varies under extranonce roll; version, prev_hash,
  timestamp, bits are template-fixed.
- `assemble_produces_valid_bitcoin_block_with_supplied_nonce` — the
  κ-derived nonce is spliced into a wire-format `Block` with all
  header fields preserved; coinbase carries BIP141 witness and BIP34
  height push.
- `from_components_accepts_witness_commitment` — when SegWit is
  active and bitcoind supplies a witness commitment, the coinbase
  output[1] carries the OP_RETURN commitment correctly.

**Regtest E2E** (gated `#[ignore]`, runs against a real bitcoind):

- `mines_a_block_and_advances_the_chain` — single-block end-to-end:
  1. `getblocktemplate` for a fresh regtest template.
  2. `PrismMiner::mine_one_block` drives the host-boundary
     template-variation loop: build `MiningTask` from current
     extranonce, call `prism_btc::mine`, on `DidNotAdmit` roll the
     extranonce, on `Ok` submit.
  3. `submitblock` accepts the prism-btc-produced block.
  4. The observer client confirms the chain height advanced by
     exactly 1 and the new tip equals the prism-btc-mined block hash.
  5. The mined `MiningWitness` carries a non-zero `unit_address`,
     `witt_level_bits == 32`, and an `output_bytes` of 80 bytes whose
     nonce-field bytes (76..80, LE) decode to the same `u32` the
     submitted block's header carries.

- `mines_a_chain_of_blocks_without_fail` — multi-block end-to-end (10
  consecutive `mine_one_block` calls). Pins the "valid input → valid
  output without fail" claim across repeated invocations: each block
  is `submitblock`-accepted, every per-block wire-format invariant
  holds, every mined block hash is distinct, and the chain advances
  by exactly 10.

**Signet validity gate**: on `Network::Signet`, if `getblocktemplate`
returns a non-empty `signet_challenge` (the default public signet),
`mine_one_block` returns a clear error rather than submitting an
unsigned (invalid) block. BIP325 block signing is not implemented in
prism-btc-node; private no-challenge signets are supported.

To reproduce:

```bash
~/bin/bitcoind -datadir=$HOME/regtest-data -daemon
~/bin/bitcoin-cli -datadir=$HOME/regtest-data -rpcwait createwallet prism
export PRISM_RPC_URL=http://127.0.0.1:18443
export PRISM_RPC_USER=prism PRISM_RPC_PASS=demo
export PRISM_PAYOUT=$(~/bin/bitcoin-cli -datadir=$HOME/regtest-data -rpcwallet=prism getnewaddress "" bech32)
cargo test -p prism-btc-node --release -- --ignored --nocapture
```

## Reproducing the full V&V suite

```bash
just vv
```

`just vv` runs §1 fmt + clippy + unit + integration + V&V tests
(release), §3 Lean proofs, and §4 regtest end-to-end (auto-skipped
when `PRISM_RPC_URL` is unset). The complete suite is the normative
acceptance gate for prism-btc; CI runs the same flow.
