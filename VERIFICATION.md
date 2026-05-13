# prism-btc — Verification & Validation

> **Scope.** This document records what prism-btc verifies and how.
> The V&V suite is reproducible via `just vv` across four axes:
> architecture (fmt + clippy + unit + integration tests), the
> dedicated V&V test module, Lean proofs, and a regtest end-to-end
> run.

prism-btc's V&V covers four axes. Each axis has a concrete reproducible
artifact in the repo.

## §1 Architectural conformance — `cargo test --release`

The verb arena, model declarations, and substrate-bindings carry
compile-time invariants the test surface re-asserts at runtime. 55
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

- **`crates/prism-btc/src/pipeline.rs::tests`** (16 tests) — the
  UOR-optimal mining surface (architecture §14):
  - Predicate semantics: empty commitment ≡ bare `mine()`;
    `Predicate::Parity` reads a single bit (bandwidth 1);
    `Predicate::StratumEq{k}` matches the 2-adic stratum
    (bandwidth `k+1`); `Predicate::PAdicEq{p, k}` matches the
    p-adic valuation (bandwidth `(k+1)·log₂p − log₂(p−1)`);
    `Predicate::UltrametricCloseTo{r, k}` matches the 2-adic
    distance (bandwidth `k`).
  - Bandwidth-additivity (U6) over **disjoint** supports;
    Conjunction'd evaluation = AND of per-predicate evaluations
    across mixed types; `mine_with_commitment` admits at a
    permissive target with the empty commitment.
  - Support algebra (§14.2): `PAdicEq{p=2}` canonicalizes to
    `BitSet`; `BitSet ⊥ BitSet` iff bit-disjoint; same-byte
    overlap is detected as dependent; distinct-byte `BitSet`s are
    independent; `Modular{p₁} ⊥ Modular{p₂}` iff `p₁ ≠ p₂`;
    `Modular{p≥3} ⊥ BitSet(_)` always.
  - Enforcement: `try_add_predicate` returns
    `Err(OverlappingSupport{ existing_index })` on overlap and
    succeeds on disjoint supports; `add_predicate` panics with
    "overlapping support" on overlap.

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

## §3 Formal proofs — `prism-btc-lean/`

Lean 4 proofs of foundational algebraic identities prism-btc depends on:

| File | Theorem | Status |
|---|---|---|
| `RingIdentity.lean` | `−(¬x) = x + 1` (the W8 / W32 ring identity) | proved |
| `TriadicCoords.lean` | Stratum / spectrum bounds; satisfies-target antitonicity | proved |
| `ShapeConstraint.lean` | Target satisfaction monotonicity; leading-zeros → stratum bound | proved |
| `FreeRankProtocol.lean` | FreeRank decreases monotonically under refinement | proved |
| `ConvergenceProtocol.lean` | σ-projection identity + ψ-vs-σ distinction (load-bearing for ADR-035) | proved |
| `CommitmentChannel.lean` | U6 Bandwidth-Additivity: Conjunction is monoidal over commitment concatenation; bandwidth and evaluation distribute over append; `Support.disjoint` symmetry; `Commitment.wellFormed` invariant of the Rust typed-iso surface (architecture §14) | proved |

Run: `just verify` (= `cd prism-btc-lean && lake update && lake build`).
Build is green against `leanprover/lean4:v4.16.0`.

## §4 Regtest end-to-end — `crates/prism-btc-node/tests/regtest.rs`

`mines_a_block_and_advances_the_chain` (gated `#[ignore]`) runs the
complete client against a real bitcoind:

1. `getblocktemplate` for a fresh regtest template.
2. `PrismMiner::mine_one_block` drives the host-boundary template-
   variation loop: build `MiningTask` from current extranonce, call
   `prism_btc::mine`, on `DidNotAdmit` (κ-derivation didn't satisfy
   target at the boundary admission check) roll the extranonce,
   on `Ok` submit.
3. `submitblock` accepts the prism-btc-produced block.
4. The observer client confirms the chain height advanced by exactly 1
   and the new tip equals the prism-btc-mined block hash.
5. The mined `MiningWitness` carries a non-zero `unit_address`,
   `witt_level_bits == 32`, and an `output_bytes` of 80 bytes whose
   nonce-field bytes (76..80, LE) decode to the same `u32` the
   submitted block's header carries.

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
