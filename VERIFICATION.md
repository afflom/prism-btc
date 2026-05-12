# prism-btc — Verification & Validation

> **Scope.** This document records what prism-btc verifies and how.
> The V&V suite is reproducible via `just vv` (architecture, fail-closed
> mining, wire-format equivalence, ψ-pipeline determinism, Lean proofs,
> regtest end-to-end). All four axes pass against the current
> implementation.

prism-btc's V&V covers four axes. Each axis has a concrete reproducible
artifact in the repo.

## §1 Architectural conformance — `cargo test --release`

The verb arena, model declarations, and substrate-bindings carry
compile-time invariants the test surface re-asserts at runtime.

- **`crates/prism-btc/src/verbs.rs::tests`** — 6 tests pin the verb
  arena's structural shape: non-empty; contains ψ_1 Nerve, ψ_7
  PostnikovTower, ψ_8 HomotopyGroups, ψ_9 KInvariants; contains zero
  σ-residuals (no `Term::FirstAdmit`, no `Term::AxisInvocation`, no
  byte-comparison or `Concat` ops in the verb body). The substrate's
  proc-macro discipline (ADR-035) enforces the latter at compile time;
  these runtime assertions are defense-in-depth.

- **`crates/prism-btc/src/model.rs::tests`** — 5 tests pin the typed
  feature hierarchy: `TemplatePrefix`'s 76-byte layout
  (`version‖prev_hash‖merkle_root‖timestamp‖bits`); `MiningTask`'s
  108-byte partition_product layout; `MiningResult`'s 80 W8 sites
  (wire-format header width); `IntoBindingValue` 108-byte projection;
  CONSTRAINTS non-empty.

- **`crates/prism-btc/src/shapes/bounds.rs::tests`** — 2 tests pin
  `PrismBtcBounds`' 24 capacity constants and the uniformity of the
  per-ψ-stage output ceilings.

## §2 V&V suite — `crates/prism-btc/tests/verification.rs`

10 tests that pin the load-bearing architectural properties — see the
module docstring for the per-test rationale.

| # | Test | Property |
|---|---|---|
| 1 | `v_verb_arena_composes_only_psi_stages_no_sigma_residuals` | Pure-prism commitment: verb body contains only ψ-Terms + Variable/Literal scaffolding |
| 2 | `v_verb_arena_implements_the_k_invariant_branch` | ψ_1 → ψ_7 → ψ_8 → ψ_9 — the canonical mining transform (architecture §4) |
| 3 | `v_mine_admitting_outcome_digest_actually_satisfies_target` | Cryptographic re-derivation: `outcome.digest` = SHA-256d(wire-format header) and admits target |
| 4 | `v_mine_never_returns_admitting_outcome_for_unachievable_target` | Fail-closed: across 256 variations against a strict target, every `Ok` outcome's digest genuinely satisfies |
| 5 | `v_psi_pipeline_is_pure_function_of_typed_input` | Determinism: 5 repetitions of the same `MiningTask` produce byte-identical κ-labels |
| 6 | `v_psi_pipeline_is_injective_in_the_resolved_nonce_field` | Distinctness: 64 distinct inputs produce 64 distinct κ-derived nonces (no collisions) |
| 7 | `v_kappa_label_is_wire_format_header_byte_for_byte` | Bit-identicality: κ-label = `serialize_header(host_header, resolved_nonce)` byte-for-byte |
| 8 | `v_kappa_label_preserves_the_host_supplied_prefix` | ψ-pipeline preserves the template prefix; only the nonce field is derived |
| 9 | `v_psi_pipeline_invariant_across_network_byte_thresholds` | Network-invariance: same model + same layout across regtest/signet/testnet/testnet4/mainnet `bits` values |
| 10 | `v_compile_unit_fingerprint_identifies_the_typed_iso_path` | TC-03 typed-iso path-singularity: distinct inputs share CompileUnit fingerprint (the path, not the input) |

Run: `cargo test --release -p prism-btc --test verification`. All 10 pass.

## §3 Formal proofs — `prism-btc-lean/`

Lean 4 proofs of foundational algebraic identities prism-btc depends on:

| File | Theorem | Status |
|---|---|---|
| `RingIdentity.lean` | `−(¬x) = x + 1` (the W8 / W32 ring identity) | proved |
| `TriadicCoords.lean` | Stratum / spectrum bounds; satisfies-target antitonicity | proved |
| `ShapeConstraint.lean` | Target satisfaction monotonicity; leading-zeros → stratum bound | proved |
| `FreeRankProtocol.lean` | FreeRank decreases monotonically under refinement | proved |
| `ConvergenceProtocol.lean` | σ-projection identity + ψ-vs-σ distinction (load-bearing for ADR-035) | proved |

Run: `just verify` (= `cd prism-btc-lean && lake update && lake build`).
Build is currently green against `leanprover/lean4:v4.16.0`.

## §4 Regtest end-to-end — `crates/prism-btc-node/tests/regtest.rs`

`mines_a_block_and_advances_the_chain` (gated `#[ignore]`) runs the
complete client against a real bitcoind:

1. `getblocktemplate` for a fresh regtest template.
2. `PrismMiner::mine_one_block` drives the host-boundary template-
   variation loop: build `MiningTask` from current extranonce, call
   `prism_btc::mine`, on `DidNotAdmit` roll the extranonce, on `Ok`
   submit.
3. `submitblock` accepts the prism-btc-produced block.
4. The observer client confirms the chain height advanced by exactly 1
   and the new tip equals the prism-btc-mined block hash.
5. The mined `MiningWitness` carries a non-zero `unit_address`,
   `witt_level_bits == 32`, and an `output_bytes` of 80 bytes whose
   nonce-field bytes (76..80, LE) decode to the same `u32` the
   submitted block's header carries.

**The end-to-end test passed 4/4 in this session's V&V run** — each
invocation advanced the regtest chain by exactly one block. To
reproduce:

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

`just vv` runs §1 fmt + clippy, §2 unit + integration + V&V tests
(release), §3 Lean proofs, and §4 regtest end-to-end (auto-skipped
when `PRISM_RPC_URL` is unset). The complete suite is the normative
acceptance gate for prism-btc; CI runs the same flow.
