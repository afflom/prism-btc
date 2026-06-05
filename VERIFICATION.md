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
compile-time invariants the test surface re-asserts at runtime. 54
unit tests across the prism-btc crate's modules:

- **`crates/prism-btc/src/model.rs::tests`** (3 tests) — the model's
  input/output shapes: `BlockHeaderCarrier`'s canonical header field
  decomposition (version‖prev_hash‖merkle_root‖timestamp‖bits‖nonce);
  `BlockAddressLabel`'s 72 W8 sites (the `sha256d:<64hex>` κ-label
  width per wiki ADR-048/049); CONSTRAINTS' 72 disjoint Site instances
  spanning [0, 72). The verb-arena's structural shape (ψ_1 Nerve, ψ_7
  PostnikovTower, ψ_8 HomotopyGroups, ψ_9 KInvariants; zero
  σ-residuals) is pinned by the §2 V&V tests (rows 1–2).

- **`crates/prism-btc/src/composition.rs::tests`** (6 tests) — the
  ADR-061 `sha256d` composition reference impl: `compose_g2_product`
  commutativity, `compose_ordered_product` non-commutativity,
  `compose_e8_embedding` grounding, Bitcoin `merkle_root` as iterated
  ordered composition, and non-`sha256d`-axis rejection.

- **`crates/prism-btc/src/shapes/bounds.rs::tests`** (1 test) —
  `PrismBtcBounds` is a transparent alias for the shared
  `uor_addr::AddrBounds` profile (`FINGERPRINT_MAX_BYTES = 32`); under
  ADR-060 there are no per-ψ-stage byte ceilings, and the structural
  site ceiling admits the 72-byte κ-label.

- **`crates/prism-btc/src/shapes/hasher.rs::tests`** (3 tests) —
  `Sha256dHasher` streaming-vs-one-shot equivalence and FIPS-180-4
  display-order vector matching.

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

- **`crates/prism-btc/src/pipeline.rs::tests`** (3 tests) — the
  kernel's admission-recognition entry (`mine_at`) under foundation's
  typed-commitment surface (wiki ADR-048):
  - A bridge-layer nonce-scan over `mine_at` admits within a small
    window for a permissive regtest target — foundation's
    `run_route` evaluates `TargetCommitment` on the κ-label inside
    the catamorphism; the `AddressWitness` re-verifies to the same
    72-byte κ-label.
  - On `Ok`, the κ-label is the `sha256d:<64hex>` address (carrying
    the 32-byte display-order digest, wiki ADR-048/049 cost-model
    surface); the 80-byte wire-format header is surfaced on the side
    as `outcome.wire_format_header` for the `submitblock` boundary.
  - `MiningFailure::DidNotAdmit` carries the receiver-side typed
    lens (`observables`, `nonce`, `digest`) — total lens, not
    admission-only.

- **`crates/prism-btc/src/commitment.rs::tests`** — foundation's
  re-exported cost-model surface + prism-btc's K-fold payload
  helpers:
  - `target_commitment(...)` (foundation's
    `SingletonCommitment<LexicographicLessEqThreshold>` alias)
    admits a 32-byte digest at the threshold neighborhood;
    `predicate_count() == 1`.
  - `payload_commitment_k2 / k4 / k8` round-trip: encode K bits at
    canonical low-bit positions, the commitment admits the
    synthesized digest, and `decode_payload` returns the encoded
    bits.
  - `AndCommitment<TargetCommitment, payload>` is bandwidth-additive
    and `predicate_count`-additive; `EmptyCommitment` is the
    composition identity.
  - `leak_target` deduplicates: repeat calls with the same bytes
    return the same `&'static` pointer (registry-backed).

- **`crates/prism-btc/src/observables.rs::tests`** (3 tests) — the
  receiver-side typed lens:
  - `KappaObservables::from_digest` decodes the canonical landscape
    (stratum, spectrum, p-adic valuations at `CANONICAL_PRIMES =
    {2, 3, 5, 7}`); `p_adic_at(2)` agrees with `coords.stratum`.
  - **Round-trip identity** across each canonical
    `ObservablePredicate` variant (`Stratum<P>`,
    `WalshHadamardParity`, `UltrametricCloseTo<P>`, `AffineParity`,
    `LexicographicLessEqThreshold`):
    `pred.evaluate(d) == ExtendedObservables::from_digest(d, ωs,
    refs).satisfies(&pred, d)` — sender ↔ receiver consistency
    pinned algebraically.
  - `ExtendedObservables::<0, 0>` is a valid instantiation
    (canonical-only lens; the const-generic shape covers
    the zero-extension case).

Every admitting `forward()` carries a replayable TC-05
[`AddressWitness<72, 32>`](crates/prism-btc/src/pipeline.rs) (alias
`MiningWitness`) — the proof-of-work witness; `.verify()` re-certifies
the κ-label without re-invoking the σ-axis. Its behaviour is pinned by
the §2 V&V tests below (row 14).

## §2 V&V suite — `crates/prism-btc/tests/verification.rs`

14 tests that pin the load-bearing architectural properties. 7
additional integration tests in `crates/prism-btc/tests/integration.rs`
exercise the typed-iso surface end-to-end. Module docstrings carry the
per-test rationale.

| # | Test | Property |
|---|---|---|
| 1 | `v_verb_arena_composes_only_psi_stages_no_sigma_residuals` | Pure-prism commitment: verb body contains only ψ-Terms + Variable/Literal scaffolding |
| 2 | `v_verb_arena_implements_the_k_invariant_branch` | ψ_1 → ψ_7 → ψ_8 → ψ_9 — the canonical block-address transform (architecture §4) |
| 3 | `v_mine_admits_for_permissive_target` | A bridge-layer scan over `mine_at` admits within a small nonce-scan window for a permissive regtest target — admission decided by foundation's `run_route` via the model's `TargetCommitment` |
| 4 | `v_mine_outcome_digest_actually_satisfies_target_when_admitted` | Fail-closed: every `Ok` outcome's digest genuinely satisfies the target (the typed-iso gate is inside `run_route`) |
| 5 | `v_psi_pipeline_is_pure_function_of_typed_input` | Determinism: repetitions of the same header carrier produce byte-identical κ-labels |
| 6 | `v_kappa_label_is_distinct_for_distinct_typed_inputs` | Distinctness: distinct inputs produce distinct κ-labels |
| 7 | `v_kappa_label_is_sha256d_of_reconstructed_wire_format_header` | The κ-label digest equals `SHA-256d(serialize_header(host_header, nonce))` (display order) byte-for-byte |
| 8 | `v_wire_format_header_preserves_the_host_supplied_prefix` | The wire-format header preserves the host-supplied template prefix; only the explicit nonce field varies |
| 9 | `v_model_declarations_invariant_across_network_byte_thresholds` | Network-invariance: same model + same verb arena + same `TargetCommitment` shape across regtest/signet/testnet/testnet4/mainnet `bits` values |
| 10 | `v_witness_replays_to_the_attested_kappa_label` | TC-05 replayable witness: `AddressWitness::verify()` re-certifies the same 72-byte κ-label without re-invoking the σ-axis |
| 11 | `v_block_address_label_constraints_have_seventy_two_disjoint_site_instances` | Algebraic-closure encoding: 72 disjoint `ConstraintRef::Site` instances on `BlockAddressLabel` (IT_7d) |
| 12 | `v_constraint_nerve_is_seventy_two_isolated_vertices_no_higher_simplices` | Constraint-nerve geometry: β_0 = 72, β_k = 0 for k ≥ 1, χ = SITE_COUNT = 72 |
| 13 | `v_constraint_site_supports_span_the_full_kappa_label` | Site supports cover [0, 72) — every κ-label byte pinned by one Site constraint |
| 14 | `v_prism_btc_bounds_declare_algebraic_closure_target` | `PrismBtcBounds` (alias for `uor_addr::AddrBounds`) admits the 72-site κ-label geometry (compile-time assertion) |

Run: `cargo test --release -p prism-btc --test verification`.

## §3 Conformance suite — `crates/prism-btc/tests/{conformance,mainnet}.rs`

19 conformance tests validating that prism's zero-cost runtime model
scales arbitrarily over K (commitment bandwidth), α (admission
probability), and the full range of legitimate mainnet inputs. See
[`CONFORMANCE.md`](CONFORMANCE.md) for the normative per-invariant
statements; tests are ID'd against it.

| Class | Count | What it asserts |
|---|---|---|
| **CS** (structural) | 6 | No `Vec<Predicate>` / `dyn TypedCommitment` / `Box<dyn …>` in `src/`; `TypedCommitment: Copy + Sealed` enforced (foundation supertrait, wiki ADR-048); foundation's five canonical `ObservablePredicate` impls (`Stratum<P>`, `WalshHadamardParity`, `UltrametricCloseTo<P>`, `AffineParity`, `LexicographicLessEqThreshold`) reachable + closed catalog pinned (ADR-049); `MiningOutcome.observables: KappaObservables` always present; no legacy commitment-surface identifiers (`MiningCommitment`, `mine_with(`, `PayloadCommitment<`, `enum Predicate`, `enum Support`, …) in `src/`. |
| **CD** (dynamic) | 3 | `mine_at` returns `Ok` ⇒ digest satisfies the model's pinned `TargetCommitment` (admission was evaluated inside `run_route`); `payload_commitment_k*` helpers round-trip at K ∈ {1, 2, 4, 8}; `MiningOutcome.observables` agrees with the per-primitive `TriadicCoords::from_hash` / `p_adic_valuation` computation. |
| **CP** (probabilistic scaling) | 4 | `α⁻¹ × 2^K` cost identity holds within ±30% (≈4σ at N=200) across (a) K-sweep over four decades [0..12] at fixed α, (b) α-sweep over four decades [2⁻¹..2⁻¹²] at fixed K=2, (c) compound K × α decompositions of the same product; (d) foundation's `AndCommitment<TargetCommitment, payload>` is bandwidth-additive + `predicate_count`-additive + identity under `EmptyCommitment`, witnessed empirically across (lz, K) combinations. |
| **CM** (mainnet readiness) | 6 | `Target::new(nBits)` accepts every mainnet-difficulty value in the chain's history; `mine_at` produces well-formed 72-byte `sha256d` κ-labels (with 80-byte `wire_format_header` + 32-byte display-order digest) on synthetic mainnet inputs (`PipelineFailure` unreachable across 400 attempts × 8 difficulty levels); aggregate `CampaignStats` matches PRF baseline at N=10⁴ (χ² goodness-of-fit on stratum + spectrum at α=0.001); empirical α converges to theoretical α at N=10⁴ within ±5%; campaign is consistent under cooperative interruption. |
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
| `CommitmentChannel.lean` §1 | U6 Joint-Probability Multiplicativity: Conjunction is monoidal over commitment concatenation; `acceptProb` (multiplicative) and `evaluate` (Boolean AND) distribute over append; `Support.disjoint` symmetry; `Commitment.wellFormed` invariant of the foundation `TypedCommitment` catalog (wiki ADR-048 + ADR-049). The Lean `Predicate.acceptProb : Rat` field faithfully covers each canonical `ObservablePredicate` variant (including `Stratum<P>` for primes p ≥ 3 whose log-space bandwidth is irrational). | proved |
| `CommitmentChannel.lean` §2 | **PRF tight-acceptance theorem** (`prf_prob_tight_wellFormed`): under U1 (marginal-uniformity) + U2 (joint-independence under disjoint supports), a `wellFormed` commitment's PRF acceptance probability equals its declared `acceptProb` at equality, not as an upper bound — the operational form of U6 (ANALYSIS.md §5.5, architecture §14.1). U1 + U2 axioms are empirically witnessed by `examples/uor_cryptanalysis.rs` §I + §J at α=0.001. | proved |

Run: `just verify` (= `cd prism-btc-lean && lake update && lake build`).
Build is green against `leanprover/lean4:v4.16.0`.

## §5 Production host loop — `crates/prism-btc-node/`

**Host-loop unit tests** (`crates/prism-btc-node/src/lib.rs::tests`, 4
tests) — pin the extranonce-roll invariants without requiring
bitcoind:

- `extranonce_roll_produces_distinct_merkle_roots` — distinct
  extranonce values produce distinct merkle roots (and hence distinct
  header carriers, distinct κ-labels). Same-extranonce rebuilds are
  byte-identical (deterministic host loop).
- `extranonce_roll_holds_non_merkle_header_fields_constant` — only
  the merkle root varies under extranonce roll; version, prev_hash,
  timestamp, bits are template-fixed.
- `assemble_produces_valid_bitcoin_block_with_supplied_nonce` — the
  winning nonce (from the bridge's nonce scan over `mine_at`) is
  spliced into a wire-format `Block` with all header fields preserved;
  coinbase carries BIP141 witness and BIP34 height push.
- `from_components_accepts_witness_commitment` — when SegWit is
  active and bitcoind supplies a witness commitment, the coinbase
  output[1] carries the OP_RETURN commitment correctly.

**Regtest E2E** (gated `#[ignore]`, runs against a real bitcoind):

- `mines_a_block_and_advances_the_chain` — single-block end-to-end:
  1. `getblocktemplate` for a fresh regtest template.
  2. `PrismMiner::mine_one_block` drives the host-boundary
     template-variation loop: build the block header from the current
     extranonce, walk the nonce space invoking `prism_btc::mine_at`
     per candidate, on exhaustion roll the extranonce, on `Ok` submit.
  3. `submitblock` accepts the prism-btc-produced block.
  4. The observer client confirms the chain height advanced by
     exactly 1 and the new tip equals the prism-btc-mined block hash.
  5. The mined `MiningWitness` (the replayable TC-05
     `AddressWitness<72, 32>`) re-certifies via `.verify()` to the
     attested `sha256d:<64hex>` κ-label (72 bytes) and carries a
     32-byte `content_fingerprint` — the proof-of-work witness.

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
