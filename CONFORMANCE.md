# prism-btc — Conformance

> **Purpose.** This document defines the conformance contract prism-btc
> must uphold to claim that prism's zero-cost runtime model **scales
> arbitrarily** — to mainnet, beyond, and across any UOR-hardened
> σ-projection axis. Each conformance invariant is identified by class
> + number, stated normatively, paired with its enforcement mechanism,
> and traced to a concrete test or proof artifact in the repo. Passing
> the conformance suite (`just conformance`, included in `just vv`)
> is the durable signal that the implementation continues to realize
> the model.

## The contract

Prism's zero-cost runtime model says, for any well-formed typed
commitment `C` and any admission target with probability `α`:

> **Operational mining cost** (expected template variations per
> commit-admitting κ-label) **equals** `α⁻¹ × 2^bandwidth_bits(C)` **at
> equality, not as an upper bound** (Lean theorem
> `Commitment.prf_prob_tight_wellFormed`).

For this contract to **scale arbitrarily** the implementation must
preserve five structural properties for any (K, α, network)
combination the framework can produce:

1. **No dynamic dispatch** on the commitment shape — every commitment
   is a compile-time-known typed structure.
2. **No runtime allocation** in the commitment hot path — stack-only.
3. **`wellFormed` discharged at the type level** — never via a
   runtime disjointness check.
4. **Per-template structural cost is O(1)** in target.difficulty,
   network parameters, and commitment K (per template — the host's
   loop count `1/α × 2^K` is the externality, not a per-template
   overhead).
5. **The Lean tight-bound theorem applies** to every Rust
   monomorphization the framework produces.

Conformance enforces these structural properties; the V&V suite
(`VERIFICATION.md`) enforces functional correctness; together they
make the cost-model claim verifiable rather than aspirational.

## Conformance classes

| Class | Scope | Enforcement |
|---|---|---|
| **CS** | Structural invariants — what the implementation must never grow into | source-grep + compile-time + struct-field tests |
| **CD** | Dynamic invariants — per-input runtime behavior the model demands | runtime tests, parameterized over input shape |
| **CP** | Probabilistic scaling — cost identity holds across K and α | empirical scaling tests with statistical power |
| **CN** | Network-invariance — pipeline is uniform across all chains | cross-reference to V&V + host-loop tests |
| **CL** | Lean-formal — algebraic and probabilistic theorems | cross-reference to `prism-btc-lean/` |

## CS — Structural invariants

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CS-1** | No `Vec<Predicate>` is constructed anywhere in `crates/prism-btc/src`. The dynamic commitment surface was deleted and must not return. | source-grep test | `tests/conformance.rs::cs1_no_vec_of_predicate_in_library_source` |
| **CS-2** | No `Box<dyn TypedCommitment>` or other dynamic dispatch on the commitment trait. The trait must be monomorphized per use site. | source-grep test | `tests/conformance.rs::cs2_no_dyn_typed_commitment_in_library_source` |
| **CS-3** | `TypedCommitment: Copy` — every commitment is a `Copy` type, stack-allocable, no heap pressure. | compile-time (supertrait bound on `TypedCommitment`) | `crates/prism-btc/src/commitment.rs::TypedCommitment` declaration |
| **CS-4** | `Predicate` has exactly four variants (`Parity`, `StratumEq`, `PAdicEq`, `UltrametricCloseTo`) — the canonical typed observable basis the cryptanalysis battery covers. Adding a variant without re-running U1/U2 calibration is forbidden. | compile-time (match exhaustiveness) | `tests/conformance.rs::cs4_predicate_has_exactly_four_variants` |
| **CS-5** | `MiningOutcome` carries `observables: KappaObservables` as a non-optional field. The receiver-side lens is always present. | compile-time (struct field) | `tests/conformance.rs::cs5_mining_outcome_carries_observables` |
| **CS-6** | No legacy commitment terminology (`MiningCommitment`, `mine_with_commitment`, `CommitmentError`, `try_add_predicate`, `add_predicate`) appears in `src/` or in documentation that ships as part of the crate. | source-grep test | `tests/conformance.rs::cs6_no_legacy_commitment_surface_references` |

## CD — Dynamic invariants

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CD-1** | `mine_with(_, _, EmptyCommitment)` is byte-equivalent to bare `mine`. The typed surface adds zero runtime cost over the no-commitment case. | runtime test | `tests/conformance.rs::cd1_mine_with_empty_is_bit_equivalent_to_bare_mine` |
| **CD-2** | For every K ∈ {0, 1, 2, 4, 8}, `PayloadCommitment::<K>` round-trips: encode K payload bits, find an admitting κ-label, decode the κ-label's bits, agree byte-for-byte with the encoded payload. (Higher K is covered probabilistically by CP-1 — round-tripping at K=16 would require ~10^5 admitting templates per round-trip, redundant with the K-sweep scaling test.) | runtime test (parameterized via macro expansion) | `tests/conformance.rs::cd2_payload_commitment_round_trips_at_every_k` |
| **CD-3** | `MiningOutcome.observables.coords` agrees with `TriadicCoords::from_hash(&outcome.digest)`; `MiningOutcome.observables.p_adic[i]` agrees with `p_adic_valuation(&outcome.digest, CANONICAL_PRIMES[i])`. The receiver-side decoding is consistent with the per-primitive computation. | runtime test | `tests/conformance.rs::cd3_observables_agree_with_per_primitive_computation` |
| **CD-4** | The constraint nerve has exactly 80 disjoint Site instances spanning `[0, 80)`, regardless of target.bits. The algebraic-closure encoding is target-invariant. | runtime test | `tests/verification.rs::v_constraint_nerve_*` (cross-reference) |
| **CD-5** | Distinct extranonces produce distinct merkle roots (and hence distinct `MiningTask` prefixes and κ-derivations) at the host boundary. | runtime test | `crates/prism-btc-node/src/lib.rs::tests::extranonce_roll_produces_distinct_merkle_roots` (cross-reference) |

## CP — Probabilistic scaling

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CP-1** | At fixed α (admission_lz = 1, α = 1/2), expected trial count matches `α⁻¹ × 2^K` for K ∈ {0, 2, 4, 8, 12} within ±30% (≈ 4σ) at N=200 trials per K. The doubling holds across four decades in K. | empirical (synthetic mining loop over SHA-256d) | `tests/conformance.rs::cp1_k_scaling_holds_across_two_decades` |
| **CP-2** | At fixed K=2, expected trial count scales as `α⁻¹` across admission probabilities α ∈ {2⁻¹, 2⁻⁴, 2⁻⁸, 2⁻¹²} within ±30% at N=200. The `α⁻¹` factor holds independently of K. | empirical (synthetic mining loop, varying admission stringency) | `tests/conformance.rs::cp2_alpha_scaling_holds_at_fixed_k` |
| **CP-3** | The compound cost `α⁻¹ × 2^K` factors multiplicatively: trial count at (K=4, α=2⁻⁴), (K=2, α=2⁻⁶), and (K=0, α=2⁻⁸) — all targeting product 2⁸ = 256 trials — agree on the product within ±30%. The model's product structure is empirically realized. | empirical | `tests/conformance.rs::cp3_compound_k_alpha_scaling_is_multiplicative` |
| **CP-4** | U1 (marginal-uniformity) holds per Predicate variant at α = 0.001 confidence: empirical acceptance rate of each variant matches its `accept_prob_rational()` at 10⁶ samples (χ² < 10.83, df=1). | empirical | `examples/uor_cryptanalysis.rs::section_i_u1_marginal_calibration` (cross-reference) |
| **CP-5** | U2 (joint-independence) holds for disjoint-support Predicate pairs at α = 0.001 confidence across BitSet⊥BitSet / BitSet⊥Modular / Modular⊥Modular regimes. | empirical | `examples/uor_cryptanalysis.rs::section_j_u2_joint_independence` (cross-reference) |

## CN — Network-invariance

| ID | Statement | Witness |
|---|---|---|
| **CN-1** | Same `BitcoinMiningModel`, same verb arena, same resolver tuple across regtest/signet/testnet/testnet4/mainnet `bits` values; only the target byte threshold varies. | `tests/verification.rs::v_model_declarations_invariant_across_network_byte_thresholds` |
| **CN-2** | The host loop in `prism-btc-node::PrismMiner::mine_one_block` does not branch on the network beyond template rules (SegWit/Csv/Taproot/Signet) and the signet-challenge gate. | source inspection + `crates/prism-btc-node/src/lib.rs::mine_one_block` |
| **CN-3** | Wire-format output is byte-identical to what `submitblock` expects for any network with template-supplied parameters. | `tests/regtest.rs::mines_a_chain_of_blocks_without_fail` (10-block chain accepted byte-for-byte) |
| **CN-4** | On `Network::Signet` with non-empty `signet_challenge`, `mine_one_block` fail-closed rather than produce an unsigned (invalid) block. | `crates/prism-btc-node/src/lib.rs::mine_one_block` signet gate |

## CL — Lean-formal

| ID | Statement | Witness |
|---|---|---|
| **CL-1** | `Commitment.prf_prob_tight_wellFormed` is proven for every `c : Commitment` of arbitrary length under U1+U2 axioms. The theorem covers all Rust monomorphizations. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` §2 |
| **CL-2** | `Commitment.acceptProb_append` (the multiplicative form of U6) is proven for arbitrary commitment concatenation. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` §1 |
| **CL-3** | `Predicate.acceptProb : Rat` faithfully covers all four Rust variants — including `PAdicEq { p ≥ 3 }` whose log-space bandwidth is irrational. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` Predicate definition + Rust `Predicate::accept_prob_rational()` correspondence |
| **CL-4** | `Support.disjoint` is symmetric; `wellFormed_empty` and `wellFormed_singleton` hold vacuously; `wellFormed.head_disjoint` and `wellFormed.tail` destructure `cons`. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` Support + Commitment.wellFormed |

## What conformance does **not** claim

- **Compute feasibility** of high-difficulty mining. Mainnet `α ≈ 2⁻⁷⁷`
  implies `2⁷⁷` template variations in expectation — a physics +
  hardware budget, not a prism-btc property. The conformance suite
  validates that prism-btc's per-template structural cost is `O(1)` in
  target.difficulty; the externality is the host loop's iteration count.
- **Cryptographic security** of the σ-projection beyond what U1–U5
  empirical witnessing covers. The Lean theorem is conditional on
  U1+U2; the conformance suite witnesses them per-variant. Proving
  SHA-256d is a PRF is an open cryptographic problem; conformance
  doesn't claim to close it.
- **Operational invariants** outside prism-btc's surface: stale
  templates over long mining sessions, network reorganizations,
  RPC reliability. The host loop's behavior under these is bounded by
  `prism-btc-node`'s gates; deeper operational concerns belong to the
  operator.
- **Identity of the σ-projection axis**. The conformance suite is
  stated against prism-btc's choice of `Sha256dHasher`. The framework
  generalizes; substituting another UOR-hardened axis (Blake3, Keccak,
  post-quantum) is the natural extension and will re-instantiate the
  same conformance contract against the new hasher.

## Reproducing

```bash
# Conformance only:
cargo test -p prism-btc --release --test conformance

# Conformance as part of the full V&V suite:
just vv
```

The conformance suite is part of `just vv`'s §3 axis (after fmt+clippy
and the unit/V&V tests, before rustdoc/Lean/regtest E2E). Failing any
conformance test indicates the implementation has drifted from prism's
zero-cost contract and must be reconciled before merge.
