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
| **CM** | Mainnet readiness — implementation handles every legitimate mainnet input | runtime tests using synthetic mainnet-difficulty inputs + aggregate observatory at N=10⁴ |
| **CN** | Network-invariance — pipeline is uniform across all chains | cross-reference to V&V + host-loop tests |
| **CL** | Lean-formal — algebraic and probabilistic theorems | cross-reference to `prism-btc-lean/` |

## CS — Structural invariants

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CS-1** | No `Vec<Predicate>`, `Vec<dyn TypedCommitment>`, or `Vec<Box<dyn TypedCommitment>>` is constructed anywhere in `crates/prism-btc/src`. The dynamic commitment surface (legacy local `Predicate` enum + boxed-trait dispatch) was deleted and must not return. | source-grep test | `tests/conformance.rs::cs1_no_vec_of_typed_commitment_in_library_source` |
| **CS-2** | No `dyn TypedCommitment` or `Box<dyn TypedCommitment>` appears in library sources. Foundation's `TypedCommitment` is sealed (wiki ADR-048) and must be monomorphized per use site. | source-grep test | `tests/conformance.rs::cs2_no_dyn_typed_commitment_in_library_source` |
| **CS-3** | `TypedCommitment: Copy + Sealed` — foundation's supertrait bound (ADR-048) is enforced at compile time. Every commitment shape an application can construct is stack-allocable and has the Lean `prf_prob_tight_wellFormed` theorem applying at equality. | compile-time (supertrait bound on `TypedCommitment`) | `tests/conformance.rs::cs3_typed_commitment_requires_copy` |
| **CS-4** | Foundation's five canonical `ObservablePredicate` impls (`Stratum<P>`, `WalshHadamardParity`, `UltrametricCloseTo<P>`, `AffineParity`, `LexicographicLessEqThreshold`) are reachable through prism-btc's re-exports and pin the closed catalog at compile time per wiki ADR-049. The catalog is sealed; adding a new variant requires foundation-side U1/U2 calibration. | compile-time (trait-bound witnesses) + runtime accept-probability checks | `tests/conformance.rs::cs4_foundation_observable_predicates_cover_five_canonical_families` |
| **CS-5** | `MiningOutcome` carries `observables: KappaObservables` as a non-optional field. The receiver-side lens is always present (and total — also present on `MiningFailure::DidNotAdmit`). | compile-time (struct field) | `tests/conformance.rs::cs5_mining_outcome_carries_observables` |
| **CS-6** | No legacy commitment-surface identifier (`MiningCommitment`, `mine_with_commitment`, `CommitmentError`, `try_add_predicate`, `add_predicate`, `mine_with(`, `PayloadCommitment<`, `enum Predicate `, `enum Support `) appears in `src/`. These pre-foundation APIs would re-introduce author-side trait impls / runtime dispatch / non-canonical predicate enums if they returned. | source-grep test | `tests/conformance.rs::cs6_no_legacy_commitment_surface_references` |

## CD — Dynamic invariants

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CD-1** | `mine_at(header, target, nonce)` threads `TargetCommitment` through foundation's `run_route` as the model's pinned `C: TypedCommitment` (wiki ADR-048). When `mine_at` returns `Ok(outcome)` the κ-label's 32-byte digest satisfies the target by construction — admission was evaluated inside the catamorphism, not at a host-boundary gate. | runtime test | `tests/conformance.rs::cd1_mine_admits_under_target_commitment` |
| **CD-2** | For every K ∈ {1, 2, 4, 8} the `payload_commitment_k*` helpers produce foundation `AndCommitment` trees of `SingletonCommitment<AffineParity>` leaves (wiki QS-06's K-fold exemplar). The commitment `evaluate` and `decode_payload` are inverses: a synthetic digest carrying K bits at the canonical low-bit positions admits the commitment, and `decode_payload` round-trips the encoded payload byte-for-byte. (K=1 is the `payload_bit` single-leaf case.) | runtime test (synthetic digest, per-K) | `tests/conformance.rs::cd2_payload_commitment_round_trips_at_every_k` |
| **CD-3** | `MiningOutcome.observables.coords` agrees with `TriadicCoords::from_hash(&outcome.digest)`; `MiningOutcome.observables.p_adic[i]` agrees with `p_adic_valuation(&outcome.digest, CANONICAL_PRIMES[i])`. The receiver-side decoding is consistent with the per-primitive computation. | runtime test | `tests/conformance.rs::cd3_observables_agree_with_per_primitive_computation` |
| **CD-4** | The constraint nerve of `BlockAddressLabel` has exactly 72 disjoint `Site` instances spanning `[0, 72)`, regardless of target.bits. The algebraic-closure encoding (IT_7d, χ = SITE_COUNT = 72) is target-invariant. | runtime test | `tests/verification.rs::v_constraint_nerve_is_seventy_two_isolated_vertices_no_higher_simplices` (cross-reference) |
| **CD-5** | Distinct extranonces produce distinct merkle roots (and hence distinct header carriers and κ-labels) at the host boundary. | runtime test | `crates/prism-btc-node/src/lib.rs::tests::extranonce_roll_produces_distinct_merkle_roots` (cross-reference) |

## CP — Probabilistic scaling

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CP-1** | At fixed α (admission_lz = 1, α = 1/2), expected trial count matches `α⁻¹ × 2^K` for K ∈ {0, 2, 4, 8, 12} within ±30% (≈ 4σ) at N=200 trials per K. The doubling holds across four decades in K. | empirical (synthetic mining loop over SHA-256d) | `tests/conformance.rs::cp1_k_scaling_holds_across_two_decades` |
| **CP-2** | At fixed K=2, expected trial count scales as `α⁻¹` across admission probabilities α ∈ {2⁻¹, 2⁻⁴, 2⁻⁸, 2⁻¹²} within ±30% at N=200. The `α⁻¹` factor holds independently of K. | empirical (synthetic mining loop, varying admission stringency) | `tests/conformance.rs::cp2_alpha_scaling_holds_at_fixed_k` |
| **CP-3** | The compound cost `α⁻¹ × 2^K` factors multiplicatively: trial count at (K=4, α=2⁻⁴), (K=2, α=2⁻⁶), and (K=0, α=2⁻⁸) — all targeting product 2⁸ = 256 trials — agree on the product within ±30%. The model's product structure is empirically realized. | empirical | `tests/conformance.rs::cp3_compound_k_alpha_scaling_is_multiplicative` |
| **CP-4** | Foundation's `AndCommitment<TargetCommitment, payload>` (wiki QS-06's typed composition surface) has additive `bandwidth_bits`, additive `predicate_count`, and multiplicative `accept_prob`; `EmptyCommitment` is the composition identity (bandwidth = 0). Empirically: at `lz` leading-zero admission bits and a K-bit payload at canonical AffineParity positions, the composed gate lands an admitting+committed digest in ~2^(lz + K) synthetic trials within ±30%. The U3-orthogonality between target admission and payload predicates witnesses that the Lean tight-bound theorem applies at equality over the unified `K + B` bandwidth. | empirical + compile-time bandwidth check | `tests/conformance.rs::cp4_typed_commitment_composition_is_bandwidth_additive` |
| **CP-5** | U1 (marginal-uniformity) holds per `ObservablePredicate` variant at α = 0.001 confidence: empirical acceptance rate of each variant matches its `accept_prob()` at 10⁶ samples (χ² < 10.83, df=1). | empirical | `examples/uor_cryptanalysis.rs::section_i_u1_marginal_calibration` (cross-reference) |
| **CP-6** | U2 (joint-independence) holds for disjoint-support predicate pairs at α = 0.001 confidence across BitSet⊥BitSet / BitSet⊥Modular / Modular⊥Modular regimes. | empirical | `examples/uor_cryptanalysis.rs::section_j_u2_joint_independence` (cross-reference) |

## CM — Mainnet readiness

The CM class enforces that prism-btc handles every well-formed mainnet
input correctly. Mainnet's structural admission probability
(`α ≈ 2⁻⁷⁷`) makes a successful mining session computationally
intensive — that's intrinsic to PoW, not a prism-btc property. The
CM class proves prism-btc's *correctness* on mainnet inputs at any
compute budget; throughput is the operator's hardware concern.

The total receiver-side typed lens
([`MiningFailure::DidNotAdmit { observables, .. }`])
makes the CM-3 / CM-5 observatory checks possible: every ψ-pipeline
inference — admitting or not — folds into a
[`CampaignStats`](`crates/prism-btc/src/campaign.rs`) aggregate at
`O(1)` per attempt with no heap allocation. At a long mainnet session
this aggregate is the operator's typed window onto the search space.

| ID | Statement | Enforcement | Witness |
|---|---|---|---|
| **CM-1** | `Target::new(nBits)` accepts every mainnet-difficulty `nBits` value spanning Bitcoin's history (8 representative values, genesis-era through current epoch) without panic, overflow, or invalid output. | runtime test over the difficulty history | `tests/mainnet.rs::cm1_target_constructor_accepts_full_mainnet_difficulty_history` |
| **CM-2** | `mine_at` produces an admitting outcome whose κ-label is a 72-byte `sha256d:<64hex>` address (carrying the 32-byte SHA-256d display-order digest) for every well-formed mainnet-difficulty header, or `Err(DidNotAdmit{observables, digest, ..})` carrying the candidate's typed property landscape. `PipelineFailure` is **unreachable** — exercised over 8 difficulty values × 50 seeds = 400 attempts. The wire-format Bitcoin header is surfaced on the `Ok` arm as `outcome.wire_format_header: [u8; 80]` for the `submitblock` boundary. | runtime test | `tests/mainnet.rs::cm2_pipeline_inference_succeeds_at_every_mainnet_difficulty` |
| **CM-3** | At N=10⁴ inferences against the typed surface, the aggregate `CampaignStats` matches the PRF baseline: stratum histogram passes χ² goodness-of-fit against Geom(1/2) at α=0.001 (df=16, crit ≈ 39.25); spectrum histogram passes balanced-Bernoulli χ² at α=0.001 (df=1, crit ≈ 10.83). The receiver-side lens at session scale is consistent with U1 marginal-uniformity. | runtime test | `tests/mainnet.rs::cm3_aggregate_observatory_matches_prf_baseline_at_n_10000` |
| **CM-4** | `CampaignStats` is consistent under cooperative interruption: stopping at an arbitrary attempt count M and resuming produces an aggregate byte-identical to a single-shot N-attempt run. The session-level aggregate is path-independent. | runtime test | `tests/mainnet.rs::cm4_campaign_stats_consistent_under_cooperative_interruption` |
| **CM-5** | Empirical admission rate `CampaignStats::empirical_alpha()` converges to the target's theoretical α within ±5% at N=10⁴ (binomial SE ≈ 0.5%; this is ~10σ confident). The host's observed admission rate matches the model's declared α. | runtime test | `tests/mainnet.rs::cm5_empirical_alpha_converges_to_theoretical_at_n_10000` |
| **CM-6** | `CampaignStats` histogram dimensions match the public constants (`STRATUM_BINS`, `PADIC_BINS`) — the typed surface's declared shape is byte-identical to its runtime layout. | runtime test | `tests/mainnet.rs::cm6_campaign_stratum_bin_count_matches_declared_constant` |

## CN — Network-invariance

| ID | Statement | Witness |
|---|---|---|
| **CN-1** | Same `BitcoinAddressModel`, same verb arena, same shared `AddressResolverTuple` ψ-tower across regtest/signet/testnet/testnet4/mainnet `bits` values; only the target byte threshold (consumed by foundation's `LexicographicLessEqThreshold` predicate inside `TargetCommitment`) varies. | `tests/verification.rs::v_model_declarations_invariant_across_network_byte_thresholds` |
| **CN-2** | The host loop in `prism-btc-node::PrismMiner::mine_one_block` does not branch on the network beyond template rules (SegWit/Csv/Taproot/Signet) and the signet-challenge gate. | source inspection + `crates/prism-btc-node/src/lib.rs::mine_one_block` |
| **CN-3** | The wire-format header (`outcome.wire_format_header`) is byte-identical to what `submitblock` expects for any network with template-supplied parameters. | `tests/regtest.rs::mines_a_chain_of_blocks_without_fail` (10-block chain accepted byte-for-byte) |
| **CN-4** | On `Network::Signet` with non-empty `signet_challenge`, `mine_one_block` fail-closed rather than produce an unsigned (invalid) block. | `crates/prism-btc-node/src/lib.rs::mine_one_block` signet gate |

## CL — Lean-formal

| ID | Statement | Witness |
|---|---|---|
| **CL-1** | `Commitment.prf_prob_tight_wellFormed` is proven for every `c : Commitment` of arbitrary length under U1+U2 axioms. The theorem covers all Rust monomorphizations the foundation `TypedCommitment` catalog (ADR-048 + ADR-049) can produce. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` §2 |
| **CL-2** | `Commitment.acceptProb_append` (the multiplicative form of U6) is proven for arbitrary commitment concatenation. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` §1 |
| **CL-3** | The Lean `Predicate` carries `acceptProb : Rat`, faithfully covering each Rust `ObservablePredicate` variant — including `Stratum<P>` for primes p ≥ 3 whose log-space bandwidth is irrational. The Lean correspondence (rational-domain probabilities ↔ foundation's f64 surface) has moved upstream to foundation per wiki ADR-049's proposed `axis::cryptanalyze` test primitive. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` Predicate definition + foundation's `ObservablePredicate::accept_prob` |
| **CL-4** | `Support.disjoint` is symmetric; `wellFormed_empty` and `wellFormed_singleton` hold vacuously; `wellFormed.head_disjoint` and `wellFormed.tail` destructure `cons`. | `prism-btc-lean/PrismBtc/CommitmentChannel.lean` Support + Commitment.wellFormed |

## What conformance **does** and **does not** claim

**Claims (proven by the conformance suite):**

- **Mainnet cost-model conformance.** `BitcoinAddressModel` realizes
  wiki ADR-048's 5-position `PrismModel<H, B, A, R, C>` form with
  `C = TargetCommitment` (foundation alias for
  `SingletonCommitment<LexicographicLessEqThreshold>`, ADR-040 +
  ADR-049). Admission (`block_hash ≤ target`, both expressed in
  κ-label form, where equal-length lowercase-hex lexicographic order is
  big-endian integer order) is evaluated **inside foundation's
  `run_route` catamorphism** on the `sha256d:<64hex>` κ-label ψ_9 emits —
  not at a host-boundary gate sitting outside the typed surface. The
  cost-model contract `operational = declared at equality` therefore
  ranges over the full typed commitment surface (CS, CD, CP, CM).
- **Mainnet correctness** — prism-btc accepts every well-formed
  mainnet input and produces a well-formed 72-byte `sha256d` κ-label
  (plus the 80-byte wire-format header and 32-byte display-order digest
  for the `submitblock` path) or a typed `DidNotAdmit` observation;
  `PipelineFailure` is unreachable on legitimate inputs (CM-1, CM-2).
- **Aggregate observability at scale** — the typed receiver-side lens
  is total across every ψ-pipeline inference; the campaign aggregate
  matches PRF baseline at N=10⁴ and converges empirically to the
  target's theoretical α (CM-3, CM-4, CM-5).
- **Zero-cost runtime model** — every typed commitment is
  monomorphized; no `Vec`, no `dyn`, no allocation; per-template cost
  is `O(1)` in target.difficulty and commitment K (CS, CD, CP).
- **Cost-identity scaling** — `expected_trials = α⁻¹ × 2^K` holds at
  equality, validated across four decades of K and four decades of α
  at 4σ confidence (CP-1, CP-2, CP-3).
- **Composition is bandwidth-additive** — foundation's
  `AndCommitment<TargetCommitment, payload>` reports the sum of
  component bandwidths; `EmptyCommitment` is the identity (CP-4).
- **Network-invariance** — the same pipeline, the same model
  declarations, the same wire-format output across regtest / signet /
  testnet3 / testnet4 / mainnet (CN-1..4).

**Does not claim (intrinsic limits, not prism-btc properties):**

- **Compute feasibility** of high-difficulty mining. Mainnet
  `α ≈ 2⁻⁷⁷` implies ~2⁷⁷ template variations in expectation. The
  conformance suite validates that prism-btc's per-template cost is
  `O(1)` in target.difficulty (so total cost = α⁻¹ × per-template
  cost, no superlinear overhead). The operator's hardware budget is
  what bounds throughput.
- **Cryptographic security** of the σ-projection beyond what U1–U5
  empirical witnessing covers. The Lean theorem is conditional on
  U1+U2; per-variant calibration witnesses them (CP-5, CP-6). Proving
  SHA-256d is a PRF is an open cryptographic problem.
- **Operational invariants** outside prism-btc's surface — stale
  templates over long mining sessions, network reorganizations, RPC
  reliability. The host loop's behavior is bounded by `prism-btc-node`'s
  gates (signet gate, chain-mismatch guard, BIP141/BIP34 conformance);
  external operational concerns belong to the operator.
- **Identity of the σ-projection axis** — the conformance suite is
  stated against prism-btc's `Sha256dHasher`. The framework
  generalizes; substituting another UOR-hardened axis (Blake3,
  Keccak, post-quantum) re-instantiates the same conformance contract
  against the new hasher.

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
