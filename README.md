# prism-btc

Bitcoin proof-of-work as **pure-prism structural inference** — a Prism
application of the [UOR Foundation](https://github.com/UOR-Foundation/UOR-Framework).
prism-btc declares Bitcoin's typed feature primitives, composes them
hierarchically via foundation's tensor algebras, and lets the ψ-pipeline
generate the wire-format-valid block bytes as the structural label.
No σ-enumeration in the verb body; mining is not an algorithm.

> **Normative architecture:** see [ARCHITECTURE.md](ARCHITECTURE.md). The
> repository is reconciled to it; ARCHITECTURE.md is the pure-prism
> specification.
>
> **Substrate:** [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki)
> (ADR-024 verb declarations, ADR-030 canonical hash axis, ADR-035
> ψ-chain Term variants + ψ-residuals discipline, ADR-036 `ResolverTuple`,
> ADR-037 `HostBounds`-parametric capacity ceilings, ADR-041
> typed-coordinate resolver carriers). Foundation's SDK enforces the
> ψ-residuals discipline at proc-macro expansion: `<=` / `<` / `>=` /
> `>` / `concat(...)` / `first_admit(...)` / `hash(...)` are rejected
> in verb bodies with error messages naming `k_invariants(homotopy_groups(
> postnikov_tower(nerve(input))))` as the canonical compiled form.
> prism-btc's verb body is exactly that — the discipline is
> substrate-enforced.

## The architectural commitment

prism-btc implements the prism conceptual model without compromise. We
declare Bitcoin's typed primitives (`Version`, `PrevHash`, `MerkleRoot`,
`Timestamp`, `Bits`, `Nonce`, `Target`), compose them hierarchically into
typed feature shapes (`TemplatePrefix`, `Header`, `MiningTask`,
`MiningResult`) via foundation's tensor algebras (`partition:PartitionProduct`,
`operad:OperadComposition`, `monoidal:MonoidalProduct`), and apply the
ψ-pipeline transform's k-invariant branch (`nerve → postnikov_tower →
homotopy_groups → k_invariants`) to derive the structural label.

What's *not* in prism-btc: σ-enumeration, FirstAdmit-shaped search,
hash-rate metrics, "CPU mining time" framing. Those are algorithmic
framings. prism declares relationships, applies parametric tensor-algebra
functors, and generates labels.

## The mining transform

```rust
verb! {
    pub fn mining_inference(input: MiningTask) -> MiningResult {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

The verb body lowers to the ψ-Term variants `Term::Nerve` (ψ_1) →
`Term::PostnikovTower` (ψ_7) → `Term::HomotopyGroups` (ψ_8) →
`Term::KInvariants` (ψ_9) — the **k-invariant branch** of the ψ-pipeline.
Foundation's catamorphism evaluates the chain end-to-end, dispatching
each ψ-stage through prism-btc's `BitcoinResolverTuple`. The terminal
ψ_9 resolver performs the **structural κ-derivation**: it projects the
typed `MiningTask` to a 32-byte content-address via the canonical hash
axis and pins the four nonce-byte sites (positions 76..80) to the
leading four bytes in canonical Bitcoin little-endian. One σ-projection
per `forward()` — deterministic in the typed input, no enumeration.
The emitted 80 bytes ARE the wire-format Bitcoin header by construction
(architecture §4, §6).

## The mining model

```rust
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        TargetCommitment                      // ← ADR-048 5th-position
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
        fn commitment() -> TargetCommitment {
            target_commitment(current_thread_target())
        }
    }
}
```

`BitcoinMiningModel::forward(task: MiningTask) -> Result<Grounded<MiningResult>, _>`
is the canonical typed-iso surface (wiki ADR-020 + ADR-036 + ADR-048
5-position form, foundation 0.4.12). The 5th-position
`C = TargetCommitment` is foundation's alias for
`SingletonCommitment<LexicographicLessEqThreshold>` (wiki ADR-040 +
ADR-049). **Bitcoin proof-of-work is realized as a typed admission
relation inside the typed-iso surface:** the catamorphism seals a
`Grounded<MiningResult>` only when `LexicographicLessEqThreshold`
holds on the κ-label, so the existence of the sealed value is
**constructive proof that Bitcoin's `digest ≤ target` admission
relation holds at the framework level.** There is no separate
"verify admission" step — admission is a premise of the type being
constructed. The seal is the certificate; its `output_bytes()` carry
the 32-byte SHA-256d κ-label.

## Workspace

| Crate | Role |
|---|---|
| [`prism-btc`](crates/prism-btc/) | The pure-prism domain layer. Declares Bitcoin's typed feature hierarchy, the ψ-chain verb, `BitcoinMiningModel`, `BitcoinResolverTuple`, and the public `mine()` entry point. Pure-Rust SHA-256 for the canonical hash axis. |
| [`prism-btc-node`](crates/prism-btc-node/) | bitcoind RPC boundary. `getblocktemplate → BitcoinMiningModel::forward → submitblock`. `prism-mine` CLI binary. |
| [`prism-btc-wasm`](crates/prism-btc-wasm/) | `wasm-bindgen` JS surface around `prism_btc::mine`. |
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape-constraint monotonicity, convergence protocol. |

## Substitution axes

| Axis | prism-btc selection |
|---|---|
| `HostTypes` | `DefaultHostTypes` (foundation default) |
| `HostBounds` | [`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) — `WITT_LEVEL_MAX_BITS = 32`, `FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64`, `NERVE_SITES_MAX = 80`, `NERVE_CONSTRAINTS_MAX = 128`, `BETTI_DIMENSION_MAX = 80` |
| `Hasher` | [`Sha256dHasher`](crates/prism-btc/src/shapes/hasher.rs) — pure-Rust SHA-256-then-SHA-256. The canonical hash axis is a **content-addressing primitive**, not an algorithm prism-btc runs. |
| `ResolverTuple` | [`BitcoinResolverTuple`](crates/prism-btc/src/resolvers.rs) — Bitcoin-specific realization of the eight resolver-bound ψ-stages (ψ_1, ψ_2, ψ_3, ψ_5, ψ_6, ψ_7, ψ_8, ψ_9; ψ_4 Betti is resolver-free). |

## Witness construction + bit-identicality (architecture §6)

`mine(header, target)` is the canonical entry. Internally it
publishes the target on the thread-local commitment slot and invokes
`BitcoinMiningModel::forward(task)`. **The catamorphism constructs a
sealed `Grounded<MiningResult>` only when admission holds** — the
seal itself is the witness that Bitcoin's PoW admission relation
held on this κ-label. There is no host-boundary recomputation of the
σ-projection. Foundation's `Grounded<MiningResult>` carries the
32-byte SHA-256d κ-label as `output_bytes()`; the 80-byte wire-format
Bitcoin header is reconstructed for `submitblock` at the prism-btc
boundary and surfaced on the success path as
`MiningOutcome.wire_format_header: [u8; 80]`.

When the catamorphism does not seal, foundation reports
`PipelineFailure::ShapeViolation` with the
`commitment/TypedCommitment/VIOLATED` shape IRI and prism-btc
classifies that as
`Err(MiningFailure::DidNotAdmit { observables, nonce, digest })`. The
host boundary varies the template (extranonce roll → distinct
`MiningTask` → distinct κ-derivation) and retries, folding each
attempt's typed property landscape into a `CampaignStats` aggregate.

**The receiver-side typed lens (`KappaObservables`) is total** —
present on `Ok(MiningOutcome)` and on `DidNotAdmit` alike. Every
ψ-pipeline inference exposes its candidate's UOR property landscape,
giving the host operator typed visibility into the search at session
granularity.

**Fail-closed by construction.** `mine()` never returns an outcome
whose κ-label does not admit, because the type `MiningOutcome`
itself can only be constructed from a sealed `Grounded<MiningResult>`,
and the seal is contingent on the catamorphism's admission predicate.
The typed-iso gate is not a runtime check the implementation could
forget; it is a premise of the return type's existence.

prism-btc's transform is structural: the typed-iso surface maps
`MiningTask → 32-byte κ-label` deterministically via the ψ-pipeline,
and the catamorphism seals iff `TargetCommitment` admits. There is
no inner search loop, no nonce enumeration, no "hashrate" metric.
The reconstructed wire-format header (`outcome.wire_format_header`)
is byte-for-byte what Bitcoin Core's `submitblock` accepts because
both reach the same canonical serialization.

**Cost-model = proof-of-work, by construction.** The Lean theorem
`Commitment.prf_prob_tight_wellFormed` (wiki ADR-047 U6) says
expected mining trials equal `α⁻¹ × 2^bandwidth_bits` at equality,
where bandwidth is `TargetCommitment::bandwidth_bits() ≈ -log₂(target_accept_prob)`.
At mainnet difficulty this is ≈ 77 bits — the same number as
"expected mining attempts at mainnet difficulty," not coincidentally
but because they are the same statement. Cost-model conformance and
Bitcoin proof-of-work are the same theorem; the framework operationalizes
it. The result generalizes: substituting any UOR-hardened σ-projection
axis (Blake3, Keccak, post-quantum) preserves the framework-level
admission proof — Bitcoin is the realization-witness that the cost
model holds at a deployed PoW protocol at mainnet difficulty.

**Network-invariant.** Same `BitcoinMiningModel`, same ψ-pipeline verb
body, same `BitcoinResolverTuple`, same κ-derivation, same
`TargetCommitment` shape across regtest, signet, testnet, testnet4,
and mainnet. The network-dependent value is the byte threshold from
the template's `Bits` field; that threshold pins the
`LexicographicLessEqThreshold::target` for the call. From outside,
`forward()` is **one structural inference per `MiningTask`** at
constant cost — the network-dependent quantity is the number of
template variations the host attempts, not the cost per attempt.

## Algebraic-closure encoding

`MiningResult::CONSTRAINTS` declares 32 disjoint `ConstraintRef::Site`
instances — one per κ-label digest byte. The constraint nerve has 32
isolated vertices with no higher simplices; β_0 = 32, β_k = 0 for
k ≥ 1, χ = SITE_COUNT = 32 — the UOR Index Theorem IT_7d
algebraic-closure criterion is satisfied at the declaration level
(architecture §2.3). All 32 sites are **κ-pinned by ψ_9
simultaneously**: ψ_9 structurally κ-derives the 4-byte nonce from
the typed `MiningTask` via the canonical hash axis, reconstructs the
80-byte wire-format Bitcoin header from `(template_prefix,
derived_nonce)`, and emits `SHA-256d(wire_format_header)` as the
32-byte κ-label. `FreeRank` drops from 32 to 0 in this single
terminal stage; convergence at the typed-iso surface is then handed
to foundation's `run_route` for the `TargetCommitment::evaluate` gate.

## Diagnostic surface

ψ_9 records a [`ResolutionState`](crates/prism-btc/src/diagnostics.rs)
for every `forward()` call — `free_rank` (always 0 at the terminal
ψ-stage's convergence) plus `derived_nonce` (the κ-derivation that
pinned the four nonce-byte sites). Available via
`MiningOutcome.resolution` (the `Ok` path) and the public
`take_resolution_state()` function (the `Err` path and direct
`forward()` callers). `prism-btc-node`'s `MinedBlock` summary
includes the resolution state plus the host-boundary
`extranonce_attempts` counter for end-to-end observability across
the typed-iso surface + the template-variation loop.

## Quick start

```bash
cargo install just

just build      # cargo build --workspace
just test       # cargo test --workspace
just lint       # cargo clippy --workspace -- -D warnings
just fmt-check  # cargo fmt --check

# Formal proofs (requires elan / Lean 4)
just verify

# Complete V&V suite (see VERIFICATION.md)
just vv

# WebAssembly
just build-wasm

# End-to-end regtest exercise
just regtest-demo
```

## Verification & Validation

See [VERIFICATION.md](VERIFICATION.md) for the complete V&V suite —
architectural conformance, fail-closed mining contract, wire-format
equivalence, ψ-pipeline determinism, Lean proofs, and regtest
end-to-end. `just vv` reproduces it.

## Analyses

[ANALYSIS.md](ANALYSIS.md) — **UOR-and-prism-informed
cryptanalysis of SHA-256d**. UOR as ultrametric framework; Prism
as causal-semantic transport field on a content-addressed
semantic manifold. Two empirical chapters:

- **§3 Cryptanalysis battery (8 tests at 10⁷ samples).** Triadic
  coordinates, ultrametric avalanche, Walsh–Hadamard spectrum at
  32 non-trivial frequencies, stratum / κ-derivation autocorrelation,
  generalized p-adic stratification for `p ∈ {3, 5, 7}`, pairwise
  admission independence, differential cryptanalysis at six
  Δ-weights — all pass α=0.001. Reproducible via
  `cargo run --release --example uor_cryptanalysis`.
- **§5 Conjunction as typed information channel.** Empirical K-sweep
  shows substrate `type:Conjunction` is a Shannon channel: K
  independent typed predicates encode K bits of structural
  commitment in the κ-label at PRF-bounded `2^K` cost. Reproducible
  via `cargo run --release --example bandwidth_scaling`.

§4 + §5 extrapolate to framework contributions: a six-condition
**σ-Projection Hardening Principle** (U1 marginal-uniformity, U2
joint-independence, U3 admission-orthogonality, U4 avalanche, U5
autocorrelation-flatness, **U6 bandwidth-additivity**), a proposed
**UOR Cryptanalysis Battery** as a substrate primitive, a bridge to
traditional cryptanalysis, and ADR-style framework proposals.

[ARCHITECTURE.md §14](ARCHITECTURE.md) — **UOR-optimal mining**.
The cryptanalysis identifies the Pareto frontier
`cost(B) = 2^B × α^-1`; prism-btc realizes it via foundation's
sealed `TypedCommitment` catalog (wiki ADR-048 + ADR-049). `mine()`
is the only public mining entry; admission is evaluated inside
foundation's `run_route` catamorphism via the model's pinned
`TargetCommitment`. For typed-bandwidth commitments beyond bare
admission, applications compose `AndCommitment<TargetCommitment,
payload>` using prism-btc's `payload_commitment_k2 / k4 / k8`
helpers (each producing an `AndCommitment` tree of
`SingletonCommitment<AffineParity>` leaves per wiki QS-06's K-fold
exemplar) and declare a derived `PrismModel<…, C>` with that
composed shape in the 5th slot. Every commitment is `Copy + Sealed`,
monomorphized per use site — no `Vec`, no dynamic dispatch, no
runtime allocation, no runtime disjointness check. `wellFormed` is
discharged at the type level by foundation's catalog seal; the Lean
theorem `Commitment.prf_prob_tight_wellFormed` applies at equality
across every Rust monomorphization the catalog produces. The
receiver-side typed lens is `KappaObservables` — **total**, carried
on every `MiningOutcome` and every `MiningFailure::DidNotAdmit` —
and `ExtendedObservables<N_PAR, N_REF>` for application-specific
parities and reference points. Session-level aggregation lives in
`CampaignStats` (zero-allocation histograms folded across every
attempt) — the operator's typed window onto the search at mainnet
scale.

## Real-network mining (`prism-btc-node`)

```bash
prism-mine \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user RPCUSER --rpc-pass RPCPASS \
  --network testnet4 \
  --payout TB1Q... \
  --blocks 1
```

The mining inference is identical across regtest, signet, testnet,
testnet4, and mainnet: same `BitcoinMiningModel`, same ψ-pipeline verb
body, same `BitcoinResolverTuple`. The network-dependent value is the
runtime byte threshold encoded in the template's `Bits` field.

**Safety airlocks:**
- **Chain-mismatch guard**: refuses to mine if `getblockchaininfo.chain`
  disagrees with the requested `--network`.
- **Mainnet opt-in**: `--network mainnet` requires `--i-know-what-im-doing`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
