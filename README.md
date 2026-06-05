# prism-btc

Bitcoin proof-of-work as a **UOR-ADDR realization** — a Prism
application of the [UOR Foundation](https://github.com/UOR-Foundation/UOR-Framework).
prism-btc content-addresses Bitcoin block headers through uor-addr's
shared addressing surface: a block header is the canonical-form input,
the `sha256d` σ-axis is the content-addressing primitive, and the κ-label
the ψ-pipeline emits — `sha256d:<64hex>` — is the conventional Bitcoin
block hash. No σ-enumeration in the verb body; mining is not an algorithm.

> **Normative architecture:** see [ARCHITECTURE.md](ARCHITECTURE.md). The
> repository is reconciled to it; ARCHITECTURE.md is the pure-prism
> specification.
>
> **Substrate:** [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki)
> (ADR-024 verb declarations, ADR-030 canonical hash axis, ADR-035
> ψ-chain Term variants + ψ-residuals discipline, ADR-036 shared
> `AddressResolverTuple`, ADR-037 `HostBounds`-parametric capacity
> ceilings, ADR-041 typed-coordinate resolver carriers, ADR-060 borrowed
> canonical-form carrier, ADR-061 composition framework). Foundation's SDK enforces the
> ψ-residuals discipline at proc-macro expansion: `<=` / `<` / `>=` /
> `>` / `concat(...)` / `first_admit(...)` / `hash(...)` are rejected
> in verb bodies with error messages naming `k_invariants(homotopy_groups(
> postnikov_tower(nerve(input))))` as the canonical compiled form.
> prism-btc's verb body is exactly that — the discipline is
> substrate-enforced.

## The architectural commitment

prism-btc implements the prism conceptual model without compromise. We
declare Bitcoin's typed primitives (`Version`, `PrevHash`, `MerkleRoot`,
`Timestamp`, `Bits`, `Nonce`, `Target`), serialize a block header to its
80-byte wire form (the ADR-060 canonical form), wrap it in a borrowed
`BlockHeaderCarrier`, and run the **shared** uor-addr ψ-tower's
k-invariant branch (`nerve → postnikov_tower → homotopy_groups →
k_invariants`) to mint the content-address κ-label.

What's *not* in prism-btc: σ-enumeration, FirstAdmit-shaped search,
hash-rate metrics, "CPU mining time" framing. Those are algorithmic
framings. prism declares relationships, folds the canonical-form carrier
through the shared ψ-tower, and generates κ-labels.

## The block-address transform

```rust
verb! {
    pub fn block_address_inference(input: BlockHeaderCarrier<'_>) -> BlockAddressLabel {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

The verb body lowers to the ψ-Term variants `Term::Nerve` (ψ_1) →
`Term::PostnikovTower` (ψ_7) → `Term::HomotopyGroups` (ψ_8) →
`Term::KInvariants` (ψ_9) — the **k-invariant branch** of the ψ-pipeline.
Foundation's catamorphism evaluates the chain end-to-end through uor-addr's
**shared, format-independent** `AddressResolverTuple` ψ-tower. Under
ADR-060, ψ₁–ψ₈ thread the borrowed header carrier through unchanged, and
the terminal ψ_9 folds the carrier through the `sha256d` σ-axis and emits
the `sha256d:<64hex>` κ-label — the conventional Bitcoin block hash in
display order. Canonicalization (wire serialization) happens at the host
boundary, not in a resolver. One σ-fold per `forward()` — deterministic
in the typed input, no enumeration. prism-btc carries no resolver code;
it binds the shared tower (architecture §4, §6).

## The block-address model

```rust
prism_model! {
    pub struct BitcoinAddressModel;
    pub struct BitcoinAddressRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        uor_addr::AddressResolverTuple<Sha256dHasher>,
        TargetCommitment                      // ← ADR-048 5th-position
    > for BitcoinAddressModel {
        type Input = BlockHeaderCarrier<'a>;
        type Output = BlockAddressLabel;
        type Route = BitcoinAddressRoute;
        fn route(input: Self::Input) -> Self::Output {
            block_address_inference(input)
        }
        fn commitment() -> TargetCommitment {
            target_commitment(current_thread_target())
        }
    }
}
```

`BitcoinAddressModel::forward(carrier: BlockHeaderCarrier) -> Result<Grounded<BlockAddressLabel>, _>`
is the canonical typed-iso surface (wiki ADR-020 + ADR-036 + ADR-048
5-position form). The 5th-position `C = TargetCommitment` is foundation's
alias for `SingletonCommitment<LexicographicLessEqThreshold>` (wiki
ADR-040 + ADR-049). **Bitcoin proof-of-work is realized as a typed
admission relation inside the typed-iso surface:** the catamorphism seals
a `Grounded<BlockAddressLabel>` only when `LexicographicLessEqThreshold`
holds on the κ-label, so the existence of the sealed value is
**constructive proof that Bitcoin's `block_hash ≤ target` admission
relation holds at the framework level** (the target is expressed in
κ-label form, and equal-length lowercase-hex lexicographic order is
big-endian integer order). There is no separate "verify admission" step —
admission is a premise of the type being constructed. The seal is the
certificate; ψ_9's output is the 72-byte `sha256d:<64hex>` κ-label.

## Workspace

| Crate | Role |
|---|---|
| [`prism-btc`](crates/prism-btc/) | The pure-prism domain layer. Declares Bitcoin's typed primitives, the `BlockHeaderCarrier` input + `BlockAddressLabel` output shapes, the ψ-chain verb, `BitcoinAddressModel` (binding the shared uor-addr ψ-tower), the ADR-061 `sha256d` composition reference impl, and the admission stack — `mine_at` (single recognition `W`), `NonceOrbit` (lazy `Iterator` enumeration of `W` over the 32-bit space), and `admit` (the Kleene-star closure `W*` as `NonceOrbit::find_map(Result::ok)`). Pure-Rust SHA-256 for the `sha256d` σ-axis. |
| [`prism-btc-node`](crates/prism-btc-node/) | bitcoind RPC boundary. `getblocktemplate → admission closure → submitblock`. The bridge composes `NonceOrbit` with `Iterator::inspect` (campaign side-effect) and `Iterator::find_map` (admission selector); no explicit nonce loops, extranonce roll on orbit exhaustion. `prism-mine` CLI binary. |
| [`prism-btc-wasm`](crates/prism-btc-wasm/) | `wasm-bindgen` JS surface around `prism_btc::admit` — the wasm `mine_block` is one call to the admission closure, no explicit loop. |
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape-constraint monotonicity, convergence protocol. |

## Substitution axes

| Axis | prism-btc selection |
|---|---|
| `HostTypes` | `DefaultHostTypes` (foundation default) |
| `HostBounds` | [`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) — a type alias for the shared [`uor_addr::AddrBounds`](crates/prism-btc/src/shapes/bounds.rs) profile. Under ADR-060 there are no fixed per-ψ-stage byte ceilings; the carrier is a source-polymorphic `TermValue`. |
| `Hasher` | [`Sha256dHasher`](crates/prism-btc/src/shapes/hasher.rs) — pure-Rust SHA-256-then-SHA-256, finalizing in Bitcoin display order. The `sha256d` σ-axis is a **content-addressing primitive**, not an algorithm prism-btc runs; it implements foundation `Hasher<32>` **and** `uor_addr::AddrHash`. |
| `ResolverTuple` | [`uor_addr::AddressResolverTuple<Sha256dHasher>`](crates/prism-btc/src/model.rs) — uor-addr's **shared, format-independent** ψ-tower (ADR-036). prism-btc owns no resolver code; under ADR-060 ψ₁–ψ₈ are pass-throughs and ψ₉ folds the carrier through `sha256d`. |

## Witness construction + bit-identicality (architecture §6)

`mine_at(header, target, nonce)` is the kernel's sole
admission-recognition entry — one inference at one nonce. It
serializes `(header, nonce)` to the 80-byte wire form, wraps it in a
`BlockHeaderCarrier`, and invokes `BitcoinAddressModel::forward(carrier)`.
**The catamorphism constructs a sealed `Grounded<BlockAddressLabel>` only
when admission holds** — the replayable TC-05 `AddressWitness` it carries
is the witness that Bitcoin's PoW admission relation held on this κ-label.
The `sha256d:<64hex>` κ-label ψ_9 emits is the conventional block hash;
the 80-byte wire-format header is surfaced on the success path as
`MiningOutcome.wire_format_header: [u8; 80]` (the canonical-form
companion to the witness, from which every other `MiningOutcome` field is
derivable by replaying the σ-axis — L5).

When the catamorphism does not seal, foundation reports
`PipelineFailure::ShapeViolation` with the
`commitment/TypedCommitment/VIOLATED` shape IRI and prism-btc
classifies that as
`Err(MiningFailure::DidNotAdmit { observables, nonce, digest })`.
**The kernel does not search.** The bridge layer (`prism-btc-node`,
`prism-btc-wasm`) varies its candidate stream — next nonce, next
extranonce → distinct merkle root → distinct κ-label — and
re-recognizes, folding each attempt's typed property landscape into a
`CampaignStats` aggregate.

**The receiver-side typed lens (`KappaObservables`) is total** —
present on `Ok(MiningOutcome)` and on `DidNotAdmit` alike. Every
ψ-pipeline inference exposes its candidate's UOR property landscape,
giving the host operator typed visibility into the search at session
granularity.

**Fail-closed by construction.** `mine_at` never returns an outcome
whose κ-label does not admit, because `MiningOutcome` can only be
constructed from a sealed `Grounded<BlockAddressLabel>`, and the seal is
contingent on the catamorphism's admission predicate. The typed-iso gate
is not a runtime check the implementation could forget; it is a premise
of the return type's existence.

prism-btc's transform is structural: the typed-iso surface maps
`BlockHeaderCarrier → 72-byte sha256d κ-label` deterministically via the
ψ-pipeline, and the catamorphism seals iff `TargetCommitment` admits.
There is no inner σ-enumeration in the verb body, no "hashrate" metric;
the bridge layer iterates candidates and the kernel recognizes each one.
The wire-format header (`outcome.wire_format_header`) is byte-for-byte
what Bitcoin Core's `submitblock` accepts because both reach the same
canonical serialization.

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

**Network-invariant.** Same `BitcoinAddressModel`, same ψ-pipeline verb
body, same shared `AddressResolverTuple` ψ-tower, same `sha256d` σ-axis,
same `TargetCommitment` shape across regtest, signet, testnet, testnet4,
and mainnet. The network-dependent value is the byte threshold from
the template's `Bits` field; that threshold pins the
`LexicographicLessEqThreshold::target` (in κ-label form) for the call.
From outside, `forward()` is **one structural inference per
`BlockHeaderCarrier`** at constant cost — the network-dependent quantity
is the number of nonce/template variations the host attempts, not the
cost per attempt.

## Algebraic-closure encoding

`BlockAddressLabel::CONSTRAINTS` declares 72 disjoint `ConstraintRef::Site`
instances — one per κ-label ASCII byte (`sha256d:<64hex>`). The constraint
nerve has 72 isolated vertices with no higher simplices; β_0 = 72, β_k = 0
for k ≥ 1, χ = SITE_COUNT = 72 — the UOR Index Theorem IT_7d
algebraic-closure criterion is satisfied at the declaration level
(architecture §2.3). The nonce is an explicit input field of the header
carrier, not a structurally-derived site. ψ_9 folds the borrowed carrier
through the `sha256d` σ-axis and emits the display-order κ-label;
convergence at the typed-iso surface is then handed to foundation's
`run_route` for the `TargetCommitment::evaluate` gate.

## Witness surface

Every admitting `forward()` yields a replayable TC-05
[`AddressWitness<72, 32>`](crates/prism-btc/src/pipeline.rs) (alias
`MiningWitness`) — it owns its derivation trace plus content fingerprint,
and `.verify()` re-certifies the κ-label without re-invoking the σ-axis.
This witness **is** the proof-of-work witness — the catamorphism's seal.
It is surfaced on the `Ok` path as `MiningOutcome.witness`.
`prism-btc-node`'s `MinedBlock` summary includes the winning nonce plus
the host-boundary `extranonce_attempts` counter for end-to-end
observability across the typed-iso surface + the template-variation loop.

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
sealed `TypedCommitment` catalog (wiki ADR-048 + ADR-049). `mine_at`
is the kernel's sole admission-recognition entry; admission is
evaluated inside foundation's `run_route` catamorphism via the
model's pinned `TargetCommitment`. For typed-bandwidth commitments
beyond bare
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

The block-address inference is identical across regtest, signet, testnet,
testnet4, and mainnet: same `BitcoinAddressModel`, same ψ-pipeline verb
body, same shared `AddressResolverTuple` ψ-tower. The network-dependent
value is the runtime byte threshold encoded in the template's `Bits` field.

**Safety airlocks:**
- **Chain-mismatch guard**: refuses to mine if `getblockchaininfo.chain`
  disagrees with the requested `--network`.
- **Mainnet opt-in**: `--network mainnet` requires `--i-know-what-im-doing`.

## License

Apache-2.0 — see [LICENSE](LICENSE).
