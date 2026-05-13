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
ψ_9 resolver implements the wiki's iterative-resolution discipline
(`iterative-resolution.md`): walks the W32 nonce ring until the
structural admission relation lands, pins the four nonce-byte sites,
and emits the κ-label — 80 bytes that ARE the wire-format Bitcoin
header by construction (architecture §4, §6).

## The mining model

```rust
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
    }
}
```

`BitcoinMiningModel::forward(task: MiningTask) -> Result<Grounded<MiningResult>, _>`
is the canonical typed-iso surface (ADR-020 + ADR-036 4-position form).
The `Grounded<MiningResult>` is the foundation-sealed certificate that
the typed inference admits; its `output_bytes()` carry the label.

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

## Bit-identicality + fail-closed contract (architecture §6)

`BitcoinMiningModel::forward(task)` returns a `Grounded<MiningResult>`
whose `output_bytes()` are exactly 80 bytes — the wire-format Bitcoin
header. The host-boundary entry point `mine(header, target)` only
returns `Ok(MiningOutcome)` when the κ-derived header's SHA-256d digest
genuinely satisfies the host-supplied `target` — the ψ_9 resolver's
convergence guarantee. The W32 ring walked to exhaustion without
admission surfaces as `Err(MiningFailure::PipelineFailure)`, carrying
the canonical `proof:InhabitanceImpossibilityWitness`; the host boundary
varies the template (extranonce roll → distinct `MiningTask` → fresh
W32 ring) and retries.

**Valid input either produces a valid mined-block header or surfaces an
`InhabitanceImpossibilityWitness` for the host to handle.** `mine()`
never returns a non-admitting outcome dressed as success.

prism-btc's transform is structural (the ψ-pipeline + the resolver's
iterative-resolution loop); a traditional miner's transform is
algorithmic (enumerate nonces, double-SHA-256, compare to target). The
two paths arrive at byte-for-byte equivalent wire-format output because
both are determined by the same wire-format protocol — prism-btc
declares the protocol structurally; the traditional miner discovers it
by enumeration. The label is the same artifact.

**Network-invariant.** Same `BitcoinMiningModel`, same ψ-pipeline verb
body, same `BitcoinResolverTuple` across regtest, signet, testnet,
testnet4, and mainnet. The network-dependent value is the runtime byte
threshold from the template's `Bits` field; the host boundary
(`prism-btc-node`) iterates over template-derived `MiningTask`
variations (extranonce roll) when the ψ-pipeline returns the
`InhabitanceImpossibilityWitness`. From outside, `forward()` is **one
structural inference per `MiningTask`**.

## Algebraic-closure encoding

`MiningResult::CONSTRAINTS` declares 80 disjoint `ConstraintRef::Site`
instances — one per wire-format-header byte. The constraint nerve has
80 isolated vertices with no higher simplices; β_0 = 80, β_k = 0 for
k ≥ 1, χ = 80 = SITE_COUNT — the UOR Index Theorem IT_7d
algebraic-closure criterion is satisfied at the declaration level
(architecture §2.3). Sites 0..76 are template-pinned (host-supplied
prefix bytes); sites 76..80 are κ-pinned (ψ_9 resolver's W32 walk
materializes the admitting nonce bytes). Both mechanisms terminate at
the same fixed point: 80 sites pinned ⇒ `FreeRank = 0` ⇒ convergence.

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
