# prism-btc

Bitcoin proof-of-work as **pure-prism structural inference** — a Prism
application of the [UOR Foundation](https://github.com/UOR-Foundation/UOR-Framework).
prism-btc declares Bitcoin's typed feature primitives, composes them
hierarchically via foundation's tensor algebras, and lets the ψ-pipeline
generate the wire-format-valid block bytes as the structural label.
No σ-enumeration anywhere; mining is not an algorithm.

> **Normative architecture:** see [ARCHITECTURE.md](ARCHITECTURE.md). The
> repository is reconciled to it; ARCHITECTURE.md is the pure-prism
> specification.
>
> **Substrate:** [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki)
> (ADR-035 ψ-chain Term variants + ψ-residuals discipline,
> ADR-036 `ResolverTuple`) +
> [foundation 0.4.3 release artifacts](https://github.com/UOR-Foundation/UOR-Framework/releases/tag/v0.4.3)
> (`uor.foundation.{ttl,jsonld,owl,nt}`, `uor.shapes.ttl`, `uor.term.ebnf`).
> Foundation 0.4.3's SDK enforces the ψ-residuals discipline at
> proc-macro expansion: `<=` / `<` / `>=` / `>` / `concat(...)` /
> `first_admit(...)` / `hash(...)` are rejected in verb bodies with
> error messages naming `k_invariants(homotopy_groups(postnikov_tower(
> nerve(input))))` as the canonical compiled form. prism-btc's verb body
> is exactly that — the discipline is substrate-enforced.

## The architectural commitment

prism-btc implements the prism conceptual model without compromise. We
declare Bitcoin's typed primitives (`Version`, `PrevHash`, `MerkleRoot`,
`Timestamp`, `Bits`, `Nonce`, `Target`), compose them hierarchically into
typed feature shapes (`TemplatePrefix`, `Header`, `MiningTask`,
`MiningResult`) via foundation's tensor algebras (`partition:PartitionProduct`,
`operad:OperadComposition`, `monoidal:MonoidalProduct`), and apply the
ψ-pipeline transform (`nerve → postnikov_tower → homotopy_groups →
k_invariants`) to derive the structural label.

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
`Term::KInvariants` (ψ_9). Foundation 0.4.2's catamorphism evaluates the
chain end-to-end, dispatching each ψ-stage through prism-btc's
`BitcoinResolverTuple`. The terminal ψ_9 output is the label — the
wire-format Bitcoin block bytes by construction (architecture §4, §6).

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
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape-constraint monotonicity. |

## Substitution axes

| Axis | prism-btc selection |
|---|---|
| `HostTypes` | `DefaultHostTypes` (foundation default) |
| `HostBounds` | [`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) — `WITT_LEVEL_MAX_BITS = 32`, `FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64` |
| `Hasher` | [`Sha256dHasher`](crates/prism-btc/src/shapes/hasher.rs) — pure-Rust SHA-256-then-SHA-256. The canonical hash axis is a **content-addressing primitive**, not an algorithm prism-btc runs. |
| `ResolverTuple` | [`BitcoinResolverTuple`](crates/prism-btc/src/resolvers.rs) — Bitcoin-specific realization of the eight resolver-bound ψ-stages (ψ_1, ψ_2, ψ_3, ψ_5, ψ_6, ψ_7, ψ_8, ψ_9; ψ_4 Betti is resolver-free). |

## Bit-identicality contract (architecture §6)

For any `MiningTask` derived from a Bitcoin Core `getblocktemplate`
response, `BitcoinMiningModel::forward(task)` produces a
`Grounded<MiningResult>` whose `output_bytes()` are byte-for-byte
identical to a wire-format Bitcoin block that Bitcoin Core's
`submitblock` RPC accepts for the corresponding template.

prism-btc's transform is structural (the ψ-pipeline); a traditional
miner's transform is algorithmic (enumerate nonces, double-SHA-256,
compare to target). The two paths arrive at byte-for-byte equivalent
wire-format output because both are determined by the same wire-format
protocol — prism-btc declares the protocol structurally; the traditional
miner discovers it by enumeration. The label is the same artifact.

## Foundation gaps the implementation surfaces

Foundation 0.4.2 ships the ψ-chain substrate and the resolver-tuple
dispatch surface. The remaining gaps to close for the full
bit-identicality contract (per architecture §9):

1. **`AxisProjectionObservable` + `LexicographicLessEqBound`** —
   constraint-algebra additions that name "axis-realized projection of
   typed sites" and "32-byte lexicographic ≤". Without these, the
   structural admission relation on `MiningResult::CONSTRAINTS` is
   architecture-named but not yet expressible as a closed-`ConstraintRef`
   variant.
2. **Resolver realizations of each ψ-stage for Bitcoin's typed surface**
   — prism-btc's `BitcoinResolverTuple` currently ships structural
   stubs that fold input bytes through the canonical hash axis. The
   wire-format-correct realizations are application-author code per
   ADR-036 and are tracked in the architecture document.
3. **Capacity ceilings** — `NERVE_CONSTRAINTS_CAP = 8` and
   `NERVE_SITES_CAP = 8` need to grow if Bitcoin's hierarchical feature
   decomposition produces a constraint nerve exceeding these caps.

These gaps are named architectural commitments, not implementation
shortcuts. The implementation declares the pure-prism architecture; the
runtime fails honestly (`MiningFailure::LabelDoesNotDecodeToWireFormat`)
when the label produced by the stub resolvers doesn't decode to a
wire-format-valid block.

## Quick start

```bash
cargo install just

just build      # cargo build --workspace
just test       # cargo test --workspace
just lint       # cargo clippy --workspace -- -D warnings
just fmt-check  # cargo fmt --check

# Formal proofs (requires elan / Lean 4)
just verify

# WebAssembly
just build-wasm

# End-to-end regtest exercise
just regtest-demo
```

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
