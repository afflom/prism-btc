# prism-btc

Bitcoin proof-of-work as **real-time structural inference** — a Prism
application of the [UOR Foundation](https://github.com/UOR-Foundation/UOR-Framework).
prism-btc is the prism implementor for the Bitcoin use case: it
provides the runtime that walks the foundation-typed structure
declared via `ConstrainedTypeShape` + `Term::Application` compositions,
finds the admitting fiber point in the W32 nonce ring, and produces a
foundation-sealed `Grounded<ConstrainedTypeInput, MiningTag>` whose
wire bytes are accepted byte-for-byte by Bitcoin Core.

> **Defined architecture:** see [ARCHITECTURE.md](ARCHITECTURE.md).
> The repository state is reconciled to that document; ARCHITECTURE.md
> is normative.
>
> **Frame of reference:** the
> [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki),
> which is itself the normative specification of Prism.

## The claim

Traditional Bitcoin miners blackbox-import SHA-256, iterate a `u32`,
compare bytes to a threshold, and emit a block. Their process is
invisible to the type system and untraced.

prism-btc is the converse: **bit-identical output to a traditional
miner, derived through Prism's vocabulary alone.** No `sha2` import,
no `rayon`, no opaque crate imports, no implementor-side W32 search
loop. SHA-256d is a pure-Rust foundation `Hasher` impl
([`Sha256dHasher`](crates/prism-btc/src/shapes/hasher.rs)) promoted
to a 1-tuple `AxisTuple` via foundation's blanket impl (ADR-030); the
W32 search is the
[`nonce_fiber_traversal` verb](crates/prism-btc/src/verbs.rs)'s
`first_admit` body, evaluated end-to-end by foundation 0.4.1's
`Term::FirstAdmit` catamorphism (ADR-034 Mechanism 2).

The mining inference is one `BitcoinMiningModel::forward` call on
foundation 0.4.1
([`BitcoinMiningModel`](crates/prism-btc/src/model.rs)):

- `Input  = MiningTask` — `partition_product` of `TemplatePrefixShape`
  (76 bytes) and `TargetShape` (32 bytes), with field access
  (`input.prefix`, `input.target`) per ADR-033 G20.
- `Output = MiningResult` — the 6-byte `(disc, idx_bytes)` coproduct
  foundation's `Term::FirstAdmit` returns for a W32 domain.
- Route: `nonce_fiber_traversal(input)`, with body
  `first_admit(witt_domain::W32, |nonce| hash(concat(input.prefix, nonce)) <= input.target)`.
- Application axis: `Sha256dHasher` (canonical hash axis at
  `(axis: 0, kernel: 0)` per ADR-030).

## Workspace

| Crate | Role |
|---|---|
| [`prism-btc`](crates/prism-btc/) | The prism implementor. Declares `BitcoinMiningModel` + `nonce_fiber_traversal` verb. Public `mine()` entry point composes a `MiningTask`, calls `forward`, parses the FirstAdmit coproduct. Pure-Rust SHA-256/SHA-256d for `Sha256dHasher`. **No external crypto dep, no search loop.** |
| [`prism-btc-node`](crates/prism-btc-node/) | Bitcoin Core RPC boundary. `getblocktemplate` → `prism_btc::mine` → `submitblock`. `PrismMiner::mine_one_block` is the single API; `prism-mine` CLI binary. |
| [`prism-btc-wasm`](crates/prism-btc-wasm/) | `wasm-bindgen` JS surface around `prism_btc::mine`. |
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coords, FreeRank protocol, shape constraint monotonicity. |

## The substrate-vs-implementor split (ADR-024 + ADR-026 G16)

**`uor-foundation` (0.4.1)** provides: sealed types, `PrimitiveOp`
enum (15 generators), `Term` variants (including `AxisInvocation`,
`FirstAdmit`), the `AxisTuple` / `Hasher` / `HostBounds` /
`HostTypes` substitution-axis traits, the `mint_*` primitives, the
`Trace` / `TraceEvent` structures, `enforcement::replay::certify_from_trace`,
and the catamorphism `pipeline::evaluate_term_tree` whose
`Term::FirstAdmit` fold-rule (ADR-034 M2) drives the W32 search
end-to-end.

**`prism-btc`** declares: the
[`Sha256dHasher`](crates/prism-btc/src/shapes/hasher.rs) (the
application's `Hasher` substitution-axis selection),
[`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) (the
`HostBounds` selection), the
[`nonce_fiber_traversal` verb](crates/prism-btc/src/verbs.rs) (the
mining inference's structural form), the
[`BitcoinMiningModel`](crates/prism-btc/src/model.rs) (`PrismModel`
declaration whose route invokes the verb), and the public
[`mine()`](crates/prism-btc/src/pipeline.rs) entry point that builds
the `MiningTask` and parses the `MiningResult` coproduct. Plus
host-side wire helpers: pure-Rust SHA-256d, header serialization,
merkle-root reduction.

## Public API

```rust
use prism_btc::{
    mine, block_hash_grounded,
    BitcoinMiningModel, MiningTask, MiningResult,
    BlockHeader, MerkleRoot, Target, Bits, Timestamp, Version,
    MiningOutcome, MiningFailure, MiningWitness,
    Sha256dHasher, PrismBtcBounds,
};

let header = BlockHeader {
    version: Version(1),
    prev_hash: [0u8; 32],
    merkle_root: MerkleRoot::from_bytes([
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2,
        0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
        0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
    ]),
    timestamp: Timestamp(1231006505),
    bits: Bits(0x1d00ffff),
};

// Foundation 0.4.1's catamorphism evaluates the verb's term arena
// end-to-end via Term::FirstAdmit (ADR-034 M2): iterate `nonce`
// ascending, evaluate `hash(concat(prefix, nonce)) <= target` per
// fiber visit, short-circuit on first admission.
let outcome = mine(&header, Target::new(0x207fffff))
    .expect("easy target must admit");

assert_eq!(outcome.witness.witt_level_bits(), 32);
assert!(Target::new(0x207fffff).is_satisfied_by_bytes(&outcome.digest));
```

The `MiningOutcome` carries the foundation-sealed `MiningWitness =
Grounded<MiningResult, MiningTag>`, whose `output_bytes()` carries
the 6-byte `(disc, idx_bytes)` coproduct from foundation's
`Term::FirstAdmit`. `outcome.nonce` is the admitting u32 extracted
from the coproduct; `outcome.digest` is the block hash in display
order; `outcome.coords` is the digest's `TriadicCoords` (datum +
2-adic stratum + Walsh–Hadamard parity).

## Real-network mining (`prism-btc-node`)

The `prism-mine` CLI drives `prism_btc::mine` against any running
bitcoind. Each invocation fetches one template, runs one
`forward()`, submits one block.

```bash
just regtest-demo   # mines 10 blocks against a local bitcoind
```

```bash
prism-mine \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user RPCUSER --rpc-pass RPCPASS \
  --network testnet4 \
  --payout TB1Q... \
  --blocks 1
```

**Safety airlocks:**
- **Chain-mismatch guard**: refuses to mine if `getblockchaininfo.chain` disagrees with the requested `--network`.
- **Mainnet opt-in**: `--network mainnet` requires `--i-know-what-im-doing`.

## Foundation `Hasher` and `HostBounds`

`Sha256dHasher` is the foundation `Hasher` substitution-axis selection
for prism-btc. Per ADR-010 it is deterministic, fixed-width (32 bytes),
and idempotent. The body is pure-Rust SHA-256 (FIPS-180-4) applied
twice; no external crypto dependency.

`PrismBtcBounds` is the foundation `HostBounds` selection:

| Constant | Value |
|---|---|
| `FINGERPRINT_MIN_BYTES` | `32` |
| `FINGERPRINT_MAX_BYTES` | `32` |
| `TRACE_MAX_EVENTS` | `64` |
| `WITT_LEVEL_MAX_BITS` | `32` |

The `TRACE_MAX_EVENTS = 64` ceiling is the architectural commitment
that the trace records one event per stage transition, not one per
W32 fiber visit.

## Quick start

```bash
cargo install just

just build      # cargo build --workspace
just test       # cargo test --workspace
just lint       # cargo clippy --workspace -- -D warnings
just fmt-check  # cargo fmt --check

# Formal proofs (requires elan / Lean 4)
just verify     # lake update && lake build

# WebAssembly
just build-wasm

# End-to-end regtest demo
just regtest-demo
```

## WebAssembly

```bash
just build-wasm   # wasm-pack build → pkg/prism-btc-wasm/
```

```js
import init, { JsBlockHeader, mine_block } from './prism_btc_wasm.js';
await init();

const header = new JsBlockHeader(version, prevHashBytes, merkleBytes, timestamp, bits);
const result = mine_block(header, 0x1d00ffff);
console.log(result.stratum, result.spectrum, result.hash());
```

The wasm `mine_block` calls `prism_btc::mine` directly. The 2-adic
stratum and the Walsh-Hadamard parity spectrum are returned alongside
the digest.

## License

Apache-2.0 — see [LICENSE](LICENSE).
