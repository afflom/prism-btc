# prism-btc — pure-prism architecture

> **Architectural commitment.** prism-btc implements the prism conceptual
> model without compromise. We do not define mining as an algorithm; we
> declare Bitcoin's typed primitives, observe the structural relationships
> between them, and let foundation's catalog of parametric tensor algebras
> generate the label. There is no σ-enumeration, no FirstAdmit-shaped
> search, no traditional-miner complexity model. Where foundation's
> primitive catalog cannot yet express what we need, we name the gap and
> file it upstream — never substitute a non-prism implementation.

> **Normative references.**
> [UOR-Foundation/UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki),
> ADR-035 (ψ-chain Term variants + ψ-residuals discipline), ADR-036
> (ResolverTuple substitution-axis), and the canonical foundation
> ontology artifacts shipped at
> [v0.4.3 release assets](https://github.com/UOR-Foundation/UOR-Framework/releases/tag/v0.4.3)
> (`uor.foundation.{ttl,jsonld,owl,nt}`, `uor.shapes.ttl`, `uor.term.ebnf`).

---

## 1. The Prism conceptual model applied to Bitcoin

prism declares the universal vocabulary for typed structural inference:

- **Typed primitives** — `ConstrainedTypeShape` instances. Each is a finite
  algebraic surface with constraints declared as structural relations over
  its sites. Foundation's closed catalog of `ConstraintRef` variants
  (`Residue`, `Hamming`, `Depth`, `Carry`, `Site`, `Affine`, `SatClauses`,
  `Bound { observable, bound_shape, args }`, `Conjunction`) names the
  expressible relations.
- **Hierarchical composition** — primitives compose via foundation's tensor
  algebras: `partition:PartitionProduct` (sequenced sub-shapes),
  `partition:PartitionCoproduct` (alternative sub-shapes),
  `partition:CartesianPartitionProduct` (cartesian product of typed sites),
  `operad:OperadComposition` (outer-applied-to-inner nesting governed by
  `operad:StructuralOperad`'s eight structural-type composition rules), and
  `monoidal:MonoidalProduct` (`A ⊗ B`, the sequential composition of
  computations with `MonoidalUnit` and `MonoidalAssociator` witnesses).
- **ψ-pipeline transform** — the categorical functor chain
  ψ_1…ψ_9: `Constraints → Nerve → ChainComplex → HomologyGroups → Betti →
  CochainComplex → CohomologyGroups → PostnikovTower → HomotopyGroups →
  KInvariants`. Each ψ-stage is a parametric structure-preserving functor;
  the chain is monoidal composition of these functors. Foundation 0.4.2
  ships the chain as `Term::{Nerve, ChainComplex, HomologyGroups, Betti,
  CochainComplex, CohomologyGroups, PostnikovTower, HomotopyGroups,
  KInvariants}`; foundation 0.4.3's SDK enforces the ψ-residuals
  discipline at proc-macro expansion (architecture §9.0). Eight of the
  nine are *resolver-bound* through the application's `ResolverTuple`
  (ψ_4 Betti is resolver-free byte projection); the catamorphism
  dispatches each stage through the application-supplied resolver.
- **Label generation** — applying the ψ-pipeline to a typed input produces
  a structural witness — the **label**. The label is the output bytes the
  parametric transformation generates. For Bitcoin, the label IS the
  wire-format Bitcoin block bytes.

What's *not* in the conceptual model: search, enumeration, "find a nonce
satisfying," "compute SHA-256d 2^32 times." Those are algorithmic framings.
prism declares relationships, applies parametric tensor-algebra functors,
and generates labels.

## 2. Bitcoin's typed feature hierarchy

Bitcoin's wire-format primitives, declared as `ConstrainedTypeShape`
instances, composed hierarchically via foundation's tensor algebras.

### 2.1 Atomic feature primitives

| Primitive | Site count | Witt level | Role |
|---|---|---|---|
| `Version` | 4 W8 sites | W32 (as scalar) | Block version field (4-byte LE) |
| `PrevHash` | 32 W8 sites | W256 | The previous block's `Sha256dHasher` content-address |
| `MerkleRoot` | 32 W8 sites | W256 | Root of the transaction merkle tree, content-addressed |
| `Timestamp` | 4 W8 sites | W32 | Header timestamp (4-byte LE, Unix seconds) |
| `Bits` | 4 W8 sites | W32 | Compact-encoded target |
| `Nonce` | 4 W8 sites | W32 | Miner's resolved nonce (4-byte LE) |
| `Target` | 32 W8 sites | W256 | Decoded threshold (structural projection of `Bits`) |

Each is a typed primitive with the canonical hash axis (`Sha256dHasher`,
ADR-030) bound via `AxisTuple` for content-addressing per
`morphism:GroundingMap`'s "typed, derivation-witnessed, constraint-preserving
map from surface to coordinate."

### 2.2 Composite feature primitives

| Composite | Composition | Site count | Structural role |
|---|---|---|---|
| `TemplatePrefix` | `partition_product(Version, PrevHash, MerkleRoot, Timestamp, Bits)` | 76 W8 | Template-supplied bytes — the miner cannot change these |
| `Header` | `partition_product(TemplatePrefix, Nonce)` | 80 W8 | The canonical 80-byte Bitcoin header |
| `MiningTask` | `partition_product(TemplatePrefix, Target)` | 108 W8 | The typed mining input |
| `MiningResult` | The structural witness whose `IntoBindingValue` bytes are the wire-format-valid `Header` | — | The label generated by the ψ-pipeline |
| `Block` | `operad_composition(Header, Transactions[])` | variable | The full wire-format block (host-boundary level; see §7) |

The composition is **declarative**, not algorithmic. `Header`'s site layout
is the sequenced concatenation of its factors under
`partition:PartitionProduct`'s structural-operad-governed nesting
(`operad:StructuralOperad`).

### 2.3 The admission constraint

The structural admission relation between `Header` and `Target` —
"the Header's content-address (under the canonical hash axis) is
structurally bounded by Target" — is declared as a `ConstraintRef` on
`MiningResult::CONSTRAINTS`. The relation is structural, not algorithmic:
we do not say "iterate Nonce until SHA-256d(Header) ≤ Target." We declare
*the structural relationship* between Header's hash-axis content-address
and Target's typed surface, and let the ψ-pipeline observe it.

The exact `ConstraintRef` encoding is one of foundation's catalog
variants — see §9 for the gap analysis between what foundation 0.4.2 ships
in its closed `ConstraintRef` catalog and what the structural admission
relation requires.

## 3. Substitution axes

Foundation's `PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple>`
fixes prism-btc's four substitution axes (ADR-007, ADR-010, ADR-018,
ADR-030, ADR-036):

| Axis | prism-btc selection | Role |
|---|---|---|
| `HostTypes` | `DefaultHostTypes` | Foundation-default host-side type carriers |
| `HostBounds` | `PrismBtcBounds` | `WITT_LEVEL_MAX_BITS = 32`, `FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64` |
| `Hasher` | `Sha256dHasher` | Canonical hash axis (axis_index=0, kernel_id=0). Pure-Rust SHA-256-then-SHA-256. Content-addressing bijection for double-SHA-256-bound Bitcoin types. **Not the mining transform** — the σ-projection is a content-addressing primitive, not an algorithm prism-btc runs. |
| `ResolverTuple` | `BitcoinResolverTuple<Sha256dHasher>` | Bitcoin-specific realization of the 8 resolver-bound ψ-stages. Each resolver names what the parametric tensor-algebra functor computes for Bitcoin's typed feature hierarchy. |

`PrismBtcBounds`' `WITT_LEVEL_MAX_BITS = 32` matches Bitcoin's `Nonce`
field exactly. Higher Witt levels are not required — the typed surface's
algebra is W32-bounded; nothing in prism-btc enumerates a domain larger
than what Bitcoin's wire-format already encodes.

## 4. The ψ-pipeline transform

The mining inference is the ψ-pipeline applied to `MiningTask`:

```text
MiningTask
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_2 ChainComplex     (SimplicialComplex → ChainComplex)
   ↓ ψ_3 HomologyGroups   (ChainComplex → HomologyGroups)
   ↓ ψ_4 Betti            (HomologyGroups → BettiNumbers — resolver-free)
   ↓ ψ_5 CochainComplex   (ChainComplex → CochainComplex)
   ↓ ψ_6 CohomologyGroups (CochainComplex → CohomologyGroups)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
MiningResult — the label
```

The verb body declares this composition as a `TermExpression`. Foundation
0.4.2's catamorphism (`pipeline::evaluate_term_tree<H, R>`) dispatches each
ψ-Term through `BitcoinResolverTuple`'s corresponding resolver.

Each resolver's `resolve(input: &[u8], out: &mut [u8]) → Result<usize,
ShapeViolation>` is **parametric** — it computes the ψ-stage's structural
transformation over Bitcoin's typed feature hierarchy, generating output
bytes whose interpretation is given by the next ψ-stage. The composition's
final output is the label — Bitcoin's wire-format-valid block bytes.

**The verb body** (`crates/prism-btc/src/verbs.rs`):

```rust
verb! {
    pub fn mining_inference(input: MiningTask) -> MiningResult {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

The ψ_1 → ψ_7 → ψ_8 → ψ_9 branch is the **k-invariant branch** — it
classifies the structural typed inference via Postnikov-tower k-invariants.
The label generated by ψ_9 is the typed witness of the admitting Bitcoin
block. The homology branch (ψ_1 → ψ_2 → ψ_3 → ψ_4) is available; prism-btc
selects the k-invariant branch as the canonical mining transform because
k-invariants are the universal classifying invariants of the Postnikov
truncation, and the typed-iso surface of a wire-format-valid Bitcoin block
is naturally characterized by its k-invariant signature.

## 5. The mining model

```rust
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
        fn resolvers() -> BitcoinResolverTuple<Sha256dHasher> {
            BitcoinResolverTuple::new()
        }
    }
}
```

`forward(task: MiningTask) → Result<Grounded<MiningResult>, PipelineFailure>`
is the canonical typed-iso surface. The `Grounded<MiningResult>` is the
foundation-sealed certificate that the typed inference admits; its
`output_bytes()` carry the label — the wire-format-valid Bitcoin block.

## 6. Bit-identicality contract

**Invariant.** For any `MiningTask` derived from a Bitcoin Core
`getblocktemplate` response, if `BitcoinMiningModel::forward(task)`
returns `Ok(grounded)`, then `grounded.output_bytes()` is byte-for-byte
identical to a wire-format Bitcoin block that Bitcoin Core's `submitblock`
RPC accepts for the corresponding template.

This is not a claim about path. prism-btc's transform is structural (the
ψ-pipeline over Bitcoin's typed feature hierarchy); a traditional miner's
transform is algorithmic (enumerate nonces, double-SHA-256, compare to
target). The two paths arrive at byte-for-byte equivalent wire-format
output because both are determined by the same wire-format protocol —
prism-btc declares the protocol structurally; the traditional miner
discovers it by enumeration. The label is the same artifact.

The bit-identicality guarantee composes from the structural commitments:

1. `Header`'s composition via `partition_product(Version, PrevHash,
   MerkleRoot, Timestamp, Bits, Nonce)` enforces the canonical 80-byte
   layout.
2. The structural admission constraint on `MiningResult` declares the
   admission relation (Header's content-address bounded by Target) in
   wire-format terms.
3. The label's bytes are produced by the ψ-pipeline's parametric
   transformations operating on the typed feature hierarchy — the
   structural witness's `IntoBindingValue::into_binding_bytes` projection
   *is* the wire-format Header (and, at the host boundary, the wire-format
   Block).
4. The boundary's submitblock assembly (§7) is byte-for-byte the same
   serialization a traditional miner uses.

## 7. Host boundary

`crates/prism-btc-node/` is the bitcoind boundary. It is **not** part of
the transform; it adapts between prism's typed-iso surface and Bitcoin
Core's JSON-RPC surface.

The boundary's responsibilities:

1. Call `getblocktemplate` and decode the response into a
   `MiningTask` (the typed input to `BitcoinMiningModel::forward`).
2. Compose the coinbase transaction with the user's payout address and a
   chosen extranonce.
3. Derive the `MerkleRoot` from the coinbase + the template's transaction
   list.
4. Invoke `BitcoinMiningModel::forward(task)`.
5. Extract the label from `Grounded<MiningResult>::output_bytes()`,
   assemble the wire-format Block (Header + TxCount + Transactions), and
   submit via `submitblock`.

The pure-Rust SHA-256 helpers in `crates/prism-btc/src/ops/sha256.rs`,
`ops/merkle.rs`, and `ops/header.rs` exist **only** to serialize bytes for
the bitcoind RPC boundary — they are not invoked inside the ψ-pipeline
transform. The σ-projection (SHA-256d) inside the transform is a
content-addressing primitive realized via `Term::AxisInvocation` over the
canonical hash axis (`Sha256dHasher`), not via direct invocation.

## 8. Public API surface

```rust
// crates/prism-btc/src/lib.rs

// Typed feature primitives
pub use shapes::primitives::{Version, PrevHash, MerkleRoot, Timestamp, Bits, Nonce, Target};
// Composite feature primitives
pub use model::{TemplatePrefix, Header, MiningTask, MiningResult, Block};

// The mining model
pub use model::{BitcoinMiningModel, BitcoinMiningRoute};

// Substitution axes
pub use shapes::hasher::Sha256dHasher;
pub use shapes::bounds::PrismBtcBounds;
pub use resolvers::BitcoinResolverTuple;

// Public entry point
pub use pipeline::{mine, MiningOutcome, MiningFailure};

// Host-boundary witnesses
pub use domain::{MiningTag, MiningWitness, TriadicCoords, BlockHeader};
```

`mine(header: &BlockHeader, target: Target) → Result<MiningOutcome, MiningFailure>`
builds a `MiningTask` from the host-side `BlockHeader` + `Target`, invokes
`BitcoinMiningModel::forward`, and returns a `MiningOutcome` whose
`witness: MiningWitness` carries the foundation-sealed `Grounded<MiningResult>`
and whose `digest: [u8; 32]` is the block hash in display order.

## 9. Foundation gaps the implementation surfaces

prism-btc's pure-prism architecture exercises foundation surfaces at the
edge of what's currently expressible. The gaps below are surfaced by the
implementation and proposed as upstream amendments to
`UOR-Foundation/UOR-Framework`.

### 9.0 ψ-residuals discipline — closed in 0.4.3

Foundation 0.4.3's SDK enforces the ψ-residuals discipline at
proc-macro expansion time: the `verb!` and `prism_model!` closure-body
parsers reject `<=` / `<` / `>=` / `>` (byte-comparison ops), `concat(...)`
(`PrimitiveOp::Concat` application), `first_admit(...)` (ψ-enumeration
over a counter domain), and `hash(...)` (axis dispatch from a verb body)
with explicit error messages that name `k_invariants(homotopy_groups(
postnikov_tower(nerve(input))))` as the canonical compiled form. The
substrate additionally enforces ψ-chain receiver-shape compatibility
(ADR-035: `chain_complex` requires a `SimplicialComplex` operand,
`homology_groups` requires a `ChainComplex` operand, …) at macro
expansion. prism-btc's pure-prism architecture is now substrate-enforced;
the discipline cannot regress to σ-residual forms without a build-time
failure naming the violation.

### 9.1 Structural admission encoding

The ontology declares the relation prism-btc needs:
"`Header`'s content-address under the canonical hash axis is lex-bounded
by `Target`." The closed `ConstraintRef` catalog (`Residue / Hamming /
Depth / Carry / Site / Affine / SatClauses / Bound { observable_iri,
bound_shape_iri, args_repr } / Conjunction`) does not yet include an
observable that names "axis-realized projection of typed sites" or a
bound shape that names "32-byte lexicographic ≤."

**Proposed amendment**: extend foundation's closed `Observable` catalog
with `AxisProjectionObservable { axis_index, kernel_id, source_sites }`
(IRI: `https://uor.foundation/observable/AxisProjectionObservable`) and
the closed `BoundShape` catalog with `LexicographicLessEqBound`
(IRI: `https://uor.foundation/type/LexicographicLessEqBound`).
prism-btc consumes both via `ConstraintRef::Bound { observable_iri,
bound_shape_iri, args_repr }`.

The ontology already declares the underlying concepts:
`morphism:GroundingMap` (the content-addressing bijection),
`type:MetricAxis` (the tri-metric classification),
`observable:RingMetric` (the additive ring distance). The amendment
surfaces these as a closed-catalog `(observable, bound_shape)` pair the
constraint algebra can index.

### 9.2 Resolver realization of the ψ-stages for Bitcoin's typed surface

Foundation 0.4.2's `Null{Nerve,ChainComplex,…,KInvariant}Resolver` impls
return `RESOLVER_ABSENT` shape violations. prism-btc's
`BitcoinResolverTuple` must provide concrete realizations of each
resolver-bound ψ-stage that compute the parametric tensor-algebra
transformation over Bitcoin's typed feature hierarchy.

The realizations are application-author code (prism-btc-side, per
ADR-036's sealed-via-SDK-macro discipline). They consume bytes,
produce bytes, and the composition's final output is the label. The
specific byte-level semantics of each ψ-stage for Bitcoin are part of
prism-btc's design — see `crates/prism-btc/src/resolvers.rs`.

### 9.3 Capacity ceilings

`primitive_simplicial_nerve_betti<T: ConstrainedTypeShape>()`'s
`NERVE_CONSTRAINTS_CAP = 8` and `NERVE_SITES_CAP = 8` are tight. If
prism-btc's hierarchical feature decomposition produces a constraint
nerve exceeding these caps, foundation must raise them or move the cap
to a `HostBounds`-parametric constant.

### 9.4 Resolver-output bit width

Resolver outputs are byte-flat (`out: &mut [u8]`). The ψ-pipeline's final
output (the label) for Bitcoin must be exactly the wire-format block
bytes; the resolver chain must thread structural data of arbitrary width
through each ψ-stage. The byte-flat carrier may need to grow to a
typed-coordinate carrier (e.g., `Coordinate<L>` per
`type:Coordinate`/`type:MetricAxis`) if prism-btc's ψ-stages need richer
structural carriers than raw bytes.

## 10. Conformance under the pure-prism framing

| Tenet | prism-btc realization |
|---|---|
| **TC-01 zero-cost runtime** | All `ConstrainedTypeShape` impls, `partition_product` compositions, and substitution-axis selections are resolved by `rustc` at compile time. Foundation's catamorphism is monomorphised against `BitcoinResolverTuple<Sha256dHasher>` at the `BitcoinMiningModel` declaration site. |
| **TC-02 sealing** | Every `Datum`, `Triad`, `Derivation`, `FreeRank`, `Validated`, `Grounded`, `Certified` arrives via foundation's mint primitives or as a `pipeline::run_route` return value. prism-btc constructs zero sealed types directly. |
| **TC-03 path singularity** | `BitcoinMiningModel::forward` (which delegates to `pipeline::run_route → pipeline::evaluate_term_tree`) is the only pathway to a `Grounded<MiningResult>`. `Grounded` is sealed; `MiningTag` is a phantom over it. |
| **TC-04 declarative semantics** | The mining model is declarative: typed primitives + structural admission constraint + ψ-pipeline transform composition. No algorithmic body in prism-btc's code; the catamorphism evaluates the structural declaration. |
| **TC-05 replayability** | The pipeline emits a `Trace` (foundation 0.4.2 `enforcement::trace`); `enforcement::replay::certify_from_trace` re-validates the typed inference structurally without invoking any hasher's hashing method or any decider written by prism-btc. |
| **TC-06 local execution** | Every stage executes locally on the user's hardware. No oracle, no service call, no remote evaluator. |

## 11. Cross-reference to UOR ontology

The IRIs prism-btc consumes from the foundation ontology (v0.4.2,
`uor.foundation.{ttl,jsonld,owl,nt}`):

- `type:ConstrainedType`, `type:Constraint`, `type:BoundConstraint`,
  `type:BoundShape`, `type:Conjunction`
- `partition:PartitionProduct`, `partition:PartitionCoproduct`,
  `partition:CartesianPartitionProduct`
- `operad:StructuralOperad`, `operad:OperadComposition`
- `monoidal:MonoidalProduct`, `monoidal:MonoidalUnit`,
  `monoidal:MonoidalAssociator`
- `homology:NerveFunctor`, `homology:ChainComplex`,
  `homology:ChainFunctor`, `homology:HomologyGroup`,
  `homology:PostnikovTruncation`, `homology:KInvariant`,
  `homology:HornFiller`, `homology:KanComplex`,
  `homology:SimplicialComplex`, `homology:BoundaryOperator`,
  `homology:FaceMap`
- `cohomology:CochainComplex`, `cohomology:CohomologyGroup`,
  `cohomology:CoboundaryOperator`, `cohomology:Sheaf`,
  `cohomology:Stalk`, `cohomology:Section`, `cohomology:LocalSection`,
  `cohomology:RestrictionMap`, `cohomology:GluingObstruction`
- `observable:Observable`, `observable:HomotopyGroup`,
  `observable:BettiNumber`, `observable:TopologicalObservable`,
  `observable:RingMetric`, `observable:MetricObservable`
- `morphism:GroundingMap`, `morphism:GroundingWitness`,
  `morphism:GroundingCertificate`, `morphism:ProjectionMap`,
  `morphism:ProjectionWitness`, `morphism:Witness`
- `resolver:Resolver`, `resolver:CechNerve`,
  `resolver:HomotopyResolver`, `resolver:EvaluationResolver`,
  `resolver:CompletenessResolver`, `resolver:InhabitanceResolver`
- `cert:InhabitanceCertificate`, `cert:LiftChainCertificate`,
  `cert:ChainAuditTrail`, `cert:GroundingCertificate`
- `state:GroundedContext`, `state:GroundingWitness`,
  `state:Session`, `state:Frame`

These names are normative. prism-btc's IRIs
(`https://prism.btc/shape/*`) are the application's instantiation of the
foundation classes.

## 12. What this architecture deliberately excludes

- **No σ-enumeration anywhere in the transform.** The ψ-pipeline is
  parametric tensor-algebra composition over the typed feature hierarchy;
  it does not iterate Nonce, does not invoke SHA-256d as an algorithmic
  step, does not "search."
- **No `Term::FirstAdmit` usage in the mining verb body.** FirstAdmit is
  a substrate primitive (foundation 0.4.2) for bounded structural search
  over small typed domains; it is not the mining transform.
- **No traditional-miner complexity framing.** prism-btc's wall-clock
  cost is the cost of the parametric ψ-pipeline's catamorphism
  evaluation, not "expected hashes × per-hash cost." Wall-clock is a
  property of foundation's evaluator + the resolvers' tensor-algebraic
  realizations; it is invariant across network choice (regtest, signet,
  testnet, testnet4, mainnet) at the vocabulary level. The byte-threshold
  in `Target` parameterizes the admission relation's structural
  complexity, not a probabilistic puzzle parameter.
- **No "CPU mining" framing.** prism-btc's mining is one structural
  inference. Hash-rate is not a meaningful metric; one `forward()` is one
  mining operation regardless of network.
- **No external crypto dependency.** `Sha256dHasher` is pure-Rust
  SHA-256-then-SHA-256 (FIPS-180-4) as the canonical hash axis's
  content-addressing primitive. No `sha2`, no `blake3`, no opaque crate.
- **No mining-pool integration.** Stratum, share submission, pool wallet
  management — out of scope. prism-btc is solo-mining; the bitcoind it
  talks to is the user's own.

## 13. Workspace layout

| Crate | Role |
|---|---|
| [`prism-btc`](crates/prism-btc/) | The pure-prism domain layer. Declares Bitcoin's typed feature hierarchy, the ψ-chain verb body, `BitcoinMiningModel`, `BitcoinResolverTuple`, and the public `mine()` entry point. Pure-Rust SHA-256 for the canonical hash axis. No external crypto dep, no search loop. |
| [`prism-btc-node`](crates/prism-btc-node/) | bitcoind RPC boundary. `getblocktemplate → BitcoinMiningModel::forward → submitblock`. `prism-mine` CLI binary. Adapts between Bitcoin Core's JSON-RPC and prism's typed-iso surface. |
| [`prism-btc-wasm`](crates/prism-btc-wasm/) | `wasm-bindgen` surface around `prism_btc::mine`. |
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape constraint monotonicity. The proofs are anchored to foundation's algebraic structure; refresh against the pure-prism architecture is tracked separately. |

## 14. Quick start

```bash
cargo install just

just build      # cargo build --workspace
just test       # cargo test --workspace
just lint       # cargo clippy --workspace -- -D warnings
just fmt-check  # cargo fmt --check

just verify     # Lean 4 proofs (lake update && lake build)
just build-wasm # WebAssembly build
just regtest-demo  # End-to-end regtest exercise against a local bitcoind
```

The mining inference is invariant across networks (regtest, signet,
testnet, testnet4, mainnet). The `prism-mine` CLI binary is the public
surface for driving `BitcoinMiningModel::forward` against any running
bitcoind.

## License

Apache-2.0 — see [LICENSE](LICENSE).
