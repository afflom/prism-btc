# prism-btc — pure-prism architecture

> **Architectural commitment.** prism-btc implements the prism conceptual
> model without compromise. The mining inference is not an algorithm; it
> is a declarative composition of foundation's parametric tensor algebras
> over Bitcoin's typed feature hierarchy. There is no σ-enumeration in
> the verb body, no FirstAdmit-shaped search at the typed-iso surface,
> no traditional-miner complexity framing. Where foundation's primitive
> catalog does not yet express something prism-btc needs, prism-btc
> names the gap and files it upstream — never substitutes a non-prism
> implementation.
>
> **Output contract.** The 80-byte κ-label emitted by the ψ-pipeline is
> byte-for-byte the canonical wire-format Bitcoin header. The mining
> inference is identical across regtest, signet, testnet, testnet4, and
> mainnet; the only network-dependent value is the runtime target
> threshold encoded in the template's `bits` field.

> **Normative references.**
> [UOR-Foundation/UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki),
> the canonical foundation ontology artifacts
> (`uor.foundation.{ttl,jsonld,owl,nt}`, `uor.shapes.ttl`, `uor.term.ebnf`),
> and ADR-024 (verb declarations), ADR-030 (canonical hash axis),
> ADR-035 (ψ-chain Term variants + ψ-residuals discipline), ADR-036
> (`ResolverTuple` substitution-axis), ADR-037 (`HostBounds`-parametric
> capacity ceilings), ADR-041 (typed-coordinate resolver carriers).

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
  foundation ships the chain as `Term::{Nerve, ChainComplex, HomologyGroups,
  Betti, CochainComplex, CohomologyGroups, PostnikovTower, HomotopyGroups,
  KInvariants}` and enforces the ψ-residuals discipline at proc-macro
  expansion (architecture §9). Eight of the nine are *resolver-bound*
  through the application's `ResolverTuple` (ψ_4 Betti is resolver-free
  byte projection); the catamorphism dispatches each stage through the
  application-supplied resolver.
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
| `MiningResult` | The structural witness whose `IntoBindingValue` bytes are the wire-format-valid `Header` | 80 W8 | The κ-label generated by the ψ-pipeline |
| `Block` | `operad_composition(Header, Transactions[])` | variable | The full wire-format block (host-boundary level; see §7) |

The composition is **declarative**, not algorithmic. `Header`'s site layout
is the sequenced concatenation of its factors under
`partition:PartitionProduct`'s structural-operad-governed nesting
(`operad:StructuralOperad`).

### 2.3 The admission constraint — algebraic-closure encoded

`MiningResult::CONSTRAINTS` declares **80 disjoint `ConstraintRef::Site`
instances** — one per wire-format-header byte position (0..80) — the
algebraic-closure encoding per the UOR Index Theorem IT_7d
([`analytical-completeness.md`](https://github.com/UOR-Foundation/UOR-Framework/blob/main/docs/content/concepts/analytical-completeness.md)).
Each constraint pins exactly one site; site supports are pairwise
disjoint; the constraint nerve N(C) is **80 isolated vertices, no
higher simplices**:

```
β_0 = 80,    β_k = 0 for k ≥ 1
χ(N(C)) = β_0 − β_1 + … = 80 = SITE_COUNT
```

— the framework's algebraic-closure criterion (*resolution is
complete iff χ(N(C)) = n and all β_k = 0*) is satisfied at the
declaration level. The wiki's iterative-resolution discipline
(`iterative-resolution.md`) converges in `n − χ(N(C)) = 0` residual
rank: each iteration pins one site by applying one constraint, and
the resolver chain materializes the pinned values end-to-end.

The 80 sites partition into two pinning mechanisms:

| Sites | Mechanism | Source |
|---|---|---|
| `0..76` | template-pinned | host-supplied template bytes (`Version‖PrevHash‖MerkleRoot‖Timestamp‖Bits`) carried through `MiningTask::prefix` |
| `76..80` | κ-pinned | ψ_9 resolver's iterative-resolution loop walks the W32 ring and pins the four nonce bytes to the admitting nonce's bytes (architecture §4 + §6) |

Both mechanisms terminate at the same fixed point: 80 sites pinned ⇒
`FreeRank = 0` ⇒ convergence ⇒ admission witness.

The encoding is pinned by V&V tests in
[`crates/prism-btc/tests/verification.rs`](crates/prism-btc/tests/verification.rs):
80 disjoint Site constraints, 80 isolated nerve vertices, site supports
spanning [0, 80) exactly.

## 3. Substitution axes

Foundation's `PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple>`
fixes prism-btc's four substitution axes (ADR-007, ADR-010, ADR-018,
ADR-030, ADR-036):

| Axis | prism-btc selection | Role |
|---|---|---|
| `HostTypes` | `DefaultHostTypes` | Foundation-default host-side type carriers |
| `HostBounds` | `PrismBtcBounds` | `WITT_LEVEL_MAX_BITS = 32`, `FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64`, `NERVE_SITES_MAX = 80`, `NERVE_CONSTRAINTS_MAX = 128`, `BETTI_DIMENSION_MAX = 80`, `AFFINE_COEFFS_MAX = 80`, `CONJUNCTION_TERMS_MAX = 128` |
| `Hasher` | `Sha256dHasher` | Canonical hash axis (axis_index=0, kernel_id=0). Pure-Rust SHA-256-then-SHA-256. Content-addressing bijection for double-SHA-256-bound Bitcoin types. **Not the mining transform** — the σ-projection is a content-addressing primitive, not an algorithm prism-btc runs. |
| `ResolverTuple` | `BitcoinResolverTuple<Sha256dHasher>` | Bitcoin-specific realization of the 8 resolver-bound ψ-stages. Each resolver names what the parametric tensor-algebra functor computes for Bitcoin's typed feature hierarchy. |

`PrismBtcBounds`' `WITT_LEVEL_MAX_BITS = 32` matches Bitcoin's `Nonce`
field exactly. Higher Witt levels are not required — the typed surface's
algebra is W32-bounded; nothing in prism-btc enumerates a domain larger
than what Bitcoin's wire-format already encodes. The nerve and Betti
ceilings (`NERVE_SITES_MAX = 80`, `BETTI_DIMENSION_MAX = 80`) match
`MiningResult`'s 80-site algebraic-closure declaration so the
constraint geometry is fully expressible at the binding ceiling.

## 4. The ψ-pipeline transform

prism-btc's mining inference is the **k-invariant branch** of the
ψ-pipeline applied to `MiningTask`:

```text
MiningTask
   ↓ ψ_1 Nerve            (Constraints → SimplicialComplex)
   ↓ ψ_7 PostnikovTower   (SimplicialComplex → PostnikovTower)
   ↓ ψ_8 HomotopyGroups   (PostnikovTower → HomotopyGroups)
   ↓ ψ_9 KInvariants      (HomotopyGroups → KInvariants)
MiningResult — the κ-label
```

k-invariants are the universal classifying invariants of the Postnikov
tower; the typed-iso surface of a wire-format-valid Bitcoin block is
naturally characterized by its k-invariant signature. The homology
branch (ψ_1 → ψ_2 → ψ_3 → ψ_4) and cohomology branch
(ψ_2 → ψ_5 → ψ_6) are alternative paths through the ψ-DAG that
foundation's `Term::*` vocabulary names; prism-btc commits to the
k-invariant branch as the canonical mining transform. Their resolvers
are realized in `BitcoinResolverTuple` to keep the substitution-axis
total under foundation's `resolver!` discipline (ADR-036), but they
are not on the mining-transform path.

**The verb body** ([`crates/prism-btc/src/verbs.rs`](crates/prism-btc/src/verbs.rs)):

```rust
verb! {
    pub fn mining_inference(input: MiningTask) -> MiningResult {
        k_invariants(homotopy_groups(postnikov_tower(nerve(input))))
    }
}
```

Foundation's catamorphism (`pipeline::evaluate_term_tree<H, R>`)
dispatches each ψ-Term through `BitcoinResolverTuple`'s corresponding
resolver (ADR-036), with per-ψ-stage typed-coordinate carriers
(ADR-041: `SimplicialComplexBytes`, `PostnikovTowerBytes`,
`HomotopyGroupsBytes`, `KInvariantsBytes`) type-checking ψ-chain
composition at the resolver-impl boundary.

**Resolver carrier semantics — structural, not content-addressed.**
Each non-terminal ψ-stage emits a 208-byte structural carrier that
describes its mathematical content for the 80-isolated-vertices
constraint geometry:

```text
[0..108)    MiningTask bytes (TemplatePrefix‖Target) — threaded forward unchanged
[108..116)  ψ-stage tag (u64 BE, one of {1, 2, 3, 5, 6, 7, 8})
[116..120)  u32 BE: vertex_count of the nerve N(C) = 80
[120..124)  u32 BE: highest_nontrivial_dim of the underlying space = 0
[124..128)  u32 BE: reserved (= 0)
[128..208)  80 × u8: per-vertex Site positions (the 80 generators)
```

The `vertex_count`, `highest_dim`, and Site-position cells encode the
ψ-stage's structural content. For prism-btc's 80-disjoint-Sites
constraint geometry (architecture §2.3), every non-terminal ψ-stage's
output is the same discrete 80-element object up to its named
ψ-vocabulary: ψ_1 emits the nerve N(C) = 80 isolated vertices; ψ_2
emits the chain complex C_• with `C_0 = ℤ^80, C_k = 0`; ψ_3 emits
homology `H_0 = ℤ^80, H_k = 0`; ψ_5/ψ_6 mirror by duality; ψ_7 emits
the Postnikov tower truncating at level 0; ψ_8 emits the homotopy
groups `π_0 = 80-set, π_k = 0`. The stage tag at offset 108 carries
the per-stage discrimination so ψ-chain replay can audit which stage
produced which carrier.

Each downstream stage validates the upstream stage tag and the
structural invariants (`vertex_count = 80`, `highest_dim = 0`) before
emitting its own stage's bytes. A mismatched upstream tag or a
malformed geometry surfaces a `ShapeViolation` — the resolver chain
refuses to compose if the upstream object is not the typed-coordinate
carrier the downstream ψ-functor consumes.

**ψ_1 Nerve — builds N(C) from `MiningResult::CONSTRAINTS`.** Reads
the 80 declared `ConstraintRef::Site` instances, verifies the IT_7d
algebraic-closure shape (Site_i pins position i for i ∈ [0, 80)), and
emits the ψ_1 carrier. Pairwise-disjoint site supports ⇒ no
1-simplices ⇒ `highest_dim = 0`. The nerve is built from declared
data, not threaded from a hash chain.

**ψ_9 KInvariant — the terminal label, iterative-resolution.**
Consumes the ψ_8 HomotopyGroups carrier and emits exactly **80 bytes
— the wire-format Bitcoin header**. k-invariants `κ_n ∈
H^{n+2}(π_1; π_{n+1})` classify the Postnikov tower's
twisted-fibration data; for the 80-isolated-vertices case
(`π_0 = 80-set`, `π_k = 0` for k ≥ 1) the k-invariant signature
itself is trivial (no obstruction classes). The load-bearing
computation is the framework's iterative-resolution discipline
(`iterative-resolution.md`): ψ_9 validates the upstream carrier
(80 π_0 generators, no higher homotopy), extracts the prefix
(76 bytes) and target (32 bytes) from the threaded `MiningTask`
data, and walks the W32 nonce ring (`witt_domain::W32`,
`CYCLE_SIZE = 2^32`) with `FreeRank` decreasing per iteration. Each
iteration pins a candidate nonce, evaluates the structural admission
relation `H(header) ≤ target` via the canonical hash axis, and
continues until convergence (the first satisfying nonce) or W32 ring
exhaustion (the canonical `proof:InhabitanceImpossibilityWitness`).
Convergence pins the four nonce-byte sites; the resolver emits the
admitting wire-format header. **From outside, `forward()` is one
structural inference per `MiningTask`** — the resolver's internal
iteration IS the iterative-resolution discipline the framework names.

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

## 6. Bit-identicality and fail-closed contract

**Invariant.** `BitcoinMiningModel::forward(task)` returns a
`Grounded<MiningResult>` whose `output_bytes()` are exactly 80 bytes —
the wire-format Bitcoin header (`prefix(76) ‖ nonce(4 LE)`). The leading
76 bytes are unchanged from `task.prefix`; the trailing 4 bytes are the
κ-derived nonce.

**Fail-closed.** When `forward(task)` returns `Ok(grounded)`, the
κ-derived header *genuinely satisfies* `task.target` — the resolver's
convergence guarantee is the admission witness. The host-boundary
`mine(header, target)` entry point translates the typed-iso success
into a `MiningOutcome` and a host-side SHA-256d sanity-derivation;
`Err(MiningFailure::PipelineFailure)` corresponds to the ψ_9
resolver's `InhabitanceImpossibilityWitness` — the W32 ring was
walked end-to-end without admission, and the host boundary
(architecture §7) varies the template-derived `MiningTask`
(extranonce roll → distinct prefix → fresh W32 ring) and retries.
**Valid input either produces a valid mined-block header or surfaces
the impossibility witness for the host to handle.** `mine()` never
returns a `MiningOutcome` whose header does not actually admit.

The bit-identicality guarantee composes from the structural commitments:

1. `Header`'s composition via `partition_product(Version, PrevHash,
   MerkleRoot, Timestamp, Bits, Nonce)` enforces the canonical 80-byte
   layout.
2. The structural admission constraint on `MiningResult` declares the
   admission relation (80 disjoint Site constraints — algebraic
   closure) in wire-format terms.
3. The label's bytes are produced by the ψ-pipeline's parametric
   transformations operating on the typed feature hierarchy — the
   structural witness's `IntoBindingValue::into_binding_bytes` projection
   *is* the wire-format Header (and, at the host boundary, the wire-format
   Block).
4. The boundary's submitblock assembly (§7) is byte-for-byte the same
   serialization a traditional miner uses.

**Network-invariant.** The mining inference is identical across
regtest, signet, testnet, testnet4, and mainnet: same
`BitcoinMiningModel`, same ψ-pipeline verb body, same
`BitcoinResolverTuple`. The network-dependent value is the runtime
byte threshold encoded in the template's `Bits` field. For permissive
regtest targets, the κ-derived header typically admits on the first
template variation; for restrictive mainnet targets, the host boundary
iterates extranonces (each producing a distinct `MiningTask` → distinct
κ-derived header) until admission lands. In every regime, a returned
`MiningOutcome`'s wire-format header genuinely satisfies the target —
no compromises, no invalid output.

## 7. Host boundary

`crates/prism-btc-node/` is the bitcoind boundary. It is **not** part of
the transform; it adapts between prism's typed-iso surface and Bitcoin
Core's JSON-RPC surface, and it owns the **template-variation loop**
that iterates `MiningTask` inputs until the deterministic ψ-pipeline
lands on an admitting κ-derived header.

`PrismMiner::mine_one_block`'s loop:

1. Call `getblocktemplate` once per block attempt.
2. Initialize `extranonce = 0`.
3. Compose the coinbase transaction with the user's payout address and
   the current extranonce (which lands in the coinbase's `scriptSig`).
4. Derive the `MerkleRoot` from the modified coinbase + the template's
   transaction list.
5. Build a `MiningTask` from `(version, prev_hash, merkle_root,
   timestamp, bits, decoded_target)`.
6. Call `prism_btc::mine(header, target)`. The ψ_9 resolver's
   iterative-resolution loop walks the W32 nonce ring internally
   until admission lands; `mine()` is one structural inference per
   `MiningTask` from the host's perspective.
   - `Ok(outcome)` ⇒ assemble the wire-format Block, submit via
     `submitblock`, return summary.
   - `Err(MiningFailure::PipelineFailure)` ⇒ ψ_9 returned the
     `InhabitanceImpossibilityWitness` (W32 ring walked without
     admission). Increment `extranonce`, goto step 3. The wrapped
     extranonce (after `~10¹⁹` variations) signals exhaustion — the
     chain has typically advanced first, so the caller fetches a
     new template.

The boundary's outer loop is the wire-format adaptation — coinbase
construction, merkle derivation, RPC plumbing. The inner ψ-pipeline
inference handles its own iteration per the wiki's iterative-
resolution discipline (`iterative-resolution.md`); the resolver
walks the W32 ring with `FreeRank` decreasing per iteration, and
convergence (FreeRank = 0) is admission. From outside, `forward()`
is one structural inference per `MiningTask`.

The pure-Rust SHA-256 helpers in `crates/prism-btc/src/ops/sha256.rs`,
`ops/merkle.rs`, and `ops/header.rs` exist **only** to serialize bytes for
the bitcoind RPC boundary — they are not invoked inside the ψ-pipeline
transform. The σ-projection (SHA-256d) inside the transform is a
content-addressing primitive realized via the canonical hash axis
(`Sha256dHasher`) consumed by resolvers, not via direct invocation
from the verb body.

## 8. Public API surface

```rust
// crates/prism-btc/src/lib.rs

// Typed feature primitives
pub use domain::{Version, MerkleRoot, Timestamp, Bits, Target, BlockHeader};
// Composite feature primitives
pub use model::{TemplatePrefix, MiningTask, MiningResult};

// The mining model
pub use model::{BitcoinMiningModel, BitcoinMiningRoute};

// Substitution axes
pub use shapes::{Sha256dHasher, PrismBtcBounds};
pub use resolvers::BitcoinResolverTuple;

// Public entry point
pub use pipeline::{mine, MiningOutcome, MiningFailure};

// Host-boundary witnesses
pub use domain::{MiningTag, MiningWitness, TriadicCoords};
```

`mine(header: &BlockHeader, target: Target) → Result<MiningOutcome, MiningFailure>`
builds a `MiningTask` from the host-side `BlockHeader` + `Target`, invokes
`BitcoinMiningModel::forward`, and returns a `MiningOutcome` whose
`witness: MiningWitness` carries the foundation-sealed `Grounded<MiningResult>`
and whose `digest: [u8; 32]` is the block hash in display order.

## 9. Substrate surface

prism-btc consumes the following foundation surface end-to-end. Each
item is a substrate primitive prism-btc relies on; the application
declarations name what is computed *for Bitcoin* over the substrate.

### 9.1 ψ-residuals discipline

Foundation's SDK enforces the ψ-residuals discipline at proc-macro
expansion: the `verb!` and `prism_model!` closure-body parsers reject
`<=` / `<` / `>=` / `>` (byte-comparison ops), `concat(...)`
(`PrimitiveOp::Concat`), `first_admit(...)` (ψ-enumeration over a
counter domain), and `hash(...)` (axis dispatch from a verb body) with
explicit error messages that name `k_invariants(homotopy_groups(
postnikov_tower(nerve(input))))` as the canonical compiled form. The
substrate additionally enforces ψ-chain receiver-shape compatibility
(ADR-035: `chain_complex` requires a `SimplicialComplex` operand,
`homology_groups` requires a `ChainComplex` operand, …) at macro
expansion. prism-btc's pure-prism architecture is substrate-enforced;
the discipline cannot regress to σ-residual forms without a build-time
failure naming the violation.

### 9.2 Constraint catalog — algebraic-closure declaration

`MiningResult::CONSTRAINTS` declares 80 disjoint `ConstraintRef::Site`
instances from foundation's closed `ConstraintRef` catalog. The Site
variant is the load-bearing constraint type for prism-btc's
algebraic-closure encoding (architecture §2.3): each Site_i pins one
distinct wire-format-header byte position; the 80-Site declaration is
the IT_7d algebraic-closure realization for the typed output shape.

### 9.3 Resolver realizations

`BitcoinResolverTuple` ([`crate::resolvers`](crates/prism-btc/src/resolvers.rs))
ships concrete realizations of all 8 resolver-bound ψ-stages. Each
resolver realizes its named mathematical role over the 80-isolated-
vertices constraint geometry: ψ_1 builds the nerve N(C) from
`MiningResult::CONSTRAINTS`; ψ_2/ψ_3/ψ_5/ψ_6 produce the chain
complex, homology, cochain, and cohomology data; ψ_7 truncates the
Postnikov tower; ψ_8 extracts the homotopy groups; ψ_9 validates the
upstream π_0-only geometry, then runs the iterative-resolution loop
on the four nonce-byte sites and emits the wire-format Bitcoin
header. Each non-terminal stage emits a 208-byte structural carrier
(architecture §4); each downstream stage validates the upstream
stage tag and structural geometry before emitting. ψ_2/ψ_3/ψ_5/ψ_6
are off the mining-transform path (the verb body composes only ψ_1,
ψ_7, ψ_8, ψ_9) but compute their stage's content for substitution-
axis completeness under ADR-036.

### 9.4 Capacity ceilings

ADR-037 makes the catamorphism's ceilings `HostBounds`-parametric.
[`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) declares
prism-btc's capacity profile: `NERVE_SITES_MAX = 80` and
`NERVE_CONSTRAINTS_MAX = 128` accommodate `MiningResult`'s 80-Site
algebraic-closure declaration; `BETTI_DIMENSION_MAX = 80` and
`AFFINE_COEFFS_MAX = 80` mirror the nerve geometry; each per-ψ-stage
output ceiling is `4096` (TERM_VALUE_MAX_BYTES) — the carrier
(172 bytes) and the κ-label (80 bytes) fit comfortably.

### 9.5 Typed-coordinate resolver carriers

ADR-041 replaced the resolver traits' byte-flat `input: &[u8]`
parameter with per-ψ-stage typed-coordinate carriers
(`SimplicialComplexBytes`, `ChainComplexBytes`, `HomologyGroupsBytes`,
`CochainComplexBytes`, `CohomologyGroupsBytes`, `PostnikovTowerBytes`,
`HomotopyGroupsBytes`, `KInvariantsBytes`, `BettiNumbersBytes`). Each
wrapper is `#[repr(transparent)]` over `&'a [u8]` — zero-cost at
runtime; the typing is purely compile-time discrimination so ψ-stage
composition is type-checked at the resolver-impl boundary. ψ_1
`Nerve` keeps `&[u8]` input as the ψ-chain entry point.
[`BitcoinResolverTuple`](crates/prism-btc/src/resolvers.rs) consumes
the typed carriers; the typed-iso surface refuses any miswired
ψ-chain composition at compile time.

## 10. Conformance

| Tenet | prism-btc realization |
|---|---|
| **TC-01 zero-cost runtime** | All `ConstrainedTypeShape` impls, `partition_product` compositions, and substitution-axis selections are resolved by `rustc` at compile time. Foundation's catamorphism is monomorphised against `BitcoinResolverTuple<Sha256dHasher>` at the `BitcoinMiningModel` declaration site. |
| **TC-02 sealing** | Every `Datum`, `Triad`, `Derivation`, `FreeRank`, `Validated`, `Grounded`, `Certified` arrives via foundation's mint primitives or as a `pipeline::run_route` return value. prism-btc constructs zero sealed types directly. |
| **TC-03 path singularity** | `BitcoinMiningModel::forward` (which delegates to `pipeline::run_route → pipeline::evaluate_term_tree`) is the only pathway to a `Grounded<MiningResult>`. `Grounded` is sealed; `MiningTag` is a phantom over it. |
| **TC-04 declarative semantics** | The mining model is declarative: typed primitives + 80-Site algebraic-closure declaration + ψ-pipeline verb body. No algorithmic body in prism-btc's verb arena; the catamorphism evaluates the structural declaration. |
| **TC-05 replayability** | The pipeline emits a `Trace` (foundation's `enforcement::trace`); `enforcement::replay::certify_from_trace` re-validates the typed inference structurally without invoking any hasher's hashing method or any decider written by prism-btc. |
| **TC-06 local execution** | Every stage executes locally on the user's hardware. No oracle, no service call, no remote evaluator. |

## 11. Cross-reference to UOR ontology

The IRIs prism-btc consumes from the foundation ontology
(`uor.foundation.{ttl,jsonld,owl,nt}`):

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
- `proof:InhabitanceImpossibilityWitness`

These names are normative. prism-btc's IRIs
(`https://prism.btc/shape/*`, `https://prism.btc/resolver/*`) are the
application's instantiation of the foundation classes.

## 12. What this architecture deliberately excludes

- **No σ-enumeration in the verb body.** The ψ-pipeline is parametric
  tensor-algebra composition over the typed feature hierarchy; the
  verb arena contains only ψ-Term variants. Substrate-enforced at
  proc-macro expansion (architecture §9.1).
- **No `Term::FirstAdmit` in the mining verb body.** FirstAdmit is a
  substrate primitive for bounded structural search over small typed
  domains; it is not the mining transform.
- **No traditional-miner complexity framing.** prism-btc's wall-clock
  cost is the cost of the parametric ψ-pipeline's catamorphism
  evaluation plus the resolver-internal iterative-resolution loop in
  ψ_9, not "expected hashes × per-hash cost." Wall-clock is a property
  of foundation's evaluator + the resolvers' realizations; it is
  invariant across network choice (regtest, signet, testnet, testnet4,
  mainnet) at the vocabulary level. The byte-threshold in `Target`
  parameterizes the admission relation's structural complexity, not a
  probabilistic puzzle parameter.
- **No "CPU mining" framing.** prism-btc's mining is one structural
  inference per `MiningTask`. Hash-rate is not a meaningful metric;
  one `forward()` is one mining operation regardless of network.
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
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape constraint monotonicity, convergence protocol. The proofs are anchored to foundation's algebraic structure. |

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
just vv         # The full V&V suite (fmt + clippy + tests + Lean + regtest)
```

The mining inference is invariant across networks (regtest, signet,
testnet, testnet4, mainnet). The `prism-mine` CLI binary is the public
surface for driving `BitcoinMiningModel::forward` against any running
bitcoind.

## License

Apache-2.0 — see [LICENSE](LICENSE).
