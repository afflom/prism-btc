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

### 1.0 Framing: ultrametric framework, causal-semantic transport

UOR provides an **ultrametric framework**: the canonical addressing
space is the set of 256-bit content-addresses produced by the σ-
projection (the canonical hash axis), equipped with the 2-adic
ultrametric `d(a, b) = 2^-{ν(a XOR b)}` where ν is the 2-adic
valuation of the XOR-difference. The address space stratifies into
nested ultrametric balls indexed by ν; the balls partition `2^256`
addresses into a hierarchy that the UOR observables read.

Prism generalizes UOR's addressing, latent embeddings, and
ultrametric hierarchies into a single **causal-semantic transport
field on a content-addressed semantic manifold**:

- **Content-addressed semantic manifold** — the space of typed
  objects, with addresses given by the σ-projection. For prism-btc,
  this is the space of typed `MiningTask` / intermediate ψ-stage /
  `MiningResult` instances, each carrying its own σ-projection
  identity.
- **Latent embeddings** — each typed object embeds into the
  manifold via foundation's `IntoBindingValue` projection plus the
  canonical hash axis. The triadic coordinates
  [`crate::TriadicCoords`](crates/prism-btc/src/domain.rs)
  (`{datum, stratum, spectrum}`) read structural observables at
  the embedding point.
- **Ultrametric hierarchy** — `stratum` is the 2-adic valuation
  observable; the 256-bit address space stratifies by `stratum`
  into ultrametric balls. The helpers
  [`crate::ultrametric_valuation`](crates/prism-btc/src/domain.rs)
  and [`crate::walsh_hadamard_parity_at`](crates/prism-btc/src/domain.rs)
  expose the ultrametric distance and the Walsh–Hadamard spectral
  observable at arbitrary bit-mask frequencies.
- **Causal-semantic transport field** — the ψ-pipeline is a
  directed field of structure-preserving morphisms over the
  manifold: ψ_k+1 ∘ ψ_k transports an embedded object from one
  ψ-stage's typed-coordinate carrier to the next, in causal
  order (ψ_1 → ψ_7 → ψ_8 → ψ_9 on the mining-transform path).
  Each ψ-stage is "semantic" — it preserves the typed structural
  invariants the downstream stage expects — and "causal" — the
  ψ-DAG is acyclic, transport flows in one direction.

[`ANALYSIS.md`](ANALYSIS.md) extends this framing into a broader
**UOR-specific cryptanalysis**: does any of the UOR-named structural
observability on the manifold (triadic, ultrametric, Walsh–Hadamard,
avalanche, autocorrelation, κ-derivation autocorrelation) expose
non-uniform-random structure in SHA-256d that could be exploited for
Bitcoin-style mining? The empirical answer, at 10⁷ samples per test,
is uniformly no — the σ-projection is hardened against the
cryptanalysis the framework can pose.

### 1.1 Vocabulary

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
| `76..80` | κ-pinned | ψ_9 resolver's structural κ-derivation projects the typed `MiningTask` via the canonical hash axis and pins the four nonce bytes simultaneously to the derivation's leading 4 bytes (architecture §4) |

Both mechanisms terminate at the same fixed point: 80 sites pinned ⇒
`FreeRank = 0` ⇒ convergence at the terminal ψ-stage. Whether the
resulting κ-label admits at the host boundary (`σ(header) ≤ target`)
is a separate question, enforced by [`crate::pipeline::mine`].

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

**ψ_9 KInvariant — the terminal label, structural κ-derivation.**
Consumes the ψ_8 HomotopyGroups carrier and emits exactly **80 bytes
— the wire-format Bitcoin header**. k-invariants
`κ_n ∈ H^{n+2}(π_1; π_{n+1})` classify the Postnikov tower's
twisted-fibration data; for the 80-isolated-vertices case
(`π_0 = 80-set`, `π_k = 0` for k ≥ 1) the k-invariant signature
itself is trivial (no obstruction classes). The terminal ψ-stage's
load-bearing computation is the **structural κ-derivation**: the
canonical hash axis projects the typed `MiningTask` to a 32-byte
content-address; the leading four bytes — in canonical Bitcoin
little-endian — are the κ-nonce that pins the four free nonce-byte
sites (positions 76..80) simultaneously. **One σ-projection per
`forward()`** — deterministic in the typed input, no enumeration,
no search. The wiki's iterative-resolution discipline converges
here: `FreeRank` over `MiningResult` drops from 4 (the four free
nonce-byte sites) to 0 (all 80 sites pinned) in this single ψ-
stage. ψ_9 always succeeds for well-formed `MiningTask` inputs.

The admission relation `σ(header) ≤ target` is **not enforced
inside the ψ-pipeline**; it is the host boundary's responsibility
(architecture §6 + §7). [`crate::pipeline::mine`] recomputes the
σ-projection on the emitted wire-format header and returns
`Ok(MiningOutcome)` when admission holds or
`Err(MiningFailure::DidNotAdmit)` when it does not. The host
boundary varies the template-derived `MiningTask` (extranonce roll
→ distinct prefix → distinct κ-derivation) until a κ-candidate
admits.

**Diagnostic surface.** ψ_9 records a [`ResolutionState`] for every
`forward()` call: `free_rank` (always 0 — convergence) plus
`derived_nonce` (the κ-derivation). The host reads it via
[`crate::pipeline::MiningOutcome::resolution`] on the `Ok` path or
[`crate::diagnostics::take_resolution_state`] on the `Err` path.
The channel is thread-local; concurrent miners on separate threads
are independent.

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

**Bit-identicality.** `BitcoinMiningModel::forward(task)` returns a
`Grounded<MiningResult>` whose `output_bytes()` are exactly 80 bytes —
the wire-format Bitcoin header (`prefix(76) ‖ nonce(4 LE)`). The
leading 76 bytes are unchanged from `task.prefix`; the trailing 4
bytes are ψ_9's κ-derivation. `forward()` always succeeds for well-
formed inputs — the ψ-pipeline is total over the typed input
surface.

**Fail-closed admission, enforced at the host boundary.** The host
entry point `mine(header, target)` recomputes the σ-projection on
the κ-derived wire-format header and checks `σ(header) ≤ target`.
It returns:

- `Ok(MiningOutcome)` — admission holds; the wire-format header is
  a valid mined block.
- `Err(MiningFailure::DidNotAdmit)` — the κ-candidate's σ-projection
  did not satisfy `target`. The host (architecture §7) varies the
  template-derived `MiningTask` (extranonce roll → distinct prefix
  → distinct κ-derivation) and retries.

**`mine()` never returns a `MiningOutcome` whose header does not
admit** — the boundary check is the fail-closed gate.

The bit-identicality guarantee composes from the structural commitments:

1. `Header`'s composition via `partition_product(Version, PrevHash,
   MerkleRoot, Timestamp, Bits, Nonce)` enforces the canonical 80-byte
   layout.
2. The structural admission constraint on `MiningResult` declares the
   admission relation (80 disjoint Site constraints — algebraic
   closure) in wire-format terms.
3. The label's bytes are produced by the ψ-pipeline's parametric
   transformations operating on the typed feature hierarchy — the
   structural witness's `IntoBindingValue::into_binding_bytes`
   projection *is* the wire-format Header (and, at the host boundary,
   the wire-format Block).
4. The boundary's submitblock assembly (§7) is byte-for-byte the same
   serialization Bitcoin Core itself uses.

**Network-invariant.** The mining inference is identical across
regtest, signet, testnet, testnet4, and mainnet: same
`BitcoinMiningModel`, same ψ-pipeline verb body, same
`BitcoinResolverTuple`, same κ-derivation. The network-dependent
value is the byte threshold encoded in the template's `Bits` field;
that threshold is carried into the typed `MiningTask` and threaded
to ψ_9, but ψ_9 does not consult it (the κ-derivation is over the
threaded task content as a whole). For each `MiningTask`, `mine()`
produces one structural candidate; whether it admits is the
boundary's check. Across networks the **per-`forward()` cost is
constant**; the network-dependent quantity is the number of
template variations the host has to attempt, not the cost per
attempt.

## 7. Host boundary

`crates/prism-btc-node/` is the bitcoind boundary. It is **not** part
of the typed-iso transform; it adapts between prism's typed-iso
surface and Bitcoin Core's JSON-RPC surface, owns the **template-
variation loop** that iterates `MiningTask` inputs across distinct
κ-derivations, and enforces the admission relation
`σ(header) ≤ target` that gates `MiningOutcome`.

`PrismMiner::mine_one_block`'s loop:

1. Call `getblocktemplate` once per block attempt.
2. Initialize `extranonce = 0`.
3. Compose the coinbase transaction with the user's payout address
   and the current extranonce (which lands in the coinbase's
   `scriptSig`).
4. Derive the `MerkleRoot` from the modified coinbase + the
   template's transaction list.
5. Build a `MiningTask` from `(version, prev_hash, merkle_root,
   timestamp, bits, decoded_target)`.
6. Call `prism_btc::mine(header, target)`. One structural inference:
   ψ_9 κ-derives a candidate; the boundary admission check decides.
   - `Ok(outcome)` ⇒ assemble the wire-format Block, submit via
     `submitblock`, return summary.
   - `Err(MiningFailure::DidNotAdmit)` ⇒ the κ-derivation for this
     `(prefix, target)` did not satisfy `target`. Increment
     `extranonce`, goto step 3. The wrapped extranonce (after
     `~10¹⁹` variations) signals exhaustion — the chain has
     typically advanced first, so the caller fetches a new template.

The boundary's outer loop is the wire-format adaptation — coinbase
construction, merkle derivation, RPC plumbing — plus the per-
template admission gate. From `forward()`'s perspective every call
is one structural inference at constant cost; the boundary loop is
where target-restrictiveness shows up as more template variations
(more `MiningTask`s tried), never as more work per `forward()`.

The pure-Rust SHA-256 helpers in `crates/prism-btc/src/ops/sha256.rs`,
`ops/merkle.rs`, and `ops/header.rs` exist **only** to serialize
bytes for the bitcoind RPC boundary and the host-side σ-projection
recomputation in `mine()`. They are not invoked inside the ψ-pipeline
transform. The σ-projection inside the transform is the canonical
hash axis (`Sha256dHasher`) consumed by resolvers — once per
`forward()`, by ψ_9, for the κ-derivation — and never from the verb
body.

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

// UOR-optimal mining: typed Conjunction commitment (architecture §14)
pub use pipeline::{mine_with_commitment, MiningCommitment, Predicate};

// Iterative-resolution diagnostic surface
pub use diagnostics::{ResolutionState, take_resolution_state};

// UOR observable surface (manifold helpers; ANALYSIS.md §1.3)
pub use domain::{p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at};

// Host-boundary witnesses
pub use domain::{MiningTag, MiningWitness, TriadicCoords};
```

`mine(header: &BlockHeader, target: Target) → Result<MiningOutcome, MiningFailure>`
builds a `MiningTask` from the host-side `BlockHeader` + `Target`,
invokes `BitcoinMiningModel::forward` (which always produces a
κ-label candidate for well-formed inputs), and enforces the boundary
admission relation `σ(header) ≤ target`. On `Ok`, `MiningOutcome`
carries the foundation-sealed `Grounded<MiningResult>`, the
display-order digest, and `resolution: ResolutionState` (the κ-
derived nonce + the `free_rank = 0` convergence observable). On
`Err(MiningFailure::DidNotAdmit)`, [`take_resolution_state`] returns
ψ_9's `ResolutionState` so the host can inspect the κ-derivation
that didn't admit.

`mine_with_commitment(header, target, &commitment) → Result<MiningOutcome, MiningFailure>`
is the UOR-optimal mining entry point (architecture §14): the
host-boundary admission gate is augmented with a Conjunction of
typed [`Predicate`] instances spanning the UOR observable library
(Walsh–Hadamard parity, 2-adic stratum equality, p-adic equality,
ultrametric closeness). Returns `Ok` iff the κ-label satisfies both
admission and every commitment predicate; expected cost grows as
`α^-1 × 2^B` template variations per ANALYSIS.md §5.5 (U6
Bandwidth-Additivity), where `B = commitment.bandwidth_bits()` is
the sum of per-predicate bandwidth contributions.

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
upstream π_0-only geometry, then performs the structural κ-
derivation that pins the four nonce-byte sites and emits the
wire-format Bitcoin header. Each non-terminal stage emits a 208-byte
structural carrier (architecture §4); each downstream stage
validates the upstream stage tag and structural geometry before
emitting. ψ_2/ψ_3/ψ_5/ψ_6 are off the mining-transform path (the
verb body composes only ψ_1, ψ_7, ψ_8, ψ_9) but compute their
stage's content for substitution-axis completeness under ADR-036.

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

### 9.6 Iterative-resolution discipline

The wiki's [`iterative-resolution.md`](https://github.com/UOR-Foundation/UOR-Framework/blob/main/docs/content/concepts/iterative-resolution.md)
names the resolver-internal iteration model: each ψ-stage pins free
sites, `FreeRank` is the count of unpinned sites at any point,
convergence is `FreeRank = 0`. prism-btc realizes the discipline as
ψ-stage progression: ψ_1 → ψ_7 → ψ_8 advance the structural
carriers; ψ_9 performs the terminal κ-derivation that pins the
four nonce-byte sites (positions 76..80) simultaneously, dropping
`FreeRank` from 4 to 0 in one stage. The discipline converges at
the terminal ψ-stage for every well-formed `MiningTask` — there is
no impossibility verdict inside the ψ-pipeline; whether the
κ-derived header admits at the host boundary is a separate question
(architecture §6 + §7). prism-btc surfaces ψ_9's state via
[`crate::diagnostics`](crates/prism-btc/src/diagnostics.rs).

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
- **No traditional-miner complexity framing.** prism-btc's
  per-`forward()` cost is constant — one ψ-pipeline pass with ψ_9's
  one σ-projection for the κ-derivation, plus the host-boundary's
  one σ-projection for the admission check. There is no
  "expected hashes × per-hash cost", no inner search loop. The
  byte-threshold in `Target` parameterizes the boundary admission
  relation, not a probabilistic puzzle parameter; the
  network-dependent quantity is the number of template variations
  the host has to attempt, not the cost per attempt.
- **No "CPU mining" or hashrate framing.** prism-btc's mining is
  one structural inference per `MiningTask`. Hash-rate is not a
  meaningful metric for this implementation; one `forward()` is one
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
| [`prism-btc-lean/`](prism-btc-lean/) | Lean 4 formal proofs: ring identity (W8/W32), triadic coordinates, FreeRank protocol, shape constraint monotonicity, convergence protocol. The proofs are anchored to foundation's algebraic structure. |

## 14. UOR-optimal mining: bandwidth-aware Conjunction commitment

The cryptanalysis battery (ANALYSIS.md §3) confirms that no UOR
observable on the σ-projection's output exposes admission-relevant
structure under PRF, and ANALYSIS.md §5 shows the substrate's
`type:Conjunction` primitive is a **typed information channel** over
the σ-projection: K independent 1-bit predicates encode K bits of
structural commitment in the κ-label at expected
`2^K × α^-1` template variations.

This section names the **optimal mining surface** prism-btc exposes
within that framework, and the implementation that realizes it.

### 14.1 What "optimal" means under UOR

Under the random-oracle baseline:

- The bare admission relation `σ(header) ≤ target` has PRF
  probability `α` (= `target / 2²⁵⁶`). Expected template variations
  to find one admitting κ-label: `α^-1`. This bound is **fundamental**
  — no UOR observable cheaper than σ itself can reduce it (ANALYSIS.md
  §4.1 U3 admission-orthogonality).
- The κ-label, when found, carries `log₂ α^-1` bits of "raw" entropy
  beyond the wire-format prefix. Standard mining discards this
  entropy; the κ-label happens to satisfy admission, full stop.
- The σ-projection Hardening Principle's U6 Bandwidth-Additivity
  lets the application **reclaim** part of that entropy as
  structural bandwidth: K independent typed predicates
  Conjunction'd onto admission cost a `2^K` factor in expected
  variations but deliver K bits of application-declared commitment
  per κ-label.

**Optimal UOR mining** is therefore the **Pareto frontier**: for any
target admission rate, the application chooses K (the bandwidth)
and pays `2^K × α^-1` expected variations. Smaller K means cheaper
mining; larger K means more structural information per mined block.
The frontier is sharp under PRF — there is no UOR-structural
shortcut that delivers bandwidth without paying the proportional
PRF cost.

### 14.2 Implementation surface

`crates/prism-btc/src/pipeline.rs` exposes the optimal-mining
surface:

```rust
pub enum Predicate {
    Parity              { omega: [u8; 32], expected: u32 },
    StratumEq           { k: u32 },
    PAdicEq             { p: u64, k: u32 },
    UltrametricCloseTo  { reference: [u8; 32], k: u32 },
}

pub struct MiningCommitment { /* Vec<Predicate> */ }

pub fn mine_with_commitment(
    header: &BlockHeader,
    target: Target,
    commitment: &MiningCommitment,
) -> Result<MiningOutcome, MiningFailure>;
```

The [`Predicate`] enum names the typed predicate library —
each variant is one of the UOR observables that the cryptanalysis
battery (ANALYSIS.md §3) confirmed admission-orthogonal under PRF:

| Variant | Predicate condition | PRF probability | Bandwidth (bits) |
|---|---|---|---|
| `Parity { ω, e }` | `walsh_hadamard_parity_at(d, ω) == e` | `1/2` | `1` |
| `StratumEq { k }` | `stratum(d) == k` | `2⁻⁽ᵏ⁺¹⁾` | `k + 1` |
| `PAdicEq { p, k }` | `p_adic_valuation(d, p) == k` | `(p − 1)/p^(k+1)` | `(k+1)·log₂p − log₂(p−1)` |
| `UltrametricCloseTo { r, k }` | `ultrametric_valuation(d, &r) ≥ k` | `2⁻ᵏ` | `k` |

Each variant exposes `Predicate::evaluate(digest) -> bool` and
`Predicate::bandwidth_bits() -> f64`. The variants span
2-adic / 2-adic-shifted / p-adic / ultrametric observables — every
elementary observable on the content-addressed manifold the
analysis battery covered.

[`MiningCommitment`] is a runtime Conjunction of K `Predicate`
instances. Typed builders:

```rust
let commitment = MiningCommitment::empty()
    .add_parity(omega, 1)                 // +1 bit
    .add_stratum_eq(3)                    // +4 bits
    .add_p_adic_eq(3, 0)                  // +~0.585 bits
    .add_ultrametric_close_to(reference, 7); // +7 bits
// commitment.bandwidth_bits() ≈ 12.585
```

The substrate's [`uor_foundation::pipeline::ConstraintRef::Conjunction`]
variant is the compile-time analogue for fixed commitments declared
at type-definition time. [`mine_with_commitment`] wraps [`mine`]
with the additional boundary check `commitment.evaluate(&digest)`.
The fail-closed contract holds across both axes:
`Ok(MiningOutcome)` is returned only when both admission AND every
commitment predicate hold.

**Bandwidth-additivity (U6) — enforced at the typed-iso surface.**
`MiningCommitment::bandwidth_bits()` returns the sum of per-predicate
contributions. Per
[`PrismBtc.CommitmentChannel.bandwidth_append`](../prism-btc-lean/PrismBtc/CommitmentChannel.lean),
the Conjunction is monoidal under list-concatenation: bandwidth and
evaluation distribute over commitment concatenation algebraically.

The probabilistic content of U6 (PRF cost = `α⁻¹ · 2^bandwidth_bits`)
holds when the predicates are **jointly independent**. prism-btc
turns this from an honor-system upper bound into a typed-iso
invariant via the [`Support`] type:

```rust
pub enum Support {
    BitSet([u8; 32]),     // bit-position support
    Modular { p: u64 },   // mod-p^* support (p ≥ 3)
}
```

Each `Predicate` exposes `support() -> Support`. Two supports are
**disjoint** iff predicates with these supports are jointly
independent under PRF:

- `BitSet(a)` ⊥ `BitSet(b)` ⇔ `a & b == 0` (bit-disjoint masks).
- `Modular { p }` ⊥ `BitSet(_)` ⇔ `p ≠ 2`.
- `Modular { p₁ }` ⊥ `Modular { p₂ }` ⇔ `p₁ ≠ p₂` (coprime primes).

`PAdicEq { p: 2, k }` is canonicalized to `BitSet(low_bits_mask(k+1))`
at `Predicate::support()` so its independence with bit-set
predicates is checked correctly.

[`MiningCommitment::add_predicate`] panics on overlap;
[`MiningCommitment::try_add_predicate`] returns
[`CommitmentError::OverlappingSupport { existing_index }`]. A
commitment built only via the typed builders is **well-formed by
construction** (all pairwise supports disjoint), so
`bandwidth_bits()` is a tight bound on the PRF mining cost — not an
upper bound. The Lean theorem
[`Commitment.wellFormed`](../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
formalizes the invariant.

### 14.3 Empirical scaling

The example `crates/prism-btc/examples/optimal_mining.rs` runs a
K-sweep at regtest target `0x207fffff` (`α ≈ 1/2`), averaging
`N_TRIALS = 50` independent template searches per K. Each search
rolls the timestamp until [`mine_with_commitment`] returns `Ok`;
the function defensively re-checks both admission and the
commitment on every successful outcome.

| K | bandwidth | PRF prediction (2 · 2^K) | observed mean variations | ratio |
|---:|---:|---:|---:|---:|
| 0 | 0 bits | 2 | 1.9 | 0.94× |
| 1 | 1 bit  | 4 | 3.1 | 0.78× |
| 2 | 2 bits | 8 | 7.0 | 0.88× |
| 3 | 3 bits | 16 | 12.2 | 0.76× |
| 4 | 4 bits | 32 | 30.7 | 0.96× |
| 5 | 5 bits | 64 | 64.7 | 1.01× |
| 6 | 6 bits | 128 | 134.9 | 1.05× |

Ratios cluster around 1.0 within ~25% sampling variance at N = 50;
the step-to-step doubling is sharp. Reproduce via
`cargo run --release --example optimal_mining`.

### 14.4 Reading the κ-label as a typed commitment

Every block mined via [`mine_with_commitment`] is wire-format-valid
for Bitcoin's `submitblock` — Bitcoin Core does not see or check
the application's typed predicates. But any verifier of the
application's protocol can re-evaluate the K predicates on the
published κ-label and read off the K bits of structural commitment.
The κ-label is thus simultaneously:

1. A valid Bitcoin block header (PoW + structure as Bitcoin
   demands), and
2. A typed commitment to K bits of application-declared
   information.

The 80-byte κ-label is the same object on both axes — what differs
is which observer reads it. This is the Shannon-channel
construction of ANALYSIS.md §5.4, realized for Bitcoin via
prism-btc's typed-iso surface.

### 14.5 Pareto-optimality and the limits of UOR

The Pareto frontier `cost(K) = 2^K × α^-1` is **tight** under PRF:
- Lower bound. ANALYSIS.md §4.1 U3 (admission-orthogonality) plus
  U6 (bandwidth-additivity) imply that no UOR observable cheaper
  than σ predicts joint commit-admission. Any procedure for
  finding commit-admitting κ-labels must therefore evaluate σ on
  Ω(`2^K × α^-1`) candidates in expectation.
- Upper bound. The implementation matches this asymptotic exactly
  (§14.3 empirical results within sampling variance of the
  prediction).

The framework therefore identifies **mining cost** with **the
information content of the κ-label**: at PRF baseline, mining
`log₂ α^-1 + K` bits of structural information takes
`2^(log₂ α^-1 + K) = α^-1 × 2^K` σ-evaluations. The application
chooses how to allocate that bandwidth — between admission
(Bitcoin's network-wide protocol) and Conjunction predicates
(application-declared commitments).

What UOR cannot improve on (ANALYSIS.md §4.4 boundaries):
- The per-σ-evaluation cost (substitution-axis selection, ADR-030).
- The fundamental PRF lower bound — quantum oracles give `√` in
  preimage search but UOR observability does not narrow the
  search further.
- Input-side algebraic structure attacks, side-channel leakage,
  adversarial-input attacks (all out of UOR's observability
  surface).

prism-btc's `mine_with_commitment` is therefore the **absolute
optimal** mining surface within UOR's framework: it realizes every
bit of bandwidth that the σ-projection's PRF baseline makes
available, with no concession to traditional miner tropes (no
hashrate metric, no GPU offload, no W32 walk inside the ψ-pipeline).

## 15. Performance model

prism-btc commits to **one structural inference per `MiningTask`**.
The cost of that inference is constant — independent of the
`target` byte threshold, independent of the network. There is no
loop inside `forward()` whose iteration count depends on the input;
ψ_9's κ-derivation is one σ-projection on the threaded task, and
every other ψ-stage is a structural-carrier emit.

The architectural levers that keep per-`forward()` cost minimal:

- **Compile-time validation.** `MiningResult::CONSTRAINTS`' 80-
  disjoint-Site IT_7d shape is a compile-time invariant — asserted
  by a `const _: () = { … }` block in
  [`crates/prism-btc/src/resolvers.rs`](crates/prism-btc/src/resolvers.rs).
  ψ_1's runtime body does not re-validate; any malformed CONSTRAINTS
  declaration fails the build before ψ_1 ever runs.
- **Const carrier-tail template.** The geometry tail every non-
  terminal ψ-stage writes (`vertex_count = 80`, `highest_dim = 0`,
  the 80 Site positions) lives as a 92-byte compile-time constant
  [`CARRIER_GEOMETRY_TAIL`](crates/prism-btc/src/resolvers.rs). Each
  per-stage `emit_carrier` is three `copy_from_slice` calls — no
  per-field arithmetic, no `for i in 0..80` loop.
- **`#[inline]` on trivial resolver bodies.** ψ_1..ψ_8 are decode-
  validate-emit functions; inlining lets LLVM fuse them with the
  catamorphism's per-Term dispatch.
- **No heap allocations in `mine()`.** The carrier buffers live in
  foundation's pre-sized scratch space (per `PrismBtcBounds`); the
  `MiningOutcome` is constructed on the stack.

The cost of the σ-projection inside ψ_9 (and the second σ-projection
at the host boundary for the admission check) is the canonical hash
axis's affair — a substitution-axis selection per ADR-030, not an
implementation surface prism-btc tunes. The architecture's
structural-inference framing (§12) treats the σ-projection as a
typed primitive; its wall-clock cost is whatever the chosen hash
axis delivers.

### 14.1 Benchmarks

[`crates/prism-btc/benches/mining.rs`](crates/prism-btc/benches/mining.rs):

| Bench | What it measures |
|---|---|
| `mine/one_structural_inference` | One full `mine()` call: ψ_1 → ψ_7 → ψ_8 → ψ_9 structural κ-derivation plus the host-boundary admission check. Constant per call, independent of target. |
| `misc/target_check_reject` | Lex-≤ on a non-satisfying digest vs target — the boundary admission relation in isolation. |
| `misc/triadic_coords_from_hash` | `TriadicCoords` projection on a 32-byte digest. |

Run: `cargo bench -p prism-btc`. The metric is **wall-clock per
`mine()`** — the cost of one structural inference. There is no
"throughput" or "rate" metric here; prism-btc commits to one
inference per `MiningTask`, and the boundary loop's variation count
is a property of the target, not of the implementation.

## 16. Quick start

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
