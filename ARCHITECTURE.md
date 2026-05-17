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
> **Output contract.** The 32-byte κ-label emitted by ψ_9 is the
> SHA-256d digest of the reconstructed wire-format Bitcoin header per
> wiki ADR-048/049's natural cost-model framing; foundation's
> `LexicographicLessEqThreshold` predicate consumes that digest inside
> `run_route` as Bitcoin's admission relation. The reconstructed
> 80-byte wire-format header is surfaced on the success path as
> `MiningOutcome.wire_format_header` — byte-for-byte what
> `submitblock` accepts. The mining inference is identical across
> regtest, signet, testnet, testnet4, and mainnet; the only
> network-dependent value is the runtime target threshold encoded in
> the template's `bits` field.

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
  parametric transformation generates. For Bitcoin under wiki ADR-048/049,
  the label is the 32-byte SHA-256d digest (the natural cost-model
  κ-label); the 80-byte wire-format Bitcoin header is the
  reconstruction at the prism-btc boundary that `submitblock` accepts.

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
| `MiningTask` | `partition_product(TemplatePrefix, Target)` | 108 W8 | The typed PrismModel input (`H, B, A, R, C`'s `Input` slot) |
| `MiningResult` | The 32-byte SHA-256d κ-label foundation's `LexicographicLessEqThreshold` predicate compares against the target | 32 W8 | The natural cost-model κ-label per wiki ADR-048/049 |
| `wire_format_header` | Reconstructed at the prism-btc boundary from `(template_prefix, derived_nonce)` — the 80-byte canonical Bitcoin header | 80 W8 | Boundary artifact for `submitblock`; *not* the κ-label |
| `Block` | `operad_composition(wire_format_header, Transactions[])` | variable | The full wire-format block (host-boundary level; see §7) |

The composition is **declarative**, not algorithmic. The cost-model
κ-label is the digest, not the wire-format header: foundation's
`LexicographicLessEqThreshold` predicate (wiki ADR-049) compares a
byte sequence against the target threshold, and that byte sequence IS
the 32-byte SHA-256d digest. The 80-byte wire-format header is
reconstructed at the prism-btc boundary (architecture §7) for
`submitblock`; it is the byte-identical artifact Bitcoin Core
accepts, but it is *not* what the typed-iso surface's commitment
evaluates.

### 2.3 The admission constraint — algebraic-closure encoded

`MiningResult::CONSTRAINTS` declares **32 disjoint `ConstraintRef::Site`
instances** — one per κ-label digest byte position (0..32) — the
algebraic-closure encoding per the UOR Index Theorem IT_7d
([`analytical-completeness.md`](https://github.com/UOR-Foundation/UOR-Framework/blob/main/docs/content/concepts/analytical-completeness.md)).
Each constraint pins exactly one site; site supports are pairwise
disjoint; the constraint nerve N(C) is **32 isolated vertices, no
higher simplices**:

```
χ = SITE_COUNT = 32
β_0 = 32,    β_k = 0 for k ≥ 1
χ(N(C)) = β_0 − β_1 + … = 32 = SITE_COUNT
```

— the framework's algebraic-closure criterion (*resolution is
complete iff χ(N(C)) = n and all β_k = 0*) is satisfied at the
declaration level. The wiki's iterative-resolution discipline
(`iterative-resolution.md`) converges in `n − χ(N(C)) = 0` residual
rank.

All 32 sites are **κ-pinned by ψ_9 simultaneously**: the terminal
resolver structurally κ-derives a 4-byte nonce from the typed
`MiningTask` via the canonical hash axis, reconstructs the 80-byte
wire-format Bitcoin header from `(template_prefix, derived_nonce)`,
and emits `SHA-256d(wire_format_header)` as the 32-byte κ-label.
FreeRank over `MiningResult` drops from 32 to 0 in this single
terminal stage. Whether the κ-label admits is decided **inside
foundation's `run_route`** by the model's pinned
`C: TypedCommitment` (architecture §5, §6), not at the prism-btc
boundary.

The encoding is pinned by V&V tests in
[`crates/prism-btc/tests/verification.rs`](crates/prism-btc/tests/verification.rs):
32 disjoint Site constraints, 32 isolated nerve vertices, site
supports spanning [0, 32) exactly.

## 3. Substitution axes

Foundation's `PrismModel<HostTypes, HostBounds, Hasher, ResolverTuple,
TypedCommitment>` fixes prism-btc's five substitution axes (ADR-007,
ADR-010, ADR-018, ADR-030, ADR-036, ADR-048):

| Axis | prism-btc selection | Role |
|---|---|---|
| `HostTypes` | `DefaultHostTypes` | Foundation-default host-side type carriers |
| `HostBounds` | `PrismBtcBounds` | `WITT_LEVEL_MAX_BITS = 32`, `FINGERPRINT_{MIN,MAX}_BYTES = 32`, `TRACE_MAX_EVENTS = 64`, `NERVE_SITES_MAX = 80`, `NERVE_CONSTRAINTS_MAX = 128`, `BETTI_DIMENSION_MAX = 80`, `AFFINE_COEFFS_MAX = 80`, `CONJUNCTION_TERMS_MAX = 128` |
| `Hasher` | `Sha256dHasher` | Canonical hash axis (axis_index=0, kernel_id=0). Pure-Rust SHA-256-then-SHA-256. Content-addressing bijection for double-SHA-256-bound Bitcoin types. **Not the mining transform** — the σ-projection is a content-addressing primitive, not an algorithm prism-btc runs. |
| `ResolverTuple` | `BitcoinResolverTuple<Sha256dHasher>` | Bitcoin-specific realization of the 8 resolver-bound ψ-stages. Each resolver names what the parametric tensor-algebra functor computes for Bitcoin's typed feature hierarchy. |
| `TypedCommitment` | `crate::commitment::TargetCommitment` | The cost-model commitment surface (wiki ADR-048). `BitcoinMiningModel` binds `C = TargetCommitment`, foundation's alias for `SingletonCommitment<LexicographicLessEqThreshold>` (wiki ADR-040 + ADR-049). Foundation 0.4.12 ships `LexicographicLessEqThreshold` as the canonical byte-threshold `ObservablePredicate`, so Bitcoin's `digest ≤ target` admission relation is a typed predicate the catamorphism evaluates inside `run_route` — *not* a host-boundary gate. The prism contract `operational = declared at equality` therefore ranges over the typed admission gate. |

`PrismBtcBounds`' `WITT_LEVEL_MAX_BITS = 32` matches Bitcoin's `Nonce`
field exactly. Higher Witt levels are not required — the typed surface's
algebra is W32-bounded; nothing in prism-btc enumerates a domain larger
than what Bitcoin's wire-format already encodes. The nerve and Betti
ceilings (`NERVE_SITES_MAX = 80`, `BETTI_DIMENSION_MAX = 80`)
accommodate `TemplatePrefix`'s 76-site geometry plus headroom; the
κ-label's 32-site geometry fits comfortably within them.

**The 5th-position binding is load-bearing.** Pinning
`C = TargetCommitment` realizes wiki QS-06's "declare a
`PrismModel<…, C>` with C pinned to your chosen typed-bandwidth
conjunction" exemplar shape: foundation's `run_route` consults
`commitment.evaluate(kappa_label)` before sealing the
`Grounded<MiningResult>`, so admission failure surfaces as
`PipelineFailure::ShapeViolation` with the
`commitment/TypedCommitment/VIOLATED` shape IRI — classified at the
prism-btc boundary as `MiningFailure::DidNotAdmit` (§6, §7).

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
Consumes the ψ_8 HomotopyGroups carrier and emits exactly **32 bytes
— the SHA-256d digest κ-label** (wiki ADR-048/049's natural
cost-model surface). k-invariants
`κ_n ∈ H^{n+2}(π_1; π_{n+1})` classify the Postnikov tower's
twisted-fibration data; for the isolated-vertices case
(`π_0 = SITE_COUNT-set`, `π_k = 0` for k ≥ 1) the k-invariant
signature itself is trivial (no obstruction classes). The terminal
ψ-stage's load-bearing computation is the **structural
κ-derivation**: the canonical hash axis projects the typed
`MiningTask` to a 32-byte content-address, the leading four bytes
— in canonical Bitcoin little-endian — are the κ-nonce that pins
the wire-format-header nonce slot, and ψ_9 then reconstructs the
80-byte wire-format Bitcoin header from `(template_prefix,
derived_nonce)` and emits `SHA-256d(wire_format_header)` as the
32-byte κ-label. **One canonical-hash-axis projection plus one
SHA-256d evaluation per `forward()`** — deterministic in the typed
input, no enumeration, no search. The wiki's iterative-resolution
discipline converges here: `FreeRank` over `MiningResult` drops from
32 (the 32 digest sites) to 0 in this single ψ-stage. ψ_9 always
succeeds for well-formed `MiningTask` inputs.

The admission relation `σ(header) ≤ target` is **evaluated inside
foundation's `run_route` catamorphism** — not at a host-boundary
gate. `BitcoinMiningModel`'s 5th-slot `C = TargetCommitment` (§3, §5)
pins admission as
`SingletonCommitment<LexicographicLessEqThreshold>`; `run_route`
consults `commitment.evaluate(kappa_label)` immediately after ψ_9
emits the digest. On rejection it returns
`PipelineFailure::ShapeViolation` with the
`commitment/TypedCommitment/VIOLATED` shape IRI;
[`crate::pipeline::mine`] classifies that as
`Err(MiningFailure::DidNotAdmit { observables, nonce, digest })`. The
receiver-side typed lens is **total** — every inference exposes the
candidate's typed property landscape regardless of admission, so the
host loop can fold each attempt into a
[`crate::campaign::CampaignStats`] aggregate observatory. The host
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

`BitcoinMiningModel` realizes wiki ADR-048's **5-position
`PrismModel<H, B, A, R, C>` form** with the 5th slot binding
Bitcoin's admission relation as a typed predicate:

```rust
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        crate::commitment::TargetCommitment      // ← ADR-048 5th-position
    > for BitcoinMiningModel {
        type Input = MiningTask;
        type Output = MiningResult;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            mining_inference(input)
        }
        fn commitment() -> crate::commitment::TargetCommitment {
            crate::commitment::target_commitment(
                crate::pipeline::current_thread_target()
            )
        }
    }
}
```

The `commitment()` clause reads the active target from a
thread-local slot — foundation's `LexicographicLessEqThreshold::target`
requires `&'static [u8]` (the predicate is `Copy`), so per-call target
bytes are leaked into a process-lifetime registry by
[`crate::commitment::leak_target`]. Bitcoin's difficulty retarget
every 2016 blocks bounds the registry size to `O(epochs)` in
practice; the registry deduplicates so repeat calls with the same
bytes return the same `&'static` reference.

`forward(task: MiningTask) → Result<Grounded<MiningResult>, PipelineFailure>`
is the canonical typed-iso surface. Foundation's `run_route` drives
the catamorphism end-to-end, dispatches each ψ-Term through
`BitcoinResolverTuple`, and — once ψ_9 emits the 32-byte κ-label —
evaluates `TargetCommitment::evaluate(kappa_label)`. On admission it
seals a `Grounded<MiningResult>` whose `output_bytes()` carry the
32-byte digest; on rejection it returns `PipelineFailure::ShapeViolation`
with the commitment-violation shape IRI.

## 6. Bit-identicality and fail-closed contract

**Wire-format bit-identicality.** ψ_9 internally reconstructs the
80-byte Bitcoin wire-format header from `(template_prefix,
derived_nonce)` to compute the κ-label, and the prism-btc boundary
surfaces that header on the success path as
`MiningOutcome.wire_format_header: [u8; 80]`. The reconstructed
header is byte-for-byte what Bitcoin Core's `submitblock` accepts:
the leading 76 bytes are unchanged from `task.prefix`, the trailing
4 bytes are ψ_9's κ-derivation in canonical Bitcoin LE. ψ_9 emits
the SHA-256d *digest* of this header as the κ-label per wiki
ADR-048/049's natural cost-model framing; the 80-byte wire form is
the *reconstruction at the boundary*, not the κ-label itself.

**Fail-closed admission, evaluated inside `run_route`.** Foundation's
catamorphism consults `BitcoinMiningModel`'s pinned
`C = TargetCommitment` (§3, §5) on the 32-byte κ-label immediately
after ψ_9 emits it. The catamorphism either seals a
`Grounded<MiningResult>` (admission holds) or returns
`PipelineFailure::ShapeViolation` with the
`commitment/TypedCommitment/VIOLATED` shape IRI (admission fails).
`[crate::pipeline::mine]` classifies the result:

- `Ok(MiningOutcome)` — admission held inside `run_route`; the
  reconstructed `wire_format_header` is a valid mined block. Carries
  `observables: KappaObservables`.
- `Err(MiningFailure::DidNotAdmit { observables, nonce, digest })` —
  the catamorphism reported the commitment-violation shape IRI: the
  κ-candidate's digest did not satisfy `target` under
  `LexicographicLessEqThreshold`. The candidate's typed property
  landscape is exposed in the payload; the receiver-side lens is
  total. The host (architecture §7) varies the template-derived
  `MiningTask` and retries, folding each attempt's observables into a
  `CampaignStats` aggregate.
- `Err(MiningFailure::PipelineFailure)` — defensive: a substrate-level
  shape violation surfaced *before* the commitment stage. Unreachable
  for well-formed `MiningTask` inputs (the ψ-pipeline is total over
  the typed input surface); conformance test CM-2 pins this
  unreachability across the mainnet difficulty history.

**`mine()` never returns a `MiningOutcome` whose digest does not
admit** — the typed-iso gate is inside the catamorphism, not at the
host boundary.

The wire-format-identicality guarantee composes from the structural
commitments:

1. `TemplatePrefix`'s composition via `partition_product(Version,
   PrevHash, MerkleRoot, Timestamp, Bits)` enforces the canonical
   76-byte layout.
2. The structural admission constraint on `MiningResult` declares the
   32-Site algebraic-closure encoding of the κ-label (§2.3).
3. ψ_9's internal reconstruction of the 80-byte wire-format header
   uses the canonical Bitcoin serialization (`prefix(76) ‖ nonce(4
   LE)`); the same serialization is surfaced as
   `outcome.wire_format_header` for the boundary.
4. The boundary's `submitblock` assembly (§7) is byte-for-byte the
   same serialization Bitcoin Core itself uses.

**Network-invariant.** The mining inference is identical across
regtest, signet, testnet, testnet4, and mainnet: same
`BitcoinMiningModel`, same ψ-pipeline verb body, same
`BitcoinResolverTuple`, same κ-derivation, same `TargetCommitment`
shape. The network-dependent value is the byte threshold the
template's `Bits` field decodes to; that threshold pins
`LexicographicLessEqThreshold::target` for the call. For each
`MiningTask`, `mine()` produces one structural candidate; whether
it admits is decided inside `run_route`. Across networks the
**per-`forward()` cost is constant**; the network-dependent quantity
is the number of template variations the host has to attempt, not
the cost per attempt.

## 7. Host boundary

`crates/prism-btc-node/` is the bitcoind boundary. It is **not** part
of the typed-iso transform; it adapts between prism's typed-iso
surface and Bitcoin Core's JSON-RPC surface, owns the **template-
variation loop** that iterates `MiningTask` inputs across distinct
κ-derivations, and **classifies** the typed-iso surface's outcome
(admission is evaluated inside `run_route`, not here — see §6).

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
6. Call `prism_btc::mine(header, target)`. One structural inference;
   foundation's `run_route` evaluates `TargetCommitment` on the
   κ-label inside the catamorphism, and prism-btc classifies:
   - `Ok(outcome)` ⇒ fold `outcome.observables` into the session's
     `CampaignStats`, assemble the wire-format Block from
     `outcome.wire_format_header` + the template's transaction list,
     submit via `submitblock`, return summary (with the campaign
     aggregate).
   - `Err(MiningFailure::DidNotAdmit { observables, digest, .. })` ⇒
     foundation's `run_route` reported the commitment-violation shape
     IRI; the κ-derivation for this `(prefix, target)` did not satisfy
     `target`. Fold the candidate's observables into the campaign
     (the receiver-side lens is total), then increment `extranonce`
     and goto step 3. The wrapped extranonce (after `~10¹⁹`
     variations) signals exhaustion — the chain has typically
     advanced first, so the caller fetches a new template.
   - `Err(MiningFailure::PipelineFailure)` ⇒ defensive surface for a
     substrate-level shape violation *before* the commitment stage.
     Unreachable in normal flow (CM-2).

The boundary's outer loop is the wire-format adaptation — coinbase
construction, merkle derivation, RPC plumbing — plus the
classification of `mine()`'s typed result. From `forward()`'s
perspective every call is one structural inference at constant cost;
the boundary loop is where target-restrictiveness shows up as more
template variations (more `MiningTask`s tried), never as more work
per `forward()`.

The pure-Rust SHA-256 helpers in `crates/prism-btc/src/ops/sha256.rs`,
`ops/merkle.rs`, and `ops/header.rs` exist **only** to serialize
bytes for the bitcoind RPC boundary and for ψ_9's internal
κ-derivation (one canonical-hash-axis projection plus one SHA-256d
of the reconstructed wire-format header). They are not invoked from
the `verb!` arena. The σ-projection inside the transform is the
canonical hash axis (`Sha256dHasher`) consumed by ψ_9 — once per
`forward()` for the κ-derivation — and never from the verb body.

## 8. Public API surface

```rust
// crates/prism-btc/src/lib.rs

// Typed feature primitives
pub use domain::{Version, MerkleRoot, Timestamp, Bits, Target, BlockHeader};
// Composite feature primitives
pub use model::{TemplatePrefix, MiningTask, MiningResult};

// The mining model — ADR-048 5-position form
pub use model::{BitcoinMiningModel, BitcoinMiningRoute};

// Substitution axes
pub use shapes::{Sha256dHasher, PrismBtcBounds};
pub use resolvers::BitcoinResolverTuple;

// Public entry point — the only mining entry. Admission is evaluated
// inside foundation's run_route via the model's pinned TargetCommitment.
pub use pipeline::{mine, MiningOutcome, MiningFailure,
                   set_thread_target, set_thread_target_bytes,
                   current_thread_target};

// Cost-model commitment surface — foundation's canonical
// TypedCommitment catalog (ADR-048) + the five ObservablePredicate
// impls (ADR-049), all re-exported from prism-btc so applications can
// declare derived PrismModel<…, C>s composing TargetCommitment with
// additional typed payload predicates.
pub use commitment::{
    // Sealed trait + composition shapes (ADR-048)
    TypedCommitment, EmptyCommitment, SingletonCommitment, AndCommitment,
    // Bitcoin's admission alias
    TargetCommitment,
    // The five canonical ObservablePredicate impls (ADR-049)
    ObservablePredicate, Stratum, WalshHadamardParity, UltrametricCloseTo,
    AffineParity, LexicographicLessEqThreshold,
    // QS-06 K-fold payload helpers — AndCommitment trees of
    // SingletonCommitment<AffineParity> leaves
    payload_bit, payload_commitment_k2, payload_commitment_k4, payload_commitment_k8,
    PayloadK2, PayloadK4, PayloadK8, decode_payload,
    // 'static byte-buffer registry (runtime bytes → &'static [u8])
    leak_target, leak_reference, leak_frequency, target_commitment,
};

pub use observables::{KappaObservables, ExtendedObservables, CANONICAL_PRIMES};

// Session-level aggregate observatory — receiver-side typed lens at scale.
// Folds every per-attempt KappaObservables (admitting or not) into a
// stack-resident aggregate. See CONFORMANCE.md §CM.
pub use campaign::{CampaignStats, STRATUM_BINS, PADIC_BINS};

// Iterative-resolution diagnostic surface
pub use diagnostics::{ResolutionState, take_resolution_state};

// UOR observable surface (manifold helpers; ANALYSIS.md §1.3)
pub use domain::{p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at};

// Host-boundary witnesses
pub use domain::{MiningTag, MiningWitness, TriadicCoords};
```

### 8.1 `mine` — the only public mining entry

`mine(header: &BlockHeader, target: Target) → Result<MiningOutcome, MiningFailure>`
is the canonical entry. It:

1. Promotes `target.to_bytes()` to `&'static [u8]` via
   [`leak_target`] (deduplicating against a process-lifetime
   registry) and publishes it on the thread-local commitment slot via
   [`set_thread_target`].
2. Builds a `MiningTask` from `(header_prefix, target_bytes)`.
3. Invokes `BitcoinMiningModel::forward(task)`, which delegates to
   foundation's `run_route<H, B, A, M, R, TargetCommitment>`.
4. Classifies the result:
   - `Ok(grounded)` ⇒ wraps the foundation-sealed
     `Grounded<MiningResult>` (32-byte digest output) as
     `MiningOutcome`, reconstructs the 80-byte
     `wire_format_header: [u8; 80]` from `(template_prefix,
     derived_nonce)`, decodes `KappaObservables`, surfaces the
     `ResolutionState`.
   - `Err(ShapeViolation { commitment-IRI })` ⇒
     `MiningFailure::DidNotAdmit { observables, nonce, digest }`.
   - Any earlier substrate-level violation ⇒
     `MiningFailure::PipelineFailure` (unreachable on well-formed
     inputs).

Admission is **one foundation `TypedCommitment::evaluate` invocation
inside the catamorphism** — not a host-boundary recomputation of the
σ-projection. The prism contract `operational = declared at
equality` applies over the typed `TargetCommitment` bandwidth (Lean
theorem `Commitment.prf_prob_tight_wellFormed`).

### 8.2 Typed payload commitments via derived `PrismModel`s

Applications that want a richer typed commitment (admission ∧
K bits of structural payload, in the spirit of wiki QS-06's K-fold
exemplar) **declare a derived `PrismModel<…, C>`** with their own
composed `C: TypedCommitment` in the 5th slot. The foundation-shipped
composition primitives:

| Primitive | Role |
|---|---|
| [`EmptyCommitment`] | Composition identity, bandwidth = 0 |
| [`SingletonCommitment<P>`] | Single predicate, `P: ObservablePredicate` |
| [`AndCommitment<A, B>`] | Conjunction, bandwidth additive |

are paired with the five canonical `ObservablePredicate` impls
foundation ships under wiki ADR-049 — `Stratum<P>`,
`WalshHadamardParity`, `UltrametricCloseTo<P>`, `AffineParity`,
`LexicographicLessEqThreshold`. The catalog is sealed
(`__sdk_seal::Sealed`): applications compose from it, they cannot
`impl ObservablePredicate` or `impl TypedCommitment` themselves. The
seal is what makes the Lean theorem
`Commitment.prf_prob_tight_wellFormed` apply at equality across every
shape an application can construct — every monomorphization the
catalog produces has a `wellFormed` discharge at the type level.

The legacy `mine_with(_, _, commitment)` API has been **removed**.
Applications wanting K+B-bit conjunctions follow QS-06's exemplar
shape directly: declare a `PrismModel<…, AndCommitment<TargetCommitment,
payload>>` and invoke its `forward()` from a thread that has the
target's `&'static` bytes published.

> **Cost-model attribution: closed at the substrate.** Foundation
> 0.4.12 (wiki ADR-048) carries the cost-model commitment as
> `PrismModel`'s 5th type parameter `C: TypedCommitment + Copy +
> Sealed`. The catamorphism (`run_route`) evaluates
> `commitment.evaluate(kappa_label)` immediately after ψ_9 emits the
> 32-byte κ-label and short-circuits to
> `PipelineFailure::ShapeViolation` with the
> `commitment/TypedCommitment/VIOLATED` shape IRI on rejection; the
> `CommitmentEvaluated` trace event records the result. Bitcoin's
> admission `digest ≤ target` is realized as foundation's
> `LexicographicLessEqThreshold` predicate (ADR-049) inside
> `TargetCommitment = SingletonCommitment<LexicographicLessEqThreshold>`,
> so it sits **inside the typed-iso surface** — no host-boundary
> recomputation. The prism contract `operational = declared at
> equality` applies over the full bandwidth of the model's pinned `C`,
> not an asymptotic upper bound.

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

`MiningResult::CONSTRAINTS` declares 32 disjoint `ConstraintRef::Site`
instances from foundation's closed `ConstraintRef` catalog. The Site
variant is the load-bearing constraint type for prism-btc's
algebraic-closure encoding (architecture §2.3): each Site_i pins one
distinct κ-label digest byte position; the 32-Site declaration
realizes the IT_7d algebraic-closure criterion (χ = SITE_COUNT = 32)
for the typed cost-model κ-label per wiki ADR-048/049.

### 9.3 Resolver realizations

`BitcoinResolverTuple` ([`crate::resolvers`](crates/prism-btc/src/resolvers.rs))
ships concrete realizations of all 8 resolver-bound ψ-stages. Each
resolver realizes its named mathematical role over the isolated-
vertices constraint geometry: ψ_1 builds the nerve N(C) from
`MiningResult::CONSTRAINTS`; ψ_2/ψ_3/ψ_5/ψ_6 produce the chain
complex, homology, cochain, and cohomology data; ψ_7 truncates the
Postnikov tower; ψ_8 extracts the homotopy groups; ψ_9 validates the
upstream π_0-only geometry, then performs the structural
κ-derivation that produces the 4-byte nonce, reconstructs the 80-byte
wire-format Bitcoin header from `(template_prefix, derived_nonce)`,
and emits `SHA-256d(wire_format_header)` as the 32-byte κ-label.
Each non-terminal stage emits a 208-byte structural carrier
(architecture §4); each downstream stage validates the upstream stage
tag and structural geometry before emitting. ψ_2/ψ_3/ψ_5/ψ_6 are off
the mining-transform path (the verb body composes only ψ_1, ψ_7,
ψ_8, ψ_9) but compute their stage's content for substitution-axis
completeness under ADR-036.

### 9.4 Capacity ceilings

ADR-037 makes the catamorphism's ceilings `HostBounds`-parametric.
[`PrismBtcBounds`](crates/prism-btc/src/shapes/bounds.rs) declares
prism-btc's capacity profile: `NERVE_SITES_MAX = 80` and
`NERVE_CONSTRAINTS_MAX = 128` accommodate the wire-format header's
76-site `TemplatePrefix` geometry with headroom; the κ-label's
32-Site nerve fits comfortably within the same ceilings.
`BETTI_DIMENSION_MAX = 80` and `AFFINE_COEFFS_MAX = 80` mirror the
nerve ceilings; each per-ψ-stage output ceiling is `4096`
(`TERM_VALUE_MAX_BYTES`) — the carrier (208 bytes) and the 32-byte
κ-label fit comfortably.

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
carriers; ψ_9 performs the terminal κ-derivation that pins all 32
κ-label digest sites simultaneously (via the canonical hash axis
projection of the typed `MiningTask`, the wire-format header
reconstruction, and the SHA-256d that produces the 32-byte digest),
dropping `FreeRank` from 32 to 0 in one stage. The discipline
converges at the terminal ψ-stage for every well-formed
`MiningTask` — there is no impossibility verdict inside ψ_9.
Whether the κ-label admits is decided immediately after ψ_9 by
foundation's `run_route` consulting the model's pinned
`TargetCommitment` (architecture §5, §6). prism-btc surfaces ψ_9's
state via
[`crate::diagnostics`](crates/prism-btc/src/diagnostics.rs).

## 10. Conformance

| Tenet | prism-btc realization |
|---|---|
| **TC-01 zero-cost runtime** | All `ConstrainedTypeShape` impls, `partition_product` compositions, and substitution-axis selections are resolved by `rustc` at compile time. Foundation's catamorphism is monomorphised against `BitcoinResolverTuple<Sha256dHasher>` at the `BitcoinMiningModel` declaration site. |
| **TC-02 sealing** | Every `Datum`, `Triad`, `Derivation`, `FreeRank`, `Validated`, `Grounded`, `Certified` arrives via foundation's mint primitives or as a `pipeline::run_route` return value. prism-btc constructs zero sealed types directly. |
| **TC-03 path singularity** | `BitcoinMiningModel::forward` (which delegates to `pipeline::run_route → pipeline::evaluate_term_tree`) is the only pathway to a `Grounded<MiningResult>`. `Grounded` is sealed; `MiningTag` is a phantom over it. |
| **TC-04 declarative semantics** | The mining model is declarative: typed primitives + 32-Site algebraic-closure declaration on `MiningResult` + ψ-pipeline verb body + `TargetCommitment` pinned at the model's 5th position. No algorithmic body in prism-btc's verb arena; the catamorphism evaluates the structural declaration. |
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
  per-`forward()` cost is constant — one ψ-pipeline pass with ψ_9
  performing one canonical-hash-axis projection for the κ-derivation
  plus one SHA-256d of the reconstructed wire-format header to emit
  the κ-label, then one typed-commitment `evaluate` inside
  `run_route` for the admission gate. There is no "expected hashes ×
  per-hash cost", no inner search loop. The byte-threshold in
  `Target` parameterizes the typed admission predicate
  (`LexicographicLessEqThreshold`), not a probabilistic puzzle
  parameter; the network-dependent quantity is the number of
  template variations the host has to attempt, not the cost per
  attempt.
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

## 14. UOR-optimal mining: foundation's typed-commitment surface

The cryptanalysis battery (ANALYSIS.md §3) confirms that no UOR
observable on the σ-projection's output exposes admission-relevant
structure under PRF, and ANALYSIS.md §5 shows the substrate's
`type:Conjunction` primitive is a **typed information channel** over
the σ-projection: K independent typed predicates encode K bits of
structural commitment in the κ-label at expected
`2^K × α^-1` template variations.

This section names the **optimal mining surface** prism-btc exposes
within that framework. Foundation 0.4.12 (wiki ADR-048 + ADR-049)
ships the typed-commitment catalog as a sealed substrate primitive;
prism-btc consumes it through the `PrismModel`'s 5th-position `C`
slot.

### 14.1 What "optimal" means under UOR

Under the random-oracle baseline:

- The bare admission relation `digest ≤ target` has PRF
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

### 14.2 Foundation's sealed catalog — three composition shapes + five predicates

Foundation publishes the cost-model commitment surface as a **sealed
catalog**. Applications compose from it; they cannot extend it.

The three composition shapes (`crate::commitment` re-exports per wiki
ADR-048):

| Shape | Role | Bandwidth |
|---|---|---|
| `EmptyCommitment` | Composition identity | `0` |
| `SingletonCommitment<P>` where `P: ObservablePredicate` | Single predicate | `-log₂(P::accept_prob())` |
| `AndCommitment<A, B>` where `A, B: TypedCommitment` | Conjunction | `A::bandwidth() + B::bandwidth()` |

The five canonical `ObservablePredicate` impls (wiki ADR-049):

| Predicate | Condition | PRF probability |
|---|---|---|
| `Stratum<P> { k }` | 2-adic stratum (`prime P`) | `(P−1)/P^(k+1)` |
| `WalshHadamardParity { frequency, expected }` | spectral parity at ω | `1/2` |
| `UltrametricCloseTo<P> { reference, k }` | ν_P(d XOR r) ≥ k | `P^-k` |
| `AffineParity { bit_index, expected }` | digest single-bit value | `1/2` |
| `LexicographicLessEqThreshold { target }` | digest ≤ target lex BE | `≈ target / 2^(8·target.len())` |

Every predicate is `Copy + Sealed`; every commitment shape is
`TypedCommitment: Copy + Sealed`. The seal makes the catalog closed:
no author-side `impl ObservablePredicate` and no author-side
`impl TypedCommitment` are possible. Foundation publishes one
canonical alias prism-btc relies on:

```rust
pub type TargetCommitment = SingletonCommitment<LexicographicLessEqThreshold>;
```

`BitcoinMiningModel` binds `C = TargetCommitment` (§3, §5) so the
`run_route` catamorphism evaluates Bitcoin's admission predicate
inline.

### 14.3 The K-fold payload helpers (wiki QS-06 exemplar shape)

`crates/prism-btc/src/commitment.rs` exposes builder helpers for
the canonical K∈{1,2,4,8} payload-bit conjunctions of the cost-model
conformance suite (wiki QS-06 K-fold exemplar):

```rust
pub fn payload_bit(bit_index: u32, expected: bool)
    -> SingletonCommitment<AffineParity>;          // K = 1

pub type PayloadK2 =
    AndCommitment<SingletonCommitment<AffineParity>, SingletonCommitment<AffineParity>>;
pub fn payload_commitment_k2(bits: [bool; 2]) -> PayloadK2;

pub type PayloadK4 = AndCommitment<AndCommitment<PayloadK2, …>, …>;
pub fn payload_commitment_k4(bits: [bool; 4]) -> PayloadK4;

pub type PayloadK8 = …;
pub fn payload_commitment_k8(bits: [bool; 8]) -> PayloadK8;

pub fn decode_payload<const K: usize>(digest: &[u8]) -> [bool; K];
```

Each helper produces a fully-named `AndCommitment` tree of
`SingletonCommitment<AffineParity>` leaves: K disjoint single-bit
predicates at canonical low-bit positions. The return type is
**fully concrete** (no `impl Trait`) so the resulting commitment can
be threaded into a derived `PrismModel<…, C>` declaration as `C`.
`decode_payload` is the receiver-side inverse: read K bits at the
matching positions.

### 14.4 The composition pattern — derive your own `PrismModel`

Applications that want admission ∧ K-bit payload follow QS-06's
exemplar shape: declare a derived `PrismModel<…, C>` with `C` pinned
to the composed shape, then invoke its `forward()` from a thread
with the target's `&'static` bytes published.

```rust
use prism_btc::{
    BitcoinResolverTuple, PayloadK4, PrismBtcBounds, Sha256dHasher,
    TargetCommitment, leak_target, payload_commitment_k4, set_thread_target_bytes,
};
use prism::pipeline::{prism_model, AndCommitment};
use prism::vocabulary::DefaultHostTypes;

type AdmissionAndPayload = AndCommitment<TargetCommitment, PayloadK4>;

// Application declares its own PrismModel with the composed C in the 5th slot.
prism_model! {
    pub struct MyModel;
    pub struct MyRoute;
    impl PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        AdmissionAndPayload
    > for MyModel {
        type Input  = prism_btc::MiningTask;
        type Output = prism_btc::MiningResult;
        type Route  = MyRoute;
        fn route(input: Self::Input) -> Self::Output { prism_btc::mining_inference(input) }
        fn commitment() -> AdmissionAndPayload {
            AndCommitment {
                left:  prism_btc::target_commitment(MY_TARGET_STATIC),
                right: payload_commitment_k4([true, false, true, true]),
            }
        }
    }
}
```

The composed gate's bandwidth is `TargetCommitment::bandwidth() +
PayloadK4::bandwidth() = log₂(2²⁵⁶/target) + 4`; expected template
variations to land an admitting+committed κ-label are
`α⁻¹ × 2⁴` — the conjunction is bandwidth-additive (CP-4).

**The legacy `mine_with(_, _, commitment)` runtime-injection API
has been removed.** Wiki QS-06's exemplar requires the commitment
to be pinned at the model declaration site so the Lean theorem
applies at equality over the full bandwidth; the typed-iso surface
no longer accepts an arbitrary runtime-supplied commitment.

### 14.5 `wellFormed` discharged at the type level — by the seal

The Lean theorem
[`Commitment.prf_prob_tight_wellFormed`](../prism-btc-lean/PrismBtc/CommitmentChannel.lean)
requires the commitment to be `wellFormed` (pairwise-disjoint
predicate supports). For every commitment shape an application can
construct from foundation's catalog, this is guaranteed by the
seal:

- `EmptyCommitment` is vacuously `wellFormed`.
- `SingletonCommitment<P>` is trivially `wellFormed` (one
  predicate).
- `AndCommitment<A, B>` is `wellFormed` when `A` and `B` are
  individually `wellFormed` and their supports are disjoint;
  foundation pins disjointness by construction across the five
  canonical predicates (each occupies a distinct support regime —
  bit-set / modular / threshold).

The runtime does not check — and because the catalog is sealed,
applications cannot construct an ill-formed commitment shape. The
Lean theorem therefore applies at equality across every Rust
monomorphization the catalog produces:

> Under U1 (marginal-uniformity) and U2 (joint-independence under
> disjoint supports) as axioms on the σ-projection, the PRF
> acceptance probability for a well-formed commitment equals its
> declared `acceptProb` exactly:
> `Pr[c.evaluate d = true] = acceptProb c`.

Equivalent log-space statement:
`expected mining trials = 1 / acceptProb c = 2^bandwidth_bits c`.

U1 + U2 are calibration assumptions; they are empirically witnessed
in the prism-btc cryptanalysis battery (ANALYSIS.md §3) at 10⁶+
samples across each canonical predicate variant.

### 14.6 Reading the κ-label as a typed commitment — `KappaObservables`

Every block mined through `BitcoinMiningModel` is wire-format-valid
for Bitcoin's `submitblock` (via `outcome.wire_format_header`) —
Bitcoin Core does not see or check the application's typed
predicates beyond the threshold. Any verifier of the application's
protocol can re-evaluate the derived `PrismModel`'s commitment on
the published κ-label digest and read off the K bits of structural
commitment. The 32-byte κ-label is the same object on both axes —
what differs is which observer reads it (Shannon-channel
construction of ANALYSIS.md §5.4, realized for Bitcoin via
prism-btc's typed-iso surface).

The receiver-side typed lens is `KappaObservables` and the
const-generic `ExtendedObservables<N_PAR, N_REF>`, both in
`crates/prism-btc/src/observables.rs`:

```rust
pub const CANONICAL_PRIMES: [u64; 4] = [2, 3, 5, 7];

pub struct KappaObservables {
    pub coords: TriadicCoords,           // stratum + spectrum
    pub p_adic: [u32; 4],                // valuations at CANONICAL_PRIMES
}

pub struct ExtendedObservables<const N_PAR: usize, const N_REF: usize> {
    pub base: KappaObservables,
    pub parity_omegas: [[u8; 32]; N_PAR],
    pub parities: [u32; N_PAR],
    pub reference_points: [[u8; 32]; N_REF],
    pub ultrametric_dists: [u32; N_REF],
}
```

**The lens is total.** Every `MiningOutcome` carries a
`KappaObservables` decoded from the produced κ-label, AND every
`MiningFailure::DidNotAdmit { observables, nonce, digest }` carries
the candidate's `KappaObservables` too. Every ψ-pipeline inference
exposes its candidate's typed property landscape regardless of
whether the candidate admits. Always computed at zero overhead
(no `Vec`, stack-resident).

Applications with custom observable sets use `ExtendedObservables`
to capture parities at chosen ω-frequencies and ultrametric distances
to chosen reference points; sizes are const generics, so all the
arrays are stack-allocated and the from-digest loops are unrolled by
the optimizer.

**Session-level aggregate observatory.** [`CampaignStats`] folds
every per-attempt `KappaObservables` (admitting or not) into a
stack-resident aggregate — stratum / spectrum / p-adic histograms,
empirical α, best-candidate-so-far. `O(1)` per recorded attempt; no
heap. At mainnet's `α ≈ 2⁻⁷⁷` this is what makes the search legible:
the operator gets typed visibility into a session that would
otherwise be opaque (CONFORMANCE.md §CM-3, §CM-5).

The Lean correspondence: `KappaObservables` and `ExtendedObservables`
are the *receiver-side* typed lens to the *sender-side*
`TypedCommitment` surface — together they realize the sender ↔
receiver duality of prism's typed information channel
(ANALYSIS.md §5). `CampaignStats` lifts the per-attempt duality to
session granularity.

### 14.7 Pareto-optimality and the limits of UOR

The Pareto frontier `cost(K) = 2^K × α^-1` is **tight** under PRF:
- Lower bound. ANALYSIS.md §4.1 U3 (admission-orthogonality) plus
  U6 (bandwidth-additivity) imply that no UOR observable cheaper
  than σ predicts joint commit-admission. Any procedure for
  finding commit-admitting κ-labels must therefore evaluate σ on
  Ω(`2^K × α^-1`) candidates in expectation.
- Upper bound. The implementation matches this asymptotic exactly
  — conformance test `cp4_typed_commitment_composition_is_bandwidth_additive`
  witnesses it empirically across (lz, K) combinations and pins
  foundation's `AndCommitment` bandwidth-additivity surface.

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

prism-btc's `BitcoinMiningModel` + foundation's sealed
`TypedCommitment` catalog is therefore the **absolute optimal**
mining surface within UOR's framework: it realizes every bit of
bandwidth that the σ-projection's PRF baseline makes available, with
no concession to traditional miner tropes (no hashrate metric, no
GPU offload, no W32 walk inside the ψ-pipeline), and prism's
zero-runtime-movement contract is upheld end-to-end: every
commitment is a monomorphized compile unit, no `Vec`, no dynamic
dispatch, no runtime disjointness check.

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

The cost of the σ-projection inside ψ_9 (one canonical-hash-axis
projection plus one SHA-256d of the reconstructed wire-format header
to emit the 32-byte κ-label) is the canonical hash axis's affair —
a substitution-axis selection per ADR-030, not an implementation
surface prism-btc tunes. Foundation's `TargetCommitment::evaluate`
on the κ-label digest is one byte-compare loop bounded by the target
length (32 bytes); it adds an `O(1)` overhead per `forward()`.

### 15.1 Benchmarks

[`crates/prism-btc/benches/mining.rs`](crates/prism-btc/benches/mining.rs):

| Bench | What it measures |
|---|---|
| `mine/one_structural_inference` | One full `mine()` call: ψ_1 → ψ_7 → ψ_8 → ψ_9 structural κ-derivation plus the typed `TargetCommitment::evaluate` inside `run_route`. Constant per call, independent of target. |
| `misc/target_check_reject` | `LexicographicLessEqThreshold::evaluate` on a non-satisfying digest vs target — the typed admission predicate in isolation. |
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
