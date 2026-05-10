# prism-btc: Defined Architecture

> **Status:** Normative for prism-btc. This document is the authoritative
> specification of what prism-btc is, what it claims, and how it realises
> those claims through Prism + uor-foundation. The repository state is
> reconciled to this document, not the other way around.
>
> **Frame of reference:** the [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki),
> which is itself the normative specification of Prism — the boundary
> properties TC-01..TC-06 and the architectural commitments
> ADR-001..ADR-034. **As of foundation `0.4.1`, the typed-iso
> contract `PrismModel<H, B, A>` (ADR-020), the `IntoBindingValue`
> input adapter (ADR-023), the catamorphism evaluator
> `pipeline::evaluate_term_tree` (ADR-029), the
> `Grounded::output_bytes` payload carrier (ADR-028), and the
> `TERM_VALUE_MAX_BYTES = 4096` per-value capacity all ship in the
> substrate**. The prism implementor (this crate) declares its model
> via the `uor-foundation-sdk::prism_model!` macro (ADR-022) — with
> the route body `hash(input)` (ADR-026 G19) — and provides the W32
> fiber traversal that finds the admitting input. The 80-byte canonical
> Bitcoin header now flows through the typed-iso evaluator end-to-end:
> the Grounded's `output_bytes` IS the Bitcoin block hash.

---

## 1. The claim: real-time structural inference

prism-btc is a **real-time inference engine for Bitcoin proof-of-work**,
realised as a Prism application. The artifact is the binary `prism-mine`,
which produces blocks accepted byte-for-byte by Bitcoin Core.

The load-bearing distinction between prism-btc and a traditional miner is
that the σ-projection is not invoked through an opaque external crate —
it is invoked through foundation 0.4.1's typed-iso surface
(`PrismModel<H, B, A>`, ADR-020) and the catamorphism evaluator
(ADR-029). prism-btc declares a `BitcoinMiningModel` whose `Input` is
the 80-byte canonical wire-format header (`MiningInput`), whose
`Output` is foundation's `ConstrainedTypeInput`, whose application
`Hasher` is `Sha256dHasher` (pure-Rust SHA-256d), and whose `Route` is
declared in the closure-grammar form `hash(input)` — `prism_model!`
(ADR-026 G19) lowers it to the term arena `[Term::Variable {0},
Term::AxisInvocation {0,0,0}]`.

`BitcoinMiningModel::forward` produces a `Grounded` whose three
substrate carriers all run through `Sha256dHasher`:

- The input-binding's `content_address` is the 8 high-order bytes of
  `Sha256dHasher` over the 80-byte header (ADR-023 path).
- The `content_fingerprint` and `unit_address` are derived from
  `Sha256dHasher` over the canonical `CompileUnit` byte layout (the
  **typed-iso path identity**).
- The Grounded's `output_bytes` is the catamorphism evaluator's
  result — `Term::Variable {0}` carries all 80 input bytes through
  the `TermValue` per-value buffer (`TERM_VALUE_MAX_BYTES = 4096` in
  0.3.4, comfortably above the 80 the header requires); `Term::AxisInvocation` (canonical hash axis)
  then folds those 80 bytes through `Sha256dHasher` and emits the
  32-byte digest, attached via `Grounded::with_output_bytes`
  (ADR-028).

**The 32 bytes of `MiningWitness::output_bytes()` ARE the Bitcoin
block hash** in the Hasher's internal byte order. Reversed, they are
the canonical block hash in display order — bit-identical, by
construction, to what `submitblock` accepts. The σ-projection runs
*inside* the foundation typed-iso pipeline, end-to-end. The same
`Sha256dHasher` body is also the algorithm prism-btc's W32 traversal
evaluates per fiber visit ([`crate::ops::sha256::sha256d_display`])
to test admission against the target; `MiningOutcome::digest` carries
the same digest in display order as a convenience for callers
consuming the protocol-level hash without reaching through the
Grounded.

The W32 nonce fiber traversal — finding the input value to feed
`forward()` — is prism-btc's runtime (foundation 0.4.1's pipeline does
not drive search; the catamorphism is structural per ADR-019). The
mining "inference" is therefore a structural commitment: the type-level
contract is a `PrismModel`, and the runtime that walks the W32 ring to
the admitting fiber point is the prism implementor's job.
- Determinism + finite domain (`|W32| = 2^32`) + unique-first-admission
  in the structural ordering of the W32 ring together mean: given the
  template prefix and the foundation `Hasher` substitution, the
  pipeline derives the same nonce on every invocation. There is no
  randomness, no choice, no "search and check." The answer is uniquely
  determined by the structure; the pipeline computes it.

This is what "real-time inference" means here:

- **Inference**, not search: the answer is structurally entailed by
  (template, target, σ-projection composition). The pipeline derives it.
- **Real-time**, not compile-time: templates arrive at runtime; the
  inference runs on user hardware at the moment a block is to be mined,
  with time bounded by the structural complexity of the inference task
  (the count of fiber points the deterministic traversal visits before
  admission). It is **not** a precomputed table, **not** an oracle
  query, **not** a service call — every stage executes locally
  (TC-06).
- **Bit-identical output to traditional mining**, by a different path:
  the (header, nonce) pair the pipeline emits, when serialised under
  Bitcoin's standard 80-byte layout and SHA-256d-projected by Bitcoin
  Core, satisfies the protocol's target. The block is accepted by
  `submitblock` exactly as any other miner's block would be. What
  differs is the path: every step of prism-btc's derivation is a
  composition of foundation `PrimitiveOp` discriminants and a sealed
  `pipeline::run` traversal — never an opaque crate import, never a
  hand-rolled loop.

What prism-btc does **not** claim:

- It does **not** invert SHA-256, escape proof-of-work, or weaken
  any cryptographic primitive. The `Hasher` substitution-axis
  contract (ADR-010) treats the chosen digest as a one-way function
  — `Sha256dHasher` evaluates the digest at each fiber visit the
  catamorphism walks. The architectural shift is in the
  *vocabulary*, not the cryptography: the per-fiber-visit digest
  evaluation is a fold-rule application of `Term::AxisInvocation` (canonical hash axis)
  (ADR-029), whose cost is a property of the chosen `Hasher` impl,
  not of "mining."
- It does **not** introduce primitive operations beyond the
  substrate's closed set (ADR-013, with the 0.3.6 amendment (now in foundation 0.4.1) for
  `Le` / `Concat`). Every Bitcoin verb used by prism-btc decomposes
  into the closed `PrimitiveOp` vocabulary plus `Term::AxisInvocation` (canonical hash axis)
  (the substitution-axis-realised form, ADR-026 G19).
- The catamorphism's evaluation cost — what a traditional miner
  would call "mining time" — is **parametric in the substitution
  axes** (`Hasher`, `HostBounds`) and the implementation runtime
  per ADR-026 G16 (sequential, parallel, or any other strategy
  that satisfies the conformance test). Per-call cost of
  `Sha256dHasher`'s pure-Rust body is one specific point in that
  parameter space; an alternative `Hasher` impl bound at the
  `BitcoinMiningModel` declaration site changes per-call cost
  without changing the verb body or the route declaration.

The value is architectural and epistemic: a mined block carries with
it a `Trace` that an independent verifier can replay (TC-05) without
invoking SHA-256, without invoking any decider written by prism-btc's
author, and without contacting any service — yielding a
`Certified<GroundingCertificate>` that the trace's claimed nonce was
derived under the declared shape via the structural traversal the
trace records.

---

## 2. Conceptual model

> Cross-reference: this section follows the [UOR-Framework wiki's Conceptual-Model page](https://github.com/UOR-Foundation/UOR-Framework/wiki/Conceptual-Model)
> convention — OPM (ISO 19450) entities and processes declared in OPL.
> The wiki's Prism-level entities (Application Author, Application User,
> Rust Toolchain, Prism, Trace, etc.) are inherited; this section
> declares prism-btc's specialisations and adds Bitcoin-domain entities
> and processes.

### 2.1 Inherited Prism entities (from the wiki)

`Application Author` is a stakeholder. `Application Author` distributes
`prism-mine`. `prism-mine` is an `Application` (in the wiki's sense:
the executable a Prism application author distributes).

`Application User` is a stakeholder. `Application User` runs `prism-mine`.
`Application User` may invoke `prism-verify::certify_from_trace` on
the resulting `Trace`.

`Rust Toolchain` is an enabler. `Rust Toolchain` compiles `prism-mine`,
exhibiting compile-time UORassembly enforcement (TC-04, ADR-006).

`Prism` is a system. `Prism` consists of `uor-foundation`, `prism`, and
`prism-verify`. `Prism` exhibits the boundary properties TC-01..TC-06.

`Trace` is an output object. `Trace` consists of a fixed sequence of
`TraceEvent` values, a `ContentFingerprint`, a hasher identifier, and
a format version (per Building Block View, bridge::trace::Trace).

`Grounded<T>` is a sealed object. `pipeline::run` yields `Grounded<T>`
and `Trace` simultaneously (Runtime View Scenario 1, step 8).

`Certified<GroundingCertificate>` is a sealed object.
`certify_from_trace` yields `Certified<GroundingCertificate>` from a
`Trace` and a hasher instance (Runtime View Scenario 2, step 9).

### 2.2 prism-btc-specific entities

`Bitcoin Core node` is an external system. `prism-mine` requires a
`Bitcoin Core node` for `getblocktemplate` and `submitblock`. The
node is **outside Prism's scope** (ADR-004, distribution channel
external to Prism — applied here to the upstream block-template source
and downstream block-submission sink).

`Block template` is an input object obtained from a `Bitcoin Core
node`. `Block template` consists of: a previous-block hash, a target
`bits` value, a coinbase value, a transaction list, a height, a
current time, and the segwit witness commitment script.

`Coinbase transaction` is a derived object. `CoinbaseConstruction`
(§4.4) yields a `Coinbase transaction` from a `Block template`, an
`Extranonce`, and a payout address.

`Extranonce` is a free coordinate (`u64` value space). `Extranonce`
exhibits resolution by the session's outer loop (§6.1).

`Merkle root` is a derived object. `MerkleRootDerivation` (§4.5)
yields a `Merkle root` from the `Coinbase transaction` txid and the
`Block template`'s transaction txid list.

`Template prefix` is a derived object. `HeaderSerialization` (§4.3)
yields a 76-byte `Template prefix` from `(version, prev_hash,
merkle_root, timestamp, bits)`.

`Nonce` is a free coordinate (W32 = `Z/(2^32)Z` value space).
`NonceFiberTraversal` (§4.6) resolves `Nonce` by a deterministic W32
traversal.

`Block digest` is a derived object. `Sha256dProjection` (§4.2) yields
a `Block digest` from a `Template prefix` and a `Nonce`.

`Mining inference` is a process. `Mining inference` consists of
`HeaderSerialization`, `Sha256dProjection`, and the lexicographic
target-admission rule. `Mining inference` is realised by one
`NonceFiberTraversal` (prism-btc's runtime) followed by one
`BitcoinMiningModel::forward` invocation (foundation's
`pipeline::run_route`) per (`Template prefix`, `Extranonce`) pair.

`Mining session` is a process. `Mining session` consists of: an
outer loop over `Block template`s and `Extranonce`s; one or more
invocations of `Mining inference`; one `submitblock` call per
admitted result. `Mining session` is realised by `prism-btc-node`'s
`Session` (§7.5).

`Mined block` is an output object. `Mining session` yields a `Mined
block` (the wire-format Bitcoin block bytes) and an accompanying
`Trace`. The `Bitcoin Core node` confirms the `Mined block` by
returning a non-error result from `submitblock`.

### 2.3 Inherited Prism processes (from the wiki)

`Grounding` is a process. `Grounding` admits host bytes to a `Datum`
or rejects with a typed impossibility witness.

`CompileUnitConstruction` is a process. `CompileUnitConstruction`
yields `Validated<CompileUnit, FinalPhase>` from a `Datum`, a
`ConstrainedTypeShape` impl, and substitution-axis selections.

`PipelineRun` is a process. `PipelineRun` yields `Grounded<T>` and
`Trace` from `Validated<CompileUnit, FinalPhase>`.

`CertificateEmission` is a process. `CertificateEmission` invokes the
`Hasher` exactly once to compute the `ContentFingerprint`.

`TraceReplay` is a process. `TraceReplay` is realised by
`certify_from_trace`. `TraceReplay` does not invoke the `Hasher`'s
hashing method and does not invoke the application author's
deciders (TC-05).

### 2.4 prism-btc-specific processes

The six prism-btc-specific processes are the `PrimitiveOp` compositions
declared in §4. Each is a process that yields its specified output
object from its specified input objects, realised entirely as a
foundation `PrimitiveOp` composition (closed under ADR-013):

| Process | Input objects | Output object | §-ref |
|---|---|---|---|
| `Sha256Compression` | 512-bit message block, 256-bit prior state | 256-bit working state | §4.1 |
| `Sha256dProjection` | 80-byte serialised header | 32-byte `Block digest` | §4.2 |
| `HeaderSerialization` | (version, prev_hash, merkle_root, timestamp, bits, nonce) | 80-byte serialised header | §4.3 |
| `CoinbaseConstruction` | (height, extranonce, payout_address, coinbase_value, witness_commitment) | `Coinbase transaction` | §4.4 |
| `MerkleRootDerivation` | coinbase txid, other-tx txids | `Merkle root` | §4.5 |
| `NonceFiberTraversal` | template prefix, target | (winning nonce, winning digest) ∨ no-match | §4.6 |

### 2.5 Object-process relationships (OPL)

The complete prism-btc OPL declarations:

```
Application Author distributes prism-mine.
prism-mine requires Bitcoin Core node.
Mining session invokes Mining inference.
Mining session invokes CoinbaseConstruction.
Mining session invokes MerkleRootDerivation.
Mining session invokes HeaderSerialization.
Mining session invokes submitblock.
Mining inference is PipelineRun.
Mining inference invokes Grounding.
Mining inference invokes NonceFiberTraversal.
NonceFiberTraversal invokes HeaderSerialization (per fiber visit).
NonceFiberTraversal invokes Sha256dProjection (per fiber visit).
NonceFiberTraversal yields (Nonce, Block digest) ∨ no-match.
Sha256dProjection invokes Sha256Compression (twice).
CertificateEmission invokes Hasher (= Sha256dHasher).
CertificateEmission yields ContentFingerprint.
PipelineRun yields Grounded<T> and Trace simultaneously.
TraceReplay yields Certified<GroundingCertificate> from Trace and hasher_instance.
TraceReplay does not invoke Sha256dProjection.
TraceReplay does not invoke NonceFiberTraversal.
TraceReplay does not invoke Hasher.
```

Every OPL declaration above is grounded in either a wiki normative
source (Runtime View, Building Block View, ADR-*, TC-*) or a §-ref
back to this document's specification.

---

## 3. Substitution-axis bindings (ADR-007, ADR-010, ADR-018)

Every prism application binds the three substitution axes. prism-btc
binds them as follows:

### 3.1 `HostTypes`

prism-btc selects `uor_foundation::DefaultHostTypes`. The host string
type is `&'static str`; the host byte type is `u8`; integer types are
the standard fixed-width Rust types. No application-specific host-type
selections are required.

### 3.2 `HostBounds = prism_btc::PrismBtcBounds`

A unit struct in `prism-btc::shapes::bounds` with these associated
constants (ADR-018: every capacity bound flows through `HostBounds`):

| Constant | Value | Justification |
|---|---|---|
| `FINGERPRINT_MIN_BYTES` | `32` | matches SHA-256 output width; below this is insufficient for a 256-bit collision-resistant content fingerprint |
| `FINGERPRINT_MAX_BYTES` | `32` | fixed: prism-btc declares one Hasher (§3.3) at exactly 32 bytes |
| `TRACE_MAX_EVENTS` | `64` | bounds the per-`pipeline::run` trace at a small constant — the pipeline emits one event per stage transition (§6.4), not one per fiber visit. Headroom is for future stage subdivisions in the foundation. |
| `WITT_LEVEL_MAX_BITS` | `32` | the W32 nonce ring is the largest algebraic level the prism-btc principal data path computes against. |

`TRACE_MAX_EVENTS = 64` is a binding architectural commitment. It
forbids any implementation strategy that records every fiber visit.
The traversal of 2^32 fiber points is a *single* `PipelineRunEvent`
that carries (winning fiber index, count of fiber visits, terminal
digest) as scalar fields — not a sequence of per-visit events.
Replayability (TC-05) is preserved because the event's structural
validation depends on the scalar fields, not on enumerating visits.

### 3.3 `Hasher = prism_btc::Sha256dHasher`

A foundation-conforming `Hasher` impl whose body is a `PrimitiveOp`
composition (§4.1). Concrete properties (ADR-010):

- Deterministic: same input bytes → same output bytes, on every
  hardware, every Rust toolchain version, every build profile.
- Fixed output: `OUTPUT_BYTES = 32`.
- Distinct identifier: `HASHER_IDENTIFIER` is the IRI
  `https://prism.btc/hasher/Sha256dHasher` (a u32 derived from this
  IRI by foundation's identifier-derivation discipline).
- Idempotent under truncation: trivially, since `OUTPUT_BYTES =
  FINGERPRINT_MAX_BYTES`.

`Sha256dHasher` is bound to **two distinct foundation roles**, and the
architecture treats them as separate concerns (resolving an earlier
draft's conflation):

- **As the `Hasher` substitution axis**, invoked exactly once per
  `pipeline::run` at certificate-emission time (Runtime View Scenario 1
  step 9) to compute the `ContentFingerprint` over the CompileUnit's
  canonical byte layout.
- **As the σ-projection inside the pipeline's `PipelineRun` stage**,
  invoked on each fiber point during the W32 traversal as part of
  `Sha256dProjection` (§4.2).

These are the same algorithm, two roles. The trace records the
σ-projection invocations as part of the `PipelineRunEvent`; the Hasher
is identified but not invoked at replay (TC-05).

---

## 4. The Bitcoin verbs as `PrimitiveOp` compositions (ADR-014)

ADR-014 commits prism to ship vocabulary, not pre-implemented
operations: "authors declare operations as `PrimitiveOp` compositions."
prism-btc declares **six** compositional operations and **two**
constrained-type shapes that fully cover the mining computation. All
six compositions are closed under foundation's primitive set
(ADR-013): bit-rotation, integer-handling, lookup, content-comparison,
depth-projection, observable-arithmetic.

### 4.1 `Sha256Compression` (`PrimitiveOp` composition)

The 64-round SHA-256 compression function on a 512-bit message block.
Declared as:

- 8 working-state words (`a..h`) initialised by `lookup` against the
  foundation-fixed initial-state vector.
- 64 rounds, each composing `bit-rotation` (`Σ0 Σ1 σ0 σ1`),
  `integer-handling` (modular `add`, `xor`, `and`, bitwise `not`),
  and `lookup` against the K-round-constants table.
- Final `integer-handling` add of the working state into the input
  state vector.

Output: a 256-bit working state (8 × u32 words). Total, pure, no new
primitives required.

### 4.2 `Sha256dProjection` (`PrimitiveOp` composition)

The σ-projection: `Sha256Compression` applied twice on the canonical
80-byte header padded per the SHA-256 specification, followed by
`depth-projection` to extract the 32 most-significant bytes in
Bitcoin's display order (byte-reversed from the SHA-256 native
output). Closure: composition of `Sha256Compression` (§4.1) +
`depth-projection`.

`Sha256dHasher` (§3.3) is the `Hasher`-trait implementation that
internally invokes `Sha256dProjection` on the canonical CompileUnit
byte layout when the foundation pipeline calls it for fingerprinting.

### 4.3 `HeaderSerialization` (`PrimitiveOp` composition)

The fixed 80-byte wire layout of a Bitcoin block header. Declared as a
`depth-projection` composition that takes `(version, prev_hash,
merkle_root, timestamp, bits, nonce)` and emits the canonical byte
sequence:

```
[0..4)   version    (LE u32, integer-handling → depth-projection)
[4..36)  prev_hash  (32 bytes, depth-projection)
[36..68) merkle_root (32 bytes, depth-projection)
[68..72) timestamp  (LE u32, integer-handling → depth-projection)
[72..76) bits       (LE u32, integer-handling → depth-projection)
[76..80) nonce      (LE u32, integer-handling → depth-projection)
```

No primitive beyond `integer-handling` and `depth-projection` is
required.

### 4.4 `CoinbaseConstruction` (`PrimitiveOp` composition)

The Bitcoin coinbase transaction is the first transaction in every
block. Its scriptSig contains a BIP34 height push, an extranonce
field, and arbitrary data ("prism-btc" tag). prism-btc declares:

- `BIP34HeightPush`: `integer-handling` composition emitting the
  CompactSize-encoded block-height bytes.
- `ExtranoncePush`: `integer-handling` + `depth-projection` emitting
  little-endian u64 bytes.
- `ScriptSigAssembly`: `depth-projection` concatenating the height
  push, extranonce push, and the literal-byte tag from a `lookup`
  table.
- `CoinbaseTxAssembly`: `depth-projection` over the transaction
  envelope (version, inputs, outputs, lock_time, witnesses) producing
  the canonical serialised coinbase bytes.

Closure: `integer-handling` + `depth-projection` + `lookup`.

### 4.5 `MerkleRootDerivation` (`PrimitiveOp` composition)

Pairwise SHA-256d up the transaction tree. Declared as:

- For each transaction, `Sha256dProjection` (§4.2) applied to the
  serialised tx bytes → txid.
- A folded composition of `Sha256dProjection` over pairs at each tree
  level until a single 32-byte root remains.

Closure: `Sha256dProjection` (§4.2). No new primitives.

### 4.6 `NonceFiberTraversal` (prism-btc runtime)

The W32 nonce fiber traversal — the structural inference's
load-bearing operation. **prism-btc is the prism implementor for the
Bitcoin use case; the traversal is therefore prism-btc's runtime, not
a foundation-supplied primitive.** Foundation provides the substrate
(sealed types, `Hasher` and `HostBounds` traits, `Term` and
`PrismitiveOp` vocabulary, mint primitives, trace structure); prism-btc
provides the runtime that traverses the typed structure declared via
that substrate.

Structural declaration (compile-time):

- **Index domain**: the W32 ring. Declared at the type level via
  `WittLevel::W32` and the `Term::Application { operator: PrimitiveOp::Succ, .. }`
  successor composition.
- **Per-index map**: `Sha256dProjection ∘ HeaderSerialization`,
  declared at the type level as a `Term::Application` chain over
  prism-btc's chosen `PrimitiveOp` decomposition. The runtime that
  evaluates the composition is `prism_btc::ops::sigma::sha256d`
  (pure-Rust SHA-256d, no external crate).
- **Halt predicate**: lexicographic byte comparison `digest ≤ target`
  in display order — the Bitcoin protocol's target-satisfaction rule
  (§4.8), evaluated at runtime by prism-btc's traversal as a
  `PrimitiveOp::Sub`-driven byte comparison closed under ADR-013.

Runtime evaluation (prism-btc's job):

- The traversal visits W32 indices in canonical successor order
  starting at 0. prism-btc's runtime walks the fiber, applying the
  σ-projection at each point and testing admission. On first admit,
  the traversal terminates and prism-btc invokes foundation's
  `pipeline::run` (or `pipeline::run_const`) to mint a
  `Grounded<ConstrainedTypeInput, MiningTag>` certifying the shape.
- On exhaustion, prism-btc returns `MiningFailure::NoMatch`; the
  bitcoind boundary (`prism-btc-node`) increments the extranonce and
  re-invokes `prism_btc::mine` with a new `TemplatePrefixDatum`.
- Determinism: same template + same extranonce + same `Sha256dHasher`
  → same terminal index. No randomness.

Parallelism: prism-btc's runtime MAY partition the W32 ring across
threads (the natural coset partition over `Z/(2^32)Z`); first-finder
wins. This is a runtime implementation detail and does not change
the categorical structure.

**This is the operation that replaces the rayon for-loop currently
in `prism-btc-reduction/src/parallel.rs`.** The replacement is not a
foundation primitive — foundation never claimed to ship one — but a
prism-btc runtime that respects the foundation-typed structural
declaration (Term composition + ConstrainedTypeShape constraints).
The categorical routing claim holds at the type level: the shapes
and Term compositions declare the structure; the prism-btc runtime
walks it.

### 4.7 `MiningInput` (`ConstrainedTypeShape`)

The PrismModel's input shape: the 80-byte canonical wire-format Bitcoin
block header (76-byte prefix + 4-byte nonce, the bytes the W32 fiber
admitted).
- `IRI`: `https://prism.btc/shape/MiningInput`
- `SITE_COUNT`: 80
- `CONSTRAINTS`: empty list. The 76 prefix bytes are upstream-validated
  by `getblocktemplate` (ADR-004 — outside Prism's scope); the 4 nonce
  bytes are the W32 fiber coordinate, structurally a free site until
  the traversal admits.

`MiningInput` impls `IntoBindingValue` (`MAX_BYTES = 80`) so foundation's
`pipeline::run_route` can fold its bytes through `Sha256dHasher` to
derive the input-binding's `content_address`. The 76/4 split is a wire-
layout convention preserved at the byte level inside the 80-byte payload
(positions [0..76) are the template prefix, [76..80) are the nonce).

### 4.8 Target admission as `NonceFiberTraversal` halt predicate

The Bitcoin protocol's target-satisfaction rule — "the 32-byte digest
in display order is lexicographically ≤ the 32-byte target value
decoded from compact nBits" — is the halt predicate of
[`crate::ops::traversal::traverse_sequential`]. The 4-byte compact
nBits is decoded by [`crate::domain::Target::to_bytes`]; the
comparison is byte-wise lexicographic. There is no separate
`ConstrainedTypeShape` for the admission rule because foundation 0.4.1
seals `GroundedShape` to `ConstrainedTypeInput`: any output bundle the
prism implementor declares can carry an IRI and constraints but cannot
appear as the `T` parameter of `Grounded<T>`. The architecture pins the
admission rule in `NonceFiberTraversal`'s halt predicate (which is a
`PrimitiveOp::Sub`-driven byte comparison closed under ADR-013); the
runtime check is what enforces the Bitcoin protocol's target rule.

---

## 5. The mining inference task

One mining inference is the composition of (a) one `NonceFiberTraversal`
invocation by prism-btc's runtime and (b) one `BitcoinMiningModel::forward`
invocation that delegates to foundation's `pipeline::run_route`. The
structural picture is:

```
Inputs (host-side):
  Template prefix  ←  76 bytes from BlockHeader (version, prev_hash,
                      merkle_root, timestamp, bits)
  Target           ←  4-byte compact nBits, decoded to 32-byte target
  Extranonce       ←  u64, rolled by the bitcoind boundary (§6.5)

W32 fiber traversal (prism-btc runtime, §4.6):
  for nonce in 0..2^32:
      digest = sha256d_display(serialize_header(prefix, nonce))
      if digest ≤ target_bytes: halt with (nonce, digest)
  outcome: FiberOutcome::Admitted | FiberOutcome::Exhausted

PrismModel forward call (foundation 0.4.1 typed-iso surface):
  input  = MiningInput(serialize_header(prefix, winning_nonce))  [80 bytes]
  route  = [Term::Variable {0}, Term::AxisInvocation {0,0,0}]      // hash(input)
  output = BitcoinMiningModel::forward(input)
            └─ run_route folds 80 bytes through Sha256dHasher
               (the binding's content_address, ADR-023)
            └─ evaluate_term_tree runs the route's term tree
               (ADR-029): Variable {0} carries all 80 bytes through
               TermValue (TERM_VALUE_MAX_BYTES = 4096); AxisInvocation
               folds those 80 bytes through Sha256dHasher and emits the
               32-byte digest as a TermValue
            └─ run folds CompileUnit metadata through Sha256dHasher
               (the Grounded's content_fingerprint and unit_address)
            └─ run_route attaches the evaluator's TermValue to
               the Grounded as `output_bytes` (ADR-028)
  result = Grounded<ConstrainedTypeInput, MiningTag>:
            content_fingerprint  = digest of CompileUnit metadata
                                   (witt level, output IRI, output
                                   site count, output constraints,
                                   certificate kind) under Sha256dHasher
            unit_address         = u128 derived from the same digest
            triad                = stratum/spectrum/address of the
                                   unit_address (foundation Triad)
            witt_level_bits      = 32
            output_bytes         = Sha256dHasher over all 80 header
                                   bytes — the Bitcoin block hash in
                                   internal byte order

prism-btc emits, via the public `mine()` entry point:
  MiningOutcome {
    witness:  Grounded<ConstrainedTypeInput, MiningTag>,
                              // witness.output_bytes() reversed is the
                              //   block hash in display order
    nonce:    u32,
    digest:   [u8; 32],       // same SHA-256d in display order; a
                              //   call-site convenience
    coords:   TriadicCoords,  // (digest stratum, spectrum) — the
                              //   digest-domain projection
  }
```

The `MiningTag` phantom (per the foundation's `Grounded<T, Tag>`
contract; see §6) marks this Grounded as a Bitcoin block solution at
the type level. Two distinct admitted (header, nonce) pairs produce
Groundeds with bit-identical `content_fingerprint` and `unit_address`
because the fingerprint is over CompileUnit metadata, not input bytes
— the Grounded attests the typed-iso path, while the per-input bytes
flow as the `MiningOutcome::digest` alongside.

---

## 6. The pipeline shape for one mining session

### 6.1 The session's outer loop

A "mining session" is the public-facing operation: from user-supplied
RPC credentials and payout parameters, run until a block is mined and
accepted, or until the user cancels. The session's outer loop lives
in `prism-btc-node`, the bitcoind-boundary crate; its responsibilities
are:

1. Acquire a fresh template from `bitcoind` via `getblocktemplate`.
2. Construct the coinbase via `CoinbaseConstruction` (§4.4).
3. Derive the merkle root via `MerkleRootDerivation` (§4.5).
4. Form the 76-byte template prefix via `HeaderSerialization` (§4.3),
   nonce field zero-filled.
5. Invoke `pipeline::run` once with that prefix and the current
   extranonce.
6. On success: assemble the wire-format block and submit via
   `submitblock`.
7. On `PipelineFailure::NoMatch`: increment the extranonce and goto 2.
8. Between iterations: poll `getbestblockhash`; if the chain has
   advanced, abandon the current template and goto 1.

### 6.2 The pipeline invocation (Runtime View Scenario 1)

Per mining-inference task, the framework's Scenario 1 sequence applies,
instantiated for prism-btc as:

1. Application (boundary, `prism-btc-node`) has the 76-byte prefix bytes
   and the 4-byte compact nBits target.
2. Application calls `prism_btc::mine(header, target, cancel)`. prism-btc's
   runtime walks the W32 fiber via `NonceFiberTraversal` (§4.6),
   evaluating `sha256d_display(serialize_header(prefix, nonce))` per
   visit and halting at the first nonce where the digest ≤ target.
3. On admission, prism-btc serialises the full 80-byte header
   (`serialize_header`) and wraps it in `MiningInput`.
4. prism-btc invokes `BitcoinMiningModel::forward(MiningInput(...))`,
   whose body (emitted by `prism_model!`) is exactly
   `pipeline::run_route::<DefaultHostTypes, PrismBtcBounds, Sha256dHasher, Self>(input)`.
5. `run_route` folds the 80 input bytes through `Sha256dHasher` to
   derive the input-binding's `content_address` (8 high-order bytes of
   SHA-256d of the header), assembles a `Validated<CompileUnit, FinalPhase>`
   with `result_type = ConstrainedTypeInput`, `root_term = &[]`
   (identity route), `witt_level_ceiling = W32` (from
   `PrismBtcBounds::WITT_LEVEL_MAX_BITS`), and dispatches to `run`.
6. `run` runs the reduction-stages preflights, then folds the canonical
   CompileUnit byte layout through `Sha256dHasher` to compute
   `ContentFingerprint` and `unit_address`. It mints
   `Grounded<ConstrainedTypeInput>` carrying both.
7. prism-btc tags the Grounded with `MiningTag` and packs it into
   `MiningOutcome` together with the admitting nonce and the 32-byte
   block-hash digest from §6.2 step 2.
8. Application (boundary) receives `MiningOutcome`; it assembles the
   wire-format Block and submits via `submitblock`.

### 6.3 Path singularity (TC-03)

There is exactly one path to a `Grounded<ConstrainedTypeInput, MiningTag>`
in prism-btc: through `BitcoinMiningModel::forward` (which delegates to
`pipeline::run_route`). There is no alternative constructor; `Grounded`
is sealed in foundation, and `MiningTag` is a phantom over it.

A mining session may invoke `mine()` multiple times (once per
(template, extranonce) pair), but each invocation traverses the singular
path. TC-03 prohibits second-pathways, not multiple traversals.

### 6.4 Trace structure for one inference

The trace is a foundation-emitted `Trace` carrying the five `TraceEvent`s
the `pipeline::run` driver records, one per stage transition:

| # | Variant | Carries |
|---|---|---|
| 1 | `DatumAdmissionEvent` | input-binding `content_address` (Sha256dHasher of the 80-byte header, truncated to u64) |
| 2 | `CompileUnitConstructionEvent` | result-type IRI (`ConstrainedTypeInput`'s identity IRI); witt-level ceiling; thermodynamic budget; target-domains |
| 3 | `ValidationPhaseEvent` | sequence of phase transitions reaching FinalPhase |
| 4 | `PipelineRunEvent` | derivation root address; outcome marker (admitted) |
| 5 | `CertificateEmissionEvent` | hasher identifier; `ContentFingerprint` bytes |

Trace size is bounded by a small constant (~64 events × ~few hundred
bytes = ~few KB), independent of fiber-visit count. This is the design
that makes replay tractable (TC-05): the verifier walks five events,
not 2^32.

### 6.5 Extranonce rolling, tip changes, and TC-03

Extranonce rolling and tip-change handling live in `prism-btc-node`
(§6.1, the outer loop). They are **not** inside `pipeline::run`; they
are the boundary's responsibility. Per invocation of `pipeline::run`:

- The (template, extranonce) pair is fully determined before the call.
- The pipeline traverses W32 deterministically.
- On admission (Grounded), the boundary submits.
- On exhaustion (`PipelineFailure::NoMatch`), the boundary increments
  extranonce and re-invokes `pipeline::run` with a new
  `TemplatePrefixDatum` (re-derived merkle root).
- On tip change between invocations, the boundary discards the in-flight
  state and starts fresh from §6.1 step 1.

The pipeline itself has no abort mechanism. A `pipeline::run` in
flight runs to completion; if its result is for a stale parent, the
boundary discards the result without submitting. The catamorphism's
evaluation cost on the `nonce_fiber_traversal` verb is parametric in
the substitution-axis triple (`Sha256dHasher`, `PrismBtcBounds`) and
the implementation runtime's parallelism per ADR-026 G16. With
`Sha256dHasher`'s pure-Rust SHA-256d body and an 8-coset partition,
one full evaluation over `Z/(2^32)Z` completes on the order of
seconds-to-minutes per the runtime's hardware realisation; tip
churn on production chains is sized in the tens of minutes, so the
discard rate is bounded by the substitution-axis selection's
throughput, not by anything intrinsic to prism-btc.

### 6.6 Replay (Runtime View Scenario 2)

A user receives `(Trace, Sha256dHasher_identifier)` out-of-band. The
user invokes `prism-verify::certify_from_trace(trace, hasher_instance)`.
Per Scenario 2:

1. The verifier decodes the trace bytes against
   `TRACE_REPLAY_FORMAT_VERSION`.
2. Confirms `hasher_identifier` matches the supplied hasher's
   identifier.
3. Walks the five `TraceEvent`s structurally, validating that each
   event's variant is well-typed against its successor (e.g., a
   `DatumAdmissionEvent` must be followed by a
   `CompileUnitConstructionEvent` carrying the same Datum address;
   `PipelineRunEvent.derivation_root` must match the
   `CompileUnitConstructionEvent.root_term`; etc.).
4. Confirms the `PipelineRunEvent`'s scalar nonce matches the digest
   that, under the trace's recorded structural relationships, the
   admitting fiber point produced.
5. **Does not invoke any hasher's hashing method** (TC-05); the
   hasher is provided so its identity can be confirmed.
6. **Does not invoke any decider written by prism-btc** (TC-05);
   `Sha256dProjection`, `NonceFiberTraversal`, and the §4.8
   target-admission rule are not run.
7. On success, mints `Certified<GroundingCertificate>`. On failure,
   emits a structured `ReplayError`.

The `Certified` output is a *structural* attestation: the trace is
internally consistent; its claimed nonce is a coherent record of a
valid pipeline traversal. It is **not** a re-derivation of the digest
or a re-check of the proof-of-work — that re-derivation is the
domain of Bitcoin Core's own validator (which any node receiving the
block performs independently). prism-btc's certification and
Bitcoin's are two distinct claims; they happen to commit to the same
nonce by construction.

---

## 7. Public API surface

This section enumerates the exact Rust signatures the reconciled
prism-btc presents. They are normative: any deviation between code
and these signatures is non-conforming.

### 7.1 `prism_btc` crate (the domain layer)

```rust
// src/lib.rs

/// The application-author entry point. Walks the W32 fiber to find
/// an admitting nonce, constructs `MiningInput` from the resulting
/// 80-byte serialised header, calls `BitcoinMiningModel::forward`,
/// returns the witness + admitting (nonce, digest).
pub fn mine(
    header: &BlockHeader,
    target: Target,
    cancel: &dyn Cancel,
) -> Result<MiningOutcome, MiningFailure>;

/// Parallel variant: partitions the W32 ring across `threads` workers.
#[cfg(feature = "std")]
pub fn mine_parallel(
    header: &BlockHeader,
    target: Target,
    threads: usize,
    cancel: &(dyn Cancel + Sync),
) -> Result<MiningOutcome, MiningFailure>;

/// The grounded mining witness + admitting fiber data.
pub struct MiningOutcome {
    pub witness: MiningWitness, // alias for Grounded<ConstrainedTypeInput, MiningTag>
    pub nonce:   u32,
    pub digest:  [u8; 32],
    pub coords:  TriadicCoords,
}

/// Type alias for the certificate prism-btc returns.
pub type MiningWitness = uor_foundation::enforcement::Grounded<
    uor_foundation::enforcement::ConstrainedTypeInput,
    MiningTag,
>;

/// Phantom tag distinguishing prism-btc's Grounded from other domains.
pub struct MiningTag;

/// Failure modes from `mine`.
pub enum MiningFailure {
    /// All 2^32 fiber points exhausted; no nonce admits this prefix.
    NoMatch,
    /// The boundary cancelled the in-flight traversal.
    Cancelled,
}

// ----- Foundation typed-iso surface (ADR-020 / 022 / 023) -----

/// 80-byte canonical wire-format Bitcoin block header.
/// `ConstrainedTypeShape` (76+4 W8 sites) + hand-rolled
/// `IntoBindingValue` (MAX_BYTES = 80).
pub struct MiningInput(pub [u8; 80]);

/// `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>` —
/// declared via `uor_foundation_sdk::prism_model!` (ADR-022).
/// `Input = MiningInput`, `Output = ConstrainedTypeInput`,
/// `Route = BitcoinMiningRoute` (identity term).
pub struct BitcoinMiningModel;

/// Foundation-closed route witness emitted by `prism_model!`.
pub struct BitcoinMiningRoute;
```

There is no `Boundary` trait. There is no `BoundaryDecodeError`. There
is no `MorphismKind` re-export. There is no `BlockCertificate<Sigma>`.
There is no `MiningRound`. The domain layer's public verbs are `mine`,
`mine_parallel`, `block_hash_grounded`, plus the foundation-typed-iso
surface (`MiningInput`, `BitcoinMiningModel`, `BitcoinMiningRoute`).

### 7.2 `prism_btc::Sha256dHasher` (foundation `Hasher` impl)

```rust
// src/shapes/hasher.rs

pub struct Sha256dHasher { /* internal SHA-256d state */ }

impl uor_foundation::enforcement::Hasher for Sha256dHasher {
    const OUTPUT_BYTES:      usize = 32;
    const HASHER_IDENTIFIER: u32   = /* identifier derived from
        "https://prism.btc/hasher/Sha256dHasher" */;
    fn initial() -> Self;
    fn fold_byte(self, byte: u8) -> Self;
    fn finalize(self) -> [u8; 32];
}
```

The body of `fold_byte` and `finalize` is a `PrimitiveOp` composition
(via the §4.1–§4.2 declarations); the trait impl is the foundation-side
binding. No `sha2` import; no opaque hashing code.

### 7.3 `prism_btc::PrismBtcBounds` (foundation `HostBounds` impl)

```rust
// src/shapes/bounds.rs

pub struct PrismBtcBounds;

impl uor_foundation::HostBounds for PrismBtcBounds {
    const FINGERPRINT_MIN_BYTES: usize = 32;
    const FINGERPRINT_MAX_BYTES: usize = 32;
    const TRACE_MAX_EVENTS:      usize = 64;
    const WITT_LEVEL_MAX_BITS:   u32   = 32;
}
```

### 7.4 `MiningInput` (the model's input shape)

```rust
// src/model.rs

pub struct MiningInput(pub [u8; 80]);

impl uor_foundation::pipeline::ConstrainedTypeShape for MiningInput {
    const IRI:         &'static str = "https://prism.btc/shape/MiningInput";
    const SITE_COUNT:  usize        = 80;
    const CONSTRAINTS: &'static [uor_foundation::pipeline::ConstraintRef] = &[];
}

impl uor_foundation::pipeline::IntoBindingValue for MiningInput {
    const MAX_BYTES: usize = 80;
    fn into_binding_bytes(&self, out: &mut [u8])
        -> Result<usize, uor_foundation::enforcement::ShapeViolation>;
}
```

The 76-byte prefix / 4-byte nonce decomposition is preserved at the
byte-layout level inside the 80-byte payload (positions [0..76) are the
template prefix, [76..80) are the nonce). Foundation 0.4.1 seals
`GroundedShape` to `ConstrainedTypeInput`, so the architecture's
conceptual `TemplatePrefixShape`/`TargetSubBundle` distinction does not
appear as separate `ConstrainedTypeShape` types in code; the rule it
expresses (target admission as halt predicate) is carried by
`NonceFiberTraversal` per §4.8.

### 7.5 `prism_btc_node::Session`

```rust
// crates/prism-btc-node/src/session.rs

pub struct Session {
    rpc_url:        String,
    auth:           bitcoincore_rpc::Auth,
    payout_address: bitcoin::Address,
    network:        bitcoin::Network,
    cfg:            SessionConfig,
}

pub struct SessionConfig {
    pub tip_poll:       Duration,    // poll bestblockhash every N
    pub progress_every: Duration,    // emit a hash-rate report every N
}

impl Session {
    pub fn new(
        rpc_url:        &str,
        auth:           bitcoincore_rpc::Auth,
        payout_address: &str,
        network:        bitcoin::Network,
        cfg:            SessionConfig,
    ) -> Result<Self, SessionInitError>;

    /// The session's outer loop (§6.1). Runs until a block is mined
    /// and `submitblock` returns success, or until `cancel` is set.
    /// Internally calls `prism_btc::mine` once per (template, extranonce);
    /// the mining algorithm is `pipeline::run`, not anything in this crate.
    pub fn mine_until_block(
        &self,
        cancel: Arc<AtomicBool>,
    ) -> Result<MinedBlockReceipt, SessionError>;
}

pub struct MinedBlockReceipt {
    pub hash:      bitcoin::BlockHash,
    pub height:    u64,
    pub witness:   prism_btc::MiningWitness, // §7.1
    pub trace:     prism::Trace,             // §6.4
    pub tx_count:  usize,
}
```

### 7.6 `prism_btc_node::bin::prism_mine` (CLI)

The CLI binary's surface is unchanged from the current state's
intent: `--rpc-url`, `--rpc-user`, `--rpc-pass`, `--network`,
`--payout`, `--blocks`, `--threads`, `--i-know-what-im-doing`. The
`--session` flag becomes redundant (the session is the only mode
under the reconciled architecture) and is removed. `--threads`
becomes a hint to foundation's `NonceFiberTraversal` parallelism
budget but is not load-bearing — the traversal is foundation-typed,
not user-orchestrated.

### 7.7 `prism_btc_wasm::mine_block`

```rust
// crates/prism-btc-wasm/src/api.rs

#[wasm_bindgen]
pub fn mine_block(js_header: &JsBlockHeader, nbits: u32)
    -> Result<JsMiningResult, JsValue>;
```

The body delegates to `prism_btc::mine` with the JS-encoded inputs.
The WASM surface does not expose `Trace`, `Grounded`, or any
foundation type directly; it exposes the digest bytes and the
triadic decomposition (which, under the reconciled architecture, are
queries against the foundation `Triad` minted alongside the witness;
see §5).

### 7.8 What is NOT in the public API

- No `Boundary` trait. Wire decode/encode is `prism-verify`'s
  `certify_from_trace` pathway.
- No `MorphismKind` markers (`DigestProjectionMap` etc.). The
  morphism is a `PrimitiveOp` composition, not a phantom marker.
- No `MiningRound`. The session is the entry point; `mine` is the
  per-invocation primitive.
- No `BlockCertificate<Sigma>`. The witness type is
  `MiningWitness = Grounded<ConstrainedTypeInput, MiningTag>`.
- No `Triadic`/`TriadicCoords` hand-rolled type with Hamming weight
  + nonzero-byte-mask. The triadic decomposition is the foundation
  `Triad` (datum, stratum, spectrum) with stratum being the 2-adic
  valuation and spectrum being the Walsh–Hadamard image (per the
  wiki Glossary). Existing tests that asserted Hamming-weight
  semantics are rewritten against the foundation Triad's actual
  semantics.

---

## 8. The repository layout

Three application crates in this repo, plus three external Prism
crates.

| Crate | Source | Role |
|---|---|---|
| `uor-foundation` | crates.io (`UOR-Foundation/UOR-Framework`, 0.4.1) | Substrate. Sealed types, `PrimitiveOp` discriminants, the closed primitive operation set, the substitution-axis trait surface, `mint_*` primitives, and the typed-iso surface (`PrismModel`, `FoundationClosed`, `IntoBindingValue`, `pipeline::run_route`). |
| `uor-foundation-sdk` | crates.io (`UOR-Foundation/UOR-Framework`, 0.4.1) | The `prism_model!` proc-macro that emits the seal + `FoundationClosed` + `PrismModel` impls from a closure-bodied route declaration (ADR-022). |
| `prism` | crates.io (`UOR-Foundation/Prism`) | Runtime. Three Prism-mechanism sealed types, `pipeline::run`, the seal regime. |
| `prism-verify` | crates.io (`UOR-Foundation/Prism`) | Replay façade. `certify_from_trace`. |
| `prism-btc` | this repo, `crates/prism-btc/` | The application's pure domain layer. Declares all `ConstrainedTypeShape` impls (§4.7, §4.8), all `PrimitiveOp` compositions (§4.1–§4.6), the `HostBounds` selection (§3.2), the `Hasher` selection (§3.3), and the public entry point `mine` that constructs a CompileUnit and invokes `pipeline::run` once per (template, extranonce). No `sha2` dep, no `rayon` dep, no opaque crypto. |
| `prism-btc-node` | this repo, `crates/prism-btc-node/` | The bitcoind boundary. The only external-system glue: `getblocktemplate`, `submitblock`, `getbestblockhash` polling for tip-change. Holds the session's outer loop (§6.1). Also hosts the `prism-mine` CLI binary. Imports `bitcoincore-rpc` and `rust-bitcoin` as the RPC and serialisation surfaces. **No mining algorithm lives here**; the algorithm is `pipeline::run`. |
| `prism-btc-wasm` | this repo, `crates/prism-btc-wasm/` | The JavaScript surface. `wasm-bindgen` wrapper around `prism-btc::mine`. |

Three application crates, mirroring the framework's three-crate
substrate/runtime/replay split at the application scale (domain layer
/ boundary layer / wasm wrapper). The earlier draft's
`prism-btc-shapes` / `prism-btc-ops` / `prism-btc-pipeline`
sub-decomposition is rejected as over-engineering for this scale; the
domain layer is one crate.

### 8.1 Disappearances under reconciliation

These current artifacts are gone in the reconciled state:

| Removed artifact | Why |
|---|---|
| `crates/prism-btc-reduction/` (entire crate) | Its role (σ-projection + nonce iteration) is absorbed into `prism-btc`'s `PrimitiveOp` compositions and `pipeline::run`. |
| `crates/prism-btc-reduction/src/parallel.rs` | The rayon for-loop is replaced by `NonceFiberTraversal` (§4.6). |
| `crates/prism-btc-reduction/src/sha256d.rs` | The `sha2`-crate call is replaced by `Sha256dProjection` (§4.2). |
| `crates/prism-btc-reduction/src/serialize.rs` | The hand-rolled byte layout is replaced by `HeaderSerialization` (§4.3). |
| `crates/prism-btc-reduction/src/certificate.rs::BlockCertificate<Sigma>` | Replaced by `Grounded<ConstrainedTypeInput, MiningTag>` direct from `pipeline::run`. The phantom `Sigma` is removed because the σ-projection is now a concrete `PrimitiveOp` composition. |
| `crates/prism-btc-reduction/src/hasher.rs::Fnv1aHasher16` | Replaced by `Sha256dHasher` (§3.3). The Fnv1a substrate was a workaround when σ-projection and the foundation Hasher were conflated; under the §3.3 split they are now the same algorithm. |
| `Boundary` trait + `BoundaryDecodeError` (in `prism-btc/src/traits.rs`) | The wire-byte ↔ certificate isomorphism is no longer modelled as a separate trait; the trace IS the wire representation, and `prism-verify::certify_from_trace` IS the decode operation. |
| `MiningSession` (in `prism-btc-node/src/session.rs`) | The orchestrator that drives the rayon loop is gone; the session's outer loop (§6.1) — extranonce rolling, tip-change polling, hash-rate reporting — moves into a much smaller `prism-btc-node::session` module that does only what bitcoind requires of an external miner. The inner inference is `pipeline::run`. |
| `Cargo.toml` deps: `sha2`, `rayon` | gone. ADR-013 closure: SHA-256 is a `PrimitiveOp` composition; parallelism is a foundation-level concern within `NonceFiberTraversal`. |
| The `MorphismKind` / `DigestProjectionMap` / `BinaryGroundingMap` / `BinaryProjectionMap` / `ProjectionMapKind` / `GroundingMapKind` / `Total` / `Invertible` re-exports in the prelude | These markers were placeholders for what `PrimitiveOp` compositions now express concretely. With the operations declared as compositions, the markers are redundant. |

### 8.2 Imports outside the framework (closure under uor-foundation, ADR-013)

Per ADR-013 every prism-btc operation must be derivable from
`uor-foundation`'s closed primitive set. The architecture admits these
**non-foundation** dependencies, and only these:

| Dependency | Crate | Justification |
|---|---|---|
| Bitcoin RPC client | `bitcoincore-rpc` | The `bitcoind` boundary is an external system (ADR-004). `getblocktemplate`/`submitblock` are not Prism operations; they are calls into bitcoind's RPC. |
| Block / transaction serialisation | `bitcoin` (rust-bitcoin) | The block envelope, transaction format, script encoding, address parsing are Bitcoin protocol details outside Prism's scope. The σ-projection and merkle root are NOT delegated to rust-bitcoin; only the block-level container around a finished mining result is. |
| CLI argument parsing | `clap` | Outside Prism's scope. |
| Error reporting | `anyhow` | Outside Prism's scope. |
| Signal handling | `ctrlc` | Outside Prism's scope. |
| Serialisation glue for RPC | `serde`, `serde_json`, `hex` | Required by `bitcoincore-rpc`'s public surface; outside Prism's scope. |
| WebAssembly bindings | `wasm-bindgen`, `js-sys` | Outside Prism's scope (a JS interop concern). |

No cryptographic dependency (`sha2`, `blake3`, etc.). No
parallelism dependency (`rayon`, `tokio`, `crossbeam`). No
hand-rolled iteration utilities. The σ-projection, the nonce
traversal, the merkle derivation, the coinbase construction are all
foundation `PrimitiveOp` compositions.

---

## 9. The boundary properties (TC-01 .. TC-06) in prism-btc terms

| Constraint | How prism-btc realises it |
|---|---|
| **TC-01 zero-cost runtime** | Every `ConstrainedTypeShape` impl, `PrimitiveOp` composition, and substitution-axis selection is resolved by `rustc` at compile time. The executable contains no UORassembly enforcement code. The W32 traversal loop is a foundation-provided primitive; its body is monomorphised by the Rust compiler against `Sha256dHasher`. |
| **TC-02 sealing** | prism-btc constructs zero sealed types directly. Every `Datum`, `Triad`, `Derivation`, `FreeRank`, `Validated`, `Grounded`, `Certified` arrives via foundation's `mint_*` primitives or as a `pipeline::run` return value. The `BlockCertificate<Sigma>` wrapper is removed (§6.1); the Grounded is consumed directly. |
| **TC-03 path singularity** | `pipeline::run` is the only pathway to a `Grounded<...>` for prism-btc. Multiple invocations during extranonce rolling are permitted — TC-03 forbids alternative constructors, not iteration over the singular constructor. |
| **TC-04 UORassembly bilateral** | `prism-btc`'s ConstrainedTypeShape impls and PrimitiveOp compositions must satisfy `prism`'s trait bounds; checked by `rustc` on every build. Foundation amendments (ADR-013) are sequenced before prism-btc updates that depend on them. |
| **TC-05 replayability without deciders or hashing** | `prism-verify::certify_from_trace` walks the five-event trace structurally (§6.6). It does not invoke `Sha256dHasher`'s hashing method, does not invoke `Sha256dProjection`, does not invoke the §4.8 target-admission rule. It produces `Certified<GroundingCertificate>` from the trace's recorded fingerprint and structural relationships. |
| **TC-06 no author infrastructure** | `prism-mine` runs entirely on user hardware. The user supplies the bitcoind RPC. There is no prism-btc service, no callback to a content-addressed registry, no telemetry. After distribution, the binary is fully self-contained. |

---

## 10. Compile-time vs runtime separation

Per TC-01 + ADR-006 + Runtime View Scenario 3, the work split is
strict.

### At compile time (Scenario 3):

- `rustc` checks every `ConstrainedTypeShape` impl against `prism`'s
  `ConstrainedTypeShape` trait bounds.
- `rustc` checks every `PrimitiveOp` composition for closure under
  the foundation's primitive set (ADR-013).
- `rustc` monomorphises `pipeline::run::<ConstrainedTypeInput, M, H>`
  for `M = BinaryGroundingMap` and `H = Sha256dHasher` (§3.3).
- `rustc` validates `HostBounds::PrismBtcBounds`'s capacity constants
  against the wires they parameterise (ADR-018).
- The validated `CompileUnit`'s static structure (root term, witt
  level, target domains) is encoded into the executable as
  monomorphised constants. ConstrainedTypeShape `IRI`, `SITE_COUNT`,
  and `CONSTRAINTS` are static.
- The executable that `cargo build` produces contains no UORassembly
  validation code (TC-01).

### At runtime (Scenarios 1, 2, 4):

- `prism-btc-node` calls `bitcoind::getblocktemplate` (the only
  cross-boundary call).
- `prism-btc::mine` constructs the per-invocation CompileUnit
  (template-dependent), validates it (which is mostly a no-op since
  the structure is monomorphised; only template-specific sites need
  runtime validation), invokes `pipeline::run`.
- The pipeline executes `NonceFiberTraversal`'s deterministic
  traversal of the W32 ring. The runtime work is the σ-projection
  evaluation per fiber visit and the admission check per visit.
- `pipeline::run` returns `(Grounded<...>, Trace)`.
- `prism-btc-node` assembles the wire-format Block and submits.
- A user runs `prism-verify::certify_from_trace` on the trace; this
  runs structurally against the trace's events without invoking any
  decider or hasher (TC-05).

Compile time produces the executable; runtime produces the block.

---

## 11. Non-goals (explicit)

- **No SHA-256 inversion.** The strong cryptanalytic claim is not
  asserted. `nonce_fiber_traversal`'s structural form
  `first_admit(W32, |n| hash(concat(input, n)) <= input)` declares
  the typed predicate the catamorphism evaluates; the catamorphism
  evaluates the predicate at fiber points (per the implementation
  runtime's strategy under ADR-026 G16) until admission. The
  evaluation count is a property of the constraint's structural
  complexity (the number of leading-zero bits the `Le` admission
  enforces) and the `Hasher` substitution-axis impl's per-call cost.
  Different `Hasher` selections (e.g., `Sha256dHasher` vs an
  intrinsics-backed equivalent) and different implementation
  runtimes (sequential vs parallel coset partition vs fully
  parallel via a different ADR-007 axis selection) change this cost
  parametrically.
- **`Hasher` per-evaluation cost is a substitution-axis property,
  not a prism-btc property.** prism-btc's `Sha256dHasher` is one
  `Hasher` impl (pure-Rust, no external crypto dep, ADR-013
  closure-conformant). Under ADR-007's three-position pattern, an
  application author can select a different `Hasher` impl (e.g., a
  SHA-NI-intrinsics impl that the application crate ships and
  binds at the model declaration site) without changing
  `BitcoinMiningModel`'s route or `nonce_fiber_traversal`'s verb
  body. The architectural value (closure under ADR-013,
  structurally-traced derivation, replayability without re-hashing,
  parametricity in the substitution axes) is the deliverable;
  per-call performance is a substitution-axis dimension the
  architecture exposes for the implementor to choose, not a fixed
  cost.
- **No foundation amendments asserted by this document.** Foundation
  0.3.6's `PrismModel<H, B, A>` (ADR-020) + `IntoBindingValue`
  (ADR-023) + `pipeline::run_route` (ADR-022 D5) +
  `evaluate_term_tree` (ADR-029, recursive `Term::Recurse`) +
  `Grounded::output_bytes` (ADR-028) + `TERM_VALUE_MAX_BYTES = 4096`
  per-value capacity + `PrimitiveOp::{Le, Lt, Ge, Gt, Concat}`
  (substrate amendment per ADR-013/TR-08) + closure-body-grammar
  binary comparison operators + `concat(...)` keyword supply the
  typed-iso surface prism-btc requires. The W32 fiber traversal
  lives in prism-btc per ADR-026 G16's three-way responsibility
  split (substrate provides structural primitives; prism provides
  the operator declaration; the implementation provides the runtime
  traversal that respects the structural declaration). This document
  forbids importing an opaque external crate (`sha2`, `blake3`, etc.)
  in lieu of `Sha256dHasher`, the application's pure-Rust `Hasher`
  substitution-axis selection.
- **No mining-pool integration.** Stratum protocol, share submission,
  pool wallet management — all out of scope. prism-btc is solo-mining
  only; the bitcoind it talks to is the user's own.
- **No support for chains other than Bitcoin Core's accepted networks.**
  prism-btc supports `regtest`, `signet`, `testnet`, `testnet4`,
  `mainnet`. Other PoW chains (Litecoin, Bitcoin Cash, etc.) require
  a different `Hasher` substitution-axis selection (e.g. scrypt for
  Litecoin) or a different `ConstrainedTypeShape` for the input;
  they are scope for a different architecture document.

---

## 12. Reconciliation plan

The current repository state is non-conforming to this architecture
in the ways enumerated in §6.1. Reconciliation is one coherent change
set, not a sequence of phases:

1. **Replace the σ-projection.** Delete `prism-btc-reduction/src/sha256d.rs`
   and the `sha2` workspace dependency. Declare `Sha256Compression`
   and `Sha256dProjection` as `PrimitiveOp` compositions in
   `crates/prism-btc/src/ops/sha256.rs`.
2. **Replace the nonce iteration.** Delete `prism-btc-reduction/src/parallel.rs`
   and the `rayon` workspace dependency. Declare `NonceFiberTraversal`
   as a `kernel::convergence`-driven W32 fold in
   `crates/prism-btc/src/ops/traversal.rs`.
3. **Replace the wire serialisation.** Delete `prism-btc-reduction/src/serialize.rs`.
   Declare `HeaderSerialization` as a `depth-projection` composition
   in `crates/prism-btc/src/ops/header.rs`.
4. **Add merkle derivation and coinbase construction.** New
   compositions `MerkleRootDerivation`, `CoinbaseConstruction` in
   `crates/prism-btc/src/ops/{merkle,coinbase}.rs`. These replace the
   current rust-bitcoin merkle/coinbase logic in
   `prism-btc-node/src/session.rs`.
5. **Replace the certificate type.** Delete
   `prism-btc-reduction/src/certificate.rs` (the `BlockCertificate<Sigma>`
   wrapper). The result type of `prism-btc::mine` is
   `Grounded<ConstrainedTypeInput, MiningTag>` (alias
   `prism_btc::MiningWitness`), accompanied by a `Trace`.
6. **Replace the Hasher.** Delete `prism-btc-reduction/src/hasher.rs`
   (Fnv1aHasher16). Define `Sha256dHasher` in
   `crates/prism-btc/src/shapes/hasher.rs` as a foundation `Hasher`
   impl whose body is the `Sha256dProjection` PrimitiveOp composition.
7. **Declare the model's input shape.** `MiningInput` (§4.7) lives in
   `crates/prism-btc/src/model.rs` as the single load-bearing
   `ConstrainedTypeShape` impl: 80 W8 sites, the canonical wire-format
   header. The conceptual `TemplatePrefixShape` (76 sites) and
   `TargetSubBundle` (32 sites) of an earlier draft are conceptual
   only — foundation 0.4.1 seals `GroundedShape` to
   `ConstrainedTypeInput`, so they cannot appear as `Grounded<T>`
   parameters. Their semantics are carried inside `MiningInput`'s
   76/4-byte payload split and `NonceFiberTraversal`'s halt predicate.
8. **Define `PrismBtcBounds`.** A unit struct in
   `crates/prism-btc/src/shapes/bounds.rs` with the four
   `HostBounds` constants per §3.2.
9. **Declare the public entry point.** A single
   `crates/prism-btc/src/pipeline.rs::mine(header: &BlockHeader,
   target: Target, cancel: &dyn Cancel) -> Result<MiningOutcome,
   MiningFailure>` that walks the W32 fiber, on admission wraps the
   80-byte header in `MiningInput`, and calls
   `BitcoinMiningModel::forward` to mint the foundation-sealed
   witness. Returns `MiningOutcome { witness, nonce, digest, coords }`.
10. **Dissolve `prism-btc-reduction`.** Remove the crate from the
    workspace; remove the dependency from `prism-btc` and
    `prism-btc-node`. The crate is gone.
11. **Rewire `prism-btc-node` to invoke `prism-btc::mine`.** Delete
    `prism-btc-node/src/session.rs::MiningSession`. Replace with a
    minimal `Session` that does only: tip polling, extranonce
    iteration, calling `prism-btc::mine`, calling `submitblock`. No
    rayon, no closures, no parallel orchestration logic.
12. **Update `prism-btc-wasm`.** Re-target its `mine_block` against
    `prism-btc::mine`'s new signature.
13. **Delete the `Boundary` trait, `BoundaryDecodeError`, the
    `MorphismKind` re-exports.** Update prelude and lib re-exports.
14. **Update the README.** Replace the existing "Mining as
    σ-convergence" framing with the §1 real-time-inference framing.
    Remove the testnet4 demo paragraph (its framing was
    rejected); replace with a description of what the architecture
    achieves.
15. **Delete or update the existing tests.** The parallel/rayon tests
    are gone. Add new tests: a regtest end-to-end through
    `prism-btc::mine` + `submitblock`; a trace-replay test that
    `prism-verify::certify_from_trace` produces a `Certified` from
    the regtest run's emitted trace.

The reconciliation is non-conforming if any of the 15 points above is
incomplete: prism-btc is either fully in this state, or it is
non-conforming. There is no partial conformance.

---

## 13. Responsibility split: foundation substrate vs prism implementor

The wiki distinguishes two roles, and prism-btc occupies the second.
Foundation 0.4.1 closes the substrate-vs-implementor gap with the
typed-iso surface plus the catamorphism evaluator
(ADR-019/020/022/023/026/028/029):

- **`uor-foundation` (0.4.1) is the substrate.** It provides:
  sealed types (`Datum`, `Triad`, `Derivation`, `FreeRank`,
  `Validated`, `Grounded`, `Certified`); the closed `PrimitiveOp`
  vocabulary (15 generators — the original 10 dihedral generators
  plus `Le`, `Lt`, `Ge`, `Gt`, `Concat` added in 0.3.6 per
  ADR-013/TR-08 substrate amendment) and `Term` variants (10 forms,
  with `HasherProjection` added in 0.3.3 per ADR-026 G19); the
  substitution-axis traits (`Hasher`, `HostBounds`, `HostTypes`,
  `GroundingMapKind`); the mint primitives (`mint_datum`,
  `mint_triad`, `mint_derivation`, `mint_freerank`); the
  `Trace`/`TraceEvent` structure and `enforcement::replay::certify_from_trace`;
  and the **typed-iso surface** introduced in 0.3.2 and extended
  through 0.3.6: `PrismModel<H, B, A>` (ADR-020), `FoundationClosed`
  (ADR-022 D1), `IntoBindingValue` (ADR-023), `pipeline::run_route`
  (ADR-022 D5), `pipeline::evaluate_term_tree` (ADR-029, with
  `Term::Recurse` evaluating recursively to N iterations and
  `Term::Unfold` to a Kleene fixpoint or `UNFOLD_MAX_ITERATIONS`,
  both shipped in 0.3.6), `Grounded::output_bytes` (ADR-028), and
  the `TermValue` per-value carrier with `TERM_VALUE_MAX_BYTES =
  4096` capacity.
- **`uor-foundation-sdk` (0.4.1)** ships the `prism_model!` and
  `verb!` proc-macros that emit the seal impls + `FoundationClosed`
  impl + `PrismModel` impl from closure-bodied declarations (ADR-022
  D3 grammar G1–G11 plus ADR-026 G13–G19 for `parallel`, `fold_n`,
  `tree_fold`, `first_admit`, `recurse`, `unfold`, `hash(input)`
  lowering to `Term::AxisInvocation` (canonical hash axis), plus 0.3.6's substrate-
  amendment forms: binary `<= < >= >` lowering to `Term::Application`
  over `PrimitiveOp::{Le, Lt, Ge, Gt}` and `concat(a, b)` lowering
  to `Term::Application` over `PrimitiveOp::Concat`). The macros
  are the sanctioned path for declaring application models and
  Layer-3 verbs.
- **`prism-btc` is the prism implementor for the Bitcoin use case.**
  It declares its `PrismModel<DefaultHostTypes, PrismBtcBounds,
  Sha256dHasher>` via `prism_model!` ([`crate::model::BitcoinMiningModel`]),
  provides the `MiningInput` `ConstrainedTypeShape` + `IntoBindingValue`
  for the 80-byte canonical wire-format header, provides the
  `Sha256dHasher` and `PrismBtcBounds` substitution-axis selections,
  and provides the W32 fiber traversal runtime that finds the input
  value to feed `BitcoinMiningModel::forward`. Foundation drives the
  catamorphism (ADR-019); prism-btc drives the search.

The architecture above (§§1–11) is therefore a specification of
prism-btc's runtime, expressed in foundation 0.4.1 vocabulary, not a
list of demands on foundation. Foundation does not need to be amended
for prism-btc to reach the defined state; prism-btc just needs to be
written.

### 13.0 ADR alignment

| Wiki ADR | prism-btc realisation |
|---|---|
| ADR-019 (foundation as initial-algebra signature) | `Term`-based route declarations consumed by `pipeline::evaluate_term_tree` as the catamorphism. |
| ADR-020 (PrismModel hylomorphism contract) | `BitcoinMiningModel` impls `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>`. |
| ADR-021 (V&V split: prism = V, prism-verify = IV&V) | `BitcoinMiningModel::forward` is the V agent (catamorphism); foundation's `enforcement::replay::certify_from_trace` is the IV&V agent (anamorphism). |
| ADR-022 D1 (`FoundationClosed` seal) | `BitcoinMiningRoute`'s seal + `FoundationClosed` impl emitted by `prism_model!`. |
| ADR-022 D2 (`TermArena::from_slice`) | `prism_model!` emits the const `ROUTE_TERMS_FOR_BITCOIN_MINING_MODEL: &'static [Term]` slice carrying `[Term::Variable {0}, Term::AxisInvocation {0,0,0}]`. |
| ADR-022 D3 (closure grammar G1–G11) | `BitcoinMiningModel`'s route body is `hash(input)`. |
| ADR-022 D4 (substitution axes at impl site) | `impl PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>`. |
| ADR-022 D5 (`run_route` call-site) | `BitcoinMiningModel::forward` body delegates to `pipeline::run_route`. |
| ADR-023 (`IntoBindingValue` + buffer ceiling) | `MiningInput` impls `IntoBindingValue` with `MAX_BYTES = 80`; well under `ROUTE_INPUT_BUFFER_BYTES = 4096`. |
| ADR-026 G19 + ADR-030 (`hash(input)` → `Term::AxisInvocation`) | `prism_model!` lowers `hash(input)` to `Term::AxisInvocation { axis_index: 0, kernel_id: 0, input_index: 0 }` (the canonical hash axis) over `Term::Variable {0}`. |
| ADR-028 (`Grounded::output_bytes` carrier) | `MiningWitness::output_bytes()` exposes the catamorphism evaluator's TermValue payload. |
| ADR-029 (catamorphism evaluator) | `pipeline::run_route` calls `pipeline::evaluate_term_tree`. The `AxisInvocation` fold rule dispatches `(axis 0, kernel 0)` through `Sha256dHasher` via the blanket `AxisTuple` impl. `Term::Recurse` iterates N times (recursive fold-rule), `Term::Unfold` iterates to a Kleene fixpoint, `Term::FirstAdmit` iterates ascending and short-circuits — all per ADR-029's per-variant fold rules. |
| ADR-030 (`AxisExtension` + `AxisTuple`) | `Sha256dHasher` is automatically a 1-tuple `AxisTuple` via the blanket `impl<H: Hasher> AxisTuple for H`; `(axis_index: 0, kernel_id: 0)` dispatches to `Hasher::initial().fold_bytes(input).finalize()`. |
| ADR-032 (`CYCLE_SIZE` on `ConstrainedTypeShape`) | `MiningInput` declares `CYCLE_SIZE = u64::MAX` (saturating; 80 bytes ≫ 2^64). The `nonce_fiber_traversal` verb names `witt_domain::W32` whose `CYCLE_SIZE = 2^32` becomes the search domain. |
| ADR-033 (`PartitionProductFields` + `Term::ProjectField`) | `MiningInput` is a single 80-byte shape (not a partition product); the closure-body grammar's field-access form is admitted by 0.4.0 but not consumed by this implementation. |
| ADR-034 Mechanism 1 (`recurse(measure, base, \|self, idx\| step)`) | Not consumed by `nonce_fiber_traversal` (uses `first_admit` instead); admitted by 0.4.1's SDK if a future verb needs index-aware tail recursion. |
| ADR-034 Mechanism 2 (`Term::FirstAdmit`) | `nonce_fiber_traversal`'s `first_admit(witt_domain::W32, …)` lowers to `Term::FirstAdmit { domain_size_index, predicate_index }` (foundation 0.4.1 SDK). The catamorphism iterates `idx` ascending from 0 to 2^32, threads the candidate `idx` through the predicate via `FIRST_ADMIT_IDX_NAME_INDEX`, and short-circuits on the first non-zero predicate result — the wiki's intended search semantics, end-to-end through the catamorphism. |

### 13.1 What foundation 0.4.1 supplies, used as-is

| Surface | Foundation path | prism-btc usage |
|---|---|---|
| Sealed `Datum`, `Triad`, `Derivation`, `FreeRank` | `enforcement::{Datum, Triad, Derivation, FreeRank}` | Returned via mint primitives during admission. |
| Sealed `Validated`, `Grounded`, `Certified` | `enforcement::{Validated, Grounded}` + `enforcement::replay::certify_from_trace` returning `Certified` | Returned by `pipeline::run` (Grounded) or replay (Certified). prism-btc never constructs them directly. |
| `mint_*` primitives | `enforcement` module | Foundation's pipeline / replay machinery calls these; prism-btc does not. |
| `CompileUnitBuilder` + `Validated<CompileUnit, FinalPhase>` | `enforcement::{CompileUnit, CompileUnitBuilder}` | Used to declare the BlockHash shape unit; const-validated via `validate_compile_unit_const`. |
| `pipeline::run` / `pipeline::run_route` | `pipeline::{run, run_route}` | `run_route` is the typed-iso entry (ADR-022 D5); `BitcoinMiningModel::forward` delegates to it. Foundation drives the catamorphism; prism-btc does not call `run` or `run_const` directly any longer. |
| `pipeline::PrismModel<H, B, A>` (ADR-020) | `pipeline::PrismModel` | Implemented by `BitcoinMiningModel` via the `prism_model!` macro. The typed-iso contract. |
| `pipeline::FoundationClosed` (ADR-022 D1) | `pipeline::FoundationClosed` | Implemented by `BitcoinMiningRoute` via `prism_model!`'s emission. |
| `pipeline::IntoBindingValue` (ADR-023) | `pipeline::IntoBindingValue` | Implemented hand-rolled by `MiningInput` (the wiki sanctions hand-rolled impls for application authors carrying runtime input data). |
| Closed `PrimitiveOp` set (15 generators) | `enums::PrimitiveOp` | The 10 dihedral generators (`Add`, `Sub`, `Mul`, `Xor`, `And`, `Or`, `Neg`, `Bnot`, `Succ`, `Pred`) plus the 5 ADR-013/TR-08 amendments: `Le`, `Lt`, `Ge`, `Gt` (byte-level lexicographic comparison), `Concat` (byte-sequence concatenation). The SDK closure-body grammar admits all 15 plus `hash` (G19), `first_admit` (G16), `concat`, and the binary `<=`, `<`, `>=`, `>` operators. |
| `Term` (10 variants, with `AxisInvocation` per ADR-030 replacing `HasherProjection` from 0.3.3–0.3.6) | `enforcement::Term` | Emitted by `prism_model!` into the route witness's const arena: `[Term::Variable {0}, Term::AxisInvocation {axis_index: 0, kernel_id: 0, input_index: 0}]`. |
| `pipeline::evaluate_term_tree` (ADR-029) | `pipeline::evaluate_term_tree` | Called by `run_route` at runtime; the `AxisInvocation` fold-rule dispatches `(axis 0, kernel 0)` through `Sha256dHasher` via the blanket `AxisTuple` impl. |
| `pipeline::AxisExtension` + `AxisTuple` (ADR-030) | `pipeline::{AxisExtension, AxisTuple}` | Foundation provides a blanket `impl<H: Hasher> AxisTuple for H` so `Sha256dHasher` participates as the canonical 1-tuple AxisTuple without prism-btc declaring its own axis. |
| `pipeline::TermValue` + `TERM_VALUE_MAX_BYTES = 4096` | `pipeline::TermValue` | The catamorphism's per-value carrier. Wide enough for the 80-byte mining input to flow through `Variable` and `AxisInvocation` whole. |
| `pipeline::witt_domain::{W8, W16, W24, W32, …}` (ADR-032) | `pipeline::witt_domain::W32` | `ConstrainedTypeShape`-implementing domain markers with `CYCLE_SIZE` set per the Witt level's cardinality. `nonce_fiber_traversal`'s `first_admit` references `witt_domain::W32` (`CYCLE_SIZE = 2^32`). |
| `Grounded::output_bytes` (ADR-028) | `enforcement::Grounded::output_bytes` | Carries the catamorphism evaluator's result on the witness. |
| `ConstrainedTypeShape` trait + `ConstraintRef` | `pipeline::{ConstrainedTypeShape, ConstraintRef}` | Implemented by `MiningInput`. |
| `HostBounds` trait | `HostBounds` | Implemented by `PrismBtcBounds`. |
| `Hasher` trait | `enforcement::Hasher` | Implemented by `Sha256dHasher` with arbitrary Rust code (ADR-010). |
| `Trace` and `TraceEvent` | `enforcement::{Trace, TraceEvent}` | Emitted by foundation's pipeline, consumed by `enforcement::replay::certify_from_trace`. |
| `enforcement::replay::certify_from_trace` | `enforcement::replay::certify_from_trace` | Mints `Certified` from a `Trace` without invoking prism-btc deciders or `Sha256dHasher`'s body (TC-05). |

### 13.2 What prism-btc supplies as the prism implementor

| Surface | prism-btc path | Role |
|---|---|---|
| `Sha256dHasher` | `prism_btc::shapes::hasher::Sha256dHasher` | Foundation `Hasher` substitution-axis selection. Body is pure-Rust SHA-256d. ADR-010 conforming (deterministic, fixed-width 32 bytes, idempotent, distinct identifier IRI). |
| `PrismBtcBounds` | `prism_btc::shapes::bounds::PrismBtcBounds` | Foundation `HostBounds` selection. ADR-018 capacity constants. |
| `MiningInput` | `prism_btc::model::MiningInput` | `ConstrainedTypeShape` (80 W8 sites) + hand-rolled `IntoBindingValue` (MAX_BYTES = 80). The 80-byte canonical wire-format Bitcoin block header. |
| `BitcoinMiningModel` + `BitcoinMiningRoute` | `prism_btc::model::*` | `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>` declared via `prism_model!`. Route body `hash(input)` (ADR-026 G19) lowers to `[Term::Variable {0}, Term::AxisInvocation {0,0,0}]`. |
| (`TemplatePrefixShape`, `TargetSubBundle`) | _conceptual only_ | The architecture's input/output sub-bundle distinction is carried inside `MiningInput`'s 76/4 byte split and `NonceFiberTraversal`'s halt predicate. Foundation 0.4.1 seals `GroundedShape` to `ConstrainedTypeInput`, so these conceptual shapes do not appear as separate `ConstrainedTypeShape` types in code. |
| `Sha256Compression`, `Sha256dProjection`, `HeaderSerialization`, `MerkleRootDerivation`, `CoinbaseConstruction` | `prism_btc::ops::*` | Pure-Rust runtime evaluators; no `sha2` dependency. The σ-projection runtime is identical to what `Sha256dHasher` does inside `pipeline::run_route`. |
| `NonceFiberTraversal` | `prism_btc::ops::traversal` | An optional ADR-026 G16 implementation-runtime override. Foundation 0.4.1 evaluates the [`crate::verbs::nonce_fiber_traversal`] verb's `Term::FirstAdmit` end-to-end per ADR-034 Mechanism 2 (no implementation-side delegation needed for structural correctness). prism-btc's runtime adds two practical capabilities the foundation evaluator doesn't yet expose: parallel coset-partition traversal (`traverse_parallel`, ADR-026 G16 sanctions parallel overrides) and external cancellation (the bitcoind boundary's tip-watcher signals via the [`Cancel`] trait through every fiber visit). |
| `mine()` | `prism_btc::pipeline::mine` | The public entry point. Walks the W32 fiber to find an admitting nonce, constructs `MiningInput` from the 80-byte serialized header, calls `BitcoinMiningModel::forward(input)` to mint the foundation-sealed `Grounded<ConstrainedTypeInput>`, tags it with `MiningTag`, returns `MiningOutcome`. |

The substrate-vs-implementor split above is the architecture's
load-bearing distinction. Foundation does not ship a search runtime,
a SHA-256 implementation, or a fold-with-halt primitive because those
belong to the prism implementor. Reconciling prism-btc to the
architecture is therefore a matter of prism-btc writing what is its
responsibility to write — which it now does, in full, against
foundation 0.4.1's typed-iso surface.

### 13.3 The mining inference under the UOR lens

The wiki's Conceptual-Model defines mining for prism-btc not as a
brute-force search but as one **typed inference** — a `PrismModel`
declaration (ADR-020) whose `forward` evaluates a verb-spliced
`Term` arena (ADR-024 + ADR-026) through foundation's catamorphism
(ADR-029). Reading prism-btc through that lens dissolves three
traditional-miner concepts that don't survive translation:

#### "Difficulty" → output-shape constraint complexity

Bitcoin's `nBits` field is — in UOR terms — the **byte threshold
for an `Le` admission constraint** on the catamorphism's output
payload. The `nonce_fiber_traversal` verb's body
`first_admit(W32, |nonce| hash(concat(input, n)) <= input)` lowers
to a `Term::Recurse` whose step contains
`Term::Application(Le, [hash_term, target_term])`. The constraint's
**structural complexity** — the count of leading-zero bits the `Le`
admission enforces — is what Bitcoin calls "difficulty." It is a
typed property of the output declaration's `CONSTRAINTS` list, not
a probabilistic puzzle parameter.

Under this reading, "difficulty" is a static property of the
catamorphism's output type, decoded from the runtime input
(`getblocktemplate`'s `bits`) at evaluation time the same way any
other constraint parameter is decoded. The traversal admits when
the predicate evaluates to `Literal(1)` per the `Le` fold-rule
(ADR-029); admission is constraint satisfaction, not a coin flip.

#### "CPU mining time" → catamorphism evaluation cost, parametric in (Hasher, HostBounds, runtime)

Wall-clock-to-admission in a traditional miner is "expected SHA-256
evaluations × per-evaluation cost." Under the UOR lens it is the
catamorphism's evaluation cost on `nonce_fiber_traversal`'s `Term`
arena — and that cost is **parametric in the substitution-axis
triple plus the implementation runtime**:

- **`Hasher` axis** (ADR-007, ADR-010): determines the per-fiber-visit
  cost of evaluating `Term::AxisInvocation` (canonical hash axis). prism-btc's
  `Sha256dHasher` is one impl (pure-Rust, ADR-013-conformant, no
  external dep). An alternative `Hasher` impl with SHA-NI / AVX2
  intrinsics — bound at the `BitcoinMiningModel` declaration site,
  ADR-007 three-position pattern — changes per-evaluation cost
  without changing the verb body or the route.
- **`HostBounds` axis** (ADR-018): determines the domain's
  cardinality and per-value buffer ceilings. prism-btc's
  `PrismBtcBounds` selects `WITT_LEVEL_MAX_BITS = 32` (the `W32`
  fiber); a different bounds selection would parameterise the
  domain.
- **Implementation runtime** (ADR-026 G16): the W32 traversal's
  evaluation strategy. Sequential, std-thread-scoped parallel, or
  a different parallelism realisation (e.g., FPGA-bound coset
  evaluator behind the same `traverse_first_admit` contract). The
  contract is "produces the same first-admitting index a reference
  sequential traversal would"; the strategy is the implementor's
  choice.

"CPU forever" is not a property of prism-btc — it is a property of
**one specific instantiation** (pure-Rust `Hasher` + sequential
runtime). The architecture's ADR-007 + ADR-026 G16 parametricity
exposes the substitution-axis dimensions for the implementor to
choose; the architectural commitment is the typed structure, not a
fixed cost.

#### "Network" → runtime input value, not branch in the implementation

prism-btc's code path does not branch on regtest / signet / testnet
/ testnet4 / mainnet. Same `BitcoinMiningModel`, same
`nonce_fiber_traversal` verb, same `Sha256dHasher`, same
`PrismBtcBounds`, same implementation runtime. The
network-dependent value is `getblocktemplate`'s `bits` field, which
becomes the runtime byte-threshold the catamorphism's `Le`
admission constraint enforces.

| Element | Regtest | Mainnet | Why identical |
|---|---|---|---|
| `BitcoinMiningModel` impl | same | same | one const term arena |
| `nonce_fiber_traversal_term_arena()` | same | same | one verb declaration |
| Substitution-axis triple `(H, B, A)` | same | same | one `impl PrismModel<…>` site |
| Catamorphism evaluator | same | same | foundation `pipeline::run_route` |
| Implementation runtime per ADR-026 G16 | same | same | one runtime in `ops/traversal` |
| `Grounded::output_bytes` semantics | block hash | block hash | ADR-028 invariant |
| `getblocktemplate.bits` (runtime input) | `0x207fffff` | `0x17xxxxxx` | network-dependent runtime *value*, not configuration |

### 13.4 Layer-3 verb declarations (ADR-024 + ADR-026 G16)

prism-btc declares its mining-domain verbs in
[`crate::verbs`](crates/prism-btc/src/verbs.rs) via the
`uor-foundation-sdk::verb!` macro. Each verb's term-tree fragment is
a `&'static [Term]` slice emitted at the application's compile time;
the SDK runs the verb-closure check (closure under foundation
primitives ∪ own-implementation verbs ∪ imported verbs; acyclicity
through non-`recurse` operators); the implementation provides the
runtime that evaluates the declaration per ADR-026 G16's three-way
responsibility split.

#### `nonce_fiber_traversal`

| Field | Value |
|---|---|
| Body | `first_admit(witt_domain::W32, \|nonce\| hash(concat(input, nonce)) <= input)` |
| Lowering | `[Variable {0}, Concat(input, nonce), AxisInvocation(0,0,_), Le(_, input), Recurse { measure: LiteralExpr(W32::CYCLE_SIZE @ W64), base: Literal(0), step: <predicate> }]` (per ADR-026 G16 + G19, ADR-013/TR-08, ADR-030, ADR-032) |
| Implementation runtime | [`crate::ops::traversal::traverse_sequential`](crates/prism-btc/src/ops/traversal.rs) (sequential) and [`traverse_parallel`](crates/prism-btc/src/ops/traversal.rs) (parallel coset partition over `Z/(2^32)Z`) |
| Conformance test | ADR-026 G16: "for any (domain, predicate) pair, the implementation's runtime produces the same first-admitting index as a reference sequential traversal would." prism-btc's `traverse_sequential` IS the reference sequential traversal. |

Pinned by [`crate::verbs::tests`](crates/prism-btc/src/verbs.rs):
- `verb_term_arena_is_emitted_and_nonempty`
- `verb_arena_contains_a_recurse_node` (ADR-026 G16 lowering)
- `verb_arena_contains_a_canonical_hash_axis_invocation` (ADR-026 G19 + ADR-030)
- `verb_arena_contains_concat_application` (ADR-013/TR-08 byte-packing)
- `verb_arena_contains_le_application` (ADR-013/TR-08 byte-comparison)

#### Substrate amendments closing the wiki's intended semantics

Foundation 0.4.1's evaluator + SDK proc-macro realise the verb's
structural form end-to-end against ADR-026 G16's specification:

| Earlier gap | Resolution |
|---|---|
| `Term::Recurse` walked one step (0.3.x) | Recursive fold-rule per ADR-029 (foundation 0.3.6): iterates N times where N = `bytes_to_u64_be(measure)` |
| `first_admit` measure was placeholder `Literal(256, W8)` (=0) | SDK reads `<DomainTy as ConstrainedTypeShape>::CYCLE_SIZE` per ADR-032 (foundation 0.4.0); for `witt_domain::W32`, measure = 2^32 |
| No byte-comparison / byte-packing `PrimitiveOp` | `Le`, `Lt`, `Ge`, `Gt`, `Concat` added per ADR-013/TR-08 (foundation 0.3.6); binary `<=`, `<`, `>=`, `>` and `concat(...)` admitted in closure-body grammar |
| `Term::HasherProjection` was a single-axis special case | Replaced by `Term::AxisInvocation { axis_index, kernel_id, input_index }` per ADR-030 (foundation 0.4.0); `hash(input)` lowers to the canonical hash axis `(0, 0)`; `Sha256dHasher` participates via the blanket `impl<H: Hasher> AxisTuple for H` |
| No field-access projection for product-of-shapes inputs | `PartitionProductFields` + `Term::ProjectField` admit `input.<field>` in closure bodies per ADR-033 G20 (foundation 0.4.0). prism-btc's `MiningInput` is a single 80-byte shape, so no field access is required. |
| SDK bound `idx_ident` to the measure root (constant), not the iteration counter; `Term::Recurse` had no admission short-circuit | `first_admit` lowers to `Term::FirstAdmit { domain_size_index, predicate_index }` per ADR-034 Mechanism 2 (foundation 0.4.1). The catamorphism iterates `idx` ascending from 0 to `CYCLE_SIZE`, threads the candidate `idx` through the predicate via `FIRST_ADMIT_IDX_NAME_INDEX`, and short-circuits on the first non-zero predicate result. |

#### `ops/traversal.rs` is now an optional ADR-026 G16 override

With ADR-034 Mechanism 2 in place, foundation's catamorphism evaluates
the W32 search end-to-end through the verb's term arena:

- The predicate body `hash(concat(input.prefix, nonce)) <= input.target`
  lowers to a Term subtree (`AxisInvocation`, `Concat`, `Le`,
  `FirstAdmitIdxPlaceholder`) with the candidate `nonce` threaded per
  iteration.
- `Term::FirstAdmit` walks the W32 ring, evaluates the predicate per
  fiber visit, and returns `(0x01, idx_bytes)` on admission or
  `(0x00, padding)` on exhaustion.

The implementation runtime in [`crate::ops::traversal`] is no longer
load-bearing for structural correctness. It remains as an **optional
override per ADR-026 G16** for two practical capabilities the
substrate-side `Term::FirstAdmit` evaluator doesn't yet expose:

1. **Parallel coset-partition traversal**. ADR-026 G16 explicitly
   permits implementations to "replace the default with their own
   runtime" for parallel traversal across coset partitions of the
   ring. prism-btc's [`crate::ops::traversal::traverse_parallel`]
   provides std-thread-scoped parallelism.
2. **External cancellation**. The bitcoind boundary's tip-watcher
   needs to abort an in-flight traversal on chain advance. Foundation's
   evaluator has no cancellation hook; prism-btc's runtime threads a
   [`crate::ops::traversal::Cancel`] trait object through every fiber
   visit.

The verb declaration is bit-identical regardless of which runtime
evaluates it. `BitcoinMiningModel::forward` going through foundation's
evaluator and prism-btc's `mine()` going through `traverse_sequential`
produce the same admitting nonce per the ADR-026 G16 conformance test.

---

## 14. Wiki cross-reference index

Every architectural commitment in this document traces back to a
specific page or clause of the [UOR-Framework wiki](https://github.com/UOR-Foundation/UOR-Framework/wiki).
This section is the round-trip index: every wiki entry that prism-btc
relies on, with the §-refs of this document that depend on it.

### 14.1 Boundary properties (TC-01..TC-06)

Source: [02 Architecture Constraints](https://github.com/UOR-Foundation/UOR-Framework/wiki/02-Architecture-Constraints).

| Wiki entry | prism-btc commitment | §-refs |
|---|---|---|
| TC-01 zero-cost runtime | No UORassembly enforcement code in `prism-mine`. All work compile-time-resolved. | §1, §9, §10 |
| TC-02 sealing of certified types | prism-btc constructs zero sealed types directly; uses `mint_*` and `pipeline::run` returns. | §6.3, §9 |
| TC-03 path singularity | One `pipeline::run` per (template, extranonce). No alternative constructor. | §1, §6.3, §6.5, §9 |
| TC-04 UORassembly bilateral | `prism-btc`'s impls must satisfy `prism`'s bounds; checked by `rustc`. | §9 |
| TC-05 replayability without deciders or hashing | `prism-verify::certify_from_trace` walks 5 events; no Hasher invocation; no decider invocation. | §6.6, §9 |
| TC-06 no author infrastructure | `prism-mine` runs entirely on user hardware. | §9 |

### 14.2 Architecture decisions (ADR-001..ADR-034)

Source: [09 Architecture Decisions](https://github.com/UOR-Foundation/UOR-Framework/wiki/09-Architecture-Decisions).

| ADR | prism-btc impact | §-refs |
|---|---|---|
| ADR-001 Prism system definition | Wiki is normative. This doc is reconciled to the wiki. | preamble |
| ADR-002 Boundary properties normative | All six TC-* enforced. | §9 |
| ADR-003 Verification local-by-construction | `prism-verify` runs on user hardware; no service. | §6.6 |
| ADR-004 Distribution channel external to Prism | bitcoind RPC and submitblock are external; outside Prism's scope. | §6.1, §8.2 |
| ADR-005 Three-crate decomposition | foundation/prism/prism-verify are separate external crates; prism-btc is independent. | §8 |
| ADR-006 UORassembly bilateral compile-time | Compile-time-only validation; no runtime UORassembly. | §10 |
| ADR-007 Substitution-axes allocation | `HostTypes` / `HostBounds` / `Hasher` selected at the application crate. | §3 |
| ADR-008 Trace wire format normative | prism-btc emits trace bytes per the wiki's wire format. | §6.4 |
| ADR-009 Certificate format normative | Certificates carry `(CertificateKind, ContentAddress)` per the wiki. | §6.6 |
| ADR-010 Hasher contract | `Sha256dHasher` satisfies determinism + fixed width + idempotence + distinct identifier. | §3.3, §7.2 |
| ADR-011 Sealing via Rust visibility | All seven sealed types use `pub(crate)` constructors; prism-btc never bypasses. | §9 |
| ADR-012 Pipeline lives in prism, not foundation | prism-btc imports `prism::pipeline::run`; foundation provides primitives. | §6.2 |
| ADR-013 Prism closed under uor-foundation | All prism-btc operations are `PrimitiveOp` compositions. No `sha2`, no `rayon`. | §1, §4, §8.2, §11 |
| ADR-014 Operation declaration vs. shipment | prism-btc declares its six operations as `PrimitiveOp` compositions. | §4 |
| ADR-015 Repository split strategy | Foundation amendments sequenced before prism-btc updates. | §11, §13 |
| ADR-016 Cross-crate seal mechanism via mint primitives | prism-btc never calls `mint_*` directly; `pipeline::run` does. | §9 |
| ADR-017 Canonical UOR-address surface | prism-btc's IRIs are `https://prism.btc/...` for stable schema. | §4.7, §7.2 |
| ADR-018 HostBounds capacity completeness | All capacity values flow through `PrismBtcBounds`. | §3.2 |
| ADR-019 Foundation as initial-algebra signature endofunctor | `Term`-based routes consumed by `pipeline::run` as the catamorphism; the W32 search lives in prism-btc. | §1, §13 |
| ADR-020 PrismModel hylomorphism contract | `BitcoinMiningModel` impls `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>`. | §13.0, §7.1 |
| ADR-021 V&V split (V = prism, IV&V = prism-verify) | `BitcoinMiningModel::forward` is the V agent; `enforcement::replay::certify_from_trace` is the IV&V agent. | §6.6, §13.0 |
| ADR-022 D1..D5 prism_model! emissions + grammar | All four emissions (seal, FoundationClosed, PrismModel, run_route delegation) come from the SDK macro applied to the closure-bodied route `hash(input)`. | §13.0 |
| ADR-023 IntoBindingValue + ROUTE_INPUT_BUFFER_BYTES | `MiningInput` impls `IntoBindingValue` with `MAX_BYTES = 80`; well under the foundation ceiling of 4096. | §13.0, §13.2 |
| ADR-026 G19 `hash(input)` lowers to `Term::AxisInvocation` (canonical hash axis) | The closure body `hash(input)` in `BitcoinMiningModel`'s route is lowered by `prism_model!` to `[Term::Variable {0}, Term::AxisInvocation {0,0,0}]`; the catamorphism evaluator runs the application Hasher over `Term::Variable {0}`'s evaluated bytes. | §1, §13.0 |
| ADR-028 `Grounded::output_bytes` carrier | The Grounded mints with the catamorphism's evaluated `TermValue` attached as `output_bytes`. | §1, §5, §13.0, §13.1 |
| ADR-029 catamorphism evaluator + per-value capacity | `pipeline::evaluate_term_tree` runs the term tree over the input bytes; per-value carrier is `TermValue` with `TERM_VALUE_MAX_BYTES = 4096` (foundation 0.4.1), wide enough to carry the 80-byte mining input through `Variable → HasherProjection` whole. | §1, §5, §13.0, §13.1 |

### 14.3 Building Block View

Source: [05 Building Block View](https://github.com/UOR-Foundation/UOR-Framework/wiki/05-Building-Block-View).

| Wiki block | prism-btc dependency | §-refs |
|---|---|---|
| `enforcement::resolver` (Hasher contract) | `Sha256dHasher` impls the contract. | §3.3, §7.2 |
| `enforcement::calibrations` | implicit via `PrismBtcBounds`. | §3.2 |
| `enforcement::transcendentals` | foundation-fixed wire-format constants used in trace serialisation. | §6.4 |
| `enforcement::combinators` | composing UOR-domain values inside the pipeline. | §5 |
| `mint primitives` (`mint_datum`, `mint_triad`, `mint_derivation`, `mint_freerank`) | invoked by `pipeline::run` at admission stages; not by prism-btc. | §6.2, §9 |
| `bridge::ConstrainedTypeShape` trait | `MiningInput` impls this; the 76/4-byte split is carried inside the 80-byte payload (§4.7, §4.8). | §4.7, §4.8 |
| `bridge::Grounding` trait | prism-btc's Grounding impls. | §7.4 |
| `bridge::trace::{Trace, TraceEvent}` | prism-btc's trace structure. | §6.4 |
| `bridge::cert::{Certificate, ContentFingerprint, ContentAddress}` | the certificate the pipeline emits and `prism-verify` certifies. | §6.6 |
| `kernel::HostTypes`, `kernel::HostBounds` traits | `DefaultHostTypes` and `PrismBtcBounds` impl. | §3.1, §3.2 |
| `kernel::convergence` | `NonceFiberTraversal` is a convergence-driven W32 fold. | §4.6 |
| `kernel::primitives` (closed primitive set) | every prism-btc operation is closed under this set. | §4 |
| `prism::pipeline::run` | the single entry point to a `Grounded<T>`. | §1, §5, §6.2 |
| `prism::seal regime` | `Validated`, `Grounded`, `Certified` are sealed; prism-btc consumes via mint primitives. | §6.3 |
| `prism::replay::certify_from_trace` | trace replay yielding `Certified<GroundingCertificate>`. | §6.6 |

### 14.4 Runtime View

Source: [06 Runtime View](https://github.com/UOR-Foundation/UOR-Framework/wiki/06-Runtime-View).

| Wiki scenario | prism-btc usage | §-refs |
|---|---|---|
| Scenario 1 Principal data path execution | One `pipeline::run` per (template, extranonce); produces Grounded + Trace simultaneously. | §6.2 |
| Scenario 2 Trace-replay verification | `prism-verify::certify_from_trace` walks the 5-event trace structurally. | §6.6 |
| Scenario 3 Compile-time UORassembly enforcement | `cargo build` checks all impls + bounds; emits `prism-mine`. | §10 |
| Scenario 4 Distribute and run | `prism-mine` distributed externally; user runs on own hardware with own bitcoind. | §1, §9 |

### 14.5 Concepts and Glossary

Source: [08 Concepts](https://github.com/UOR-Foundation/UOR-Framework/wiki/08-Concepts) and [12 Glossary](https://github.com/UOR-Foundation/UOR-Framework/wiki/12-Glossary).

| Wiki term | prism-btc usage | §-refs |
|---|---|---|
| Datum | the 80-byte `MiningInput` byte sequence the W32 fiber admitted; folded by `pipeline::run_route` into the binding's `content_address`. | §5 |
| Triad (foundation `Triad<T>`) | accessible from `MiningWitness::triad()` (foundation 0.4.1). Coordinates: `(stratum, spectrum, address)` derived from the `Grounded`'s `unit_address`. The digest-domain projection over the block-hash bytes is the prism-btc-supplied [`crate::domain::TriadicCoords`] on `MiningOutcome::coords`. | §7.7, §7.8 |
| Derivation | the foundation `Derivation` (`MiningWitness::derivation()`) recording the typed-iso path the W32 admission traversed; replayable to re-derive the certificate. | §5 |
| FreeRank | the W32 fiber's free coordinate; collapses on admission (the runtime selects the unique winning nonce). | §5 |
| Validated, Grounded, Certified | `Validated<CompileUnit, FinalPhase>`, `Grounded<ConstrainedTypeInput, MiningTag>`, `Certified<GroundingCertificate>`. | §5, §6.6, §7.1 |
| ConstrainedTypeShape | `MiningInput` (the literal PrismModel input). The architecture's `TemplatePrefixShape`/`TargetSubBundle` are conceptual; foundation 0.4.1 seals `GroundedShape` to `ConstrainedTypeInput`. | §4.7, §4.8 |
| Grounding | Foundation 0.4.1's `pipeline::run_route` admits `MiningInput` directly via `IntoBindingValue`; no separate `Grounding` impl is required at the prism implementor level. | §7.4 |
| Hasher | `Sha256dHasher`. | §3.3, §7.2 |
| HostTypes, HostBounds | `DefaultHostTypes`, `PrismBtcBounds`. | §3.1, §3.2 |
| Trace | five-event sequence per `pipeline::run`. | §6.4 |
| Resolution | the W32 fiber's free coordinate is resolved by `NonceFiberTraversal`. | §4.6, §5 |

### 14.6 Context and Scope

Source: [03 Context and Scope](https://github.com/UOR-Foundation/UOR-Framework/wiki/03-Context-and-Scope).

| Wiki boundary | prism-btc placement | §-refs |
|---|---|---|
| Application Author input | `prism-btc::mine`'s arguments (prefix, extranonce, target). | §7.1 |
| Application Author output | `MiningOutcome` (witness + trace). | §7.1 |
| Verification (Author → User) | trace + hasher_identifier passed out-of-band. | §6.6 |
| Verification output | `Certified<GroundingCertificate>` or `ReplayError`. | §6.6 |
| Out-of-scope: distribution channels | bitcoind RPC, `submitblock`, JS distribution are outside Prism. | §6.1, §8.2 |

### 14.7 Conceptual Model

Source: [Conceptual Model](https://github.com/UOR-Foundation/UOR-Framework/wiki/Conceptual-Model).

prism-btc's §2 follows the wiki's OPM convention. The wiki's
`Application`, `Application Author`, `Application User`, `Rust
Toolchain`, `Prism` entities are inherited (§2.1). prism-btc's
specialisations are the Bitcoin-domain entities and processes (§2.2,
§2.4). All OPL declarations (§2.5) reference back to either a wiki
normative source or a §-ref of this document.

### 14.8 Lifecycle

Source: [Lifecycle Technical Processes](https://github.com/UOR-Foundation/UOR-Framework/wiki/Lifecycle-Technical-Processes).

| Wiki process | prism-btc realisation |
|---|---|
| System Requirements Definition | TC-01..TC-06 + ADR-007's three substitution axes are inputs to this document. |
| System Architecture Definition | this document is prism-btc's architecture definition. |
| Design Definition | §4 (operations) + §7 (API surface) constitute the design. |
| Integration | §10 commits to compile-time-only integration via UORassembly bilateral enforcement. |
| Implementation | §12 reconciliation enumerates the implementation-level deltas required. |
| Verification (in lifecycle sense) | §6.6 (replay) + §9 (boundary properties) + the regtest end-to-end test (§12 step 15). |

---

> **End of normative content.** Subsequent edits to this document
> change prism-btc's defined state. Implementation reconciliation
> follows §12.
