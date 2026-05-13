# UOR-and-prism-informed cryptanalysis of SHA-256d

> **Frame.** UOR is an **ultrametric framework**. Prism generalizes
> UOR's addressing, latent embeddings, and ultrametric hierarchies
> into a **causal-semantic transport field on a content-addressed
> semantic manifold** (ARCHITECTURE.md §1.0). The σ-projection
> (SHA-256d, the canonical hash axis per ADR-030) maps typed inputs
> onto the 256-bit content-address manifold; UOR observables —
> p-adic valuations, Walsh–Hadamard spectral parities, ultrametric
> distances — read structural positions on the manifold.
>
> **Question.** Does any UOR-named observable on the manifold expose
> non-uniform-random structure in SHA-256d that could be exploited
> for Bitcoin-style mining?
>
> **Short answer.** No — at 10⁷ samples per test across eight UOR-
> structural tests covering low-bit (2-adic stratum), generalized
> (p-adic stratum for p ∈ {3, 5, 7}), spectral (WH at 32 random
> frequencies), avalanche (single-bit + multi-bit differential),
> autocorrelative (stratum + κ-derivation under sequential
> inputs), and joint (pairwise admission independence) channels.
> The σ-projection is hardened against the cryptanalysis the
> framework can pose; prism-btc's commitment to one structural
> inference per `MiningTask` is empirically vindicated.

---

## 1. The content-addressed semantic manifold

### 1.1 Address space and ultrametric

prism-btc's canonical addressing is the 256-bit content-address space
`{0, …, 2²⁵⁶ − 1}` produced by the σ-projection. The space is
equipped with the **2-adic ultrametric**:

```
d(a, b) = 2^-{ν₂(a ⊕ b)}
```

where `ν₂(x)` is the 2-adic valuation of `x` viewed as a 256-bit
big-endian integer (the index of the lowest set bit, or 256 if
`x = 0`). This is the [`ultrametric_valuation`][um] helper in
`crate::domain`. The strong (ultrametric) triangle inequality
`d(a, c) ≤ max(d(a, b), d(b, c))` holds. Balls of radius `2^-k`
form a hierarchical partition of the address space.

### 1.2 Generalized p-adic stratifications

The manifold inherits an analogous **p-adic ultrametric** for every
prime `p ≥ 2`:

```
d_p(a, b) = p^-{ν_p(a ⊕ b)}
```

where `ν_p(x)` is the p-adic valuation. This is the
[`p_adic_valuation`][padic] helper. The 2-adic case is the most
natural for binary digests, but `ν_p` for `p ∈ {3, 5, 7, …}` reads
orthogonal stratifications. A σ-projection that's uniform in `ν₂`
but biased in `ν_3` would still leak structure (the address space
is a multi-prime ultrametric simultaneously).

### 1.3 UOR observables at a position

A digest `d` is observed via:

- **`stratum(d) = ν₂(d)`** — 2-adic valuation; reads ultrametric
  ball membership at radius `2^-stratum`.
- **`p_adic_valuation(d, p)`** — generalized p-adic stratum.
- **`spectrum(d) = popcount(d) mod 2`** — WH parity at ω = `1²⁵⁶`.
- **`walsh_hadamard_parity_at(d, ω)`** — generalized spectral parity
  at an arbitrary non-trivial frequency `ω`.

These are the elementary UOR observables in
`crate::domain`. Higher-order observables (joint, differential,
autocorrelative) compose them.

### 1.4 The causal-semantic transport field

The ψ-pipeline (architecture §4) is a directed field of structure-
preserving morphisms over the manifold: ψ_1 → ψ_7 → ψ_8 → ψ_9. ψ_9
projects the typed `MiningTask` to its content-address via the
canonical hash axis and pins the four nonce-byte sites to the
leading four bytes of that content-address. The κ-label *is* the
wire-format Bitcoin header at that manifold position.

### 1.5 What "exploitable" means

A UOR observable `f(d)` is *exploitable* iff it is **both** (a)
cheap to compute relative to evaluating the full σ-projection and
(b) admission-correlated. A miner with such an observable could
reject candidates whose `f` falls in the admission-disjoint region
without evaluating the full σ-projection. None of the tested
observables satisfies both conditions; for the ones that have any
distributional structure (e.g. stratum's Geometric(1/2)), the
structure is admission-orthogonal.

[um]: crates/prism-btc/src/domain.rs
[padic]: crates/prism-btc/src/domain.rs

## 2. Methodology

The script
[`crates/prism-btc/examples/uor_cryptanalysis.rs`](crates/prism-btc/examples/uor_cryptanalysis.rs)
runs eight tests at `N = 10⁷` samples each on a deterministic input
stream (sequential 80-byte headers / 108-byte mining tasks varying a
4-byte counter field). Statistical conventions: χ² tests at
α = 0.001; two-sided z thresholds at α = 0.001 (|z| > 3.29). Each
test reports observed statistic versus critical value; passing ⇔
observed below critical.

Reproduce:

```bash
cargo run --release --example uor_cryptanalysis -- --samples 10000000
```

## 3. Empirical battery (8 tests)

### 3.1 §A — Triadic coordinate uniformity

| Statistic | Observed | Critical (α=0.001) | Pass |
|---|---:|---:|:---:|
| stratum χ² (df = 16) | **15.9** | 39.2 | ✓ |
| spectrum χ² (df = 1) | **0.22** | 10.83 | ✓ |
| max \|P(spec=0 \| stratum=k) − 0.5\|, k=0..9 | 0.003 | binom SE | ✓ |
| max \|P(admit \| stratum=k) − P(admit)\|, k=0..9 | 0.013 | binom SE | ✓ |
| \|P(admit \| spec=s) − P(admit)\|, s ∈ {0,1} | 1.3×10⁻⁴ | ≈ ±3×10⁻⁴ | ✓ |

`P(admit) = 0.499913` against the regtest target. The triadic
projection reveals no admission-relevant structure within sampling
precision. Theoretical justification: stratum reads low bits;
spectrum is a global parity; admission depends on high bits. The
three observables are admission-orthogonal to cryptographic
precision under the random-oracle model.

### 3.2 §B — Ultrametric avalanche distribution

For each sample, flip one bit of an 80-byte input and measure
`ν₂(σ(x) ⊕ σ(x ⊕ e_b))`.

| Statistic | Observed | Critical | Pass |
|---|---:|---:|:---:|
| Avalanche valuation χ² (df = 16) | **13.3** | 39.2 | ✓ |

| ν | observed | expected | obs/exp |
|---:|---:|---:|---:|
| 0 | 4,999,809 | 5,000,000 | 1.0000 |
| 1 | 2,501,471 | 2,500,000 | 1.0006 |
| 2 | 1,249,606 | 1,250,000 | 0.9997 |
| 3 | 624,376   | 625,000   | 0.9990 |
| 4 | 312,360   | 312,500   | 0.9996 |
| 5 | 155,600   | 156,250   | 0.9958 |
| 6 | 78,567    | 78,125    | 1.0057 |
| 7 | 38,984    | 39,062    | 0.9980 |
| ≥8 | 39,227   | 39,062    | 1.0042 |

A single-bit perturbation dissolves into a uniform-random
content-address displacement. **Input proximity does not transfer
to output proximity.**

### 3.3 §C — Walsh–Hadamard spectrum at 32 non-trivial frequencies

| Statistic | Observed | Critical (α=0.001) | Pass |
|---|---:|---:|:---:|
| max \|P(parity=0 \| ω_j) − 0.5\| over 32 frequencies | 4.2×10⁻⁴ | binom SE | ✓ |
| aggregate χ² over 32 frequencies (df = 32) | **25.8** | 62.5 | ✓ |

SHA-256d's output is spectrally flat at every tested non-trivial
frequency.

### 3.4 §D — Stratum autocorrelation under sequential inputs

| Statistic | Observed | Critical | Pass |
|---|---:|---:|:---:|
| max \|z\| across lags 1..10 | **1.29** | 3.29 | ✓ |
| stratum mean | 0.9999 | ≈ 1.0 | ✓ |
| stratum variance | 2.0023 | ≈ 2.0 | ✓ |

Sequential inputs produce strata that are statistically i.i.d.

### 3.5 §E — κ-derivation autocorrelation (mining-specific)

For sequential `MiningTask` inputs varying the timestamp field
(bytes 68..72), ψ_9's κ-derived nonce
`u32::from_le_bytes(H(task)[..4])`:

| Statistic | Observed | Expected/Critical | Pass |
|---|---:|---:|:---:|
| κ-nonce mean | 2.148 × 10⁹ | 2.147 × 10⁹ | ✓ |
| κ-nonce variance | 1.537 × 10¹⁸ | 1.537 × 10¹⁸ | ✓ |
| max \|z\| across lags 1..10 | **1.56** | 3.29 (α=0.001) | ✓ |

**Mining-specific finding.** Sequential template variations produce
κ-derivations that are statistically indistinguishable from i.i.d.
uniform u32 draws. **A miner cannot predict the next κ-derivation
from the current one** — the prism-btc-specific exploitability
channel is closed by the σ-projection's avalanche.

### 3.6 §F — p-adic stratification for `p ∈ {3, 5, 7}`

Generalizes §A's stratum (`p = 2`) to other primes. Under the
random-oracle model `P(ν_p = k) = (p − 1)/p^(k+1)`.

| `p` | df | χ² observed | Critical (α=0.001) | Pass |
|---:|---:|---:|---:|:---:|
| 3 | 13 | **14.1** | 34.5 | ✓ |
| 5 | 9  | **5.8**  | 27.9 | ✓ |
| 7 | 8  | **10.7** | 26.1 | ✓ |

Per-prime breakdown of the low cells:

**p = 3** (expected `P(0) = 2/3`, `P(1) = 2/9`, …):

| k | observed | expected | obs/exp |
|---:|---:|---:|---:|
| 0 | 6,668,544 | 6,666,667 | 1.0003 |
| 1 | 2,222,009 | 2,222,222 | 0.9999 |
| 2 | 739,330   | 740,741   | 0.9981 |
| 3 | 246,496   | 246,914   | 0.9983 |
| 4 | 82,425    | 82,305    | 1.0015 |
| 5 | 27,645    | 27,435    | 1.0077 |

**p = 5** (`P(0) = 4/5`, `P(1) = 4/25`, …):

| k | observed | expected | obs/exp |
|---:|---:|---:|---:|
| 0 | 7,998,182 | 8,000,000 | 0.9998 |
| 1 | 1,602,169 | 1,600,000 | 1.0014 |
| 2 | 319,507   | 320,000   | 0.9985 |
| 3 | 64,119    | 64,000    | 1.0019 |
| 4 | 12,841    | 12,800    | 1.0032 |
| 5 | 2,551     | 2,560     | 0.9965 |

**p = 7** (`P(0) = 6/7`, `P(1) = 6/49`, …):

| k | observed | expected | obs/exp |
|---:|---:|---:|---:|
| 0 | 8,571,365 | 8,571,429 | 1.0000 |
| 1 | 1,225,159 | 1,224,490 | 1.0005 |
| 2 | 174,657   | 174,927   | 0.9985 |
| 3 | 24,697    | 24,990    | 0.9883 |
| 4 | 3,536     | 3,570     | 0.9905 |
| 5 | 515       | 510       | 1.0098 |

The σ-projection's output is uniform in *every* prime stratification
we tested — not just the binary one. The manifold is ultrametrically
isotropic across primes.

### 3.7 §G — Joint admission independence (sequential pairs)

For sequential 80-byte inputs `(x_i, x_{i+1})`, test pairwise
independence: `H₀: P(admit(x_i) ∧ admit(x_{i+1})) = P(admit)²`.

| Statistic | Observed |
|---|---:|
| `P(admit x_i)` | 0.499913 |
| `P(admit x_{i+1})` | 0.499913 |
| `P(both admit, observed)` | 0.249786 |
| `P(both admit, under H₀)` | 0.249913 |
| Observed − independent | −1.3 × 10⁻⁴ |
| 2×2 contingency χ² (df = 1) | **2.56** (crit 10.83) ✓ |

Admission events on consecutive templates are pairwise independent
to cryptographic precision. There is no sequential clustering of
admitting templates.

### 3.8 §H — Differential cryptanalysis via the ultrametric

For fixed input differences Δ of various Hamming weights, measures
`ν₂(σ(x) ⊕ σ(x ⊕ Δ))` over sequential `x` and tests against
Geometric(1/2):

| Δ pattern | Hamming weight | χ² (df = 16) | Pass |
|---|---:|---:|:---:|
| single bit | 1 | **12.9** | ✓ |
| low 4 bits | 4 | **11.2** | ✓ |
| low 16 bits | 16 | **23.5** | ✓ |
| low 64 bits | 64 | **10.0** | ✓ |
| low half (320 bits) | 320 | **7.7** | ✓ |
| all but one (639 bits) | 639 | **11.2** | ✓ |

(Critical χ² at α=0.001, df=16: 39.2.)

**No tested differential pattern exposes a structural shortcut.** A
miner with any of these Δ patterns cannot predict the output's
ultrametric position relative to the unperturbed digest.

### 3.9 Empirical-section summary

All eight tests pass their α = 0.001 thresholds at `N = 10⁷`:

| § | Observable family | Statistic | Crit | Pass |
|---|---|---:|---:|:---:|
| A | triadic coordinates | χ²_stratum = 15.9 | 39.2 | ✓ |
| A | triadic coordinates | χ²_spectrum = 0.22 | 10.83 | ✓ |
| A | admission orthogonality | max dev = 1.3×10⁻⁴ | binom SE | ✓ |
| B | ultrametric avalanche | χ² = 13.3 | 39.2 | ✓ |
| C | WH spectrum, 32 freqs | aggregate χ² = 25.8 | 62.5 | ✓ |
| D | stratum autocorr 1..10 | max \|z\| = 1.29 | 3.29 | ✓ |
| E | κ-derivation autocorr | max \|z\| = 1.56 | 3.29 | ✓ |
| F | 3-adic stratum | χ² = 14.1 (df 13) | 34.5 | ✓ |
| F | 5-adic stratum | χ² = 5.8 (df 9) | 27.9 | ✓ |
| F | 7-adic stratum | χ² = 10.7 (df 8) | 26.1 | ✓ |
| G | pairwise admission ⊥ | χ² = 2.56 | 10.83 | ✓ |
| H | differential, 6 Δ weights | max χ² = 23.5 | 39.2 | ✓ |

**No observable in the battery shows deviation beyond sampling
variance from the random-oracle model.**

---

## 4. Extrapolation to the UOR Framework

The empirical results justify framework-level statements about the
σ-projection axis and the manifold it induces. This section
proposes formal contributions.

### 4.1 The σ-Projection Hardening Principle

A σ-projection axis selection (ADR-030 chooses a `Hasher` impl) is
**UOR-hardened** iff it satisfies, for the random-oracle model:

1. **Marginal-uniformity (U1)** — every elementary UOR observable
   on the projection's output is distributed as the random-oracle
   model predicts: `ν_p` is Geometric((p − 1)/p) for every prime
   `p`; WH parity at any non-trivial frequency `ω` is Bernoulli(1/2).
2. **Joint-independence (U2)** — for any `k`-tuple of distinct
   inputs and any joint UOR observable, the joint distribution
   factorizes as the product of marginals (to cryptographic
   precision).
3. **Admission-orthogonality (U3)** — for every UOR observable `f`
   and every admission relation `R` of the form `d ≤ target`, `f(d)`
   and `R(d)` are statistically independent.
4. **Avalanche (U4)** — for any fixed Δ ≠ 0, the distribution of
   `ν_p(σ(x) ⊕ σ(x ⊕ Δ))` matches its random-oracle reference for
   every prime `p`. Input proximity in the input space does not
   transfer to output proximity on the manifold.
5. **Autocorrelation-flatness (U5)** — under any structured input
   sequence (sequential, AP, etc.), all per-observable
   autocorrelations are 0 to within sampling error.

SHA-256d passes (U1)–(U5) empirically at `N = 10⁷` (§3). The
principle generalizes: **any σ-projection candidate that passes
this battery is UOR-hardened**; failure on any axis is a structural
attack surface.

### 4.2 The UOR Cryptanalysis Battery — proposed substrate primitive

A foundation-level test suite implementing the eight tests of §3
would let any application's σ-projection selection be substrate-
validated. Proposed (ADR-style):

> **ADR-XXX (proposed): UOR Cryptanalysis Battery for canonical
> hash axes.** Foundation provides
> `uor_foundation::axis::test::cryptanalyze<H: Hasher>(samples: usize)
> -> CryptanalysisReport` that runs the eight tests of ANALYSIS.md
> §3 against `H` and emits a structured report. `H: Hasher`
> implementations are expected to pass the battery at α = 0.001 with
> `N = 10⁷` to qualify as a UOR-hardened σ-projection.

prism-btc's `Sha256dHasher` would be the reference passing
implementation. Substrate amendments to the canonical hash axis
(future Blake3-axis, Keccak-axis, post-quantum axes) would be
validated against the same battery.

### 4.3 Bridge to traditional cryptanalysis

Every UOR observable in §3 has a traditional-cryptanalysis analogue:

| UOR observable | Traditional analogue |
|---|---|
| `ν₂(d)` distribution (stratum, §A) | low-order-bit bias / LSB cryptanalysis |
| `spectrum(d)`, `walsh_hadamard_parity_at(d, ω)` (§A, §C) | linear cryptanalysis bias at frequency ω |
| `ν_p(d)` for `p > 2` (§F) | non-binary statistical tests (generalized χ² over residue classes) |
| ultrametric avalanche (§B) | strict avalanche criterion (SAC) |
| differential ν₂ (§H) | differential cryptanalysis at fixed Δ |
| autocorrelation under sequential inputs (§D, §E) | TMTO precomputation feasibility |
| joint admission independence (§G) | k-tuple correlation / multi-output bias |

**The UOR battery is not a new fad** — it's a unified categorical
restatement of the cryptanalytic tests SHA-256d was designed to
defeat, with the framework's vocabulary (ultrametric, manifold,
spectrum, transport field) making the unification visible. Where
traditional cryptanalysis enumerates ad-hoc tests, UOR provides a
common typed surface that exposes the same questions at the level
of structural observables on the content-addressed manifold.

### 4.4 What UOR cryptanalysis cannot see

The framework's observability surface has principled boundaries:

- **Input-side algebraic structure.** UOR observables read the
  σ-projection's *output*; attacks that exploit algebraic structure
  in the input (e.g. multi-collision attacks via the Merkle–Damgård
  structure, length-extension) are not on the manifold the
  observables read. These are visible to the ψ-pipeline as
  *resolver-internal* observables on the typed input, not to the
  cryptanalysis battery applied to digests.
- **Side-channel observables.** Timing, power, EM emissions on a
  specific implementation of the σ-projection are off-manifold —
  they observe the executor, not the manifold position.
- **Quantum oracle attacks.** Grover-style preimage search reduces
  the σ-projection's preimage problem from `2^256` to `2^128`
  quantum operations. UOR observability does not give a further
  reduction; the framework is classical-oracle.
- **Adversarial-input attacks.** Chosen-prefix collisions (the
  attacker picks `x_1, x_2` with `σ(x_1) = σ(x_2)`) are not visible
  to the cryptanalysis battery applied to randomly-streamed inputs.
  Foundation's `Hasher` impls must independently meet collision-
  resistance criteria.

The boundary is principled: UOR observes **output structure under
random input**. Attacks that step outside that frame need different
tools.

### 4.5 Framework contributions (proposed)

1. **ADR-XXX-A: Hardening Principle as substrate axiom.** The five
   conditions of §4.1 are formal requirements on `Hasher` impls. A
   `Hasher` that fails any condition fails the substrate's
   canonical-hash-axis selection.
2. **ADR-XXX-B: UOR observable surface.** Formal types for the
   elementary UOR observables (currently lifted to prism-btc as
   `TriadicCoords`, `ultrametric_valuation`, `p_adic_valuation`,
   `walsh_hadamard_parity_at`) move to foundation as
   `observable::Stratum<P>`, `observable::WalshHadamardFrequency`,
   etc. Applications consume the typed observables; the substrate
   makes the manifold structure first-class.
3. **ADR-XXX-C: Cryptanalysis Battery as substrate primitive.**
   The eight tests of §3 ship as `uor_foundation::axis::cryptanalyze`
   (§4.2); substrate CI runs the battery against
   `DefaultSigmaProjection` on every release.
4. **Lean formalization.** The Hardening Principle's marginal-
   uniformity and admission-orthogonality theorems are stateable in
   Lean. A foundation-side `axis/CryptanalysisProtocol.lean` would
   carry the proof obligations the substrate axiom imposes.

### 4.6 Implication for prism-btc

The cryptanalysis empirically vindicates the architectural choice
(ARCHITECTURE.md §6, §12, §14):

- **One structural inference per `MiningTask`** is not a performance
  compromise; there is no UOR-structural exploit a "more
  algorithmic" implementation could anchor itself to.
- **Constant per-`forward()` cost** is consistent with admission-
  orthogonality: cheaper-than-σ observables cannot predict
  admission, so the resolver chain's overhead has no useful
  rejection-shortcut to skip past.
- **Host-boundary template variation** is the *only* viable channel
  for finding admitting templates, because every other channel UOR
  exposes is uniform-random under the manifold.

These are framework-level facts now, not just prism-btc
architectural choices — the σ-projection's UOR-hardening makes
them so.

## 5. Reproducing the analysis

```bash
cargo run --release --example uor_cryptanalysis -- --samples 10000000
```

Default sample size is `1,000,000`; the report above is at
`10,000,000`. The script is deterministic across machines.

## 6. References

- **ADR-030** — canonical hash axis selection.
- **ARCHITECTURE.md §1.0** — UOR / Prism conceptual framing
  (ultrametric framework, causal-semantic transport field on a
  content-addressed semantic manifold).
- **ARCHITECTURE.md §4** — ψ-pipeline transport on the manifold.
- **ARCHITECTURE.md §6, §12, §14** — fail-closed contract,
  pure-prism commitment, performance model — all empirically
  vindicated by the cryptanalysis above.
- `crate::ultrametric_valuation`, `crate::p_adic_valuation`,
  `crate::walsh_hadamard_parity_at` — the elementary UOR observable
  helpers exposed by prism-btc; candidates for promotion to
  `uor_foundation::observable::*` per §4.5.
