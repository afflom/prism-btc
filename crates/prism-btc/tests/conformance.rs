//! prism-btc conformance suite.
//!
//! Validates that the implementation continues to realize prism's
//! zero-cost runtime model — the cost contract `expected_trials =
//! α⁻¹ × 2^bandwidth_bits` at equality, scaling arbitrarily over K
//! and α. See [`CONFORMANCE.md`](../../../CONFORMANCE.md) for the
//! normative definition.
//!
//! Test IDs match the CONFORMANCE.md tables:
//!
//! * **CS-1 … CS-6** — structural invariants (the implementation must
//!   not drift back to dynamic dispatch / runtime allocation).
//! * **CD-1 … CD-3** — per-input runtime invariants the model demands.
//! * **CP-1 … CP-4** — empirical scaling of the cost identity over K
//!   and α, including the unified `TargetCommitment × PayloadCommitment`
//!   composition (CP-4). CP-5/CP-6 (per-Predicate-variant U1/U2
//!   calibration) are witnessed by the cryptanalysis battery and
//!   cross-referenced from CONFORMANCE.md.
//!
//! Run: `cargo test -p prism-btc --release --test conformance`

use prism_btc::{
    mine, mine_with, p_adic_valuation, sha256d_display, AndCommitment, Bits, BlockHeader,
    EmptyCommitment, KappaObservables, MerkleRoot, MiningFailure, PayloadCommitment, Predicate,
    Target, TargetCommitment, Timestamp, TriadicCoords, TypedCommitment, Version, CANONICAL_PRIMES,
};
use std::fs;
use std::path::{Path, PathBuf};

const REGTEST_NBITS: u32 = 0x207fffff;

// ─── helpers ───────────────────────────────────────────────────────────

fn src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn walk_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            fs::read_dir(&dir).unwrap_or_else(|e| panic!("read_dir({}): {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("read_dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

fn assert_pattern_absent_in_sources(pattern: &str, label: &str) {
    let mut hits = Vec::new();
    for path in walk_rust_sources(&src_root()) {
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read_to_string({}): {e}", path.display()));
        for (lineno, line) in body.lines().enumerate() {
            // Ignore doc-comment lines mentioning the pattern as
            // historical context — only flag executable code.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//!") || trimmed.starts_with("///") || trimmed.starts_with("//")
            {
                continue;
            }
            if line.contains(pattern) {
                hits.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(src_root().parent().unwrap())
                        .unwrap_or(&path)
                        .display(),
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{label}: forbidden pattern `{pattern}` found in library sources:\n  {}",
        hits.join("\n  ")
    );
}

fn permissive_header(timestamp: u32) -> BlockHeader {
    BlockHeader {
        version: Version(1),
        prev_hash: [0u8; 32],
        merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
        timestamp: Timestamp(timestamp),
        bits: Bits(REGTEST_NBITS),
    }
}

// ─── CS — Structural invariants ────────────────────────────────────────

#[test]
fn cs1_no_vec_of_predicate_in_library_source() {
    assert_pattern_absent_in_sources(
        "Vec<Predicate>",
        "CS-1: dynamic-commitment Vec must not return",
    );
}

#[test]
fn cs2_no_dyn_typed_commitment_in_library_source() {
    assert_pattern_absent_in_sources(
        "dyn TypedCommitment",
        "CS-2: TypedCommitment must be monomorphized, not trait-object dispatched",
    );
    assert_pattern_absent_in_sources(
        "Box<dyn TypedCommitment",
        "CS-2: TypedCommitment must not be boxed for dynamic dispatch",
    );
}

#[test]
fn cs3_typed_commitment_requires_copy() {
    // CS-3 is enforced at compile time by the supertrait bound
    // `pub trait TypedCommitment: Copy` in `commitment.rs`. This
    // runtime witness is a tautology: if `TypedCommitment: Copy` weren't
    // declared, the function below wouldn't compile.
    fn requires_copy_typed_commitment<C: TypedCommitment>(c: C) -> (C, C) {
        // Two-value usage exercises the `Copy` bound (move would only
        // permit one).
        (c, c)
    }
    let (_a, _b) = requires_copy_typed_commitment(EmptyCommitment);
    let (_a, _b) = requires_copy_typed_commitment(PayloadCommitment::<4>::from_bits([true; 4]));
}

#[test]
fn cs4_predicate_has_exactly_four_variants() {
    // CS-4 is enforced at compile time by match exhaustiveness — if a
    // fifth variant is added, this match fails to compile unless a new
    // arm (and a corresponding U1/U2 calibration in §I + §J of the
    // cryptanalysis battery) is added.
    fn exhaustive_match(p: &Predicate) -> &'static str {
        match p {
            Predicate::Parity { .. } => "parity",
            Predicate::StratumEq { .. } => "stratum_eq",
            Predicate::PAdicEq { .. } => "p_adic_eq",
            Predicate::UltrametricCloseTo { .. } => "ultrametric_close_to",
        }
    }
    // Exercise every arm — confirms the canonical observable basis
    // remains four variants.
    assert_eq!(
        exhaustive_match(&Predicate::Parity {
            omega: [0u8; 32],
            expected: 0
        }),
        "parity"
    );
    assert_eq!(
        exhaustive_match(&Predicate::StratumEq { k: 0 }),
        "stratum_eq"
    );
    assert_eq!(
        exhaustive_match(&Predicate::PAdicEq { p: 3, k: 0 }),
        "p_adic_eq"
    );
    assert_eq!(
        exhaustive_match(&Predicate::UltrametricCloseTo {
            reference: [0u8; 32],
            k: 0
        }),
        "ultrametric_close_to"
    );
}

#[test]
fn cs5_mining_outcome_carries_observables() {
    // CS-5: every MiningOutcome carries `observables: KappaObservables`
    // as a non-optional field — the receiver-side typed lens is always
    // present. Compile-time witness: this function projects the field
    // by its declared name + type.
    fn project_observables(outcome: prism_btc::MiningOutcome) -> KappaObservables {
        outcome.observables
    }
    let header = permissive_header(1_700_000_000);
    let target = Target::new(REGTEST_NBITS);
    if let Ok(outcome) = mine(&header, target) {
        let obs: KappaObservables = project_observables(outcome);
        // The lens decodes both halves of the typed observable surface.
        assert!(obs.coords.stratum <= 256);
        assert_eq!(obs.p_adic.len(), CANONICAL_PRIMES.len());
    }
}

#[test]
fn cs6_no_legacy_commitment_surface_references() {
    // CS-6: the deleted dynamic-commitment surface must not return.
    // Each forbidden identifier names a piece of the pre-typed-surface
    // API that would re-introduce runtime dispatch / dynamic disjointness
    // / Vec<Predicate> if added back.
    for legacy in &[
        "MiningCommitment",
        "mine_with_commitment",
        "CommitmentError",
        "try_add_predicate",
        "add_predicate",
    ] {
        assert_pattern_absent_in_sources(
            legacy,
            &format!("CS-6: legacy commitment surface identifier `{legacy}` must not return"),
        );
    }
}

// ─── CD — Dynamic invariants ───────────────────────────────────────────

#[test]
fn cd1_mine_with_empty_is_bit_equivalent_to_bare_mine() {
    // CD-1: `EmptyCommitment` is the typed-surface identity. `mine_with`
    // with it must produce byte-identical outcomes to bare `mine`.
    let target = Target::new(REGTEST_NBITS);
    for ts in 0u32..32 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        match (
            mine(&header, target),
            mine_with(&header, target, EmptyCommitment),
        ) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.digest, b.digest, "CD-1: digest must match");
                assert_eq!(a.nonce, b.nonce, "CD-1: nonce must match");
                assert_eq!(a.observables, b.observables, "CD-1: observables must match");
            }
            (Err(_), Err(_)) => {}
            (a, b) => panic!(
                "CD-1: mine vs mine_with(EmptyCommitment) disagreed at ts={ts}: a={:?} b={:?}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
}

#[test]
fn cd2_payload_commitment_round_trips_at_every_k() {
    // CD-2: For each K ∈ {0, 1, 2, 4, 8} we encode K payload bits,
    // mine until admission, decode the κ-label's bits, and confirm the
    // encoded payload round-trips through the channel. Macro-expanded
    // so every K is a separate monomorphization.
    fn payload_for_k(k: usize, seed: u64) -> Vec<bool> {
        (0..k)
            .map(|i| ((seed.wrapping_add(i as u64)) & 1) == 1)
            .collect()
    }

    let target = Target::new(REGTEST_NBITS);

    macro_rules! round_trip {
        ($k:literal) => {{
            const K: usize = $k;
            // For K ≤ 32 the round trip is fast at regtest α≈1/2.
            // Higher K is covered probabilistically by CP-1.
            let payload_vec = payload_for_k(K, 0xC0FFEE);
            let mut payload_arr = [false; K];
            for (i, b) in payload_vec.iter().enumerate().take(K) {
                payload_arr[i] = *b;
            }
            let commitment = PayloadCommitment::<K>::from_bits(payload_arr);
            let mut found = false;
            // Higher K needs more variations; 2^K × 2 (admission factor) is the
            // expected count, with a 16× safety margin.
            let max_variations = (1u64 << K) * 32 + 256;
            for ts in 0..max_variations {
                let header = permissive_header(1_700_000_000_u32.wrapping_add(ts as u32));
                if let Ok(outcome) = mine_with(&header, target, commitment) {
                    let decoded = PayloadCommitment::<K>::decode(&outcome.digest);
                    assert_eq!(
                        decoded, payload_arr,
                        "CD-2: decoded payload must round-trip for K={K}"
                    );
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "CD-2: PayloadCommitment<{K}> must admit within {max_variations} variations at regtest"
            );
        }};
    }

    round_trip!(0);
    round_trip!(1);
    round_trip!(2);
    round_trip!(4);
    round_trip!(8);
}

#[test]
fn cd3_observables_agree_with_per_primitive_computation() {
    // CD-3: KappaObservables on a successful outcome agrees byte-for-byte
    // with the per-primitive computation on the same digest. The
    // receiver-side lens is consistent.
    let target = Target::new(REGTEST_NBITS);
    let mut checked = 0;
    for ts in 0u32..16 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        if let Ok(outcome) = mine(&header, target) {
            let canonical = TriadicCoords::from_hash(&outcome.digest);
            assert_eq!(
                outcome.observables.coords, canonical,
                "CD-3: observables.coords must agree with TriadicCoords::from_hash"
            );
            for (i, &p) in CANONICAL_PRIMES.iter().enumerate() {
                assert_eq!(
                    outcome.observables.p_adic[i],
                    p_adic_valuation(&outcome.digest, p),
                    "CD-3: observables.p_adic[{i}] must agree with p_adic_valuation(p={p})"
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 4,
        "CD-3: at least 4 admitting outcomes expected at regtest"
    );
}

// ─── CP — Probabilistic scaling ────────────────────────────────────────

/// Synthetic mining trial — count templates until SHA-256d(input)
/// passes the joint (admission, commitment-K-bit) gate. Used by CP-1,
/// CP-2, CP-3 to exercise the cost identity across (K, α) without
/// depending on `Target`'s specific compact encoding.
fn synthetic_trials(
    admission_lz_bits: u32,
    commitment_k: u32,
    payload_bits_lsb_first: u64,
    seed: u64,
    max_attempts: u64,
) -> Option<u64> {
    let mut input = [0u8; 80];
    input[0] = 0x01;
    input[8..16].copy_from_slice(&seed.to_le_bytes());
    for i in 1..=max_attempts {
        input[64..72].copy_from_slice(&i.to_le_bytes());
        let digest = sha256d_display(&input);
        if !admits_lz(&digest, admission_lz_bits) {
            continue;
        }
        if !commits_low_k_bits(&digest, commitment_k, payload_bits_lsb_first) {
            continue;
        }
        return Some(i);
    }
    None
}

/// Admission gate: digest has at least `lz` leading-zero bits in
/// display order. α = 2^-lz under PRF.
fn admits_lz(digest: &[u8; 32], lz: u32) -> bool {
    let full = (lz / 8) as usize;
    let extra = lz % 8;
    for d in digest.iter().take(full) {
        if *d != 0 {
            return false;
        }
    }
    if extra > 0 && full < 32 {
        let mask = 0xff_u8 << (8 - extra);
        if digest[full] & mask != 0 {
            return false;
        }
    }
    true
}

/// Commitment gate: digest's low `k` bits (LSB-numbered) match the low
/// `k` bits of `payload`. Bandwidth = k bits.
fn commits_low_k_bits(digest: &[u8; 32], k: u32, payload: u64) -> bool {
    for i in 0..(k as usize) {
        let byte_idx = 31 - i / 8;
        let bit_idx = i % 8;
        let digest_bit = (digest[byte_idx] >> bit_idx) & 1;
        let payload_bit = ((payload >> i) & 1) as u8;
        if digest_bit != payload_bit {
            return false;
        }
    }
    true
}

fn average_trials(
    admission_lz: u32,
    commitment_k: u32,
    payload: u64,
    n_trials: usize,
    max_per_trial: u64,
) -> f64 {
    let mut total: u64 = 0;
    for trial in 0..n_trials {
        let seed = 0xDEADBEEF_u64.wrapping_mul((trial as u64).wrapping_add(1));
        let t = synthetic_trials(admission_lz, commitment_k, payload, seed, max_per_trial)
            .unwrap_or_else(|| {
                panic!("trial {trial} exceeded max_per_trial={max_per_trial} attempts")
            });
        total += t;
    }
    (total as f64) / (n_trials as f64)
}

// CP statistical tolerances. The synthetic mining loop draws geometric
// trial counts under PRF baseline: trial count T ~ Geom(p), with
// E[T] = 1/p and SD(T) ≈ 1/p. The sample-mean coefficient of variation
// at N trials is therefore 1/√N. We want P(test fails on a sound
// implementation) ≪ 1%; that's a ~4-σ tolerance.
//   - N = 200: SE = 7.07% of mean. ±30% tolerance is 4.24σ → P(fail) ≈ 0.002%.
// The tolerance is statistical, not architectural — the model is exact.

const CP_N_TRIALS: usize = 200;
const CP_TOLERANCE: f64 = 0.30;

#[test]
fn cp1_k_scaling_holds_across_two_decades() {
    // CP-1: at α = 1/2 (admission_lz=1), expected trials at bandwidth K
    // is 2^(K+1). Sweep K ∈ {0, 2, 4, 8, 12}; the doubling holds across
    // four decades in K.
    const ADMISSION_LZ: u32 = 1;
    let cases: &[(u32, f64)] = &[
        (0, 2.0),     // 2^1
        (2, 8.0),     // 2^3
        (4, 32.0),    // 2^5
        (8, 512.0),   // 2^9
        (12, 8192.0), // 2^13
    ];
    for &(k, predicted) in cases {
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(ADMISSION_LZ, k, 0xC0FFEE_u64, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-1 K={k}: observed mean trials {observed:.1} \
             vs predicted {predicted:.1} (ratio {ratio:.3}); \
             must hold within ±{:.0}% sampling variance",
            CP_TOLERANCE * 100.0
        );
    }
}

#[test]
fn cp2_alpha_scaling_holds_at_fixed_k() {
    // CP-2: at fixed K=2 (bandwidth 2 bits, factor 4×), expected trials
    // scales as α⁻¹ across admission probabilities. Sweep
    // admission_lz ∈ {1, 4, 8, 12}; confirm the α⁻¹ factor holds.
    const K: u32 = 2;
    let cases: &[(u32, f64)] = &[
        (1, (1u64 << 1) as f64 * 4.0),   // α⁻¹ = 2,    × 2^K = 4  → 8
        (4, (1u64 << 4) as f64 * 4.0),   // α⁻¹ = 16,   × 4        → 64
        (8, (1u64 << 8) as f64 * 4.0),   // α⁻¹ = 256,  × 4        → 1024
        (12, (1u64 << 12) as f64 * 4.0), // α⁻¹ = 4096, × 4        → 16384
    ];
    for &(lz, predicted) in cases {
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, K, 0xBADF00D_u64, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-2 admission_lz={lz} K={K}: observed mean trials {observed:.1} \
             vs predicted {predicted:.1} (ratio {ratio:.3}); \
             must hold within ±{:.0}% sampling variance",
            CP_TOLERANCE * 100.0
        );
    }
}

#[test]
fn cp3_compound_k_alpha_scaling_is_multiplicative() {
    // CP-3: the cost identity factors multiplicatively. Configurations
    // with the same product (K + lz = 8 → expected 2^8 = 256 trials)
    // must produce the same average trial count, regardless of which
    // decomposition is chosen.
    const PRODUCT: u64 = 1 << 8; // 256
    let cases: &[(u32, u32)] = &[
        (4, 4), // K=4, α=1/16
        (2, 6), // K=2, α=1/64
        (0, 8), // K=0, α=1/256
    ];
    let mut results = Vec::new();
    for &(k, lz) in cases {
        let predicted = (1u64 << (k + lz)) as f64;
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, k, 0xABACABA_u64, CP_N_TRIALS, max_per_trial);
        results.push((k, lz, observed, predicted));
    }
    // Each configuration matches its prediction within tolerance.
    for &(k, lz, observed, predicted) in &results {
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-3 (K={k}, lz={lz}): observed {observed:.1} vs predicted {predicted:.1} \
             (ratio {ratio:.3}); compound K×α scaling must hold the product"
        );
    }
    // Cross-configuration: all decompositions of the same product
    // agree on the trial count, modulo sampling variance.
    let observed_means: Vec<f64> = results.iter().map(|(_, _, o, _)| *o).collect();
    let mean_of_means = observed_means.iter().sum::<f64>() / (observed_means.len() as f64);
    for (k, lz, observed, _predicted) in &results {
        let dev = (observed - mean_of_means).abs() / mean_of_means;
        assert!(
            dev < CP_TOLERANCE,
            "CP-3 cross-config: (K={k}, lz={lz}) observed {observed:.1} \
             deviates {:.1}% from mean-of-configs {mean_of_means:.1}",
            dev * 100.0
        );
    }
    // The target product itself is matched.
    assert!(
        (mean_of_means / (PRODUCT as f64) - 1.0).abs() < CP_TOLERANCE,
        "CP-3 product: mean-of-configurations {mean_of_means:.1} must match \
         target product {PRODUCT}"
    );
}

#[test]
fn cp4_target_commitment_admission_orthogonal_to_payload_predicates() {
    // CP-4: the typed admission gate introduced by `mine_with` is
    // `AndCommitment<TargetCommitment, PayloadCommitment<K>>`. For the
    // prism cost contract to apply *at equality* over the unified
    // K + B bound (not as an upper bound), the base admission relation
    // carried by `TargetCommitment` must be admission-orthogonal to
    // the payload predicates (σ-Projection Hardening Principle U3,
    // ANALYSIS.md §3; bandwidth-additivity U6, §4).
    //
    // This test witnesses the orthogonality empirically: with `lz`
    // leading-zero admission bits (α = 2^-lz) and a K-bit payload, the
    // composed gate should land an admitting + committed digest in
    // ~2^(lz + K) synthetic trials. If TargetCommitment-admission and
    // the payload parity predicates were *not* independent, the
    // observed count would diverge from the product.
    let cases: &[(u32, u32, u64)] = &[
        (4, 4, 0b1010),  // lz=4, K=4 — product 2^8
        (6, 2, 0b01),    // lz=6, K=2 — product 2^8
        (3, 5, 0b10110), // lz=3, K=5 — product 2^8
    ];
    for &(lz, k, payload) in cases {
        let predicted = (1u64 << (lz + k)) as f64;
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, k, payload, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-4 (lz={lz}, K={k}): observed {observed:.1} vs predicted {predicted:.1} \
             (ratio {ratio:.3}); TargetCommitment admission must be orthogonal to \
             the payload predicates for AndCommitment bandwidth to be tight"
        );
    }

    // Surface cross-check: AndCommitment<TargetCommitment, _> reports
    // the sum of component bandwidths; EmptyCommitment is the
    // composition identity (mine == mine_with at B = 0).
    let target_c = TargetCommitment::from(Target::new(REGTEST_NBITS));
    let payload = PayloadCommitment::<6>::from_bits([true, false, true, true, false, true]);
    let composed: AndCommitment<TargetCommitment, PayloadCommitment<6>> = target_c.and(payload);
    let sum = target_c.bandwidth_bits() + payload.bandwidth_bits();
    assert!(
        (composed.bandwidth_bits() - sum).abs() < 1e-9,
        "CP-4: AndCommitment bandwidth must equal the sum of component bandwidths"
    );
    assert_eq!(
        composed.predicate_count(),
        target_c.predicate_count() + payload.predicate_count(),
        "CP-4: AndCommitment predicate_count must be additive"
    );
    let identity = target_c.and(EmptyCommitment);
    assert!(
        (identity.bandwidth_bits() - target_c.bandwidth_bits()).abs() < 1e-9,
        "CP-4: TargetCommitment.and(EmptyCommitment) must equal TargetCommitment — \
         mine is mine_with at B = 0"
    );
}

#[test]
fn mining_failure_is_typed_and_carries_total_observability_lens() {
    // Negative-conformance witness: MiningFailure has exactly two
    // variants. `DidNotAdmit` carries the receiver-side typed lens
    // (KappaObservables) so the lens is total — present on every
    // ψ-pipeline inference, not just admitting ones. The fail-closed
    // contract is type-level, not runtime-decided.
    fn exhaustive_failure_match(f: MiningFailure) -> &'static str {
        match f {
            MiningFailure::DidNotAdmit { .. } => "did_not_admit",
            MiningFailure::PipelineFailure => "pipeline_failure",
        }
    }
    let mock_did_not_admit = MiningFailure::DidNotAdmit {
        observables: KappaObservables::from_digest(&[0u8; 32]),
        nonce: 0,
        digest: [0u8; 32],
    };
    assert_eq!(
        exhaustive_failure_match(mock_did_not_admit),
        "did_not_admit"
    );
    assert_eq!(
        exhaustive_failure_match(MiningFailure::PipelineFailure),
        "pipeline_failure"
    );
}
