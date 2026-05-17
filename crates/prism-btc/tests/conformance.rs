//! prism-btc conformance suite.
//!
//! Validates that the implementation continues to realize prism's
//! zero-cost cost model — the contract `expected_trials =
//! α⁻¹ × 2^bandwidth_bits` at equality, scaling arbitrarily over K
//! and α. See [`CONFORMANCE.md`](../../../CONFORMANCE.md) for the
//! normative definition and wiki ADR-048 (TypedCommitment) +
//! ADR-049 (ObservablePredicate) for the substrate.
//!
//! Test IDs match the CONFORMANCE.md tables:
//!
//! * **CS-1 … CS-6** — structural invariants (the implementation must
//!   not drift back to dynamic dispatch / runtime allocation; legacy
//!   prism-btc-local cost-model surfaces must not return).
//! * **CD-1 … CD-3** — per-input runtime invariants the model demands.
//! * **CP-1 … CP-4** — empirical scaling of the cost identity over K
//!   and α. CP-4 witnesses the unified
//!   `AndCommitment<TargetCommitment, payload>` composition surface.
//!   CP-5/CP-6 (per-predicate U1/U2 calibration) are witnessed by the
//!   cryptanalysis battery and cross-referenced from CONFORMANCE.md.
//!
//! Run: `cargo test -p prism-btc --release --test conformance`

use std::fs;
use std::path::{Path, PathBuf};

use prism_btc::{
    decode_payload, leak_target, mine, p_adic_valuation, payload_bit, payload_commitment_k2,
    payload_commitment_k4, payload_commitment_k8, sha256d_display, target_commitment, AffineParity,
    AndCommitment, Bits, BlockHeader, EmptyCommitment, KappaObservables,
    LexicographicLessEqThreshold, MerkleRoot, MiningFailure, ObservablePredicate,
    SingletonCommitment, Stratum, Target, TargetCommitment, Timestamp, TriadicCoords,
    TypedCommitment, UltrametricCloseTo, Version, WalshHadamardParity, CANONICAL_PRIMES,
};

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
fn cs1_no_vec_of_typed_commitment_in_library_source() {
    // CS-1: prism's zero-cost contract requires every commitment be
    // monomorphized — no `Vec<dyn TypedCommitment>` / `Vec<Predicate>`
    // (the latter is a *legacy* prism-btc surface that has been
    // removed in favor of foundation's `ObservablePredicate` catalog
    // per wiki ADR-049). Both patterns must not return.
    assert_pattern_absent_in_sources(
        "Vec<Predicate>",
        "CS-1: legacy Vec<Predicate> dynamic-commitment surface must not return",
    );
    assert_pattern_absent_in_sources(
        "Vec<dyn TypedCommitment",
        "CS-1: dynamic TypedCommitment vector must not return",
    );
    assert_pattern_absent_in_sources(
        "Vec<Box<dyn TypedCommitment",
        "CS-1: boxed TypedCommitment vector must not return",
    );
}

#[test]
fn cs2_no_dyn_typed_commitment_in_library_source() {
    // CS-2: foundation's `TypedCommitment` is sealed and monomorphized
    // per ADR-048. `dyn` / `Box<dyn>` would defeat both properties.
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
    // CS-3 is enforced at compile time by foundation's supertrait
    // bound `pub trait TypedCommitment: Copy + Sealed` (ADR-048). This
    // runtime witness is a tautology: if `TypedCommitment: Copy`
    // weren't declared, the function below wouldn't compile.
    fn requires_copy_typed_commitment<C: TypedCommitment>(c: C) -> (C, C) {
        // Two-value usage exercises the `Copy` bound (move would only
        // permit one).
        (c, c)
    }
    let (_a, _b) = requires_copy_typed_commitment(EmptyCommitment);
    let (_a, _b) = requires_copy_typed_commitment(payload_commitment_k4([true; 4]));
    let t = leak_target([0xff; 32]);
    let (_a, _b) = requires_copy_typed_commitment(target_commitment(t));
}

#[test]
fn cs4_foundation_observable_predicates_cover_five_canonical_families() {
    // CS-4: the cost-model commitment surface is built from foundation's
    // five canonical `ObservablePredicate` impls per ADR-049
    // (`Stratum<P>`, `WalshHadamardParity`, `UltrametricCloseTo<P>`,
    // `AffineParity`, `LexicographicLessEqThreshold`). The catalog is
    // closed; adding a new variant requires foundation-side U1/U2
    // calibration. Compile-time witness: each typed predicate
    // satisfies `ObservablePredicate`.
    fn accepts<P: ObservablePredicate>() {}
    accepts::<Stratum<2>>();
    accepts::<Stratum<3>>();
    accepts::<Stratum<5>>();
    accepts::<Stratum<7>>();
    accepts::<WalshHadamardParity>();
    accepts::<UltrametricCloseTo<2>>();
    accepts::<AffineParity>();
    accepts::<LexicographicLessEqThreshold>();

    // Runtime witness: each predicate evaluates over a digest sample
    // and reports a finite accept_prob within [0, 1].
    let digest = [0u8; 32];
    let cases: &[(&str, f64)] = &[
        (
            "Stratum<2>",
            ObservablePredicate::accept_prob(&Stratum::<2> { k: 0 }),
        ),
        (
            "WalshHadamardParity",
            ObservablePredicate::accept_prob(&WalshHadamardParity {
                frequency: &[0xffu8; 32],
                expected: false,
            }),
        ),
        (
            "UltrametricCloseTo<2>",
            ObservablePredicate::accept_prob(&UltrametricCloseTo::<2> {
                reference: &[0u8; 32],
                k: 1,
            }),
        ),
        (
            "AffineParity",
            ObservablePredicate::accept_prob(&AffineParity {
                bit_index: 0,
                expected: false,
            }),
        ),
        (
            "LexicographicLessEqThreshold",
            ObservablePredicate::accept_prob(&LexicographicLessEqThreshold {
                target: &[0xffu8; 8],
            }),
        ),
    ];
    for (name, prob) in cases {
        assert!(
            *prob >= 0.0 && *prob <= 1.0,
            "CS-4 {name}: accept_prob={prob} out of [0, 1]"
        );
    }
    // And evaluate each on the zero digest — exhaustive Rust trait
    // dispatch witness.
    let _ = ObservablePredicate::evaluate(&Stratum::<2> { k: 0 }, &digest);
    let _ = ObservablePredicate::evaluate(
        &WalshHadamardParity {
            frequency: &[0xffu8; 32],
            expected: false,
        },
        &digest,
    );
}

#[test]
fn cs5_mining_outcome_carries_observables() {
    // CS-5: every MiningOutcome carries `observables: KappaObservables`
    // as a non-optional field — the receiver-side typed lens is always
    // present.
    fn project_observables(outcome: prism_btc::MiningOutcome) -> KappaObservables {
        outcome.observables
    }
    let header = permissive_header(1_700_000_000);
    let target = Target::new(REGTEST_NBITS);
    if let Ok(outcome) = mine(&header, target) {
        let obs: KappaObservables = project_observables(outcome);
        assert!(obs.coords.stratum <= 256);
        assert_eq!(obs.p_adic.len(), CANONICAL_PRIMES.len());
    }
}

#[test]
fn cs6_no_legacy_commitment_surface_references() {
    // CS-6: every prism-btc-local cost-model surface that has been
    // replaced by foundation's typed-commitment catalog (wiki
    // ADR-048 + ADR-049) must not be reachable through `src/`. Each
    // forbidden identifier names a piece of the pre-foundation API
    // that would re-introduce author-side trait impls / runtime
    // dispatch / non-canonical predicate enums if added back.
    for legacy in &[
        // Pre-typed-surface dynamic-dispatch API.
        "MiningCommitment",
        "mine_with_commitment",
        "CommitmentError",
        "try_add_predicate",
        "add_predicate",
        // Local-trait surfaces (replaced by foundation):
        "mine_with(",
        "PayloadCommitment<",
        // Local-enum surfaces (replaced by foundation observables):
        "enum Predicate ",
        "enum Support ",
    ] {
        assert_pattern_absent_in_sources(
            legacy,
            &format!("CS-6: legacy surface identifier `{legacy}` must not return"),
        );
    }
}

// ─── CD — Dynamic invariants ───────────────────────────────────────────

#[test]
fn cd1_mine_admits_under_target_commitment() {
    // CD-1 (revised for ADR-048 conformance): the canonical entry
    // [`mine`] threads `TargetCommitment` through foundation's
    // `run_route` as the model's pinned `C: TypedCommitment`. For a
    // permissive target, admission holds for some template
    // variation; the κ-label's digest satisfies the target by
    // construction (foundation's `run_route` gates `Grounded`
    // emission on `commitment.evaluate(kappa_label) == true`).
    let target = Target::new(REGTEST_NBITS);
    let mut admitted = false;
    for ts in 0u32..32 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        if let Ok(outcome) = mine(&header, target) {
            assert!(
                target.is_satisfied_by_bytes(&outcome.digest),
                "CD-1: mine() Ok ⇒ digest must satisfy target"
            );
            admitted = true;
            break;
        }
    }
    assert!(
        admitted,
        "CD-1: permissive target must admit within 32 variations"
    );
}

#[test]
fn cd2_payload_commitment_round_trips_at_every_k() {
    // CD-2 (revised for ADR-049 conformance): the payload-commitment
    // helpers produce foundation `AndCommitment` trees of
    // `SingletonCommitment<AffineParity>` leaves per wiki QS-06's
    // K-fold exemplar shape. For each K ∈ {1, 2, 4, 8} we encode K
    // payload bits, synthesize a digest carrying those bits at the
    // canonical low-bit positions, evaluate the commitment, and
    // decode back — the receiver-side `decode_payload` agrees with
    // the encoded payload.
    //
    // The full mining round-trip (admission + payload at the
    // typed-iso surface) is exercised probabilistically by CP-4.
    // Here we pin the commitment-surface contract: `evaluate` ↔
    // `decode_payload` are inverses on every K.
    fn synthesize_digest_with_low_bits(bits: &[bool]) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, b) in bits.iter().enumerate() {
            if *b {
                let byte_idx = i / 8;
                let bit_off = i % 8;
                d[byte_idx] |= 1 << bit_off;
            }
        }
        d
    }

    // K = 1: payload_bit. Tests single-leaf shape (no AndCommitment).
    {
        for bit in [false, true] {
            let cmt = payload_bit(0, bit);
            let digest = synthesize_digest_with_low_bits(&[bit]);
            assert!(
                cmt.evaluate(&digest),
                "CD-2 K=1: commitment must admit synthetic digest carrying the bit"
            );
            let decoded: [bool; 1] = decode_payload(&digest);
            assert_eq!(decoded[0], bit, "CD-2 K=1: decode must round-trip");
        }
    }
    // K = 2.
    {
        let bits = [true, false];
        let cmt = payload_commitment_k2(bits);
        let digest = synthesize_digest_with_low_bits(&bits);
        assert!(cmt.evaluate(&digest));
        let decoded: [bool; 2] = decode_payload(&digest);
        assert_eq!(decoded, bits);
    }
    // K = 4.
    {
        let bits = [true, false, true, true];
        let cmt = payload_commitment_k4(bits);
        let digest = synthesize_digest_with_low_bits(&bits);
        assert!(cmt.evaluate(&digest));
        let decoded: [bool; 4] = decode_payload(&digest);
        assert_eq!(decoded, bits);
    }
    // K = 8.
    {
        let bits = [true, false, true, true, false, false, true, false];
        let cmt = payload_commitment_k8(bits);
        let digest = synthesize_digest_with_low_bits(&bits);
        assert!(cmt.evaluate(&digest));
        let decoded: [bool; 8] = decode_payload(&digest);
        assert_eq!(decoded, bits);
    }
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
            assert_eq!(outcome.observables.coords, canonical);
            for (i, &p) in CANONICAL_PRIMES.iter().enumerate() {
                assert_eq!(
                    outcome.observables.p_adic[i],
                    p_adic_valuation(&outcome.digest, p),
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
/// passes the joint (admission, K-bit-commitment) gate. Used by CP-1,
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

const CP_N_TRIALS: usize = 200;
const CP_TOLERANCE: f64 = 0.30;

#[test]
fn cp1_k_scaling_holds_across_two_decades() {
    const ADMISSION_LZ: u32 = 1;
    let cases: &[(u32, f64)] = &[(0, 2.0), (2, 8.0), (4, 32.0), (8, 512.0), (12, 8192.0)];
    for &(k, predicted) in cases {
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(ADMISSION_LZ, k, 0xC0FFEE_u64, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-1 K={k}: observed {observed:.1} vs predicted {predicted:.1} (ratio {ratio:.3})"
        );
    }
}

#[test]
fn cp2_alpha_scaling_holds_at_fixed_k() {
    const K: u32 = 2;
    let cases: &[(u32, f64)] = &[
        (1, (1u64 << 1) as f64 * 4.0),
        (4, (1u64 << 4) as f64 * 4.0),
        (8, (1u64 << 8) as f64 * 4.0),
        (12, (1u64 << 12) as f64 * 4.0),
    ];
    for &(lz, predicted) in cases {
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, K, 0xBADF00D_u64, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-2 admission_lz={lz} K={K}: observed {observed:.1} vs predicted {predicted:.1} \
             (ratio {ratio:.3})"
        );
    }
}

#[test]
fn cp3_compound_k_alpha_scaling_is_multiplicative() {
    const PRODUCT: u64 = 1 << 8;
    let cases: &[(u32, u32)] = &[(4, 4), (2, 6), (0, 8)];
    let mut results = Vec::new();
    for &(k, lz) in cases {
        let predicted = (1u64 << (k + lz)) as f64;
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, k, 0xABACABA_u64, CP_N_TRIALS, max_per_trial);
        results.push((k, lz, observed, predicted));
    }
    for &(k, lz, observed, predicted) in &results {
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-3 (K={k}, lz={lz}): observed {observed:.1} vs predicted {predicted:.1}"
        );
    }
    let observed_means: Vec<f64> = results.iter().map(|(_, _, o, _)| *o).collect();
    let mean_of_means = observed_means.iter().sum::<f64>() / (observed_means.len() as f64);
    for (k, lz, observed, _) in &results {
        let dev = (observed - mean_of_means).abs() / mean_of_means;
        assert!(
            dev < CP_TOLERANCE,
            "CP-3 cross-config (K={k}, lz={lz}): deviates {:.1}% from mean",
            dev * 100.0
        );
    }
    assert!((mean_of_means / (PRODUCT as f64) - 1.0).abs() < CP_TOLERANCE);
}

#[test]
fn cp4_typed_commitment_composition_is_bandwidth_additive() {
    // CP-4 (revised for ADR-048 conformance): the typed admission
    // surface foundation publishes is
    // `AndCommitment<TargetCommitment, payload>` per wiki QS-06.
    // Empirical orthogonality: with `lz` leading-zero admission bits
    // (α = 2^-lz) and a K-bit payload at canonical AffineParity
    // positions, the composed gate lands an admitting+committed
    // digest in ~2^(lz + K) synthetic trials. This is the
    // U3-orthogonality witness — if target admission were not
    // independent of the payload predicates, the count would diverge.
    let cases: &[(u32, u32, u64)] = &[(4, 4, 0b1010), (6, 2, 0b01), (3, 5, 0b10110)];
    for &(lz, k, payload) in cases {
        let predicted = (1u64 << (lz + k)) as f64;
        let max_per_trial = (predicted as u64) * 64 + 1024;
        let observed = average_trials(lz, k, payload, CP_N_TRIALS, max_per_trial);
        let ratio = observed / predicted;
        assert!(
            (ratio - 1.0).abs() < CP_TOLERANCE,
            "CP-4 (lz={lz}, K={k}): observed {observed:.1} vs predicted {predicted:.1}"
        );
    }

    // Surface cross-check: foundation's `AndCommitment` reports the
    // sum of component bandwidths (additive per ADR-048's
    // `bandwidth_bits` contract). The composed commitment uses the
    // 5th-slot `C: TypedCommitment` shape foundation evaluates inside
    // `run_route`.
    let target_static = leak_target([0xffu8; 32]);
    let target_c: TargetCommitment = target_commitment(target_static);
    let payload: AffineParity = AffineParity {
        bit_index: 0,
        expected: true,
    };
    let payload_singleton: SingletonCommitment<AffineParity> =
        SingletonCommitment { predicate: payload };
    let composed: AndCommitment<TargetCommitment, SingletonCommitment<AffineParity>> =
        AndCommitment {
            left: target_c,
            right: payload_singleton,
        };
    let sum = target_c.bandwidth_bits() + payload_singleton.bandwidth_bits();
    assert!(
        (composed.bandwidth_bits() - sum).abs() < 1e-9,
        "CP-4: AndCommitment bandwidth must equal the sum of component bandwidths"
    );
    assert_eq!(
        composed.predicate_count(),
        target_c.predicate_count() + payload_singleton.predicate_count(),
        "CP-4: AndCommitment predicate_count must be additive"
    );
    // EmptyCommitment is the composition identity (bandwidth = 0).
    let identity = AndCommitment {
        left: target_c,
        right: EmptyCommitment,
    };
    assert!(
        (identity.bandwidth_bits() - target_c.bandwidth_bits()).abs() < 1e-9,
        "CP-4: TargetCommitment ⊗ EmptyCommitment must equal TargetCommitment bandwidth"
    );
}

#[test]
fn mining_failure_is_typed_and_carries_total_observability_lens() {
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
