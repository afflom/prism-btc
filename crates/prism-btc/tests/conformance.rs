//! prism-btc conformance suite — κ-derivation kernel.
//!
//! Coverage of the structural invariants the κ-derivation kernel
//! commits to, and the generic typed-commitment surface that hosts
//! compose over their κ-labels.

use std::fs;
use std::path::{Path, PathBuf};

use prism_btc::{
    address_block, decode_payload, p_adic_valuation, payload_bit, payload_commitment_k2,
    payload_commitment_k4, payload_commitment_k8, serialize_header, sha256d_display, AffineParity,
    AndCommitment, Bits, BlockHeader, EmptyCommitment, KappaObservables,
    LexicographicLessEqThreshold, MerkleRoot, ObservablePredicate, SingletonCommitment, Stratum,
    Target, Timestamp, TriadicCoords, TypedCommitment, UltrametricCloseTo, Version,
    WalshHadamardParity, CANONICAL_PRIMES,
};

const REGTEST_NBITS: u32 = 0x207fffff;

fn src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn walk_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).expect("read_dir");
        for entry in entries {
            let path = entry.expect("entry").path();
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
        let body = fs::read_to_string(&path).expect("read");
        for (lineno, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            if line.contains(pattern) {
                hits.push(format!("{}:{}", path.display(), lineno + 1));
            }
        }
    }
    assert!(hits.is_empty(), "{label}: pattern found at {hits:?}");
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
fn cs1_no_vec_predicate_or_box_dyn_in_kernel_src() {
    for forbidden in &[
        "Vec<Predicate>",
        "Vec<dyn TypedCommitment",
        "Box<dyn TypedCommitment",
    ] {
        assert_pattern_absent_in_sources(
            forbidden,
            &format!("CS-1: forbidden runtime-dispatch surface `{forbidden}`"),
        );
    }
}

#[test]
fn cs2_no_legacy_admission_surface_in_kernel_src() {
    // L6: the kernel does not embed admission. None of the legacy
    // admission identifiers should appear in src — admission is a
    // host-side observation now.
    for legacy in &[
        "TargetCommitment",
        "fn mine_at",
        "fn mine(",
        "fn admit(",
        "NonceOrbit",
        "MiningOutcome",
        "MiningFailure",
        "leak_target",
        "set_thread_target",
        "current_thread_target",
        "recognize_under",
    ] {
        assert_pattern_absent_in_sources(
            legacy,
            &format!("CS-2: legacy admission identifier `{legacy}` must not appear in src"),
        );
    }
}

#[test]
fn cs3_typed_commitment_catalog_reachable() {
    // The five canonical ObservablePredicate impls + the three
    // composition shapes are reachable through prism-btc's re-exports.
    let _: SingletonCommitment<AffineParity> = payload_bit(0, true);
    let _: AndCommitment<SingletonCommitment<AffineParity>, SingletonCommitment<AffineParity>> =
        payload_commitment_k2([true, false]);
    let _ = EmptyCommitment;
    // Predicate-level reachability via trait dispatch (compile-time).
    let digest = [0u8; 32];
    let _ = ObservablePredicate::evaluate(&Stratum::<2> { k: 0 }, &digest);
    let _ = ObservablePredicate::evaluate(
        &WalshHadamardParity {
            frequency: &[0xffu8; 32],
            expected: false,
        },
        &digest,
    );
    let _ = ObservablePredicate::evaluate(
        &UltrametricCloseTo::<2> {
            reference: &[0u8; 32],
            k: 0,
        },
        &digest,
    );
    let _ = ObservablePredicate::evaluate(
        &LexicographicLessEqThreshold {
            target: &[0xff; 32],
        },
        &digest,
    );
}

#[test]
fn cs4_observables_are_pure_digest_projection() {
    // The receiver-side lens is a function of the digest alone — same
    // digest → same observables.
    let digest = [0xa5u8; 32];
    let a = KappaObservables::from_digest(&digest);
    let b = KappaObservables::from_digest(&digest);
    assert_eq!(a, b);
    assert!(a.coords.stratum <= 256);
    assert_eq!(a.p_adic.len(), CANONICAL_PRIMES.len());
}

// ─── CD — Dynamic invariants ───────────────────────────────────────────

#[test]
fn cd1_host_side_admission_holds_iff_digest_satisfies_target() {
    // L6: admission is host-side. The kernel emits a κ-label
    // unconditionally; the host's `target.is_satisfied_by_bytes(digest)`
    // is the admission relation.
    let target = Target::new(REGTEST_NBITS);
    let mut admitted = 0;
    for ts in 0u32..32 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        for nonce in 0..256u32 {
            let wire = serialize_header(&header, nonce);
            let _ = address_block(&wire); // kernel emits κ-label
            let digest = sha256d_display(&wire);
            if target.is_satisfied_by_bytes(&digest) {
                admitted += 1;
                break;
            }
        }
    }
    assert!(admitted > 0, "permissive target admits at least once");
}

#[test]
fn cd2_payload_commitment_round_trips_at_every_k() {
    // K=1 (payload_bit)
    let cmt1 = payload_bit(0, true);
    let mut digest = [0u8; 32];
    digest[0] = 0b0000_0001;
    assert!(cmt1.evaluate(&digest));

    // K=2
    let cmt2 = payload_commitment_k2([true, false]);
    let mut digest = [0u8; 32];
    digest[0] = 0b0000_0001;
    assert!(cmt2.evaluate(&digest));
    let decoded: [bool; 2] = decode_payload(&digest);
    assert_eq!(decoded, [true, false]);

    // K=4
    let bits = [true, false, true, true];
    let cmt4 = payload_commitment_k4(bits);
    let mut digest = [0u8; 32];
    digest[0] = 0b0000_1101;
    assert!(cmt4.evaluate(&digest));
    let decoded: [bool; 4] = decode_payload(&digest);
    assert_eq!(decoded, bits);

    // K=8
    let bits = [true, false, true, true, false, true, false, true];
    let cmt8 = payload_commitment_k8(bits);
    let mut digest = [0u8; 32];
    digest[0] = 0b1010_1101;
    assert!(cmt8.evaluate(&digest));
    let decoded: [bool; 8] = decode_payload(&digest);
    assert_eq!(decoded, bits);
}

#[test]
fn cd3_observables_agree_with_per_primitive_computation() {
    // The receiver-side lens is consistent with the per-primitive
    // canonical computation: TriadicCoords::from_hash + p_adic_valuation.
    for ts in 0u32..16 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        let wire = serialize_header(&header, 0);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        let canonical = TriadicCoords::from_hash(&digest);
        assert_eq!(observables.coords, canonical);
        for (i, &p) in CANONICAL_PRIMES.iter().enumerate() {
            assert_eq!(observables.p_adic[i], p_adic_valuation(&digest, p));
        }
    }
}

// ─── CP — Generic typed-commitment composition ────────────────────────

#[test]
fn cp1_and_commitment_bandwidth_is_additive() {
    // AndCommitment composition is bandwidth-additive (ADR-047 U6).
    let cmt = payload_commitment_k4([false; 4]);
    assert!((cmt.bandwidth_bits() - 4.0).abs() < 1e-9);
    let cmt8 = payload_commitment_k8([false; 8]);
    assert!((cmt8.bandwidth_bits() - 8.0).abs() < 1e-9);
}

#[test]
fn cp2_predicate_count_is_additive() {
    let cmt = payload_commitment_k4([false; 4]);
    assert_eq!(cmt.predicate_count(), 4);
    let cmt8 = payload_commitment_k8([false; 8]);
    assert_eq!(cmt8.predicate_count(), 8);
}

#[test]
fn cp3_empty_commitment_is_the_composition_identity() {
    assert!((EmptyCommitment.bandwidth_bits() - 0.0).abs() < 1e-9);
    assert_eq!(EmptyCommitment.predicate_count(), 0);
    assert!(EmptyCommitment.evaluate(&[0u8; 32]));
    assert!(EmptyCommitment.evaluate(&[0xff; 32]));
}

// ─── CN — Cross-network κ-derivation invariance ───────────────────────

#[test]
fn cn1_address_block_is_well_formed_at_every_network_bits() {
    // The κ-derivation is total over well-formed canonical input,
    // independent of nBits. This is what L4 + L6 buy together.
    let bits_set: &[u32] = &[
        0x207fffff, // regtest
        0x1d00ffff, // mainnet historical
        0x1cffff00, // testnet4-ish
        0x1c0001b3, // mid-difficulty
    ];
    for &bits in bits_set {
        let header = BlockHeader {
            version: Version(1),
            prev_hash: [0u8; 32],
            merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
            timestamp: Timestamp(1_700_000_000),
            bits: Bits(bits),
        };
        let wire = serialize_header(&header, 0);
        let outcome = address_block(&wire);
        assert!(outcome.address.starts_with("sha256d:"));
        assert_eq!(outcome.address.len(), 72);
        // Host-side admission is what consumes the target; the kernel
        // is target-agnostic.
        let target = Target::new(bits);
        let _admits = target.is_satisfied_by_bytes(&sha256d_display(&wire));
    }
}
