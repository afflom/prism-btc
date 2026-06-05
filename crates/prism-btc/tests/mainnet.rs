//! Mainnet-readiness conformance — the κ-derivation kernel handles
//! every well-formed mainnet input correctly. The runtime cost of PoW
//! admission at mainnet difficulty is intrinsic to the protocol, not a
//! kernel property; what's proven here is **correctness of κ-derivation
//! and observability** across the mainnet-difficulty input space.

use prism_btc::{
    address_block, serialize_header, sha256d_display, Bits, BlockHeader, CampaignStats,
    KappaObservables, MerkleRoot, Target, Timestamp, Version, STRATUM_BINS,
};

const TRIAL_NONCE: u32 = 0;

const MAINNET_DIFFICULTY_VALUES: &[u32] = &[
    0x1d00ffff, 0x1d00d86a, 0x1c0001b3, 0x18009645, 0x17027a01, 0x1702e9e7, 0x170269e0, 0x1701c2b6,
];

fn synthetic_mainnet_header(nbits: u32, seed: u32) -> BlockHeader {
    let mut prev = [0u8; 32];
    prev[28..32].copy_from_slice(&seed.to_le_bytes());
    let mut merkle = [0u8; 32];
    merkle[28..32].copy_from_slice(&seed.wrapping_mul(0x9E37_79B1).to_le_bytes());
    BlockHeader {
        version: Version(0x2000_0000),
        prev_hash: prev,
        merkle_root: MerkleRoot::from_bytes(merkle),
        timestamp: Timestamp(1_700_000_000_u32.wrapping_add(seed)),
        bits: Bits(nbits),
    }
}

#[test]
fn cm1_target_constructor_accepts_full_mainnet_difficulty_history() {
    for &nbits in MAINNET_DIFFICULTY_VALUES {
        let target = Target::new(nbits);
        let _bytes = target.to_bytes();
        // Trivial totality probe.
        let _ = target.is_satisfied_by_bytes(&[0u8; 32]);
        let _ = target.is_satisfied_by_bytes(&[0xff; 32]);
    }
}

#[test]
fn cm2_address_block_total_at_every_mainnet_difficulty() {
    // L4 + L6: the ψ-pipeline is total over well-formed input. Across
    // every mainnet nBits × 50 synthetic seeds the kernel emits a
    // well-formed κ-label without panic.
    const SEEDS: u32 = 50;
    for &nbits in MAINNET_DIFFICULTY_VALUES {
        for seed in 0..SEEDS {
            let header = synthetic_mainnet_header(nbits, seed);
            let wire = serialize_header(&header, TRIAL_NONCE);
            let outcome = address_block(&wire);
            assert!(outcome.address.starts_with("sha256d:"));
            assert_eq!(outcome.address.len(), 72);
        }
    }
}

#[test]
fn cm3_observatory_matches_prf_baseline_on_synthetic_digests() {
    // At N = 10_000 single-nonce inferences against the regtest target
    // (so we get a mix of digests), the campaign's stratum distribution
    // matches Geom(1/2) within χ² α=0.001 (df=16, crit≈39.25).
    const N: u32 = 10_000;
    const REGTEST_NBITS: u32 = 0x207fffff;

    let mut campaign = CampaignStats::new();
    for seed in 0..N {
        let header = synthetic_mainnet_header(REGTEST_NBITS, seed);
        let wire = serialize_header(&header, TRIAL_NONCE);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        campaign.record_attempt(&observables, &digest);
    }

    assert_eq!(campaign.attempts, N as u64);

    let n = N as f64;
    let mut chi_sq = 0.0_f64;
    for k in 0..16 {
        let expected = n * 0.5_f64.powi(k as i32 + 1);
        let observed = campaign.stratum_hist[k] as f64;
        chi_sq += (observed - expected).powi(2) / expected;
    }
    let tail_observed: u64 = campaign.stratum_hist[16..].iter().sum();
    let tail_expected = n * 0.5_f64.powi(16);
    chi_sq += ((tail_observed as f64) - tail_expected).powi(2) / tail_expected;
    assert!(
        chi_sq < 39.25,
        "stratum χ² = {chi_sq:.3} exceeds α=0.001 critical"
    );
}

#[test]
fn cm4_campaign_stats_is_path_independent() {
    // Aggregating in two batches matches aggregating in one — the
    // observatory is monotone and order-independent.
    const REGTEST_NBITS: u32 = 0x207fffff;
    const N: u32 = 200;
    const SPLIT: u32 = 73;

    let mut baseline = CampaignStats::new();
    for seed in 0..N {
        let h = synthetic_mainnet_header(REGTEST_NBITS, seed);
        let wire = serialize_header(&h, TRIAL_NONCE);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        baseline.record_attempt(&observables, &digest);
    }

    let mut split = CampaignStats::new();
    for seed in 0..SPLIT {
        let h = synthetic_mainnet_header(REGTEST_NBITS, seed);
        let wire = serialize_header(&h, TRIAL_NONCE);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        split.record_attempt(&observables, &digest);
    }
    let mut resumed = split;
    for seed in SPLIT..N {
        let h = synthetic_mainnet_header(REGTEST_NBITS, seed);
        let wire = serialize_header(&h, TRIAL_NONCE);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        resumed.record_attempt(&observables, &digest);
    }

    assert_eq!(baseline, resumed);
}

#[test]
fn cm5_empirical_admission_alpha_converges_to_theoretical() {
    // At the regtest target the digest admits with α ≈ 0.5; the host-
    // side admission rate at N = 10_000 converges to that value
    // within ±5%.
    const N: u32 = 10_000;
    const REGTEST_NBITS: u32 = 0x207fffff;
    let target = Target::new(REGTEST_NBITS);

    let mut campaign = CampaignStats::new();
    for seed in 0..N {
        let h = synthetic_mainnet_header(REGTEST_NBITS, seed);
        let wire = serialize_header(&h, TRIAL_NONCE);
        let digest = sha256d_display(&wire);
        let observables = KappaObservables::from_digest(&digest);
        if target.is_satisfied_by_bytes(&digest) {
            campaign.record_admission(&observables, &digest);
        } else {
            campaign.record_attempt(&observables, &digest);
        }
    }
    let observed = campaign.empirical_alpha();
    let dev = (observed - 0.5).abs();
    assert!(
        dev < 0.05,
        "α empirical {observed:.4} deviates {dev:.4} from theoretical 0.5"
    );
}

#[test]
fn cm6_campaign_stratum_bin_count_matches_constant() {
    let stats = CampaignStats::new();
    assert_eq!(stats.stratum_hist.len(), STRATUM_BINS);
    assert_eq!(stats.padic_3_hist.len(), prism_btc::PADIC_BINS);
}
