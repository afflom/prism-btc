//! UOR-optimal mining via the typed Conjunction commitment surface.
//!
//! Exercises [`prism_btc::mine_with_commitment`] across the typed
//! predicate library (`Predicate::Parity`, `Predicate::StratumEq`,
//! `Predicate::PAdicEq`, `Predicate::UltrametricCloseTo`) at
//! regtest-target admission. Two demonstrations:
//!
//! 1. **K-bit parity sweep** — K ∈ [0, MAX_K] parity predicates
//!    Conjunction'd onto admission. Each parity is 1 bit; total
//!    bandwidth = K bits; PRF cost = `2 × 2^K` template variations.
//!
//! 2. **Mixed-predicate commitment** — one parity + one stratum-
//!    equality + one ultrametric-closeness, total bandwidth =
//!    `1 + (k+1) + k'`. Shows that the richer predicate library
//!    gives the same `2^B` cost scaling for total bandwidth `B`.
//!
//! Reported cost is the empirical mean of `N_TRIALS` independent
//! template searches per commitment; expected = `α^-1 × 2^B`.
//!
//! Run: `cargo run --release --example optimal_mining`.

use std::time::Instant;

use prism_btc::{
    mine_with_commitment, Bits, BlockHeader, MerkleRoot, MiningCommitment, Target, Timestamp,
    Version,
};

/// Regtest nBits — the bare-admission baseline (α ≈ 1/2).
const REGTEST_NBITS: u32 = 0x207fffff;
/// Maximum K (number of parity predicates) for §1 sweep.
const MAX_K: usize = 6;
/// Independent trials per K — averaged for the empirical estimate.
const N_TRIALS: usize = 50;
/// Per-trial cap on template variations.
const MAX_VARIATIONS: u32 = 1_000_000;

/// Construct the ω-mask for the i-th parity predicate.
fn omega_for_predicate(i: usize) -> [u8; 32] {
    let mut omega = [0u8; 32];
    let byte_idx = 8 + (i % 24);
    let bit_idx = (i / 24) % 8;
    omega[byte_idx] = 1u8 << bit_idx;
    omega
}

/// Build a K-bit parity-only MiningCommitment.
fn build_parity_commitment(k: usize) -> MiningCommitment {
    (0..k).fold(MiningCommitment::empty(), |c, i| {
        c.add_parity(omega_for_predicate(i), 1)
    })
}

/// Build a permissive regtest-style header parameterized by a seed.
fn build_header(trial_seed: u32) -> BlockHeader {
    let prev = trial_seed.to_le_bytes();
    let merkle = trial_seed.wrapping_mul(0x9E37_79B1).to_le_bytes();
    let mut prev32 = [0u8; 32];
    let mut merkle32 = [0u8; 32];
    for i in 0..32 {
        prev32[i] = prev[i % 4] ^ (i as u8);
        merkle32[i] = merkle[i % 4] ^ (i as u8).wrapping_mul(7);
    }
    BlockHeader {
        version: Version(1),
        prev_hash: prev32,
        merkle_root: MerkleRoot::from_bytes(merkle32),
        timestamp: Timestamp(1_700_000_000),
        bits: Bits(REGTEST_NBITS),
    }
}

/// Roll the timestamp until [`mine_with_commitment`] returns `Ok`,
/// up to [`MAX_VARIATIONS`].
fn find_committed_block(trial_seed: u32, commitment: &MiningCommitment) -> Option<u32> {
    let target = Target::new(REGTEST_NBITS);
    let base = build_header(trial_seed);
    for variation in 0..MAX_VARIATIONS {
        let mut header = base.clone();
        header.timestamp = Timestamp(base.timestamp.0.wrapping_add(variation));
        if let Ok(outcome) = mine_with_commitment(&header, target, commitment) {
            assert!(target.is_satisfied_by_bytes(&outcome.digest));
            assert!(commitment.evaluate(&outcome.digest));
            return Some(variation + 1);
        }
    }
    None
}

fn main() {
    println!("=== UOR-optimal mining: typed Conjunction commitment ===");
    println!();
    println!(
        "σ-projection: SHA-256d. Admission: regtest target 0x{:08x} (α ≈ 1/2).",
        REGTEST_NBITS
    );
    println!("PRF prediction (U6 Bandwidth-Additivity): variations = α^-1 × 2^B");
    println!("where B = commitment.bandwidth_bits() (sum of per-predicate contributions).");
    println!();

    sweep_parity_only();
    demo_mixed_predicates();

    println!();
    println!("Each mined block is a wire-format-valid Bitcoin κ-label that ALSO commits");
    println!("to B bits of application-declared structural information. Bitcoin Core sees");
    println!("a normal block; an application-layer verifier reads the typed predicates off");
    println!("the published digest.");
}

fn sweep_parity_only() {
    println!("── §1. Parity-only sweep ───────────────────────────────");
    println!();
    println!("K parity predicates Conjunction'd onto admission; bandwidth = K bits.");
    println!();
    println!("  K   bandwidth      PRF pred       observed       ratio");
    println!("  --  ----------     ----------     ----------     -------");

    let started = Instant::now();
    for k in 0..=MAX_K {
        let commitment = build_parity_commitment(k);
        let bandwidth_bits = commitment.bandwidth_bits();
        // Normalize ±0.0 → 0.0 for cosmetic table alignment.
        let bandwidth_display = if bandwidth_bits == 0.0 {
            0.0_f64
        } else {
            bandwidth_bits
        };
        let pred = 2.0_f64.powf(bandwidth_bits + 1.0); // 2 × 2^B baseline at α ≈ 1/2

        let mut variations = Vec::with_capacity(N_TRIALS);
        for trial in 0..N_TRIALS {
            match find_committed_block(trial as u32, &commitment) {
                Some(v) => variations.push(v as f64),
                None => panic!("Failed at K={k}, trial={trial}"),
            }
        }
        let mean: f64 = variations.iter().sum::<f64>() / (N_TRIALS as f64);
        println!(
            "  {:2}  {:>4.1} bits      {:>10.0}     {:>10.1}     {:>4.2}x",
            k,
            bandwidth_display,
            pred,
            mean,
            mean / pred,
        );
    }
    println!();
    println!(
        "Parity sweep wall-clock: {:.2}s",
        started.elapsed().as_secs_f64()
    );
}

fn demo_mixed_predicates() {
    println!();
    println!("── §2. Mixed-predicate Conjunction ─────────────────────");
    println!();
    println!("A single commitment composing predicates from different");
    println!("families on the manifold. The total bandwidth is the");
    println!("sum of per-predicate contributions (U6 Bandwidth-Additivity).");
    println!();

    // Predicates must be **independent** for U6 bandwidth-additivity
    // to hold. Both `StratumEq{k}` and `UltrametricCloseTo` read
    // low-bit content; pairing them would double-count constraints.
    // Here we pair predicates from different algebraic strata:
    //
    //   - `Parity` at byte 8 bit 0:   reads bit 64 (BE) → independent
    //                                 from byte-31 observables.
    //   - `StratumEq{k=2}`:           reads bits 0..2 of byte 31
    //                                 (the 2-adic stratification).
    //   - `PAdicEq{p=3, k=0}`:        digest's 3-adic valuation = 0
    //                                 ⇔ digest as 256-bit integer
    //                                 not divisible by 3. Modular
    //                                 constraint approximately
    //                                 independent of any specific bit
    //                                 pattern (mod-2 vs mod-3 are
    //                                 jointly independent over
    //                                 uniform random integers).

    let mixed = MiningCommitment::empty()
        .add_parity(omega_for_predicate(0), 1) // 1 bit
        .add_stratum_eq(2) // bit 2 of byte 31 = 1, bits 0..1 = 0 → 3 bits
        .add_p_adic_eq(3, 0); // P = 2/3 → bandwidth ≈ 0.585 bits

    let bandwidth_bits = mixed.bandwidth_bits();
    let count = mixed.predicate_count();
    let pred = 2.0_f64.powf(bandwidth_bits + 1.0); // baseline ≈ 2 at α ≈ 1/2

    println!("  Commitment: {} predicates", count);
    println!("    1× Parity                (1.000 bits)");
    println!("    1× StratumEq{{k=2}}        (3.000 bits)");
    println!("    1× PAdicEq{{p=3, k=0}}     (≈0.585 bits)");
    println!("  Total bandwidth: {:.3} bits", bandwidth_bits);
    println!(
        "  PRF prediction: {:.0} variations (= 2 × 2^{:.3})",
        pred, bandwidth_bits
    );
    println!();

    let started = Instant::now();
    let mut variations = Vec::with_capacity(N_TRIALS);
    for trial in 0..N_TRIALS {
        match find_committed_block(trial as u32, &mixed) {
            Some(v) => variations.push(v as f64),
            None => panic!("Mixed-predicate trial {} failed", trial),
        }
    }
    let mean: f64 = variations.iter().sum::<f64>() / (N_TRIALS as f64);
    println!(
        "  Observed mean variations: {:.0} (ratio {:.2}x)",
        mean,
        mean / pred,
    );
    println!(
        "  Mixed-predicate wall-clock: {:.2}s",
        started.elapsed().as_secs_f64()
    );
}
