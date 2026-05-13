//! UOR-optimal mining via the typed Conjunction commitment surface.
//!
//! Exercises [`prism_btc::mine_with_commitment`] across a K-sweep at
//! regtest-target admission. For each K ∈ [0, MAX_K]:
//!
//! - Build a `MiningCommitment` Conjunction'ing K Walsh–Hadamard
//!   parity predicates at distinct single-bit frequencies in bytes
//!   [8, 32) of the κ-label.
//! - Run `N_TRIALS` independent template-variation searches (rolling
//!   the timestamp) until a κ-label satisfies both the admission
//!   relation *and* every commitment predicate.
//! - Report observed variations vs the PRF prediction
//!   `α^-1 × 2^K` per ANALYSIS.md §5.5 (U6 Bandwidth-Additivity).
//!
//! At regtest target `0x207fffff` the bare admission probability
//! `α ≈ 0.5`, so the baseline (K = 0) is ~2 variations; with K
//! predicates Conjunction'd on top, expected variations grow as
//! `~2 × 2^K`.
//!
//! Every returned [`MiningOutcome`] is a fail-closed witness: the
//! 80-byte wire-format κ-label admits at the target AND commits to
//! exactly K bits of structural information (the K predicates'
//! satisfaction in the digest). The mined block is wire-format-
//! valid for `submitblock`; the additional Conjunction predicates
//! are application-side structural commitments that Bitcoin Core
//! itself does not enforce — but that any verifier of the
//! application's protocol can re-check from the published κ-label.
//!
//! Run: `cargo run --release --example optimal_mining`.

use std::time::Instant;

use prism_btc::{
    mine_with_commitment, Bits, BlockHeader, MerkleRoot, MiningCommitment, Target, Timestamp,
    Version,
};

/// Regtest nBits — the bare-admission baseline (α ≈ 1/2).
const REGTEST_NBITS: u32 = 0x207fffff;
/// Maximum bandwidth (in bits) to sweep.
const MAX_K: usize = 6;
/// Independent trials per K — averaged for the empirical estimate.
const N_TRIALS: usize = 50;
/// Per-trial cap on template variations.
const MAX_VARIATIONS: u32 = 100_000;

/// Construct the ω-mask for the i-th typed predicate: a single bit
/// in bytes [8, 32) of the digest, orthogonal to any leading-zero
/// admission region used in the rest of the analysis.
fn omega_for_predicate(i: usize) -> [u8; 32] {
    let mut omega = [0u8; 32];
    let byte_idx = 8 + (i % 24);
    let bit_idx = (i / 24) % 8;
    omega[byte_idx] = 1u8 << bit_idx;
    omega
}

/// Build a K-bit MiningCommitment Conjunction'ing K parity
/// predicates with `expected = 1` at distinct single-bit
/// frequencies.
fn build_commitment(k: usize) -> MiningCommitment {
    (0..k).fold(MiningCommitment::empty(), |c, i| {
        c.add_parity(omega_for_predicate(i), 1)
    })
}

/// Build a permissive regtest-style header parameterized by a seed
/// (varying the prev_hash / merkle_root cheaply across trials).
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

/// Roll the timestamp until [`mine_with_commitment`] returns `Ok`.
/// Returns the number of template variations the search consumed,
/// or `None` if [`MAX_VARIATIONS`] was exhausted.
fn find_committed_block(trial_seed: u32, k: usize) -> Option<u32> {
    let commitment = build_commitment(k);
    let target = Target::new(REGTEST_NBITS);
    let base = build_header(trial_seed);

    for variation in 0..MAX_VARIATIONS {
        let mut header = base.clone();
        header.timestamp = Timestamp(base.timestamp.0.wrapping_add(variation));
        if let Ok(outcome) = mine_with_commitment(&header, target, &commitment) {
            // Defensive: the boundary already guaranteed admission AND
            // commitment, but verify here so the example self-checks.
            assert!(target.is_satisfied_by_bytes(&outcome.digest));
            assert!(commitment.evaluate(&outcome.digest));
            return Some(variation + 1);
        }
    }
    None
}

fn main() {
    println!("=== UOR-optimal mining: K-bit Conjunction commitment ===");
    println!();
    println!(
        "σ-projection: SHA-256d. Admission: regtest target 0x{:08x} (α ≈ 1/2).",
        REGTEST_NBITS
    );
    println!("K = bandwidth (independent 1-bit typed predicates Conjunction'd onto admission).");
    println!("PRF prediction (U6 Bandwidth-Additivity): variations = α^-1 × 2^K ≈ 2 × 2^K.");
    println!();
    println!("Each successful row: a wire-format-valid Bitcoin-style κ-label that ALSO");
    println!("commits to K bits of application-declared structural information.");
    println!();
    println!("  K   bandwidth      PRF pred       observed       ratio");
    println!("  --  ----------     ----------     ----------     -------");

    let started = Instant::now();
    for k in 0..=MAX_K {
        let mut variations = Vec::with_capacity(N_TRIALS);
        for trial in 0..N_TRIALS {
            match find_committed_block(trial as u32, k) {
                Some(v) => variations.push(v as f64),
                None => panic!(
                    "Failed to land commit-admitting κ-label at K={k}, trial={trial} \
                     within {MAX_VARIATIONS} variations"
                ),
            }
        }
        let mean: f64 = variations.iter().sum::<f64>() / (N_TRIALS as f64);
        // Bare-admission baseline at this target ≈ 2 variations.
        let pred = 2.0_f64 * (1u64 << k) as f64;
        let ratio = mean / pred;
        println!(
            "  {:2}  {:>6} bits     {:>10.0}     {:>10.1}     {:>4.2}x",
            k, k, pred, mean, ratio
        );
    }
    println!();
    println!("Total wall-clock: {:.2}s", started.elapsed().as_secs_f64());
    println!();
    println!("Implementation surface (ARCHITECTURE.md §14):");
    println!("  - `MiningCommitment::empty().add_parity(omega, expected)…` declares K predicates.");
    println!("  - `mine_with_commitment(header, target, &commitment)` is the typed entry point.");
    println!("  - Cost grows as 2^K per U6 Bandwidth-Additivity; the substrate's Conjunction");
    println!("    primitive makes the K-fold composition free at the typed-iso surface.");
}
