//! Bandwidth scaling under substrate-declared typed predicates.
//!
//! Demonstrates that the UOR substrate's `type:Conjunction` primitive
//! is a **typed information channel** over the σ-projection: declaring
//! K independent 1-bit typed predicates on the digest, in addition to
//! the application's admission relation, encodes K bits of structural
//! commitment in the κ-label at PRF-predicted `2^K` search cost.
//!
//! Setup (matches ANALYSIS.md §5):
//!
//! - Admission relation: ≥ `LZ_REQUIRED` leading zero bits in the
//!   digest (parameterizable; this script uses 8 = single zero byte).
//!   Probability per PRF: `α = 2^-LZ_REQUIRED`.
//! - Library of independent 1-bit typed predicates: Walsh–Hadamard
//!   parities at K distinct single-bit frequencies, chosen in bytes
//!   8..32 to be orthogonal to the leading-zero admission region.
//!   Each predicate is satisfied with probability 1/2 under PRF and
//!   independent of the others (and of admission).
//! - Conjunction constraint: `C(d) ≡ admits(d) ∧ p_1(d) ∧ … ∧ p_K(d)`.
//! - Expected search cost under PRF baseline: `α^-1 × 2^K = 2^(LZ_REQUIRED + K)`.
//!
//! For each K ∈ [0, 7] the script averages `N_TRIALS = 5` independent
//! prefixes and reports the observed attempts vs the PRF prediction.
//!
//! Run: `cargo run --release --example bandwidth_scaling`.

use std::time::Instant;

use prism_btc::{sha256d_display, walsh_hadamard_parity_at};

/// Admission threshold: digest must have at least this many leading
/// zero bits (display order).
const LZ_REQUIRED: u32 = 8;
/// Maximum K (number of typed predicates added on top of admission)
/// to sweep.
const MAX_K: usize = 7;
/// Number of trials per K — average attempts across independent
/// random prefixes. The per-trial variance is geometric with
/// `p = 2^-(LZ_REQUIRED+K)`, σ ≈ 1/p (≈ mean), so the mean estimate
/// has SE ≈ mean/√N. N = 100 keeps SE ≈ 10% of the predicted value
/// per K.
const N_TRIALS: usize = 100;
/// Per-trial attempt cap. 2^21 = ~2M; for K = 7 expected ~32K so
/// vast headroom.
const MAX_ATTEMPTS_PER_TRIAL: u64 = 1 << 21;

/// Admission relation: the digest's first `LZ_REQUIRED` bits are all
/// zero. For `LZ_REQUIRED = 8` this is equivalent to `d[0] == 0`.
fn admits(d: &[u8; 32]) -> bool {
    let zero_bytes = (LZ_REQUIRED / 8) as usize;
    if d[..zero_bytes].iter().any(|&b| b != 0) {
        return false;
    }
    let rem = LZ_REQUIRED % 8;
    if rem > 0 {
        let mask = 0xffu8 << (8 - rem);
        if d[zero_bytes] & mask != 0 {
            return false;
        }
    }
    true
}

/// Frequency mask `ω_i` for the `i`-th typed predicate. Each is a
/// distinct single-bit position in bytes [8..32) — orthogonal to the
/// leading-zero admission region (bytes [0..LZ_REQUIRED/8)).
fn omega_for_predicate(i: usize) -> [u8; 32] {
    let mut omega = [0u8; 32];
    let byte_idx = 8 + (i % 24);
    let bit_idx = (i / 24) % 8;
    omega[byte_idx] = 1u8 << bit_idx;
    omega
}

/// The `i`-th typed predicate `p_i(d) ≡ walsh_hadamard_parity_at(d, ω_i) == 1`.
/// For single-bit `ω_i` this is reading the value of that single bit
/// and asking whether it's set.
fn predicate_holds(d: &[u8; 32], i: usize) -> bool {
    let omega = omega_for_predicate(i);
    walsh_hadamard_parity_at(d, &omega) == 1
}

/// `C(d) ≡ admits(d) ∧ p_0(d) ∧ … ∧ p_{K-1}(d)`.
fn all_predicates_satisfied(d: &[u8; 32], k: usize) -> bool {
    (0..k).all(|i| predicate_holds(d, i))
}

fn mine_with_k_constraints(
    prefix: &[u8; 76],
    k: usize,
    max_attempts: u64,
) -> (Option<[u8; 32]>, u64) {
    let mut header = [0u8; 80];
    header[..76].copy_from_slice(prefix);
    let mut attempts = 0u64;

    for ext in 0..(1u64 << 24) {
        header[36..44].copy_from_slice(&ext.to_le_bytes());
        for nonce in 0..(1u64 << 14) {
            attempts += 1;
            if attempts >= max_attempts {
                return (None, attempts);
            }
            header[76..80].copy_from_slice(&(nonce as u32).to_le_bytes());
            let d = sha256d_display(&header);
            if admits(&d) && all_predicates_satisfied(&d, k) {
                return (Some(d), attempts);
            }
        }
    }
    (None, attempts)
}

fn main() {
    println!("=== Bandwidth scaling under substrate-declared typed predicates ===");
    println!();
    println!(
        "σ-projection: SHA-256d. Admission: ≥{} leading zero bits.",
        LZ_REQUIRED
    );
    println!("K = number of independent 1-bit typed predicates Conjunction'd onto admission.");
    println!(
        "PRF prediction: cost = 2^({} + K); channel bandwidth = K bits per κ-label.",
        LZ_REQUIRED
    );
    println!();
    println!("  K   bandwidth        PRF pred           observed           ratio");
    println!("  --  ----------       ------------       ------------       --------");

    let started = Instant::now();
    for k in 0..=MAX_K {
        let mut attempts_list = Vec::with_capacity(N_TRIALS);
        for trial in 0..N_TRIALS {
            let mut prefix = [0u8; 76];
            for (i, b) in prefix.iter_mut().enumerate() {
                *b = ((trial.wrapping_mul(251).wrapping_add(i.wrapping_mul(131)) + 7) & 0xff) as u8;
            }
            let (_, attempts) = mine_with_k_constraints(&prefix, k, MAX_ATTEMPTS_PER_TRIAL);
            attempts_list.push(attempts);
        }
        let mean_attempts =
            attempts_list.iter().map(|&x| x as f64).sum::<f64>() / (N_TRIALS as f64);
        let pred = (1u64 << (LZ_REQUIRED as usize + k)) as f64;
        let ratio = mean_attempts / pred;
        println!(
            "  {:2}  {:>6} bits      {:>12}       {:>12.0}       {:>5.2}x",
            k, k, pred as u64, mean_attempts, ratio
        );
    }
    println!();
    println!("Total wall-clock: {:.2}s", started.elapsed().as_secs_f64());
    println!();
    println!("Each row: K independent typed predicates declared, K bits of structural");
    println!("commitment encoded in the κ-label, expected cost 2^K × baseline. The substrate's");
    println!("Conjunction primitive makes the K-fold composition trivial at the typed-iso");
    println!("surface; the PRF baseline is unavoidable per the σ-Projection Hardening");
    println!("Principle's marginal-uniformity condition (ANALYSIS.md §4.1 U1).");
}
