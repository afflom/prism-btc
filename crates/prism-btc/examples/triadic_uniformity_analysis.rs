//! UOR triadic coordinate uniformity analysis.
//!
//! **Question.** Does the UOR triadic coordinate decomposition expose
//! any non-uniform-random structure in SHA-256d that could be
//! exploited for Bitcoin-style mining?
//!
//! **Setup.** The triadic coordinates project a 32-byte digest into
//! two observables:
//!
//! - **stratum** — 2-adic valuation. Index of the lowest set bit when
//!   the digest is viewed as a 256-bit big-endian integer; 256 if the
//!   digest is all-zero.
//! - **spectrum** — Walsh–Hadamard parity. Popcount of all 256 bits,
//!   modulo 2.
//!
//! Under the standard cryptographic assumption that SHA-256d is
//! indistinguishable from a random oracle:
//!
//! - stratum follows a truncated Geometric(1/2) distribution:
//!   `P(stratum = k) = 2^-(k+1)` for k in [0, 255], plus an atom of
//!   mass `2^-256` at stratum=256.
//! - spectrum follows Bernoulli(1/2).
//! - stratum and spectrum are independent.
//! - both are independent of the admission relation
//!   (`digest ≤ target` in display order), because admission depends
//!   on the *high* bits of the digest while stratum reads *low* bits
//!   and spectrum is a global parity.
//!
//! This program samples a configurable number of SHA-256d outputs
//! over sequential 80-byte inputs, computes their triadic coordinates,
//! and tests the empirical distribution against the uniform-random
//! model. It then tests admission-orthogonality at a permissive
//! (regtest 0x207fffff) target.
//!
//! **Run:** `cargo run --release --example triadic_uniformity_analysis`
//! (optionally `-- --samples N`; defaults to 1,000,000).

use prism_btc::{sha256d_display, Target, TriadicCoords};

const DEFAULT_SAMPLES: usize = 1_000_000;
const REGTEST_NBITS: u32 = 0x207fffff;

fn main() {
    let samples = parse_samples().unwrap_or(DEFAULT_SAMPLES);
    let target = Target::new(REGTEST_NBITS);

    println!("=== UOR triadic coordinate uniformity analysis ===");
    println!();
    println!("Samples: {}", samples);
    println!(
        "Admission target: nBits=0x{:08x} (regtest, ~50% per-digest admission)",
        REGTEST_NBITS
    );
    println!();

    // Accumulators.
    let mut stratum_counts = vec![0u64; 257];
    let mut spectrum_counts = [0u64; 2];
    let mut joint_counts = vec![[0u64; 2]; 257];
    let mut admit_total: u64 = 0;
    let mut admit_by_stratum = vec![0u64; 257];
    let mut admit_by_spectrum = [0u64; 2];

    // Sample loop: vary the trailing 4 bytes of a fixed 80-byte block
    // as a `u32` LE; this exercises the same surface ψ_9's
    // σ-projection runs on (a wire-format header).
    let mut input = [0u8; 80];
    input[0] = 0x01;
    for i in 0..(samples as u32) {
        input[76..80].copy_from_slice(&i.to_le_bytes());
        let digest = sha256d_display(&input);
        let coords = TriadicCoords::from_hash(&digest);

        stratum_counts[coords.stratum as usize] += 1;
        spectrum_counts[coords.spectrum as usize] += 1;
        joint_counts[coords.stratum as usize][coords.spectrum as usize] += 1;

        if target.is_satisfied_by_bytes(&digest) {
            admit_total += 1;
            admit_by_stratum[coords.stratum as usize] += 1;
            admit_by_spectrum[coords.spectrum as usize] += 1;
        }
    }

    report_stratum(&stratum_counts, samples);
    report_spectrum(&spectrum_counts, samples);
    report_independence(&joint_counts);
    report_admission(
        admit_total,
        &admit_by_stratum,
        &admit_by_spectrum,
        &stratum_counts,
        &spectrum_counts,
        samples,
    );
}

fn report_stratum(counts: &[u64], samples: usize) {
    println!("─── Stratum distribution ───────────────────────────────");
    println!("Expected: P(stratum=k) = 2^-(k+1)  (truncated Geometric(1/2))");
    println!();
    println!("  k    observed    expected      observed/expected    χ² term");
    let mut chi_sq = 0.0_f64;
    let mut df = 0;
    let n = samples as f64;
    for (k, &c) in counts.iter().enumerate().take(16) {
        let observed = c as f64;
        let expected = n * 0.5_f64.powi(k as i32 + 1);
        let term = (observed - expected).powi(2) / expected;
        chi_sq += term;
        df += 1;
        println!(
            "  {:3}  {:>10}  {:>12.1}    {:>6.4}              {:>7.3}",
            k,
            c,
            expected,
            observed / expected,
            term
        );
    }
    let tail: u64 = counts[16..].iter().sum();
    let expected_tail = n * 0.5_f64.powi(16);
    let term_tail = ((tail as f64) - expected_tail).powi(2) / expected_tail;
    chi_sq += term_tail;
    df += 1;
    println!(
        "  ≥16  {:>10}  {:>12.1}    {:>6.4}              {:>7.3}",
        tail,
        expected_tail,
        (tail as f64) / expected_tail,
        term_tail
    );
    println!();
    println!("  χ² total = {:.3}  (df = {})", chi_sq, df - 1);
    println!(
        "  Critical χ² at α=0.001 for df={} is ≈ {:.1}",
        df - 1,
        chi_sq_critical_001(df - 1)
    );
    println!();
}

fn report_spectrum(counts: &[u64; 2], samples: usize) {
    println!("─── Spectrum distribution ──────────────────────────────");
    println!("Expected: P(spectrum=0) = P(spectrum=1) = 0.5  (Bernoulli)");
    println!();
    let n = samples as f64;
    let expected = n / 2.0;
    let term_0 = ((counts[0] as f64) - expected).powi(2) / expected;
    let term_1 = ((counts[1] as f64) - expected).powi(2) / expected;
    let chi_sq = term_0 + term_1;
    println!(
        "  spectrum=0  {:>10}  fraction={:.6}  χ² term={:.4}",
        counts[0],
        (counts[0] as f64) / n,
        term_0,
    );
    println!(
        "  spectrum=1  {:>10}  fraction={:.6}  χ² term={:.4}",
        counts[1],
        (counts[1] as f64) / n,
        term_1,
    );
    println!();
    println!("  χ² total = {:.3}  (df = 1)", chi_sq);
    println!("  Critical χ² at α=0.001 for df=1 is ≈ 10.83");
    println!();
}

fn report_independence(joint: &[[u64; 2]]) {
    println!("─── Stratum ⊥ Spectrum independence ────────────────────");
    println!("Expected: P(spectrum=0 | stratum=k) = 0.5 for all k");
    println!();
    println!("  k    n(k)        P(spectrum=0 | k)    |deviation|");
    for (k, row) in joint.iter().enumerate().take(10) {
        let n_k = row[0] + row[1];
        if n_k == 0 {
            continue;
        }
        let p = (row[0] as f64) / (n_k as f64);
        let dev = (p - 0.5).abs();
        println!("  {:3}  {:>8}    {:.6}             {:.6}", k, n_k, p, dev);
    }
    println!();
}

fn report_admission(
    admit_total: u64,
    admit_by_stratum: &[u64],
    admit_by_spectrum: &[u64; 2],
    stratum_counts: &[u64],
    spectrum_counts: &[u64; 2],
    samples: usize,
) {
    println!("─── Admission orthogonality (regtest target) ───────────");
    println!("Expected if orthogonal: P(admit | stratum=k) = P(admit | spectrum=s) = P(admit)");
    println!();
    let n = samples as f64;
    let p_admit = (admit_total as f64) / n;
    println!(
        "  Unconditional P(admit) = {} / {} = {:.6}",
        admit_total, samples, p_admit
    );
    println!();
    println!("  Conditioned on stratum:");
    println!("    k    n(k)       admit(k)   P(admit | k)   deviation");
    for k in 0..10 {
        let n_k = stratum_counts[k];
        if n_k == 0 {
            continue;
        }
        let a_k = admit_by_stratum[k];
        let p_k = (a_k as f64) / (n_k as f64);
        let dev = p_k - p_admit;
        println!(
            "    {:3}  {:>8}   {:>8}   {:.6}      {:+.6}",
            k, n_k, a_k, p_k, dev
        );
    }
    println!();
    println!("  Conditioned on spectrum:");
    println!("    s    n(s)       admit(s)   P(admit | s)   deviation");
    for s in 0..2 {
        let n_s = spectrum_counts[s];
        if n_s == 0 {
            continue;
        }
        let a_s = admit_by_spectrum[s];
        let p_s = (a_s as f64) / (n_s as f64);
        let dev = p_s - p_admit;
        println!(
            "    {:3}  {:>8}   {:>8}   {:.6}      {:+.6}",
            s, n_s, a_s, p_s, dev
        );
    }
    println!();
    println!("─── Conclusion ─────────────────────────────────────────");
    println!();
    println!("If the χ² statistics above are below their α=0.001 critical");
    println!("values and the conditional P(admit | ·) values match the");
    println!("unconditional P(admit) within sampling error, the empirical");
    println!("evidence supports the theoretical claim: the UOR triadic");
    println!("coordinate decomposition exposes no admission-relevant");
    println!("structure in SHA-256d.");
}

fn parse_samples() -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--samples" {
            return iter.next().and_then(|s| s.parse().ok());
        }
    }
    None
}

/// Approximate critical χ² values at α = 0.001 for low df. Hard-coded
/// rather than computed numerically; this is an analysis script, not
/// a stats library.
fn chi_sq_critical_001(df: usize) -> f64 {
    match df {
        1 => 10.83,
        2 => 13.82,
        3 => 16.27,
        4 => 18.47,
        5 => 20.52,
        10 => 29.59,
        15 => 37.70,
        16 => 39.25,
        20 => 45.32,
        _ => 50.0, // conservative upper bound for moderate df
    }
}
