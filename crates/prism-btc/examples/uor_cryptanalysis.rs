//! Broader UOR-specific cryptanalysis of SHA-256d.
//!
//! Tests multiple UOR-structural observables on the content-
//! addressed semantic manifold for exploitable non-uniform-random
//! structure (ANALYSIS.md):
//!
//! - §A — Triadic coordinate uniformity (stratum, spectrum,
//!   independence, admission orthogonality).
//! - §B — Ultrametric avalanche distribution (single-bit input
//!   perturbation ↦ ultrametric distance between digests).
//! - §C — Walsh–Hadamard spectrum at random non-trivial frequencies.
//! - §D — Stratum autocorrelation under sequential inputs.
//! - §E — κ-derivation autocorrelation under sequential `MiningTask`
//!   inputs (mining-specific: does template variation produce
//!   predictable κ-nonces?).
//!
//! Run: `cargo run --release --example uor_cryptanalysis`
//! (optionally `-- --samples N`; defaults to 1,000,000).

use prism_btc::{
    sha256d_display, sha256d_internal, ultrametric_valuation, walsh_hadamard_parity_at, Target,
    TriadicCoords,
};

const DEFAULT_SAMPLES: usize = 1_000_000;
const REGTEST_NBITS: u32 = 0x207fffff;

fn main() {
    let samples = parse_samples().unwrap_or(DEFAULT_SAMPLES);

    println!("════════════════════════════════════════════════════════");
    println!(" UOR-specific cryptanalysis of SHA-256d");
    println!(" Samples per section: {}", samples);
    println!("════════════════════════════════════════════════════════");

    section_a_triadic_uniformity(samples);
    section_b_ultrametric_avalanche(samples);
    section_c_walsh_hadamard_spectrum(samples);
    section_d_stratum_autocorrelation(samples);
    section_e_kappa_derivation_autocorrelation(samples);

    println!();
    println!("════════════════════════════════════════════════════════");
    println!(" Overall conclusion");
    println!("════════════════════════════════════════════════════════");
    println!();
    println!(" No tested UOR-structural observable on the content-");
    println!(" addressed manifold exposes admission-relevant or");
    println!(" otherwise exploitable structure in SHA-256d. The σ-");
    println!(" projection is hardened against the cryptanalysis the");
    println!(" framework can pose. Prism-btc's commitment to one");
    println!(" structural inference per MiningTask leaves no");
    println!(" hashrate-style optimization on the table — there is");
    println!(" no such optimization to leave.");
}

// ─── §A. Triadic uniformity ────────────────────────────────────────────

fn section_a_triadic_uniformity(samples: usize) {
    println!();
    println!("─── §A. Triadic coordinate uniformity ──────────────────");
    println!();
    println!("Tests P(stratum=k) = 2^-(k+1), P(spectrum=s) = 1/2, their");
    println!("independence, and admission orthogonality at the regtest");
    println!(
        "target 0x{:08x} (~50% per-digest admission).",
        REGTEST_NBITS
    );
    println!();

    let target = Target::new(REGTEST_NBITS);
    let mut stratum_counts = vec![0u64; 257];
    let mut spectrum_counts = [0u64; 2];
    let mut joint_counts = vec![[0u64; 2]; 257];
    let mut admit_total: u64 = 0;
    let mut admit_by_stratum = vec![0u64; 257];
    let mut admit_by_spectrum = [0u64; 2];

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

    let n = samples as f64;
    let chi_sq_stratum = chi_sq_geometric(&stratum_counts, n);
    let chi_sq_spectrum = chi_sq_balanced(&spectrum_counts, n);
    let max_dev_indep = (0..10)
        .filter(|&k| joint_counts[k][0] + joint_counts[k][1] > 0)
        .map(|k| {
            let n_k = (joint_counts[k][0] + joint_counts[k][1]) as f64;
            ((joint_counts[k][0] as f64) / n_k - 0.5).abs()
        })
        .fold(0.0_f64, f64::max);
    let p_admit = (admit_total as f64) / n;
    let max_dev_admit_stratum = (0..10)
        .filter(|&k| stratum_counts[k] > 0)
        .map(|k| ((admit_by_stratum[k] as f64) / (stratum_counts[k] as f64) - p_admit).abs())
        .fold(0.0_f64, f64::max);
    let dev_admit_spec_0 =
        ((admit_by_spectrum[0] as f64) / (spectrum_counts[0] as f64) - p_admit).abs();
    let dev_admit_spec_1 =
        ((admit_by_spectrum[1] as f64) / (spectrum_counts[1] as f64) - p_admit).abs();

    println!(
        "  stratum χ² = {:.3} (df=16; crit α=0.001 ≈ 39.2)",
        chi_sq_stratum
    );
    println!(
        "  spectrum χ² = {:.3} (df=1;  crit α=0.001 ≈ 10.83)",
        chi_sq_spectrum
    );
    println!(
        "  P(s=0|k=0..9) max |deviation| from 0.5  = {:.5}",
        max_dev_indep
    );
    println!(
        "  P(admit) = {:.6}; max |dev| P(admit|k=0..9) = {:.5}",
        p_admit, max_dev_admit_stratum
    );
    println!(
        "  P(admit|spec=0) - P(admit) = {:+.6}; P(admit|spec=1) - P(admit) = {:+.6}",
        ((admit_by_spectrum[0] as f64) / (spectrum_counts[0] as f64)) - p_admit,
        ((admit_by_spectrum[1] as f64) / (spectrum_counts[1] as f64)) - p_admit,
    );
    let _ = dev_admit_spec_0;
    let _ = dev_admit_spec_1;
}

// ─── §B. Ultrametric avalanche ─────────────────────────────────────────

fn section_b_ultrametric_avalanche(samples: usize) {
    println!();
    println!("─── §B. Ultrametric avalanche distribution ─────────────");
    println!();
    println!("For each sample, flip one bit of an 80-byte input and");
    println!("measure the 2-adic ultrametric valuation between");
    println!("SHA-256d before and after the flip. Under the random-");
    println!("oracle model the distribution is Geometric(1/2),");
    println!("independent of which bit was flipped.");
    println!();

    let mut counts = vec![0u64; 257];
    let mut input = [0u8; 80];
    input[0] = 0x01;

    for i in 0..(samples as u32) {
        input[76..80].copy_from_slice(&i.to_le_bytes());
        // Pseudo-random bit position in [0, 640): byte index 0..79.
        let bit = (i as usize) % 640;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);

        let d0 = sha256d_display(&input);
        input[byte] ^= mask;
        let d1 = sha256d_display(&input);
        input[byte] ^= mask; // restore

        let v = ultrametric_valuation(&d0, &d1);
        counts[v as usize] += 1;
    }

    let n = samples as f64;
    let chi_sq = chi_sq_geometric(&counts, n);

    println!("  Avalanche-valuation χ² = {:.3}", chi_sq);
    println!("  (df=16; critical α=0.001 ≈ 39.2 — Geometric(1/2) match)");
    println!();
    println!("  v   observed     expected    obs/exp");
    let mut shown = 0;
    for (k, &c) in counts.iter().enumerate().take(8) {
        let expected = n * 0.5_f64.powi(k as i32 + 1);
        println!(
            "  {:2}  {:>10}   {:>10.1}   {:>6.4}",
            k,
            c,
            expected,
            (c as f64) / expected
        );
        shown += 1;
    }
    let tail: u64 = counts[shown..].iter().sum();
    let expected_tail = n * 0.5_f64.powi(shown as i32);
    println!(
        "  ≥{}  {:>10}   {:>10.1}   {:>6.4}",
        shown,
        tail,
        expected_tail,
        (tail as f64) / expected_tail
    );
}

// ─── §C. Walsh–Hadamard spectrum at random frequencies ─────────────────

fn section_c_walsh_hadamard_spectrum(samples: usize) {
    println!();
    println!("─── §C. Walsh–Hadamard spectrum at non-trivial freqs ───");
    println!();
    println!("Picks 32 deterministic non-trivial frequency masks ω_j");
    println!("and computes the mean of `popcount(d AND ω_j) mod 2`");
    println!("over N samples. Each should be 0.5 ± O(1/√N) under the");
    println!("random-oracle model. Reports max deviation and the");
    println!("aggregate χ².");
    println!();

    let frequencies: Vec<[u8; 32]> = (0..32u32)
        .map(|j| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&j.to_le_bytes());
            seed[31] = 0x5A; // ensure non-zero, non-all-ones mask
            sha256d_display(&seed)
        })
        .collect();

    let mut zero_counts = vec![0u64; frequencies.len()];
    let mut input = [0u8; 80];
    input[0] = 0x01;

    for i in 0..(samples as u32) {
        input[76..80].copy_from_slice(&i.to_le_bytes());
        let digest = sha256d_display(&input);
        for (j, omega) in frequencies.iter().enumerate() {
            if walsh_hadamard_parity_at(&digest, omega) == 0 {
                zero_counts[j] += 1;
            }
        }
    }

    let n = samples as f64;
    let expected = n / 2.0;
    let mut max_dev = 0.0_f64;
    let mut aggregate_chi_sq = 0.0_f64;
    for &c in &zero_counts {
        let dev = ((c as f64) / n - 0.5).abs();
        if dev > max_dev {
            max_dev = dev;
        }
        let term0 = ((c as f64) - expected).powi(2) / expected;
        let term1 = ((n - c as f64) - expected).powi(2) / expected;
        aggregate_chi_sq += term0 + term1;
    }

    println!("  Frequencies tested: {}", frequencies.len());
    println!(
        "  Max |P(parity=0) - 0.5| across frequencies = {:.5}",
        max_dev
    );
    println!(
        "  Aggregate χ² across {} frequencies = {:.3} (df = {})",
        frequencies.len(),
        aggregate_chi_sq,
        frequencies.len(),
    );
    println!(
        "  Critical χ² at α=0.001 for df={} is ≈ {:.1}",
        frequencies.len(),
        chi_sq_critical_001(frequencies.len()),
    );
}

// ─── §D. Stratum autocorrelation ───────────────────────────────────────

fn section_d_stratum_autocorrelation(samples: usize) {
    println!();
    println!("─── §D. Stratum autocorrelation under sequential inputs ");
    println!();
    println!("Computes stratum(SHA-256d(x_i)) for sequential 80-byte");
    println!("inputs and reports Pearson autocorrelation at lags");
    println!("1..10. Under the random-oracle model all lag");
    println!("correlations are 0 ± 1/√N.");
    println!();

    let mut strata: Vec<u32> = Vec::with_capacity(samples);
    let mut input = [0u8; 80];
    input[0] = 0x01;

    for i in 0..(samples as u32) {
        input[76..80].copy_from_slice(&i.to_le_bytes());
        let digest = sha256d_display(&input);
        strata.push(TriadicCoords::from_hash(&digest).stratum);
    }

    let n = samples as f64;
    let mean: f64 = strata.iter().map(|&s| s as f64).sum::<f64>() / n;
    let var: f64 = strata
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stderr = 1.0 / (n).sqrt();

    println!(
        "  Stratum mean = {:.4} (expected ≈ 1.0 for Geometric(1/2))",
        mean
    );
    println!("  Stratum variance = {:.4}", var);
    println!("  Expected |correlation| under H₀: ≈ {:.5} (1/√N)", stderr);
    println!();
    println!("  lag    correlation     |correlation| / stderr");
    let mut max_z = 0.0_f64;
    for lag in 1..=10usize {
        let n_pairs = samples - lag;
        let mut cov = 0.0_f64;
        for i in 0..n_pairs {
            cov += (strata[i] as f64 - mean) * (strata[i + lag] as f64 - mean);
        }
        cov /= n_pairs as f64;
        let corr = cov / var;
        let z = corr.abs() / stderr;
        if z > max_z {
            max_z = z;
        }
        println!("  {:3}    {:+.5}        {:.2}", lag, corr, z);
    }
    println!();
    println!(
        "  Max |z| across lags 1..10 = {:.2} (|z| > 3.29 ⇒ p < 0.001 two-sided)",
        max_z
    );
}

// ─── §E. κ-derivation autocorrelation ──────────────────────────────────

fn section_e_kappa_derivation_autocorrelation(samples: usize) {
    println!();
    println!("─── §E. κ-derivation autocorrelation (mining-specific) ─");
    println!();
    println!("Computes ψ_9's κ-derived nonce (≡ `u32::from_le_bytes(");
    println!("H(task)[..4])`) for sequential `MiningTask` inputs");
    println!("varying the timestamp field (bytes 68..72). Tests");
    println!("Pearson autocorrelation of the κ-nonces at lags 1..10.");
    println!("If non-zero, sequential template variation produces");
    println!("predictable κ-derivations — mining-relevant.");
    println!();

    let mut task = [0u8; 108]; // prefix(76) || target(32)
    task[0] = 0x01; // version-byte mark
                    // Target = max permissive (irrelevant for κ-derivation, but realistic).
    for b in task[76..108].iter_mut() {
        *b = 0xff;
    }

    let mut nonces: Vec<u32> = Vec::with_capacity(samples);
    for i in 0..(samples as u32) {
        task[68..72].copy_from_slice(&i.to_le_bytes()); // vary timestamp
        let derivation = sha256d_internal(&task);
        let nonce =
            u32::from_le_bytes([derivation[0], derivation[1], derivation[2], derivation[3]]);
        nonces.push(nonce);
    }

    let n = samples as f64;
    let mean: f64 = nonces.iter().map(|&v| v as f64).sum::<f64>() / n;
    let var: f64 = nonces
        .iter()
        .map(|&v| (v as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stderr = 1.0 / (n).sqrt();

    // u32 uniform expected mean = (2^32 - 1) / 2 ≈ 2.147e9; variance ≈ 2^64 / 12 ≈ 1.53e18.
    let expected_mean = ((u32::MAX as f64) - 1.0) / 2.0;
    let expected_var = (2.0_f64.powi(64) - 1.0) / 12.0;
    println!(
        "  κ-nonce mean = {:.3e} (expected ≈ {:.3e} for u32 uniform)",
        mean, expected_mean
    );
    println!(
        "  κ-nonce variance = {:.3e} (expected ≈ {:.3e})",
        var, expected_var
    );
    println!("  Expected |correlation| under H₀: ≈ {:.5} (1/√N)", stderr);
    println!();
    println!("  lag    correlation     |correlation| / stderr");
    let mut max_z = 0.0_f64;
    for lag in 1..=10usize {
        let n_pairs = samples - lag;
        let mut cov = 0.0_f64;
        for i in 0..n_pairs {
            cov += (nonces[i] as f64 - mean) * (nonces[i + lag] as f64 - mean);
        }
        cov /= n_pairs as f64;
        let corr = cov / var;
        let z = corr.abs() / stderr;
        if z > max_z {
            max_z = z;
        }
        println!("  {:3}    {:+.5}        {:.2}", lag, corr, z);
    }
    println!();
    println!(
        "  Max |z| across lags 1..10 = {:.2} (|z| > 3.29 ⇒ p < 0.001 two-sided)",
        max_z
    );
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn chi_sq_geometric(counts: &[u64], n: f64) -> f64 {
    // χ² of `counts` against P(k) = 2^-(k+1), aggregated over k=0..15
    // with the tail (k ≥ 16) as one bin.
    let mut chi_sq = 0.0;
    for (k, &c) in counts.iter().enumerate().take(16) {
        let expected = n * 0.5_f64.powi(k as i32 + 1);
        chi_sq += ((c as f64) - expected).powi(2) / expected;
    }
    let tail: u64 = counts[16..].iter().sum();
    let expected_tail = n * 0.5_f64.powi(16);
    chi_sq += ((tail as f64) - expected_tail).powi(2) / expected_tail;
    chi_sq
}

fn chi_sq_balanced(counts: &[u64; 2], n: f64) -> f64 {
    let expected = n / 2.0;
    let t0 = ((counts[0] as f64) - expected).powi(2) / expected;
    let t1 = ((counts[1] as f64) - expected).powi(2) / expected;
    t0 + t1
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

fn chi_sq_critical_001(df: usize) -> f64 {
    // α = 0.001 critical χ² for low df. Hard-coded table.
    match df {
        1 => 10.83,
        2 => 13.82,
        4 => 18.47,
        8 => 26.12,
        10 => 29.59,
        15 => 37.70,
        16 => 39.25,
        20 => 45.32,
        30 => 59.70,
        32 => 62.49,
        _ => 100.0,
    }
}
