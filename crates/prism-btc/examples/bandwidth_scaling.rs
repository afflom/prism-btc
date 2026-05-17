//! Bandwidth scaling under foundation's K-fold `AffineParity` payload
//! commitments (wiki ADR-048 + ADR-049, QS-06 K-fold exemplar).
//!
//! For each K ∈ {2, 4, 8} prism-btc publishes a typed builder
//! ([`prism_btc::payload_commitment_k2`] / `_k4` / `_k8`) producing an
//! `AndCommitment` tree of `SingletonCommitment<AffineParity>` leaves
//! at the canonical low-bit positions `0..K`. The cost-model contract
//! per ADR-048 (Lean theorem `Commitment.prf_prob_tight_wellFormed`,
//! applied at equality):
//!
//! - `bandwidth_bits()` is **additive**:
//!   K=2 → 2.0, K=4 → 4.0, K=8 → 8.0.
//! - `accept_prob()` is **multiplicative**:
//!   K=2 → 1/4, K=4 → 1/16, K=8 → 1/256.
//!
//! This example also exercises the receiver-side `decode_payload`
//! inverse: synthesise a digest carrying the encoded bits at the
//! canonical positions and check that the commitment admits it.
//!
//! Run: `cargo run --release --example bandwidth_scaling`.

use prism_btc::{
    decode_payload, payload_commitment_k2, payload_commitment_k4, payload_commitment_k8,
    TypedCommitment,
};

/// Lay K payload bits onto a fresh 32-byte digest at AffineParity
/// canonical positions: bit `i` lands in `byte_idx = i/8`, `bit_off = i%8`.
fn synth_digest_with_low_bits(bits: &[bool]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            d[i / 8] |= 1u8 << (i % 8);
        }
    }
    d
}

fn main() {
    println!("=== K-fold payload-commitment bandwidth scaling (ADR-048/049) ===");
    println!();
    println!("Each `payload_commitment_kN(bits)` returns an AndCommitment tree of");
    println!("N `SingletonCommitment<AffineParity>` leaves at bit positions [0..N).");
    println!("All shapes are sealed by foundation and monomorphized per use site —");
    println!("no Vec, no dynamic dispatch.");
    println!();
    println!("  shape          predicates   bandwidth      accept_prob   evaluate   decode-rt");
    println!("  ------------   ----------   -----------    -----------   --------   ---------");

    // K = 2.
    {
        let bits = [true, false];
        let cmt = payload_commitment_k2(bits);
        let digest = synth_digest_with_low_bits(&bits);
        let decoded: [bool; 2] = decode_payload(&digest);
        println!(
            "  PayloadK2      {:>10}   {:>5.2} bits     {:>10.6}    {:>5}      {:>5}",
            cmt.predicate_count(),
            cmt.bandwidth_bits(),
            cmt.accept_prob(),
            cmt.evaluate(&digest),
            decoded == bits,
        );
    }
    // K = 4.
    {
        let bits = [true, false, true, true];
        let cmt = payload_commitment_k4(bits);
        let digest = synth_digest_with_low_bits(&bits);
        let decoded: [bool; 4] = decode_payload(&digest);
        println!(
            "  PayloadK4      {:>10}   {:>5.2} bits     {:>10.6}    {:>5}      {:>5}",
            cmt.predicate_count(),
            cmt.bandwidth_bits(),
            cmt.accept_prob(),
            cmt.evaluate(&digest),
            decoded == bits,
        );
    }
    // K = 8.
    {
        let bits = [true, false, true, true, false, false, true, false];
        let cmt = payload_commitment_k8(bits);
        let digest = synth_digest_with_low_bits(&bits);
        let decoded: [bool; 8] = decode_payload(&digest);
        println!(
            "  PayloadK8      {:>10}   {:>5.2} bits     {:>10.6}    {:>5}      {:>5}",
            cmt.predicate_count(),
            cmt.bandwidth_bits(),
            cmt.accept_prob(),
            cmt.evaluate(&digest),
            decoded == bits,
        );
    }

    println!();
    println!("Additivity / multiplicativity cross-check (predicted vs computed):");
    let k2 = payload_commitment_k2([true, false]);
    let k4 = payload_commitment_k4([true, false, true, true]);
    let k8 = payload_commitment_k8([true, false, true, true, false, false, true, false]);
    for (name, b, p) in [
        ("K2", k2.bandwidth_bits(), k2.accept_prob()),
        ("K4", k4.bandwidth_bits(), k4.accept_prob()),
        ("K8", k8.bandwidth_bits(), k8.accept_prob()),
    ] {
        println!("  {name}: bandwidth = {b:.4} bits, accept_prob = {p:.6}");
    }

    println!();
    println!("Cost identity per ADR-048: expected mining trials = α⁻¹ × 2^bandwidth_bits");
    println!("at equality. Empirical scaling is exercised by tests/conformance.rs (CP-1..CP-4).");
}
