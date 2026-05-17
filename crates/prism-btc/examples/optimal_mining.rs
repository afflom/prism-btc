//! UOR-optimal mining: composing foundation's canonical commitment
//! shapes on the κ-label of a freshly mined regtest block.
//!
//! Demonstrates the cost-model commitment surface foundation publishes
//! per wiki ADR-048 + ADR-049:
//!
//! 1. **Bare admission.** `mine()` goes through foundation's `run_route`
//!    with the model's pinned `C = TargetCommitment`. The returned
//!    `MiningOutcome` carries a κ-label digest that, by construction,
//!    satisfies `LexicographicLessEqThreshold` (regtest target).
//!
//! 2. **K-fold payload composition.** Build `AndCommitment` trees of
//!    `SingletonCommitment<AffineParity>` leaves via
//!    [`prism_btc::payload_commitment_k2`] /
//!    [`prism_btc::payload_commitment_k4`] /
//!    [`prism_btc::payload_commitment_k8`] and evaluate them on the
//!    mined digest. Each shape is monomorphized per use site — no
//!    `Vec`, no dynamic dispatch.
//!
//! 3. **Stratum composition.** A `SingletonCommitment<Stratum<2>>`
//!    over the 2-adic valuation of the κ-label.
//!
//! 4. **Composite admission ⊗ payload.** Combine `TargetCommitment`
//!    with a payload via foundation's `AndCommitment`; show that
//!    `bandwidth_bits()` is additive and `accept_prob()` is
//!    multiplicative.
//!
//! Note: this example does not mine *through* a custom
//! `PrismModel<…, C>` because foundation's `TypedCommitment` is sealed
//! and the model declaration is out of scope for examples. Mining
//! through a composed `C` requires a derived `prism_model!` declaration
//! per wiki ADR-048; the spirit "evaluate composed commitments on the
//! cost-model κ-label" is preserved by acting on the digest directly.
//!
//! Run: `cargo run --release --example optimal_mining`.

use prism_btc::{
    decode_payload, leak_target, mine, payload_commitment_k2, payload_commitment_k4,
    payload_commitment_k8, target_commitment, AndCommitment, Bits, BlockHeader, MerkleRoot,
    SingletonCommitment, Stratum, Target, Timestamp, TypedCommitment, Version,
};

const REGTEST_NBITS: u32 = 0x207fffff;

fn permissive_header(timestamp: u32) -> BlockHeader {
    BlockHeader {
        version: Version(1),
        prev_hash: [0u8; 32],
        merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
        timestamp: Timestamp(timestamp),
        bits: Bits(REGTEST_NBITS),
    }
}

fn mine_one_admitting_block() -> ([u8; 32], u32) {
    let target = Target::new(REGTEST_NBITS);
    for ts in 0u32..512 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        if let Ok(outcome) = mine(&header, target) {
            return (outcome.digest, outcome.nonce);
        }
    }
    panic!("permissive regtest target must admit within 512 template variations");
}

fn main() {
    println!("=== UOR-optimal mining (cost-model conformance per ADR-048/049) ===");
    println!();
    println!("σ-projection: SHA-256d. Admission via TargetCommitment");
    println!("(`SingletonCommitment<LexicographicLessEqThreshold>`).");
    println!("Regtest nBits = 0x{REGTEST_NBITS:08x} (α ≈ 1/2).");
    println!();

    let (digest, nonce) = mine_one_admitting_block();
    println!("── §1. Bare admission ──────────────────────────────────");
    println!("  κ-derived nonce      : 0x{nonce:08x}");
    println!("  κ-label digest (hex) : {}", hex32(&digest));
    println!();

    demo_payload_commitments(&digest);
    demo_stratum_commitment(&digest);
    demo_composed_target_and_payload(&digest);

    println!();
    println!("Every commitment above is a foundation-sealed `TypedCommitment`,");
    println!("monomorphized per use site. No Vec, no dynamic dispatch.");
}

fn print_payload_row<C: TypedCommitment>(k: usize, cmt: &C, digest: &[u8; 32], rt: bool) {
    println!(
        "  {k}   {:>5.2} bits   {:>10.6}    {:>5}      {:>5}",
        cmt.bandwidth_bits(),
        cmt.accept_prob(),
        cmt.evaluate(digest),
        rt,
    );
}

fn demo_payload_commitments(digest: &[u8; 32]) {
    println!("── §2. K-fold AffineParity payload composition ─────────");
    println!();
    println!("Decode K=2/4/8 payload bits off the digest's low bit positions");
    println!("(AffineParity convention: bit_idx/8 is byte index, bit_idx%8 is bit position),");
    println!("build the matching SingletonCommitment-tree, and check `evaluate` agrees.");
    println!();
    println!("  K   bandwidth    accept_prob    evaluate   decode_payload matches");
    println!("  --  ---------    -----------    --------   ----------------------");

    let b2 = decode_payload::<2>(digest);
    print_payload_row(
        2,
        &payload_commitment_k2(b2),
        digest,
        decode_payload::<2>(digest) == b2,
    );
    let b4 = decode_payload::<4>(digest);
    print_payload_row(
        4,
        &payload_commitment_k4(b4),
        digest,
        decode_payload::<4>(digest) == b4,
    );
    let b8 = decode_payload::<8>(digest);
    print_payload_row(
        8,
        &payload_commitment_k8(b8),
        digest,
        decode_payload::<8>(digest) == b8,
    );

    println!();
    println!("Bandwidth is additive over the AndCommitment tree;");
    println!("accept_prob is multiplicative (per ADR-048 + U2 axiom).");
}

fn demo_stratum_commitment(digest: &[u8; 32]) {
    println!();
    println!("── §3. Stratum<2> single-observable commitment ─────────");
    println!();
    // Pick k = the 2-adic valuation actually observed on this digest, so
    // the predicate accepts; show the type-level shape regardless.
    let k = prism_btc::p_adic_valuation(digest, 2).min(31);
    let cmt = SingletonCommitment {
        predicate: Stratum::<2> { k },
    };
    println!("  Stratum<P=2> {{ k = {k} }}  (ν_2(κ-label) over the BE-integer view)");
    println!(
        "  bandwidth = {:.3} bits, accept_prob = {:.6}, evaluate = {}",
        cmt.bandwidth_bits(),
        cmt.accept_prob(),
        cmt.evaluate(digest),
    );
}

fn demo_composed_target_and_payload(digest: &[u8; 32]) {
    println!();
    println!("── §4. Composite admission ⊗ payload ───────────────────");
    println!();
    // TargetCommitment against the regtest target — same bytes mine() used.
    let target_static = leak_target(Target::new(REGTEST_NBITS).to_bytes());
    let target_c = target_commitment(target_static);
    let payload = payload_commitment_k4(decode_payload::<4>(digest));
    let composed = AndCommitment {
        left: target_c,
        right: payload,
    };

    let sum_b = target_c.bandwidth_bits() + payload.bandwidth_bits();
    let prod_a = target_c.accept_prob() * payload.accept_prob();
    println!(
        "  AndCommitment<TargetCommitment, PayloadK4>: predicate_count = {}",
        composed.predicate_count(),
    );
    println!(
        "  bandwidth(left)       = {:>7.4} bits",
        target_c.bandwidth_bits()
    );
    println!(
        "  bandwidth(right)      = {:>7.4} bits",
        payload.bandwidth_bits()
    );
    println!(
        "  bandwidth(composed)   = {:>7.4} bits   (= left + right ⇒ {})",
        composed.bandwidth_bits(),
        (composed.bandwidth_bits() - sum_b).abs() < 1e-9,
    );
    println!(
        "  accept_prob(composed) = {:>10.6}      (= left·right ⇒ {})",
        composed.accept_prob(),
        (composed.accept_prob() - prod_a).abs() < 1e-12,
    );
    println!("  evaluate(κ-label)     = {}", composed.evaluate(digest));
}

fn hex32(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
