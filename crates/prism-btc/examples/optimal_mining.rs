//! Worked example: the **κ-derivation kernel + host-side admission +
//! the generic typed-commitment surface**.
//!
//! The protocol layer (the host) walks candidate nonces, derives each
//! one's κ through [`prism_btc::address_block`], and decides admission
//! by comparing the digest to the target — Bitcoin's `digest ≤ target`,
//! a host-side observation on the κ-label, **not** a kernel operation.
//! On top of bare admission the host can compose foundation's typed
//! commitments (the K-fold AffineParity payloads, the Stratum/
//! LexicographicLessEqThreshold predicates) over the same digest to
//! get richer admission gates — the receiver-side machinery the Lean
//! `prf_prob_tight_wellFormed` theorem applies to.
//!
//! Run: `cargo run --release --example optimal_mining`.

use prism_btc::{
    address_block, decode_payload, payload_commitment_k2, payload_commitment_k4,
    payload_commitment_k8, serialize_header, sha256d_display, AndCommitment, Bits, BlockHeader,
    LexicographicLessEqThreshold, MerkleRoot, SingletonCommitment, Stratum, Target, Timestamp,
    TypedCommitment, Version,
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

/// Protocol-level mining: walk template variations, derive κ for each
/// candidate via [`address_block`], take the first whose digest admits
/// the target. The kernel handles only the κ-derivation; the search
/// and the admission check are this host's concerns.
fn host_side_mining() -> ([u8; 32], u32) {
    let target = Target::new(REGTEST_NBITS);
    for ts in 0u32..512 {
        let header = permissive_header(1_700_000_000_u32.wrapping_add(ts));
        for nonce in 0u32..4096 {
            let wire = serialize_header(&header, nonce);
            let _outcome = address_block(&wire); // κ-derivation through the kernel
            let digest = sha256d_display(&wire);
            if target.is_satisfied_by_bytes(&digest) {
                return (digest, nonce);
            }
        }
    }
    panic!("permissive regtest target must admit within 512×4096 candidates");
}

fn main() {
    println!("=== Host-side PoW + generic typed-commitment composition ===");
    println!();
    println!("σ-projection: SHA-256d (the kernel's κ-derivation surface).");
    println!("Admission: host-side digest ≤ target (NOT a kernel operation).");
    println!("Regtest nBits = 0x{REGTEST_NBITS:08x} (α ≈ 1/2).");
    println!();

    let (digest, nonce) = host_side_mining();
    println!("── §1. Bare host-side admission ────────────────────────");
    println!("  Admitting nonce      : 0x{nonce:08x}");
    println!("  κ-label digest (hex) : {}", hex32(&digest));
    println!();

    demo_payload_commitments(&digest);
    demo_stratum_commitment(&digest);
    demo_composed_threshold_and_payload(&digest);

    println!();
    println!("Every commitment above is a foundation-sealed `TypedCommitment`,");
    println!("composable at the application/host layer over any κ-label.");
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
    println!("  K   bandwidth    accept_prob    evaluate   decode round-trip");

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
}

fn demo_stratum_commitment(digest: &[u8; 32]) {
    println!();
    println!("── §3. Stratum<2> single-observable commitment ─────────");
    let k = prism_btc::p_adic_valuation(digest, 2).min(31);
    let cmt = SingletonCommitment {
        predicate: Stratum::<2> { k },
    };
    println!(
        "  Stratum<P=2> {{ k = {k} }}  bandwidth = {:.3} bits, accept_prob = {:.6}, evaluate = {}",
        cmt.bandwidth_bits(),
        cmt.accept_prob(),
        cmt.evaluate(digest),
    );
}

fn demo_composed_threshold_and_payload(digest: &[u8; 32]) {
    println!();
    println!("── §4. Composite host-side threshold ⊗ payload ─────────");
    // Host builds a threshold commitment from its own static target
    // bytes — no kernel involvement.
    static TARGET_BYTES: [u8; 32] = [0xff; 32];
    let threshold = SingletonCommitment {
        predicate: LexicographicLessEqThreshold {
            target: &TARGET_BYTES,
        },
    };
    let payload = payload_commitment_k4(decode_payload::<4>(digest));
    let composed = AndCommitment {
        left: threshold,
        right: payload,
    };

    let sum_b = threshold.bandwidth_bits() + payload.bandwidth_bits();
    let prod_a = threshold.accept_prob() * payload.accept_prob();
    println!("  AndCommitment<threshold, PayloadK4>");
    println!("  predicate_count       = {}", composed.predicate_count());
    println!(
        "  bandwidth(composed)   = {:.4} bits  (= sum ⇒ {})",
        composed.bandwidth_bits(),
        (composed.bandwidth_bits() - sum_b).abs() < 1e-9
    );
    println!(
        "  accept_prob(composed) = {:.6}      (= product ⇒ {})",
        composed.accept_prob(),
        (composed.accept_prob() - prod_a).abs() < 1e-12
    );
    println!("  evaluate(digest)      = {}", composed.evaluate(digest));
}

fn hex32(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
