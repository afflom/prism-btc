//! Micro-benchmarks for prism-btc.
//!
//! **Performance model** (architecture §14). prism-btc's performance
//! is the per-`forward()` ψ-pipeline overhead — catamorphism dispatch,
//! resolver-chain carrier I/O, ψ_9 setup — NOT the hashrate of the
//! canonical hash axis. These benches are organized to make that
//! distinction visible:
//!
//! - **`psi_pipeline_structural_overhead`**: bench `forward()` under
//!   the maximally-permissive target `0xff…ff` so ψ_9 admits on
//!   `nonce = 0` after exactly one σ-projection. The wall-clock here
//!   is ψ-pipeline overhead (4-stage catamorphism + carrier I/O) plus
//!   one SHA-256d. This is what prism-btc optimizes.
//!
//! - **`canonical_hash_axis_cost`**: bench one `Sha256dHasher` σ-
//!   projection on the wire-format header in isolation. This is
//!   pure hashrate territory — prism-btc *does not* optimize it
//!   (architecture §12 + §14.2); the bench exists so the
//!   structural-overhead number above can be honestly separated
//!   from the hash cost.
//!
//! - **`target_check_reject`**: lex-≤ on a 32-byte non-satisfying
//!   digest vs target. Trivially fast; included for completeness.
//!
//! - **`triadic_coords_from_hash`**: cost of the digest-domain
//!   `TriadicCoords` projection that lives on `MiningOutcome`.
//!
//! Performance work that prism-btc explicitly **does not** undertake:
//! SHA-256 midstate optimization, SIMD vectorization of the W32
//! candidate sweep, GPU offload — every such "improvement" reduces to
//! a hashrate gain on the canonical hash axis, which the architecture
//! puts out of scope.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use prism_btc::{
    mine, sha256d_display, Bits, BlockHeader, MerkleRoot, Target, Timestamp, TriadicCoords, Version,
};

fn permissive_header() -> BlockHeader {
    // Regtest's most permissive nBits — ψ_9 admits on nonce = 0 after
    // exactly one σ-projection, so wall-clock = ψ-pipeline overhead +
    // one SHA-256d call.
    let merkle_bytes: [u8; 32] = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    BlockHeader {
        version: Version(1),
        prev_hash: [0u8; 32],
        merkle_root: MerkleRoot::from_bytes(merkle_bytes),
        timestamp: Timestamp(1_700_000_000),
        bits: Bits(0x207fffff),
    }
}

fn bench_psi_pipeline_structural_overhead(c: &mut Criterion) {
    // The canonical "prism-btc performance" bench: one structural
    // inference per MiningTask, with the W32 loop short-circuiting on
    // the first candidate. Includes the catamorphism dispatch through
    // BitcoinResolverTuple (ψ_1 Nerve → ψ_7 Postnikov → ψ_8 HomotopyGroups
    // → ψ_9 KInvariants), the three structural carriers, ψ_9's
    // iterative-resolution setup, and one canonical-hash-axis call.
    let header = permissive_header();
    let target = Target::new(0x207fffff);
    let mut g = c.benchmark_group("psi_pipeline");
    g.throughput(Throughput::Elements(1));
    g.bench_function("structural_overhead", |b| {
        b.iter(|| {
            let outcome = mine(black_box(&header), black_box(target));
            black_box(outcome.ok());
        })
    });
    g.finish();
}

fn bench_canonical_hash_axis_cost(c: &mut Criterion) {
    // Pure σ-projection cost on a wire-format header. NOT a prism-btc
    // optimization target (architecture §12 + §15); bench exists so
    // the structural-overhead number above is interpretable.
    let mut header = [0u8; 80];
    header[0] = 0x01;
    let mut g = c.benchmark_group("canonical_hash_axis");
    g.throughput(Throughput::Bytes(80));
    g.bench_function("sha256d_one_header", |b| {
        b.iter(|| {
            black_box(sha256d_display(black_box(&header)));
        })
    });
    g.finish();
}

fn bench_target_check(c: &mut Criterion) {
    let target = Target::new(Target::GENESIS_NBITS);
    let non_satisfying: [u8; 32] = [
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut g = c.benchmark_group("misc");
    g.throughput(Throughput::Elements(1));
    g.bench_function("target_check_reject", |b| {
        b.iter(|| target.is_satisfied_by_bytes(black_box(&non_satisfying)))
    });
    g.finish();
}

fn bench_triadic_coords(c: &mut Criterion) {
    let genesis_hash: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e,
        0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c,
        0xe2, 0x6f,
    ];
    let mut g = c.benchmark_group("misc");
    g.throughput(Throughput::Elements(1));
    g.bench_function("triadic_coords_from_hash", |b| {
        b.iter(|| TriadicCoords::from_hash(black_box(&genesis_hash)))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_psi_pipeline_structural_overhead,
    bench_canonical_hash_axis_cost,
    bench_target_check,
    bench_triadic_coords,
);
criterion_main!(benches);
