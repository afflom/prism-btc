//! UOR-optimal mining via prism's zero-cost typed commitment surface.
//!
//! Exercises [`prism_btc::mine_with`] across two typed-commitment
//! demonstrations:
//!
//! 1. **K-bit `PayloadCommitment<K>` sweep** — K ∈ [0, MAX_K] parity
//!    constraints on K disjoint single-bit ω-frequencies. Each
//!    commitment is a separate monomorphization; the K-sweep is a
//!    compile-time macro expansion (no `Vec`, no dynamic dispatch).
//!    Bandwidth = K bits; PRF cost = `α^-1 × 2^K`.
//!
//! 2. **User-defined typed commitment** — a custom `StratumWithParity`
//!    type implementing [`prism_btc::TypedCommitment`] directly. Shows
//!    the extension pattern: applications that need a commitment
//!    shape outside the substrate-provided typed forms implement the
//!    trait themselves. Bandwidth is type-level; no `Vec`.
//!
//! Run: `cargo run --release --example optimal_mining`.
//!
//! Every typed commitment is monomorphized per use site — there is
//! no runtime allocation or dynamic dispatch anywhere in this example.

use std::time::Instant;

use prism_btc::{
    mine_with, walsh_hadamard_parity_at, Bits, BlockHeader, MerkleRoot, PayloadCommitment, Target,
    Timestamp, TriadicCoords, TypedCommitment, Version,
};

/// Regtest nBits — the bare-admission baseline (α ≈ 1/2).
const REGTEST_NBITS: u32 = 0x207fffff;
/// Independent trials per K — averaged for the empirical estimate.
const N_TRIALS: usize = 50;
/// Per-trial cap on template variations.
const MAX_VARIATIONS: u32 = 1_000_000;

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

/// Roll the timestamp until [`mine_with`] returns `Ok`, up to
/// [`MAX_VARIATIONS`]. Monomorphized per `C: TypedCommitment`.
fn find_committed_block<C: TypedCommitment>(trial_seed: u32, commitment: C) -> Option<u32> {
    let target = Target::new(REGTEST_NBITS);
    let base = build_header(trial_seed);
    for variation in 0..MAX_VARIATIONS {
        let mut header = base.clone();
        header.timestamp = Timestamp(base.timestamp.0.wrapping_add(variation));
        if let Ok(outcome) = mine_with(&header, target, commitment) {
            assert!(target.is_satisfied_by_bytes(&outcome.digest));
            assert!(commitment.evaluate(&outcome.digest));
            return Some(variation + 1);
        }
    }
    None
}

/// Run one row of the K-sweep at compile-time-known `K`. Monomorphized
/// per K; the loop bound `K` is part of the type, not runtime data.
fn sweep_row<const K: usize>() -> (f64, f64, f64) {
    let bits = [true; K];
    let commitment = PayloadCommitment::<K>::from_bits(bits);
    let bandwidth = commitment.bandwidth_bits();
    let pred = 2.0_f64.powf(bandwidth + 1.0); // baseline 2 × 2^K at α ≈ 1/2

    let mut variations = [0.0_f64; N_TRIALS];
    for (trial, slot) in variations.iter_mut().enumerate() {
        match find_committed_block::<PayloadCommitment<K>>(trial as u32, commitment) {
            Some(v) => *slot = v as f64,
            None => panic!("Failed at K={K}, trial={trial}"),
        }
    }
    let mean: f64 = variations.iter().sum::<f64>() / (N_TRIALS as f64);
    (bandwidth, pred, mean)
}

fn main() {
    println!("=== UOR-optimal mining: zero-cost typed commitment ===");
    println!();
    println!(
        "σ-projection: SHA-256d. Admission: regtest target 0x{:08x} (α ≈ 1/2).",
        REGTEST_NBITS
    );
    println!("PRF prediction (U6, tight): variations = α^-1 × 2^B");
    println!("where B = commitment.bandwidth_bits(). Every commitment below");
    println!("is monomorphized — no Vec, no dynamic dispatch.");
    println!();

    sweep_payload();
    demo_user_defined_typed_commitment();

    println!();
    println!("Each mined block is a wire-format-valid Bitcoin κ-label that ALSO");
    println!("commits to B bits of application-declared structural information.");
    println!("Bitcoin Core sees a normal block; an application-layer verifier");
    println!("reads the typed predicates off the published digest.");
}

fn sweep_payload() {
    println!("── §1. PayloadCommitment<K> sweep (zero-cost) ──────────");
    println!();
    println!("K-bit payload as K disjoint single-bit parities. Each K is a");
    println!("separate monomorphization; the table below is compile-time");
    println!("expanded via macro.");
    println!();
    println!("  K   bandwidth      PRF pred       observed       ratio");
    println!("  --  ----------     ----------     ----------     -------");

    let started = Instant::now();

    // Compile-time macro expansion of the K-sweep. Each row is a
    // distinct monomorphization of `sweep_row::<K>()` — no runtime
    // dispatch on K.
    macro_rules! sweep {
        ($($k:literal),*) => {
            $({
                let (bandwidth, pred, mean) = sweep_row::<$k>();
                let bandwidth_display = if bandwidth == 0.0 { 0.0_f64 } else { bandwidth };
                println!(
                    "  {:2}  {:>4.1} bits      {:>10.0}     {:>10.1}     {:>4.2}x",
                    $k,
                    bandwidth_display,
                    pred,
                    mean,
                    mean / pred,
                );
            })*
        };
    }
    sweep!(0, 1, 2, 3, 4, 5, 6);

    println!();
    println!(
        "Payload sweep wall-clock: {:.2}s",
        started.elapsed().as_secs_f64()
    );
}

/// **§2 user-defined typed commitment.** A custom `TypedCommitment`
/// composing a 1-bit parity (at a high-byte ω) and a stratum-equality
/// constraint (at the low bytes). The two predicates have disjoint
/// algebraic supports by *type-level* construction — the parity reads
/// byte 8, the stratum reads byte 31's low bits — so `wellFormed` is
/// discharged at the type level (the Lean theorem's hypothesis is
/// dispatched by the user-side type invariant, not by a runtime
/// check). Bandwidth = 1 + (k + 1) = `k + 2` bits.
#[derive(Debug, Clone, Copy)]
struct StratumWithParity<const K: u32> {
    parity_omega_byte8: u8, // single bit set in byte 8 — disjoint from byte-31 low bits
    parity_expected: u32,
}

impl<const K: u32> TypedCommitment for StratumWithParity<K> {
    fn bandwidth_bits(&self) -> f64 {
        1.0 + (K as f64 + 1.0)
    }

    fn accept_prob(&self) -> f64 {
        0.5_f64 * (2.0_f64).powi(-(K as i32 + 1))
    }

    fn evaluate(&self, digest: &[u8; 32]) -> bool {
        // Parity at byte-8 single bit.
        let mut omega = [0u8; 32];
        omega[8] = self.parity_omega_byte8;
        if walsh_hadamard_parity_at(digest, &omega) != self.parity_expected {
            return false;
        }
        // StratumEq{K} = digest's 2-adic valuation equals K.
        TriadicCoords::from_hash(digest).stratum == K
    }

    fn predicate_count(&self) -> usize {
        2
    }
}

fn demo_user_defined_typed_commitment() {
    println!();
    println!("── §2. User-defined typed commitment ───────────────────");
    println!();
    println!("Applications outside the substrate-provided typed forms");
    println!("implement `TypedCommitment` directly. `wellFormed` is the");
    println!("implementor's invariant (typically at the type level) —");
    println!("no runtime disjointness check, zero allocation.");
    println!();

    // K = 2 stratum: bit 2 of byte 31 set, bits 0..1 = 0 → 3 bits.
    let commitment = StratumWithParity::<2> {
        parity_omega_byte8: 0b0000_0001,
        parity_expected: 1,
    };
    let bandwidth = commitment.bandwidth_bits();
    let pred = 2.0_f64.powf(bandwidth + 1.0);

    println!(
        "  Commitment: StratumWithParity<K=2> ({} predicates, bandwidth = {:.3} bits)",
        commitment.predicate_count(),
        bandwidth
    );
    println!(
        "  PRF prediction: {:.0} variations (= 2 × 2^{:.3})",
        pred, bandwidth
    );
    println!();

    let started = Instant::now();
    let mut variations = [0.0_f64; N_TRIALS];
    for (trial, slot) in variations.iter_mut().enumerate() {
        match find_committed_block::<StratumWithParity<2>>(trial as u32, commitment) {
            Some(v) => *slot = v as f64,
            None => panic!("StratumWithParity trial {trial} failed"),
        }
    }
    let mean: f64 = variations.iter().sum::<f64>() / (N_TRIALS as f64);
    println!(
        "  Observed mean variations: {:.0} (ratio {:.2}x)",
        mean,
        mean / pred,
    );
    println!(
        "  StratumWithParity wall-clock: {:.2}s",
        started.elapsed().as_secs_f64()
    );
}
