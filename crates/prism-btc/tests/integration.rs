//! Integration tests for prism-btc's pure-prism mining inference.
//!
//! See [ARCHITECTURE.md](../../../../ARCHITECTURE.md) for the normative
//! specification. The tests pin the **architectural commitment**:
//!
//! - `BitcoinMiningModel` is a 4-position `PrismModel<HostTypes,
//!   HostBounds, Hasher, ResolverTuple>` (architecture §5).
//! - `BitcoinResolverTuple` realizes the eight resolver-bound ψ-stages
//!   (architecture §3, §4).
//! - `BitcoinMiningModel::forward(task)` drives the ψ-pipeline end-to-end
//!   through foundation 0.4.5's catamorphism dispatching each ψ-Term
//!   through the application's resolver tuple.
//! - The κ-label (`Grounded<MiningResult>::output_bytes()`) is exactly
//!   80 bytes — the wire-format Bitcoin header by construction
//!   (architecture §6 bit-identicality contract).

use prism_btc::{
    mine, BitcoinMiningModel, BitcoinResolverTuple, Bits, BlockHeader, MerkleRoot, MiningTask,
    PrismBtcBounds, Sha256dHasher, Target, Timestamp, Version,
};
use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

fn easy_header() -> BlockHeader {
    let merkle: [u8; 32] = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    BlockHeader {
        version: Version(1),
        prev_hash: [0u8; 32],
        merkle_root: MerkleRoot::from_bytes(merkle),
        timestamp: Timestamp(1700000000),
        bits: Bits(0x207fffff),
    }
}

#[test]
fn forward_emits_an_eighty_byte_wire_format_header() {
    // The terminal ψ_9 resolver emits 80 bytes: the wire-format
    // Bitcoin header (architecture §2.2 + §6).
    let mut prefix = [0u8; 76];
    prefix[0] = 0x01;
    let target = [0xffu8; 32];
    let task = MiningTask::new(prefix, target);

    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .expect("ψ-pipeline must run end-to-end");

    let kappa_label = grounded.output_bytes();
    assert_eq!(
        kappa_label.len(),
        80,
        "κ-label is exactly the wire-format Bitcoin header width"
    );

    // The leading 76 bytes are MiningTask.prefix.
    assert_eq!(&kappa_label[..76], &prefix[..]);
    // The trailing 4 bytes are the resolved nonce (LE).
    let _nonce = u32::from_le_bytes([
        kappa_label[76],
        kappa_label[77],
        kappa_label[78],
        kappa_label[79],
    ]);

    // Witt level pinned through forward().
    assert_eq!(grounded.witt_level_bits(), 32);
}

#[test]
fn forward_kappa_label_is_deterministic_in_the_typed_input() {
    // The ψ-pipeline is parametric: same MiningTask → same κ-label.
    let mut prefix = [0u8; 76];
    prefix[0] = 0x42;
    let target = [0xffu8; 32];
    let task_a = MiningTask::new(prefix, target);
    let task_b = MiningTask::new(prefix, target);

    let grounded_a = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task_a)
    .expect("a");
    let grounded_b = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task_b)
    .expect("b");

    assert_eq!(grounded_a.output_bytes(), grounded_b.output_bytes());
}

#[test]
fn forward_kappa_label_is_distinct_for_distinct_inputs() {
    // The ψ-pipeline distinguishes typed inputs: distinct MiningTask
    // inputs yield distinct κ-labels (in the resolved-nonce field).
    let mut p_a = [0u8; 76];
    p_a[0] = 0x01;
    let mut p_b = [0u8; 76];
    p_b[0] = 0x02;
    let target = [0xffu8; 32];

    let ga = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(MiningTask::new(p_a, target))
    .expect("a");
    let gb = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(MiningTask::new(p_b, target))
    .expect("b");

    let nonce_a = &ga.output_bytes()[76..80];
    let nonce_b = &gb.output_bytes()[76..80];
    assert_ne!(
        nonce_a, nonce_b,
        "distinct typed inputs must yield distinct resolved nonces"
    );
}

#[test]
fn forward_path_identity_is_input_invariant() {
    // The Grounded's content_fingerprint and unit_address come from
    // CompileUnit metadata, not input bytes. Two distinct admitted
    // inputs agree on those substrate bits — they identify the
    // typed-iso path, not bytewise input identity.
    let mut p_a = [0u8; 76];
    p_a[0] = 0x01;
    let mut p_b = [0u8; 76];
    p_b[0] = 0x02;
    let target = [0xffu8; 32];

    let ga = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(MiningTask::new(p_a, target))
    .expect("a");
    let gb = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(MiningTask::new(p_b, target))
    .expect("b");

    assert_eq!(ga.content_fingerprint(), gb.content_fingerprint());
    assert_eq!(ga.unit_address(), gb.unit_address());
    assert_eq!(ga.witt_level_bits(), gb.witt_level_bits());
}

#[test]
fn mine_returns_outcome_with_wire_format_witness() {
    // mine() drives the ψ-pipeline through the host boundary. The
    // witness's `output_bytes` are the wire-format header; the digest
    // is the host-side SHA-256d in display order; the `admits` flag
    // reports whether the κ-label's header satisfies the host-supplied
    // target.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let outcome = mine(&header, target).expect("ψ-pipeline runs end-to-end");

    assert_eq!(
        outcome.witness.output_bytes().len(),
        80,
        "wire-format header is 80 bytes"
    );
    assert_eq!(outcome.coords.datum, outcome.digest);
    // For a permissive target the κ-derived header should admit.
    // (The structural pipeline is deterministic; this asserts the
    // permissive-target invariant of the implementation.)
    assert!(
        outcome.admits,
        "permissive target must admit κ-label header"
    );
}
