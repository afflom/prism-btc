//! Integration tests for `prism_btc::mine` — the foundation-driven
//! mining inference per ADR-034 Mechanism 2.

use prism_btc::{
    block_hash_grounded, mine, serialize_header, sha256d_display, BitcoinMiningModel, Bits,
    BlockHeader, MerkleRoot, MiningTask, PrismBtcBounds, Sha256dHasher, Target, Timestamp, Version,
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
fn mine_admits_against_an_easy_target_via_foundation_evaluator() {
    let header = easy_header();
    // 0x207fffff: very easy target. Foundation's Term::FirstAdmit
    // evaluator iterates ascending and short-circuits on the first
    // admitting nonce.
    let target = Target::new(0x207fffff);
    let outcome = mine(&header, target).expect("easy target must admit");
    assert!(target.is_satisfied_by_bytes(&outcome.digest));
    assert_eq!(outcome.coords.datum, outcome.digest);
}

#[test]
fn block_hash_grounded_carries_w32_level() {
    let grounded = block_hash_grounded();
    assert_eq!(grounded.witt_level_bits(), 32);
    assert_ne!(grounded.unit_address().as_u128(), 0);
}

#[test]
fn mine_outcome_digest_matches_sha256d_hasher_body() {
    // The mining outcome's `digest` is derived host-side via
    // `sha256d_display(serialize_header(header, nonce))`. The same
    // `Sha256dHasher` body is what foundation's catamorphism invokes
    // inside `Term::AxisInvocation` per fiber visit, so the runtime
    // helper agrees bit-for-bit with the typed-iso evaluator's
    // hashing path.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let outcome = mine(&header, target).expect("easy target must admit");

    let header_bytes = serialize_header(&header, outcome.nonce);
    let runtime_digest = sha256d_display(&header_bytes);
    assert_eq!(outcome.digest, runtime_digest);
}

#[test]
fn forward_returns_admitted_coproduct() {
    // BitcoinMiningModel::forward is the foundation typed-iso surface;
    // the Grounded's `output_bytes` carries the FirstAdmit coproduct.
    let mut prefix = [0u8; 76];
    prefix[0] = 0x01; // version=1
    let target = [0xffu8; 32]; // permissive — admits at idx=0
    let task = MiningTask::new(prefix, target);

    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
    >>::forward(task)
    .expect("forward succeeds");

    assert_eq!(grounded.witt_level_bits(), 32);
    let bytes = grounded.output_bytes();
    // 1-byte disc + 5-byte BE idx for W32 (CYCLE_SIZE = 2^32 needs 5 bytes).
    assert_eq!(bytes.len(), 6);
    assert_eq!(bytes[0], 0x01, "discriminant: admitted");
    assert_eq!(
        &bytes[1..6],
        &[0u8, 0, 0, 0, 0],
        "first-admitting nonce is 0 for permissive target"
    );
}

#[test]
fn forward_grounded_path_identity_is_input_invariant() {
    // The Grounded's content_fingerprint and unit_address come from
    // CompileUnit metadata, not input bytes (foundation
    // `fold_unit_digest`). Two distinct admitted inputs therefore
    // agree on those substrate bits — they identify the typed-iso
    // **path**, not bytewise input identity.
    let header_a = easy_header();
    let mut header_b = easy_header();
    header_b.timestamp = Timestamp(header_a.timestamp.0 + 1);

    let target = Target::new(0x207fffff);
    let oa = mine(&header_a, target).expect("a admits");
    let ob = mine(&header_b, target).expect("b admits");

    assert_eq!(
        oa.witness.content_fingerprint(),
        ob.witness.content_fingerprint()
    );
    assert_eq!(oa.witness.unit_address(), ob.witness.unit_address());
    assert_eq!(oa.witness.witt_level_bits(), ob.witness.witt_level_bits());
}

#[test]
fn forward_grounded_output_bytes_carries_admitted_nonce() {
    // ADR-028: the Grounded's `output_bytes` carries the
    // catamorphism's evaluation result — for our route, the
    // `Term::FirstAdmit` coproduct `(disc=0x01, nonce_bytes)`. The
    // nonce extracted from the coproduct must match the
    // `MiningOutcome::nonce` the public API returns.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let outcome = mine(&header, target).expect("admits");

    let bytes = outcome.witness.output_bytes();
    assert_eq!(bytes.len(), 6);
    assert_eq!(bytes[0], 0x01);
    // bytes[1] is BE pad; bytes[2..6] is the canonical 4-byte u32 nonce.
    let nonce_from_bytes = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    assert_eq!(nonce_from_bytes, outcome.nonce);
}
