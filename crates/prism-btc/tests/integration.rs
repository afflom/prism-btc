//! Integration tests for prism-btc's UOR-ADDR block-address inference.
//!
//! prism-btc is a UOR-ADDR realization (ADR-060). The host serializes a
//! [`BlockHeader`] + candidate nonce to the 80-byte wire form
//! ([`serialize_header`]) — the canonical form — and wraps it in a
//! [`BlockHeaderCarrier`]. [`BitcoinAddressModel::forward`] runs the
//! shared ψ-tower: ψ₁–ψ₈ thread the borrowed carrier through and ψ₉ folds
//! it through the `sha256d` σ-axis to mint the `sha256d:<64hex>` κ-label
//! (the block hash in display order). Foundation's `run_route` evaluates
//! the model's pinned `C = TargetCommitment` on the κ-label; admission
//! `kappa_label ≤ target_label` is Bitcoin's PoW relation.
//!
//! These tests pin the surface API: the κ-label shape, determinism,
//! distinctness, and the fail-closed admission contract through
//! [`mine_at`] — the kernel's sole admission-recognition entry. Host
//! iteration over the nonce space is **bridge-layer**, inlined here as
//! `admit_by_nonce_scan` to drive admitted outcomes against a real
//! target.

use prism::pipeline::PrismModel;
use prism_btc::{
    admit, mine_at, recognize_under_bytes, serialize_prefix, uor_addr::AddressOutcome,
    BitcoinAddressModel, Bits, BlockHeader, BlockHeaderCarrier, MerkleRoot, MiningFailure,
    MiningOutcome, Target, Timestamp, Version,
};

/// Permissive target: ~50% admission. Used for tests that exercise the
/// ψ-pipeline shape rather than a restrictive admission relation.
const PERMISSIVE_TARGET_BYTES: [u8; 32] = [0xffu8; 32];

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

/// Recognize one `(header, nonce)` candidate under a permissive
/// target — the only public way to drive `BitcoinAddressModel::forward`
/// directly is via [`recognize_under_bytes`] (the model's pinned
/// `C = TargetCommitment` reads the target the scope publishes — ADR-048).
/// Returns the κ-label string.
fn forward_kappa_label(header: &BlockHeader, nonce: u32) -> String {
    recognize_under_bytes(PERMISSIVE_TARGET_BYTES, || {
        let wire = prism_btc::serialize_header(header, nonce);
        let carrier = BlockHeaderCarrier::new(&wire);
        let grounded =
            BitcoinAddressModel::forward(carrier).expect("ψ-pipeline runs on permissive target");
        let outcome = AddressOutcome::<72, 32>::from_grounded(&grounded)
            .expect("outcome extracts from the sealed Grounded");
        outcome.address.as_str().to_owned()
    })
}

/// V&V helper: the admission closure as a panic-on-exhaustion call.
fn admit_by_nonce_scan(header: &BlockHeader, target: Target) -> MiningOutcome {
    admit(header, target).expect("permissive target should admit within the orbit")
}

#[test]
fn forward_emits_a_seventy_two_byte_sha256d_kappa_label() {
    // ψ₉ folds the carrier through the `sha256d` σ-axis and emits the
    // 72-byte `sha256d:<64hex>` κ-label — the conventional Bitcoin block
    // hash in display order. Foundation evaluates the TargetCommitment on
    // this κ-label byte sequence.
    let header = easy_header();
    let label = forward_kappa_label(&header, 0);
    assert!(
        label.starts_with("sha256d:"),
        "κ-label is the sha256d address"
    );
    assert_eq!(label.len(), 72, "sha256d:<64hex> = 7 + 1 + 64 = 72 bytes");
}

#[test]
fn forward_kappa_label_is_deterministic_in_the_typed_input() {
    // The ψ-pipeline is parametric: same (header, nonce) → same κ-label.
    let header = easy_header();
    let a = forward_kappa_label(&header, 0x42);
    let b = forward_kappa_label(&header, 0x42);
    assert_eq!(a, b, "ψ-pipeline must be deterministic");
}

#[test]
fn forward_kappa_label_is_distinct_for_distinct_inputs() {
    // Distinct typed inputs (distinct nonces) yield distinct κ-labels —
    // the σ-axis is collision-resistant, so distinct headers content-
    // address to distinct sha256d block hashes.
    let header = easy_header();
    let a = forward_kappa_label(&header, 0x01);
    let b = forward_kappa_label(&header, 0x02);
    assert_ne!(a, b, "distinct typed inputs must yield distinct κ-labels");
}

#[test]
fn admit_by_nonce_scan_lands_a_witness_against_permissive_target() {
    // The bridge-layer scan walks the nonce space invoking the kernel's
    // single-recognition mine_at. For the permissive target (regtest's
    // 0x207fffff, ~50% admission per κ-derivation) the first admitting
    // nonce arrives almost immediately. Fail-closed: the kernel returns
    // Ok only when the digest genuinely satisfies the target (admission
    // was evaluated inside foundation's run_route via the pinned
    // TargetCommitment).
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let outcome = admit_by_nonce_scan(&header, target);

    assert!(target.is_satisfied_by_bytes(&outcome.digest()));
    assert!(outcome.address().starts_with("sha256d:"));
    assert_eq!(outcome.address().len(), 72);
    assert_eq!(outcome.wire_format_header.len(), 80);
    // The replayable witness re-certifies to the same κ-label (TC-05).
    assert_eq!(
        outcome.witness.verify().expect("replays"),
        outcome.address()
    );
    // The receiver-side lens projects the block hash's UOR coordinates.
    assert_eq!(outcome.observables().coords.datum, outcome.digest());
}

#[test]
fn mine_at_re_recognizes_the_winning_nonce() {
    // A single recognition at one nonce against the permissive target,
    // re-running the bridge's winning nonce — re-derivation (L5) must
    // produce a byte-identical κ-label and digest.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let scanned = admit_by_nonce_scan(&header, target);
    let pinned =
        mine_at(&header, target, scanned.nonce()).expect("mine_at re-recognizes the winning nonce");
    assert_eq!(pinned.address().as_str(), scanned.address().as_str());
    assert_eq!(pinned.digest(), scanned.digest());
}

#[test]
fn mine_at_did_not_admit_is_typed_for_restrictive_target() {
    // A restrictive mainnet-style target rejects nonce 0 for this
    // template; DidNotAdmit carries the total receiver-side lens.
    let header = easy_header();
    let target = Target::new(0x1d00ffff);
    let failure = mine_at(&header, target, 0).expect_err("restrictive target rejects nonce 0");
    assert!(matches!(failure, MiningFailure::DidNotAdmit { .. }));
    let nonce = failure.nonce().expect("DidNotAdmit carries a nonce");
    let digest = failure.digest().expect("DidNotAdmit carries a digest");
    let observables = failure
        .observables()
        .expect("DidNotAdmit carries observables");
    assert_eq!(nonce, 0);
    assert!(!target.is_satisfied_by_bytes(&digest));
    assert_eq!(observables.coords.datum, digest);
}

#[test]
fn wire_format_header_carries_prefix_and_nonce() {
    // The 80-byte wire-format header the outcome carries is exactly
    // serialize_prefix(header) ‖ nonce.to_le_bytes() — the bytes
    // `submitblock` accepts.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let outcome = admit_by_nonce_scan(&header, target);
    let prefix = serialize_prefix(&header);
    assert_eq!(
        &outcome.wire_format_header[..76],
        &prefix[..],
        "leading 76 bytes are the host-supplied template prefix"
    );
    assert_eq!(
        &outcome.wire_format_header[76..80],
        &outcome.nonce().to_le_bytes(),
        "trailing 4 bytes are the winning nonce (canonical LE)"
    );
}
