//! Integration tests for prism-btc's UOR-ADDR block-address kernel.
//!
//! End-to-end coverage of the κ-derivation kernel + the composition
//! framework (compose_*, merkle_root) + host-side PoW observation.

use prism_btc::{
    address_block, block_label_from_digest, compose_g2_product, compose_ordered_product,
    merkle_root, serialize_header, serialize_prefix, sha256d_display, Bits, BlockHeader,
    KappaObservables, MerkleRoot, Target, Timestamp, Version,
};

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
fn end_to_end_address_derivation_and_witness_replay() {
    let wire = serialize_header(&easy_header(), 0);
    let outcome = address_block(&wire);
    assert!(outcome.address.starts_with("sha256d:"));
    assert_eq!(outcome.address.len(), 72);
    let replayed = outcome.witness.verify().expect("witness replays");
    assert_eq!(replayed, outcome.address);
}

#[test]
fn host_side_admission_finds_a_witness_for_permissive_target() {
    // The protocol layer's mining loop, in miniature. The kernel emits
    // κ-labels; the host checks digest ≤ target.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    let admitted = (0u32..1024).find_map(|nonce| {
        let wire = serialize_header(&header, nonce);
        let digest = sha256d_display(&wire);
        if target.is_satisfied_by_bytes(&digest) {
            let outcome = address_block(&wire);
            Some((nonce, outcome, digest))
        } else {
            None
        }
    });
    let (nonce, outcome, digest) = admitted.expect("permissive target admits within 1024");

    // Fail-closed at the host layer: the admitted digest genuinely
    // satisfies the target.
    assert!(target.is_satisfied_by_bytes(&digest));
    // The wire format reconstructs to the same bytes the kernel saw.
    let prefix = serialize_prefix(&header);
    let mut expected_wire = [0u8; 80];
    expected_wire[..76].copy_from_slice(&prefix);
    expected_wire[76..].copy_from_slice(&nonce.to_le_bytes());
    let actual_wire = serialize_header(&header, nonce);
    assert_eq!(expected_wire, actual_wire);
    // The witness re-certifies the κ-label.
    let replayed = outcome.witness.verify().expect("replays");
    assert_eq!(replayed, outcome.address);
}

#[test]
fn observables_are_a_pure_projection_of_the_digest() {
    let header = easy_header();
    let wire = serialize_header(&header, 0xABCDEF);
    let digest = sha256d_display(&wire);
    let observables = KappaObservables::from_digest(&digest);
    assert_eq!(observables.coords.datum, digest);
    // Deterministic on the digest.
    let again = KappaObservables::from_digest(&digest);
    assert_eq!(observables, again);
}

// ─── Composition surface ───────────────────────────────────────────────

#[test]
fn composition_g2_is_commutative() {
    let a = block_label_from_digest(&[0x11; 32]);
    let b = block_label_from_digest(&[0x22; 32]);
    let ab = compose_g2_product(&a, &b).expect("g2");
    let ba = compose_g2_product(&b, &a).expect("g2");
    assert_eq!(ab.address, ba.address);
}

#[test]
fn composition_ordered_product_is_not_commutative() {
    let a = block_label_from_digest(&[0x11; 32]);
    let b = block_label_from_digest(&[0x22; 32]);
    let ab = compose_ordered_product(&a, &b).expect("ordered");
    let ba = compose_ordered_product(&b, &a).expect("ordered");
    assert_ne!(ab.address, ba.address);
}

#[test]
fn merkle_root_recurrence_matches_bitcoin_discipline_for_three_leaves() {
    let a = block_label_from_digest(&[0x01; 32]);
    let b = block_label_from_digest(&[0x02; 32]);
    let c = block_label_from_digest(&[0x03; 32]);
    let root = merkle_root(&[a, b, c]).expect("merkle");
    // Bitcoin's odd-tail discipline: level 1 = [pair(a,b), pair(c,c)];
    // level 2 = pair(pair(a,b), pair(c,c)).
    let n12 = compose_ordered_product(&a, &b).unwrap().address;
    let n33 = compose_ordered_product(&c, &c).unwrap().address;
    let expected = compose_ordered_product(&n12, &n33).unwrap().address;
    assert_eq!(root, expected);
}
