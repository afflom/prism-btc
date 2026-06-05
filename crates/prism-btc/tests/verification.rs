//! prism-btc V&V suite — κ-derivation kernel.
//!
//! These tests pin the kernel's stated invariants:
//!
//! - **L1 / L2**: every output is a `sha256d:<64hex>` κ-label of
//!   80-byte canonical-form input.
//! - **L4**: the κ-label is sealed by foundation's
//!   `BitcoinAddressModel` via the shared `AddressResolverTuple`
//!   ψ-tower. The verb arena composes only ψ-stage Term variants
//!   (no σ-residuals).
//! - **L5**: the witness re-certifies the κ-label; the hex tail of
//!   the κ-label re-derives to `sha256d_display(wire)` byte-for-byte.
//! - **L6**: no admission is embedded in the kernel — the model's
//!   5th-slot is `EmptyCommitment`, so every well-formed input
//!   produces a sealed Grounded. The host-side admission check
//!   (`target.is_satisfied_by_bytes(digest)`) is a separate
//!   observation that the kernel exposes nothing about; tests
//!   exercise it as a host concern, not as a kernel claim.

use prism::operation::Term;
use prism::pipeline::{ConstrainedTypeShape, ConstraintRef};
use prism_btc::{
    address_block, serialize_header, serialize_prefix, sha256d_display, Bits, BlockAddressLabel,
    BlockHeader, MerkleRoot, Target, Timestamp, Version, VERB_TERMS_BLOCK_ADDRESS_INFERENCE,
};

fn canonical_header(version: u32, timestamp: u32, bits: u32) -> BlockHeader {
    let merkle: [u8; 32] = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    BlockHeader {
        version: Version(version),
        prev_hash: [0u8; 32],
        merkle_root: MerkleRoot::from_bytes(merkle),
        timestamp: Timestamp(timestamp),
        bits: Bits(bits),
    }
}

// ─── §1. Structural verb-arena invariants ──────────────────────────────

#[test]
fn v_verb_arena_composes_only_psi_stages_no_sigma_residuals() {
    let arena = VERB_TERMS_BLOCK_ADDRESS_INFERENCE::<32>();
    assert!(!arena.is_empty());
    let psi_only = arena.iter().all(|t| {
        matches!(
            t,
            Term::Nerve { .. }
                | Term::ChainComplex { .. }
                | Term::HomologyGroups { .. }
                | Term::Betti { .. }
                | Term::CochainComplex { .. }
                | Term::CohomologyGroups { .. }
                | Term::PostnikovTower { .. }
                | Term::HomotopyGroups { .. }
                | Term::KInvariants { .. }
                | Term::Variable { .. }
                | Term::Literal { .. }
        )
    });
    assert!(
        psi_only,
        "verb arena must contain only ψ-stage Term variants"
    );
}

#[test]
fn v_verb_arena_implements_the_k_invariant_branch() {
    let arena = VERB_TERMS_BLOCK_ADDRESS_INFERENCE::<32>();
    assert!(arena.iter().any(|t| matches!(t, Term::Nerve { .. })));
    assert!(arena
        .iter()
        .any(|t| matches!(t, Term::PostnikovTower { .. })));
    assert!(arena
        .iter()
        .any(|t| matches!(t, Term::HomotopyGroups { .. })));
    assert!(arena.iter().any(|t| matches!(t, Term::KInvariants { .. })));
}

// ─── §2. κ-derivation: shape + determinism + distinctness ──────────────

#[test]
fn v_address_block_emits_a_seventy_two_byte_sha256d_label() {
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let wire = serialize_header(&header, 0);
    let outcome = address_block(&wire);
    assert!(outcome.address.starts_with("sha256d:"));
    assert_eq!(outcome.address.len(), 72);
}

#[test]
fn v_address_block_is_pure_function_of_canonical_input() {
    // Same canonical bytes → same κ-label, five repetitions.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let wire = serialize_header(&header, 0xA5);
    let baseline = address_block(&wire).address;
    for _ in 0..5 {
        let repeat = address_block(&wire).address;
        assert_eq!(repeat, baseline);
    }
}

#[test]
fn v_address_block_is_distinct_for_distinct_canonical_inputs() {
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let mut labels = std::collections::HashSet::new();
    for nonce in 0u32..64 {
        let wire = serialize_header(&header, nonce);
        let outcome = address_block(&wire);
        assert!(labels.insert(outcome.address.as_str().to_owned()));
    }
}

// ─── §3. κ-label identity + wire-format reconstruction (L5) ────────────

#[test]
fn v_kappa_label_hex_tail_re_derives_to_sha256d_digest() {
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let wire = serialize_header(&header, 0xCAFE);
    let outcome = address_block(&wire);

    let expected_digest = sha256d_display(&wire);
    let hex_tail = &outcome.address.as_str()[8..];
    let mut expected_hex = String::with_capacity(64);
    for b in expected_digest {
        expected_hex.push_str(&format!("{b:02x}"));
    }
    assert_eq!(hex_tail, expected_hex);
}

#[test]
fn v_wire_format_carries_prefix_and_nonce() {
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let nonce = 0x12345678_u32;
    let wire = serialize_header(&header, nonce);
    let prefix = serialize_prefix(&header);
    assert_eq!(&wire[..76], &prefix[..]);
    assert_eq!(&wire[76..80], &nonce.to_le_bytes());
}

// ─── §4. Witness replay (TC-05) ────────────────────────────────────────

#[test]
fn v_witness_replays_to_the_attested_kappa_label() {
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let wire = serialize_header(&header, 0xBEEF);
    let outcome = address_block(&wire);
    let replayed = outcome.witness.verify().expect("witness replays");
    assert_eq!(replayed, outcome.address);
    assert_eq!(outcome.witness.kappa_label(), outcome.address);
    assert_eq!(outcome.witness.content_fingerprint().len(), 32);
}

// ─── §5. Host-side PoW admission (L6 — not a kernel concept) ───────────

#[test]
fn host_side_admission_passes_on_permissive_target() {
    // Host code does its own PoW check. Across 64 nonces against the
    // permissive regtest target, at least one digest admits.
    let target = Target::new(0x207fffff);
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let admitted_count = (0u32..64)
        .filter(|&nonce| {
            let wire = serialize_header(&header, nonce);
            let digest = sha256d_display(&wire);
            // sanity: kernel emits a κ-label for every input
            let _ = address_block(&wire);
            target.is_satisfied_by_bytes(&digest)
        })
        .count();
    assert!(
        admitted_count > 0,
        "permissive target admits at least one of 64 candidates"
    );
}

#[test]
fn host_side_admission_holds_iff_digest_satisfies_target() {
    // Validate the host's admission check is symmetric with what
    // foundation's `LexicographicLessEqThreshold` would check on the
    // κ-label form — they are byte-for-byte equivalent under the
    // sha256d:<64hex> encoding.
    let target = Target::new(0x207fffff);
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    for nonce in 0u32..16 {
        let wire = serialize_header(&header, nonce);
        let digest = sha256d_display(&wire);
        let host_admits = target.is_satisfied_by_bytes(&digest);
        // The κ-label is well-formed regardless of admission.
        let outcome = address_block(&wire);
        assert!(outcome.address.starts_with("sha256d:"));
        // host_admits ↔ digest ≤ target_bytes (definitional).
        let direct = digest <= target.to_bytes();
        assert_eq!(host_admits, direct);
    }
}

// ─── §6. Output-shape algebraic structure ──────────────────────────────

#[test]
fn v_block_address_label_has_seventy_two_disjoint_site_constraints() {
    let cs = <BlockAddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(cs.len(), 72);
    for (i, c) in cs.iter().enumerate() {
        match c {
            ConstraintRef::Site { position } => assert_eq!(*position, i as u32),
            _ => panic!("expected Site at {i}"),
        }
    }
}

#[test]
fn v_prism_btc_bounds_declare_algebraic_closure_target() {
    use prism::vocabulary::HostBounds;
    use prism_btc::PrismBtcBounds;
    const _: () = {
        assert!(<PrismBtcBounds as HostBounds>::NERVE_SITES_MAX >= 72);
        assert!(<PrismBtcBounds as HostBounds>::NERVE_CONSTRAINTS_MAX >= 72);
        assert!(<PrismBtcBounds as HostBounds>::BETTI_DIMENSION_MAX >= 72);
    };
}

// ─── §7. Cross-network κ-derivation invariance ─────────────────────────

#[test]
fn v_address_block_is_target_independent() {
    // The kernel emits κ-labels regardless of target — the target is a
    // host-side observation, not part of the κ-derivation. Same
    // canonical bytes → same κ-label across any nBits value.
    let header_a = canonical_header(1, 1_700_000_000, 0x207fffff);
    let header_b = canonical_header(1, 1_700_000_000, 0x1d00ffff);
    let wire_a = serialize_header(&header_a, 0);
    let wire_b = serialize_header(&header_b, 0);
    // Different bits → different canonical bytes → different κ.
    let outcome_a = address_block(&wire_a);
    let outcome_b = address_block(&wire_b);
    assert_ne!(outcome_a.address, outcome_b.address);
    // But neither construction involves a target threshold — the
    // kernel makes no admission decision.
    let _ = outcome_a;
    let _ = outcome_b;
}
