//! prism-btc Verification & Validation suite.
//!
//! These tests pin the architectural invariants the UOR-ADDR realization
//! commits to. They verify the **load-bearing structural properties**:
//!
//! - **ψ-pipeline structural form** — the verb arena composes only
//!   ψ-stage Term variants (no σ-residuals; substrate-enforced at
//!   compile time but pinned here for defense-in-depth).
//! - **Fail-closed mining contract** — `mine_at` only returns an
//!   admitting `MiningOutcome`; the κ-label's display-order digest
//!   actually satisfies the host-supplied target — admission is
//!   evaluated inside foundation's `run_route` via the model's
//!   `C = TargetCommitment` pin (wiki ADR-048).
//! - **Determinism + parametricity** — the ψ-pipeline is a pure
//!   deterministic function of the typed input.
//! - **κ-label identity** — the κ-label IS the `sha256d:<64hex>` address:
//!   the SHA-256d digest of the wire-format Bitcoin header in display
//!   order. `MiningOutcome.wire_format_header` carries the 80-byte header
//!   (prefix ‖ nonce) for `submitblock` compatibility.
//! - **Cross-network invariance** — the same `BitcoinAddressModel` and
//!   shared ψ-tower apply across regtest, signet, testnet, testnet4,
//!   mainnet; only the target byte threshold varies.
//! - **Output-shape algebraic structure** — `BlockAddressLabel` declares
//!   72 disjoint `Site` constraints (χ(N(C)) = 72, β_k = 0 for k ≥ 1).

use prism::operation::Term;
use prism::pipeline::{ConstrainedTypeShape, ConstraintRef, PrismModel};
use prism_btc::{
    mine_at, recognize_under_bytes, serialize_header, serialize_prefix, sha256d_display,
    uor_addr::AddressOutcome, BitcoinAddressModel, Bits, BlockAddressLabel, BlockHeader,
    BlockHeaderCarrier, MerkleRoot, MiningFailure, MiningOutcome, Target, Timestamp, Version,
    VERB_TERMS_BLOCK_ADDRESS_INFERENCE,
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

/// Recognize `(header, nonce)` under a permissive target (`[0xff;
/// 32]`) — admission holds for every κ-label — and return the κ-label
/// string. V&V tests use this to inspect the ψ-pipeline's *structural*
/// properties without an admission relation.
fn forward_kappa_label(header: &BlockHeader, nonce: u32) -> String {
    recognize_under_bytes([0xffu8; 32], || {
        let wire = serialize_header(header, nonce);
        let carrier = BlockHeaderCarrier::new(&wire);
        let grounded = BitcoinAddressModel::forward(carrier)
            .expect("ψ-pipeline must run on permissive target");
        let outcome = AddressOutcome::<72, 32>::from_grounded(&grounded)
            .expect("outcome extracts from the sealed Grounded");
        outcome.address.as_str().to_owned()
    })
}

/// Host-side admission stream — walks the nonce space invoking the
/// kernel's single-recognition `mine_at` until it admits. The kernel
/// never owns this iteration; the bridge does. Inlined here so V&V can
/// exercise admitted outcomes against a real target.
fn admit_by_nonce_scan(header: &BlockHeader, target: Target) -> MiningOutcome {
    for nonce in 0u32..u32::MAX {
        match mine_at(header, target, nonce) {
            Ok(outcome) => return outcome,
            Err(MiningFailure::DidNotAdmit { .. }) => continue,
            Err(MiningFailure::PipelineFailure) => {
                panic!("ψ-pipeline shape violation for canonical_header — unreachable")
            }
        }
    }
    panic!("permissive target should admit within the nonce space")
}

// ─── §1. Structural verb-arena invariants ──────────────────────────────

#[test]
fn v_verb_arena_composes_only_psi_stages_no_sigma_residuals() {
    // Pure-prism commitment (substrate-enforced ψ-residuals discipline).
    // The verb arena must contain only ψ-stage Term variants — no
    // FirstAdmit, no AxisInvocation, no byte-comparison / concat operators.
    let arena = VERB_TERMS_BLOCK_ADDRESS_INFERENCE::<32>();
    assert!(!arena.is_empty(), "verb arena is non-empty");

    let psi_terms_only = arena.iter().all(|t| {
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
        psi_terms_only,
        "verb arena must contain only ψ-stage Term variants (+ Variable/Literal scaffolding); \
         any other variant is a σ-residual leak"
    );
}

#[test]
fn v_verb_arena_implements_the_k_invariant_branch() {
    // prism-btc selects the k-invariant branch
    // (k_invariants ∘ homotopy_groups ∘ postnikov_tower ∘ nerve) as the
    // canonical address transform. The arena must contain these ψ-Terms.
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

// ─── §2. Fail-closed mining contract ───────────────────────────────────

#[test]
fn v_mine_admits_for_permissive_target() {
    // Fail-closed invariant: mine_at returns Ok only when the κ-label's
    // display-order digest satisfies the target (evaluated inside
    // foundation's run_route via the pinned TargetCommitment).
    // Cryptographic re-derivation: recompute SHA-256d from the wire-format
    // header and verify it matches the reported digest AND satisfies the
    // target.
    let target = Target::new(0x207fffff);
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let admitted = admit_by_nonce_scan(&header, target);

    // The κ-label IS the sha256d:<64hex> address; the hex is the display-
    // order block hash. Re-derive from the reconstructed wire-format header.
    assert!(admitted.address().starts_with("sha256d:"));
    assert_eq!(admitted.address().len(), 72);
    let re_derived = sha256d_display(&admitted.wire_format_header);
    assert_eq!(
        admitted.digest(),
        re_derived,
        "outcome.digest() must equal SHA-256d(wire_format_header) in display order"
    );
    assert!(
        target.is_satisfied_by_bytes(&re_derived),
        "fail-closed: an admitted outcome's digest MUST actually satisfy the target"
    );
}

#[test]
fn v_mine_outcome_digest_actually_satisfies_target_when_admitted() {
    // Fail-closed across the input space: for every (header, target) pair
    // where mine_at returns Ok, the digest genuinely satisfies the target.
    let target = Target::new(0x207fffff);
    let mut admitted_count = 0;
    for ts_offset in 0u32..64 {
        let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
        // Recognize the first admitting nonce for this header (the
        // bridge-layer scan, inlined). If admission lands, fail-closed
        // requires the recognized digest actually satisfies the
        // target.
        let mut admitted = None;
        for nonce in 0u32..1_000 {
            if let Ok(outcome) = mine_at(&header, target, nonce) {
                admitted = Some(outcome);
                break;
            }
        }
        if let Some(outcome) = admitted {
            admitted_count += 1;
            assert!(
                target.is_satisfied_by_bytes(&outcome.digest()),
                "fail-closed: outcome.digest() must satisfy target whenever mine_at() returns Ok"
            );
        }
    }
    assert!(
        admitted_count > 0,
        "with a permissive target and 64 variations, at least one mine_at scan should admit"
    );
}

// ─── §3. Determinism + parametricity ───────────────────────────────────

#[test]
fn v_psi_pipeline_is_pure_function_of_typed_input() {
    // The ψ-pipeline is parametric and deterministic — same (header,
    // nonce) → same κ-label. Five repetitions to defend against any
    // incidental non-determinism in the resolver chain.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let baseline = forward_kappa_label(&header, 0xA5);
    for _ in 0..5 {
        let repeat = forward_kappa_label(&header, 0xA5);
        assert_eq!(repeat, baseline, "ψ-pipeline must be deterministic");
    }
}

#[test]
fn v_kappa_label_is_distinct_for_distinct_typed_inputs() {
    // Distinct typed inputs yield distinct κ-labels — the σ-axis is
    // collision-resistant, so distinct headers content-address to
    // distinct sha256d block hashes.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let mut labels = std::collections::HashSet::new();
    for nonce in 0u32..64 {
        let label = forward_kappa_label(&header, nonce);
        assert!(
            labels.insert(label),
            "κ-labels must be distinct across distinct typed inputs (no collisions in 64-sweep)"
        );
    }
}

// ─── §4. κ-label identity + wire-format reconstruction ─────────────────

#[test]
fn v_kappa_label_is_sha256d_of_reconstructed_wire_format_header() {
    // The κ-label IS the sha256d:<64hex> address: the SHA-256d digest of
    // the wire-format Bitcoin header in display order. The 80-byte
    // wire-format header is carried as `outcome.wire_format_header`.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let outcome = admit_by_nonce_scan(&header, Target::new(0x207fffff));

    // The reconstructed wire-format header is byte-for-byte
    // serialize_header(header, winning_nonce). This is the bytes
    // `submitblock` accepts.
    let manual_wire = serialize_header(&header, outcome.nonce());
    assert_eq!(
        outcome.wire_format_header, manual_wire,
        "MiningOutcome.wire_format_header must be the canonical 80-byte serialization"
    );

    // The κ-label hex is the display-order digest of that header.
    let expected_digest = sha256d_display(&manual_wire);
    assert_eq!(outcome.digest(), expected_digest);
    // The 64-hex tail of the κ-label encodes the display-order digest.
    let address = outcome.address();
    let hex_tail = &address.as_str()[8..];
    let mut expected_hex = String::with_capacity(64);
    for b in expected_digest {
        expected_hex.push_str(&format!("{b:02x}"));
    }
    assert_eq!(
        hex_tail, expected_hex,
        "κ-label hex MUST be the display-order digest"
    );
}

#[test]
fn v_wire_format_header_preserves_the_host_supplied_prefix() {
    // The reconstructed wire-format header's leading 76 bytes are exactly
    // the host-supplied template prefix (Version ‖ PrevHash ‖ MerkleRoot ‖
    // Timestamp ‖ Bits); only the trailing 4 nonce bytes vary. The
    // ψ-pipeline does not mutate the template-supplied bytes.
    let target = Target::new(0x207fffff);
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let outcome = admit_by_nonce_scan(&header, target);

    let prefix = serialize_prefix(&header);
    assert_eq!(
        &outcome.wire_format_header[..76],
        &prefix[..],
        "wire_format_header's leading 76 bytes must equal the host-supplied prefix"
    );
    assert_eq!(
        &outcome.wire_format_header[76..80],
        &outcome.nonce().to_le_bytes(),
        "wire_format_header's trailing 4 bytes are the winning nonce (canonical LE)"
    );
}

// ─── §5. Cross-network invariance ──────────────────────────────────────

#[test]
fn v_model_declarations_invariant_across_network_byte_thresholds() {
    // Network-invariance: the ψ-pipeline transform is identical across
    // regtest / signet / testnet / testnet4 / mainnet — same
    // BitcoinAddressModel, same verb-body ψ-chain, same shared ψ-tower.
    // The network-dependent value is the target byte threshold; the model
    // declarations are uniform. We use mine_at at nonce 0 for the hard
    // targets (no actual mainnet mining) and assert the structural
    // inference is well-formed regardless of network.
    use prism::vocabulary::HostBounds;
    use prism_btc::PrismBtcBounds;

    let representative_bits: &[u32] = &[
        0x207fffff, // regtest
        0x1d00ffff, // mainnet/testnet historical
        0x1cffff00, // testnet4-ish
        0x1c0001b3, // mid-difficulty
    ];

    // The output shape's site count is uniform across networks.
    assert_eq!(<BlockAddressLabel as ConstrainedTypeShape>::SITE_COUNT, 72);
    assert_eq!(<PrismBtcBounds as HostBounds>::WITT_LEVEL_MAX_BITS, 32);
    assert!(!VERB_TERMS_BLOCK_ADDRESS_INFERENCE::<32>().is_empty());

    for &bits in representative_bits {
        let header = canonical_header(1, 1_700_000_000, bits);
        let target = Target::new(bits);
        // A single inference at nonce 0: the structural κ-derivation
        // produces a well-formed sha256d address regardless of network.
        // For the hard targets nonce 0 will not admit, but the κ-label is
        // still well-formed (carried on DidNotAdmit's digest). For the
        // permissive regtest target it may admit; either way the digest
        // is a valid 32-byte block hash.
        match mine_at(&header, target, 0) {
            Ok(outcome) => {
                assert!(outcome.address().starts_with("sha256d:"));
                assert_eq!(outcome.address().len(), 72);
            }
            Err(ref f @ prism_btc::MiningFailure::DidNotAdmit { .. }) => {
                let digest = f.digest().expect("DidNotAdmit carries a digest");
                assert_eq!(digest.len(), 32);
            }
            Err(prism_btc::MiningFailure::PipelineFailure) => {
                panic!("PipelineFailure unreachable for well-formed header (bits=0x{bits:08x})")
            }
        }
    }
}

// ─── §6. Replayable witness identity (TC-05) ───────────────────────────

#[test]
fn v_witness_replays_to_the_attested_kappa_label() {
    // The MiningOutcome carries a replayable TC-05 witness. verify()
    // re-certifies the derivation without re-invoking the σ-axis and
    // returns the attested κ-label — which must equal the outcome's
    // address. The content fingerprint is the 32-byte σ-projection.
    let target = Target::new(0x207fffff);
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let outcome = admit_by_nonce_scan(&header, target);

    let replayed = outcome.witness.verify().expect("witness replays");
    assert_eq!(
        replayed,
        outcome.address(),
        "witness re-certifies to the κ-label"
    );
    assert_eq!(outcome.witness.kappa_label(), outcome.address());
    assert_eq!(outcome.witness.content_fingerprint().len(), 32);
}

// ─── §7. Algebraic structure of BlockAddressLabel::CONSTRAINTS ─────────

#[test]
fn v_block_address_label_constraints_have_seventy_two_disjoint_site_instances() {
    // Algebraic-closure: 72 disjoint `Site` constraints, one per κ-label
    // byte position (sha256d:<64hex>). The constraint nerve has 72
    // isolated vertices, β_0 = 72, β_k = 0 for k ≥ 1, χ = 72 = SITE_COUNT.
    let cs = <BlockAddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(cs.len(), 72);
    for c in cs {
        assert!(
            matches!(c, ConstraintRef::Site { .. }),
            "every constraint is a Site"
        );
    }
}

#[test]
fn v_constraint_nerve_is_seventy_two_isolated_vertices_no_higher_simplices() {
    // The constraint nerve N(C) has vertices = the 72 constraints; site
    // supports are pairwise disjoint (each Site_i pins one distinct site
    // i ∈ [0, 72)); therefore no 1-simplices, no higher simplices.
    // β_0 = 72, β_k = 0 for k ≥ 1.
    let cs = <BlockAddressLabel as ConstrainedTypeShape>::CONSTRAINTS;

    fn site_support(c: &ConstraintRef) -> Option<u32> {
        match c {
            ConstraintRef::Site { position } => Some(*position),
            _ => None,
        }
    }

    let mut supports = std::collections::HashSet::new();
    for c in cs {
        let site = site_support(c).expect("every constraint pins exactly one site");
        assert!(
            supports.insert(site),
            "site supports must be pairwise disjoint (no overlap at site {site})"
        );
    }
    assert_eq!(
        supports.len(),
        72,
        "72 disjoint site supports across [0, 72)"
    );
}

#[test]
fn v_constraint_site_supports_span_the_full_kappa_label() {
    // Site supports collectively cover all 72 κ-label byte positions.
    let cs = <BlockAddressLabel as ConstrainedTypeShape>::CONSTRAINTS;
    let mut sites: Vec<u32> = cs
        .iter()
        .map(|c| match c {
            ConstraintRef::Site { position } => *position,
            other => panic!("unexpected constraint variant: {other:?}"),
        })
        .collect();
    sites.sort_unstable();
    assert_eq!(
        sites,
        (0u32..72).collect::<Vec<_>>(),
        "site supports span [0, 72) exactly"
    );
}

#[test]
fn v_prism_btc_bounds_declare_algebraic_closure_target() {
    // PrismBtcBounds declares prism-btc's algebraic-closure target
    // ceilings — the application-side binding ceiling for the 72-site
    // BlockAddressLabel κ-label. The capacity floor is 72 (one per byte).
    use prism::vocabulary::HostBounds;
    use prism_btc::PrismBtcBounds;
    const _: () = {
        assert!(<PrismBtcBounds as HostBounds>::NERVE_SITES_MAX >= 72);
        assert!(<PrismBtcBounds as HostBounds>::NERVE_CONSTRAINTS_MAX >= 72);
        assert!(<PrismBtcBounds as HostBounds>::BETTI_DIMENSION_MAX >= 72);
    };
}
