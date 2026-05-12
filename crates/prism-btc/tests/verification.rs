//! prism-btc Verification & Validation suite.
//!
//! These tests pin the architectural invariants the implementation
//! commits to. They are independent of the integration tests
//! ([`tests/integration.rs`]) which exercise the surface API; the
//! V&V suite verifies the **load-bearing structural properties**:
//!
//! - **ψ-pipeline structural form** — the verb arena composes only
//!   ψ-stage Term variants (no σ-residuals; substrate-enforced at
//!   compile time but pinned here for defense-in-depth).
//! - **Fail-closed mining contract** — `mine()` only returns an
//!   admitting `MiningOutcome`; the wire-format header's SHA-256d
//!   actually satisfies the host-supplied target (cryptographic
//!   re-derivation check).
//! - **Determinism + parametricity** — the ψ-pipeline is a pure
//!   deterministic function of the typed input.
//! - **Wire-format equivalence** — the κ-label is byte-for-byte the
//!   wire-format Bitcoin header that `submitblock` would accept.
//! - **Cross-network invariance** — the same `BitcoinMiningModel`
//!   declarations apply across regtest, signet, testnet, testnet4,
//!   mainnet; only the target byte threshold varies.
//! - **CompileUnit identity invariance** — distinct typed inputs
//!   produce identical CompileUnit-level fingerprints (they identify
//!   the typed-iso path, not bytewise input identity).

use prism_btc::{
    mine, serialize_header, sha256d_display, BitcoinMiningModel, BitcoinResolverTuple, Bits,
    BlockHeader, MerkleRoot, MiningFailure, MiningTask, PrismBtcBounds, Sha256dHasher, Target,
    Timestamp, Version, VERB_TERMS_MINING_INFERENCE,
};
use uor_foundation::enforcement::Term;
use uor_foundation::pipeline::PrismModel;
use uor_foundation::DefaultHostTypes;

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

fn forward(task: MiningTask) -> uor_foundation::enforcement::Grounded<prism_btc::MiningResult> {
    <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .expect("ψ-pipeline must run end-to-end")
}

// ─── §1. Structural verb-arena invariants ──────────────────────────────

#[test]
fn v_verb_arena_composes_only_psi_stages_no_sigma_residuals() {
    // Pure-prism commitment (architecture §12; substrate-enforced
    // ψ-residuals discipline §9.0). The verb arena must contain only
    // ψ-stage Term variants — no FirstAdmit, no AxisInvocation, no
    // byte-comparison / concat operators.
    let arena = VERB_TERMS_MINING_INFERENCE;
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
    // Architecture §4: prism-btc selects the k-invariant branch
    // (ψ_1 → ψ_7 → ψ_8 → ψ_9) as the canonical mining transform.
    // The arena must contain exactly these four ψ-Term variants.
    let arena = VERB_TERMS_MINING_INFERENCE;
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
fn v_mine_admitting_outcome_digest_actually_satisfies_target() {
    // Architecture §6 fail-closed invariant: when mine() returns Ok,
    // the digest IS lex-≤ the host-supplied target. Cryptographic
    // re-derivation: recompute SHA-256d from the wire-format header
    // bytes and verify it matches the reported digest AND satisfies
    // the target.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let target = Target::new(0x207fffff);

    // Iterate timestamp variations to find an admitting κ-derivation;
    // pin the cryptographic invariant on the returned outcome.
    let outcome = (0u32..1024)
        .find_map(|salt| {
            let mut varied = header.clone();
            varied.timestamp = Timestamp(header.timestamp.0.wrapping_add(salt));
            mine(&varied, target).ok().map(|o| (varied, o))
        })
        .map(|(_, o)| o)
        .expect("permissive target must admit within 1024 variations");

    // Re-derive the digest from the wire-format header bytes.
    let wire_header = outcome.witness.output_bytes();
    assert_eq!(wire_header.len(), 80);
    let mut header_bytes = [0u8; 80];
    header_bytes.copy_from_slice(wire_header);
    let re_derived_digest = sha256d_display(&header_bytes);

    assert_eq!(
        outcome.digest, re_derived_digest,
        "outcome.digest must equal SHA-256d(wire-format header) in display order"
    );
    assert!(
        target.is_satisfied_by_bytes(&re_derived_digest),
        "fail-closed: an admitted outcome's digest MUST actually satisfy the target"
    );
}

#[test]
fn v_mine_never_returns_admitting_outcome_for_unachievable_target() {
    // Architecture §6 fail-closed invariant: for a target so strict
    // that the κ-derived header cannot satisfy it, mine() must NOT
    // return Ok with a non-admitting digest. Sweep many variations
    // and assert that every Ok outcome's digest genuinely admits.
    let header = canonical_header(1, 1_700_000_000, 0x03000001);
    let strict_target = Target::new(0x03000001);

    for salt in 0u32..256 {
        let mut varied = header.clone();
        varied.timestamp = Timestamp(header.timestamp.0.wrapping_add(salt));
        match mine(&varied, strict_target) {
            Ok(outcome) => {
                // Fail-closed: if Ok, digest MUST satisfy the target.
                assert!(
                    strict_target.is_satisfied_by_bytes(&outcome.digest),
                    "fail-closed: Ok outcome's digest must actually satisfy target"
                );
            }
            Err(MiningFailure::DidNotAdmit) => { /* expected */ }
            Err(MiningFailure::PipelineFailure) => {
                panic!("ψ-pipeline rejected a well-formed input");
            }
        }
    }
}

// ─── §3. Determinism + parametricity ───────────────────────────────────

#[test]
fn v_psi_pipeline_is_pure_function_of_typed_input() {
    // Architecture §4: the ψ-pipeline is parametric and deterministic
    // — same MiningTask → same κ-label. Five repetitions to defend
    // against any incidental non-determinism in the resolver chain.
    let mut prefix = [0u8; 76];
    prefix[0] = 0xA5;
    let target = [0xffu8; 32];
    let task = MiningTask::new(prefix, target);

    let baseline = forward(task);
    let baseline_bytes = baseline.output_bytes().to_vec();

    for _ in 0..5 {
        let repeat = forward(task);
        assert_eq!(
            repeat.output_bytes(),
            baseline_bytes.as_slice(),
            "ψ-pipeline must be deterministic"
        );
    }
}

#[test]
fn v_psi_pipeline_is_injective_in_the_resolved_nonce_field() {
    // Architecture §4: distinct typed inputs yield distinct
    // κ-derived nonces. (Strict injectivity would require collision-
    // freeness; pin "at least no collisions across a small sweep.")
    let target = [0xffu8; 32];
    let mut nonces = std::collections::HashSet::new();
    for v in 0u8..64 {
        let mut prefix = [0u8; 76];
        prefix[0] = v;
        let task = MiningTask::new(prefix, target);
        let grounded = forward(task);
        let nonce_bytes = &grounded.output_bytes()[76..80];
        assert!(
            nonces.insert(u32::from_le_bytes([
                nonce_bytes[0],
                nonce_bytes[1],
                nonce_bytes[2],
                nonce_bytes[3]
            ])),
            "κ-derived nonces must be distinct across distinct typed inputs (no collisions in 64-sweep)"
        );
    }
}

// ─── §4. Wire-format byte-for-byte equivalence ─────────────────────────

#[test]
fn v_kappa_label_is_wire_format_header_byte_for_byte() {
    // Architecture §6 bit-identicality: the κ-label IS the wire-
    // format Bitcoin header. Verify by:
    //   1. extracting the resolved nonce from κ-label bytes 76..80
    //   2. constructing the canonical wire-format header from
    //      (host-side header, resolved nonce) via serialize_header
    //   3. asserting byte-for-byte equality
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);

    // Find an admission via a small variation sweep.
    let admitting = (0u32..1024)
        .find_map(|salt| {
            let mut varied = header.clone();
            varied.timestamp = Timestamp(header.timestamp.0.wrapping_add(salt));
            mine(&varied, Target::new(0x207fffff))
                .ok()
                .map(|o| (varied, o))
        })
        .expect("permissive target must admit within 1024 variations");
    let (host_header, outcome) = admitting;

    let manual_wire = serialize_header(&host_header, outcome.nonce);
    let kappa_wire = outcome.witness.output_bytes();
    assert_eq!(
        kappa_wire,
        &manual_wire[..],
        "κ-label MUST be byte-for-byte the canonical wire-format header"
    );
}

#[test]
fn v_kappa_label_preserves_the_host_supplied_prefix() {
    // Architecture §4 ψ_9 contract: κ-label bytes 0..76 are exactly
    // the host-supplied TemplatePrefix bytes (Version || PrevHash ||
    // MerkleRoot || Timestamp || Bits). The ψ-pipeline does not
    // mutate the template-supplied bytes; it only derives the nonce.
    let mut prefix = [0u8; 76];
    // Sprinkle distinct bytes across each field so any mutation
    // shows up in the comparison.
    for (i, b) in prefix.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    let target = [0xffu8; 32];
    let task = MiningTask::new(prefix, target);
    let grounded = forward(task);
    let label = grounded.output_bytes();

    assert_eq!(
        &label[..76],
        &prefix[..],
        "κ-label's leading 76 bytes must equal MiningTask.prefix unmodified"
    );
}

// ─── §5. Cross-network invariance ──────────────────────────────────────

#[test]
fn v_psi_pipeline_invariant_across_network_byte_thresholds() {
    // Architecture §6 network-invariance: the ψ-pipeline transform is
    // identical across regtest / signet / testnet / testnet4 /
    // mainnet. The network-dependent value is the target byte
    // threshold; the resolved-nonce field of the κ-label depends
    // ONLY on (prefix, target) and not on which "network" the host
    // claims to be on.
    //
    // Sweep representative `bits` values from each network and verify
    // each yields a deterministic κ-label whose leading 76 bytes are
    // exactly that template's prefix.
    let representative_bits: &[u32] = &[
        0x207fffff, // regtest
        0x1d00ffff, // mainnet/testnet historical
        0x1cffff00, // testnet4-ish
        0x1c0001b3, // mid-difficulty
    ];

    for &bits in representative_bits {
        let header = canonical_header(1, 1_700_000_000, bits);
        let prefix = serialize_header(&header, 0);
        let mut prefix76 = [0u8; 76];
        prefix76.copy_from_slice(&prefix[..76]);
        let target_bytes = Target::new(bits).to_bytes();
        let task = MiningTask::new(prefix76, target_bytes);

        let grounded = forward(task);
        let label = grounded.output_bytes();
        assert_eq!(
            label.len(),
            80,
            "every network's κ-label is 80 bytes (wire-format header width)"
        );
        assert_eq!(
            &label[..76],
            &prefix76[..],
            "every network's κ-label preserves the template prefix"
        );
    }
}

// ─── §6. CompileUnit identity invariance (TC-03 typed-iso path) ────────

#[test]
fn v_compile_unit_fingerprint_identifies_the_typed_iso_path() {
    // Architecture conformance (TC-03 typed-iso path-singularity):
    // two distinct typed inputs produce identical CompileUnit-level
    // fingerprints — they identify the **path** through the typed-
    // iso surface, not bytewise input identity. (Distinct admitted
    // values still get distinct `output_bytes`; only the substrate's
    // CompileUnit metadata is shared.)
    let mut p_a = [0u8; 76];
    p_a[0] = 0x01;
    let mut p_b = [0u8; 76];
    p_b[0] = 0x02;
    let target = [0xffu8; 32];

    let ga = forward(MiningTask::new(p_a, target));
    let gb = forward(MiningTask::new(p_b, target));

    assert_eq!(ga.content_fingerprint(), gb.content_fingerprint());
    assert_eq!(ga.unit_address(), gb.unit_address());
    assert_eq!(ga.witt_level_bits(), gb.witt_level_bits());
    assert_eq!(ga.witt_level_bits(), 32);
}
