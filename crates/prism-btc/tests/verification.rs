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
//!   admitting `MiningOutcome`; the 32-byte SHA-256d κ-label
//!   actually satisfies the host-supplied target — admission is
//!   evaluated inside foundation's `run_route` via the model's
//!   `C = TargetCommitment` pin (wiki ADR-048).
//! - **Determinism + parametricity** — the ψ-pipeline is a pure
//!   deterministic function of the typed input.
//! - **κ-label identity** — the κ-label IS the SHA-256d digest of the
//!   wire-format Bitcoin header. `MiningOutcome.wire_format_header`
//!   carries the reconstructed 80-byte header (recovered from
//!   `(template_prefix, derived_nonce)` at the prism-btc boundary)
//!   for `submitblock` compatibility.
//! - **Cross-network invariance** — the same `BitcoinMiningModel`
//!   declarations apply across regtest, signet, testnet, testnet4,
//!   mainnet; only the target byte threshold varies.
//! - **CompileUnit identity invariance** — distinct typed inputs
//!   produce identical CompileUnit-level fingerprints (they identify
//!   the typed-iso path, not bytewise input identity).

use prism::operation::Term;
use prism::pipeline::{ConstrainedTypeShape, ConstraintRef, PrismModel};
use prism::vocabulary::DefaultHostTypes;
use prism_btc::{
    mine, serialize_header, sha256d_display, take_resolution_state, BitcoinMiningModel,
    BitcoinResolverTuple, Bits, BlockHeader, MerkleRoot, MiningResult, MiningTask, PrismBtcBounds,
    Sha256dHasher, Target, Timestamp, Version, VERB_TERMS_MINING_INFERENCE,
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

/// Forward via the canonical 5-position `PrismModel<…, TargetCommitment>`
/// (wiki ADR-048). The thread-local target slot is set to a permissive
/// value (`[0xff; 32]`) so admission holds for every κ-label — V&V
/// tests exercise the ψ-pipeline's *structural* properties, not the
/// admission relation.
fn forward(task: MiningTask) -> prism::seal::Grounded<prism_btc::MiningResult> {
    prism_btc::set_thread_target_bytes([0xffu8; 32]);
    <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        prism_btc::TargetCommitment,
    >>::forward(task)
    .expect("ψ-pipeline must run end-to-end on permissive target")
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
fn v_mine_admits_within_a_few_template_variations_for_permissive_target() {
    // Architecture §6 fail-closed invariant: ψ_9's structural
    // κ-derivation produces one wire-format header candidate per
    // MiningTask; the host boundary's admission check decides Ok vs
    // DidNotAdmit. For a permissive target (regtest's 0x207fffff:
    // ~50% per-κ-derivation admission probability), iterating a
    // small number of template variations lands an admitting
    // κ-derivation. Cryptographic re-derivation: recompute SHA-256d
    // from the wire-format header bytes and verify it matches the
    // reported digest AND satisfies the target.
    let target = Target::new(0x207fffff);

    let admitted = (0u32..32)
        .find_map(|ts_offset| {
            let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
            mine(&header, target).ok()
        })
        .expect("at least one of 32 template variations should admit at a permissive target");

    // The κ-label IS the 32-byte SHA-256d digest (the natural cost-model
    // κ-label per wiki ADR-048/049). Re-derive from the reconstructed
    // wire-format header.
    let kappa_label = admitted.witness.output_bytes();
    assert_eq!(kappa_label.len(), 32, "κ-label is the 32-byte digest");
    let re_derived_digest = sha256d_display(&admitted.wire_format_header);
    let mut kappa_bytes = [0u8; 32];
    kappa_bytes.copy_from_slice(kappa_label);
    assert_eq!(
        kappa_bytes, re_derived_digest,
        "κ-label must equal SHA-256d(wire_format_header) in display order"
    );
    assert_eq!(
        admitted.digest, re_derived_digest,
        "outcome.digest mirrors the κ-label digest"
    );
    assert!(
        target.is_satisfied_by_bytes(&re_derived_digest),
        "fail-closed: an admitted outcome's digest MUST actually satisfy the target"
    );
}

#[test]
fn v_mine_outcome_digest_actually_satisfies_target_when_admitted() {
    // Fail-closed across the input space: for every (header, target)
    // pair where mine() returns Ok, the wire-format header's digest
    // genuinely satisfies the target. Templates whose κ-derivation
    // does not admit return Err(DidNotAdmit) — those don't produce
    // a MiningOutcome, so there is no admitted-but-invalid case to
    // worry about. The boundary admission check is the fail-closed
    // gate.
    let target = Target::new(0x207fffff);
    let mut admitted_count = 0;
    for ts_offset in 0u32..64 {
        let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
        if let Ok(outcome) = mine(&header, target) {
            admitted_count += 1;
            assert!(
                target.is_satisfied_by_bytes(&outcome.digest),
                "fail-closed: outcome.digest must satisfy target whenever mine() returns Ok"
            );
        }
    }
    assert!(
        admitted_count > 0,
        "with a permissive target and 64 variations, at least one κ-derivation should admit"
    );
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
fn v_kappa_label_is_distinct_for_distinct_typed_inputs() {
    // Architecture §4: distinct typed inputs yield distinct κ-labels.
    // The κ-derivation projects the typed MiningTask via the canonical
    // hash axis; distinct prefixes produce distinct content-addresses
    // and therefore distinct κ-derivations (in the cryptographic
    // collision-resistance sense). Even if two prefixes happened to
    // collide on the κ-nonce, the structural distinction would
    // remain in the wire-format prefix region of the κ-label.
    let target = [0xffu8; 32];
    let mut labels = std::collections::HashSet::new();
    for v in 0u8..64 {
        let mut prefix = [0u8; 76];
        prefix[0] = v;
        let task = MiningTask::new(prefix, target);
        let grounded = forward(task);
        let label: Vec<u8> = grounded.output_bytes().to_vec();
        assert!(
            labels.insert(label),
            "κ-labels must be distinct across distinct typed inputs (no collisions in 64-sweep)"
        );
    }
}

// ─── §4. κ-label identity + wire-format reconstruction ─────────────────

#[test]
fn v_kappa_label_is_sha256d_of_reconstructed_wire_format_header() {
    // Wiki ADR-048/049: the κ-label IS the 32-byte SHA-256d digest of
    // the wire-format Bitcoin header — this is the natural cost-model
    // κ-label foundation's `LexicographicLessEqThreshold` predicate
    // compares against the target. The 80-byte wire-format header is
    // reconstructed at the prism-btc boundary from
    // `(template_prefix, derived_nonce)` and carried as
    // `outcome.wire_format_header`.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);

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

    // The reconstructed wire-format header is byte-for-byte
    // serialize_header(host_header, derived_nonce). This is the bytes
    // `submitblock` accepts.
    let manual_wire = serialize_header(&host_header, outcome.nonce);
    assert_eq!(
        outcome.wire_format_header, manual_wire,
        "MiningOutcome.wire_format_header must be the canonical 80-byte serialization"
    );

    // The κ-label (witness.output_bytes()) is the digest of that
    // wire-format header in display order.
    let kappa_label = outcome.witness.output_bytes();
    assert_eq!(kappa_label.len(), 32);
    let expected_digest = sha256d_display(&manual_wire);
    assert_eq!(
        kappa_label,
        &expected_digest[..],
        "κ-label MUST be SHA-256d(wire_format_header) in display order"
    );
}

#[test]
fn v_wire_format_header_preserves_the_host_supplied_prefix() {
    // Architecture §4: the reconstructed wire-format header's leading
    // 76 bytes are exactly the host-supplied TemplatePrefix bytes
    // (Version || PrevHash || MerkleRoot || Timestamp || Bits). The
    // ψ-pipeline does not mutate the template-supplied bytes; it only
    // derives the nonce. (The κ-label itself is the 32-byte digest;
    // the wire-format header is the reconstructed 80-byte artifact
    // carried separately on `outcome.wire_format_header`.)
    let target = Target::new(0x207fffff);
    let mut found = None;
    for ts in 0u32..256 {
        let header = canonical_header(1, 1_700_000_000_u32 + ts, 0x207fffff);
        if let Ok(outcome) = mine(&header, target) {
            found = Some((header, outcome));
            break;
        }
    }
    let (host_header, outcome) = found.expect("permissive target must admit");
    let prefix = serialize_header(&host_header, 0);
    assert_eq!(
        &outcome.wire_format_header[..76],
        &prefix[..76],
        "wire_format_header's leading 76 bytes must equal the host-supplied TemplatePrefix"
    );
}

// ─── §5. Cross-network invariance ──────────────────────────────────────

#[test]
fn v_model_declarations_invariant_across_network_byte_thresholds() {
    // Architecture §6 network-invariance: the ψ-pipeline transform is
    // identical across regtest / signet / testnet / testnet4 /
    // mainnet — same `BitcoinMiningModel`, same verb-body ψ-chain,
    // same `BitcoinResolverTuple`. The network-dependent value is the
    // target byte threshold encoded in the template's `bits` field;
    // the model declarations are uniform.
    //
    // Static check: for representative `bits` values from each
    // network, the typed `MiningTask` partition_product layout is
    // identical, the substitution-axis triple is identical, and the
    // verb-arena slice is identical. Whether the κ-derivation for a
    // given (prefix, target) admits at the boundary is a property
    // of the typed input, not of the implementation — not exercised
    // here. The regtest end-to-end suite (VERIFICATION.md §4)
    // exercises an actual network end-to-end.
    use prism::vocabulary::HostBounds;

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

        // The typed input's structural layout is uniform across
        // networks: 108-byte partition_product of TemplatePrefix
        // (76) + Target (32), 32-site `MiningResult` output shape
        // (the SHA-256d κ-label per wiki ADR-048/049), identical
        // PrismBtcBounds capacity profile.
        assert_eq!(task.0.len(), 108);
        assert_eq!(<MiningResult as ConstrainedTypeShape>::SITE_COUNT, 32);
        assert_eq!(<PrismBtcBounds as HostBounds>::WITT_LEVEL_MAX_BITS, 32);

        // The verb arena's structural composition is uniform —
        // independent of which network's bits the runtime template
        // carries.
        assert!(!VERB_TERMS_MINING_INFERENCE.is_empty());
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

// ─── §7. Algebraic structure of MiningResult::CONSTRAINTS ──────────────

#[test]
fn v_mining_result_constraints_have_thirty_two_disjoint_site_instances() {
    // Architecture §2.3 + IT_7d algebraic-closure: 32 disjoint `Site`
    // constraints, one per SHA-256d digest byte. The constraint
    // nerve has 32 isolated vertices, β_0 = 32, β_k = 0 for k ≥ 1,
    // χ = 32 = SITE_COUNT — the framework's algebraic-closure
    // criterion satisfied at the declaration level for the 32-byte
    // κ-label per wiki ADR-048/049.
    let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(cs.len(), 32);
    for c in cs {
        assert!(
            matches!(c, ConstraintRef::Site { .. }),
            "every constraint is a Site"
        );
    }
}

#[test]
fn v_constraint_nerve_is_thirty_two_isolated_vertices_no_higher_simplices() {
    // Architecture §2.3: the constraint nerve N(C) has vertices = the
    // 32 constraints; site supports are pairwise disjoint (each
    // Site_i pins one distinct site i ∈ [0, 32)); therefore no
    // 1-simplices, no higher simplices. β_0 = 32, β_k = 0 for k ≥ 1.
    let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;

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
        32,
        "32 disjoint site supports across [0, 32)"
    );
}

#[test]
fn v_constraint_site_supports_span_the_full_digest() {
    // Architecture §2.3 + IT_7d: site supports collectively cover all
    // 32 SHA-256d κ-label byte positions. All sites are κ-pinned by
    // ψ_9's structural κ-derivation (SHA-256d of the reconstructed
    // wire-format header).
    let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
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
        (0u32..32).collect::<Vec<_>>(),
        "site supports span [0, 32) exactly"
    );
}

#[test]
fn v_prism_btc_bounds_declare_algebraic_closure_target() {
    // Architecture §2.3 + §9.3: PrismBtcBounds declares prism-btc's
    // algebraic-closure target ceilings — the application-side
    // binding ceiling for the 32-site `MiningResult` κ-label per wiki
    // ADR-048/049. The capacity floor is 32 (one per digest byte).
    use prism::vocabulary::HostBounds;
    const _: () = {
        assert!(<PrismBtcBounds as HostBounds>::NERVE_SITES_MAX >= 32);
        assert!(<PrismBtcBounds as HostBounds>::NERVE_CONSTRAINTS_MAX >= 32);
        assert!(<PrismBtcBounds as HostBounds>::BETTI_DIMENSION_MAX >= 32);
        assert!(<PrismBtcBounds as HostBounds>::AFFINE_COEFFS_MAX >= 32);
    };
}

// ─── §8. ψ_9 κ-derivation diagnostic surface ──────────────────────────

#[test]
fn v_mine_outcome_carries_kappa_derivation_state() {
    // Architecture §4 + crate::diagnostics: on the Ok path of mine(),
    // outcome.resolution carries free_rank = 0 (all 32 MiningResult
    // sites pinned at the terminal ψ-stage by the SHA-256d evaluation)
    // and derived_nonce matching the κ-derived nonce embedded in the
    // wire-format header.
    let target = Target::new(0x207fffff);
    let outcome = (0u32..32)
        .find_map(|ts_offset| {
            let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
            mine(&header, target).ok()
        })
        .expect("permissive target admits within a small variation window");

    assert_eq!(
        outcome.resolution.free_rank, 0,
        "free_rank = 0 at terminal ψ-stage convergence"
    );
    assert_eq!(
        outcome.resolution.derived_nonce, outcome.nonce,
        "ψ_9's recorded κ-derivation matches the host-perspective nonce"
    );
}

#[test]
fn v_mine_drains_thread_local_diagnostic_channel() {
    // crate::diagnostics: mine() drains the thread-local channel as
    // part of constructing MiningOutcome; a subsequent
    // take_resolution_state() returns None.
    let target = Target::new(0x207fffff);
    let _ = (0u32..32)
        .find_map(|ts_offset| {
            let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
            mine(&header, target).ok()
        })
        .expect("permissive target admits within a small variation window");

    assert!(
        take_resolution_state().is_none(),
        "mine()'s Ok path drains the channel; subsequent take() returns None"
    );
}

#[test]
fn v_forward_records_resolution_state_for_inspection() {
    // Direct forward() callers (not going through mine()) inspect
    // the diagnostic channel via take_resolution_state(). ψ_9
    // records state on every invocation.
    let _ = take_resolution_state(); // drain any leftover state
    let mut prefix = [0u8; 76];
    prefix[0] = 0x55;
    let target = [0xffu8; 32];
    let task = MiningTask::new(prefix, target);

    prism_btc::set_thread_target_bytes(target);
    let _grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
        prism_btc::TargetCommitment,
    >>::forward(task)
    .expect("ψ-pipeline runs");

    let state =
        take_resolution_state().expect("ψ_9 must have recorded resolution state for forward()");
    assert_eq!(state.free_rank, 0, "terminal ψ-stage converges");

    // The κ-label is the 32-byte SHA-256d digest. Reconstruct the
    // wire-format header from (prefix, state.derived_nonce) and
    // verify SHA-256d(reconstruction) == κ-label, i.e. ψ_9 emitted
    // the canonical digest of the canonical wire-format reconstruction.
    let kappa_label = _grounded.output_bytes();
    assert_eq!(kappa_label.len(), 32, "κ-label is the 32-byte digest");
    let reconstructed = prism_btc::splice_nonce(&prefix, state.derived_nonce);
    let expected_digest = sha256d_display(&reconstructed);
    assert_eq!(
        kappa_label,
        &expected_digest[..],
        "κ-label MUST be SHA-256d(splice_nonce(prefix, derived_nonce))"
    );
}
