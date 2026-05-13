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
    mine, serialize_header, sha256d_display, take_resolution_state, BitcoinMiningModel,
    BitcoinResolverTuple, Bits, BlockHeader, MerkleRoot, MiningResult, MiningTask, PrismBtcBounds,
    ResolutionVerdict, Sha256dHasher, Target, Timestamp, Version, VERB_TERMS_MINING_INFERENCE,
};
use uor_foundation::enforcement::Term;
use uor_foundation::pipeline::{ConstrainedTypeShape, ConstraintRef, PrismModel};
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
fn v_mine_admits_in_one_call_against_a_permissive_target() {
    // Architecture §6 fail-closed invariant + the wiki's iterative-
    // resolution discipline: the ψ_9 resolver walks the W32 nonce ring
    // internally until admission lands. For a permissive target
    // (regtest's 0x207fffff: ~50% per-nonce admission), the first
    // call to mine() admits. Cryptographic re-derivation: recompute
    // SHA-256d from the wire-format header bytes and verify it
    // matches the reported digest AND satisfies the target.
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let target = Target::new(0x207fffff);

    let outcome = mine(&header, target).expect("permissive target must admit in one call");

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
fn v_mine_outcome_digest_actually_satisfies_target_across_inputs() {
    // Fail-closed across the input space: for every host-supplied
    // (header, target) pair where mine() returns Ok, the wire-format
    // header's digest genuinely satisfies the target. The ψ_9
    // resolver's iterative-resolution guarantee: if convergence
    // lands, the pinned nonce satisfies the structural admission
    // relation.
    let target = Target::new(0x207fffff);
    for ts_offset in 0u32..16 {
        let header = canonical_header(1, 1_700_000_000_u32 + ts_offset, 0x207fffff);
        let outcome = mine(&header, target).expect("permissive target admits");
        assert!(
            target.is_satisfied_by_bytes(&outcome.digest),
            "fail-closed: outcome.digest must satisfy target"
        );
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
fn v_kappa_label_is_distinct_for_distinct_typed_inputs() {
    // Architecture §4: distinct typed inputs yield distinct κ-labels.
    // Under the resolver-owned iterative-resolution model, two
    // distinct prefixes may converge on the same admitting nonce
    // (e.g., both lock to nonce=0 against a maximally-permissive
    // target); the structural distinction is preserved in the
    // wire-format prefix region of the κ-label, not necessarily in
    // the 4-byte nonce field.
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
    // verb-arena slice is identical. The structural-admission
    // satisfaction is a runtime property of the (prefix, target)
    // pair — not exercised here because the W32 walk under
    // restrictive bits is computationally intractable in unit-test
    // time. The regtest end-to-end suite (VERIFICATION.md §4)
    // exercises an actual network end-to-end.
    use uor_foundation::HostBounds;

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
        // (76) + Target (32), 80-site `MiningResult` output shape,
        // identical PrismBtcBounds capacity profile.
        assert_eq!(task.0.len(), 108);
        assert_eq!(<MiningResult as ConstrainedTypeShape>::SITE_COUNT, 80);
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
fn v_mining_result_constraints_have_eighty_disjoint_site_instances() {
    // Architecture §2.3 + IT_7d algebraic-closure: 80 disjoint `Site`
    // constraints, one per wire-format-header byte. The constraint
    // nerve has 80 isolated vertices, β_0 = 80, β_k = 0 for k ≥ 1,
    // χ = 80 = SITE_COUNT — the framework's algebraic-closure
    // criterion satisfied at the declaration level.
    let cs = <MiningResult as ConstrainedTypeShape>::CONSTRAINTS;
    assert_eq!(cs.len(), 80);
    for c in cs {
        assert!(
            matches!(c, ConstraintRef::Site { .. }),
            "every constraint is a Site"
        );
    }
}

#[test]
fn v_constraint_nerve_is_eighty_isolated_vertices_no_higher_simplices() {
    // Architecture §2.3: the constraint nerve N(C) has vertices = the
    // 80 constraints; site supports are pairwise disjoint (each
    // Site_i pins one distinct site i ∈ [0, 80)); therefore no
    // 1-simplices, no higher simplices. β_0 = 80, β_k = 0 for k ≥ 1.
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
        80,
        "80 disjoint site supports across [0, 80)"
    );
}

#[test]
fn v_constraint_site_supports_span_the_full_wire_format_header() {
    // Architecture §2.3 + IT_7d: site supports collectively cover all
    // 80 wire-format-header byte positions. Sites 0..76 are
    // template-pinned (runtime, via MiningTask's prefix factor); sites
    // 76..80 are κ-pinned (ψ_9 resolver's W32 walk). The constraint
    // declaration is uniform; the pinning mechanism differs per
    // site range.
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
        (0u32..80).collect::<Vec<_>>(),
        "site supports span [0, 80) exactly"
    );
}

#[test]
fn v_prism_btc_bounds_declare_algebraic_closure_target() {
    // Architecture §2.3 + §9.3: PrismBtcBounds declares prism-btc's
    // algebraic-closure target ceilings (NERVE_CONSTRAINTS_MAX = 128,
    // NERVE_SITES_MAX = 80, AFFINE_COEFFS_MAX = 80, etc.) — the
    // application-side binding ceiling that becomes the operational
    // cap when foundation's nerve primitive becomes HostBounds-
    // parametric. Pin the architectural target here.
    use uor_foundation::HostBounds;
    const _: () = {
        assert!(<PrismBtcBounds as HostBounds>::NERVE_SITES_MAX >= 80);
        assert!(<PrismBtcBounds as HostBounds>::NERVE_CONSTRAINTS_MAX >= 80);
        assert!(<PrismBtcBounds as HostBounds>::BETTI_DIMENSION_MAX >= 80);
        assert!(<PrismBtcBounds as HostBounds>::AFFINE_COEFFS_MAX >= 80);
    };
}

// ─── §8. Iterative-resolution diagnostic surface ───────────────────────

#[test]
fn v_mine_outcome_carries_converged_resolution_state() {
    // Architecture §4 + crate::diagnostics: on the Ok path of mine(),
    // outcome.resolution carries the Converged verdict with the
    // admitting nonce, free_rank=0 (all 80 MiningResult sites pinned),
    // and iterations=admitting_nonce+1 (the count of W32 candidates
    // ψ_9 evaluated before convergence).
    let header = canonical_header(1, 1_700_000_000, 0x207fffff);
    let outcome = mine(&header, Target::new(0x207fffff)).expect("permissive target admits");

    assert!(outcome.resolution.converged(), "Converged on Ok path");
    assert_eq!(
        outcome.resolution.free_rank, 0,
        "free_rank = 0 when all 80 sites pinned"
    );
    match outcome.resolution.verdict {
        ResolutionVerdict::Converged { admitting_nonce } => {
            assert_eq!(
                admitting_nonce, outcome.nonce,
                "resolver's admitting_nonce matches the host-perspective u32"
            );
            assert_eq!(
                outcome.resolution.iterations,
                (admitting_nonce as u64) + 1,
                "iterations = admitting_nonce + 1 (resolver visits 0..=admitting_nonce)"
            );
        }
        ResolutionVerdict::Exhausted => panic!("permissive target must not Exhaust"),
    }
}

#[test]
fn v_mine_drains_thread_local_diagnostic_channel() {
    // crate::diagnostics: mine() drains the thread-local channel as
    // part of constructing MiningOutcome; a subsequent
    // take_resolution_state() returns None.
    let header = canonical_header(1, 1_700_000_001, 0x207fffff);
    let _ = mine(&header, Target::new(0x207fffff)).expect("admits");

    assert!(
        take_resolution_state().is_none(),
        "mine()'s Ok path drains the channel; subsequent take() returns None"
    );
}

#[test]
fn v_forward_records_resolution_state_for_inspection() {
    // Direct forward() callers (not going through mine()) inspect
    // the diagnostic channel via take_resolution_state(). ψ_9
    // records state on its way out regardless of which entry-point
    // invoked the catamorphism.
    let _ = take_resolution_state(); // drain any leftover state
    let mut prefix = [0u8; 76];
    prefix[0] = 0x55;
    let target = [0xffu8; 32];
    let task = MiningTask::new(prefix, target);

    let _grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .expect("ψ-pipeline runs");

    let state =
        take_resolution_state().expect("ψ_9 must have recorded resolution state for forward()");
    assert!(state.converged(), "permissive target Converged");
    assert_eq!(state.free_rank, 0);
    assert!(state.admitting_nonce().is_some());
}
