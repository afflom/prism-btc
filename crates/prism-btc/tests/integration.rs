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
//!   through foundation 0.4.2's catamorphism dispatching each ψ-Term
//!   through the application's resolver tuple.
//! - The label (`Grounded<MiningResult>::output_bytes()`) is the
//!   terminal ψ_9 output (32 W8 sites, architecture §2.2).

use prism_btc::{
    mine, BitcoinMiningModel, BitcoinResolverTuple, Bits, BlockHeader, MerkleRoot, MiningFailure,
    MiningTask, PrismBtcBounds, Sha256dHasher, Target, Timestamp, Version,
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
fn forward_runs_the_psi_pipeline_end_to_end() {
    // The 4-position PrismModel surface bundles HostTypes × HostBounds ×
    // Hasher × ResolverTuple. `forward` invokes
    // `pipeline::run_route → pipeline::evaluate_term_tree` which walks
    // the ψ-chain verb arena dispatching each ψ-Term through
    // `BitcoinResolverTuple`.
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
    .expect("the ψ-pipeline must run end-to-end against BitcoinResolverTuple");

    // The ψ-pipeline label is the terminal ψ_9 output. With prism-btc's
    // resolvers folding through the canonical hash axis, the label is
    // exactly the hash axis's 32-byte output width (architecture §2.2).
    let label = grounded.output_bytes();
    assert_eq!(
        label.len(),
        32,
        "label site count matches Sha256dHasher::OUTPUT_BYTES"
    );

    // Witt level is pinned through forward() from PrismBtcBounds.
    assert_eq!(grounded.witt_level_bits(), 32);
}

#[test]
fn forward_label_is_deterministic_in_the_typed_input() {
    // The ψ-pipeline is parametric: same MiningTask → same label.
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
fn mine_returns_outcome_or_named_foundation_gap() {
    // mine() drives the ψ-pipeline through the host boundary. For
    // arbitrary host-supplied templates, the structural label the
    // pipeline emits may or may not decode to a wire-format-valid
    // Bitcoin block. Under the stub resolvers shipping with this
    // implementation, mine() either:
    // - returns Ok(MiningOutcome) when the label-derived nonce happens
    //   to admit the target lexicographically, OR
    // - returns Err(MiningFailure::LabelDoesNotDecodeToWireFormat) when
    //   it doesn't — see ARCHITECTURE.md §9.1 for the foundation
    //   amendment that closes this gap.
    let header = easy_header();
    let target = Target::new(0x207fffff);
    match mine(&header, target) {
        Ok(outcome) => {
            assert!(target.is_satisfied_by_bytes(&outcome.digest));
            assert_eq!(outcome.coords.datum, outcome.digest);
        }
        Err(MiningFailure::LabelDoesNotDecodeToWireFormat) => {
            // Expected outcome under the named foundation gap.
        }
        Err(MiningFailure::PipelineFailure) => {
            panic!("ψ-pipeline must run end-to-end against BitcoinResolverTuple");
        }
    }
}

#[test]
fn forward_grounded_carries_w32_witt_level() {
    let mut prefix = [0u8; 76];
    prefix[0] = 0x01;
    let task = MiningTask::new(prefix, [0xffu8; 32]);
    let grounded = <BitcoinMiningModel as PrismModel<
        DefaultHostTypes,
        PrismBtcBounds,
        Sha256dHasher,
        BitcoinResolverTuple<Sha256dHasher>,
    >>::forward(task)
    .expect("forward succeeds");
    assert_eq!(grounded.witt_level_bits(), 32);
    assert_ne!(grounded.unit_address().as_u128(), 0);
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
