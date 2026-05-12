//! `prism_btc_wasm` integration smoke tests.
//!
//! The wasm bindings expose [`prism_btc::mine`] to JavaScript callers
//! via [`mine_block`]. These tests exercise the binding surface: header
//! construction, mine() invocation, JsMiningResult shape. The fail-
//! closed mining contract (architecture §6) — `mine()` returns `Ok`
//! only when the κ-derived wire-format header genuinely admits — is
//! pinned by the prism-btc crate's integration + V&V suites; the wasm
//! tests here verify the binding layer faithfully surfaces those
//! semantics.

use prism_btc_wasm::{mine_block, JsBlockHeader};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Permissive-target template — the κ-derivation lands on an
/// admitting nonce, exercising the success path.
#[wasm_bindgen_test]
fn mine_block_succeeds_on_permissive_target() {
    let merkle_root: Vec<u8> = vec![
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];

    // For the binding-surface smoke test, sweep a small timestamp
    // variation space to find an admitting κ-derivation — the same
    // template-variation discipline `PrismMiner::mine_one_block`
    // employs at the bitcoind boundary (architecture §7).
    for timestamp in 1_700_000_000u32..1_700_001_024 {
        let header =
            JsBlockHeader::new(1, vec![0u8; 32], merkle_root.clone(), timestamp, 0x207fffff)
                .expect("valid header");
        if let Ok(result) = mine_block(&header, 0x207fffff) {
            let hash = result.hash();
            assert_eq!(hash.len(), 32, "block hash is 32 bytes");
            return;
        }
    }
    panic!("permissive target must admit within 1024 timestamp variations");
}
