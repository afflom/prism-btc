extern crate alloc;
use alloc::format;

use crate::types::{JsBlockHeader, JsMiningResult};
use prism_btc::{mine, Bits, BlockHeader, MerkleRoot, Target, Timestamp, Version};
use wasm_bindgen::prelude::*;

/// Mine a block header from JavaScript.
///
/// Returns a `JsMiningResult` on success, or throws a JS error string on failure.
///
/// # Arguments
/// * `js_header` — block header fields (version, prev_hash, merkle_root, timestamp, bits)
/// * `nbits`     — compact target encoding (e.g. `0x1d00ffff` for genesis)
#[wasm_bindgen]
pub fn mine_block(js_header: &JsBlockHeader, nbits: u32) -> Result<JsMiningResult, JsValue> {
    let header = BlockHeader {
        version: Version(js_header.version),
        prev_hash: *js_header.prev_hash_bytes(),
        merkle_root: MerkleRoot::from_bytes(*js_header.merkle_root_bytes()),
        timestamp: Timestamp(js_header.timestamp),
        bits: Bits(js_header.bits),
    };

    mine(&header, Target::new(nbits))
        .map(|outcome| {
            JsMiningResult::new(
                outcome.observables.coords.datum,
                outcome.observables.coords.stratum,
                outcome.observables.coords.spectrum,
            )
        })
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}
