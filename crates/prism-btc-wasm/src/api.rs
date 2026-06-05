extern crate alloc;
use alloc::format;

use crate::types::{JsBlockAddress, JsBlockHeader};
use prism_btc::{
    mine_at, Bits, BlockHeader, MerkleRoot, MiningFailure, Target, Timestamp, Version,
};
use wasm_bindgen::prelude::*;

/// Mine a block header from JavaScript.
///
/// The kernel exposes one admission body — `prism_btc::mine_at` — which
/// recognizes one `(header, nonce)` candidate. This wasm bridge owns
/// the iteration: it walks the 32-bit nonce space invoking `mine_at`
/// per candidate and projects the first admitting outcome's
/// observables back to JS.
///
/// Returns a `JsBlockAddress` on success, or throws a JS error string
/// on failure.
///
/// # Arguments
/// * `js_header` — block header fields (version, prev_hash, merkle_root, timestamp, bits)
/// * `nbits`     — compact target encoding (e.g. `0x1d00ffff` for genesis)
#[wasm_bindgen]
pub fn mine_block(js_header: &JsBlockHeader, nbits: u32) -> Result<JsBlockAddress, JsValue> {
    let header = BlockHeader {
        version: Version(js_header.version),
        prev_hash: *js_header.prev_hash_bytes(),
        merkle_root: MerkleRoot::from_bytes(*js_header.merkle_root_bytes()),
        timestamp: Timestamp(js_header.timestamp),
        bits: Bits(js_header.bits),
    };
    let target = Target::new(nbits);

    for nonce in 0u32..=u32::MAX {
        match mine_at(&header, target, nonce) {
            Ok(outcome) => {
                return Ok(JsBlockAddress::new(
                    outcome.observables.coords.datum,
                    outcome.observables.coords.stratum,
                    outcome.observables.coords.spectrum,
                ));
            }
            Err(MiningFailure::DidNotAdmit { .. }) => continue,
            Err(e @ MiningFailure::PipelineFailure) => {
                return Err(JsValue::from_str(&format!("{:?}", e)));
            }
        }
    }
    Err(JsValue::from_str(
        "nonce space exhausted without admission — vary the template (timestamp / extranonce) and retry",
    ))
}
