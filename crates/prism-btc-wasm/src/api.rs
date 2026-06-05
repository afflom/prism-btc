use crate::types::{JsBlockAddress, JsBlockHeader};
use prism_btc::{admit, Bits, BlockHeader, MerkleRoot, Target, Timestamp, Version};
use wasm_bindgen::prelude::*;

/// Mine a block header from JavaScript.
///
/// Realizes [`prism_btc::admit`] — the kernel's admission closure
/// (the Kleene-star fixed point of per-nonce recognition over the
/// [`prism_btc::NonceOrbit`]) — and projects the recognized outcome's
/// receiver-side observables to JS. **No explicit loop**: the closure
/// is the declarative stream-fold the kernel exposes; the wasm bridge
/// is the JS-side projection of its result.
///
/// Returns a `JsBlockAddress` on success, or throws a JS error string
/// on failure (orbit exhaustion: vary the template — timestamp /
/// extranonce — and retry).
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

    admit(&header, Target::new(nbits))
        .map(|outcome| {
            let coords = outcome.observables().coords;
            JsBlockAddress::new(coords.datum, coords.stratum, coords.spectrum)
        })
        .ok_or_else(|| {
            JsValue::from_str(
                "nonce orbit exhausted without admission — vary the template (timestamp / extranonce) and retry",
            )
        })
}
