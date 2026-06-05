use crate::types::{JsBlockAddress, JsBlockHeader};
use prism_btc::{
    address_block, serialize_header, sha256d_display, Bits, BlockHeader, KappaObservables,
    MerkleRoot, Target, Timestamp, Version,
};
use wasm_bindgen::prelude::*;

/// Mine a block header from JavaScript — the **wasm protocol layer**'s
/// PoW search over the kernel's κ-derivation primitive.
///
/// The kernel (`prism_btc::address_block`) emits κ-labels for canonical
/// block headers; admission is a host-side observation. This bridge
/// walks the 32-bit nonce space, derives each candidate's κ, compares
/// the digest to the target, and returns the receiver-side coordinates
/// of the first candidate that admits.
///
/// Returns a `JsBlockAddress` on success, or throws a JS error string
/// when the nonce space exhausts without admission (vary the template
/// — timestamp / extranonce — and retry).
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
        let wire = serialize_header(&header, nonce);
        let _ = address_block(&wire); // κ-derivation through the kernel
        let digest = sha256d_display(&wire);
        if target.is_satisfied_by_bytes(&digest) {
            let coords = KappaObservables::from_digest(&digest).coords;
            return Ok(JsBlockAddress::new(
                coords.datum,
                coords.stratum,
                coords.spectrum,
            ));
        }
    }
    Err(JsValue::from_str(
        "nonce space exhausted without admission — vary the template (timestamp / extranonce) and retry",
    ))
}
