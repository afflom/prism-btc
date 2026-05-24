extern crate alloc;
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;

/// JavaScript-visible block header input.
///
/// `wasm-bindgen` requires `pub` struct fields to be `Copy`. `Vec<u8>` is not Copy,
/// so we use private fields with explicit getter methods for the byte arrays.
#[wasm_bindgen]
pub struct JsBlockHeader {
    pub version: u32,
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
}

#[wasm_bindgen]
impl JsBlockHeader {
    #[wasm_bindgen(constructor)]
    pub fn new(
        version: u32,
        prev_hash: Vec<u8>,
        merkle_root: Vec<u8>,
        timestamp: u32,
        bits: u32,
    ) -> Result<JsBlockHeader, JsValue> {
        if prev_hash.len() != 32 {
            return Err(JsValue::from_str("prev_hash must be exactly 32 bytes"));
        }
        if merkle_root.len() != 32 {
            return Err(JsValue::from_str("merkle_root must be exactly 32 bytes"));
        }
        let mut ph = [0u8; 32];
        let mut mr = [0u8; 32];
        ph.copy_from_slice(&prev_hash);
        mr.copy_from_slice(&merkle_root);
        Ok(Self {
            version,
            prev_hash: ph,
            merkle_root: mr,
            timestamp,
            bits,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn prev_hash(&self) -> Vec<u8> {
        self.prev_hash.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn merkle_root(&self) -> Vec<u8> {
        self.merkle_root.to_vec()
    }
}

impl JsBlockHeader {
    pub(crate) fn prev_hash_bytes(&self) -> &[u8; 32] {
        &self.prev_hash
    }
    pub(crate) fn merkle_root_bytes(&self) -> &[u8; 32] {
        &self.merkle_root
    }
}

/// JavaScript-visible block address — the result of addressing a mined
/// block header.
///
/// The nonce is not exposed — it is an internal wire-format detail.
/// Callers receive the 32-byte block hash (the `sha256d` content address)
/// plus its triadic coordinates (stratum, spectrum).
#[wasm_bindgen]
pub struct JsBlockAddress {
    pub stratum: u32,
    pub spectrum: u32,
    hash: [u8; 32],
}

#[wasm_bindgen]
impl JsBlockAddress {
    /// The 32-byte block hash as a Uint8Array.
    pub fn hash(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

impl JsBlockAddress {
    pub(crate) fn new(hash: [u8; 32], stratum: u32, spectrum: u32) -> Self {
        Self {
            hash,
            stratum,
            spectrum,
        }
    }
}
