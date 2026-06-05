//! WebAssembly bindings for the prism-btc mining library.
//!
//! This crate exposes the [`mine_block`] function and
//! supporting types to JavaScript via `wasm-bindgen`.  `mine_block` is the
//! **bridge layer** — it walks the 32-bit nonce space invoking the kernel's
//! single-recognition `prism_btc::mine_at` per candidate, and projects the first
//! admitting outcome's observables back to JS.  It is the only crate in the
//! workspace with a `wasm-bindgen` dependency; all Bitcoin and UOR logic lives
//! in `prism-btc`.
//!
//! ## JS surface
//!
//! ```js
//! import init, { JsBlockHeader, mine_block } from './prism_btc_wasm.js';
//! await init();
//!
//! const header = new JsBlockHeader(1, prevHashBytes, merkleRootBytes, timestamp, bits);
//! const result = mine_block(header, 0x1d00ffff);
//! console.log(result.stratum, result.spectrum, result.hash());
//! ```
//!
//! Build with `wasm-pack build crates/prism-btc-wasm --target web`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod api;
pub mod types;

pub use api::mine_block;
pub use types::{JsBlockAddress, JsBlockHeader};
