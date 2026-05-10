//! prism-btc operations: host-side helpers for assembling the inputs
//! the typed-iso surface evaluates.
//!
//! Foundation 0.4.1's catamorphism evaluates the
//! [`crate::verbs::nonce_fiber_traversal`] verb's term arena
//! end-to-end, so prism-btc no longer carries an implementor-side W32
//! search runtime. What remains in `ops` is purely host-side wire
//! assembly: pure-Rust SHA-256 (the algorithm body
//! [`crate::shapes::hasher::Sha256dHasher`] uses internally), the
//! 80-byte canonical header serializer, and the merkle-root reducer
//! the bitcoind boundary uses for coinbase commitment.

pub mod header;
pub mod merkle;
pub mod sha256;

pub use header::{serialize_header, serialize_prefix, splice_nonce};
pub use merkle::merkle_root_internal;
pub use sha256::{sha256, sha256d_display, sha256d_internal};
