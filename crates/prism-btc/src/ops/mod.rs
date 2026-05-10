//! prism-btc operations: the runtime that walks the foundation-typed
//! structure.
//!
//! The σ-projection's evaluator (pure-Rust SHA-256d), the canonical
//! 80-byte header layout, the merkle-root reduction, and the W32 nonce
//! fiber traversal are the prism implementor's responsibility per
//! architecture §13. Foundation 0.4.1 supplies the typed-iso surface
//! (`PrismModel<H, B, A>`, ADR-020) and the runtime catamorphism
//! (`pipeline::run_route`, ADR-022); this module is the runtime that
//! finds the admitting fiber point so that surface has an input to mint
//! its `Grounded` over.

pub mod header;
pub mod merkle;
pub mod sha256;
pub mod sigma;
pub mod traversal;

pub use header::{serialize_header, serialize_prefix, splice_nonce};
pub use merkle::merkle_root_internal;
pub use sha256::{sha256, sha256d_display, sha256d_internal};
pub use sigma::{sigma_project, sigma_project_prefix};
pub use traversal::{traverse_sequential, Cancel, Cancelled, FiberOutcome, NeverCancel};

#[cfg(feature = "std")]
pub use traversal::traverse_parallel;
