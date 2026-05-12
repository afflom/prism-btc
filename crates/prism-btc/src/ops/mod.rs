//! Host-boundary wire-format helpers.
//!
//! These are **not** part of the ψ-pipeline transform — they are
//! host-side byte-assembly utilities the bitcoind boundary uses to
//! materialise the wire-format Bitcoin block bytes for `submitblock`.
//! The ψ-pipeline's resolver chain produces the 80-byte κ-label
//! (architecture §6); the helpers here serialize headers, derive the
//! coinbase merkle root, and compute SHA-256d digests at the host
//! boundary (architecture §7).
//!
//! - [`header`] — canonical 80-byte header serialization +
//!   nonce-splicing.
//! - [`merkle`] — pairwise-SHA-256d merkle root reduction over
//!   transaction txids.
//! - [`sha256`] — pure-Rust SHA-256 / SHA-256d (the algorithm body
//!   [`crate::shapes::hasher::Sha256dHasher`] uses internally for the
//!   canonical hash axis).

pub mod header;
pub mod merkle;
pub mod sha256;

pub use header::{serialize_header, serialize_prefix, splice_nonce};
pub use merkle::merkle_root_internal;
pub use sha256::{sha256, sha256d_display, sha256d_internal};
