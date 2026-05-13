//! Foundation substitution-axis selections (architecture §3).
//!
//! - [`bounds::PrismBtcBounds`] — the `HostBounds` profile.
//! - [`hasher::Sha256dHasher`] — the `Hasher` axis body (pure-Rust
//!   SHA-256-then-SHA-256). The canonical content-addressing primitive.
//!
//! `HostTypes` is bound to `uor_foundation::DefaultHostTypes` at the
//! `BitcoinMiningModel` declaration site directly. `ResolverTuple`
//! lives in [`crate::resolvers`] as `BitcoinResolverTuple`.
//!
//! The atomic Bitcoin feature primitives (`Version`, `PrevHash`,
//! `MerkleRoot`, `Timestamp`, `Bits`, `Nonce`, `Target` — see
//! ARCHITECTURE.md §2.1) are realized at the byte-range level on the
//! composite shapes [`crate::model::TemplatePrefix`] (76-byte
//! `partition_product`) and [`crate::model::MiningTask`] (108-byte
//! `partition_product`): each composite declares its
//! `PartitionProductFields` table naming the per-factor byte offsets
//! and lengths. The 80-byte wire-format `MiningResult` site count
//! matches the canonical header width.

pub mod bounds;
pub mod hasher;

pub use bounds::PrismBtcBounds;
pub use hasher::Sha256dHasher;
