//! Foundation substitution-axis selections and Bitcoin atomic feature
//! primitives (architecture §2.1, §3).
//!
//! - [`bounds::PrismBtcBounds`] — the `HostBounds` profile.
//! - [`hasher::Sha256dHasher`] — the `Hasher` axis body (pure-Rust
//!   SHA-256-then-SHA-256). The canonical content-addressing primitive.
//! - [`primitives`] — the atomic Bitcoin feature primitives
//!   (`Version`, `PrevHash`, `MerkleRoot`, `Timestamp`, `Bits`,
//!   `Nonce`, `Target`).
//!
//! `HostTypes` is bound to `uor_foundation::DefaultHostTypes` at the
//! `BitcoinMiningModel` declaration site directly.
//! `ResolverTuple` lives in [`crate::resolvers`] as
//! `BitcoinResolverTuple`.

pub mod bounds;
pub mod hasher;
pub mod primitives;

pub use bounds::PrismBtcBounds;
pub use hasher::Sha256dHasher;
pub use primitives::{Bits, MerkleRoot, Nonce, PrevHash, Target, Timestamp, Version};
