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
//! The architecture's atomic Bitcoin feature primitives
//! (`Version`, `PrevHash`, `MerkleRoot`, `Timestamp`, `Bits`, `Nonce`,
//! `Target` — see ARCHITECTURE.md §2.1) are conceptual; the runtime
//! carrier for `MiningTask` is the flat `[u8; 108]` byte payload that
//! [`crate::model::MiningTask`]'s `PartitionProductFields` impl
//! indexes via the host-supplied template, with the 80-byte wire-
//! format `MiningResult` site count matching the canonical header
//! width. No per-primitive `ConstrainedTypeShape` impls are declared
//! today — the composition lives at the byte-range level on
//! `TemplatePrefix` / `MiningTask` directly.

pub mod bounds;
pub mod hasher;

pub use bounds::PrismBtcBounds;
pub use hasher::Sha256dHasher;
