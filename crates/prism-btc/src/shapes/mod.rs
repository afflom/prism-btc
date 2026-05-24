//! Foundation substitution-axis selections for the Bitcoin addressing
//! realization (UOR-ADDR common surface).
//!
//! - [`bounds::PrismBtcBounds`] — the `HostBounds` capacity profile.
//!   prism-btc binds uor-addr's shared [`AddrBounds`](uor_addr::AddrBounds)
//!   profile verbatim (ADR-037 single capacity profile); the alias keeps
//!   the prism-btc-facing name while reusing the framework profile.
//! - [`hasher::Sha256dHasher`] — the `sha256d` σ-axis: Bitcoin's
//!   double-SHA-256 as a foundation [`Hasher`](prism::vocabulary::Hasher)
//!   **and** a uor-addr [`AddrHash`](uor_addr::AddrHash). The canonical
//!   content-addressing primitive for block headers.
//!
//! `HostTypes` is bound to `prism::vocabulary::DefaultHostTypes` at the
//! [`crate::model::BitcoinAddressModel`] declaration. The ψ-tower is
//! uor-addr's shared, format-independent
//! [`AddressResolverTuple`](uor_addr::AddressResolverTuple) — prism-btc
//! carries no resolver code (ADR-060 carrier model: canonicalization at
//! the host boundary, ψ₉ folds the carrier through the σ-axis).

pub mod bounds;
pub mod hasher;

pub use bounds::PrismBtcBounds;
pub use hasher::Sha256dHasher;
