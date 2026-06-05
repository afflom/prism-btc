//! `PrismBtcBounds` — prism-btc's `HostBounds` capacity profile.
//!
//! Per UOR-ADDR's "single capacity profile" commitment (ADR-037), every
//! addressing realization binds the **same** [`uor_addr::AddrBounds`] profile. The
//! Bitcoin realization is no exception: `PrismBtcBounds` is a transparent
//! alias for [`uor_addr::AddrBounds`], so prism-btc reuses the framework's
//! capacity profile rather than declaring a parallel one.
//!
//! Under ADR-060 the per-ψ-stage byte-width ceilings
//! (`TERM_VALUE_MAX_BYTES`, `AXIS_OUTPUT_BYTES_MAX`,
//! `ROUTE_*_BUFFER_BYTES`) no longer exist: the carrier is a
//! source-polymorphic [`prism::operation::TermValue`] with no size cap.
//! `AddrBounds` retains only the structural-count / catamorphism-trace
//! caps (`FINGERPRINT_MAX_BYTES = 32`, `NERVE_SITES_MAX = 74`, …). Its
//! 74-site ceiling comfortably admits prism-btc's 72-byte
//! `sha256d:<64hex>` κ-label.

/// prism-btc's capacity profile — the shared UOR-ADDR
/// [`AddrBounds`](uor_addr::AddrBounds) profile.
pub type PrismBtcBounds = uor_addr::AddrBounds;

#[cfg(test)]
mod tests {
    use super::*;
    use prism::vocabulary::HostBounds;

    #[test]
    fn bounds_is_the_shared_addr_profile() {
        // FINGERPRINT_MAX_BYTES = 32 (one Hasher<32> σ-axis).
        assert_eq!(<PrismBtcBounds as HostBounds>::FINGERPRINT_MAX_BYTES, 32);
        // The site ceiling admits the 72-byte sha256d κ-label.
        let nerve_sites = <PrismBtcBounds as HostBounds>::NERVE_SITES_MAX;
        assert!(nerve_sites >= 72, "AddrBounds admits the 72-byte κ-label");
    }
}
