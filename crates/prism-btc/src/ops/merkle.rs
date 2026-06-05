//! Bitcoin's wire-format merkle root, as the **idempotent closure** of
//! pair-and-rehash under SHA-256d.
//!
//! Given a coinbase txid and a list of other transaction txids (in
//! template order), the merkle root is the unique fixed point of the
//! Bitcoin merkle recurrence: pair adjacent nodes, duplicate odd
//! tails, repeat. This module realizes that closure as a **tournament
//! reduction** identical in shape to
//! [`crate::composition::merkle_root`] — each leaf folds into a
//! stack of `(level, partial_root)` entries; same-level top entries
//! merge eagerly; finalize collapses with odd-tail duplication. Fully
//! stack-allocated; no `Vec`, no per-level heap materialization.
//!
//! Runtime: prism-btc's pure-Rust SHA-256d (no dependency on the
//! `bitcoin` crate's hashing). Bitcoin txids are stored in *internal*
//! byte order (least-significant byte first); the merkle pairing
//! concatenates internal-order bytes and applies SHA-256d, also in
//! internal byte order.

use crate::ops::sha256::sha256d_internal;

/// Stack depth ceiling for the wire-format merkle's tournament
/// reduction — supports trees with up to `2^31` leaves, well above any
/// block within Bitcoin consensus tx-count limits.
pub const MERKLE_INTERNAL_STACK_DEPTH: usize = 32;

/// Compute the merkle root of `[coinbase_txid, *other_txids]` in
/// internal byte order. The root is what gets placed in
/// `BlockHeader.merkle_root`.
///
/// # Panics
/// Debug-asserts if the leaf count exceeds
/// `2^MERKLE_INTERNAL_STACK_DEPTH` — unreachable for any block within
/// Bitcoin consensus limits.
pub fn merkle_root_internal(coinbase_txid: &[u8; 32], other_txids: &[[u8; 32]]) -> [u8; 32] {
    let mut stack: [(u8, [u8; 32]); MERKLE_INTERNAL_STACK_DEPTH] =
        [(0u8, *coinbase_txid); MERKLE_INTERNAL_STACK_DEPTH];
    let mut depth: usize = 0;

    let leaves = core::iter::once(coinbase_txid).chain(other_txids.iter());
    for leaf in leaves {
        debug_assert!(
            depth < MERKLE_INTERNAL_STACK_DEPTH,
            "merkle stack overflow at >2^{} leaves",
            MERKLE_INTERNAL_STACK_DEPTH
        );
        stack[depth] = (0, *leaf);
        depth += 1;
        // Eagerly merge same-level top entries.
        while depth >= 2 && stack[depth - 1].0 == stack[depth - 2].0 {
            let r = stack[depth - 1].1;
            let l = stack[depth - 2].1;
            let level = stack[depth - 1].0;
            stack[depth - 2] = (level + 1, pair_hash(&l, &r));
            depth -= 1;
        }
    }

    // Finalize with Bitcoin's odd-tail discipline.
    while depth > 1 {
        let top_level = stack[depth - 1].0;
        let next_level = stack[depth - 2].0;
        if top_level == next_level {
            let r = stack[depth - 1].1;
            let l = stack[depth - 2].1;
            stack[depth - 2] = (top_level + 1, pair_hash(&l, &r));
            depth -= 1;
        } else {
            let top = stack[depth - 1].1;
            stack[depth - 1] = (top_level + 1, pair_hash(&top, &top));
        }
    }

    stack[0].1
}

#[inline]
fn pair_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d_internal(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_of_single_coinbase_is_the_coinbase_txid() {
        let coinbase: [u8; 32] = [0x42; 32];
        let root = merkle_root_internal(&coinbase, &[]);
        assert_eq!(root, coinbase);
    }

    #[test]
    fn merkle_pair_matches_manual_sha256d() {
        let cb: [u8; 32] = [0xaa; 32];
        let other: [u8; 32] = [0xbb; 32];
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&cb);
        concat[32..].copy_from_slice(&other);
        let expected = sha256d_internal(&concat);
        let root = merkle_root_internal(&cb, &[other]);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_three_leaves_duplicates_last() {
        // 3 txids → at level 0 [a, b, c] → odd, duplicate c → [a, b, c, c]
        // → level 1 [d2(a||b), d2(c||c)]
        // → level 2 [d2(level1[0] || level1[1])]
        let a: [u8; 32] = [0x01; 32];
        let b: [u8; 32] = [0x02; 32];
        let c: [u8; 32] = [0x03; 32];
        let mut ab = [0u8; 64];
        ab[..32].copy_from_slice(&a);
        ab[32..].copy_from_slice(&b);
        let l1_0 = sha256d_internal(&ab);
        let mut cc = [0u8; 64];
        cc[..32].copy_from_slice(&c);
        cc[32..].copy_from_slice(&c);
        let l1_1 = sha256d_internal(&cc);
        let mut top = [0u8; 64];
        top[..32].copy_from_slice(&l1_0);
        top[32..].copy_from_slice(&l1_1);
        let expected = sha256d_internal(&top);

        let root = merkle_root_internal(&a, &[b, c]);
        assert_eq!(root, expected);
    }
}
