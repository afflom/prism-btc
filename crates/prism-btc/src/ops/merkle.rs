//! Bitcoin's wire-format merkle root, as the **Kleene-closure
//! recurrence** of pair-and-rehash under SHA-256d.
//!
//! Given a coinbase txid and a list of other transaction txids (in
//! template order), the merkle root is the unique fixed point of the
//! Bitcoin merkle recurrence:
//!
//! > `merkle_root([root]) = root`
//! > `merkle_root(leaves) = merkle_root(pair_up(leaves))`
//!
//! where `pair_up` folds each adjacent pair under SHA-256d on
//! internal-order bytes, duplicating the last element on odd arity
//! (Bitcoin's discipline). The body is the recurrence equation — base
//! case is one leaf; recursive case is a level descent on the
//! canonical-form sequence — not a procedural stack machine.
//!
//! Per-level `Vec` materializes the canonical-form sequence at each
//! recursion depth; this is representation (the operation defines a
//! sequence at each level), not procedural intrusion.
//!
//! Runtime: prism-btc's pure-Rust SHA-256d (no dependency on the
//! `bitcoin` crate's hashing). Bitcoin txids are stored in *internal*
//! byte order (least-significant byte first); the merkle pairing
//! concatenates internal-order bytes and applies SHA-256d, also in
//! internal byte order.

use crate::ops::sha256::sha256d_internal;

/// Compute the merkle root of `[coinbase_txid, *other_txids]` in
/// internal byte order. The root is what gets placed in
/// `BlockHeader.merkle_root`.
pub fn merkle_root_internal(coinbase_txid: &[u8; 32], other_txids: &[[u8; 32]]) -> [u8; 32] {
    let initial: Vec<[u8; 32]> = core::iter::once(*coinbase_txid)
        .chain(other_txids.iter().copied())
        .collect();
    merkle_fold(&initial)
}

/// The structural recurrence on the canonical-form sequence: either
/// the base case (one root) or one level descent (the next-level
/// `pair_up` image, recursed).
fn merkle_fold(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [root] => *root,
        more => {
            let next: Vec<[u8; 32]> = more
                .chunks(2)
                .map(|pair| match pair {
                    [a, b] => pair_hash(a, b),
                    [a] => pair_hash(a, a), // Bitcoin's odd-tail duplication
                    _ => unreachable!("chunks(2) yields slices of length 1 or 2"),
                })
                .collect();
            merkle_fold(&next)
        }
    }
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
