//! The κ-derivation pipeline — prism-btc's **entire** kernel surface.
//!
//! The kernel exposes one operation: [`address_block`], the κ-derivation
//! of a canonical-form Bitcoin block header. Given 80 ADR-060 wire
//! bytes, it returns the sealed `sha256d:<64hex>` κ-label and the
//! replayable TC-05 witness. The ψ-pipeline is **total** over
//! well-formed carriers — for every valid input, a Grounded κ-label.
//!
//! **The kernel does not embed PoW admission.** Bitcoin's
//! `block_hash ≤ target` relation is a protocol-level observation on
//! the κ-label — host code that wants to mine reads the κ-label's
//! 32-byte digest and compares it to a target directly. The kernel
//! makes no claim about mining: no `MiningOutcome`, no
//! `MiningFailure`, no `TargetCommitment`, no thread-local target
//! slot, no search loop, no closure form. PoW search lives in protocol
//! code that operates on the κ-labels this kernel emits.
//!
//! Body of one κ-derivation:
//!
//! 1. Wrap the 80-byte canonical-form input in a
//!    [`BlockHeaderCarrier`].
//! 2. [`BitcoinAddressModel`]'s
//!    `forward` runs the shared ψ-tower: ψ₁–ψ₈ thread the borrowed
//!    carrier through; ψ₉ folds it through the `sha256d` σ-axis to mint
//!    the `sha256d:<64hex>` κ-label (the conventional block hash in
//!    display order).
//! 3. Foundation's `run_route` evaluates the model's pinned
//!    `C = EmptyCommitment` (no admission check) and seals a
//!    `Grounded<BlockAddressLabel>`. [`AddressOutcome`] extracts the
//!    κ-label + replayable TC-05 `AddressWitness`.
//!
//! The returned [`AddressOutcome`] is the same shared outcome surface
//! every UOR-ADDR realization returns — κ-label + witness. No
//! eagerly-cached projections; the host derives whatever it needs
//! (digest, observables, admission against a target) from the κ-label
//! and the canonical-form input it certifies.

use uor_addr::AddressOutcome;

use crate::model::{BitcoinAddressModel, BlockHeaderCarrier, BLOCK_ADDRESS_LABEL_BYTES};

/// κ-label byte width for the `sha256d` σ-axis (`sha256d:<64hex>` = 72).
const LABEL: usize = BLOCK_ADDRESS_LABEL_BYTES;

/// The block-address outcome — κ-label + replayable TC-05 witness, as
/// returned by every UOR-ADDR realization.
pub type BlockAddress = AddressOutcome<LABEL, 32>;

/// **Compute the κ-label of an 80-byte canonical-form Bitcoin block
/// header.** The kernel's entire admission body.
///
/// Wraps the bytes in a [`BlockHeaderCarrier`], runs the shared ψ-tower
/// via [`BitcoinAddressModel`]'s
/// `forward`, and returns the sealed `sha256d:<64hex>` κ-label + its
/// witness. The ψ-pipeline is total over well-formed carriers, so this
/// returns a sealed outcome unconditionally.
///
/// # Mining is host code
///
/// To find a `(prev, merkle, time, bits, nonce)` whose κ-label admits a
/// PoW target, host code walks candidates and calls this function per
/// candidate — the search lives there, not here:
///
/// ```ignore
/// for nonce in 0u32..=u32::MAX {
///     let wire = prism_btc::serialize_header(&header, nonce);
///     let outcome = prism_btc::address_block(&wire);
///     let digest = prism_btc::sha256d_display(&wire);
///     if target.is_satisfied_by_bytes(&digest) {
///         // admitted — submit `wire` + witness
///         return Some(outcome);
///     }
/// }
/// ```
///
/// The kernel exposes only the κ-derivation; the search is the host's
/// honest concern (CPU loop, GPU kernel, hardware miner, distributed
/// pool — whichever fits the host).
///
/// # Panics
///
/// Foundation's `run_route` is total over well-formed
/// `BlockHeaderCarrier` inputs and `EmptyCommitment` always admits, so
/// `forward` always returns `Ok`. A panic here would indicate a
/// substrate-level shape violation — unreachable for any 80-byte input.
#[must_use]
pub fn address_block(canonical_header_bytes: &[u8; 80]) -> BlockAddress {
    use prism::pipeline::PrismModel;

    let carrier = BlockHeaderCarrier::new(canonical_header_bytes);
    let grounded = BitcoinAddressModel::forward(carrier)
        .expect("ψ-pipeline is total over well-formed 80-byte carriers");
    AddressOutcome::<LABEL, 32>::from_grounded(&grounded)
        .expect("outcome extracts from sealed Grounded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Bits, BlockHeader, MerkleRoot, Timestamp, Version};
    use crate::ops::header::serialize_header;
    use crate::ops::sha256::sha256d_display;

    fn fixture_header(timestamp: u32) -> BlockHeader {
        BlockHeader {
            version: Version(1),
            prev_hash: [0u8; 32],
            merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
            timestamp: Timestamp(timestamp),
            bits: Bits(0x207fffff),
        }
    }

    #[test]
    fn address_block_emits_a_sha256d_kappa_label() {
        let wire = serialize_header(&fixture_header(1_700_000_000), 0);
        let outcome = address_block(&wire);
        assert!(outcome.address.starts_with("sha256d:"));
        assert_eq!(outcome.address.len(), 72);
    }

    #[test]
    fn address_block_kappa_label_re_derives_to_the_sha256d_digest() {
        // L5: the κ-label hex tail is the SHA-256d digest in display
        // order — re-derivable by replaying the σ-axis on the canonical
        // input.
        let wire = serialize_header(&fixture_header(1_700_000_001), 0xCAFE);
        let outcome = address_block(&wire);
        let derived_digest = sha256d_display(&wire);
        let hex_tail = &outcome.address.as_str()[8..];
        let mut expected_hex = String::with_capacity(64);
        for b in derived_digest {
            expected_hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex_tail, expected_hex);
    }

    #[test]
    fn address_block_witness_replays_to_the_attested_kappa_label() {
        // TC-05: the witness re-certifies the κ-label without
        // re-invoking the σ-axis.
        let wire = serialize_header(&fixture_header(1_700_000_002), 42);
        let outcome = address_block(&wire);
        let replayed = outcome.witness.verify().expect("witness replays");
        assert_eq!(replayed, outcome.address);
    }

    #[test]
    fn address_block_is_deterministic_in_the_canonical_input() {
        let wire = serialize_header(&fixture_header(1_700_000_003), 0x12345678);
        let a = address_block(&wire);
        let b = address_block(&wire);
        assert_eq!(a.address, b.address);
    }
}
