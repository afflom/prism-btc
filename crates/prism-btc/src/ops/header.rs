//! `HeaderSerialization` — the canonical 80-byte Bitcoin block header layout.
//!
//! Runtime: assembles the 80-byte wire form from `(version, prev_hash,
//! merkle_root, timestamp, bits, nonce)`.
//!
//! Structural identity: the layout is a `Term::Application` chain of
//! `depth-projection` insertions over fixed byte ranges; the
//! foundation-vocabulary form lives in `prism::operation`.

use crate::domain::{BlockHeader, MerkleRoot};

/// Serialise a header + nonce to the canonical 80-byte wire layout.
///
/// Layout (multi-byte fields are little-endian per the protocol):
/// ```text
/// [0..4)   version     LE u32
/// [4..36)  prev_hash   32 bytes, internal byte order
/// [36..68) merkle_root 32 bytes, internal byte order
/// [68..72) timestamp   LE u32
/// [72..76) bits        LE u32
/// [76..80) nonce       LE u32
/// ```
pub fn serialize_header(header: &BlockHeader, nonce: u32) -> [u8; 80] {
    let mut buf = [0u8; 80];
    buf[0..4].copy_from_slice(&header.version.0.to_le_bytes());
    buf[4..36].copy_from_slice(&header.prev_hash);
    buf[36..68].copy_from_slice(merkle_root_bytes(&header.merkle_root));
    buf[68..72].copy_from_slice(&header.timestamp.0.to_le_bytes());
    buf[72..76].copy_from_slice(&header.bits.0.to_le_bytes());
    buf[76..80].copy_from_slice(&nonce.to_le_bytes());
    buf
}

#[inline]
fn merkle_root_bytes(root: &MerkleRoot) -> &[u8; 32] {
    root.as_bytes()
}

/// Serialise a 76-byte template prefix (version, prev_hash, merkle_root,
/// timestamp, bits) — the bytes that are fixed for one (template,
/// extranonce) pair. The W32 fiber's free dimension is the trailing 4-byte
/// nonce that this function does NOT write.
pub fn serialize_prefix(header: &BlockHeader) -> [u8; 76] {
    let mut buf = [0u8; 76];
    buf[0..4].copy_from_slice(&header.version.0.to_le_bytes());
    buf[4..36].copy_from_slice(&header.prev_hash);
    buf[36..68].copy_from_slice(merkle_root_bytes(&header.merkle_root));
    buf[68..72].copy_from_slice(&header.timestamp.0.to_le_bytes());
    buf[72..76].copy_from_slice(&header.bits.0.to_le_bytes());
    buf
}

/// Splice a nonce into bytes [76..80) of an 80-byte wire-format header.
/// Used by the wire-byte boundary in `prism-btc-node` to assemble the
/// final block from a prefix + winning nonce.
pub fn splice_nonce(prefix: &[u8; 76], nonce: u32) -> [u8; 80] {
    let mut buf = [0u8; 80];
    buf[..76].copy_from_slice(prefix);
    buf[76..80].copy_from_slice(&nonce.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Bits, BlockHeader, MerkleRoot, Timestamp, Version};

    fn genesis_header() -> BlockHeader {
        let merkle: [u8; 32] = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        BlockHeader {
            version: Version(1),
            prev_hash: [0u8; 32],
            merkle_root: MerkleRoot::from_bytes(merkle),
            timestamp: Timestamp(1231006505),
            bits: Bits(0x1d00ffff),
        }
    }

    #[test]
    fn header_layout_matches_protocol() {
        let h = genesis_header();
        let buf = serialize_header(&h, 2083236893);
        assert_eq!(&buf[0..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[4..36], &[0u8; 32]);
        assert_eq!(&buf[68..72], &1231006505u32.to_le_bytes());
        assert_eq!(&buf[72..76], &0x1d00ffffu32.to_le_bytes());
        assert_eq!(&buf[76..80], &2083236893u32.to_le_bytes());
    }

    #[test]
    fn prefix_then_splice_equals_full_serialize() {
        let h = genesis_header();
        let prefix = serialize_prefix(&h);
        let full = serialize_header(&h, 0xdeadbeef);
        let spliced = splice_nonce(&prefix, 0xdeadbeef);
        assert_eq!(full, spliced);
    }
}
