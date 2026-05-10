//! Bitcoin domain types for prism-btc.
//!
//! These are the host-side value types the prism implementor (this
//! crate) carries at the application boundary. Foundation provides the
//! sealed types (`Datum`, `Triad`, etc.); these types are the
//! application-level wrappers carrying Bitcoin-specific semantics.

/// Block version — XSD `PositiveInteger` → u32.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Version(pub u32);

/// Block timestamp (Unix epoch) — XSD `PositiveInteger` → u32.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Timestamp(pub u32);

/// Compact nBits target encoding — XSD `PositiveInteger` → u32.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bits(pub u32);

/// A Bitcoin block hash — a 32-byte SHA-256d digest in display order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A Bitcoin Merkle root — a 32-byte SHA-256d digest of the transaction tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MerkleRoot(pub [u8; 32]);

impl MerkleRoot {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Pure Bitcoin block header fields (without nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: Version,
    pub prev_hash: [u8; 32],
    pub merkle_root: MerkleRoot,
    pub timestamp: Timestamp,
    pub bits: Bits,
}

/// Compact nBits encoding of the Bitcoin proof-of-work target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub nbits: u32,
}

impl Target {
    /// Genesis block nBits: `0x1d00ffff`
    pub const GENESIS_NBITS: u32 = 0x1d00ffff;

    pub const fn new(nbits: u32) -> Self {
        Self { nbits }
    }

    /// Decode nBits to a 32-byte big-endian (display order) target value.
    pub fn to_bytes(&self) -> [u8; 32] {
        let nbits = self.nbits;
        let exp = (nbits >> 24) as usize;
        let mantissa = nbits & 0x00ff_ffff;
        let mut target = [0u8; 32];
        if exp == 0 || exp > 32 {
            return target;
        }
        let start = 32usize.saturating_sub(exp);
        let m2 = ((mantissa >> 16) & 0xff) as u8;
        let m1 = ((mantissa >> 8) & 0xff) as u8;
        let m0 = (mantissa & 0xff) as u8;
        if start < 32 {
            target[start] = m2;
        }
        if start + 1 < 32 {
            target[start + 1] = m1;
        }
        if start + 2 < 32 {
            target[start + 2] = m0;
        }
        target
    }

    pub fn leading_zero_bytes(&self) -> u32 {
        let exp = (self.nbits >> 24) as usize;
        if exp >= 32 {
            0
        } else {
            (32 - exp) as u32
        }
    }

    pub fn is_satisfied_by(&self, hash: &BlockHash) -> bool {
        self.is_satisfied_by_bytes(hash.as_bytes())
    }

    #[inline]
    pub fn is_satisfied_by_bytes(&self, hash: &[u8; 32]) -> bool {
        hash <= &self.to_bytes()
    }
}

/// Phantom tag distinguishing prism-btc's `Grounded` from other domains.
///
/// Foundation seals `Grounded<ConstrainedTypeInput, Tag>` to require a
/// `Tag` parameter; `MiningTag` is prism-btc's marker for an admitted
/// Bitcoin mining witness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MiningTag;

/// The grounded mining witness — `Grounded<MiningResult, MiningTag>`
/// produced by `prism_btc::mine` via foundation's `PrismModel::forward`.
///
/// Carries the FirstAdmit coproduct (5 bytes: discriminant + admitting
/// nonce) on `output_bytes` (ADR-028) and the typed-iso path
/// attestation on `content_fingerprint` / `unit_address`.
pub type MiningWitness =
    uor_foundation::enforcement::Grounded<crate::model::MiningResult, MiningTag>;

/// PRISM triadic coordinates of a 32-byte block-hash digest.
///
/// Foundation ships its own `Triad<L>` surface accessible via
/// [`MiningWitness::triad`], whose coordinates are projected from the
/// `Grounded`'s `unit_address` (the metadata-domain identity). The
/// `TriadicCoords` here is the **digest-domain** projection — `(stratum,
/// spectrum)` over the 32 bytes of the admitted block hash itself. Both
/// projections are exposed: foundation's `Triad` for the path identity,
/// and prism-btc's `TriadicCoords` for the block-hash content
/// observables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TriadicCoords {
    /// The hash bytes (display order).
    pub datum: [u8; 32],
    /// 2-adic valuation: index of the lowest set bit treating the
    /// digest as a 256-bit big-endian integer. `256` if the digest
    /// is all zeros.
    pub stratum: u32,
    /// Walsh–Hadamard parity over the 256 bits, modulo 2 — a single
    /// bit indicating spectral parity. (A full Walsh–Hadamard image
    /// is 2^256 entries; the architecture pins the spectral
    /// observable to its parity, preserving the domain-relevant
    /// information without exponential blowup.)
    pub spectrum: u32,
}

impl TriadicCoords {
    /// Project a 32-byte block-hash digest (display order) to its
    /// `(stratum, spectrum)` content observables.
    ///
    /// `stratum` is the 2-adic valuation: index of the lowest set bit
    /// when the digest is viewed as a 256-bit big-endian integer
    /// (returns 256 if the digest is all-zero). `spectrum` is the
    /// Walsh–Hadamard parity — the popcount of all 256 bits, modulo 2.
    pub fn from_hash(hash: &[u8; 32]) -> Self {
        // 2-adic valuation: count trailing zero bits when the digest is
        // viewed as a big-endian integer (so the LOW byte is index 31).
        let mut stratum: u32 = 256;
        for (i, byte) in hash.iter().enumerate().rev() {
            if *byte != 0 {
                stratum = (31 - i as u32) * 8 + byte.trailing_zeros();
                break;
            }
        }
        // Walsh–Hadamard parity: sum of all bits mod 2.
        let mut popcount: u32 = 0;
        for byte in hash.iter() {
            popcount += byte.count_ones();
        }
        Self {
            datum: *hash,
            stratum,
            spectrum: popcount & 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_genesis_leading_zeros() {
        let t = Target::new(Target::GENESIS_NBITS);
        assert_eq!(t.leading_zero_bytes(), 3);
    }

    #[test]
    fn target_satisfaction_at_genesis() {
        let t = Target::new(Target::GENESIS_NBITS);
        let genesis_hash: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83,
            0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6,
            0x0a, 0x8c, 0xe2, 0x6f,
        ];
        assert!(t.is_satisfied_by_bytes(&genesis_hash));
    }

    #[test]
    fn triadic_coords_all_zero() {
        let coords = TriadicCoords::from_hash(&[0u8; 32]);
        assert_eq!(coords.stratum, 256);
        assert_eq!(coords.spectrum, 0);
    }

    #[test]
    fn triadic_coords_low_bit_set() {
        let mut h = [0u8; 32];
        h[31] = 0x01;
        let coords = TriadicCoords::from_hash(&h);
        assert_eq!(coords.stratum, 0);
        assert_eq!(coords.spectrum, 1);
    }
}
