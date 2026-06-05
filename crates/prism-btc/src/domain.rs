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

/// The grounded proof-of-work witness — a UOR-ADDR
/// [`uor_addr::AddressWitness`] over the 72-byte `sha256d:<64hex>`
/// κ-label and the 32-byte content fingerprint.
///
/// Produced by [`crate::pipeline::address_block`] via
/// `BitcoinAddressModel::forward`. It owns a replayable TC-05 `Trace`
/// + the σ-projection fingerprint;
/// [`uor_addr::AddressWitness::verify`] re-certifies the derivation
/// without re-invoking the σ-axis. The catamorphism's seal is the
/// witness; PoW admission is a separate host-side observation on the
/// κ-label.
pub type MiningWitness = uor_addr::AddressWitness<{ crate::model::BLOCK_ADDRESS_LABEL_BYTES }, 32>;

/// PRISM triadic coordinates of a 32-byte block-hash digest.
///
/// Foundation ships its own `Triad<L>` surface accessible via
/// `MiningWitness::triad`, whose coordinates are projected from the
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

/// 2-adic ultrametric valuation on 256-bit content-addresses.
///
/// Returns the number of trailing zero bits in `a XOR b` viewed as a
/// 256-bit big-endian integer; equivalently, the 2-adic valuation of
/// the XOR-difference. Returns 256 iff `a == b`.
///
/// The induced ultrametric on the address space is
/// `d(a, b) = 2^-{ultrametric_valuation(a, b)}`. Two digests with
/// `ultrametric_valuation(a, b) ≥ k` share the lowest `k+1` bits (in
/// 256-bit BE order); the equivalence classes for each `k` are the
/// ultrametric balls of radius `2^-k`. This is the canonical
/// distance the UOR addressing space inherits — see [ANALYSIS.md]
/// for the cryptanalysis of its uniformity under SHA-256d.
///
/// [ANALYSIS.md]: https://github.com/afflom/prism-btc/blob/main/ANALYSIS.md
#[must_use]
pub fn ultrametric_valuation(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let mut xor = [0u8; 32];
    for i in 0..32 {
        xor[i] = a[i] ^ b[i];
    }
    TriadicCoords::from_hash(&xor).stratum
}

/// `p`-adic valuation of a 256-bit content-address.
///
/// Returns the largest `k` such that `p^k` divides the digest viewed
/// as a 256-bit big-endian integer. For `p = 2` this coincides with
/// [`TriadicCoords::stratum`]; for `p ∈ {3, 5, 7, …}` it
/// generalizes the ultrametric stratification to other prime-indexed
/// hierarchies of the address space.
///
/// Computed via repeated modular reduction against `p^(k+1)`, capped
/// at the largest `k` for which `p^(k+1)` fits in `u128`. For
/// realistic primes (`p ∈ {3, 5, 7}`) and SHA-256d-distributed
/// inputs the cap is far above any practically observed valuation
/// (`P(v_p ≥ 32) ≈ p^-32`, vanishing).
///
/// Panics if `p < 2`.
#[must_use]
pub fn p_adic_valuation(d: &[u8; 32], p: u64) -> u32 {
    assert!(p >= 2, "p-adic valuation requires p ≥ 2");
    let p_u128 = p as u128;
    let mut k = 0u32;
    let mut p_pow = p_u128; // p^(k+1)
    loop {
        let r = d
            .iter()
            .fold(0u128, |acc, &b| (acc * 256 + b as u128) % p_pow);
        if r != 0 {
            return k;
        }
        match p_pow.checked_mul(p_u128) {
            Some(v) => {
                p_pow = v;
                k += 1;
            }
            None => return k + 1, // p^(k+1) | d but p^(k+2) overflows u128
        }
    }
}

/// Walsh–Hadamard parity at the bit-mask frequency `omega`.
///
/// Computes `popcount(d AND omega) mod 2` — the inner product of `d`
/// and `omega` over GF(2). When `omega` is the all-ones mask this
/// reduces to [`TriadicCoords::spectrum`]; for other `omega` it is
/// the spectral observable at the corresponding non-trivial
/// frequency. The full Walsh–Hadamard image of the 256-bit address
/// space is `2^256` entries; this function reads one entry on demand.
#[must_use]
pub fn walsh_hadamard_parity_at(d: &[u8; 32], omega: &[u8; 32]) -> u32 {
    let mut p: u32 = 0;
    for i in 0..32 {
        p += (d[i] & omega[i]).count_ones();
    }
    p & 1
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

    #[test]
    fn ultrametric_valuation_zero_on_equal_addresses() {
        let a = [0xa5u8; 32];
        // ultrametric_valuation(a, a) = stratum(a XOR a) = stratum(0) = 256.
        assert_eq!(ultrametric_valuation(&a, &a), 256);
    }

    #[test]
    fn ultrametric_valuation_low_bit_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        // Differ in the lowest bit (bit 0 of byte 31).
        a[31] = 0x00;
        b[31] = 0x01;
        // XOR has lowest set bit at position 0 ⇒ valuation = 0.
        assert_eq!(ultrametric_valuation(&a, &b), 0);
    }

    #[test]
    fn ultrametric_valuation_high_bit_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        // Differ in the highest bit (bit 7 of byte 0 = bit 255 of the
        // 256-bit BE integer). XOR has only bit 255 set ⇒ lowest set
        // bit is at position 255 ⇒ valuation = 255.
        a[0] = 0x00;
        b[0] = 0x80;
        assert_eq!(ultrametric_valuation(&a, &b), 255);
    }

    #[test]
    fn walsh_hadamard_at_all_ones_matches_spectrum() {
        // At ω = all-ones, walsh_hadamard_parity_at(d, ω) coincides
        // with TriadicCoords::spectrum(d).
        let mut d = [0u8; 32];
        d[0] = 0xa5; // popcount = 4 (even) → spectrum = 0
        d[15] = 0x07; // popcount = 3 (odd)
                      // Total popcount = 4 + 3 = 7 → parity 1.
        let omega = [0xffu8; 32];
        let p = walsh_hadamard_parity_at(&d, &omega);
        let s = TriadicCoords::from_hash(&d).spectrum;
        assert_eq!(p, s);
        assert_eq!(p, 1);
    }

    #[test]
    fn p_adic_valuation_p2_matches_stratum() {
        // For p = 2 the p-adic valuation equals the stratum
        // (2-adic valuation of the digest viewed as 256-bit BE).
        let mut d = [0u8; 32];
        d[31] = 0b1000; // bit 3 set, low bits zero → v_2 = 3.
        assert_eq!(p_adic_valuation(&d, 2), 3);
        assert_eq!(TriadicCoords::from_hash(&d).stratum, 3);
    }

    #[test]
    fn p_adic_valuation_p3_basic() {
        // 9 = 3^2, so v_3(9) = 2.
        let mut d = [0u8; 32];
        d[31] = 9;
        assert_eq!(p_adic_valuation(&d, 3), 2);
    }

    #[test]
    fn p_adic_valuation_not_divisible() {
        // 7 is coprime to 3 and 5; v_3(7) = v_5(7) = 0.
        let mut d = [0u8; 32];
        d[31] = 7;
        assert_eq!(p_adic_valuation(&d, 3), 0);
        assert_eq!(p_adic_valuation(&d, 5), 0);
    }

    #[test]
    fn p_adic_valuation_zero_digest_caps_at_u128_limit() {
        // 0 is divisible by every p^k; the implementation caps at
        // the largest k for which p^(k+1) fits in u128, then returns
        // k + 1.
        let d = [0u8; 32];
        let v = p_adic_valuation(&d, 3);
        // 3^80 < 2^128 < 3^81, so cap is around k = 80.
        assert!(v >= 80);
    }

    #[test]
    fn walsh_hadamard_at_disjoint_mask_is_zero() {
        let mut d = [0u8; 32];
        d[0] = 0xff;
        let mut omega = [0u8; 32];
        omega[31] = 0xff;
        // d AND omega is all zero ⇒ parity = 0.
        assert_eq!(walsh_hadamard_parity_at(&d, &omega), 0);
    }
}
