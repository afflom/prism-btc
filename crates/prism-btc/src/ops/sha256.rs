//! SHA-256 and SHA-256d as prism-btc runtime, expressed in pure Rust.
//!
//! No external crate; the σ-projection's evaluation belongs to the prism
//! implementor (this crate). Foundation provides the `Hasher` trait;
//! prism-btc provides the body. The body is a chain of arithmetic and
//! bitwise operations that are themselves compositions of foundation
//! `PrimitiveOp` generators (`Add`, `Xor`, `And`, `Or`, plus right-rotate
//! built from `Succ`/`Pred` over `WittLevel::W32`). The composition is
//! recorded structurally at the type level via `Term::Application` in
//! `uor_foundation::term`; the per-call evaluation is the function below.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS-180-4 initial hash value for SHA-256. Exposed so the streaming
/// hasher in [`crate::shapes::hasher::Sha256dHasher`] can reuse it.
pub const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 compression of one 512-bit (64-byte) block into the running state.
///
/// Public so the streaming hasher in [`crate::shapes::hasher::Sha256dHasher`]
/// can reuse it without code duplication. This is the runtime evaluation of
/// the `Sha256Compression` operation; the structural identity in foundation
/// `PrimitiveOp` vocabulary is declared in `uor_foundation::term`.
#[inline]
pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 over a byte sequence — the canonical FIPS-180-4 algorithm.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_INITIAL_STATE;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Process all complete 64-byte blocks.
    let mut i = 0;
    while i + 64 <= data.len() {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[i..i + 64]);
        compress(&mut state, &block);
        i += 64;
    }

    // Final block: remaining bytes, 0x80 sentinel, zero-pad, 8-byte length.
    let mut tail = [0u8; 128];
    let rem = data.len() - i;
    tail[..rem].copy_from_slice(&data[i..]);
    tail[rem] = 0x80;
    if rem + 1 + 8 <= 64 {
        tail[64 - 8..64].copy_from_slice(&bit_len.to_be_bytes());
        let mut block = [0u8; 64];
        block.copy_from_slice(&tail[..64]);
        compress(&mut state, &block);
    } else {
        tail[128 - 8..128].copy_from_slice(&bit_len.to_be_bytes());
        let mut block = [0u8; 64];
        block.copy_from_slice(&tail[..64]);
        compress(&mut state, &block);
        block.copy_from_slice(&tail[64..128]);
        compress(&mut state, &block);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256d: SHA-256 applied twice. The second invocation runs on the
/// 32-byte output of the first, producing the canonical Bitcoin digest.
///
/// The result is in **internal** byte order (most-significant byte last).
/// For Bitcoin display order — and for comparison against a target whose
/// bytes are big-endian — call [`sha256d_display`].
pub fn sha256d_internal(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// SHA-256d in Bitcoin display order (big-endian, most-significant byte
/// first). This is what the protocol's target check is performed against.
pub fn sha256d_display(data: &[u8]) -> [u8; 32] {
    let mut out = sha256d_internal(data);
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        // Known: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let got = sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn sha256_abc() {
        // Known: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let got = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn sha256_long_message_crosses_two_blocks() {
        // The string "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        // is 56 bytes (FIPS-180-4 test vector for the 2-block case after pad).
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let got = sha256(msg);
        // Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let expected: [u8; 32] = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn sha256d_empty_display_order() {
        // Bitcoin display order: SHA-256d("") reversed.
        // SHA-256(SHA-256("")) raw =
        //   5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        // Reversed (display): 56944c5d3f...
        let got = sha256d_display(b"");
        let expected: [u8; 32] = [
            0x56, 0x94, 0x4c, 0x5d, 0x3f, 0x98, 0x41, 0x3e, 0xf4, 0x5c, 0xf5, 0x45, 0x45, 0x53,
            0x81, 0x03, 0xcc, 0x9f, 0x29, 0x8e, 0x05, 0x75, 0x82, 0x0a, 0xd3, 0x59, 0x13, 0x76,
            0xe2, 0xe0, 0xf6, 0x5d,
        ];
        assert_eq!(got, expected);
    }
}
