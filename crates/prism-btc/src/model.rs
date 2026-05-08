//! `BitcoinMiningModel` — prism-btc's `PrismModel<H, B, A>` declaration.
//!
//! Foundation 0.3.3 ships the `PrismModel<H, B, A>` typed-iso surface
//! (wiki ADR-019/020/022/023) **and the catamorphism evaluator
//! [`pipeline::evaluate_term_tree`] (ADR-029) plus
//! [`Grounded::output_bytes`] (ADR-028)**. prism-btc, as the prism
//! implementor for the Bitcoin use case, declares its model with:
//!
//! - `Input  = MiningInput`            — the 80-byte canonical wire-format header
//! - `Output = ConstrainedTypeInput`   — foundation's identity output shape
//! - `Route  = BitcoinMiningRoute`     — the σ-projection term tree:
//!   `hash(input)` (ADR-026 G19), which `prism_model!` lowers to
//!   `[Term::Variable {name_index: 0}, Term::HasherProjection {input_index: 0}]`
//!
//! ## What `BitcoinMiningModel::forward` produces
//!
//! Calling `forward(MiningInput(header_bytes))` invokes
//! `pipeline::run_route`, which:
//!
//! 1. Folds the 80 input bytes through `Sha256dHasher` to derive the
//!    binding's `content_address` (8 high-order bytes of SHA-256d).
//! 2. Validates the `CompileUnit` against `PrismBtcBounds`.
//! 3. **Evaluates the route's term tree via `evaluate_term_tree`**: the
//!    `Term::HasherProjection { input_index: 0 }` rule folds the
//!    expression at `input_index` (here `Term::Variable {0}`) through
//!    `Sha256dHasher` and emits the digest (ADR-029).
//! 4. Folds the canonical `CompileUnit` byte layout through the same
//!    Hasher to compute `ContentFingerprint` and `unit_address`.
//! 5. Mints `Grounded<ConstrainedTypeInput>` and attaches the evaluated
//!    digest as `output_bytes` (ADR-028).
//!
//! ## Foundation 0.3.3 evaluator ceiling
//!
//! The catamorphism evaluator carries each per-variant value as a
//! [`pipeline::TermValue`] of capacity `TERM_VALUE_MAX_BYTES = 32`
//! bytes (foundation 0.3.3's per-value architectural ceiling — sized
//! to hold a 32-byte hasher digest plus arithmetic operands). When
//! `Term::Variable {0}` evaluates against the 80-byte mining input, the
//! result is `TermValue::from_slice(input_bytes)` which truncates to
//! the first 32 bytes. The downstream `HasherProjection` therefore
//! computes `Sha256dHasher` over the leading 32 header bytes
//! (`version || prev_hash`), not all 80. The Grounded's `output_bytes`
//! is exactly that 32-byte digest.
//!
//! The full Bitcoin block hash — `Sha256dHasher` over all 80 header
//! bytes, then byte-reversed to display order — is carried on
//! [`crate::pipeline::MiningOutcome::digest`], computed by prism-btc's
//! runtime ([`crate::ops::sha256::sha256d_display`]) using the **same
//! algorithm body** that the foundation evaluator invokes inside
//! `HasherProjection`. The block-hash bytes the protocol consumes and
//! the typed-iso evaluator's certificate are produced by one and the
//! same `Sha256dHasher` substitution-axis selection.
//!
//! When foundation lifts `TERM_VALUE_MAX_BYTES` (or introduces a
//! variable-input projection that bypasses the per-value buffer), this
//! model's `output_bytes` will carry the full block hash without any
//! changes here — the route declaration `hash(input)` is independent
//! of the buffer ceiling.

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::pipeline::{ConstrainedTypeShape, ConstraintRef, IntoBindingValue};
use uor_foundation::{DefaultHostTypes, ViolationKind};
use uor_foundation_sdk::prism_model;

use crate::shapes::bounds::PrismBtcBounds;
use crate::shapes::hasher::Sha256dHasher;

/// 80-byte canonical wire-format Bitcoin block header.
///
/// Carries the bytes the W32 fiber admitted: the 76-byte template
/// prefix (extranonce-fixed merkle root) + the winning 4-byte nonce.
/// Implements [`IntoBindingValue`] so foundation's `pipeline::run_route`
/// can fold it through the application `Hasher` at certificate emission
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningInput(pub [u8; 80]);

impl MiningInput {
    /// IRI of the constraint that fails when foundation hands us a
    /// too-small output buffer (which it shouldn't, by run_route's
    /// invariant: the buffer is sized to MAX_BYTES exactly).
    const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
        shape_iri: "https://prism.btc/shape/MiningInput",
        constraint_iri: "https://prism.btc/shape/MiningInput/maxBytes",
        property_iri: "https://prism.btc/shape/MiningInput/byteCount",
        expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
        min_count: 80,
        max_count: 80,
        kind: ViolationKind::ValueCheck,
    };
}

impl ConstrainedTypeShape for MiningInput {
    const IRI: &'static str = "https://prism.btc/shape/MiningInput";
    const SITE_COUNT: usize = 80;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
}

// `IntoBindingValue` (and `PrismModel`, `FoundationClosed`) require
// `__sdk_seal::Sealed`. The wiki sanctions hand-rolled IntoBindingValue
// impls for application authors carrying runtime input data (per the
// `product_shape!` macro doc: "applications that need to carry runtime
// input data declare a custom ConstrainedTypeShape and write a bespoke
// IntoBindingValue impl"). prism-btc, as the prism implementor, exercises
// that lane.
impl uor_foundation::pipeline::__sdk_seal::Sealed for MiningInput {}

impl IntoBindingValue for MiningInput {
    const MAX_BYTES: usize = 80;

    fn into_binding_bytes(&self, out: &mut [u8]) -> Result<usize, ShapeViolation> {
        if out.len() < 80 {
            return Err(Self::BUFFER_VIOLATION);
        }
        out[..80].copy_from_slice(&self.0);
        Ok(80)
    }
}

// ----- The PrismModel declaration -----
//
// `prism_model!` emits:
// - `pub struct BitcoinMiningModel;`
// - `pub struct BitcoinMiningRoute;`
// - `__sdk_seal::Sealed` impls for both
// - `FoundationClosed for BitcoinMiningRoute` returning the term arena
// - `PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher>` for
//   `BitcoinMiningModel`, whose `forward` body is
//   `pipeline::run_route::<DefaultHostTypes, PrismBtcBounds, Sha256dHasher, Self>(input)`
//
// The route body `hash(input)` is the σ-projection in foundation 0.3.3's
// closure-body grammar (ADR-026 G19). The macro lowers it to a 2-node
// term arena:
//     [ Term::Variable { name_index: 0 },
//       Term::HasherProjection { input_index: 0 } ]
// `pipeline::run_route` (foundation 0.3.3) calls
// `pipeline::evaluate_term_tree` with this arena and the 80 input bytes;
// the `HasherProjection` fold rule (ADR-029) runs the input bytes through
// the application Hasher (`Sha256dHasher`) and emits the 32-byte digest
// — the SHA-256d of the canonical wire-format header. That digest is
// the Bitcoin block hash in the Hasher's internal byte order.
prism_model! {
    pub struct BitcoinMiningModel;
    pub struct BitcoinMiningRoute;
    impl PrismModel<DefaultHostTypes, PrismBtcBounds, Sha256dHasher> for BitcoinMiningModel {
        type Input = MiningInput;
        type Output = uor_foundation::enforcement::ConstrainedTypeInput;
        type Route = BitcoinMiningRoute;
        fn route(input: Self::Input) -> Self::Output {
            hash(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uor_foundation::pipeline::PrismModel;

    fn genesis_header_bytes() -> [u8; 80] {
        // The 80-byte genesis header in canonical wire-format.
        let merkle: [u8; 32] = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        let mut header = [0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes());
        // prev_hash = 0
        header[36..68].copy_from_slice(&merkle);
        header[68..72].copy_from_slice(&1231006505u32.to_le_bytes());
        header[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        header[76..80].copy_from_slice(&2083236893u32.to_le_bytes());
        header
    }

    #[test]
    fn into_binding_bytes_writes_eighty() {
        let bytes = [0xab; 80];
        let input = MiningInput(bytes);
        let mut out = [0u8; 80];
        let written = input.into_binding_bytes(&mut out).expect("buffer fits");
        assert_eq!(written, 80);
        assert_eq!(out, bytes);
    }

    #[test]
    fn forward_mints_grounded_at_w32() {
        let outcome = <BitcoinMiningModel as PrismModel<
            DefaultHostTypes,
            PrismBtcBounds,
            Sha256dHasher,
        >>::forward(MiningInput(genesis_header_bytes()))
        .expect("forward must mint Grounded");
        // Witt level comes from PrismBtcBounds::WITT_LEVEL_MAX_BITS = 32.
        assert_eq!(outcome.witt_level_bits(), 32);
        // The unit_address is non-zero (foundation derives it from
        // the canonical CompileUnit byte layout fingerprint).
        assert_ne!(outcome.unit_address().as_u128(), 0);
    }

    #[test]
    fn forward_grounded_path_identity_is_input_invariant() {
        // The Grounded's `content_fingerprint` and `unit_address` are
        // derived from the CompileUnit metadata digest (ADR-029
        // `fold_unit_digest`), not the input bytes. Two distinct admitted
        // inputs therefore agree on those substrate bits — they attest the
        // **typed-iso path**, not bytewise input identity.
        let a = MiningInput([0x11u8; 80]);
        let b = MiningInput([0xeeu8; 80]);
        let ga = <BitcoinMiningModel as PrismModel<
            DefaultHostTypes,
            PrismBtcBounds,
            Sha256dHasher,
        >>::forward(a)
        .expect("forward(a)");
        let gb = <BitcoinMiningModel as PrismModel<
            DefaultHostTypes,
            PrismBtcBounds,
            Sha256dHasher,
        >>::forward(b)
        .expect("forward(b)");
        assert_eq!(ga.content_fingerprint(), gb.content_fingerprint());
        assert_eq!(ga.unit_address(), gb.unit_address());
        assert_eq!(ga.witt_level_bits(), gb.witt_level_bits());
    }

    #[test]
    fn forward_output_bytes_is_sha256d_of_input_prefix() {
        // Foundation 0.3.3 catamorphism: `hash(input)` lowers to
        // `Term::HasherProjection`, and `evaluate_term_tree` (ADR-029)
        // folds the input expression's bytes through `Sha256dHasher` and
        // emits the digest as the Grounded's `output_bytes` (ADR-028).
        //
        // The per-value ceiling `TERM_VALUE_MAX_BYTES = 32` truncates
        // `Term::Variable {0}`'s evaluation against the 80-byte input to
        // its first 32 bytes (`version || prev_hash[..28]`). The
        // `HasherProjection` then computes `Sha256dHasher` over those 32
        // bytes — not all 80. This test pins the actual evaluator output
        // against an independent computation of `sha256d_internal` over
        // the same 32-byte prefix.
        let header = genesis_header_bytes();
        let grounded = <BitcoinMiningModel as PrismModel<
            DefaultHostTypes,
            PrismBtcBounds,
            Sha256dHasher,
        >>::forward(MiningInput(header))
        .expect("forward must mint Grounded");
        let output = grounded.output_bytes();
        assert_eq!(output.len(), 32);

        let expected = crate::ops::sha256::sha256d_internal(&header[..32]);
        assert_eq!(output, &expected[..]);
    }
}
