//! Bitcoin atomic feature primitives.
//!
//! Each Bitcoin wire-format feature is a typed `ConstrainedTypeShape`
//! (per architecture §2.1). They compose hierarchically into composite
//! features (`TemplatePrefix`, `Header`, `MiningTask`, `MiningResult`) via
//! `partition_product` (architecture §2.2). The ψ-pipeline observes the
//! structural relationships between them and generates a label
//! (architecture §4).
//!
//! No primitive declares constraints today (`CONSTRAINTS = &[]`). The
//! structural admission relation between `Header` and `Target` is encoded
//! on `MiningResult::CONSTRAINTS` once foundation's closed constraint
//! catalog grows the `AxisProjectionObservable` + `LexicographicLessEqBound`
//! pair (architecture §9.1). Until then, prism-btc declares the typed
//! feature hierarchy structurally; the admission relation is named in
//! the architecture but not yet expressible as a closed-catalog
//! `ConstraintRef`.

use uor_foundation::enforcement::ShapeViolation;
use uor_foundation::pipeline::{ConstrainedTypeShape, ConstraintRef, IntoBindingValue};
use uor_foundation::ViolationKind;

/// 4-byte little-endian block version (Bitcoin protocol field).
///
/// Site count: 4 W8. Scalar Witt level: W32 (`Z/(2^32)Z`).
pub struct Version;

impl ConstrainedTypeShape for Version {
    const IRI: &'static str = "https://prism.btc/shape/Version";
    const SITE_COUNT: usize = 4;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    /// 32 bits — exactly representable in `u64` per ADR-032.
    const CYCLE_SIZE: u64 = 1u64 << 32;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for Version {}

impl IntoBindingValue for Version {
    const MAX_BYTES: usize = 4;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 32-byte previous-block content-address (under the canonical hash axis).
///
/// Site count: 32 W8. Scalar Witt level: W256.
pub struct PrevHash;

impl ConstrainedTypeShape for PrevHash {
    const IRI: &'static str = "https://prism.btc/shape/PrevHash";
    const SITE_COUNT: usize = 32;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    /// 256 bits — saturates `u64` per ADR-032.
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for PrevHash {}

impl IntoBindingValue for PrevHash {
    const MAX_BYTES: usize = 32;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 32-byte merkle root content-address.
pub struct MerkleRoot;

impl ConstrainedTypeShape for MerkleRoot {
    const IRI: &'static str = "https://prism.btc/shape/MerkleRoot";
    const SITE_COUNT: usize = 32;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for MerkleRoot {}

impl IntoBindingValue for MerkleRoot {
    const MAX_BYTES: usize = 32;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 4-byte little-endian timestamp (Unix seconds since epoch).
pub struct Timestamp;

impl ConstrainedTypeShape for Timestamp {
    const IRI: &'static str = "https://prism.btc/shape/Timestamp";
    const SITE_COUNT: usize = 4;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = 1u64 << 32;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for Timestamp {}

impl IntoBindingValue for Timestamp {
    const MAX_BYTES: usize = 4;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 4-byte little-endian compact-encoded target.
pub struct Bits;

impl ConstrainedTypeShape for Bits {
    const IRI: &'static str = "https://prism.btc/shape/Bits";
    const SITE_COUNT: usize = 4;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = 1u64 << 32;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for Bits {}

impl IntoBindingValue for Bits {
    const MAX_BYTES: usize = 4;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 4-byte little-endian miner-resolved nonce.
pub struct Nonce;

impl ConstrainedTypeShape for Nonce {
    const IRI: &'static str = "https://prism.btc/shape/Nonce";
    const SITE_COUNT: usize = 4;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = 1u64 << 32;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for Nonce {}

impl IntoBindingValue for Nonce {
    const MAX_BYTES: usize = 4;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// 32-byte target threshold — the structural projection of `Bits`.
pub struct Target;

impl ConstrainedTypeShape for Target {
    const IRI: &'static str = "https://prism.btc/shape/Target";
    const SITE_COUNT: usize = 32;
    const CONSTRAINTS: &'static [ConstraintRef] = &[];
    const CYCLE_SIZE: u64 = u64::MAX;
}

impl uor_foundation::pipeline::__sdk_seal::Sealed for Target {}

impl IntoBindingValue for Target {
    const MAX_BYTES: usize = 32;
    fn into_binding_bytes(&self, _out: &mut [u8]) -> Result<usize, ShapeViolation> {
        Ok(0)
    }
}

/// Buffer-violation IRI emitted when foundation hands a too-small buffer
/// to a feature primitive's `into_binding_bytes`.
const BUFFER_VIOLATION: ShapeViolation = ShapeViolation {
    shape_iri: "https://prism.btc/shape/Primitive",
    constraint_iri: "https://prism.btc/shape/Primitive/maxBytes",
    property_iri: "https://prism.btc/shape/Primitive/byteCount",
    expected_range: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger",
    min_count: 0,
    max_count: 0,
    kind: ViolationKind::ValueCheck,
};

/// Surfaced for use by composite-shape implementors that need to emit a
/// uniform buffer-violation when foundation supplies an undersized buffer.
#[inline]
#[must_use]
pub const fn buffer_violation() -> ShapeViolation {
    BUFFER_VIOLATION
}
