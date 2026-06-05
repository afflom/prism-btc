//! UOR property landscape of a κ-label — the typed observation surface.
//!
//! Where [`crate::commitment`] is the **sender-side** typed channel
//! (commits to which UOR observables the κ-label must exhibit, via
//! foundation's `TypedCommitment` per wiki ADR-048), this module is the
//! **receiver-side** typed lens (decodes which UOR observables a given
//! κ-label *does* exhibit). Together they form the sender ↔ receiver
//! duality of prism's typed information channel.
//!
//! - [`KappaObservables`] — canonical, always-computed property
//!   decomposition: triadic coordinates (2-adic stratum + spectrum) +
//!   p-adic valuations at the small-prime set {2, 3, 5, 7}. Plain
//!   `Copy` struct, stack-allocated, zero overhead. Derived from a
//!   κ-label's digest on demand by host code.
//! - [`ExtendedObservables`]`<const N_PAR: usize, const N_REF: usize>`
//!   — const-generic extension carrying parities at `N_PAR` user-chosen
//!   ω-frequencies plus ultrametric distances to `N_REF` reference
//!   points. Stack-allocated; sizes part of the type, not runtime data.
//!
//! Both surfaces are **zero-cost**: no `Vec`, no `Box`, no runtime
//! allocation; loops are bounded by const generics and compile away.
//! The reference pattern for substrate-level `AxisObservables<H>` —
//! any UOR-hardened σ-projection axis (Blake3, Keccak, post-quantum)
//! inherits this shape, swapping the SHA-256d-specific primitives.

use crate::domain::{p_adic_valuation, ultrametric_valuation, walsh_hadamard_parity_at};
use crate::TriadicCoords;

/// The canonical small-prime set for [`KappaObservables`]'s p-adic
/// valuations. Covers the primes the cryptanalysis battery
/// (ANALYSIS.md §3.6) confirmed UOR-uniform on SHA-256d.
pub const CANONICAL_PRIMES: [u64; 4] = [2, 3, 5, 7];

/// Canonical UOR property landscape of a κ-label — derived from a
/// digest on demand. The substrate-level receiver-side observatory.
///
/// Direct correspondence point: where foundation's
/// [`prism::pipeline::TypedCommitment`] is the **sender** (commits to
/// what observables the κ-label must exhibit, evaluated inside
/// `run_route`), `KappaObservables` is the **receiver** — a typed lens
/// onto every UOR observable the σ-projection has produced for this
/// κ-label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KappaObservables {
    /// Triadic coordinates: 2-adic stratum + Walsh–Hadamard spectrum.
    pub coords: TriadicCoords,
    /// p-adic valuations at `CANONICAL_PRIMES = {2, 3, 5, 7}`.
    /// `p_adic[i]` is the valuation at `CANONICAL_PRIMES[i]`. The
    /// `i = 0` entry (p = 2) duplicates `coords.stratum` by definition;
    /// kept for uniformity of access.
    pub p_adic: [u32; 4],
}

impl KappaObservables {
    /// Decode the canonical UOR property landscape from a digest.
    /// Zero allocation; stack-resident return value.
    #[inline]
    #[must_use]
    pub fn from_digest(digest: &[u8; 32]) -> Self {
        let coords = TriadicCoords::from_hash(digest);
        let p_adic = [
            p_adic_valuation(digest, CANONICAL_PRIMES[0]),
            p_adic_valuation(digest, CANONICAL_PRIMES[1]),
            p_adic_valuation(digest, CANONICAL_PRIMES[2]),
            p_adic_valuation(digest, CANONICAL_PRIMES[3]),
        ];
        Self { coords, p_adic }
    }

    /// Look up the p-adic valuation at a canonical prime, returning
    /// `None` if `p` is not in [`CANONICAL_PRIMES`].
    #[inline]
    #[must_use]
    pub fn p_adic_at(&self, p: u64) -> Option<u32> {
        let mut i = 0;
        while i < CANONICAL_PRIMES.len() {
            if CANONICAL_PRIMES[i] == p {
                return Some(self.p_adic[i]);
            }
            i += 1;
        }
        None
    }
}

/// `ExtendedObservables<N_PAR, N_REF>` — the canonical landscape plus
/// application-declared parity frequencies and reference points,
/// lifted into the type via const generics.
///
/// `N_PAR` and `N_REF` are compile-time-known; the resulting struct
/// is stack-allocated with all loop bounds known to the optimizer.
/// Zero `Vec`, zero `Box`, zero runtime allocation.
///
/// Use [`Self::from_digest`] to compute. The produced observables
/// directly correspond to foundation's
/// [`prism::pipeline::WalshHadamardParity`] (per-frequency parity) and
/// [`prism::pipeline::UltrametricCloseTo`] (per-reference distance);
/// the cryptanalysis battery in `examples/uor_cryptanalysis.rs`
/// exercises both the lens and the foundation predicates against the
/// same digest manifold.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedObservables<const N_PAR: usize, const N_REF: usize> {
    /// Canonical always-on landscape.
    pub base: KappaObservables,
    /// Application-chosen parity frequencies.
    pub parity_omegas: [[u8; 32]; N_PAR],
    /// Observed parity values at the frequencies above.
    pub parities: [u32; N_PAR],
    /// Application-chosen ultrametric reference points.
    pub reference_points: [[u8; 32]; N_REF],
    /// Observed ultrametric valuations (digest vs each reference).
    pub ultrametric_dists: [u32; N_REF],
}

impl<const N_PAR: usize, const N_REF: usize> ExtendedObservables<N_PAR, N_REF> {
    /// Decode the canonical landscape + the N_PAR parities and N_REF
    /// ultrametric distances into a stack-resident observation
    /// record. Loops are `N_PAR`/`N_REF`-bounded; compiler unrolls.
    #[inline]
    #[must_use]
    pub fn from_digest(
        digest: &[u8; 32],
        parity_omegas: [[u8; 32]; N_PAR],
        reference_points: [[u8; 32]; N_REF],
    ) -> Self {
        let base = KappaObservables::from_digest(digest);
        let mut parities = [0u32; N_PAR];
        let mut i = 0;
        while i < N_PAR {
            parities[i] = walsh_hadamard_parity_at(digest, &parity_omegas[i]);
            i += 1;
        }
        let mut ultrametric_dists = [0u32; N_REF];
        let mut j = 0;
        while j < N_REF {
            ultrametric_dists[j] = ultrametric_valuation(digest, &reference_points[j]);
            j += 1;
        }
        Self {
            base,
            parity_omegas,
            parities,
            reference_points,
            ultrametric_dists,
        }
    }

    /// Look up the observed parity at a given ω, if it was pre-computed.
    /// Returns `None` when `omega` is not among the const-generic
    /// `parity_omegas` array.
    #[inline]
    #[must_use]
    pub fn lookup_parity(&self, omega: &[u8; 32]) -> Option<u32> {
        let mut i = 0;
        while i < N_PAR {
            if &self.parity_omegas[i] == omega {
                return Some(self.parities[i]);
            }
            i += 1;
        }
        None
    }

    /// Look up the observed ultrametric distance to a reference point,
    /// if it was pre-computed.
    #[inline]
    #[must_use]
    pub fn lookup_ultrametric(&self, reference: &[u8; 32]) -> Option<u32> {
        let mut i = 0;
        while i < N_REF {
            if &self.reference_points[i] == reference {
                return Some(self.ultrametric_dists[i]);
            }
            i += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kappa_observables_round_trip_on_canonical_primes() {
        let mut digest = [0u8; 32];
        digest[31] = 0b0010_1000; // bit 3 of byte 31 → stratum = 3
        let obs = KappaObservables::from_digest(&digest);
        for (i, &p) in CANONICAL_PRIMES.iter().enumerate() {
            assert_eq!(obs.p_adic[i], p_adic_valuation(&digest, p));
        }
        assert_eq!(obs.p_adic_at(2), Some(obs.coords.stratum));
        assert_eq!(obs.p_adic_at(11), None);
    }

    #[test]
    fn extended_observables_zero_extension_compiles_and_works() {
        // The N_PAR=0, N_REF=0 case is a valid const-generic
        // instantiation — it lowers to just the canonical KappaObservables.
        let mut digest = [0u8; 32];
        digest[31] = 1;
        let obs = ExtendedObservables::<0, 0>::from_digest(&digest, [], []);
        assert_eq!(obs.base.coords.stratum, 0);
    }

    #[test]
    fn extended_observables_parity_lookup_matches_recompute() {
        let mut digest = [0u8; 32];
        digest[31] = 0b0010_0000; // bit 5 of byte 31
        let mut omega = [0u8; 32];
        omega[31] = 0b0010_0000;
        let obs = ExtendedObservables::<1, 0>::from_digest(&digest, [omega], []);
        assert_eq!(obs.lookup_parity(&omega), Some(1));
        let other = [0u8; 32];
        assert_eq!(obs.lookup_parity(&other), None);
    }

    #[test]
    fn extended_observables_ultrametric_lookup_matches_recompute() {
        let mut digest = [0u8; 32];
        digest[31] = 0xff;
        let mut reference = [0u8; 32];
        reference[31] = 0xf0;
        let obs = ExtendedObservables::<0, 1>::from_digest(&digest, [], [reference]);
        // digest XOR reference = 0x0f → low bit set → valuation 0
        assert_eq!(obs.lookup_ultrametric(&reference), Some(0));
    }
}
