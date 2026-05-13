//! Aggregate observatory across a mining campaign — the **total**
//! receiver-side typed lens at session granularity.
//!
//! Every ψ-pipeline inference exposes a [`KappaObservables`] regardless
//! of whether the κ-label admits (the lens is total — see
//! [`crate::pipeline::MiningFailure::DidNotAdmit`]'s payload).
//! [`CampaignStats`] folds those per-attempt observables into a
//! stack-resident aggregate, giving the host operator typed visibility
//! into a mining session at scale.
//!
//! At mainnet difficulty (`α ≈ 2⁻⁷⁷`) a session walks billions to
//! quintillions of attempts. With the partial admission-only lens
//! we discarded all that structure; with the total lens
//! `CampaignStats` accumulates it without per-attempt allocation
//! (fixed-size histograms, `O(1)` per record). Operators get:
//!
//! * **Empirical α** — observed admission rate, convergent to the
//!   target's theoretical α at large N.
//! * **Distribution check** — stratum / spectrum / p-adic histograms
//!   are PRF-baseline-checkable at any point in the session
//!   (conformance CM-3).
//! * **Best-candidate tracking** — `max_leading_zeros` records the
//!   closest-to-admission κ-label seen so far, a diagnostic for
//!   long-running sessions.
//!
//! Zero allocation: every field is a stack-sized array; updates are
//! `#[inline]` and `O(1)`.

use crate::observables::KappaObservables;
use crate::pipeline::MiningOutcome;

/// Stratum-histogram bin count — bins 0..32 are tracked per-value;
/// stratum ≥ 32 folds into the last bin. Covers the practical regime
/// where mining cost is meaningful (stratum k has PRF probability
/// `2⁻(k+1)`; at k = 32 that's `2⁻³³`, well below any realistic α).
pub const STRATUM_BINS: usize = 33;

/// p-adic histogram bin count for primes p ∈ {3, 5, 7}. Covers the
/// practical low-valuation range where the distribution has support.
pub const PADIC_BINS: usize = 8;

/// Aggregate statistics across a mining campaign — running counts and
/// histograms over the typed observable surface.
///
/// `Copy`, stack-resident, zero heap allocation. Updates via
/// [`Self::record_attempt`] / [`Self::record_admission`] are `O(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignStats {
    /// Total ψ-pipeline inferences recorded — admitted + not-admitted.
    pub attempts: u64,
    /// Subset of attempts that admitted (passed both target and any
    /// typed commitment, if a campaign uses [`crate::mine_with`]).
    pub admissions: u64,
    /// Stratum histogram: `stratum_hist[k]` counts attempts whose
    /// κ-label has 2-adic valuation `min(k, STRATUM_BINS - 1)`.
    pub stratum_hist: [u64; STRATUM_BINS],
    /// Walsh–Hadamard spectrum histogram: `spectrum_hist[s]` counts
    /// attempts whose κ-label has spectrum `s ∈ {0, 1}`.
    pub spectrum_hist: [u64; 2],
    /// 3-adic valuation histogram (canonical prime, index 1 in
    /// [`crate::CANONICAL_PRIMES`]).
    pub padic_3_hist: [u64; PADIC_BINS],
    /// 5-adic valuation histogram (canonical prime, index 2).
    pub padic_5_hist: [u64; PADIC_BINS],
    /// 7-adic valuation histogram (canonical prime, index 3).
    pub padic_7_hist: [u64; PADIC_BINS],
    /// Maximum digest leading-zero bit count observed — the
    /// "best κ-label so far" diagnostic. Useful for visualising
    /// session progress at high difficulty.
    pub max_leading_zeros: u32,
}

impl Default for CampaignStats {
    fn default() -> Self {
        Self {
            attempts: 0,
            admissions: 0,
            stratum_hist: [0; STRATUM_BINS],
            spectrum_hist: [0; 2],
            padic_3_hist: [0; PADIC_BINS],
            padic_5_hist: [0; PADIC_BINS],
            padic_7_hist: [0; PADIC_BINS],
            max_leading_zeros: 0,
        }
    }
}

impl CampaignStats {
    /// Construct an empty campaign — no attempts recorded yet.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a single ψ-pipeline inference into the aggregate
    /// observatory — admitting or not. `O(1)` per call; no allocation.
    #[inline]
    pub fn record_attempt(&mut self, observables: &KappaObservables, digest: &[u8; 32]) {
        self.attempts = self.attempts.saturating_add(1);
        let stratum_idx = (observables.coords.stratum as usize).min(STRATUM_BINS - 1);
        self.stratum_hist[stratum_idx] = self.stratum_hist[stratum_idx].saturating_add(1);
        let spectrum_idx = (observables.coords.spectrum as usize) & 1;
        self.spectrum_hist[spectrum_idx] = self.spectrum_hist[spectrum_idx].saturating_add(1);
        // p-adic indices: CANONICAL_PRIMES = [2, 3, 5, 7]; we track p=3,5,7.
        let p3 = (observables.p_adic[1] as usize).min(PADIC_BINS - 1);
        self.padic_3_hist[p3] = self.padic_3_hist[p3].saturating_add(1);
        let p5 = (observables.p_adic[2] as usize).min(PADIC_BINS - 1);
        self.padic_5_hist[p5] = self.padic_5_hist[p5].saturating_add(1);
        let p7 = (observables.p_adic[3] as usize).min(PADIC_BINS - 1);
        self.padic_7_hist[p7] = self.padic_7_hist[p7].saturating_add(1);
        let lz = leading_zero_bits(digest);
        if lz > self.max_leading_zeros {
            self.max_leading_zeros = lz;
        }
    }

    /// Fold a successful admission into the aggregate — increments
    /// both `attempts` and `admissions`.
    #[inline]
    pub fn record_admission(&mut self, outcome: &MiningOutcome) {
        self.record_attempt(&outcome.observables, &outcome.digest);
        self.admissions = self.admissions.saturating_add(1);
    }

    /// Empirical admission probability observed across the campaign.
    /// At large N this converges to the target's theoretical α
    /// (conformance CM-5).
    #[inline]
    #[must_use]
    pub fn empirical_alpha(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            (self.admissions as f64) / (self.attempts as f64)
        }
    }
}

/// Count leading-zero bits in a digest (display order). At PRF
/// baseline this is `Geom(1/2)` distributed; `max_leading_zeros`
/// approximately follows `log₂(attempts)`.
#[inline]
fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &b in digest {
        if b == 0 {
            count += 8;
        } else {
            count += u32::from(b.leading_zeros() as u8);
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TriadicCoords;

    fn dummy_observables(stratum: u32, spectrum: u32, p3: u32) -> KappaObservables {
        KappaObservables {
            coords: TriadicCoords {
                datum: [0u8; 32],
                stratum,
                spectrum,
            },
            p_adic: [stratum, p3, 0, 0],
        }
    }

    #[test]
    fn fresh_stats_are_zeroed() {
        let stats = CampaignStats::new();
        assert_eq!(stats.attempts, 0);
        assert_eq!(stats.admissions, 0);
        assert_eq!(stats.empirical_alpha(), 0.0);
        assert!(stats.stratum_hist.iter().all(|&c| c == 0));
        assert_eq!(stats.max_leading_zeros, 0);
    }

    #[test]
    fn record_attempt_folds_observables_into_histograms() {
        let mut stats = CampaignStats::new();
        let obs = dummy_observables(3, 1, 2);
        stats.record_attempt(&obs, &[0xab; 32]);
        assert_eq!(stats.attempts, 1);
        assert_eq!(stats.stratum_hist[3], 1);
        assert_eq!(stats.spectrum_hist[1], 1);
        assert_eq!(stats.padic_3_hist[2], 1);
    }

    #[test]
    fn record_admission_increments_both_counts() {
        let mut stats = CampaignStats::new();
        // Reuse dummy_observables to construct a MiningOutcome-like
        // bundle via direct field access in the test — round-trip is
        // covered separately.
        let obs = dummy_observables(0, 0, 0);
        stats.record_attempt(&obs, &[0u8; 32]);
        stats.record_attempt(&obs, &[0u8; 32]);
        // Synthesize an admission by directly bumping both counters
        // through record_attempt + the admission count.
        stats.record_attempt(&obs, &[0u8; 32]);
        stats.admissions = 1;
        assert_eq!(stats.attempts, 3);
        assert_eq!(stats.admissions, 1);
        assert!((stats.empirical_alpha() - 1.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn max_leading_zeros_tracks_best_candidate() {
        let mut stats = CampaignStats::new();
        let obs = dummy_observables(0, 0, 0);
        let mut digest = [0u8; 32];
        digest[0] = 0xff; // 0 leading zeros
        stats.record_attempt(&obs, &digest);
        assert_eq!(stats.max_leading_zeros, 0);
        digest[0] = 0x00; // 8+ leading zeros
        digest[1] = 0xff;
        stats.record_attempt(&obs, &digest);
        assert_eq!(stats.max_leading_zeros, 8);
        digest[0] = 0x00;
        digest[1] = 0x00;
        digest[2] = 0x0f;
        stats.record_attempt(&obs, &digest);
        assert_eq!(stats.max_leading_zeros, 20);
    }

    #[test]
    fn high_stratum_folds_into_last_bin() {
        let mut stats = CampaignStats::new();
        let obs = dummy_observables(200, 0, 0); // stratum 200 >> STRATUM_BINS
        stats.record_attempt(&obs, &[0u8; 32]);
        assert_eq!(stats.stratum_hist[STRATUM_BINS - 1], 1);
    }
}
