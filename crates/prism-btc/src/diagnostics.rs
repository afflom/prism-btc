//! Diagnostic surface for the ψ-pipeline's iterative-resolution
//! discipline (wiki `iterative-resolution.md`). Captures the per-
//! `forward()` resolver progress through the W32 nonce ring as a
//! parallel observability channel to [`crate::pipeline::MiningOutcome`].
//!
//! ## What this surfaces
//!
//! The wiki's iterative-resolution discipline names two per-resolver
//! observables that prism-btc's ψ_9 realizes:
//!
//! - **`free_rank`** — count of unpinned [`crate::model::MiningResult`]
//!   sites at resolver exit. 0 on convergence (all 80 sites pinned —
//!   the admitting wire-format header is committed); 4 on exhaustion
//!   (the four nonce-byte sites remain free — the σ-projection
//!   admission relation has no inhabitant in the W32 witt domain for
//!   this `(prefix, target)`).
//!
//! - **`iterations`** — count of W32 candidate evaluations the
//!   resolver executed. `admitting_nonce + 1` on convergence;
//!   `2^32` on exhaustion (the full ring walked).
//!
//! The terminal verdict is one of [`ResolutionVerdict::Converged`]
//! (admission witness) or [`ResolutionVerdict::Exhausted`] (the
//! canonical `proof:InhabitanceImpossibilityWitness`).
//!
//! ## How to read it
//!
//! On the `Ok` path, [`crate::pipeline::mine`] populates
//! [`crate::pipeline::MiningOutcome::resolution`] directly (the
//! channel is drained as part of returning the outcome). On the
//! `Err` path, call [`take_resolution_state`] to drain the diagnostic
//! state from the most recent ψ_9 invocation on this thread.
//!
//! Direct [`uor_foundation::pipeline::PrismModel::forward`] callers
//! (without going through `mine()`) read via `take_resolution_state`
//! in either case — `forward()` does not drain the channel itself.
//!
//! ## Concurrency
//!
//! The state channel is thread-local; concurrent miners on separate
//! threads have independent state, so no synchronisation is required.
//! The channel is gated on the `std` feature (the default); under
//! `no_std`, the recording side-effect is a no-op and
//! [`take_resolution_state`] returns `None`.

/// Per-`forward()` diagnostic state from the ψ_9 iterative-resolution
/// loop. See the [module-level documentation](self) for the operational
/// semantics of each field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionState {
    /// Count of unpinned [`crate::model::MiningResult`] sites at
    /// resolver exit.
    ///
    /// - `0` on [`ResolutionVerdict::Converged`] (all 80 sites pinned).
    /// - `4` on [`ResolutionVerdict::Exhausted`] (sites 76..80 remain
    ///   free — the nonce-byte sites could not be pinned for this
    ///   `(prefix, target)` constraint geometry).
    pub free_rank: u32,

    /// Count of W32 candidate evaluations the resolver executed before
    /// exiting.
    ///
    /// - `admitting_nonce + 1` on [`ResolutionVerdict::Converged`]
    ///   (the resolver iterates `0, 1, …, admitting_nonce`).
    /// - `2^32` on [`ResolutionVerdict::Exhausted`] (the full witt
    ///   ring walked).
    pub iterations: u64,

    /// Terminal verdict of the iterative-resolution loop on the
    /// finite W32 witt domain.
    pub verdict: ResolutionVerdict,
}

impl ResolutionState {
    /// True iff the resolver pinned all 80 sites of `MiningResult` —
    /// `verdict` is [`ResolutionVerdict::Converged`] and `free_rank`
    /// is `0`.
    #[inline]
    #[must_use]
    pub fn converged(&self) -> bool {
        matches!(self.verdict, ResolutionVerdict::Converged { .. })
    }

    /// True iff the resolver exhausted the W32 ring without admission
    /// — the canonical `proof:InhabitanceImpossibilityWitness` for
    /// this `(prefix, target)`.
    #[inline]
    #[must_use]
    pub fn exhausted(&self) -> bool {
        matches!(self.verdict, ResolutionVerdict::Exhausted)
    }

    /// The admitting nonce on [`ResolutionVerdict::Converged`];
    /// `None` on `Exhausted`.
    #[inline]
    #[must_use]
    pub fn admitting_nonce(&self) -> Option<u32> {
        match self.verdict {
            ResolutionVerdict::Converged { admitting_nonce } => Some(admitting_nonce),
            ResolutionVerdict::Exhausted => None,
        }
    }
}

/// The two terminal verdicts of ψ_9's iterative-resolution loop on the
/// finite W32 witt domain. Exactly one is reached for any
/// `(prefix, target)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionVerdict {
    /// The structural admission relation `H(header) ≤ target` was
    /// satisfied at this nonce; the four nonce-byte sites (positions
    /// 76..80) are pinned to the admitting candidate's bytes (LE).
    Converged {
        /// The admitting nonce value (4-byte LE encoding lives at
        /// bytes 76..80 of the emitted wire-format header).
        admitting_nonce: u32,
    },
    /// The W32 ring was walked end-to-end without admission — the
    /// canonical `proof:InhabitanceImpossibilityWitness` for this
    /// `(prefix, target)` constraint geometry. The host boundary
    /// (architecture §7) varies the template-derived `MiningTask`
    /// (extranonce roll) and retries.
    Exhausted,
}

// ─── Thread-local channel ──────────────────────────────────────────────

#[cfg(feature = "std")]
mod channel {
    use super::ResolutionState;
    use std::cell::Cell;

    std::thread_local! {
        static LAST: Cell<Option<ResolutionState>> = const { Cell::new(None) };
    }

    pub(crate) fn record(state: ResolutionState) {
        LAST.with(|c| c.set(Some(state)));
    }

    pub(crate) fn take() -> Option<ResolutionState> {
        LAST.with(Cell::take)
    }
}

#[cfg(not(feature = "std"))]
mod channel {
    use super::ResolutionState;

    pub(crate) fn record(_: ResolutionState) {}

    pub(crate) fn take() -> Option<ResolutionState> {
        None
    }
}

/// Record the resolution state from a ψ_9 invocation. Called by
/// [`crate::resolvers::BitcoinKInvariantResolver::resolve`] before
/// returning.
#[inline]
pub(crate) fn record(state: ResolutionState) {
    channel::record(state);
}

/// Drain and return the diagnostic state from the most recent ψ_9
/// invocation on this thread.
///
/// Returns `None` if no resolver has run since the last
/// `take_resolution_state` call (i.e. the channel was already
/// drained), or if the crate is compiled `no_std` (the channel does
/// not exist).
///
/// [`crate::pipeline::mine`]'s `Ok` path drains the channel and
/// includes the state in `MiningOutcome::resolution`; use
/// `take_resolution_state` directly on the `Err` path to inspect the
/// `Exhausted` verdict, or after a direct
/// [`uor_foundation::pipeline::PrismModel::forward`] call.
#[must_use]
pub fn take_resolution_state() -> Option<ResolutionState> {
    channel::take()
}
