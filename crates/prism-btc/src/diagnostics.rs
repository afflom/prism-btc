//! Diagnostic surface for ψ_9's structural κ-derivation. Captures
//! the per-`forward()` resolver state as a parallel observability
//! channel to [`crate::pipeline::MiningOutcome`].
//!
//! ## What this surfaces
//!
//! The wiki's iterative-resolution discipline names two per-resolver
//! observables that prism-btc's ψ_9 realizes:
//!
//! - **`free_rank`** — count of unpinned [`crate::model::MiningResult`]
//!   sites after the ψ-pipeline. Always `0` for well-formed
//!   `MiningTask` inputs: the leading 76 sites are template-pinned;
//!   the four nonce-byte sites (positions 76..80) pin simultaneously
//!   to ψ_9's κ-derivation. `FreeRank = 0` is convergence at the
//!   terminal ψ-stage.
//!
//! - **`derived_nonce`** — the κ-derived nonce. The canonical hash
//!   axis projects the typed `MiningTask` to a 32-byte content-
//!   address; the leading four bytes (canonical Bitcoin little-
//!   endian) are the κ-nonce. One σ-projection per `forward()` —
//!   deterministic in the typed input.
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

/// Per-`forward()` diagnostic state from ψ_9's structural κ-derivation.
/// See the [module-level documentation](self) for the operational
/// semantics of each field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionState {
    /// Count of unpinned [`crate::model::MiningResult`] sites after
    /// the ψ-pipeline. Always `0` for well-formed `MiningTask`
    /// inputs — the structural κ-derivation pins the four nonce-byte
    /// sites simultaneously and the leading 76 sites are template-
    /// pinned.
    pub free_rank: u32,

    /// The κ-derived nonce — `u32::from_le_bytes(H(task)[..4])`
    /// where `H` is the canonical hash axis ([`crate::Sha256dHasher`])
    /// and `task` is the threaded `MiningTask` bytes
    /// (TemplatePrefix‖Target).
    pub derived_nonce: u32,
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
/// [`crate::pipeline::mine`] drains the channel and includes the
/// state in `MiningOutcome::resolution`; use `take_resolution_state`
/// directly on the `Err` path or after a direct
/// [`uor_foundation::pipeline::PrismModel::forward`] call.
#[must_use]
pub fn take_resolution_state() -> Option<ResolutionState> {
    channel::take()
}
