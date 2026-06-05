//! prism-btc's public entry — the ψ-pipeline **recognition** of an
//! admitted block-address inference, as a UOR-ADDR realization.
//!
//! The kernel exposes **one admission body**, [`mine_at`]: a single
//! recognition of `(header, nonce)` against `target`. There is no scan
//! loop here — the act of admitting is the act of *recognizing* one
//! canonical-form candidate; if the candidate is rejected, the host
//! varies its stream (next nonce, next extranonce, next template) and
//! calls back. The kernel never owns the iteration.
//!
//! Body of one recognition:
//!
//! 1. Serialize `(header, nonce)` to the 80-byte ADR-060 wire form
//!    ([`crate::ops::header::serialize_header`]) and wrap it in a
//!    [`BlockHeaderCarrier`].
//! 2. Publish the target's κ-label form on a per-thread slot
//!    (implementation detail — `pub(crate)` and never visible on the
//!    public surface). Foundation's macro-emitted
//!    [`BitcoinAddressModel::commitment()`](crate::model::BitcoinAddressModel)
//!    body reads this slot to construct the pinned `TargetCommitment`
//!    each `forward()` evaluates.
//! 3. [`BitcoinAddressModel`]'s `forward` runs the shared ψ-tower:
//!    ψ₁–ψ₈ thread the borrowed carrier through; ψ₉ folds it through
//!    the `sha256d` σ-axis to mint the `sha256d:<64hex>` κ-label
//!    (the block hash in display order).
//! 4. Foundation's `run_route` evaluates the model's
//!    `C = TargetCommitment` on the κ-label: admission
//!    `kappa_label ≤ target_label` is Bitcoin's PoW relation. On
//!    non-admission, run_route returns
//!    `PipelineFailure::ShapeViolation`; on admission it seals a
//!    `Grounded`, from which
//!    [`AddressOutcome`] extracts the
//!    κ-label + replayable TC-05
//!    [`AddressWitness`] — **the
//!    proof-of-work witness**.
//!
//! The [`MiningOutcome`] returned is a **witness projection**: every
//! field is derivable from `(witness, wire_format_header)` by replaying
//! the σ-axis (L3, L5). The fields exist for ergonomics, not as
//! independent truth.
//!
//! For V&V tests that drive [`BitcoinAddressModel`]'s `forward` directly
//! to inspect structural properties without an admission relation, use
//! [`recognize_under`] — a scoped helper that publishes the target,
//! runs a closure, and is the only public way to enter the ψ-pipeline
//! outside [`mine_at`].

use core::cell::Cell;

use uor_addr::{AddressOutcome, AddressWitness, KappaLabel};

use crate::domain::{BlockHeader, Target};
use crate::model::{BitcoinAddressModel, BlockHeaderCarrier, BLOCK_ADDRESS_LABEL_BYTES};
use crate::observables::KappaObservables;
use crate::ops::header::serialize_header;
use crate::ops::sha256::sha256d_display;

/// κ-label byte width for the `sha256d` σ-axis (`sha256d:<64hex>` = 72).
const LABEL: usize = BLOCK_ADDRESS_LABEL_BYTES;

/// The recognized result of a [`mine_at`] inference — a **witness
/// projection**.
///
/// `(witness, wire_format_header)` are the canonical pair; every other
/// field is derivable from those two by replaying the σ-axis (L3, L5).
/// The eagerly-stored projections — `address`, `nonce`, `digest`,
/// `observables` — exist for caller ergonomics; they are *not*
/// independent truth, and any of them can be re-derived from the pair:
///
/// - `address == witness.kappa_label()`
/// - `digest == sha256d_display(&wire_format_header)`
/// - `nonce == u32::from_le_bytes(wire_format_header[76..80])`
/// - `observables == KappaObservables::from_digest(&digest)`
///
/// `Ok(MiningOutcome)` is returned only when foundation's `run_route`
/// admits — the witness existence *is* the admission relation.
#[derive(Debug)]
pub struct MiningOutcome {
    /// The replayable TC-05 proof-of-work witness (owns its trace +
    /// fingerprint). [`AddressWitness::verify`] re-certifies the
    /// derivation without re-invoking the σ-axis.
    pub witness: AddressWitness<LABEL, 32>,
    /// The 80-byte wire-format header that re-derives to `digest`. The
    /// canonical-form companion to the witness; together they admit
    /// total re-derivation of every other field (L5).
    pub wire_format_header: [u8; 80],
    /// Projection: the `sha256d:<64hex>` κ-label — equal to
    /// `witness.kappa_label()`.
    pub address: KappaLabel<LABEL>,
    /// Projection: the recognized nonce (canonical Bitcoin LE) — equal
    /// to `u32::from_le_bytes(wire_format_header[76..80])`.
    pub nonce: u32,
    /// Projection: the 32-byte block hash in display order — equal to
    /// `sha256d_display(&wire_format_header)`.
    pub digest: [u8; 32],
    /// Projection: canonical UOR property landscape of the block hash —
    /// triadic coordinates (stratum + spectrum) plus p-adic valuations.
    /// Equal to `KappaObservables::from_digest(&digest)`.
    pub observables: KappaObservables,
}

/// Failure modes from [`mine_at`].
///
/// The receiver-side typed lens [`KappaObservables`] is **total** —
/// present on `Ok(MiningOutcome)` and on `DidNotAdmit` alike, so host
/// loops can aggregate every attempt into a
/// [`CampaignStats`](crate::campaign::CampaignStats) observatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningFailure {
    /// ψ₉ minted a κ-label, but the `TargetCommitment` did not admit it
    /// inside foundation's `run_route` — the block hash did not satisfy
    /// the target under `LexicographicLessEqThreshold`. The host varies
    /// the nonce (or template) and retries.
    DidNotAdmit {
        /// The non-admitting block hash's UOR property decomposition.
        observables: KappaObservables,
        /// The nonce of this candidate (canonical LE).
        nonce: u32,
        /// The candidate block hash in display order.
        digest: [u8; 32],
    },
    /// Defensive: foundation's catamorphism or a resolver returned a shape
    /// violation **before** the commitment stage. Unreachable for
    /// well-formed headers — the ψ-pipeline is total over the carrier.
    PipelineFailure,
}

// ─── Per-thread target slot (implementation detail) ────────────────────
//
// `LexicographicLessEqThreshold::target` requires `&'static [u8]`. The
// macro-emitted `BitcoinAddressModel::commitment()` body reads the active
// target κ-label from this slot, so [`mine_at`] and [`recognize_under`]
// publish it before invoking `forward`. The slot is `pub(crate)` — it is
// **not** part of the kernel's public surface, and the public API never
// exposes "set the target" as a separate step. Concurrent miners on
// independent threads have independent slots.

thread_local! {
    static THREAD_TARGET: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
}

/// Pin a target's κ-label-form threshold on this thread's slot.
/// Idempotent — repeated calls with the same target resolve to the same
/// `&'static [u8]` via the leak registry.
pub(crate) fn set_thread_target(target: &Target) {
    let pinned = crate::commitment::leak_target(target.to_bytes());
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Like [`set_thread_target`] but takes raw 32-byte (display-order)
/// target bytes — used by [`recognize_under`].
pub(crate) fn set_thread_target_bytes(bytes: [u8; 32]) {
    let pinned = crate::commitment::leak_target(bytes);
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Read the thread-local active target κ-label. Panics if none has been
/// set — every entry point publishes it before invoking `forward`, so a
/// panic here indicates a direct `forward()` call from inside the crate
/// without a recognition preface.
#[must_use]
pub(crate) fn current_thread_target() -> &'static [u8] {
    THREAD_TARGET.with(|cell| {
        cell.get()
            .expect("prism-btc: no active target on this thread; call mine_at() / recognize_under() before forward()")
    })
}

/// Scope a target threshold around `f`, the only public way to drive
/// [`BitcoinAddressModel`]'s `forward` directly without going through
/// [`mine_at`]. V&V tests inspecting ψ-pipeline structural properties
/// without an admission relation pass a permissive target (`[0xff;
/// 32]`) here.
///
/// The target is published on this thread's slot for the duration of
/// `f`; the slot is **not** cleared on exit (subsequent calls overwrite
/// it). This matches the contract of [`mine_at`]: the kernel does not
/// own a "target lifetime" concept — only a "the most recent
/// recognition pinned this target" invariant.
///
/// # Examples
///
/// ```ignore
/// use prism_btc::{recognize_under, BitcoinAddressModel, BlockHeaderCarrier, Target};
/// use prism::pipeline::PrismModel;
///
/// let wire: [u8; 80] = /* canonical-form header bytes */;
/// let label = recognize_under(Target::new(0x207fffff), || {
///     let carrier = BlockHeaderCarrier::new(&wire);
///     BitcoinAddressModel::forward(carrier).unwrap()
/// });
/// ```
pub fn recognize_under<R>(target: Target, f: impl FnOnce() -> R) -> R {
    set_thread_target(&target);
    f()
}

/// Like [`recognize_under`] but takes raw 32-byte (display-order)
/// threshold bytes — for V&V tests that need a threshold that is not
/// representable as nBits (e.g. `[0xff; 32]` to admit every κ-label).
pub fn recognize_under_bytes<R>(threshold: [u8; 32], f: impl FnOnce() -> R) -> R {
    set_thread_target_bytes(threshold);
    f()
}

/// **A single ψ-pipeline block-address inference** at a specific nonce.
///
/// Serializes `(header, nonce)` to canonical form, addresses it through
/// [`BitcoinAddressModel`], and reports whether the resulting κ-label
/// is admitted by `target` (evaluated inside foundation's `run_route`
/// via the pinned `C = TargetCommitment`).
///
/// This is the kernel's sole admission-recognition entry. The kernel
/// does **not** scan: if this nonce is not admitted, the host varies
/// its stream (next nonce, extranonce, next template) and re-invokes.
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — the block hash did not satisfy
///   `target`.
/// - [`MiningFailure::PipelineFailure`] — a substrate-level shape
///   violation before the commitment stage. Unreachable in normal flow.
pub fn mine_at(
    header: &BlockHeader,
    target: Target,
    nonce: u32,
) -> Result<MiningOutcome, MiningFailure> {
    set_thread_target(&target);
    address_at(header, nonce)
}

/// One inference at `nonce`, assuming the target is already published on
/// the thread-local slot.
fn address_at(header: &BlockHeader, nonce: u32) -> Result<MiningOutcome, MiningFailure> {
    use prism::pipeline::PrismModel;

    let wire = serialize_header(header, nonce);
    let carrier = BlockHeaderCarrier::new(&wire);

    match BitcoinAddressModel::forward(carrier) {
        Ok(grounded) => {
            let outcome = AddressOutcome::<LABEL, 32>::from_grounded(&grounded)
                .map_err(|_| MiningFailure::PipelineFailure)?;
            let digest = sha256d_display(&wire);
            Ok(MiningOutcome {
                witness: outcome.witness,
                wire_format_header: wire,
                address: outcome.address,
                nonce,
                digest,
                observables: KappaObservables::from_digest(&digest),
            })
        }
        Err(failure) => {
            let is_commitment_violation = matches!(
                &failure,
                prism::pipeline::PipelineFailure::ShapeViolation { report }
                    if report.shape_iri == "https://uor.foundation/commitment/TypedCommitment/VIOLATED"
            );
            if !is_commitment_violation {
                return Err(MiningFailure::PipelineFailure);
            }
            let digest = sha256d_display(&wire);
            Err(MiningFailure::DidNotAdmit {
                observables: KappaObservables::from_digest(&digest),
                nonce,
                digest,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Bits, MerkleRoot, Timestamp, Version};

    fn permissive_header(timestamp: u32) -> BlockHeader {
        BlockHeader {
            version: Version(1),
            prev_hash: [0u8; 32],
            merkle_root: MerkleRoot::from_bytes([0xaa; 32]),
            timestamp: Timestamp(timestamp),
            bits: Bits(0x207fffff),
        }
    }

    /// Host-side admission stream — vary the nonce until [`mine_at`]
    /// admits. This is the **bridge layer** in miniature: the kernel
    /// never owns the iteration; here it's inlined to drive a sweep
    /// for the test fixture's permissive target.
    fn admit_by_nonce_scan(header: &BlockHeader, target: Target) -> MiningOutcome {
        for nonce in 0u32..u32::MAX {
            match mine_at(header, target, nonce) {
                Ok(outcome) => return outcome,
                Err(MiningFailure::DidNotAdmit { .. }) => continue,
                Err(MiningFailure::PipelineFailure) => panic!("pipeline failure"),
            }
        }
        panic!("permissive target should admit within nonce space");
    }

    #[test]
    fn mine_at_admits_for_permissive_target() {
        // The permissive regtest target (~50% admission) yields an
        // admitting block hash within a few nonces under any host
        // iteration discipline; here the host inlines a scan.
        let target = Target::new(0x207fffff);
        let header = permissive_header(1_700_000_000);
        let outcome = admit_by_nonce_scan(&header, target);
        assert!(outcome.address.starts_with("sha256d:"));
        assert_eq!(outcome.address.len(), 72);
        assert_eq!(outcome.wire_format_header.len(), 80);
        assert_eq!(outcome.witness.verify().expect("replays"), outcome.address);
    }

    #[test]
    fn admitted_block_hash_satisfies_target() {
        let target = Target::new(0x207fffff);
        let header = permissive_header(1_700_000_001);
        let outcome = admit_by_nonce_scan(&header, target);
        // The display-order digest is ≤ the target value.
        assert!(target.is_satisfied_by_bytes(&outcome.digest));
    }

    #[test]
    fn mine_at_did_not_admit_carries_kappa_observables() {
        // A restrictive mainnet-style target rejects nonce 0 for this
        // template; the receiver-side lens is total.
        let target = Target::new(0x1d00ffff);
        let header = permissive_header(1_700_000_000);
        match mine_at(&header, target, 0) {
            Err(MiningFailure::DidNotAdmit {
                observables,
                digest,
                nonce,
            }) => {
                assert_eq!(nonce, 0);
                assert_eq!(observables, KappaObservables::from_digest(&digest));
                assert!(!target.is_satisfied_by_bytes(&digest));
            }
            other => panic!("expected DidNotAdmit, got {other:?}"),
        }
    }
}
