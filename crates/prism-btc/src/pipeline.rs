//! prism-btc's public entry point — the ψ-pipeline block-address
//! inference, as a UOR-ADDR realization.
//!
//! 1. The host serializes a [`BlockHeader`] + candidate nonce to the
//!    80-byte wire form ([`crate::ops::header::serialize_header`]) — the
//!    ADR-060 canonical form — and wraps it in a
//!    [`BlockHeaderCarrier`](crate::model::BlockHeaderCarrier).
//! 2. [`set_thread_target`] publishes the difficulty target's κ-label form
//!    on a thread-local slot, then [`BitcoinAddressModel::forward`] runs
//!    the shared ψ-tower: ψ₁–ψ₈ thread the borrowed carrier through, and
//!    ψ₉ folds it through the `sha256d` σ-axis to mint the
//!    `sha256d:<64hex>` κ-label (the block hash in display order).
//! 3. Foundation's `run_route` evaluates the model's `C = TargetCommitment`
//!    on the κ-label: admission `kappa_label ≤ target_label` is Bitcoin's
//!    PoW relation `block_hash ≤ target`. On non-admission, run_route
//!    returns `PipelineFailure::ShapeViolation`; on admission it seals a
//!    `Grounded`, from which [`AddressOutcome`](uor_addr::AddressOutcome)
//!    extracts the κ-label + replayable TC-05
//!    [`AddressWitness`](uor_addr::AddressWitness) — **the proof-of-work
//!    witness**.
//!
//! [`mine_at`] is a single inference at one nonce; [`mine`] scans the
//! 32-bit nonce space and returns the first admitting outcome.

use core::cell::Cell;

use uor_addr::{AddressOutcome, AddressWitness, KappaLabel};

use crate::domain::{BlockHeader, Target};
use crate::model::{BitcoinAddressModel, BlockHeaderCarrier, BLOCK_ADDRESS_LABEL_BYTES};
use crate::observables::KappaObservables;
use crate::ops::header::serialize_header;
use crate::ops::sha256::sha256d_display;

/// κ-label byte width for the `sha256d` σ-axis (`sha256d:<64hex>` = 72).
const LABEL: usize = BLOCK_ADDRESS_LABEL_BYTES;

/// The result of a successful [`mine`] / [`mine_at`] inference. The
/// `block_hash` (κ-label / 32-byte display digest) is guaranteed to
/// satisfy the host-supplied target — `Ok(MiningOutcome)` is returned only
/// when foundation's `run_route` admits.
#[derive(Debug)]
pub struct MiningOutcome {
    /// The replayable TC-05 proof-of-work witness (owns its trace +
    /// fingerprint). [`AddressWitness::verify`] re-certifies the
    /// derivation without re-invoking the σ-axis.
    pub witness: AddressWitness<LABEL, 32>,
    /// The `sha256d:<64hex>` κ-label — the conventional Bitcoin block hash
    /// (display order) as a typed reference.
    pub address: KappaLabel<LABEL>,
    /// The winning nonce (canonical Bitcoin LE).
    pub nonce: u32,
    /// The 32-byte block hash in display order (big-endian).
    pub digest: [u8; 32],
    /// The 80-byte wire-format header that addresses to `digest` — for the
    /// host-boundary `submitblock` path.
    pub wire_format_header: [u8; 80],
    /// Canonical UOR property landscape of the block hash — triadic
    /// coordinates (stratum + spectrum) plus p-adic valuations. The
    /// receiver-side typed lens; always computed, stack-resident.
    pub observables: KappaObservables,
}

/// Failure modes from [`mine`] / [`mine_at`].
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

// ─── Thread-local target slot ──────────────────────────────────────────
//
// `LexicographicLessEqThreshold::target` requires `&'static [u8]`. The
// macro-emitted `BitcoinAddressModel::commitment()` body reads the active
// target κ-label from this slot, so `mine`/`mine_at` publish it before
// invoking `forward`. Concurrent miners on independent threads have
// independent slots.

thread_local! {
    static THREAD_TARGET: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
}

/// Publish the thread-local active target as its κ-label-form threshold
/// (`sha256d:<targethex>`). Idempotent — repeated calls with the same
/// target resolve to the same `&'static [u8]` via the leak registry.
///
/// The public entry points call this automatically; callers invoking
/// [`BitcoinAddressModel::forward`] directly must call it first so the
/// model's `commitment()` body can read the target.
pub fn set_thread_target(target: &Target) {
    let pinned = crate::commitment::leak_target(target.to_bytes());
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Like [`set_thread_target`] but takes raw 32-byte (display-order) target
/// bytes — useful for tests constructing a target directly.
pub fn set_thread_target_bytes(bytes: [u8; 32]) {
    let pinned = crate::commitment::leak_target(bytes);
    THREAD_TARGET.with(|cell| cell.set(Some(pinned)));
}

/// Read the thread-local active target κ-label. Panics if none has been
/// set — every entry point sets it before invoking `forward`, so the panic
/// path indicates a direct `forward()` call without a target preface.
#[must_use]
pub fn current_thread_target() -> &'static [u8] {
    THREAD_TARGET.with(|cell| {
        cell.get()
            .expect("prism-btc: no active target on this thread; call mine() / set_thread_target() before forward()")
    })
}

/// **A single ψ-pipeline block-address inference** at a specific nonce.
///
/// Serializes `(header, nonce)`, addresses it through
/// [`BitcoinAddressModel`], and reports whether the resulting block hash
/// satisfies `target` (evaluated inside foundation's `run_route` via the
/// pinned `C = TargetCommitment`).
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

/// **prism-btc's public mining entry point** — scan the 32-bit nonce space
/// for an admitting block hash.
///
/// Publishes `target` once, then addresses `(header, nonce)` for
/// `nonce = 0, 1, …` until the κ-label satisfies the target, returning the
/// first admitting [`MiningOutcome`]. If the whole nonce space is exhausted
/// without admission, returns [`MiningFailure::DidNotAdmit`] carrying the
/// final candidate (the host then varies the template — timestamp /
/// extranonce — and retries).
///
/// # Errors
///
/// - [`MiningFailure::DidNotAdmit`] — no nonce in `[0, u32::MAX]` admitted.
/// - [`MiningFailure::PipelineFailure`] — a substrate-level shape violation.
pub fn mine(header: &BlockHeader, target: Target) -> Result<MiningOutcome, MiningFailure> {
    set_thread_target(&target);
    let mut nonce: u32 = 0;
    loop {
        match address_at(header, nonce) {
            Ok(outcome) => return Ok(outcome),
            Err(MiningFailure::PipelineFailure) => return Err(MiningFailure::PipelineFailure),
            Err(did_not_admit) => {
                if nonce == u32::MAX {
                    return Err(did_not_admit);
                }
                nonce += 1;
            }
        }
    }
}

/// One inference at `nonce`, assuming the target is already published on
/// the thread-local slot. Factored out so [`mine`]'s scan publishes the
/// target only once.
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
                address: outcome.address,
                nonce,
                digest,
                wire_format_header: wire,
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

    #[test]
    fn mine_admits_for_permissive_target() {
        // The permissive regtest target (~50% admission) must yield an
        // admitting block hash within a few nonces.
        let target = Target::new(0x207fffff);
        let header = permissive_header(1_700_000_000);
        let outcome = mine(&header, target).expect("permissive target admits");
        // The κ-label is the sha256d block hash; the witness re-verifies.
        assert!(outcome.address.starts_with("sha256d:"));
        assert_eq!(outcome.address.len(), 72);
        assert_eq!(outcome.wire_format_header.len(), 80);
        assert_eq!(outcome.witness.verify().expect("replays"), outcome.address);
    }

    #[test]
    fn admitted_block_hash_satisfies_target() {
        let target = Target::new(0x207fffff);
        let header = permissive_header(1_700_000_001);
        let outcome = mine(&header, target).expect("admits");
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
