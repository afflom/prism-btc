import PrismBtc.FreeRankProtocol
import PrismBtc.TriadicCoords

/-!
# Convergence Protocol

Formal statements covering:

1. **Host-boundary template-variation termination**: the `prism-btc-node`
   boundary loop (architecture §7) iterates header-template variations
   over the u64 extranonce space (each scanning the 32-bit nonce space).
   The loop either lands on an admitting block-hash κ-label or exhausts
   the search space; on a finite domain there is no third outcome.

   NOTE: SHA256d is the **σ-projection** (ingestion hash), NOT a UOR
   ψ-map. Foundation reserves ψ for the categorical functor chain
   ψ_1..ψ_9 (Constraints → Nerve → ChainComplex → HomologyGroups →
   Betti → CochainComplex → CohomologyGroups → PostnikovTower →
   HomotopyGroups → KInvariants per ADR-035). SHA256d satisfies none
   of those obligations — it is a deliberately non-structure-preserving
   avalanche function. prism-btc's ψ-pipeline composes the
   k-invariant branch (ψ_1 → ψ_7 → ψ_8 → ψ_9) over Bitcoin's typed
   feature hierarchy; the canonical hash axis (`Sha256dHasher`) is
   consumed by resolvers as a content-addressing primitive, not by
   the verb body's term composition (substrate-enforced ψ-residuals
   discipline per ADR-035).

2. **BlockHash Witt commitment**: a `BlockHash` is a 32-tuple of W8
   elements (32 independent sites of Z/(2^8)Z), NOT a single W256
   element of Z/(2^256)Z. The `blockHashSiteWittBits` constant (= 8)
   names the per-site Witt reference level explicitly.
-/

/-- The per-site Witt level for `BlockHash` sites. -/
def blockHashSiteWittBits : Nat := 8

/-- The host-boundary extranonce variation space is finite — bounded
    by 2^64. -/
theorem extranonce_space_finite : Fintype (Fin UInt64.size) := inferInstance

/-- Host-boundary template-variation termination: across the
    extranonce variation space, either some variation produces an
    admitting κ-derivation (the loop returns `Some`) or the space is
    exhausted with no admission (every variation returns `None`).
    There is no third outcome on a finite domain. -/
theorem host_boundary_terminates_or_extranonce_exhausted
    {T : Type} (variations : Fin UInt64.size → Option T) :
    (∃ n : Fin UInt64.size, (variations n).isSome) ∨
    (∀ n : Fin UInt64.size, (variations n).isNone) := by
  by_cases h : ∃ n, (variations n).isSome
  · exact Or.inl h
  · push_neg at h
    exact Or.inr (fun n => Option.not_isSome_iff_isNone.mp (h n))

/-- A `BlockHash` occupies 32 independent W8 sites, not a single W256
    ring element. Each site is Z/(2^8)Z; the total Datum space has
    256^32 = 2^256 values. This theorem records the arithmetic
    identity: 32 sites × 8 bits/site = 256 bits. -/
theorem block_hash_is_32_tuple_w8 :
    (32 : Nat) * blockHashSiteWittBits = 256 := by norm_num [blockHashSiteWittBits]

/-- The per-site Witt level for `BlockHash` is W8 (wittBits = 8). -/
theorem block_hash_site_witt_bits_eq_8 : blockHashSiteWittBits = 8 := rfl
