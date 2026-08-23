//! Normalized, protocol-independent mint stage model.
//!
//! Native on-chain SeaDrop state and OpenSea's off-chain stage metadata
//! are two different shapes describing the same underlying idea: a
//! time-boxed opportunity to mint at some price, subject to some
//! eligibility mechanism. This module is the one shape both are meant to
//! feed into, so stage *selection* ([`crate::execution::stage_resolver`])
//! never needs to know which protocol produced a given stage -- and never
//! trusts a UI label (e.g. "OG", "Founders") as protocol semantics; only
//! [`StageProtocol`] is ever selected on.

use alloy_primitives::U256;
use time::OffsetDateTime;

use super::timing::{PhaseWindow, StageStatus};

/// The actual authorization mechanism a stage uses. Never inferred from a
/// display label -- only from independently-verified protocol semantics
/// (on-chain `PublicDrop` config, a signed OpenSea authorization's own
/// declared stage type, etc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageProtocol {
    Public,
    Allowlist,
    SignedPresale,
    Fcfs,
    Fcfa,
    /// A thirdweb Drop claim condition (multi-phase or single-phase --
    /// see `StageId::ThirdwebMultiPhase`/`ThirdwebSinglePhase`). Never
    /// discovered alongside SeaDrop/OpenSea stages for the same
    /// collection today -- `--engine thirdweb` is explicit-only, its own
    /// protocol-exclusive stage list -- so this variant's exact rank
    /// relative to the SeaDrop/OpenSea tiers has no observable effect
    /// yet; it exists for `StageProtocol`'s own exhaustive matches.
    ThirdwebClaim,
    /// A Manifold `LazyPayableClaim` claim instance. Same "protocol
    /// exclusive today" note as `ThirdwebClaim`.
    ManifoldClaim,
}

/// What Kairox currently knows about whether the configured wallet may
/// mint in this stage. Deliberately never collapsed to a boolean: an
/// unresolved future signed stage is honestly [`Self::UnknownUntilActive`],
/// never assumed either way (brief section 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityState {
    /// Positive evidence exists -- e.g. authoritative on-chain state for a
    /// public stage, or a successful, locally-validated OpenSea
    /// wallet-specific authorization for a signed stage.
    Eligible,
    /// Negative evidence exists -- e.g. an explicit OpenSea ineligibility
    /// rejection with clear semantics, or wallet allocation already
    /// exhausted.
    Ineligible { reason: String },
    /// No legitimate wallet-preflight eligibility check exists for this
    /// stage before it activates. Never claimed `Eligible` on a guess --
    /// see brief section 15.
    UnknownUntilActive,
    /// This stage's protocol/authorization mechanism has no implemented
    /// adapter at all (e.g. token-gated, CAPTCHA, proprietary queue).
    Unsupported { reason: String },
}

/// Uniquely identifies one stage, for exclusion/re-resolution purposes --
/// deliberately distinct from [`StageExecutionRef`], which carries
/// whatever is needed to actually *act* on a stage once selected. An
/// OpenSea collection slug identifies the whole drop, never one exact
/// stage within it (a drop can have several stages -- signed presale,
/// then public -- sharing the same slug); conflating the two let
/// rejecting one OpenSea stage incorrectly exclude every stage of that
/// drop. See [`StageExecutionRef::OpenSea`]'s doc comment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StageId {
    /// The collection's single on-chain `PublicDrop` config -- there is
    /// only ever one per collection, so no further identity is needed.
    OnChainPublic,
    /// OpenSea's own per-stage `uuid` -- the one field in a
    /// `DropStageResponse` that actually identifies *this* stage, not
    /// the drop it belongs to.
    OpenSea { stage_uuid: String },
    /// A thirdweb multi-phase (`Drop`/`IClaimConditionMultiPhase`) claim
    /// condition. `condition_id` is the exact on-chain condition id this
    /// stage represents -- authoritative, never invented (see
    /// `cli::commands::resolver_adapters::discover_thirdweb_stages`'s
    /// doc comment for how it's resolved). Two different condition ids
    /// are two different stages, even on the same `drop_contract`, so
    /// watch's re-resolution can correctly detect "the specific
    /// condition being watched changed identity" (e.g. the creator
    /// reconfigured conditions) rather than silently treating a
    /// different condition as the same stage.
    ThirdwebMultiPhase {
        drop_contract: alloy_primitives::Address,
        condition_id: alloy_primitives::U256,
    },
    /// A thirdweb single-phase (`DropSinglePhase`) claim condition. No
    /// condition id exists in this flavor's ABI at all (see
    /// `protocol::thirdweb`'s module doc comment) -- `drop_contract`
    /// alone is the whole identity, since a single-phase contract has
    /// exactly one condition, ever.
    ThirdwebSinglePhase {
        drop_contract: alloy_primitives::Address,
    },
    /// A Manifold `LazyPayableClaim` claim instance. All three
    /// identifiers are required -- see `protocol::manifold`'s module doc
    /// comment for why neither `creator_contract` nor `instance_id`
    /// alone identifies a claim, and `execution::manifold_registry`'s
    /// doc comment for why `extension_contract` (not a per-collection
    /// proxy) is the address whose identity/provenance actually matters.
    ManifoldClaim {
        extension_contract: alloy_primitives::Address,
        creator_contract: alloy_primitives::Address,
        instance_id: alloy_primitives::U256,
    },
}

/// What's needed to actually execute against a selected stage. Carries
/// exactly the routing information the execution engines need -- never
/// stage identity (see [`StageId`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageExecutionRef {
    PublicSeaDrop,
    /// `slug` is the OpenSea *drop/collection* identifier -- the
    /// `POST /api/v2/drops/{slug}/mint` request target. It is never a
    /// per-stage identifier; that's [`StageId::OpenSea`]'s job.
    OpenSea {
        slug: String,
    },
    /// `drop_contract` is both the NFT and the claim logic, exactly as
    /// for explicit `--engine thirdweb` -- see
    /// `EngineSelection::Thirdweb`'s doc comment. The engine
    /// (`execution::thirdweb_engine::run_thirdweb_mint`) re-establishes
    /// provenance and re-resolves the active/single-phase condition
    /// itself at execution time; this ref carries no flavor or condition
    /// id, since the contract's own `claim()` call is condition-id-
    /// agnostic (it internally determines the active condition itself --
    /// verified against `Drop.sol`'s `getActiveClaimConditionId`).
    Thirdweb {
        drop_contract: alloy_primitives::Address,
    },
    /// See `protocol::manifold`'s module doc comment for why all three
    /// identifiers are required.
    Manifold {
        extension_contract: alloy_primitives::Address,
        creator_contract: alloy_primitives::Address,
        instance_id: alloy_primitives::U256,
    },
}

/// One normalized mint opportunity, however it was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedStage {
    /// This exact stage's unique identity -- see [`StageId`]'s doc
    /// comment for why this is a typed enum, not a raw string reused
    /// from whatever discovery happened to have on hand.
    pub id: StageId,
    /// What's needed to actually execute against this stage once
    /// selected -- see [`StageExecutionRef`].
    pub execution: StageExecutionRef,
    pub protocol: StageProtocol,
    /// Display-only. Never consulted for protocol/eligibility decisions.
    pub label: Option<String>,
    pub window: PhaseWindow,
    /// `None` only when price genuinely cannot yet be established --
    /// never a placeholder for "assume free" or "assume paid".
    pub price_per_token_wei: Option<U256>,
    pub max_per_wallet: Option<u64>,
    pub wallet_minted: Option<u64>,
    /// Remaining stage-scoped or collection-scoped supply, whichever is
    /// the tighter authoritative bound currently known. `None` when
    /// genuinely unknown -- never assumed unlimited.
    pub supply_remaining: Option<u64>,
    pub eligibility: EligibilityState,
    /// Human-readable description of what was actually checked to
    /// classify this stage -- printed in resolution reports, never used
    /// for any decision itself.
    pub evidence: String,
}

impl NormalizedStage {
    pub fn status(&self, now: OffsetDateTime) -> StageStatus {
        self.window.status(now)
    }

    /// `None` when either bound is unknown -- never assumed unlimited.
    pub fn remaining_wallet_allocation(&self) -> Option<u64> {
        match (self.max_per_wallet, self.wallet_minted) {
            (Some(max), Some(minted)) => Some(max.saturating_sub(minted)),
            _ => None,
        }
    }

    /// `false` only when a known bound (wallet allocation or supply) is
    /// provably exhausted. `None`/unknown bounds never block a stage --
    /// that is a caller's job to refuse at quantity-validation time with
    /// specific evidence, not this pass/fail gate's job to guess about.
    pub fn has_known_capacity(&self) -> bool {
        if self.supply_remaining == Some(0) {
            return false;
        }
        if self.remaining_wallet_allocation() == Some(0) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn window() -> PhaseWindow {
        PhaseWindow {
            start: datetime!(2026-08-16 12:00:00 UTC),
            end: datetime!(2026-08-16 13:00:00 UTC),
        }
    }

    fn stage() -> NormalizedStage {
        NormalizedStage {
            id: StageId::OpenSea {
                stage_uuid: "s1".to_string(),
            },
            execution: StageExecutionRef::OpenSea {
                slug: "test-collection".to_string(),
            },
            protocol: StageProtocol::Fcfa,
            label: None,
            window: window(),
            price_per_token_wei: Some(U256::ZERO),
            max_per_wallet: Some(10),
            wallet_minted: Some(6),
            supply_remaining: Some(100),
            eligibility: EligibilityState::Eligible,
            evidence: "test".to_string(),
        }
    }

    #[test]
    fn remaining_wallet_allocation_subtracts_minted_from_max() {
        assert_eq!(stage().remaining_wallet_allocation(), Some(4));
    }

    #[test]
    fn remaining_wallet_allocation_unknown_when_either_bound_unknown() {
        let mut s = stage();
        s.max_per_wallet = None;
        assert_eq!(s.remaining_wallet_allocation(), None);
    }

    #[test]
    fn has_known_capacity_false_when_wallet_allocation_exhausted() {
        let mut s = stage();
        s.wallet_minted = Some(10);
        assert!(!s.has_known_capacity());
    }

    #[test]
    fn has_known_capacity_false_when_supply_exhausted() {
        let mut s = stage();
        s.supply_remaining = Some(0);
        assert!(!s.has_known_capacity());
    }

    #[test]
    fn has_known_capacity_true_when_unknown_bounds_present() {
        let mut s = stage();
        s.max_per_wallet = None;
        s.wallet_minted = None;
        s.supply_remaining = None;
        assert!(s.has_known_capacity());
    }
}
