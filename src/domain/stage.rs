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

/// One normalized mint opportunity, however it was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedStage {
    /// Stable within one resolution -- not necessarily meaningful across
    /// separate discovery calls.
    pub id: String,
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
            id: "s1".to_string(),
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
