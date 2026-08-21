//! Selects exactly one [`NormalizedStage`] for `mint`/`watch` to act on,
//! given every stage Kairox discovered for a collection.
//!
//! This is Phase B of the Robinhood universal-resolver brief: a pure,
//! protocol-agnostic selection algorithm over an already-normalized stage
//! list. It deliberately does **not** discover stages itself (native
//! on-chain SeaDrop enumeration and OpenSea off-chain drop/stage
//! discovery are separate, larger passes -- Phase C/D -- with their own
//! network and signing-safety surface) and is **not yet wired into**
//! `cli::commands::mint`/`watch`. Every rule below is independently
//! unit-tested against synthetic [`NormalizedStage`] fixtures so the
//! selection logic itself is proven correct before any live wiring
//! depends on it.
//!
//! Chain-id verification and OpenSea-metadata/on-chain-contract-address
//! agreement are existing, separate concerns
//! ([`crate::chain::rpc::RpcClient::connect`]'s `ChainIdMismatch` check,
//! [`crate::execution::opensea_validate`]'s local calldata validation) --
//! this module only ever receives stages for a single, already-confirmed
//! chain/collection and does not re-derive that trust.

use time::OffsetDateTime;

use crate::domain::stage::{EligibilityState, NormalizedStage, StageProtocol};
use crate::domain::timing::StageStatus;

/// Non-public protocols are ranked ahead of `Public` -- a currently-active,
/// eligible-or-unknown signed/allowlist/FCFS/FCFA stage always outranks a
/// later public stage the wallet might also qualify for. This is exactly
/// the class of mistake `watch --engine public` exhibited in real use (an
/// active eligible FCFA stage existed, but the explicit-engine command
/// waited for a later public stage instead) -- `select_for_live_mint`/
/// `select_for_watch` never reproduce it. Ties within a rank break on
/// earliest stage start (the stage that opened first).
fn protocol_rank(protocol: StageProtocol) -> u8 {
    match protocol {
        StageProtocol::SignedPresale
        | StageProtocol::Fcfa
        | StageProtocol::Fcfs
        | StageProtocol::Allowlist => 0,
        StageProtocol::Public => 1,
    }
}

/// A stage is a selection candidate only when its eligibility is positive
/// or genuinely unresolved (never `Ineligible`/`Unsupported`), and no
/// already-known bound (wallet allocation, supply) is exhausted.
fn is_candidate(stage: &NormalizedStage) -> bool {
    matches!(
        stage.eligibility,
        EligibilityState::Eligible | EligibilityState::UnknownUntilActive
    ) && stage.has_known_capacity()
}

fn rank_key(stage: &NormalizedStage) -> (u8, OffsetDateTime) {
    (protocol_rank(stage.protocol), stage.window.start)
}

fn summarize(stages: &[NormalizedStage], now: OffsetDateTime) -> String {
    if stages.is_empty() {
        return "no stages were discovered for this collection".to_string();
    }
    stages
        .iter()
        .map(|s| {
            format!(
                "{:?}{} (status {:?}, eligibility {:?}{})",
                s.protocol,
                s.label
                    .as_deref()
                    .map(|l| format!(" {l:?}"))
                    .unwrap_or_default(),
                s.status(now),
                s.eligibility,
                if s.has_known_capacity() {
                    ""
                } else {
                    ", capacity exhausted"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// What `mint --engine auto` should do: exactly one selected active
/// stage, or a specific, actionable reason nothing qualifies right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveStageDecision {
    Selected(Box<NormalizedStage>),
    /// No supported, currently-active, eligible-or-unknown stage exists.
    /// Every discovered stage's status/eligibility is summarized in
    /// `reason` -- nothing is silently dropped.
    NoActiveEligibleStage {
        reason: String,
    },
}

/// Select the stage a live `mint --engine auto` should act on right now.
/// Only [`StageStatus::Active`] stages are considered -- an eligible but
/// [`StageStatus::NotStarted`] stage is `watch`'s job, never `mint`'s.
pub fn select_for_live_mint(stages: &[NormalizedStage], now: OffsetDateTime) -> LiveStageDecision {
    let mut candidates: Vec<&NormalizedStage> = stages
        .iter()
        .filter(|s| matches!(s.status(now), StageStatus::Active { .. }))
        .filter(|s| is_candidate(s))
        .collect();
    candidates.sort_by_key(|s| rank_key(s));

    match candidates.into_iter().next() {
        Some(stage) => LiveStageDecision::Selected(Box::new(stage.clone())),
        None => LiveStageDecision::NoActiveEligibleStage {
            reason: summarize(stages, now),
        },
    }
}

/// What `watch --engine auto` should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchStageDecision {
    /// A supported, eligible-or-unknown stage is already [`StageStatus::Active`]
    /// -- `watch` must never silently sit waiting for a later stage while
    /// this exists. Callers should report `STAGE_ALREADY_LIVE` and point
    /// the operator at `mint` instead.
    AlreadyLive(Box<NormalizedStage>),
    /// The earliest supported, potentially-eligible future stage to wait
    /// for.
    WaitFor(Box<NormalizedStage>),
    NoSupportedFutureStage {
        reason: String,
    },
}

/// Select what `watch --engine auto` should wait for (or report as
/// already live). Considers both [`StageStatus::Active`] and
/// [`StageStatus::NotStarted`] stages -- an active candidate always wins
/// outright, per [`WatchStageDecision::AlreadyLive`]'s docs.
pub fn select_for_watch(stages: &[NormalizedStage], now: OffsetDateTime) -> WatchStageDecision {
    if let LiveStageDecision::Selected(stage) = select_for_live_mint(stages, now) {
        return WatchStageDecision::AlreadyLive(stage);
    }

    let mut future: Vec<&NormalizedStage> = stages
        .iter()
        .filter(|s| matches!(s.status(now), StageStatus::NotStarted { .. }))
        .filter(|s| is_candidate(s))
        .collect();
    future.sort_by_key(|s| rank_key(s));

    match future.into_iter().next() {
        Some(stage) => WatchStageDecision::WaitFor(Box::new(stage.clone())),
        None => WatchStageDecision::NoSupportedFutureStage {
            reason: summarize(stages, now),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use time::Duration;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-08-16 12:00:00 UTC);

    fn active_window() -> crate::domain::timing::PhaseWindow {
        crate::domain::timing::PhaseWindow {
            start: NOW - Duration::minutes(10),
            end: NOW + Duration::hours(1),
        }
    }

    fn future_window(starts_in: Duration) -> crate::domain::timing::PhaseWindow {
        crate::domain::timing::PhaseWindow {
            start: NOW + starts_in,
            end: NOW + starts_in + Duration::hours(1),
        }
    }

    fn ended_window() -> crate::domain::timing::PhaseWindow {
        crate::domain::timing::PhaseWindow {
            start: NOW - Duration::hours(2),
            end: NOW - Duration::hours(1),
        }
    }

    fn base(id: &str, protocol: StageProtocol) -> NormalizedStage {
        NormalizedStage {
            id: id.to_string(),
            protocol,
            label: None,
            window: active_window(),
            price_per_token_wei: Some(U256::ZERO),
            max_per_wallet: Some(10),
            wallet_minted: Some(0),
            supply_remaining: Some(100),
            eligibility: EligibilityState::Eligible,
            evidence: "test fixture".to_string(),
        }
    }

    // -- brief section 57 test matrix --

    #[test]
    fn t1_active_eligible_fcfa_beats_later_active_public() {
        let fcfa = base("fcfa", StageProtocol::Fcfa);
        let public = base("public", StageProtocol::Public);
        let decision = select_for_live_mint(&[public, fcfa.clone()], NOW);
        assert_eq!(decision, LiveStageDecision::Selected(Box::new(fcfa)));
    }

    #[test]
    fn t2_ineligible_signed_stage_falls_through_to_eligible_active_public() {
        let mut fcfa = base("fcfa", StageProtocol::Fcfa);
        fcfa.eligibility = EligibilityState::Ineligible {
            reason: "not on allowlist".to_string(),
        };
        let public = base("public", StageProtocol::Public);
        let decision = select_for_live_mint(&[fcfa, public.clone()], NOW);
        assert_eq!(decision, LiveStageDecision::Selected(Box::new(public)));
    }

    #[test]
    fn t3_future_signed_unknown_eligibility_is_watched_honestly_over_later_public() {
        let mut signed = base("presale", StageProtocol::SignedPresale);
        signed.window = future_window(Duration::minutes(5));
        signed.eligibility = EligibilityState::UnknownUntilActive;
        let mut public = base("public", StageProtocol::Public);
        public.window = future_window(Duration::hours(2));
        public.eligibility = EligibilityState::UnknownUntilActive;

        let decision = select_for_watch(&[public, signed.clone()], NOW);
        assert_eq!(decision, WatchStageDecision::WaitFor(Box::new(signed)));
    }

    #[test]
    fn t4_signed_stage_ineligible_at_activation_leaves_no_active_stage_when_public_still_future() {
        let mut signed = base("presale", StageProtocol::SignedPresale);
        signed.eligibility = EligibilityState::Ineligible {
            reason: "OpenSea authorization rejected: not eligible".to_string(),
        };
        let mut public = base("public", StageProtocol::Public);
        public.window = future_window(Duration::hours(1));

        let decision = select_for_live_mint(&[signed, public], NOW);
        assert!(matches!(
            decision,
            LiveStageDecision::NoActiveEligibleStage { .. }
        ));
    }

    #[test]
    fn t4b_after_signed_ineligibility_watch_continues_to_the_later_public_stage() {
        let mut signed = base("presale", StageProtocol::SignedPresale);
        signed.eligibility = EligibilityState::Ineligible {
            reason: "not eligible".to_string(),
        };
        let mut public = base("public", StageProtocol::Public);
        public.window = future_window(Duration::hours(1));

        let decision = select_for_watch(&[signed, public.clone()], NOW);
        assert_eq!(decision, WatchStageDecision::WaitFor(Box::new(public)));
    }

    #[test]
    fn t5_active_public_with_zero_supply_remaining_is_not_selected() {
        let mut public = base("public", StageProtocol::Public);
        public.supply_remaining = Some(0);
        let decision = select_for_live_mint(&[public], NOW);
        assert!(matches!(
            decision,
            LiveStageDecision::NoActiveEligibleStage { .. }
        ));
    }

    #[test]
    fn t6_authoritative_zero_supply_overrides_an_eligible_classification() {
        // Simulates: off-chain metadata still claims minting is open, but
        // authoritative on-chain supply is exhausted -- the normalized
        // stage's own supply_remaining field is what wins, regardless of
        // where the Eligible classification came from.
        let mut stage = base("public", StageProtocol::Public);
        stage.eligibility = EligibilityState::Eligible;
        stage.supply_remaining = Some(0);
        assert!(!stage.has_known_capacity());
        let decision = select_for_live_mint(&[stage], NOW);
        assert!(matches!(
            decision,
            LiveStageDecision::NoActiveEligibleStage { .. }
        ));
    }

    #[test]
    fn ended_stage_is_never_selected_for_live_or_watch() {
        let mut stage = base("expired", StageProtocol::Public);
        stage.window = ended_window();
        assert_eq!(
            select_for_live_mint(std::slice::from_ref(&stage), NOW),
            LiveStageDecision::NoActiveEligibleStage {
                reason: summarize(std::slice::from_ref(&stage), NOW)
            }
        );
        assert!(matches!(
            select_for_watch(&[stage], NOW),
            WatchStageDecision::NoSupportedFutureStage { .. }
        ));
    }

    #[test]
    fn unsupported_protocol_stage_is_never_selected() {
        let mut stage = base("gated", StageProtocol::Allowlist);
        stage.eligibility = EligibilityState::Unsupported {
            reason: "token-gated allowlist not implemented".to_string(),
        };
        let decision = select_for_live_mint(&[stage], NOW);
        assert!(matches!(
            decision,
            LiveStageDecision::NoActiveEligibleStage { .. }
        ));
    }

    #[test]
    fn watch_reports_already_live_instead_of_waiting_when_an_active_candidate_exists() {
        let active = base("fcfa", StageProtocol::Fcfa);
        let mut future_public = base("public", StageProtocol::Public);
        future_public.window = future_window(Duration::hours(1));

        let decision = select_for_watch(&[active.clone(), future_public], NOW);
        assert_eq!(decision, WatchStageDecision::AlreadyLive(Box::new(active)));
    }

    #[test]
    fn wallet_allocation_exhausted_stage_is_not_a_candidate() {
        let mut stage = base("fcfa", StageProtocol::Fcfa);
        stage.max_per_wallet = Some(10);
        stage.wallet_minted = Some(10);
        let decision = select_for_live_mint(&[stage], NOW);
        assert!(matches!(
            decision,
            LiveStageDecision::NoActiveEligibleStage { .. }
        ));
    }

    #[test]
    fn empty_stage_list_reports_no_stages_discovered() {
        let decision = select_for_live_mint(&[], NOW);
        assert_eq!(
            decision,
            LiveStageDecision::NoActiveEligibleStage {
                reason: "no stages were discovered for this collection".to_string()
            }
        );
    }

    #[test]
    fn multiple_eligible_non_public_active_stages_prefer_the_earliest_start() {
        let mut earlier = base("earlier", StageProtocol::Fcfa);
        earlier.window.start = NOW - Duration::minutes(30);
        let mut later = base("later", StageProtocol::Fcfs);
        later.window.start = NOW - Duration::minutes(5);

        let decision = select_for_live_mint(&[later, earlier.clone()], NOW);
        assert_eq!(decision, LiveStageDecision::Selected(Box::new(earlier)));
    }
}
