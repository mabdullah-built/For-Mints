//! The dry-run planning pipeline shared by `kairox inspect`, `kairox plan`,
//! and `kairox mint`. Pure: takes already-fetched chain state as input and
//! produces a [`MintPlan`], performing no I/O and never broadcasting
//! anything.

use alloy_primitives::{Address, Bytes, U256};
use time::OffsetDateTime;

use crate::chain::registry::ChainInfo;
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::domain::supply::{CollectionSupply, WalletAllocation, validate_requested_quantity};
use crate::domain::timing::{PhaseWindow, StageStatus};
use crate::protocol::seadrop::{
    PublicDropConfig, encode_mint_public, mint_public_selector, select_fee_recipient,
};

use super::errors::{KairoxError, SessionError};

/// Everything [`build_plan`] needs, already fetched from chain state by the
/// caller (the CLI layer). Nothing in this struct triggers a network call.
#[derive(Debug, Clone)]
pub struct PlanInputs {
    pub chain: ChainInfo,
    pub nft_contract: Address,
    pub seadrop_contract: Address,
    pub minter_address: Address,
    pub quantity: u64,
    pub public_drop: PublicDropConfig,
    pub allowed_fee_recipients: Vec<Address>,
    pub preferred_fee_recipient: Option<Address>,
    pub wallet_already_minted: u64,
    pub current_total_supply: u64,
    pub max_supply: Option<u64>,
    pub nonce: Option<u64>,
    pub base_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_estimate: u64,
    pub gas_limit: u64,
    pub safety_caps: SafetyCaps,
    pub now: OffsetDateTime,
}

/// A complete, validated dry-run execution plan. Every field is display-
/// ready for `kairox plan`/`kairox mint`.
#[derive(Debug, Clone)]
pub struct MintPlan {
    pub chain: ChainInfo,
    pub nft_contract: Address,
    pub seadrop_contract: Address,
    pub quantity: u64,
    pub fee_recipient: Address,
    pub mint_value: U256,
    pub wallet_allocation_remaining: u64,
    pub collection_supply_remaining: u64,
    pub nonce: Option<u64>,
    pub gas_estimate: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub worst_case_gas_cost: U256,
    pub worst_case_total_spend: U256,
    pub calldata_selector: [u8; 4],
    pub calldata: Bytes,
    pub target_contract: Address,
    pub stage_start: OffsetDateTime,
    pub stage_end: OffsetDateTime,
    pub stage_status: StageStatus,
    /// Always `true`: a [`MintPlan`] is always a preview -- built by
    /// `kairox plan`, and by `kairox mint` (both dry-run and as the
    /// pre-signing preview before a real `--send`) -- never a record of an
    /// actual broadcast. See [`crate::execution::live::run_live_mint`] and
    /// [`crate::execution::opensea_engine`] for the real signing/broadcast
    /// path, which builds its own transaction fresh rather than reusing
    /// this preview.
    pub dry_run: bool,
}

pub(crate) fn unix_timestamp(seconds: u64, what: &str) -> Result<OffsetDateTime, KairoxError> {
    let seconds: i64 = seconds.try_into().map_err(|_| {
        KairoxError::Session(SessionError::new(format!("{what} does not fit in i64")))
    })?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "{what} is not a valid timestamp: {e}"
        )))
    })
}

/// Build a [`MintPlan`] from already-fetched inputs, enforcing every Phase 1
/// safety invariant: wallet/collection supply limits, EIP-1559 fee
/// invariants, and configured spend caps. Fails before producing a plan
/// (and therefore before any signing could occur) if any invariant is
/// violated.
pub fn build_plan(inputs: PlanInputs) -> Result<MintPlan, KairoxError> {
    let wallet = WalletAllocation {
        max_total_mintable_by_wallet: inputs.public_drop.max_total_mintable_by_wallet as u64,
        already_minted: inputs.wallet_already_minted,
    };
    let collection = CollectionSupply {
        max_supply: inputs.max_supply,
        current_supply: inputs.current_total_supply,
    };
    let (wallet_remaining, collection_remaining) =
        validate_requested_quantity(inputs.quantity, &wallet, &collection)?;

    let fee_recipient = select_fee_recipient(
        &inputs.allowed_fee_recipients,
        inputs.public_drop.restrict_fee_recipients,
        inputs.preferred_fee_recipient,
        inputs.minter_address,
    )?;

    let fees = Eip1559Fees::new(
        inputs.base_fee_per_gas,
        inputs.max_priority_fee_per_gas,
        inputs.max_fee_per_gas,
    )?;
    let worst_case_gas_cost = fees.worst_case_gas_cost(inputs.gas_limit);
    let mint_value = inputs
        .public_drop
        .mint_price
        .saturating_mul(U256::from(inputs.quantity));
    let total_spend = worst_case_total_spend(mint_value, worst_case_gas_cost);
    inputs
        .safety_caps
        .check(mint_value, worst_case_gas_cost, total_spend)?;

    let calldata = encode_mint_public(
        inputs.nft_contract,
        fee_recipient,
        Address::ZERO,
        inputs.quantity,
    )?;

    let stage_start = unix_timestamp(inputs.public_drop.start_time, "public drop startTime")?;
    let stage_end = unix_timestamp(inputs.public_drop.end_time, "public drop endTime")?;
    let stage_status = PhaseWindow {
        start: stage_start,
        end: Some(stage_end),
    }
    .status(inputs.now);

    Ok(MintPlan {
        chain: inputs.chain,
        nft_contract: inputs.nft_contract,
        seadrop_contract: inputs.seadrop_contract,
        quantity: inputs.quantity,
        fee_recipient,
        mint_value,
        wallet_allocation_remaining: wallet_remaining,
        collection_supply_remaining: collection_remaining,
        nonce: inputs.nonce,
        gas_estimate: inputs.gas_estimate,
        gas_limit: inputs.gas_limit,
        base_fee_per_gas: fees.base_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        worst_case_gas_cost,
        worst_case_total_spend: total_spend,
        calldata_selector: mint_public_selector(),
        calldata,
        target_contract: inputs.seadrop_contract,
        stage_start,
        stage_end,
        stage_status,
        dry_run: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::registry::ChainRegistry;
    use crate::protocol::seadrop::PublicDropConfig;
    use alloy_primitives::address;
    use time::macros::datetime;

    fn base_inputs() -> PlanInputs {
        PlanInputs {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            nft_contract: address!("000000000000000000000000000000000000c0de"),
            seadrop_contract: address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5"),
            minter_address: address!("0000000000000000000000000000000000000aaa"),
            quantity: 2,
            public_drop: PublicDropConfig {
                mint_price: U256::from(10_000_000_000_000_000u128), // 0.01 ETH
                start_time: datetime!(2026-08-16 12:00:00 UTC).unix_timestamp() as u64,
                end_time: datetime!(2026-08-16 13:00:00 UTC).unix_timestamp() as u64,
                max_total_mintable_by_wallet: 5,
                fee_bps: 250,
                restrict_fee_recipients: false,
            },
            allowed_fee_recipients: vec![],
            preferred_fee_recipient: None,
            wallet_already_minted: 1,
            current_total_supply: 100,
            max_supply: Some(1_000),
            nonce: Some(3),
            base_fee_per_gas: 10_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_estimate: 180_000,
            gas_limit: 220_000,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(1_000_000_000_000_000_000u128),
            },
            now: datetime!(2026-08-16 12:30:00 UTC),
        }
    }

    #[test]
    fn builds_a_valid_plan_with_expected_values() {
        let plan = build_plan(base_inputs()).unwrap();
        assert_eq!(plan.wallet_allocation_remaining, 4);
        assert_eq!(plan.collection_supply_remaining, 900);
        assert_eq!(plan.mint_value, U256::from(20_000_000_000_000_000u128));
        assert_eq!(plan.fee_recipient, base_inputs().minter_address);
        assert!(plan.dry_run);
        assert_eq!(
            plan.stage_status,
            StageStatus::Active {
                ends_in: Some(time::Duration::minutes(30))
            }
        );
        assert_eq!(&plan.calldata[0..4], plan.calldata_selector);
    }

    #[test]
    fn fails_closed_on_unknown_max_supply() {
        let mut inputs = base_inputs();
        inputs.max_supply = None;
        let err = build_plan(inputs).unwrap_err();
        assert!(matches!(err, KairoxError::Supply(_)));
    }

    #[test]
    fn fails_when_quantity_exceeds_wallet_allocation() {
        let mut inputs = base_inputs();
        inputs.quantity = 10;
        let err = build_plan(inputs).unwrap_err();
        assert!(matches!(err, KairoxError::Supply(_)));
    }

    #[test]
    fn fails_when_safety_cap_exceeded() {
        let mut inputs = base_inputs();
        inputs.safety_caps.max_mint_value = U256::from(1u64);
        let err = build_plan(inputs).unwrap_err();
        assert!(matches!(err, KairoxError::SafetyCap(_)));
    }

    #[test]
    fn fails_when_fee_invariant_violated() {
        let mut inputs = base_inputs();
        inputs.max_fee_per_gas = 1; // below base fee
        let err = build_plan(inputs).unwrap_err();
        assert!(matches!(err, KairoxError::Fee(_)));
    }

    #[test]
    fn reports_stage_not_started() {
        let mut inputs = base_inputs();
        inputs.now = datetime!(2026-08-16 11:00:00 UTC);
        let plan = build_plan(inputs).unwrap();
        assert!(matches!(plan.stage_status, StageStatus::NotStarted { .. }));
    }

    #[test]
    fn reports_stage_ended() {
        let mut inputs = base_inputs();
        inputs.now = datetime!(2026-08-16 14:00:00 UTC);
        let plan = build_plan(inputs).unwrap();
        assert_eq!(plan.stage_status, StageStatus::Ended);
    }

    #[test]
    fn restricted_fee_recipient_uses_allowed_list() {
        let mut inputs = base_inputs();
        inputs.public_drop.restrict_fee_recipients = true;
        let allowed = address!("0000000000000000000000000000000000000bbb");
        inputs.allowed_fee_recipients = vec![allowed];
        let plan = build_plan(inputs).unwrap();
        assert_eq!(plan.fee_recipient, allowed);
    }

    #[test]
    fn fails_when_sold_out() {
        let mut inputs = base_inputs();
        inputs.current_total_supply = 1_000;
        let err = build_plan(inputs).unwrap_err();
        assert!(matches!(err, KairoxError::Supply(_)));
    }
}
