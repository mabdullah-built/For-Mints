//! `kairox plan` — produces a dry-run [`MintPlan`] and prints it. Never
//! broadcasts anything.

use alloy_primitives::U256;
use time::OffsetDateTime;

use crate::chain::registry::ChainRegistry;
use crate::cli::args::PlanArgs;
use crate::cli::context::{connect_read_client, resolve_chain};
use crate::cli::format::{format_selector, format_unix, parse_gwei_to_wei, parse_wei};
use crate::cli::gather;
use crate::domain::fees::SafetyCaps;
use crate::execution::errors::KairoxError;
use crate::execution::plan::{MintPlan, PlanInputs, build_plan};
use crate::protocol::seadrop::{encode_mint_public, select_fee_recipient};

/// Fetch on-chain state and produce a validated [`MintPlan`]. Shared by
/// both `kairox plan` and `kairox mint` (which stops before any broadcast).
pub async fn build_mint_plan(args: &PlanArgs) -> Result<MintPlan, KairoxError> {
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.chain_args)?;
    let client = connect_read_client(&resolved.info, args.chain_args.rpc_url.as_ref()).await?;

    // Required state: fail closed (propagate) on any of these three.
    let public_drop =
        gather::fetch_public_drop(&client, resolved.seadrop_contract, args.collection).await?;
    let allowed_fee_recipients =
        gather::fetch_allowed_fee_recipients(&client, resolved.seadrop_contract, args.collection)
            .await?;
    let mint_stats = gather::fetch_mint_stats(&client, args.collection, args.wallet).await?;

    let fee_recipient = select_fee_recipient(
        &allowed_fee_recipients,
        public_drop.restrict_fee_recipients,
        args.fee_recipient,
        args.wallet,
    )?;

    let fee_hint = gather::fetch_fee_hint(&client).await?;
    let max_priority_fee_per_gas = match &args.priority_fee_gwei {
        Some(raw) => parse_gwei_to_wei("--priority-fee-gwei", raw)?,
        None => fee_hint
            .suggested_priority_fee
            .unwrap_or(gather::FALLBACK_PRIORITY_FEE_WEI),
    };
    let max_fee_per_gas = match &args.max_fee_gwei {
        Some(raw) => parse_gwei_to_wei("--max-fee-gwei", raw)?,
        None => fee_hint
            .base_fee_per_gas
            .saturating_mul(2)
            .saturating_add(max_priority_fee_per_gas),
    };

    let mint_value = public_drop
        .mint_price
        .saturating_mul(U256::from(args.quantity));
    let calldata = encode_mint_public(
        args.collection,
        fee_recipient,
        alloy_primitives::Address::ZERO,
        args.quantity,
    )?;
    let gas_estimate = gather::fetch_gas_estimate(
        &client,
        args.wallet,
        resolved.seadrop_contract,
        &calldata,
        mint_value,
    )
    .await;
    let gas_limit = ((gas_estimate as f64) * args.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let nonce = gather::fetch_nonce(&client, args.wallet).await;

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &args.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &args.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &args.max_total_spend_wei)?,
    };

    let inputs = PlanInputs {
        chain: resolved.info,
        nft_contract: args.collection,
        seadrop_contract: resolved.seadrop_contract,
        minter_address: args.wallet,
        quantity: args.quantity,
        public_drop,
        allowed_fee_recipients,
        preferred_fee_recipient: args.fee_recipient,
        wallet_already_minted: mint_stats.minter_num_minted,
        current_total_supply: mint_stats.current_total_supply,
        max_supply: Some(mint_stats.max_supply),
        nonce,
        base_fee_per_gas: fee_hint.base_fee_per_gas,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_estimate,
        gas_limit,
        safety_caps,
        now: OffsetDateTime::now_utc(),
    };

    build_plan(inputs)
}

pub fn print_plan(plan: &MintPlan) {
    println!(
        "chain:                     {} (chain id {})",
        plan.chain.name, plan.chain.chain_id
    );
    println!("collection (nft contract): {}", plan.nft_contract);
    println!("target contract:           {}", plan.target_contract);
    println!("quantity:                  {}", plan.quantity);
    println!("selected fee recipient:    {}", plan.fee_recipient);
    println!("mint value:                {} wei", plan.mint_value);
    println!(
        "wallet allocation remaining:     {}",
        plan.wallet_allocation_remaining
    );
    println!(
        "collection supply remaining:     {}",
        plan.collection_supply_remaining
    );
    match plan.nonce {
        Some(n) => println!("nonce:                     {n}"),
        None => println!("nonce:                     unavailable"),
    }
    println!("gas estimate:              {}", plan.gas_estimate);
    println!("gas limit (with buffer):   {}", plan.gas_limit);
    println!("base fee per gas:          {} wei", plan.base_fee_per_gas);
    println!(
        "max priority fee per gas:  {} wei",
        plan.max_priority_fee_per_gas
    );
    println!("max fee per gas:           {} wei", plan.max_fee_per_gas);
    println!(
        "worst-case gas cost:       {} wei",
        plan.worst_case_gas_cost
    );
    println!(
        "worst-case total spend:    {} wei",
        plan.worst_case_total_spend
    );
    println!(
        "calldata selector:         {}",
        format_selector(plan.calldata_selector)
    );
    println!(
        "calldata:                  0x{}",
        hex::encode(&plan.calldata)
    );
    println!(
        "planned stage-open time:   {} (unix {})",
        format_unix(plan.stage_start.unix_timestamp() as u64),
        plan.stage_start.unix_timestamp()
    );
    println!(
        "planned stage-close time:  {} (unix {})",
        format_unix(plan.stage_end.unix_timestamp() as u64),
        plan.stage_end.unix_timestamp()
    );
    println!("stage status:              {:?}", plan.stage_status);
}

pub async fn run(args: PlanArgs) -> Result<(), KairoxError> {
    let plan = build_mint_plan(&args).await?;
    print_plan(&plan);
    Ok(())
}
