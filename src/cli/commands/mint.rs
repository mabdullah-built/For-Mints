//! `kairox mint` — dry-run by default (identical to Phase 1 behavior).
//! `--send` opts into the live pipeline: confirmation, signing-key load,
//! scheduled pre-signing, identical-raw-transaction broadcast, and receipt
//! confirmation.

use std::io::BufRead;
use std::time::Duration as StdDuration;

use time::Duration;

use crate::chain::config::{ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::MintArgs;
use crate::cli::commands::plan::{build_mint_plan, print_plan};
use crate::cli::context::resolve_chain;
use crate::cli::format::{format_unix, parse_wei};
use crate::domain::fees::SafetyCaps;
use crate::domain::timing::SleepSegment;
use crate::execution::broadcast::BroadcastSummary;
use crate::execution::errors::{KairoxError, SessionError};
use crate::execution::live::{LiveMintConfig, LiveProgress, run_live_mint};
use crate::execution::prepared::LiveMintRequest;
use crate::execution::receipt::ReceiptState;
use crate::execution::scheduler::{Checkpoint, SchedulerTimings};
use crate::signing::keystore::load_signing_key;
use crate::signing::signer::Signer;

pub async fn run(args: MintArgs) -> Result<(), KairoxError> {
    if !args.send {
        let plan = build_mint_plan(&args.plan_args).await?;
        println!("=================================================");
        println!(" DRY RUN — NO TRANSACTION BROADCAST");
        println!("=================================================");
        println!();
        print_plan(&plan);
        println!();
        println!("=================================================");
        println!(" DRY RUN — NO TRANSACTION BROADCAST");
        println!(" Pass --send (with --yes, or interactive confirmation) to broadcast live.");
        println!("=================================================");
        return Ok(());
    }

    run_send(args).await
}

async fn run_send(args: MintArgs) -> Result<(), KairoxError> {
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.plan_args.chain_args)?;

    // Preview plan for the confirmation summary. Uses the same lenient
    // gather pipeline as `kairox plan` — purely informational here; the
    // actual transaction that gets signed is built fresh, strictly, by the
    // live pipeline below.
    let preview = build_mint_plan(&args.plan_args).await?;

    let endpoints: Vec<RpcEndpoint> = if let Some(url) = &args.plan_args.chain_args.rpc_url {
        vec![RpcEndpoint::new(url.clone(), EndpointRole::ReadWrite)]
    } else {
        load_chain_endpoints(&ProcessEnv, resolved.info.chain_id)?.endpoints
    };
    let (pool, reports) = RpcPool::connect_all(resolved.info.chain_id, &endpoints).await;
    for report in &reports {
        if let ConnectOutcome::Failed { error, .. } = &report.outcome {
            let label = report
                .label
                .clone()
                .unwrap_or_else(|| "(unlabeled)".to_string());
            eprintln!("warning: endpoint {label} unavailable: {error}");
        }
    }
    if pool.send_capable().is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no send-capable RPC endpoint connected; cannot broadcast live".into(),
        )));
    }

    println!("=================================================");
    println!(" LIVE SEND CONFIRMATION");
    println!("=================================================");
    println!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("wallet:                {}", args.plan_args.wallet);
    println!("collection:            {}", args.plan_args.collection);
    println!("quantity:              {}", args.plan_args.quantity);
    println!("mint value:            {} wei", preview.mint_value);
    println!("worst-case gas cost:   {} wei", preview.worst_case_gas_cost);
    println!(
        "worst-case total spend:{} wei",
        preview.worst_case_total_spend
    );
    println!("target contract:       {}", preview.target_contract);
    println!(
        "planned stage-open:    {} (unix {})",
        format_unix(preview.stage_start.unix_timestamp() as u64),
        preview.stage_start.unix_timestamp()
    );
    println!("send-capable endpoints:{}", pool.send_capable().len());
    println!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        println!("Aborted: live-send confirmation not received. Nothing was broadcast.");
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError(format!("failed to load signing key: {e}")))
    })?;
    if signer.address() != args.plan_args.wallet {
        return Err(KairoxError::Session(SessionError(format!(
            "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
            signer.address(),
            args.plan_args.wallet
        ))));
    }

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &args.plan_args.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &args.plan_args.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &args.plan_args.max_total_spend_wei)?,
    };

    let request = LiveMintRequest {
        chain: resolved.info.clone(),
        nft_contract: args.plan_args.collection,
        seadrop_contract: resolved.seadrop_contract,
        wallet: args.plan_args.wallet,
        quantity: args.plan_args.quantity,
        preferred_fee_recipient: args.plan_args.fee_recipient,
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps,
    };

    let config = LiveMintConfig {
        scheduler: SchedulerTimings {
            state_check_lead: Duration::seconds_f64(args.lead_state_check_secs),
            refresh_lead: Duration::seconds_f64(args.lead_refresh_secs),
            finalize_lead: Duration::seconds_f64(args.lead_finalize_secs),
        },
        receipt_poll_interval: StdDuration::from_millis(args.receipt_poll_interval_ms),
        receipt_timeout: StdDuration::from_secs(args.receipt_timeout_secs),
    };

    let mut receipt_pending_announced = false;
    let outcome = run_live_mint(&pool, &signer, &request, &config, |progress| {
        report_progress(progress, &mut receipt_pending_announced)
    })
    .await?;

    println!();
    println!("=================================================");
    println!(" BROADCAST RESULT");
    println!("=================================================");
    println!("tx hash: 0x{}", hex::encode(outcome.prepared.tx_hash));
    for r in &outcome.broadcast_results {
        let latency = r
            .latency_ms
            .map(|m| format!("{m} ms"))
            .unwrap_or_else(|| "n/a".into());
        println!(
            "  [{:?}] {} -> {:?} ({latency})",
            r.role, r.label, r.outcome
        );
    }
    match &outcome.broadcast_summary {
        BroadcastSummary::Confirmed { .. } => {
            println!("summary: PROPAGATED (at least one endpoint confirmed)")
        }
        BroadcastSummary::AllRejected => println!("summary: ALL_REJECTED — nothing was broadcast"),
        BroadcastSummary::Uncertain => unreachable!("uncertain outcomes are returned as Err"),
    }

    match &outcome.receipt_state {
        Some(ReceiptState::ConfirmedSuccess { minted }) => {
            println!("receipt: CONFIRMED_SUCCESS");
            for asset in minted {
                println!(
                    "  minted token id {} (amount {})",
                    asset.token_id, asset.amount
                );
            }
        }
        Some(ReceiptState::ConfirmedRevert) => println!("receipt: CONFIRMED_REVERT"),
        Some(ReceiptState::ReceiptUnknown) => {
            println!("receipt: RECEIPT_UNKNOWN (timed out waiting)")
        }
        None => println!("receipt: not polled (transaction was not confirmed as broadcast)"),
    }

    println!();
    println!("latency metrics:");
    println!("{}", outcome.metrics.render());

    Ok(())
}

/// Pure confirmation gate: `--yes` always satisfies it; otherwise the
/// supplied line-reader must return exactly `"yes"` (case-insensitive,
/// trimmed). Kept independent of stdin so it is directly unit-testable.
pub fn confirmation_satisfied(yes: bool, mut read_line: impl FnMut() -> Option<String>) -> bool {
    if yes {
        return true;
    }
    match read_line() {
        Some(line) => line.trim().eq_ignore_ascii_case("yes"),
        None => false,
    }
}

fn read_stdin_confirmation() -> Option<String> {
    print!("Type 'yes' to broadcast live, anything else to abort: ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    Some(line)
}

fn report_progress(progress: LiveProgress, receipt_pending_announced: &mut bool) {
    match progress {
        LiveProgress::Checkpoint(Checkpoint::StateCheck) => println!("[checkpoint] state check"),
        LiveProgress::Checkpoint(Checkpoint::Refresh) => {
            println!("[checkpoint] refresh (nonce/fee/balance/supply)")
        }
        LiveProgress::Checkpoint(Checkpoint::Finalize) => {
            println!("[checkpoint] finalize (sign + serialize)")
        }
        LiveProgress::Waiting(SleepSegment::Coarse(d)) => {
            println!("[waiting] {} s until next checkpoint", d.whole_seconds())
        }
        LiveProgress::Waiting(SleepSegment::Fine(_)) => {}
        LiveProgress::Broadcasting {
            send_endpoint_count,
        } => {
            println!("[dispatch] broadcasting to {send_endpoint_count} endpoint(s)");
        }
        LiveProgress::ReceiptPending => {
            if !*receipt_pending_announced {
                println!("[receipt] waiting for confirmation...");
                *receipt_pending_announced = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_flag_always_satisfies_without_reading_input() {
        assert!(confirmation_satisfied(true, || panic!(
            "must not read input when --yes is set"
        )));
    }

    #[test]
    fn typed_yes_satisfies_confirmation() {
        assert!(confirmation_satisfied(false, || Some("yes".to_string())));
    }

    #[test]
    fn typed_yes_is_case_insensitive_and_trims_whitespace() {
        assert!(confirmation_satisfied(false, || Some(
            "  YES\n".to_string()
        )));
    }

    #[test]
    fn anything_else_aborts() {
        assert!(!confirmation_satisfied(false, || Some("y".to_string())));
        assert!(!confirmation_satisfied(false, || Some("".to_string())));
        assert!(!confirmation_satisfied(false, || Some("no".to_string())));
    }

    #[test]
    fn closed_stdin_aborts_rather_than_defaulting_to_confirmed() {
        assert!(!confirmation_satisfied(false, || None));
    }
}
