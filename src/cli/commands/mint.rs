//! `kairox mint` — dry-run by default (identical to Phase 1 behavior).
//! `--send` opts into the live pipeline: confirmation, signing-key load,
//! scheduled pre-signing, identical-raw-transaction broadcast, and receipt
//! confirmation.

use std::io::BufRead;
use std::time::Duration as StdDuration;

use time::Duration;

use crate::chain::config::{EnvSource, ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::{EngineSelection, MintArgs};
use crate::cli::commands::plan::{build_mint_plan, print_plan};
use crate::cli::context::resolve_chain;
use crate::cli::format::{format_unix, parse_wei};
use crate::domain::fees::SafetyCaps;
use crate::domain::timing::{SleepSegment, StageStatus};
use crate::execution::broadcast::BroadcastSummary;
use crate::execution::errors::{KairoxError, SessionError};
use crate::execution::live::{LiveMintConfig, LiveProgress, run_live_mint};
use crate::execution::opensea_engine::{OpenSeaMintRequest, OpenSeaProgress, run_opensea_mint};
use crate::execution::prepared::LiveMintRequest;
use crate::execution::profile::ExecutionProfile;
use crate::execution::receipt::ReceiptState;
use crate::execution::scheduler::Checkpoint;
use crate::opensea::client::{OPENSEA_API_KEY_ENV, OpenSeaClient};
use crate::opensea::errors::OpenSeaError;
use crate::signing::keystore::load_signing_key;
use crate::signing::signer::Signer;

/// Which engine `run`/`run_send` actually decided to use for this
/// invocation, and why. `Auto` never means "try random paths until one
/// works" — it resolves deterministically to exactly one of these two
/// before anything runs.
enum SelectedEngine {
    Public,
    OpenSea { slug: String },
}

/// Resolve `--engine`/`--slug` into exactly one concrete engine.
///
/// `Auto` without `--slug` always resolves to `Public` (the OpenSea engine
/// can never be reached without an explicit slug — see `EngineSelection`'s
/// docs; Kairox never guesses a slug). `Auto` with `--slug` prefers
/// `Public` when the public on-chain stage is currently active and the
/// public engine can fully prepare it (checked by actually building the
/// dry-run plan); otherwise it falls back to `OpenSea`, on the reasoning
/// that a wallet-specific/off-chain-gated stage needs OpenSea's
/// transaction data. `Explicit Public`/`Explicit Opensea` always win
/// outright.
async fn select_engine(args: &MintArgs) -> Result<SelectedEngine, KairoxError> {
    match args.plan_args.engine {
        EngineSelection::Public => Ok(SelectedEngine::Public),
        EngineSelection::Opensea => {
            let slug = args
                .plan_args
                .slug
                .clone()
                .ok_or(KairoxError::OpenSea(OpenSeaError::SlugRequired))?;
            Ok(SelectedEngine::OpenSea { slug })
        }
        EngineSelection::Auto => {
            let Some(slug) = args.plan_args.slug.clone() else {
                return Ok(SelectedEngine::Public);
            };
            let public_active = build_mint_plan(&args.plan_args)
                .await
                .map(|plan| matches!(plan.stage_status, StageStatus::Active { .. }))
                .unwrap_or(false);
            if public_active {
                Ok(SelectedEngine::Public)
            } else {
                Ok(SelectedEngine::OpenSea { slug })
            }
        }
    }
}

fn load_opensea_client(timeout: StdDuration) -> Result<OpenSeaClient, KairoxError> {
    let api_key = ProcessEnv
        .get(OPENSEA_API_KEY_ENV)?
        .ok_or(KairoxError::OpenSea(OpenSeaError::ApiKeyMissing))?;
    Ok(OpenSeaClient::new_http(api_key, timeout))
}

pub async fn run(args: MintArgs) -> Result<(), KairoxError> {
    if args.wallet_manifest.is_some() {
        return crate::cli::commands::mint_multi::run_manifest(args).await;
    }
    if !args.send {
        return run_dry_run(args).await;
    }

    run_send(args).await
}

async fn run_dry_run(args: MintArgs) -> Result<(), KairoxError> {
    println!("=================================================");
    println!(" DRY RUN — NO TRANSACTION BROADCAST");
    println!("=================================================");
    println!();

    match select_engine(&args).await? {
        SelectedEngine::Public => {
            println!("selected engine: PUBLIC (pure on-chain PublicSeaDropEngine)");
            println!();
            let plan = build_mint_plan(&args.plan_args).await?;
            print_plan(&plan);
        }
        SelectedEngine::OpenSea { slug } => {
            println!("selected engine: OPENSEA (official OpenSea Drops API)");
            println!();
            let opensea = load_opensea_client(StdDuration::from_secs(10))?;
            let drop_details = opensea.get_drop_details(&slug).await?;
            println!("--- OPENSEA API METADATA (off-chain, informational only) ---");
            println!("collection_slug:  {}", drop_details.collection_slug);
            println!("chain:            {}", drop_details.chain);
            println!("contract_address: {}", drop_details.contract_address);
            println!("drop_type:        {}", drop_details.drop_type);
            println!("is_minting:       {}", drop_details.is_minting);
            println!("stages:           {}", drop_details.stages.len());
            if let Some(stage) = &drop_details.active_stage {
                println!(
                    "active_stage:     {} ({})",
                    stage.stage_type,
                    stage.label.as_deref().unwrap_or("(unlabeled)")
                );
            } else {
                println!("active_stage:     none");
            }
            println!("--- (nothing above this line is on-chain verified state) ---");
        }
    }

    println!();
    println!("=================================================");
    println!(" DRY RUN — NO TRANSACTION BROADCAST");
    println!(" Pass --send (with --yes, or interactive confirmation) to broadcast live.");
    println!("=================================================");
    Ok(())
}

async fn run_send(args: MintArgs) -> Result<(), KairoxError> {
    match select_engine(&args).await? {
        SelectedEngine::Public => run_send_public(args).await,
        SelectedEngine::OpenSea { slug } => run_send_opensea(args, slug).await,
    }
}

/// Connect every configured endpoint for `chain_args`'s chain and fail
/// closed if nothing send-capable came up. Shared by both engines' `--send`
/// paths.
async fn connect_send_pool(
    resolved: &crate::cli::context::ResolvedChain,
    rpc_url_override: Option<&url::Url>,
) -> Result<RpcPool, KairoxError> {
    let endpoints: Vec<RpcEndpoint> = if let Some(url) = rpc_url_override {
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
    Ok(pool)
}

async fn run_send_public(args: MintArgs) -> Result<(), KairoxError> {
    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)".into(),
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.plan_args.chain_args)?;

    // Preview plan for the confirmation summary. Uses the same lenient
    // gather pipeline as `kairox plan` — purely informational here; the
    // actual transaction that gets signed is built fresh, strictly, by the
    // live pipeline below.
    let preview = build_mint_plan(&args.plan_args).await?;

    let mut pool = connect_send_pool(&resolved, args.plan_args.chain_args.rpc_url.as_ref()).await?;

    println!("selected engine: PUBLIC (pure on-chain PublicSeaDropEngine)");
    println!("=================================================");
    println!(" LIVE SEND CONFIRMATION");
    println!("=================================================");
    println!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("wallet:                {}", wallet);
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
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError(format!(
            "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
            signer.address(),
            wallet
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
        wallet,
        quantity: args.plan_args.quantity,
        preferred_fee_recipient: args.plan_args.fee_recipient,
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps,
    };

    // Start from the chain's execution profile (benchmark sampling, health
    // policy, and default scheduler leads), then apply any explicit CLI
    // overrides for the scheduler/receipt-polling/benchmark timings on top.
    let profile = ExecutionProfile::for_chain(resolved.info.chain_id);
    let mut config = LiveMintConfig::from(&profile);
    if let Some(secs) = args.lead_state_check_secs {
        config.scheduler.state_check_lead = Duration::seconds_f64(secs);
    }
    if let Some(secs) = args.lead_refresh_secs {
        config.scheduler.refresh_lead = Duration::seconds_f64(secs);
    }
    if let Some(secs) = args.lead_finalize_secs {
        config.scheduler.finalize_lead = Duration::seconds_f64(secs);
    }
    if let Some(secs) = args.receipt_timeout_secs {
        config.receipt_timeout = StdDuration::from_secs(secs);
    }
    if let Some(ms) = args.receipt_poll_interval_ms {
        config.receipt_poll_interval = StdDuration::from_millis(ms);
    }
    if let Some(samples) = args.benchmark_samples {
        config.benchmark.sample_count = samples;
    }

    let mut receipt_pending_announced = false;
    let outcome = run_live_mint(&mut pool, &signer, &request, &config, |progress| {
        report_progress(progress, &mut receipt_pending_announced)
    })
    .await?;

    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
    );

    Ok(())
}

async fn run_send_opensea(args: MintArgs, slug: String) -> Result<(), KairoxError> {
    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)".into(),
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.plan_args.chain_args)?;
    let opensea = load_opensea_client(StdDuration::from_secs(10))?;

    let mut pool = connect_send_pool(&resolved, args.plan_args.chain_args.rpc_url.as_ref()).await?;

    let drop_details = opensea.get_drop_details(&slug).await?;

    println!("selected engine: OPENSEA (official OpenSea Drops API)");
    println!("=================================================");
    println!(" LIVE SEND CONFIRMATION");
    println!("=================================================");
    println!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("wallet:                {}", wallet);
    println!("collection:            {}", args.plan_args.collection);
    println!("opensea slug:          {slug}");
    println!("quantity:              {}", args.plan_args.quantity);
    println!(
        "opensea drop_type:     {} (off-chain metadata, not on-chain verified)",
        drop_details.drop_type
    );
    println!("target contract:       {}", resolved.seadrop_contract);
    println!("send-capable endpoints:{}", pool.send_capable().len());
    println!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        println!("Aborted: live-send confirmation not received. Nothing was broadcast.");
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError(format!("failed to load signing key: {e}")))
    })?;
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError(format!(
            "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
            signer.address(),
            wallet
        ))));
    }

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &args.plan_args.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &args.plan_args.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &args.plan_args.max_total_spend_wei)?,
    };

    let profile = ExecutionProfile::for_chain(resolved.info.chain_id);
    let mut receipt_timeout = profile.receipt_timeout;
    let mut receipt_poll_interval = profile.receipt_poll_interval;
    let mut benchmark = profile.benchmark_policy;
    if let Some(secs) = args.receipt_timeout_secs {
        receipt_timeout = StdDuration::from_secs(secs);
    }
    if let Some(ms) = args.receipt_poll_interval_ms {
        receipt_poll_interval = StdDuration::from_millis(ms);
    }
    if let Some(samples) = args.benchmark_samples {
        benchmark.sample_count = samples;
    }

    let request = OpenSeaMintRequest {
        chain: resolved.info.clone(),
        slug,
        nft_contract: args.plan_args.collection,
        seadrop_contract: resolved.seadrop_contract,
        wallet,
        quantity: args.plan_args.quantity,
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps,
        receipt_poll_interval,
        receipt_timeout,
        benchmark,
        health: profile.health_policy,
        prewarm_lead: std_duration_from_time(profile.prewarm_lead),
    };

    let outcome = run_opensea_mint(&opensea, &mut pool, &signer, &request, |progress| {
        report_opensea_progress(progress)
    })
    .await?;

    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
    );

    Ok(())
}

fn std_duration_from_time(d: time::Duration) -> StdDuration {
    d.try_into().unwrap_or(StdDuration::ZERO)
}

fn print_broadcast_result(
    tx_hash: alloy_primitives::B256,
    broadcast_results: &[crate::execution::broadcast::EndpointBroadcastResult],
    broadcast_summary: &BroadcastSummary,
    receipt_state: &Option<ReceiptState>,
    metrics: &crate::execution::metrics::LatencyMetrics,
) {
    println!();
    println!("=================================================");
    println!(" BROADCAST RESULT");
    println!("=================================================");
    println!("tx hash: 0x{}", hex::encode(tx_hash));
    for r in broadcast_results {
        let latency = r
            .latency_ms
            .map(|m| format!("{m} ms"))
            .unwrap_or_else(|| "n/a".into());
        println!(
            "  [{:?}] {} -> {:?} ({latency})",
            r.role, r.label, r.outcome
        );
    }
    match broadcast_summary {
        BroadcastSummary::Confirmed { .. } => {
            println!("summary: PROPAGATED (at least one endpoint confirmed)")
        }
        BroadcastSummary::AllRejected => println!("summary: ALL_REJECTED — nothing was broadcast"),
        BroadcastSummary::Uncertain => unreachable!("uncertain outcomes are returned as Err"),
    }

    match receipt_state {
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
    println!("{}", metrics.render());
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
        LiveProgress::Benchmarking => println!("[benchmark] sampling endpoint latency"),
        LiveProgress::Prewarming { scheduling } => {
            let mode = match scheduling {
                crate::execution::live::PrewarmScheduling::StageRelative => "stage-relative",
                crate::execution::live::PrewarmScheduling::Immediate => "immediate",
            };
            println!("[prewarm] rewarming connections ({mode})");
        }
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

fn report_opensea_progress(progress: OpenSeaProgress) {
    match progress {
        OpenSeaProgress::Benchmarking => println!("[benchmark] sampling endpoint latency"),
        OpenSeaProgress::FetchingDropDetails => {
            println!("[opensea] fetching drop details")
        }
        OpenSeaProgress::Prewarming { scheduling } => {
            let mode = match scheduling {
                crate::execution::live::PrewarmScheduling::StageRelative => "stage-relative",
                crate::execution::live::PrewarmScheduling::Immediate => "immediate",
            };
            println!("[prewarm] rewarming connections ({mode})");
        }
        OpenSeaProgress::Waiting(SleepSegment::Coarse(d)) => {
            println!("[waiting] {} s until stage open", d.whole_seconds())
        }
        OpenSeaProgress::Waiting(SleepSegment::Fine(_)) => {}
        OpenSeaProgress::RequestingMintTransaction => {
            println!("[opensea] requesting mint transaction")
        }
        OpenSeaProgress::Validating => println!("[opensea] validating response locally"),
        OpenSeaProgress::Simulating => println!("[chain] simulating transaction"),
        OpenSeaProgress::Broadcasting {
            send_endpoint_count,
        } => {
            println!("[dispatch] broadcasting to {send_endpoint_count} endpoint(s)");
        }
        OpenSeaProgress::ReceiptPending => println!("[receipt] waiting for confirmation..."),
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
