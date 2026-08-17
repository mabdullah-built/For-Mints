//! `kairox mint --wallet-manifest` — the multi-wallet CLI surface. Dry-run
//! by default, exactly like the single-wallet path; `--send` opts into
//! live multi-wallet orchestration.

use std::io::BufRead;

use alloy_primitives::U256;

use crate::chain::config::load_chain_endpoints;
use crate::chain::config::{EnvSource, ProcessEnv};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::{EngineSelection, MintArgs};
use crate::cli::commands::mint::confirmation_satisfied;
use crate::cli::context::resolve_chain;
use crate::cli::format::parse_wei;
use crate::domain::fees::SafetyCaps;
use crate::execution::errors::{KairoxError, SessionError};
use crate::execution::manifest::{WalletManifest, load_manifest_file};
use crate::execution::multi_wallet::{
    MultiWalletConfig, OpenSeaMultiWalletTarget, WalletExecutionState, WalletMintRequest,
    load_and_verify_wallet_keys, run_multi_wallet_opensea_mint, run_multi_wallet_public_mint,
};
use crate::opensea::client::{OPENSEA_API_KEY_ENV, OpenSeaClient};
use crate::opensea::errors::OpenSeaError;

pub async fn run_manifest(args: MintArgs) -> Result<(), KairoxError> {
    let manifest_path = args
        .wallet_manifest
        .as_ref()
        .expect("run_manifest is only called when --wallet-manifest is set");
    let manifest = load_manifest_file(manifest_path)
        .map_err(|e| KairoxError::Session(SessionError(format!("manifest error: {e}"))))?;

    // Deterministic scope reduction for Phase 5: multi-wallet sessions
    // require an explicit engine choice. `auto` would need to check
    // public-stage activity against a *specific* wallet's allocation
    // (`build_mint_plan` is wallet-shaped), which has no single correct
    // answer across a whole manifest -- fail clearly rather than guess.
    let engine = match args.plan_args.engine {
        EngineSelection::Public => Engine::Public,
        EngineSelection::Opensea => Engine::OpenSea,
        EngineSelection::Auto => {
            return Err(KairoxError::Session(SessionError(
                "--engine auto is not supported with --wallet-manifest; pass --engine public or --engine opensea explicitly".into(),
            )));
        }
    };

    if args.send {
        run_manifest_send(args, manifest, engine).await
    } else {
        run_manifest_dry_run(args, manifest, engine).await
    }
}

enum Engine {
    Public,
    OpenSea,
}

fn multi_wallet_config(args: &MintArgs) -> Result<MultiWalletConfig, KairoxError> {
    let mut config = MultiWalletConfig {
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps: SafetyCaps {
            max_mint_value: parse_wei("--max-mint-value-wei", &args.plan_args.max_mint_value_wei)?,
            max_gas_cost: parse_wei("--max-gas-cost-wei", &args.plan_args.max_gas_cost_wei)?,
            max_total_spend: parse_wei(
                "--max-total-spend-wei",
                &args.plan_args.max_total_spend_wei,
            )?,
        },
        ..MultiWalletConfig::default()
    };
    if let Some(raw) = &args.max_session_total_spend_wei {
        config.max_session_total_spend = Some(parse_wei("--max-session-total-spend-wei", raw)?);
    }
    if let Some(n) = args.broadcast_concurrency {
        config.broadcast_concurrency = n.max(1);
    }
    if let Some(n) = args.opensea_api_concurrency {
        config.opensea_api_concurrency = n.max(1);
    }
    if let Some(samples) = args.benchmark_samples {
        config.benchmark.sample_count = samples;
    }
    if let Some(secs) = args.receipt_timeout_secs {
        config.receipt_timeout = std::time::Duration::from_secs(secs);
    }
    if let Some(ms) = args.receipt_poll_interval_ms {
        config.receipt_poll_interval = std::time::Duration::from_millis(ms);
    }
    Ok(config)
}

async fn connect_pool_for_manifest(
    args: &MintArgs,
) -> Result<(crate::cli::context::ResolvedChain, RpcPool), KairoxError> {
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.plan_args.chain_args)?;
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
    Ok((resolved, pool))
}

async fn run_manifest_dry_run(
    args: MintArgs,
    manifest: WalletManifest,
    engine: Engine,
) -> Result<(), KairoxError> {
    println!("=================================================");
    println!(" MULTI-WALLET DRY RUN — NO TRANSACTION BROADCAST");
    println!("=================================================");
    println!();

    let (resolved, mut pool) = connect_pool_for_manifest(&args).await?;
    pool.benchmark_all(&crate::chain::benchmark::BenchmarkConfig::default())
        .await;

    let engine_name = match engine {
        Engine::Public => "PUBLIC",
        Engine::OpenSea => "OPENSEA",
    };
    let aggregate_quantity: u64 = manifest.wallets.iter().map(|w| w.quantity).sum();

    println!(
        "chain:               {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("collection:          {}", args.plan_args.collection);
    println!("engine:              {engine_name}");
    println!("wallets configured:  {}", manifest.wallets.len());
    println!("aggregate quantity:  {aggregate_quantity}");
    println!("send-capable endpoints: {}", pool.send_capable().len());
    println!("read-capable endpoints: {}", pool.read_capable().len());

    if let Engine::OpenSea = engine {
        let slug = args
            .plan_args
            .slug
            .clone()
            .ok_or(KairoxError::OpenSea(OpenSeaError::SlugRequired))?;
        let api_key = ProcessEnv.get(OPENSEA_API_KEY_ENV).ok().flatten();
        if let Some(api_key) = api_key {
            let opensea = OpenSeaClient::new_http(api_key, std::time::Duration::from_secs(10));
            match opensea.get_drop_details(&slug).await {
                Ok(details) => {
                    println!();
                    println!("--- OPENSEA API METADATA (off-chain, informational only) ---");
                    println!("collection_slug: {}", details.collection_slug);
                    println!("is_minting:      {}", details.is_minting);
                    println!("stages:          {}", details.stages.len());
                }
                Err(e) => println!("OpenSea drop details: COULD NOT BE FETCHED ({e})"),
            }
        } else {
            println!(
                "OpenSea drop details: NOT FETCHED ({})",
                OpenSeaError::ApiKeyMissing
            );
        }
    } else if let Some(read_client) = pool.preferred_read() {
        let mint_stats_calldata =
            crate::protocol::seadrop::encode_get_mint_stats(alloy_primitives::Address::ZERO);
        match read_client
            .eth_call(args.plan_args.collection, &mint_stats_calldata)
            .await
        {
            Ok(raw) => match crate::protocol::seadrop::decode_get_mint_stats(&raw) {
                Ok(stats) => {
                    let remaining = stats.max_supply.saturating_sub(stats.current_total_supply);
                    println!();
                    println!("verified remaining supply: {remaining}");
                    if aggregate_quantity > remaining {
                        println!(
                            "WARNING: aggregate requested quantity ({aggregate_quantity}) exceeds verified remaining supply ({remaining}); a live session would fail before signing."
                        );
                    }
                }
                Err(e) => println!("mint stats: COULD NOT BE DECODED ({e})"),
            },
            Err(e) => println!("mint stats: COULD NOT BE FETCHED ({e})"),
        }
    }

    println!();
    println!("=================================================");
    println!(" MULTI-WALLET DRY RUN — NO TRANSACTION BROADCAST");
    println!(" Pass --send (with --yes, or interactive confirmation) to broadcast live.");
    println!(" No private key was loaded during this dry run.");
    println!("=================================================");
    Ok(())
}

async fn run_manifest_send(
    args: MintArgs,
    manifest: WalletManifest,
    engine: Engine,
) -> Result<(), KairoxError> {
    let (resolved, mut pool) = connect_pool_for_manifest(&args).await?;
    if pool.send_capable().is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no send-capable RPC endpoint connected; cannot broadcast live".into(),
        )));
    }

    let config = multi_wallet_config(&args)?;
    let aggregate_quantity: u64 = manifest.wallets.iter().map(|w| w.quantity).sum();
    let worst_case_session_spend = config
        .safety_caps
        .max_total_spend
        .saturating_mul(U256::from(manifest.wallets.len() as u64));

    println!("=================================================");
    println!(" MULTI-WALLET LIVE SEND CONFIRMATION");
    println!("=================================================");
    println!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("collection:           {}", args.plan_args.collection);
    println!("wallets configured:   {}", manifest.wallets.len());
    println!("aggregate quantity:   {aggregate_quantity}");
    println!(
        "worst-case max session spend (declared per-wallet caps): {worst_case_session_spend} wei"
    );
    if let Some(cap) = config.max_session_total_spend {
        println!("configured session spend cap: {cap} wei");
    }
    println!("send-capable endpoints: {}", pool.send_capable().len());
    println!("=================================================");
    println!(
        "WARNING: multiple-wallet participation may violate a project's rules even when each\n\
         wallet individually passes the smart-contract checks. Kairox does not determine\n\
         off-chain project policy. Proceeding confirms every configured wallet is legitimately\n\
         controlled or authorized by you, and that using them together complies with the drop's\n\
         rules."
    );
    println!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        println!("Aborted: live-send confirmation not received. Nothing was broadcast.");
        return Ok(());
    }

    let key_results = load_and_verify_wallet_keys(&ProcessEnv, &manifest.wallets);
    let mut wallets: Vec<(WalletMintRequest, crate::signing::signer::LocalSigner)> = Vec::new();
    for (entry, result) in key_results {
        match result {
            Ok(signer) => wallets.push((WalletMintRequest::from(&entry), signer)),
            Err(reason) => {
                println!(
                    "  [{}] {} -> KEY_LOAD_FAILED: {reason}",
                    entry.label.as_deref().unwrap_or("(unlabeled)"),
                    mask_address(&entry.address.to_string())
                );
            }
        }
    }
    if wallets.is_empty() {
        return Err(KairoxError::Session(SessionError(
            "no manifest wallet's key loaded and verified successfully; nothing to do".into(),
        )));
    }

    match engine {
        Engine::Public => {
            let result = run_multi_wallet_public_mint(
                &mut pool,
                &resolved.info,
                args.plan_args.collection,
                resolved.seadrop_contract,
                &wallets,
                &config,
                |_| {},
            )
            .await?;
            print_session_result(&result);
        }
        Engine::OpenSea => {
            let slug = args
                .plan_args
                .slug
                .clone()
                .ok_or(KairoxError::OpenSea(OpenSeaError::SlugRequired))?;
            let api_key = ProcessEnv
                .get(OPENSEA_API_KEY_ENV)?
                .ok_or(KairoxError::OpenSea(OpenSeaError::ApiKeyMissing))?;
            let opensea = OpenSeaClient::new_http(api_key, std::time::Duration::from_secs(10));
            let target = OpenSeaMultiWalletTarget {
                chain: &resolved.info,
                slug: &slug,
                nft_contract: args.plan_args.collection,
                seadrop_contract: resolved.seadrop_contract,
            };
            let (result, _drop_details) = run_multi_wallet_opensea_mint(
                &opensea,
                &mut pool,
                &target,
                &wallets,
                &config,
                |_| {},
            )
            .await?;
            print_session_result(&result);
        }
    }

    Ok(())
}

fn mask_address(addr: &str) -> String {
    if addr.len() > 10 {
        format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}

fn print_session_result(result: &crate::execution::multi_wallet::SessionResult) {
    println!();
    println!("=================================================");
    println!(" MULTI-WALLET SESSION RESULT");
    println!("=================================================");
    println!(
        "wallets: {} configured, {} succeeded, {} failed, {} uncertain",
        result.metrics.wallet_count,
        result.successful_count(),
        result.metrics.failed_wallet_count,
        result.metrics.uncertain_wallet_count,
    );
    println!();
    for w in &result.wallets {
        let label = w.request.label.as_deref().unwrap_or("(unlabeled)");
        let addr = mask_address(&w.request.address.to_string());
        let status = match &w.state {
            WalletExecutionState::ConfirmedSuccess { minted } => {
                let ids: Vec<String> = minted.iter().map(|m| m.token_id.to_string()).collect();
                format!("CONFIRMED_SUCCESS token_ids=[{}]", ids.join(","))
            }
            WalletExecutionState::ConfirmedRevert => "CONFIRMED_REVERT".to_string(),
            WalletExecutionState::Uncertain => {
                "UNCERTAIN (must not be automatically retried)".to_string()
            }
            WalletExecutionState::Ineligible { reason } => format!("INELIGIBLE: {reason}"),
            WalletExecutionState::InsufficientBalance => "INSUFFICIENT_BALANCE".to_string(),
            WalletExecutionState::AllocationExceeded => "ALLOCATION_EXCEEDED".to_string(),
            WalletExecutionState::Failed { reason } => format!("FAILED: {reason}"),
            other => format!("{other:?}"),
        };
        let tx_hash = w
            .tx_hash
            .map(|h| format!("0x{}", hex::encode(h)))
            .unwrap_or_else(|| "-".to_string());
        println!("  [{label}] {addr} -> {status} (tx: {tx_hash})");
    }

    println!();
    println!(
        "This result is NOT atomic: individual wallets may have succeeded, reverted, failed, or\n\
         remained uncertain independently of one another."
    );

    if let Some(skew) = result.metrics.multiwallet_dispatch_skew_ms {
        println!();
        println!("multiwallet_dispatch_skew_ms: {skew}");
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
