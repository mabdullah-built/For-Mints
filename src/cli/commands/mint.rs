//! `kairox mint` — dry-run by default (identical to Phase 1 behavior).
//! `--send` opts into the live pipeline: confirmation, signing-key load,
//! scheduled pre-signing, identical-raw-transaction broadcast, and receipt
//! confirmation.

use std::io::BufRead;
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime};

use crate::chain::config::{EnvSource, ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::{EngineSelection, MintArgs};
use crate::cli::commands::plan::{build_mint_plan, print_plan};
use crate::cli::context::resolve_chain_and_runtime;
use crate::cli::format::{format_unix, parse_wei};
use crate::domain::fees::SafetyCaps;
use crate::domain::timing::SleepSegment;
use crate::execution::broadcast::BroadcastSummary;
use crate::execution::errors::{KairoxError, SessionError, SessionErrorKind};
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
    OpenSea {
        slug: String,
    },
    Generic {
        target: crate::execution::generic_engine::ResolvedGenericTarget,
    },
    /// thirdweb Drop -- `args.plan_args.collection` doubles as the Drop
    /// contract address (see `EngineSelection::Thirdweb`'s doc comment).
    Thirdweb,
}

/// Resolve `--engine`/`--slug` into exactly one concrete engine.
///
/// `Explicit Public`/`Explicit Opensea` always win outright -- the operator
/// already decided. `Auto` goes through the shared
/// [`crate::execution::resolver::AdapterRegistry`] (native on-chain SeaDrop
/// tried first, the official OpenSea Drops route only as a fallback), which
/// fails closed with `UNSUPPORTED_PROTOCOL`/`AMBIGUOUS_PROTOCOL` rather than
/// silently defaulting to a guess. The resolved evidence is printed so an
/// operator can see *why* Kairox picked what it picked.
async fn select_engine(
    args: &MintArgs,
    config_path: Option<&std::path::Path>,
) -> Result<SelectedEngine, KairoxError> {
    match args.plan_args.engine {
        EngineSelection::Public => Ok(SelectedEngine::Public),
        EngineSelection::Thirdweb => Ok(SelectedEngine::Thirdweb),
        EngineSelection::Opensea => {
            let slug = args
                .plan_args
                .slug
                .clone()
                .ok_or(KairoxError::OpenSea(OpenSeaError::SlugRequired))?;
            Ok(SelectedEngine::OpenSea { slug })
        }
        EngineSelection::Auto => {
            let detection = resolve_auto_engine(&args.plan_args, config_path, false, &[]).await?;
            print_resolution_evidence(&detection);
            Ok(match detection.engine {
                crate::execution::resolver::ResolvedEngine::Public => SelectedEngine::Public,
                crate::execution::resolver::ResolvedEngine::OpenSea { slug, .. } => {
                    SelectedEngine::OpenSea { slug }
                }
                crate::execution::resolver::ResolvedEngine::Generic { target } => {
                    SelectedEngine::Generic { target }
                }
            })
        }
    }
}

/// Shared by `mint --engine auto` and `watch --engine auto`.
/// `allow_not_yet_started` distinguishes "I want to send right now"
/// (`mint`, false) from "I'm willing to wait for this stage" (`watch`,
/// true) -- see
/// [`crate::cli::commands::resolver_adapters::NormalizedStageAdapter`].
/// `excluded_stage_ids` lets `watch`'s re-resolution loop exclude stages
/// it has already proved ineligible at T0 -- always `&[]` for `mint`.
pub(crate) async fn resolve_auto_engine(
    plan_args: &crate::cli::args::PlanArgs,
    config_path: Option<&std::path::Path>,
    allow_not_yet_started: bool,
    excluded_stage_ids: &[crate::domain::stage::StageId],
) -> Result<crate::execution::resolver::Detection, KairoxError> {
    use crate::cli::commands::resolver_adapters::{
        GenericVerifiedContractAdapter, NormalizedStageAdapter,
    };
    use crate::execution::resolver::{AdapterRegistry, MintAdapter};

    let generic_schema = plan_args
        .generic_schema
        .as_deref()
        .map(crate::execution::generic_schema::load_schema)
        .transpose()?;

    // Resolved once here purely to pick a chain-appropriate verified-metadata
    // provider (if any) -- each adapter still independently resolves/connects
    // its own chain/client inside `detect()`, exactly as before.
    let chain_registry = ChainRegistry::builtin();
    let metadata_provider =
        resolve_chain_and_runtime(&chain_registry, &plan_args.chain_args, config_path)
            .ok()
            .and_then(|(resolved, _runtime)| {
                crate::metadata::blockscout::BlockscoutProvider::for_chain(
                    resolved.info.chain_id,
                    StdDuration::from_secs(10),
                )
            });
    let metadata_provider: Option<Box<dyn crate::metadata::VerifiedContractMetadataProvider>> =
        metadata_provider
            .map(|p| Box::new(p) as Box<dyn crate::metadata::VerifiedContractMetadataProvider>);

    // OpenSea auto-discovery is best-effort: if no API key is configured
    // (or it's otherwise unusable), `opensea` stays `None` and
    // `OpenSeaDropsAdapter` simply never attempts auto-discovery -- never
    // an error, since an operator running a purely native-SeaDrop
    // collection has no reason to configure an OpenSea key at all. An
    // explicit `--slug` still works regardless of this.
    let opensea = load_opensea_client(StdDuration::from_secs(10)).ok();

    let registry = AdapterRegistry::new(vec![
        Box::new(NormalizedStageAdapter {
            plan_args,
            config_path,
            slug: plan_args.slug.as_deref(),
            opensea: opensea.as_ref(),
            allow_not_yet_started,
            excluded_stage_ids,
        }) as Box<dyn MintAdapter>,
        Box::new(GenericVerifiedContractAdapter {
            plan_args,
            config_path,
            schema: generic_schema.as_ref(),
            trusted_registry: crate::execution::generic_registry::BUILTIN_REGISTRY,
            metadata_provider: metadata_provider.as_deref(),
        }) as Box<dyn MintAdapter>,
    ]);
    registry.resolve().await
}

pub(crate) fn print_resolution_evidence(detection: &crate::execution::resolver::Detection) {
    eprintln!(
        "resolved_engine: {:?} | adapter: {} | confidence: {:?} | evidence: {}",
        detection.engine,
        detection.evidence.adapter,
        detection.evidence.confidence,
        detection.evidence.source
    );
}

pub(crate) fn load_opensea_client(timeout: StdDuration) -> Result<OpenSeaClient, KairoxError> {
    let api_key = ProcessEnv
        .get(OPENSEA_API_KEY_ENV)?
        .ok_or(KairoxError::OpenSea(OpenSeaError::ApiKeyMissing))?;
    // KAIROX_OPENSEA_BASE_URL is an advanced/test-only override -- never
    // consulted unless explicitly set (see its own doc comment).
    match ProcessEnv.get(crate::opensea::client::OPENSEA_BASE_URL_OVERRIDE_ENV)? {
        Some(raw) => {
            let base_url = raw.parse().map_err(|e| {
                KairoxError::Session(SessionError::new(format!(
                    "{} is not a valid URL: {e}",
                    crate::opensea::client::OPENSEA_BASE_URL_OVERRIDE_ENV
                )))
            })?;
            Ok(OpenSeaClient::new_http_with_base_url(
                api_key, base_url, timeout,
            ))
        }
        None => Ok(OpenSeaClient::new_http(api_key, timeout)),
    }
}

pub async fn run(args: MintArgs, config_path: Option<&std::path::Path>) -> Result<(), KairoxError> {
    if args.wallet_manifest.is_some() {
        if args.rehearsal {
            return Err(KairoxError::Session(SessionError::new(
                "--rehearsal is not supported with --wallet-manifest yet; rehearse a single wallet first",
            )));
        }
        return crate::cli::commands::mint_multi::run_manifest(args, config_path).await;
    }
    if !args.send && !args.rehearsal {
        return run_dry_run(args, config_path).await;
    }

    run_send(args, config_path).await
}

async fn run_dry_run(
    args: MintArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let json = args.plan_args.json;
    let output = args.plan_args.output.clone();

    if !json {
        eprintln!("=================================================");
        eprintln!(" DRY RUN — NO TRANSACTION BROADCAST");
        eprintln!("=================================================");
        eprintln!();
    }

    match select_engine(&args, config_path).await? {
        SelectedEngine::Public => {
            let plan = build_mint_plan(&args.plan_args, config_path).await?;
            if json || output.is_some() {
                let wallet = args
                    .plan_args
                    .wallet
                    .expect("build_mint_plan already required --wallet");
                let report = crate::cli::report::build_execution_plan_report(
                    &plan,
                    "public",
                    wallet,
                    config_path,
                );
                emit_report(&report, json, output.as_deref())?;
                return Ok(());
            }
            println!("selected engine: PUBLIC (pure on-chain PublicSeaDropEngine)");
            println!();
            print_plan(&plan);
        }
        SelectedEngine::OpenSea { slug } => {
            if json || output.is_some() {
                // `kairox plan`/`kairox mint`'s JSON dry-run report is built
                // from a validated MintPlan (see `cli::report::ExecutionPlanReport`),
                // which the OpenSea engine's dry-run preview does not
                // produce today (it only fetches informational drop
                // metadata, never a validated on-chain plan) -- fail
                // clearly rather than emit a JSON object with a different,
                // undocumented shape.
                return Err(KairoxError::Session(SessionError::new(
                    "--json/--output for a dry run is only supported for the PUBLIC engine today; the OpenSea engine's dry-run preview has no structured report yet",
                )));
            }
            eprintln!("selected engine: OPENSEA (official OpenSea Drops API)");
            eprintln!();
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
        SelectedEngine::Generic { target } => {
            if json || output.is_some() {
                return Err(KairoxError::Session(SessionError::new(
                    "--json/--output for a dry run is only supported for the PUBLIC engine today",
                )));
            }
            let wallet = args
                .plan_args
                .wallet
                .expect("--wallet is required for a generic-engine dry run");
            println!("selected engine: GENERIC ({:?})", target.standard);
            println!();
            println!("source:         {}", target.source_label);
            println!("bytecode_hash:  {}", target.bytecode_hash);
            println!("shape:          {:?}", target.shape);
            println!("token_id:       {:?}", target.token_id);
            match target.price {
                crate::execution::generic_engine::ResolvedPrice::Fixed(p) => {
                    println!("price/token:    {p} wei (fixed)")
                }
                crate::execution::generic_engine::ResolvedPrice::LiveGetter(selector) => {
                    println!(
                        "price/token:    live getter 0x{} (read immediately before signing)",
                        hex::encode(selector)
                    )
                }
            }
            let schema = crate::execution::generic_schema::GenericMintSchema {
                standard: target.standard,
                shape: target.shape,
                token_id: target.token_id,
                price_per_token_wei: "0".to_string(),
            };
            let calldata = crate::execution::generic_engine::encode_calldata(
                &schema,
                wallet,
                args.plan_args.quantity,
            )?;
            println!("calldata:       0x{}", hex::encode(&calldata));
        }
        SelectedEngine::Thirdweb => {
            if json || output.is_some() {
                return Err(KairoxError::Session(SessionError::new(
                    "--json/--output for a dry run is only supported for the PUBLIC engine today",
                )));
            }
            let registry = ChainRegistry::builtin();
            let (resolved, runtime) =
                resolve_chain_and_runtime(&registry, &args.plan_args.chain_args, config_path)?;
            let client = crate::cli::context::connect_read_client(
                &resolved.info,
                args.plan_args.chain_args.rpc_url.as_ref(),
                runtime.config.as_ref(),
            )
            .await?;
            let condition_id = crate::cli::gather::fetch_thirdweb_active_claim_condition_id(
                &client,
                args.plan_args.collection,
            )
            .await?;
            let condition = crate::cli::gather::fetch_thirdweb_claim_condition_by_id(
                &client,
                args.plan_args.collection,
                condition_id,
            )
            .await?;
            println!("selected engine: THIRDWEB (thirdweb Drop ClaimCondition)");
            println!();
            println!("drop contract:            {}", args.plan_args.collection);
            println!("active claim condition:   {condition_id}");
            println!(
                "start:                    {} (unix {})",
                format_unix(condition.start_timestamp),
                condition.start_timestamp
            );
            println!(
                "price/token:              {} wei",
                condition.price_per_token
            );
            println!("currency:                 {}", condition.currency);
            println!(
                "native currency:          {}",
                condition.is_native_currency()
            );
            println!("supply remaining:         {}", condition.supply_remaining());
            println!(
                "per-wallet limit:         {}",
                condition.quantity_limit_per_wallet
            );
            println!(
                "allowlist gated:          {}",
                !condition.merkle_root.is_zero()
            );
            println!("--- (nothing above this line reflects wallet-specific eligibility) ---");
        }
    }

    println!();
    println!("=================================================");
    println!(" DRY RUN — NO TRANSACTION BROADCAST");
    println!(" Pass --send (with --yes, or interactive confirmation) to broadcast live.");
    println!("=================================================");
    Ok(())
}

/// Serialize `report` to JSON once, and: print it to stdout iff `json`,
/// write it to `output` iff given. At least one of the two is always true
/// when this is called. stdout carries ONLY the JSON object -- diagnostic
/// text about where a file was written goes to stderr.
pub(crate) fn emit_report<T: serde::Serialize>(
    report: &T,
    json: bool,
    output: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let text = serde_json::to_string(report).expect("report types are always serializable");
    if let Some(path) = output {
        crate::cli::report::write_report_atomic(path, &text).map_err(|e| {
            KairoxError::Session(SessionError::new(format!(
                "failed to write report to {}: {e}",
                path.display()
            )))
        })?;
        eprintln!("Report written to {}", path.display());
    }
    if json {
        println!("{text}");
    }
    Ok(())
}

async fn run_send(
    args: MintArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    match select_engine(&args, config_path).await? {
        SelectedEngine::Public => run_send_public(args, config_path).await,
        SelectedEngine::OpenSea { slug } => run_send_opensea(args, slug, config_path).await,
        SelectedEngine::Generic { target } => {
            if args.rehearsal {
                return Err(KairoxError::Session(SessionError::new(
                    "--rehearsal is only supported with the PUBLIC engine today; pass --engine public",
                )));
            }
            run_send_generic(args, target, config_path).await
        }
        SelectedEngine::Thirdweb => run_send_thirdweb(args, config_path).await,
    }
}

async fn run_send_generic(
    args: MintArgs,
    target: crate::execution::generic_engine::ResolvedGenericTarget,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    use crate::execution::broadcast::{
        broadcast_to_all, summarize_broadcast, uncertain_outcome_error,
    };
    use crate::execution::generic_engine::{GenericMintRequest, prepare_generic_transaction};
    use crate::execution::receipt::poll_receipt;

    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)",
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) =
        resolve_chain_and_runtime(&registry, &args.plan_args.chain_args, config_path)?;

    eprintln!(
        "selected engine: GENERIC ({:?}, source {:?})",
        target.standard, target.source_label
    );
    eprintln!("=================================================");
    eprintln!(" LIVE SEND CONFIRMATION");
    eprintln!("=================================================");
    eprintln!(
        "chain:      {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    eprintln!("wallet:         {wallet}");
    eprintln!("collection:     {}", args.plan_args.collection);
    eprintln!("bytecode_hash:  {}", target.bytecode_hash);
    eprintln!("shape:          {:?}", target.shape);
    match target.price {
        crate::execution::generic_engine::ResolvedPrice::Fixed(p) => {
            eprintln!("price/token:    {p} wei (fixed)")
        }
        crate::execution::generic_engine::ResolvedPrice::LiveGetter(selector) => eprintln!(
            "price/token:    live getter 0x{} (read immediately before signing)",
            hex::encode(selector)
        ),
    }
    eprintln!("quantity:       {}", args.plan_args.quantity);
    eprintln!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        eprintln!(
            "Aborted: confirmation not received. Nothing was signed, prepared, or broadcast."
        );
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e}"
        )))
    })?;
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                wallet
            ),
        )));
    }

    let pool = connect_send_pool(
        &resolved,
        args.plan_args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await?;
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            crate::execution::errors::SessionErrorKind::NoVerifiedReadRpc,
            "no healthy, chain-verified read-capable RPC endpoint available",
        ))
    })?;

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &args.plan_args.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &args.plan_args.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &args.plan_args.max_total_spend_wei)?,
    };

    // An operator-supplied --generic-schema, if present, only ever acts as
    // a maximum-price ceiling check against the registry-verified price --
    // never as the source of truth. See GenericMintRequest's docs.
    let operator_max_price_per_token_wei = args
        .plan_args
        .generic_schema
        .as_deref()
        .map(crate::execution::generic_schema::load_schema)
        .transpose()?
        .map(|s| {
            s.price_per_token_wei
                .parse::<alloy_primitives::U256>()
                .map_err(|e| {
                    KairoxError::Session(SessionError::new(format!(
                        "--generic-schema: invalid price_per_token_wei: {e}"
                    )))
                })
        })
        .transpose()?;

    let request = GenericMintRequest {
        chain: resolved.info.clone(),
        collection: args.plan_args.collection,
        wallet,
        quantity: args.plan_args.quantity,
        target,
        operator_max_price_per_token_wei,
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps,
    };

    let prepared = prepare_generic_transaction(read_client, &signer, &request).await?;

    let send_clients =
        pool.select_send_endpoints(&crate::chain::benchmark::HealthPolicy::default());
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError::new(
            "no healthy send-capable RPC endpoint available",
        )));
    }
    let broadcast_results = broadcast_to_all(&send_clients, &prepared.broadcast).await;
    let summary = summarize_broadcast(&broadcast_results);

    let receipt_state = match &summary {
        BroadcastSummary::Confirmed { .. } => Some(
            poll_receipt(
                read_client,
                prepared.tx_hash,
                args.plan_args.collection,
                wallet,
                args.plan_args.quantity,
                StdDuration::from_millis(750),
                StdDuration::from_secs(60),
                || {},
            )
            .await,
        ),
        BroadcastSummary::AllRejected => None,
        BroadcastSummary::Uncertain => return Err(uncertain_outcome_error(&broadcast_results)),
        BroadcastSummary::NotSent => None,
    };

    print_broadcast_result(
        prepared.tx_hash,
        &broadcast_results,
        &summary,
        &receipt_state,
        &crate::execution::metrics::LatencyMetrics::default(),
        false,
    );
    Ok(())
}

/// Connect every configured endpoint for `chain_args`'s chain and fail
/// closed if nothing send-capable came up. Shared by both engines' `--send`
/// paths.
pub(crate) async fn connect_send_pool(
    resolved: &crate::cli::context::ResolvedChain,
    rpc_url_override: Option<&url::Url>,
    config: Option<&crate::config::KairoxConfig>,
) -> Result<RpcPool, KairoxError> {
    let endpoints: Vec<RpcEndpoint> = if let Some(url) = rpc_url_override {
        vec![RpcEndpoint::new(url.clone(), EndpointRole::ReadWrite)]
    } else {
        let from_config = crate::cli::context::config_endpoints_for_chain(&resolved.info, config);
        if !from_config.is_empty() {
            from_config
        } else {
            load_chain_endpoints(&ProcessEnv, resolved.info.chain_id)?.endpoints
        }
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
        return Err(KairoxError::Session(SessionError::new(
            "no send-capable RPC endpoint connected; cannot broadcast live",
        )));
    }
    Ok(pool)
}

async fn run_send_public(
    args: MintArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let json = args.plan_args.json;
    let output = args.plan_args.output.clone();
    let started_at = OffsetDateTime::now_utc();

    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)",
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) =
        resolve_chain_and_runtime(&registry, &args.plan_args.chain_args, config_path)?;

    // Preview plan for the confirmation summary. Uses the same lenient
    // gather pipeline as `kairox plan` — purely informational here; the
    // actual transaction that gets signed is built fresh, strictly, by the
    // live pipeline below.
    let preview = build_mint_plan(&args.plan_args, config_path).await?;

    // session_id is generated here -- before any signing key is loaded or
    // used -- purely for correlating this session's own report/logs with
    // itself. No signing material is ever derived from it.
    let session_id = crate::cli::report::generate_session_id();
    let plan_id = Some(crate::cli::report::compute_plan_id(
        crate::cli::report::PlanIdInputs {
            chain_id: preview.chain.chain_id,
            collection: preview.nft_contract,
            engine: "public",
            wallets: &[wallet],
            quantities: &[preview.quantity],
            stage_start_unix: preview.stage_start.unix_timestamp(),
            stage_end_unix: preview.stage_end.unix_timestamp(),
            config_fingerprint: &crate::cli::report::config_fingerprint(config_path),
        },
    ));

    let mut pool = connect_send_pool(
        &resolved,
        args.plan_args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await?;

    eprintln!("selected engine: PUBLIC (pure on-chain PublicSeaDropEngine)");
    eprintln!("session_id: {session_id}");
    eprintln!("=================================================");
    if args.rehearsal {
        eprintln!(" REHEARSAL CONFIRMATION (no transaction will be broadcast)");
    } else {
        eprintln!(" LIVE SEND CONFIRMATION");
    }
    eprintln!("=================================================");
    eprintln!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    eprintln!("wallet:                {}", wallet);
    eprintln!("collection:            {}", args.plan_args.collection);
    eprintln!("quantity:              {}", args.plan_args.quantity);
    eprintln!("mint value:            {} wei", preview.mint_value);
    eprintln!("worst-case gas cost:   {} wei", preview.worst_case_gas_cost);
    eprintln!(
        "worst-case total spend:{} wei",
        preview.worst_case_total_spend
    );
    eprintln!("target contract:       {}", preview.target_contract);
    eprintln!(
        "planned stage-open:    {} (unix {})",
        format_unix(preview.stage_start.unix_timestamp() as u64),
        preview.stage_start.unix_timestamp()
    );
    eprintln!("send-capable endpoints:{}", pool.send_capable().len());
    eprintln!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        eprintln!(
            "Aborted: confirmation not received. Nothing was signed, prepared, or broadcast."
        );
        if json || output.is_some() {
            let report = crate::cli::report::build_session_report(
                session_id,
                plan_id,
                started_at,
                resolved.info.name,
                resolved.info.chain_id,
                args.plan_args.collection,
                "public",
                false,
                vec![crate::cli::report::wallet_report_from_receipt(
                    None,
                    wallet,
                    args.plan_args.quantity,
                    None,
                    None,
                    Vec::new(),
                )],
                None,
            );
            emit_report(&report, json, output.as_deref())?;
        }
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e}"
        )))
    })?;
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                wallet
            ),
        )));
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
    config.rehearsal = args.rehearsal;

    // Non-blocking progress reporting (final hardening pass item 1) --
    // see `cli::progress_reporter`'s module docs. `mint --send` is a
    // single, shorter-lived attempt (no long wait beforehand), but the
    // same stalled-consumer risk applies to every synchronous progress
    // print inside `run_live_mint`'s dispatch-critical checkpoint loop,
    // so it gets the identical treatment `watch` does.
    let mut receipt_pending_announced = false;
    let reporter =
        crate::cli::progress_reporter::ProgressReporter::spawn(move |progress: LiveProgress| {
            report_progress(progress, &mut receipt_pending_announced)
        });
    let outcome = run_live_mint(&mut pool, &signer, &request, &config, |progress| {
        reporter.emit(progress)
    })
    .await?;
    reporter.finish().await;

    if json || output.is_some() {
        let broadcast =
            crate::cli::report::build_broadcast_outcome_reports(&outcome.broadcast_results);
        let wallet_report = crate::cli::report::wallet_report_from_receipt(
            None,
            wallet,
            args.plan_args.quantity,
            Some(outcome.prepared.tx_hash),
            outcome.receipt_state.as_ref(),
            broadcast,
        );
        let report = crate::cli::report::build_session_report(
            session_id,
            plan_id,
            started_at,
            resolved.info.name,
            resolved.info.chain_id,
            args.plan_args.collection,
            "public",
            false,
            vec![wallet_report],
            Some(outcome.metrics),
        );
        emit_report(&report, json, output.as_deref())?;
        return Ok(());
    }

    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
        args.rehearsal,
    );

    Ok(())
}

/// `kairox mint --engine thirdweb --send` -- public-phase (no allowlist
/// gating) native-currency claims only, for now; see
/// `execution::thirdweb_engine`'s module doc comment for the exact
/// scope. An operator-supplied allowlist-proof CLI flag for gated phases
/// is explicit follow-up work -- the engine itself already supports it
/// (`ThirdwebMintRequest::allowlist_proof`), only the CLI plumbing to
/// accept one does not exist yet.
async fn run_send_thirdweb(
    args: MintArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)",
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) =
        resolve_chain_and_runtime(&registry, &args.plan_args.chain_args, config_path)?;

    let pool = connect_send_pool(
        &resolved,
        args.plan_args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await?;

    // Preview read for the confirmation summary only -- purely
    // informational here; the actual transaction that gets signed is
    // built fresh, strictly, by `run_thirdweb_mint` below.
    let preview_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::NoVerifiedReadRpc,
            "no healthy, chain-verified read-capable RPC endpoint available",
        ))
    })?;
    let preview_condition_id = crate::cli::gather::fetch_thirdweb_active_claim_condition_id(
        preview_client,
        args.plan_args.collection,
    )
    .await?;
    let preview_condition = crate::cli::gather::fetch_thirdweb_claim_condition_by_id(
        preview_client,
        args.plan_args.collection,
        preview_condition_id,
    )
    .await?;

    eprintln!("selected engine: THIRDWEB (thirdweb Drop ClaimCondition)");
    eprintln!("=================================================");
    if args.rehearsal {
        eprintln!(" REHEARSAL CONFIRMATION (no transaction will be broadcast)");
    } else {
        eprintln!(" LIVE SEND CONFIRMATION");
    }
    eprintln!("=================================================");
    eprintln!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    eprintln!("wallet:                {}", wallet);
    eprintln!("drop contract:         {}", args.plan_args.collection);
    eprintln!("quantity:              {}", args.plan_args.quantity);
    eprintln!(
        "price/token:           {} wei",
        preview_condition.price_per_token
    );
    eprintln!(
        "allowlist gated:       {}",
        !preview_condition.merkle_root.is_zero()
    );
    eprintln!("send-capable endpoints:{}", pool.send_capable().len());
    eprintln!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        eprintln!(
            "Aborted: confirmation not received. Nothing was signed, prepared, or broadcast."
        );
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e}"
        )))
    })?;
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                wallet
            ),
        )));
    }

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &args.plan_args.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &args.plan_args.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &args.plan_args.max_total_spend_wei)?,
    };

    let request = crate::execution::thirdweb_engine::ThirdwebMintRequest {
        chain: resolved.info.clone(),
        drop_contract: args.plan_args.collection,
        wallet,
        quantity: args.plan_args.quantity,
        gas_buffer_multiplier: args.plan_args.gas_buffer_multiplier,
        safety_caps,
        allowlist_proof: None,
    };

    let profile = ExecutionProfile::for_chain(resolved.info.chain_id);
    let outcome = crate::execution::thirdweb_engine::run_thirdweb_mint(
        &pool,
        &signer,
        &request,
        &profile.health_policy,
        profile.receipt_poll_interval,
        profile.receipt_timeout,
        args.rehearsal,
    )
    .await?;

    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &crate::execution::metrics::LatencyMetrics::default(),
        args.rehearsal,
    );

    Ok(())
}

async fn run_send_opensea(
    args: MintArgs,
    slug: String,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let json = args.plan_args.json;
    let output = args.plan_args.output.clone();
    let started_at = OffsetDateTime::now_utc();

    let wallet = args.plan_args.wallet.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "--wallet is required (or use --wallet-manifest for a multi-wallet session)",
        ))
    })?;
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) =
        resolve_chain_and_runtime(&registry, &args.plan_args.chain_args, config_path)?;
    let opensea = load_opensea_client(StdDuration::from_secs(10))?;

    let mut pool = connect_send_pool(
        &resolved,
        args.plan_args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await?;

    let drop_details = opensea.get_drop_details(&slug).await?;

    // session_id/plan_id are generated here -- before any signing key is
    // loaded or used. The OpenSea engine's plan_id uses a zero stage
    // window: unlike the public engine, the pre-signing preview here is
    // only the informational drop-metadata fetch above, which carries no
    // validated on-chain stage window to hash.
    let session_id = crate::cli::report::generate_session_id();
    let plan_id = Some(crate::cli::report::compute_plan_id(
        crate::cli::report::PlanIdInputs {
            chain_id: resolved.info.chain_id,
            collection: args.plan_args.collection,
            engine: "opensea",
            wallets: &[wallet],
            quantities: &[args.plan_args.quantity],
            stage_start_unix: 0,
            stage_end_unix: 0,
            config_fingerprint: &crate::cli::report::config_fingerprint(config_path),
        },
    ));

    eprintln!("selected engine: OPENSEA (official OpenSea Drops API)");
    eprintln!("session_id: {session_id}");
    eprintln!("=================================================");
    if args.rehearsal {
        eprintln!(" REHEARSAL CONFIRMATION (no transaction will be broadcast)");
    } else {
        eprintln!(" LIVE SEND CONFIRMATION");
    }
    eprintln!("=================================================");
    eprintln!(
        "chain:                {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    eprintln!("wallet:                {}", wallet);
    eprintln!("collection:            {}", args.plan_args.collection);
    eprintln!("opensea slug:          {slug}");
    eprintln!("quantity:              {}", args.plan_args.quantity);
    eprintln!(
        "opensea drop_type:     {} (off-chain metadata, not on-chain verified)",
        drop_details.drop_type
    );
    eprintln!("target contract:       {}", resolved.seadrop_contract);
    eprintln!("send-capable endpoints:{}", pool.send_capable().len());
    eprintln!("=================================================");

    if !confirmation_satisfied(args.yes, read_stdin_confirmation) {
        eprintln!(
            "Aborted: {} confirmation not received. Nothing was broadcast.",
            if args.rehearsal {
                "rehearsal"
            } else {
                "live-send"
            }
        );
        if json || output.is_some() {
            let report = crate::cli::report::build_session_report(
                session_id,
                plan_id,
                started_at,
                resolved.info.name,
                resolved.info.chain_id,
                args.plan_args.collection,
                "opensea",
                false,
                vec![crate::cli::report::wallet_report_from_receipt(
                    None,
                    wallet,
                    args.plan_args.quantity,
                    None,
                    None,
                    Vec::new(),
                )],
                None,
            );
            emit_report(&report, json, output.as_deref())?;
        }
        return Ok(());
    }

    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e}"
        )))
    })?;
    if signer.address() != wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                wallet
            ),
        )));
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
        skip_benchmark: false,
        health: profile.health_policy,
        prewarm_lead: std_duration_from_time(profile.prewarm_lead),
        rehearsal: args.rehearsal,
    };

    // Non-blocking progress reporting -- see run_send_public's identical
    // comment and `cli::progress_reporter`'s module docs.
    let reporter = crate::cli::progress_reporter::ProgressReporter::spawn(report_opensea_progress);
    let outcome = run_opensea_mint(&opensea, &mut pool, &signer, &request, |progress| {
        reporter.emit(progress)
    })
    .await?;
    reporter.finish().await;

    if json || output.is_some() {
        let broadcast =
            crate::cli::report::build_broadcast_outcome_reports(&outcome.broadcast_results);
        let wallet_report = crate::cli::report::wallet_report_from_receipt(
            None,
            wallet,
            args.plan_args.quantity,
            Some(outcome.prepared.tx_hash),
            outcome.receipt_state.as_ref(),
            broadcast,
        );
        let report = crate::cli::report::build_session_report(
            session_id,
            plan_id,
            started_at,
            resolved.info.name,
            resolved.info.chain_id,
            args.plan_args.collection,
            "opensea",
            false,
            vec![wallet_report],
            Some(outcome.metrics),
        );
        emit_report(&report, json, output.as_deref())?;
        return Ok(());
    }

    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
        args.rehearsal,
    );

    Ok(())
}

fn std_duration_from_time(d: time::Duration) -> StdDuration {
    d.try_into().unwrap_or(StdDuration::ZERO)
}

pub(crate) fn print_broadcast_result(
    tx_hash: alloy_primitives::B256,
    broadcast_results: &[crate::execution::broadcast::EndpointBroadcastResult],
    broadcast_summary: &BroadcastSummary,
    receipt_state: &Option<ReceiptState>,
    metrics: &crate::execution::metrics::LatencyMetrics,
    is_rehearsal: bool,
) {
    println!();
    println!("=================================================");
    if is_rehearsal {
        println!(" REHEARSAL RESULT (nothing was broadcast)");
    } else {
        println!(" BROADCAST RESULT");
    }
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
        BroadcastSummary::NotSent => println!(
            "summary: REHEARSAL COMPLETE — signed and serialized, but eth_sendRawTransaction was never called. Pass --send to actually broadcast."
        ),
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
        Some(ReceiptState::ConfirmedExecutionMismatch {
            minted,
            expected_quantity,
        }) => {
            println!(
                "receipt: CONFIRMED_EXECUTION_MISMATCH -- blockchain execution confirmed, but expected mint not proven"
            );
            println!(
                "  expected {expected_quantity} attributable mint transfer(s), observed {}",
                minted.len()
            );
            for asset in minted {
                println!(
                    "  observed mint token id {} (amount {})",
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
    eprint!("Type 'yes' to broadcast live, anything else to abort: ");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    Some(line)
}

/// Progress/diagnostic text always goes to stderr -- never stdout, in
/// either human or `--json` mode -- so stdout is always either the final
/// human report or (with `--json`) exactly one JSON object, never a mix.
fn report_progress(progress: LiveProgress, receipt_pending_announced: &mut bool) {
    match progress {
        LiveProgress::Benchmarking => eprintln!("[benchmark] sampling endpoint latency"),
        LiveProgress::Prewarming { scheduling } => {
            let mode = match scheduling {
                crate::execution::live::PrewarmScheduling::StageRelative => "stage-relative",
                crate::execution::live::PrewarmScheduling::Immediate => "immediate",
            };
            eprintln!("[prewarm] rewarming connections ({mode})");
        }
        LiveProgress::Checkpoint(Checkpoint::StateCheck) => eprintln!("[checkpoint] state check"),
        LiveProgress::Checkpoint(Checkpoint::Refresh) => {
            eprintln!("[checkpoint] refresh (nonce/fee/balance/supply)")
        }
        LiveProgress::Checkpoint(Checkpoint::Finalize) => {
            eprintln!("[checkpoint] finalize (sign + serialize)")
        }
        LiveProgress::Waiting(SleepSegment::Coarse(d)) => {
            eprintln!("[waiting] {} s until next checkpoint", d.whole_seconds())
        }
        LiveProgress::Waiting(SleepSegment::Fine(_)) => {}
        LiveProgress::Broadcasting {
            send_endpoint_count,
        } => {
            eprintln!("[dispatch] broadcasting to {send_endpoint_count} endpoint(s)");
        }
        LiveProgress::ReceiptPending => {
            if !*receipt_pending_announced {
                eprintln!("[receipt] waiting for confirmation...");
                *receipt_pending_announced = true;
            }
        }
    }
}

fn report_opensea_progress(progress: OpenSeaProgress) {
    match progress {
        OpenSeaProgress::Benchmarking => eprintln!("[benchmark] sampling endpoint latency"),
        OpenSeaProgress::FetchingDropDetails => {
            eprintln!("[opensea] fetching drop details")
        }
        OpenSeaProgress::Prewarming { scheduling } => {
            let mode = match scheduling {
                crate::execution::live::PrewarmScheduling::StageRelative => "stage-relative",
                crate::execution::live::PrewarmScheduling::Immediate => "immediate",
            };
            eprintln!("[prewarm] rewarming connections ({mode})");
        }
        OpenSeaProgress::Waiting(SleepSegment::Coarse(d)) => {
            eprintln!("[waiting] {} s until stage open", d.whole_seconds())
        }
        OpenSeaProgress::Waiting(SleepSegment::Fine(_)) => {}
        OpenSeaProgress::RequestingMintTransaction => {
            eprintln!("[opensea] requesting mint transaction")
        }
        OpenSeaProgress::Validating => eprintln!("[opensea] validating response locally"),
        OpenSeaProgress::Simulating => eprintln!("[chain] simulating transaction"),
        OpenSeaProgress::Broadcasting {
            send_endpoint_count,
        } => {
            eprintln!("[dispatch] broadcasting to {send_endpoint_count} endpoint(s)");
        }
        OpenSeaProgress::ReceiptPending => eprintln!("[receipt] waiting for confirmation..."),
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
