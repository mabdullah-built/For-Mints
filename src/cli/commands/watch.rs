//! `kairox watch` — waits for an explicitly-configured, not-yet-open stage
//! to become active, then executes automatically. See
//! [`crate::execution::watch`] for the state machine and the long-horizon
//! WAITING poll loop; this module wires that machinery to the CLI (argument
//! parsing, engine resolution, the watchlist file, and console reporting)
//! and to the same already-hardened `run_live_mint`/`run_opensea_mint`
//! critical paths `kairox mint --send` uses.
//!
//! Never discovers a collection/wallet on its own -- every target watched
//! is either the single `--collection`/`--wallet` pair on the command line,
//! or an entry explicitly listed in an operator-provided `--manifest` file.

use std::path::Path;
use std::time::Duration as StdDuration;

use alloy_primitives::Address;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use crate::chain::config::ProcessEnv;
use crate::chain::registry::ChainRegistry;
use crate::cli::args::{ChainArgs, EngineSelection, PlanArgs, WatchArgs};
use crate::cli::commands::mint::{connect_send_pool, load_opensea_client, print_broadcast_result};
use crate::cli::commands::plan::build_mint_plan;
use crate::cli::context::resolve_chain_and_runtime;
use crate::cli::format::{format_unix, parse_wei};
use crate::domain::fees::SafetyCaps;
use crate::domain::timing::StageStatus;
use crate::execution::errors::{KairoxError, SessionError, SessionErrorKind};
use crate::execution::live::{LiveMintConfig, LiveProgress, run_live_mint};
use crate::execution::opensea_engine::{OpenSeaMintRequest, OpenSeaProgress, run_opensea_mint};
use crate::execution::prepared::LiveMintRequest;
use crate::execution::profile::ExecutionProfile;
use crate::execution::watch::{
    StageProbe, StageSnapshot, WatchPollConfig, WatchState, wait_for_stage,
};
use crate::opensea::client::OpenSeaClient;
use crate::signing::keystore::load_signing_key;
use crate::signing::signer::Signer;

/// One fully-resolved target: exactly what to watch, for whom, and within
/// what safety limits. Built either directly from `WatchArgs` (single
/// target) or from one `[[target]]` entry of a `--manifest` file.
#[derive(Debug, Clone)]
struct WatchTarget {
    chain_args: ChainArgs,
    collection: Address,
    wallet: Address,
    slug: Option<String>,
    quantity: u64,
    engine: EngineSelection,
    fee_recipient: Option<Address>,
    max_mint_value_wei: String,
    max_gas_cost_wei: String,
    max_total_spend_wei: String,
    gas_buffer_multiplier: f64,
}

impl WatchTarget {
    fn to_plan_args(&self) -> PlanArgs {
        PlanArgs {
            collection: self.collection,
            chain_args: self.chain_args.clone(),
            engine: self.engine,
            slug: self.slug.clone(),
            wallet: Some(self.wallet),
            quantity: self.quantity,
            fee_recipient: self.fee_recipient,
            max_mint_value_wei: self.max_mint_value_wei.clone(),
            max_gas_cost_wei: self.max_gas_cost_wei.clone(),
            max_total_spend_wei: self.max_total_spend_wei.clone(),
            gas_buffer_multiplier: self.gas_buffer_multiplier,
            priority_fee_gwei: None,
            max_fee_gwei: None,
            json: false,
            output: None,
        }
    }
}

pub async fn run(args: WatchArgs, config_path: Option<&Path>) -> Result<(), KairoxError> {
    if !args.auto_send {
        return Err(KairoxError::Session(SessionError::new(
            "watch requires --auto-send: explicit informed consent for unattended broadcast at \
             T0. There is no interactive operator present to confirm mid-wait, so watch refuses \
             to run at all without it -- rerun with --auto-send once you have reviewed the \
             target below.",
        )));
    }

    let targets = if let Some(manifest_path) = &args.manifest {
        load_manifest(manifest_path)?
    } else {
        let collection = args.collection.ok_or_else(|| {
            KairoxError::Session(SessionError::new(
                "a collection address is required unless --manifest is used",
            ))
        })?;
        let wallet = args.wallet.ok_or_else(|| {
            KairoxError::Session(SessionError::new(
                "--wallet is required unless --manifest is used",
            ))
        })?;
        vec![WatchTarget {
            chain_args: args.chain_args.clone(),
            collection,
            wallet,
            slug: args.slug.clone(),
            quantity: args.quantity,
            engine: args.engine,
            fee_recipient: args.fee_recipient,
            max_mint_value_wei: args.max_mint_value_wei.clone(),
            max_gas_cost_wei: args.max_gas_cost_wei.clone(),
            max_total_spend_wei: args.max_total_spend_wei.clone(),
            gas_buffer_multiplier: args.gas_buffer_multiplier,
        }]
    };

    if targets.is_empty() {
        return Err(KairoxError::Session(SessionError::new(
            "no targets configured (empty --manifest)",
        )));
    }

    let poll_interval = StdDuration::from_secs(args.poll_interval_secs.max(1));

    // Every target's watch is independent (own chain connection, own
    // signer-address check, own stage/eligibility state) and none of them
    // shares mutable state, so a manifest with multiple entries runs them
    // concurrently rather than serially waiting on each in turn.
    let futures = targets
        .into_iter()
        .map(|target| run_single_target(target, poll_interval, config_path));
    let results = futures_util::future::join_all(futures).await;

    let mut first_err = None;
    for result in results {
        if let Err(e) = result {
            eprintln!("watch target stopped: {e}");
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn watch_poll_config(profile: &ExecutionProfile, poll_interval: StdDuration) -> WatchPollConfig {
    WatchPollConfig {
        poll_interval,
        arm_threshold: profile.scheduler_policy.state_check_lead,
        ..WatchPollConfig::default()
    }
}

fn print_state(state: &WatchState) {
    match state {
        WatchState::Waiting {
            stage_start,
            time_remaining,
        } => {
            eprintln!(
                "WAITING FOR STAGE — launch_at={} (unix {}) time_remaining={}s",
                format_unix(stage_start.unix_timestamp() as u64),
                stage_start.unix_timestamp(),
                time_remaining.whole_seconds().max(0),
            );
        }
        other => eprintln!("watch: {other:?}"),
    }
}

async fn run_single_target(
    target: WatchTarget,
    poll_interval: StdDuration,
    config_path: Option<&Path>,
) -> Result<(), KairoxError> {
    eprintln!(
        "=== watch target: collection={} wallet={} ===",
        target.collection, target.wallet
    );
    print_state(&WatchState::Discover);

    let registry = ChainRegistry::builtin();
    let (resolved, _runtime) =
        resolve_chain_and_runtime(&registry, &target.chain_args, config_path)?;

    // Fail fast, before any waiting: an unattended multi-day wait that ends
    // in a signing-key/wallet mismatch would waste the entire wait for
    // nothing.
    let signer = load_signing_key(&ProcessEnv, true).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e}"
        )))
    })?;
    if signer.address() != target.wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to watch",
                signer.address(),
                target.wallet
            ),
        )));
    }

    print_state(&WatchState::Verify);
    let plan_args = target.to_plan_args();
    let profile = ExecutionProfile::for_chain(resolved.info.chain_id);
    let poll_config = watch_poll_config(&profile, poll_interval);

    let engine = resolve_watch_engine(&target, &plan_args, config_path).await?;

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &target.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &target.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &target.max_total_spend_wei)?,
    };

    match engine {
        ResolvedWatchEngine::Public => {
            run_public_watch(
                target,
                plan_args,
                config_path,
                &poll_config,
                &resolved,
                &profile,
                &signer,
                safety_caps,
            )
            .await
        }
        ResolvedWatchEngine::OpenSea { slug } => {
            run_opensea_watch(
                target,
                slug,
                config_path,
                &poll_config,
                &resolved,
                &profile,
                &signer,
                safety_caps,
            )
            .await
        }
    }
}

enum ResolvedWatchEngine {
    Public,
    OpenSea { slug: String },
}

/// Delegates to the shared `execution::resolver::AdapterRegistry`
/// (`cli::commands::mint::resolve_auto_engine`) with
/// `allow_not_yet_started = true` -- unlike `mint`'s Auto (which only picks
/// Public when the stage is *already* `Active`, since a manually-timed
/// `mint --send` is expected to be run right at kickoff), `watch` must also
/// treat a `NotStarted` on-chain public stage as a legitimate Public
/// candidate -- that is precisely the "coming soon" case watch exists to
/// wait through.
async fn resolve_watch_engine(
    target: &WatchTarget,
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
) -> Result<ResolvedWatchEngine, KairoxError> {
    match target.engine {
        EngineSelection::Public => Ok(ResolvedWatchEngine::Public),
        EngineSelection::Opensea => {
            let slug = target.slug.clone().ok_or(KairoxError::OpenSea(
                crate::opensea::errors::OpenSeaError::SlugRequired,
            ))?;
            Ok(ResolvedWatchEngine::OpenSea { slug })
        }
        EngineSelection::Auto => {
            let detection =
                crate::cli::commands::mint::resolve_auto_engine(plan_args, config_path, true)
                    .await?;
            crate::cli::commands::mint::print_resolution_evidence(&detection);
            Ok(match detection.engine {
                crate::execution::resolver::ResolvedEngine::Public => ResolvedWatchEngine::Public,
                crate::execution::resolver::ResolvedEngine::OpenSea { slug } => {
                    ResolvedWatchEngine::OpenSea { slug }
                }
            })
        }
    }
}

struct PublicStageProbe<'a> {
    plan_args: &'a PlanArgs,
    config_path: Option<&'a Path>,
}

#[async_trait::async_trait]
impl StageProbe for PublicStageProbe<'_> {
    async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
        let plan = build_mint_plan(self.plan_args, self.config_path).await?;
        Ok(StageSnapshot {
            stage_start: plan.stage_start,
            status: plan.stage_status,
        })
    }
}

struct OpenSeaStageProbe<'a> {
    opensea: &'a OpenSeaClient,
    slug: &'a str,
}

#[async_trait::async_trait]
impl StageProbe for OpenSeaStageProbe<'_> {
    async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
        let details = self
            .opensea
            .get_drop_details(self.slug)
            .await
            .map_err(KairoxError::OpenSea)?;

        if let (Some(total), Some(max)) = (&details.total_supply, &details.max_supply)
            && let (Ok(total), Ok(max)) = (total.parse::<u64>(), max.parse::<u64>())
            && total >= max
        {
            return Err(KairoxError::Session(SessionError::new(format!(
                "collection {} is sold out ({total}/{max})",
                self.slug
            ))));
        }

        let stage = details
            .active_stage
            .as_ref()
            .or(details.next_stage.as_ref())
            .ok_or_else(|| {
                KairoxError::Session(SessionError::new(format!(
                    "OpenSea reports no active or upcoming stage for slug {}",
                    self.slug
                )))
            })?;
        let stage_start = OffsetDateTime::parse(
            &stage.start_time,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|e| {
            KairoxError::Session(SessionError::new(format!(
                "invalid OpenSea stage start_time: {e}"
            )))
        })?;
        let end_time = OffsetDateTime::parse(
            &stage.end_time,
            &time::format_description::well_known::Rfc3339,
        )
        .ok();
        let now = OffsetDateTime::now_utc();
        let status = match end_time {
            Some(end) if now >= end => StageStatus::Ended,
            _ if now >= stage_start => StageStatus::Active {
                ends_in: end_time.map(|e| e - now).unwrap_or(Duration::ZERO),
            },
            _ => StageStatus::NotStarted {
                starts_in: stage_start - now,
            },
        };
        Ok(StageSnapshot {
            stage_start,
            status,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_public_watch(
    target: WatchTarget,
    plan_args: PlanArgs,
    config_path: Option<&Path>,
    poll_config: &WatchPollConfig,
    resolved: &crate::cli::context::ResolvedChain,
    profile: &ExecutionProfile,
    signer: &dyn Signer,
    safety_caps: SafetyCaps,
) -> Result<(), KairoxError> {
    let probe = PublicStageProbe {
        plan_args: &plan_args,
        config_path,
    };
    let stage_start = wait_for_stage(&probe, poll_config, |state| print_state(&state)).await?;
    print_state(&WatchState::Arming);

    let mut pool = connect_send_pool(
        resolved,
        target.chain_args.rpc_url.as_ref(),
        None, // config-file endpoints were already consulted by resolve_chain_and_runtime's runtime; a raw connect here follows the same KAIROX_RPC_* / --rpc-url precedence mint uses.
    )
    .await?;

    let request = LiveMintRequest {
        chain: resolved.info.clone(),
        nft_contract: target.collection,
        seadrop_contract: resolved.seadrop_contract,
        wallet: target.wallet,
        quantity: target.quantity,
        preferred_fee_recipient: target.fee_recipient,
        gas_buffer_multiplier: target.gas_buffer_multiplier,
        safety_caps,
    };

    let mut config = LiveMintConfig::from(profile);
    config.known_stage_start = Some(stage_start);

    let outcome = run_live_mint(&mut pool, signer, &request, &config, |progress| {
        print_state(&live_progress_to_watch_state(&progress))
    })
    .await?;

    print_state(&WatchState::Success);
    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
        false,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_opensea_watch(
    target: WatchTarget,
    slug: String,
    _config_path: Option<&Path>,
    poll_config: &WatchPollConfig,
    resolved: &crate::cli::context::ResolvedChain,
    profile: &ExecutionProfile,
    signer: &dyn Signer,
    safety_caps: SafetyCaps,
) -> Result<(), KairoxError> {
    let opensea = load_opensea_client(StdDuration::from_secs(10))?;
    let probe = OpenSeaStageProbe {
        opensea: &opensea,
        slug: &slug,
    };
    // Per the OpenSea engine's own design, only stage timing/supply is
    // knowable ahead of T0 -- wallet-specific eligibility/proof/
    // authorization is only ever obtained from the real mint-request call
    // `run_opensea_mint` makes below, never fabricated here.
    wait_for_stage(&probe, poll_config, |state| print_state(&state)).await?;
    print_state(&WatchState::Arming);

    let mut pool = connect_send_pool(resolved, target.chain_args.rpc_url.as_ref(), None).await?;

    let request = OpenSeaMintRequest {
        chain: resolved.info.clone(),
        slug,
        nft_contract: target.collection,
        seadrop_contract: resolved.seadrop_contract,
        wallet: target.wallet,
        quantity: target.quantity,
        gas_buffer_multiplier: target.gas_buffer_multiplier,
        safety_caps,
        receipt_poll_interval: profile.receipt_poll_interval,
        receipt_timeout: profile.receipt_timeout,
        benchmark: profile.benchmark_policy,
        health: profile.health_policy,
        prewarm_lead: profile.prewarm_lead.try_into().unwrap_or(StdDuration::ZERO),
    };

    let outcome = run_opensea_mint(&opensea, &mut pool, signer, &request, |progress| {
        print_state(&opensea_progress_to_watch_state(&progress))
    })
    .await?;

    print_state(&WatchState::Success);
    print_broadcast_result(
        outcome.prepared.tx_hash,
        &outcome.broadcast_results,
        &outcome.broadcast_summary,
        &outcome.receipt_state,
        &outcome.metrics,
        false,
    );
    Ok(())
}

fn live_progress_to_watch_state(progress: &LiveProgress) -> WatchState {
    match progress {
        LiveProgress::Benchmarking | LiveProgress::Prewarming { .. } => WatchState::Arming,
        LiveProgress::Checkpoint(crate::execution::scheduler::Checkpoint::StateCheck) => {
            WatchState::TMinus10
        }
        LiveProgress::Checkpoint(crate::execution::scheduler::Checkpoint::Refresh) => {
            WatchState::TMinus3
        }
        LiveProgress::Checkpoint(crate::execution::scheduler::Checkpoint::Finalize) => {
            WatchState::Armed
        }
        LiveProgress::Waiting(_) => WatchState::T0,
        LiveProgress::Broadcasting { .. } => WatchState::Broadcasting,
        LiveProgress::ReceiptPending => WatchState::Receipt,
    }
}

fn opensea_progress_to_watch_state(progress: &OpenSeaProgress) -> WatchState {
    match progress {
        OpenSeaProgress::Benchmarking
        | OpenSeaProgress::Prewarming { .. }
        | OpenSeaProgress::Waiting(_) => WatchState::Arming,
        OpenSeaProgress::FetchingDropDetails
        | OpenSeaProgress::RequestingMintTransaction
        | OpenSeaProgress::Validating
        | OpenSeaProgress::Simulating => WatchState::Armed,
        OpenSeaProgress::Broadcasting { .. } => WatchState::Broadcasting,
        OpenSeaProgress::ReceiptPending => WatchState::Receipt,
    }
}

#[derive(Debug, Deserialize)]
struct WatchManifestFile {
    target: Vec<WatchManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct WatchManifestEntry {
    chain: Option<String>,
    collection: String,
    wallet: String,
    slug: Option<String>,
    #[serde(default = "default_quantity")]
    quantity: u64,
    #[serde(default)]
    engine: ManifestEngine,
    fee_recipient: Option<String>,
    max_mint_value_wei: Option<String>,
    max_gas_cost_wei: Option<String>,
    max_total_spend_wei: Option<String>,
    #[serde(default = "default_gas_buffer_multiplier")]
    gas_buffer_multiplier: f64,
}

fn default_quantity() -> u64 {
    1
}
fn default_gas_buffer_multiplier() -> f64 {
    1.25
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ManifestEngine {
    #[default]
    Auto,
    Public,
    Opensea,
}

impl From<ManifestEngine> for EngineSelection {
    fn from(e: ManifestEngine) -> Self {
        match e {
            ManifestEngine::Auto => EngineSelection::Auto,
            ManifestEngine::Public => EngineSelection::Public,
            ManifestEngine::Opensea => EngineSelection::Opensea,
        }
    }
}

fn parse_address(field: &str, raw: &str) -> Result<Address, KairoxError> {
    raw.parse().map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "manifest field {field}: {raw:?} is not a valid address: {e}"
        )))
    })
}

fn load_manifest(path: &Path) -> Result<Vec<WatchTarget>, KairoxError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to read watch manifest {}: {e}",
            path.display()
        )))
    })?;
    let file: WatchManifestFile = toml::from_str(&raw).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to parse watch manifest {}: {e}",
            path.display()
        )))
    })?;

    file.target
        .into_iter()
        .map(|entry| {
            let collection = parse_address("collection", &entry.collection)?;
            let wallet = parse_address("wallet", &entry.wallet)?;
            let fee_recipient = entry
                .fee_recipient
                .as_deref()
                .map(|raw| parse_address("fee_recipient", raw))
                .transpose()?;
            Ok(WatchTarget {
                chain_args: ChainArgs {
                    chain: entry.chain,
                    rpc_url: None,
                    seadrop_contract: None,
                },
                collection,
                wallet,
                slug: entry.slug,
                quantity: entry.quantity,
                engine: entry.engine.into(),
                fee_recipient,
                max_mint_value_wei: entry
                    .max_mint_value_wei
                    .unwrap_or_else(|| "1000000000000000000".to_string()),
                max_gas_cost_wei: entry
                    .max_gas_cost_wei
                    .unwrap_or_else(|| "1000000000000000000".to_string()),
                max_total_spend_wei: entry
                    .max_total_spend_wei
                    .unwrap_or_else(|| "2000000000000000000".to_string()),
                gas_buffer_multiplier: entry.gas_buffer_multiplier,
            })
        })
        .collect()
}
