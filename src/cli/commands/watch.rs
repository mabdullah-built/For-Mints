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
use futures_util::stream::{self, StreamExt};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use crate::chain::config::ProcessEnv;
use crate::chain::registry::ChainRegistry;
use crate::cli::args::{ChainArgs, EngineSelection, PlanArgs, WatchArgs};
use crate::cli::commands::mint::{
    connect_send_pool, emit_report, load_opensea_client, print_broadcast_result,
};
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
            // The generic verified contract engine is not wired into
            // `watch` this pass -- see docs/generic-engine.md.
            generic_schema: None,
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

/// `watch --auto-send` must never fall back to a permissive monetary
/// default -- checked before chain resolution, signing-key load, or any
/// network activity at all, for every target (single or manifest).
fn require_explicit_caps(
    label: &str,
    max_mint_value_wei: &Option<String>,
    max_gas_cost_wei: &Option<String>,
    max_total_spend_wei: &Option<String>,
) -> Result<(), KairoxError> {
    let mut missing = Vec::new();
    if max_mint_value_wei.is_none() {
        missing.push("--max-mint-value-wei");
    }
    if max_gas_cost_wei.is_none() {
        missing.push("--max-gas-cost-wei");
    }
    if max_total_spend_wei.is_none() {
        missing.push("--max-total-spend-wei");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::MissingSpendCaps,
            format!(
                "{label} is missing explicit spend cap(s): {}. watch --auto-send never assumes \
                 a permissive default for unattended broadcast -- pass all three explicitly \
                 (use \"0\" for a mint you have explicitly confirmed is free).",
                missing.join(", ")
            ),
        )))
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
        require_explicit_caps(
            "this watch invocation",
            &args.max_mint_value_wei,
            &args.max_gas_cost_wei,
            &args.max_total_spend_wei,
        )?;
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
            max_mint_value_wei: args
                .max_mint_value_wei
                .clone()
                .expect("checked by require_explicit_caps above"),
            max_gas_cost_wei: args
                .max_gas_cost_wei
                .clone()
                .expect("checked by require_explicit_caps above"),
            max_total_spend_wei: args
                .max_total_spend_wei
                .clone()
                .expect("checked by require_explicit_caps above"),
            gas_buffer_multiplier: args.gas_buffer_multiplier,
        }]
    };

    if targets.is_empty() {
        return Err(KairoxError::Session(SessionError::new(
            "no targets configured (empty --manifest)",
        )));
    }

    let poll_interval = StdDuration::from_secs(args.poll_interval_secs.max(1));
    let concurrency = args.max_concurrent_targets.max(1);
    let json = args.json;

    // Every target's watch is independent (own chain connection, own
    // signer-address check, own stage/eligibility state) and none of them
    // shares mutable state, so a manifest with multiple entries can run
    // concurrently rather than serially waiting on each in turn -- but
    // bounded, via the same `stream::iter(...).buffered(n)` pattern
    // `execution::multi_wallet` uses, never an unbounded `join_all` over an
    // arbitrarily large manifest and never a detached task.
    let results: Vec<Result<(), KairoxError>> = stream::iter(
        targets
            .into_iter()
            .map(|target| run_single_target(target, poll_interval, config_path, json)),
    )
    .buffered(concurrency)
    .collect()
    .await;

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
    json: bool,
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
    // nothing. `allow_interactive = false` is deliberate and load-bearing,
    // unlike `mint --send`'s prompt fallback: watch is meant to run
    // unattended (cron/systemd/CI), and blocking on a hidden stdin prompt
    // that will never receive input would hang forever instead of failing
    // closed -- a real, previously-untested production hang found while
    // adding this pass's e2e coverage.
    let signer = load_signing_key(&ProcessEnv, false).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to load signing key: {e} (watch never falls back to an interactive prompt; \
             set KAIROX_SIGNING_KEY before running watch --auto-send)"
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
    let profile = ExecutionProfile::for_chain(resolved.info.chain_id);
    let poll_config = watch_poll_config(&profile, poll_interval);

    let safety_caps = SafetyCaps {
        max_mint_value: parse_wei("--max-mint-value-wei", &target.max_mint_value_wei)?,
        max_gas_cost: parse_wei("--max-gas-cost-wei", &target.max_gas_cost_wei)?,
        max_total_spend: parse_wei("--max-total-spend-wei", &target.max_total_spend_wei)?,
    };

    // Bounded re-resolution: a fresh, semantically clear OpenSea
    // eligibility rejection for the exact stage just attempted at T0
    // excludes that stage (by its own unique StageId -- never by the
    // OpenSea collection slug, which identifies the whole drop and could
    // span several distinct stages) and re-resolves, so a later
    // legitimately-supported stage (e.g. a second signed stage, or an
    // on-chain public stage opening after a presale) still gets a real
    // chance instead of the whole session aborting. The exclusion list
    // only ever grows across attempts (never cleared), so a stage
    // already conclusively rejected this session can never be reselected
    // -- A rejected -> B rejected -> A reselected is structurally
    // impossible. Bounded (not unbounded) so a pathological resolver
    // loop can never spin forever.
    //
    // Pool lifecycle across a re-resolution: each loop iteration below is
    // a genuinely distinct execution attempt (a different stage was just
    // conclusively rejected), so `run_public_watch`/`run_opensea_watch`
    // each connect and fully benchmark exactly one *new* `RpcPool` for
    // that attempt -- this is intentional, not a mid-wait reconnect. The
    // "one pool stays alive across the wait" guarantee is scoped to a
    // single attempt (a single call to `run_public_watch` or
    // `run_opensea_watch`): within that call the pool is connected once,
    // benchmarked once, and never reconnected before dispatch. It is
    // never reused *across* attempts, since a new attempt targets a
    // different stage and has no reason to trust the previous attempt's
    // now-irrelevant ranking data.
    const MAX_RESOLUTION_ATTEMPTS: u32 = 4;
    let mut excluded_stage_ids: Vec<crate::domain::stage::StageId> = Vec::new();
    let mut ineligibility_attempts = 0u32;
    let mut reresolution_restarts = 0u32;
    loop {
        let plan_args = target.to_plan_args();
        let engine =
            resolve_watch_engine(&target, &plan_args, config_path, &excluded_stage_ids).await?;

        let result = match &engine {
            ResolvedWatchEngine::Public => {
                run_public_watch(
                    target.clone(),
                    plan_args,
                    config_path,
                    &poll_config,
                    &resolved,
                    &profile,
                    &signer,
                    safety_caps,
                    &excluded_stage_ids,
                    engine.clone(),
                    json,
                )
                .await
            }
            ResolvedWatchEngine::OpenSea { slug, .. } => {
                run_opensea_watch(
                    target.clone(),
                    slug.clone(),
                    plan_args,
                    config_path,
                    &poll_config,
                    &resolved,
                    &profile,
                    &signer,
                    safety_caps,
                    &excluded_stage_ids,
                    engine.clone(),
                    json,
                )
                .await
            }
        };

        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Round 6 item 10: a long wait's periodic re-resolution
                // found a materially different stage/engine than the one
                // this attempt started with -- restart against the fresh
                // resolution. Never a wallet-eligibility signal, never
                // added to the exclusion list, and bounded independently
                // of the ineligibility-retry counter below.
                if matches!(
                    &e,
                    KairoxError::Session(SessionError {
                        kind: SessionErrorKind::StageResolutionChanged,
                        ..
                    })
                ) {
                    reresolution_restarts += 1;
                    if reresolution_restarts > MAX_RERESOLUTION_RESTARTS {
                        return Err(e);
                    }
                    eprintln!(
                        "watch: {e} (restart {reresolution_restarts}/{MAX_RERESOLUTION_RESTARTS})"
                    );
                    continue;
                }

                let stage_id = match &engine {
                    ResolvedWatchEngine::OpenSea {
                        stage_uuid: Some(uuid),
                        ..
                    } => Some(crate::domain::stage::StageId::OpenSea {
                        stage_uuid: uuid.clone(),
                    }),
                    // An operator-provided --slug (no discovered stage
                    // identity) or the native public engine -- neither
                    // has a single specific stage to exclude, so a
                    // rejection here is never retried; it propagates.
                    ResolvedWatchEngine::OpenSea {
                        stage_uuid: None, ..
                    }
                    | ResolvedWatchEngine::Public => None,
                };
                if let (Some(stage_id), true) = (stage_id, is_clear_ineligibility_rejection(&e)) {
                    ineligibility_attempts += 1;
                    if ineligibility_attempts >= MAX_RESOLUTION_ATTEMPTS {
                        return Err(e);
                    }
                    eprintln!(
                        "watch: stage {stage_id:?} rejected as ineligible for this wallet \
                         (attempt {ineligibility_attempts}/{MAX_RESOLUTION_ATTEMPTS}) -- \
                         re-resolving, excluding it: {e}"
                    );
                    excluded_stage_ids.push(stage_id);
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// `true` only for a fresh, semantically unambiguous OpenSea
/// wallet-ineligibility rejection (`422` classified as
/// `EligibilityRejected` -- see `opensea::client::classify_precondition_failure`).
/// Deliberately narrow: a transport error, rate limit, timeout, server
/// error, or any other outcome must never be treated as proof the wallet
/// is ineligible -- only an explicit rejection from OpenSea's own backend
/// does. `AllocationExceeded`/`SupplyExhausted` (also 422s, but
/// keyword-classified as distinct outcomes) are deliberately excluded
/// too: those mean *this stage* is exhausted, not that the wallet was
/// rejected as ineligible for it, and re-resolving past them is not
/// (yet) part of this pass's scope.
fn is_clear_ineligibility_rejection(err: &KairoxError) -> bool {
    matches!(
        err,
        KairoxError::OpenSea(crate::opensea::errors::OpenSeaError::EligibilityRejected { .. })
    )
}

#[derive(Clone, PartialEq, Eq)]
enum ResolvedWatchEngine {
    Public,
    OpenSea {
        slug: String,
        /// The exact discovered stage identity, when one exists -- see
        /// `execution::resolver::ResolvedEngine::OpenSea`'s doc comment.
        stage_uuid: Option<String>,
    },
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
    excluded_stage_ids: &[crate::domain::stage::StageId],
) -> Result<ResolvedWatchEngine, KairoxError> {
    match target.engine {
        EngineSelection::Public => Ok(ResolvedWatchEngine::Public),
        EngineSelection::Opensea => {
            let slug = target.slug.clone().ok_or(KairoxError::OpenSea(
                crate::opensea::errors::OpenSeaError::SlugRequired,
            ))?;
            Ok(ResolvedWatchEngine::OpenSea {
                slug,
                stage_uuid: None,
            })
        }
        EngineSelection::Auto => {
            let detection = crate::cli::commands::mint::resolve_auto_engine(
                plan_args,
                config_path,
                true,
                excluded_stage_ids,
            )
            .await?;
            crate::cli::commands::mint::print_resolution_evidence(&detection);
            match detection.engine {
                crate::execution::resolver::ResolvedEngine::Public => {
                    Ok(ResolvedWatchEngine::Public)
                }
                crate::execution::resolver::ResolvedEngine::OpenSea { slug, stage_uuid } => {
                    Ok(ResolvedWatchEngine::OpenSea { slug, stage_uuid })
                }
                crate::execution::resolver::ResolvedEngine::Generic { .. } => {
                    // Not wired into watch this pass: the generic engine
                    // has no stage-timing model to wait against yet -- see
                    // docs/generic-engine.md. Use `kairox mint --engine
                    // auto --generic-schema ...` for an already-live
                    // generic contract instead.
                    Err(KairoxError::Session(SessionError::new(
                        "the generic verified contract engine is not yet supported by `watch` \
                         (no stage-timing model for it exists yet); use `kairox mint` for an \
                         already-live generic contract instead",
                    )))
                }
            }
        }
    }
}

/// How often a long `Auto`-engine wait re-runs full resolution to check
/// whether the currently-targeted stage is still what auto-resolution
/// would pick right now. Deliberately coarse (bounded API/RPC traffic,
/// "no hammering") -- this is a background correctness check for a
/// multi-hour/multi-day wait, not a tight polling loop; `wait_for_stage`'s
/// own `poll_interval` already covers the "is the targeted stage open
/// yet" question at whatever cadence the operator configured.
const DEFAULT_RERESOLUTION_INTERVAL: StdDuration = StdDuration::from_secs(30);

/// The real interval, honoring `KAIROX_WATCH_RERESOLUTION_INTERVAL_MS` when
/// set. This override exists solely so tests can observe re-resolution
/// restart behavior in seconds rather than real minutes -- it is never
/// documented as an operator-facing tuning flag, and an invalid/absent
/// value always falls back to [`DEFAULT_RERESOLUTION_INTERVAL`], never a
/// parse error.
fn reresolution_interval() -> StdDuration {
    std::env::var("KAIROX_WATCH_RERESOLUTION_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(StdDuration::from_millis)
        .unwrap_or(DEFAULT_RERESOLUTION_INTERVAL)
}

/// Bounded cap on how many times a single long wait may restart due to a
/// detected material resolution change, independent of
/// `MAX_RESOLUTION_ATTEMPTS` (which governs restarts after a clear
/// ineligibility rejection). Generous -- a real stage change is a rare
/// event even over a very long wait -- but never unbounded.
const MAX_RERESOLUTION_RESTARTS: u32 = 20;

/// Runs [`wait_for_stage`] (`execution::watch`'s unmodified, hardened
/// state machine) exactly as-is, but for an `Auto`-selected engine, races
/// it against a periodic full re-resolution check so a long wait never
/// remains permanently committed to a stage selection that has gone
/// stale -- see Round 6 item 10. Returns
/// `Err(SessionErrorKind::StageResolutionChanged)` the moment a
/// re-resolution disagrees with `currently_selected`; the caller
/// (`run_single_target`) is expected to catch that specific kind and
/// restart the whole attempt (a fresh pool connect + fresh benchmark +
/// fresh wait against the new selection), exactly like it already does
/// for a clear ineligibility rejection.
///
/// For an operator-forced `--engine public`/`--engine opensea` target
/// there is no ambiguity to re-check (`resolve_watch_engine` is
/// deterministic for those), so this is a pure pass-through to
/// `wait_for_stage` with no extra RPC/API traffic at all.
#[allow(clippy::too_many_arguments)]
async fn wait_for_stage_with_reresolution(
    probe: &dyn StageProbe,
    poll_config: &WatchPollConfig,
    target: &WatchTarget,
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    excluded_stage_ids: &[crate::domain::stage::StageId],
    currently_selected: &ResolvedWatchEngine,
    mut on_state: impl FnMut(WatchState),
) -> Result<OffsetDateTime, KairoxError> {
    if !matches!(target.engine, EngineSelection::Auto) {
        return wait_for_stage(probe, poll_config, on_state).await;
    }

    let reresolution_check = async {
        loop {
            tokio::time::sleep(reresolution_interval()).await;
            let fresh =
                resolve_watch_engine(target, plan_args, config_path, excluded_stage_ids).await?;
            if &fresh != currently_selected {
                return Err(KairoxError::Session(SessionError::with_kind(
                    SessionErrorKind::StageResolutionChanged,
                    "periodic re-resolution during a long wait found a materially different \
                     stage/engine than the one currently being waited on (a creator-changed \
                     start time, a new earlier-supported stage, a changed stage identity, or \
                     an OpenSea recovery/outage) -- restarting the attempt against the fresh \
                     resolution",
                )));
            }
            // Unchanged: loop and re-check again after another interval.
        }
    };
    tokio::pin!(reresolution_check);

    tokio::select! {
        biased;
        result = wait_for_stage(probe, poll_config, &mut on_state) => result,
        changed = &mut reresolution_check => changed,
    }
}

/// Decorates any [`StageProbe`] with bounded, in-memory, advisory-only
/// latency/outcome telemetry -- see `chain::telemetry`'s module docs for
/// the full rationale and invariants. Deliberately implemented as a pure
/// decorator around an existing probe, rather than a change to
/// `execution::watch::wait_for_stage` itself: telemetry piggybacks on
/// I/O the watch loop already performs every poll, so recording it adds
/// no new RPC/HTTP call, no new task, and zero risk to
/// `wait_for_stage`'s own already-hardened state machine (which remains
/// completely unmodified).
struct TelemetryProbe<'a> {
    inner: &'a dyn StageProbe,
    label: &'a str,
    store: &'a std::sync::Mutex<crate::chain::telemetry::TelemetryStore>,
    /// A read-capable client from the same already-connected, already
    /// -warm send `RpcPool` `watch` maintains for dispatch (never a new
    /// connection). When present, each probe cycle also takes one
    /// additional bounded, read-only `eth_getBlockByNumber` (+
    /// best-effort `eth_maxPriorityFeePerGas`) sample to populate
    /// [`crate::chain::telemetry::NetworkTelemetry`]. `None` when the
    /// pool currently has no healthy read-capable client -- network
    /// telemetry is then simply left unpopulated for this cycle, never a
    /// reason to fail the real probe.
    network_source: Option<&'a crate::chain::rpc::RpcClient>,
}

#[async_trait::async_trait]
impl StageProbe for TelemetryProbe<'_> {
    async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
        let started = std::time::Instant::now();
        let result = self.inner.probe().await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // A best-effort, read-only network observation -- entirely
        // separate from `self.inner.probe()`'s own outcome above, and
        // never allowed to affect it: a failure here is silently
        // dropped, never propagated. See `NetworkTelemetry`'s doc
        // comment for why this is safe to call every poll cycle (it
        // reuses an already-connected client, never opens a new one).
        if let Some(client) = self.network_source {
            if let Ok(mut store) = self.store.lock() {
                store.record_endpoint_identity(
                    client.label().unwrap_or("(unlabeled send-pool endpoint)"),
                    client.role(),
                );
            }
            if let Ok(block) = client.latest_block().await {
                let priority_fee = client.max_priority_fee_per_gas().await.ok();
                if let Some(base_fee) = block.base_fee_per_gas
                    && let Ok(mut store) = self.store.lock()
                {
                    store.record_network_observation(
                        block.number,
                        block.timestamp,
                        base_fee,
                        priority_fee,
                    );
                }
            }
        }

        // A poisoned telemetry mutex is never allowed to affect the real
        // probe outcome -- telemetry is strictly advisory, so a recording
        // failure here is silently skipped, never propagated or panicked
        // on.
        if let Ok(mut store) = self.store.lock() {
            match &result {
                Ok(_) => store.record_probe_success(self.label, elapsed_ms),
                Err(_) => store.record_probe_failure(self.label),
            }
        }
        result
    }
}

/// Prints one advisory-only summary line per endpoint/probe observed
/// during the wait -- purely informational, never consulted by any
/// downstream decision. `eprintln!`'d once, only *after*
/// `run_live_mint`/`run_opensea_mint` has already returned and
/// `WatchState::Success` has already printed -- i.e. strictly after
/// dispatch and receipt confirmation, never between stage-open
/// detection and broadcast.
fn print_telemetry_summary(store: &std::sync::Mutex<crate::chain::telemetry::TelemetryStore>) {
    let Ok(store) = store.lock() else {
        return;
    };
    for line in store.summary_lines() {
        eprintln!("watch: telemetry (advisory only): {line}");
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
    excluded_stage_ids: &[crate::domain::stage::StageId],
    currently_selected: ResolvedWatchEngine,
    json: bool,
) -> Result<(), KairoxError> {
    let started_at = OffsetDateTime::now_utc();
    let session_id = crate::cli::report::generate_session_id();

    // EARLY POOL LIFETIME: connect and fully benchmark *before* the wait,
    // not after -- the same pool then stays alive across the entire wait
    // and straight into dispatch, never reconnected from scratch at T0.
    // See `chain::benchmark::BenchmarkConfig::minimal`'s and
    // `execution::live::LiveMintConfig::skip_benchmark`'s doc comments
    // for why the internal near-T0 check (inside `run_live_mint`, via
    // REWARM) deliberately does *not* repeat this full ranking pass.
    let mut pool = connect_send_pool(resolved, target.chain_args.rpc_url.as_ref(), None).await?;
    pool.benchmark_all(&profile.benchmark_policy).await;
    pool.rewarm_all().await;

    let inner_probe = PublicStageProbe {
        plan_args: &plan_args,
        config_path,
    };
    let telemetry = std::sync::Mutex::new(crate::chain::telemetry::TelemetryStore::default());
    let probe = TelemetryProbe {
        inner: &inner_probe,
        label: "public-stage-probe",
        store: &telemetry,
        network_source: pool.preferred_read(),
    };
    let stage_start = wait_for_stage_with_reresolution(
        &probe,
        poll_config,
        &target,
        &plan_args,
        config_path,
        excluded_stage_ids,
        &currently_selected,
        |state| print_state(&state),
    )
    .await?;
    // NOTE: no telemetry/reporting output here -- this is the boundary
    // between "stage detected as open" and dispatch preparation. Nothing
    // optional runs between here and the broadcast; the telemetry
    // summary is printed only after the whole send/receipt sequence
    // completes, below.
    print_state(&WatchState::Arming);

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
    // The full benchmark above already ranked this exact pool; the
    // internal minimal check would otherwise silently discard that
    // ranking data (see `skip_benchmark`'s doc comment). REWARM (which
    // never touches ranking) still runs unconditionally inside
    // `run_live_mint`, giving a genuine near-T0 liveness re-check.
    config.skip_benchmark = true;

    let outcome = run_live_mint(&mut pool, signer, &request, &config, |progress| {
        print_state(&live_progress_to_watch_state(&progress))
    })
    .await?;

    print_state(&WatchState::Success);
    // Telemetry is printed here, after dispatch/receipt -- never between
    // stage-open detection and broadcast. See the module's regression
    // test proving this ordering.
    print_telemetry_summary(&telemetry);

    if json {
        let broadcast =
            crate::cli::report::build_broadcast_outcome_reports(&outcome.broadcast_results);
        let wallet_report = crate::cli::report::wallet_report_from_receipt(
            None,
            target.wallet,
            target.quantity,
            Some(outcome.prepared.tx_hash),
            outcome.receipt_state.as_ref(),
            broadcast,
        );
        let report = crate::cli::report::build_session_report(
            session_id,
            None,
            started_at,
            resolved.info.name,
            resolved.info.chain_id,
            target.collection,
            "public",
            false,
            vec![wallet_report],
            Some(outcome.metrics),
        );
        emit_report(&report, true, None)?;
        return Ok(());
    }

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
    plan_args: PlanArgs,
    config_path: Option<&Path>,
    poll_config: &WatchPollConfig,
    resolved: &crate::cli::context::ResolvedChain,
    profile: &ExecutionProfile,
    signer: &dyn Signer,
    safety_caps: SafetyCaps,
    excluded_stage_ids: &[crate::domain::stage::StageId],
    currently_selected: ResolvedWatchEngine,
    json: bool,
) -> Result<(), KairoxError> {
    let started_at = OffsetDateTime::now_utc();
    let session_id = crate::cli::report::generate_session_id();
    let opensea = load_opensea_client(StdDuration::from_secs(10))?;

    // EARLY POOL LIFETIME: connect and fully benchmark the chain RPC pool
    // *before* the wait -- see `run_public_watch`'s identical comment.
    // The OpenSea HTTP client itself is already warmed by its own
    // periodic drop-details polling below (a real, natural, already
    // -required request -- never a separate speculative warm-up call).
    let mut pool = connect_send_pool(resolved, target.chain_args.rpc_url.as_ref(), None).await?;
    pool.benchmark_all(&profile.benchmark_policy).await;
    pool.rewarm_all().await;

    let inner_probe = OpenSeaStageProbe {
        opensea: &opensea,
        slug: &slug,
    };
    let telemetry = std::sync::Mutex::new(crate::chain::telemetry::TelemetryStore::default());
    let probe = TelemetryProbe {
        inner: &inner_probe,
        label: "opensea-drop-details-probe",
        store: &telemetry,
        network_source: pool.preferred_read(),
    };
    // Per the OpenSea engine's own design, only stage timing/supply is
    // knowable ahead of T0 -- wallet-specific eligibility/proof/
    // authorization is only ever obtained from the real mint-request call
    // `run_opensea_mint` makes below, never fabricated here.
    wait_for_stage_with_reresolution(
        &probe,
        poll_config,
        &target,
        &plan_args,
        config_path,
        excluded_stage_ids,
        &currently_selected,
        |state| print_state(&state),
    )
    .await?;
    // No telemetry/reporting output here -- see run_public_watch's
    // identical comment; printed only after dispatch/receipt, below.
    print_state(&WatchState::Arming);

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
        // See run_public_watch's identical comment -- the full benchmark
        // above already ranked this pool.
        skip_benchmark: true,
        health: profile.health_policy,
        prewarm_lead: profile.prewarm_lead.try_into().unwrap_or(StdDuration::ZERO),
    };

    let outcome = run_opensea_mint(&opensea, &mut pool, signer, &request, |progress| {
        print_state(&opensea_progress_to_watch_state(&progress))
    })
    .await?;

    print_state(&WatchState::Success);
    print_telemetry_summary(&telemetry);

    if json {
        let broadcast =
            crate::cli::report::build_broadcast_outcome_reports(&outcome.broadcast_results);
        let wallet_report = crate::cli::report::wallet_report_from_receipt(
            None,
            target.wallet,
            target.quantity,
            Some(outcome.prepared.tx_hash),
            outcome.receipt_state.as_ref(),
            broadcast,
        );
        let report = crate::cli::report::build_session_report(
            session_id,
            None,
            started_at,
            resolved.info.name,
            resolved.info.chain_id,
            target.collection,
            "opensea",
            false,
            vec![wallet_report],
            Some(outcome.metrics),
        );
        emit_report(&report, true, None)?;
        return Ok(());
    }

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
        .enumerate()
        .map(|(index, entry)| {
            let label = format!("watchlist target #{index} ({})", entry.collection);
            require_explicit_caps(
                &label,
                &entry.max_mint_value_wei,
                &entry.max_gas_cost_wei,
                &entry.max_total_spend_wei,
            )?;
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
                    .expect("checked by require_explicit_caps above"),
                max_gas_cost_wei: entry
                    .max_gas_cost_wei
                    .expect("checked by require_explicit_caps above"),
                max_total_spend_wei: entry
                    .max_total_spend_wei
                    .expect("checked by require_explicit_caps above"),
                gas_buffer_multiplier: entry.gas_buffer_multiplier,
            })
        })
        .collect()
}

#[cfg(test)]
mod ineligibility_classification_tests {
    use super::*;
    use crate::chain::rpc::{RpcError, TransportError};
    use crate::opensea::errors::OpenSeaError;

    #[test]
    fn eligibility_rejected_is_the_only_clear_ineligibility_signal() {
        assert!(is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::EligibilityRejected {
                detail: "wallet not in allowlist".to_string()
            }
        )));
    }

    #[test]
    fn allocation_exceeded_and_supply_exhausted_are_not_ineligibility() {
        // Distinct outcomes -- the stage itself is exhausted, not proof
        // the wallet was rejected as ineligible for it. Re-resolving past
        // these is deliberately out of scope this pass -- see
        // is_clear_ineligibility_rejection's doc comment.
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::AllocationExceeded {
                detail: "limit exceeded".to_string()
            }
        )));
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::SupplyExhausted {
                detail: "sold out".to_string()
            }
        )));
    }

    #[test]
    fn transient_transport_errors_are_never_treated_as_ineligibility() {
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::ApiTimeout
        )));
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::ApiUnavailable {
                detail: "connection reset".to_string()
            }
        )));
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::RateLimited
        )));
        assert!(!is_clear_ineligibility_rejection(&KairoxError::OpenSea(
            OpenSeaError::ServerError {
                detail: "internal error".to_string()
            }
        )));
    }

    #[test]
    fn rpc_and_session_errors_are_never_treated_as_ineligibility() {
        assert!(!is_clear_ineligibility_rejection(&KairoxError::Rpc(
            RpcError::Transport(TransportError::Timeout(StdDuration::from_secs(1)))
        )));
        assert!(!is_clear_ineligibility_rejection(&KairoxError::Session(
            SessionError::new("some other session failure")
        )));
    }

    /// Round 6 item 3E: a benchmark/rewarm-driven infrastructure failure
    /// (every read-capable endpoint unhealthy -- exactly what
    /// `run_live_mint` returns as `NoVerifiedReadRpc` when
    /// `pool.preferred_read()` comes back `None`) must never be treated
    /// as wallet ineligibility. If it were, a transient run of dead RPC
    /// endpoints would permanently exclude a perfectly eligible stage --
    /// endpoint health and protocol/wallet eligibility are deliberately
    /// unrelated error classes.
    #[test]
    fn a_no_healthy_read_endpoint_infrastructure_failure_is_never_treated_as_ineligibility() {
        assert!(!is_clear_ineligibility_rejection(&KairoxError::Session(
            SessionError::with_kind(
                SessionErrorKind::NoVerifiedReadRpc,
                "no healthy, chain-verified read-capable RPC endpoint available",
            )
        )));
    }
}
