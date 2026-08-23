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
            // Manifold is not wired into `watch` either (see the
            // EngineSelection::Manifold match arm in resolve_watch_engine
            // below) -- these fields are never consulted.
            manifold_extension: None,
            instance_id: "0".to_string(),
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
    // `--rehearsal` never broadcasts, so it needs none of the "unattended
    // real broadcast" consent `--auto-send` exists for -- it satisfies
    // this same gate on its own.
    if !args.auto_send && !args.rehearsal {
        return Err(KairoxError::Session(SessionError::new(
            "watch requires --auto-send (or --rehearsal, which never broadcasts): explicit \
             informed consent for unattended broadcast at T0. There is no interactive operator \
             present to confirm mid-wait, so watch refuses to run at all without one of them -- \
             rerun with --auto-send once you have reviewed the target below, or with \
             --rehearsal to safely exercise the full pipeline without ever broadcasting.",
        )));
    }
    let rehearsal = args.rehearsal;

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
            .map(|target| run_single_target(target, poll_interval, config_path, json, rehearsal)),
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
    rehearsal: bool,
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
        let engine = resolve_watch_engine(
            &target,
            &plan_args,
            config_path,
            &excluded_stage_ids,
            safety_caps,
            rehearsal,
        )
        .await?;

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
                    rehearsal,
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
                    rehearsal,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
/// Constructs the operator-facing `STAGE_ALREADY_LIVE` refusal. Only ever
/// called once actionability has genuinely been *verified* -- see
/// [`resolve_watch_engine`]'s callers -- so "verified" in the message is
/// never an overclaim: for a native SeaDrop public stage, real on-chain
/// timing/allocation/supply reads are themselves sufficient proof; for an
/// OpenSea stage, [`crate::cli::commands::resolver_adapters::check_opensea_stage_actionable_now`]
/// has already positively validated a real, wallet-specific mint-builder
/// response before this is ever constructed.
fn stage_already_live_error(collection: alloy_primitives::Address) -> KairoxError {
    KairoxError::Session(SessionError::with_kind(
        SessionErrorKind::StageAlreadyLive,
        format!(
            "STAGE_ALREADY_LIVE: this stage is already active and Kairox verified that the \
             configured wallet/quantity can currently use it. `watch` is for future stages; use \
             `kairox mint {collection:#x} --send --yes` instead (or pass --rehearsal to safely \
             exercise this stage's pipeline without broadcasting)."
        ),
    ))
}

/// Constructs the `ACTIVE_STAGE_ELIGIBILITY_UNKNOWN` refusal -- see
/// [`SessionErrorKind::ActiveStageEligibilityUnknown`]'s doc comment.
/// Deliberately distinguishable from both `stage_already_live_error` and
/// a clean ineligibility rejection: an ambiguous outcome must never be
/// silently upgraded to either.
fn active_stage_eligibility_unknown_error(
    wallet: alloy_primitives::Address,
    collection: alloy_primitives::Address,
    cause: KairoxError,
) -> KairoxError {
    KairoxError::Session(SessionError::with_kind(
        SessionErrorKind::ActiveStageEligibilityUnknown,
        format!(
            "ACTIVE_STAGE_ELIGIBILITY_UNKNOWN: an active, supported stage exists for this \
             collection, but Kairox could not establish whether wallet {wallet:#x} can \
             currently execute it ({cause}); refusing to guess in either direction. Retry, or \
             use `kairox mint {collection:#x} --send --yes` to attempt it directly and observe \
             the real outcome."
        ),
    ))
}

/// Bounded cap on how many times [`resolve_watch_engine`]'s `Auto` branch
/// may exclude a temporally-active-but-not-actionable OpenSea stage and
/// re-resolve before giving up -- distinct from (and much smaller than)
/// `MAX_RESOLUTION_ATTEMPTS`, since this only ever runs once per attempt
/// at initial resolution time, never in a hot polling loop.
const MAX_LIVE_CHECK_ATTEMPTS: u32 = 4;

/// Resolves which engine a `watch` attempt should target, and -- for a
/// real (non-rehearsal) initial resolution -- enforces the WATCH-vs-LIVE
/// contract: `watch` exists to wait for a *future* stage, never to
/// silently act on one that is already live (that is `mint`'s job).
///
/// True-final-release-gate semantic correction: an earlier version of
/// this check treated `WatchStageDecision::AlreadyLive` alone (temporally
/// active + `EligibilityState::Eligible | UnknownUntilActive`) as
/// sufficient grounds for `STAGE_ALREADY_LIVE`. That is correct for a
/// native SeaDrop public stage (its `NormalizedStage` capacity fields
/// come from a real, authoritative on-chain read -- see
/// `resolver_adapters::discover_public_stage`) but was **too broad** for
/// an OpenSea signed/allowlist/FCFS/FCFA stage: `UnknownUntilActive` is
/// not positive proof any specific wallet can execute it, only that
/// eligibility genuinely cannot be known before the stage is active. A
/// wallet could be temporally looking at an active signed stage it is
/// actually ineligible for, while a later public stage remains a
/// perfectly valid future target -- `STAGE_ALREADY_LIVE` must never tell
/// the operator to switch to `mint` on that basis. For an OpenSea stage,
/// this now additionally requires
/// `resolver_adapters::check_opensea_stage_actionable_now` to positively
/// verify a real, wallet-specific mint-builder response before
/// `STAGE_ALREADY_LIVE` is ever emitted -- see that function's doc
/// comment. Applies identically across all three engine-selection modes
/// (`--engine auto`, `--engine public`, `--engine opensea --slug`): the
/// specifically-selected route being already `Active` and positively
/// actionable always means `STAGE_ALREADY_LIVE`, never a silent
/// immediate execution through `watch`.
async fn resolve_watch_engine(
    target: &WatchTarget,
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    excluded_stage_ids: &[crate::domain::stage::StageId],
    safety_caps: SafetyCaps,
    // `false` only for the *very first* resolution of a fresh attempt
    // (and even then, only when not `--rehearsal`): an `AlreadyLive`
    // decision there means the operator asked `watch` to wait for
    // something that is already live, which `watch` refuses
    // (`STAGE_ALREADY_LIVE`). `true` for every other caller --
    // critically, the periodic re-resolution check that runs *during* an
    // already-in-progress wait, where the very stage being waited on
    // transitioning to `AlreadyLive` is success, not an error: refusing
    // there would abort a legitimate wait the instant its target stage
    // opens, racing against (and potentially beating) `wait_for_stage`'s
    // own correct handoff.
    allow_already_live: bool,
) -> Result<ResolvedWatchEngine, KairoxError> {
    match target.engine {
        EngineSelection::Thirdweb => Err(KairoxError::Session(SessionError::new(
            "--engine thirdweb is not yet supported by watch; use kairox mint --engine thirdweb \
             --send directly against an already-live phase (v0.8 Phase B scope)"
                .to_string(),
        ))),
        EngineSelection::Manifold => Err(KairoxError::Session(SessionError::new(
            "--engine manifold is not yet supported by watch; use kairox mint --engine manifold \
             --send directly against an already-live claim (v0.8 scope)"
                .to_string(),
        ))),
        EngineSelection::Public => {
            // Explicit-engine modes obey the exact same WATCH-vs-LIVE
            // contract as `--engine auto` -- item 6 of the true-final
            // release gate. A native public stage's on-chain
            // timing/allocation/supply reads are themselves sufficient
            // proof, so this reuses `select_for_live_mint` (the identical
            // check `mint --engine auto` performs) directly on the one
            // discovered stage -- no separate actionability preflight
            // needed, unlike OpenSea below.
            if !allow_already_live
                && let Some(stage) = crate::cli::commands::resolver_adapters::discover_public_stage(
                    plan_args,
                    config_path,
                )
                .await?
                && matches!(
                    crate::execution::stage_resolver::select_for_live_mint(
                        std::slice::from_ref(&stage),
                        OffsetDateTime::now_utc()
                    ),
                    crate::execution::stage_resolver::LiveStageDecision::Selected(_)
                )
            {
                return Err(stage_already_live_error(target.collection));
            }
            Ok(ResolvedWatchEngine::Public)
        }
        EngineSelection::Opensea => {
            let slug = target.slug.clone().ok_or(KairoxError::OpenSea(
                crate::opensea::errors::OpenSeaError::SlugRequired,
            ))?;
            if !allow_already_live {
                // An operator-provided slug identifies a whole drop, not
                // one exact stage -- `get_drop_details` is the same real,
                // read-only lookup `run_opensea_mint`/`OpenSeaStageProbe`
                // already perform to learn the drop's current stage.
                let opensea =
                    crate::cli::commands::mint::load_opensea_client(StdDuration::from_secs(10))?;
                let details = opensea
                    .get_drop_details(&slug)
                    .await
                    .map_err(KairoxError::OpenSea)?;
                let now = OffsetDateTime::now_utc();
                let is_temporally_active = details.active_stage.as_ref().is_some_and(|stage| {
                    let start = OffsetDateTime::parse(
                        &stage.start_time,
                        &time::format_description::well_known::Rfc3339,
                    );
                    let end = OffsetDateTime::parse(
                        &stage.end_time,
                        &time::format_description::well_known::Rfc3339,
                    );
                    match (start, end) {
                        (Ok(start), Ok(end)) => now >= start && now < end,
                        (Ok(start), Err(_)) => now >= start,
                        (Err(_), _) => false,
                    }
                });
                if is_temporally_active {
                    match crate::cli::commands::resolver_adapters::check_opensea_stage_actionable_now(
                        plan_args,
                        config_path,
                        &opensea,
                        &slug,
                        target.wallet,
                        target.quantity,
                        safety_caps,
                    )
                    .await
                    {
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::Actionable => {
                            return Err(stage_already_live_error(target.collection));
                        }
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::NotActionable { .. } => {
                            // Not actionable for this wallet right now --
                            // never invent a fallback beyond this
                            // explicitly-requested slug (item 8: preserve
                            // operator intent). The unmodified
                            // `OpenSeaStageProbe` already falls through to
                            // `next_stage` *within this same slug* when
                            // one exists; if not, the normal pipeline
                            // surfaces the real rejection at T0, ungated
                            // by this preflight.
                        }
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::Ambiguous(e) => {
                            return Err(active_stage_eligibility_unknown_error(
                                target.wallet,
                                target.collection,
                                e,
                            ));
                        }
                    }
                }
            }
            Ok(ResolvedWatchEngine::OpenSea {
                slug,
                stage_uuid: None,
            })
        }
        EngineSelection::Auto => {
            // True-final-release-gate item 6/7: preserve the resolver's
            // own AlreadyLive-vs-WaitFor distinction (previously
            // collapsed by routing through the generic
            // `resolve_auto_engine`/`Detection` path, which has no way to
            // carry it) so a genuinely already-live stage refuses with
            // STAGE_ALREADY_LIVE for a real `--auto-send` run, rather
            // than silently minting immediately via the watch code path.
            // The one deliberate exception is `--rehearsal`: it never
            // broadcasts, so exercising an already-active stage's full
            // pipeline is safe and useful for testing -- see
            // docs/watch.md's "WATCH vs LIVE" section.
            let opensea =
                crate::cli::commands::mint::load_opensea_client(StdDuration::from_secs(10)).ok();
            let mut extra_excluded: Vec<crate::domain::stage::StageId> = Vec::new();

            for _ in 0..MAX_LIVE_CHECK_ATTEMPTS {
                let mut combined_excluded = excluded_stage_ids.to_vec();
                combined_excluded.extend(extra_excluded.iter().cloned());

                let decision =
                    crate::cli::commands::resolver_adapters::resolve_watch_stage_decision(
                        plan_args,
                        config_path,
                        opensea.as_ref(),
                        &combined_excluded,
                    )
                    .await?;

                let (stage, already_live) = match decision {
                    crate::execution::stage_resolver::WatchStageDecision::AlreadyLive(stage) => {
                        (stage, true)
                    }
                    crate::execution::stage_resolver::WatchStageDecision::WaitFor(stage) => {
                        (stage, false)
                    }
                    crate::execution::stage_resolver::WatchStageDecision::NoSupportedFutureStage {
                        reason,
                    } => {
                        return Err(KairoxError::Session(SessionError::with_kind(
                            SessionErrorKind::UnsupportedProtocol,
                            format!(
                                "no supported stage (active or future) found for this \
                                 collection: {reason}"
                            ),
                        )));
                    }
                };

                // OpenSea's `UnknownUntilActive` eligibility is not proof
                // of actionability -- see this function's doc comment.
                // Verify with a real preflight before ever declaring
                // STAGE_ALREADY_LIVE; a native public stage needs no
                // equivalent (its capacity fields are already
                // authoritative on-chain reads).
                if already_live
                    && !allow_already_live
                    && let crate::domain::stage::StageExecutionRef::OpenSea { slug } =
                        &stage.execution
                {
                    let opensea_client = opensea.as_ref().expect(
                        "an OpenSea stage was discovered above, which requires an OpenSea client",
                    );
                    match crate::cli::commands::resolver_adapters::check_opensea_stage_actionable_now(
                        plan_args,
                        config_path,
                        opensea_client,
                        slug,
                        target.wallet,
                        target.quantity,
                        safety_caps,
                    )
                    .await
                    {
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::Actionable => {}
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::NotActionable { detail } => {
                            eprintln!(
                                "watch: active stage {:?} is not actionable for this wallet \
                                 ({detail}) -- excluding it and re-resolving toward a later \
                                 supported stage, if any",
                                stage.id
                            );
                            extra_excluded.push(stage.id.clone());
                            continue;
                        }
                        crate::cli::commands::resolver_adapters::OpenSeaLiveActionability::Ambiguous(e) => {
                            return Err(active_stage_eligibility_unknown_error(
                                target.wallet,
                                target.collection,
                                e,
                            ));
                        }
                    }
                }

                let detection = crate::cli::commands::resolver_adapters::stage_to_detection(&stage);
                crate::cli::commands::mint::print_resolution_evidence(&detection);

                if already_live && !allow_already_live {
                    return Err(stage_already_live_error(target.collection));
                }

                return match detection.engine {
                    crate::execution::resolver::ResolvedEngine::Public => {
                        Ok(ResolvedWatchEngine::Public)
                    }
                    crate::execution::resolver::ResolvedEngine::OpenSea { slug, stage_uuid } => {
                        Ok(ResolvedWatchEngine::OpenSea { slug, stage_uuid })
                    }
                    crate::execution::resolver::ResolvedEngine::Generic { .. } => {
                        unreachable!(
                            "resolve_watch_stage_decision only ever discovers NormalizedStage \
                             candidates, never a Generic-engine target"
                        )
                    }
                };
            }

            Err(KairoxError::Session(SessionError::with_kind(
                SessionErrorKind::ActiveStageEligibilityUnknown,
                format!(
                    "gave up after {MAX_LIVE_CHECK_ATTEMPTS} attempts excluding active-but-\
                     not-actionable OpenSea stages for collection {:#x}; refusing to guess \
                     further",
                    target.collection
                ),
            )))
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
///
/// **What this mechanism does and does not detect** (Round 6 item 5 --
/// audited explicitly, not assumed): `ResolvedWatchEngine`'s equality
/// only compares engine type and, for OpenSea, `slug`/`stage_uuid`. A
/// changed start/end time, price, or `max_per_wallet` for the *same*
/// already-selected stage compares equal and is deliberately **not**
/// treated as a material change here -- restarting the whole attempt
/// (fresh pool, fresh benchmark) over a timing tweak to the stage already
/// being waited on would be wasteful and is unnecessary, because:
/// - Start/end time drift for the same stage is already handled by
///   `wait_for_stage`/`StageProbe` itself: `PublicStageProbe`/
///   `OpenSeaStageProbe` both re-fetch fresh state every poll and
///   `wait_for_stage` always uses that fresh `stage_start`, in either
///   direction -- see `execution::watch::tests::
///   stage_start_moving_later_while_waiting_updates_the_target` and
///   `..._moving_earlier_..._and_arms_promptly`.
/// - Price/value drift for the same stage can never produce an
///   incorrectly-signed transaction: `execution::opensea_validate`
///   (unchanged, core safety code) always validates the *real*,
///   freshly-fetched authorization response's value against a
///   freshly-fetched expectation immediately before signing, and fails
///   closed (`UnsafeValue`) on any mismatch -- see
///   `execution::opensea_validate::tests::rejects_value_disagreeing_with_expected_stage_price`.
///   Nothing here ever signs against stale, resolution-time price data.
///
/// What *is* a material change here: the winning engine/slug/stage
/// identity itself changing -- a different stage becoming the better
/// choice, including a same-slug stage UUID swap (a different stage
/// replacing the one being waited on) -- see
/// `cli::commands::watch::reresolution_change_detection_tests`.
#[allow(clippy::too_many_arguments)]
async fn wait_for_stage_with_reresolution(
    probe: &dyn StageProbe,
    poll_config: &WatchPollConfig,
    target: &WatchTarget,
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    excluded_stage_ids: &[crate::domain::stage::StageId],
    safety_caps: SafetyCaps,
    currently_selected: &ResolvedWatchEngine,
    mut on_state: impl FnMut(WatchState),
) -> Result<OffsetDateTime, KairoxError> {
    if !matches!(target.engine, EngineSelection::Auto) {
        return wait_for_stage(probe, poll_config, on_state).await;
    }

    let reresolution_check = async {
        loop {
            tokio::time::sleep(reresolution_interval()).await;
            // `allow_already_live: true` -- see `resolve_watch_engine`'s
            // doc comment on that parameter: the stage this attempt is
            // already waiting for transitioning to Active during the
            // wait is success, never grounds for a STAGE_ALREADY_LIVE
            // refusal here.
            let fresh = resolve_watch_engine(
                target,
                plan_args,
                config_path,
                excluded_stage_ids,
                safety_caps,
                true,
            )
            .await?;
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

/// Minimum spacing between optional network telemetry reads
/// (`eth_getBlockByNumber`/`eth_maxPriorityFeePerGas`), independent of
/// `--poll-interval-secs`. An aggressive poll interval must never turn
/// into network telemetry traffic on every single poll for the whole
/// (possibly very long) wait -- this is a diagnostic nicety, not
/// something that benefits from being maximally fresh every second.
const NETWORK_TELEMETRY_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

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
    /// The exact same `arm_threshold` `wait_for_stage` itself uses to
    /// decide whether *this* probe result is the one that hands off to
    /// execution (`remaining <= arm_threshold`). Telemetry network calls
    /// are skipped whenever this probe's own result would meet that same
    /// condition -- see `probe`'s doc comment for why this must mirror
    /// `wait_for_stage`'s criterion exactly, not merely approximate it.
    arm_threshold: time::Duration,
}

#[async_trait::async_trait]
impl StageProbe for TelemetryProbe<'_> {
    /// CRITICAL ORDERING INVARIANT: the moment `self.inner.probe()`'s
    /// result is the one `wait_for_stage` will use to hand off to
    /// execution (`remaining <= arm_threshold`, or the stage already
    /// `Ended`), this function returns *immediately* -- no optional
    /// network telemetry call is ever made on that result, because doing
    /// so would delay delivery of a MANDATORY stage observation behind
    /// OPTIONAL diagnostic RPC traffic. An earlier version of this code
    /// got this wrong: it always ran the telemetry reads before
    /// returning, regardless of how close to (or past) T0 the observed
    /// stage already was. See the regression test
    /// `optional_telemetry_never_delays_delivery_of_an_active_stage_result`.
    ///
    /// Telemetry is only ever attempted on a result that is *not* about
    /// to hand off -- i.e. only while genuinely far from T0, which is
    /// exactly when it is safe for it to cost a little extra latency.
    async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
        let started = std::time::Instant::now();
        let result = self.inner.probe().await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        // About to hand off (or terminate)? Computed purely from `result`
        // -- no lock involved -- so this check itself can never be
        // delayed by anything. Mirrors `wait_for_stage`'s own
        // `remaining <= arm_threshold` check exactly, so this can never
        // disagree with the real handoff decision made a moment later by
        // the caller.
        let about_to_hand_off_or_terminate = match &result {
            Ok(snapshot) => {
                matches!(snapshot.status, crate::domain::timing::StageStatus::Ended)
                    || (snapshot.stage_start - OffsetDateTime::now_utc()) <= self.arm_threshold
            }
            Err(_) => true,
        };

        // Cheap, in-memory-only latency/outcome recording. Even though
        // this never does network I/O, the mutex itself is OPTIONAL work
        // -- a MANDATORY stage observation must never wait on lock
        // contention either, so this uses `try_lock`, never `lock`: if
        // another thread happens to be holding it, the sample is simply
        // dropped rather than waited for. A poisoned lock is handled
        // identically (treated as "unavailable right now").
        if let Ok(mut store) = self.store.try_lock() {
            match &result {
                Ok(_) => store.record_probe_success(self.label, elapsed_ms),
                Err(_) => store.record_probe_failure(self.label),
            }
        }

        if about_to_hand_off_or_terminate {
            return result;
        }

        // A best-effort, read-only network observation -- entirely
        // separate from `self.inner.probe()`'s own outcome above, and
        // never allowed to affect it: a failure here is silently
        // dropped, never propagated. See `NetworkTelemetry`'s doc
        // comment for why this reuses an already-connected client, never
        // opens a new one. Round 6 item 9: gated to at most once every
        // `NETWORK_TELEMETRY_MIN_INTERVAL`, independent of
        // `--poll-interval-secs` -- an aggressive poll interval (e.g. 1s)
        // must never turn into optional network RPC traffic every single
        // second for the whole (possibly very long) wait. This check is a
        // fast, in-memory `try_lock` only; it never itself performs I/O
        // and never waits on contention (a busy lock here simply means
        // "skip telemetry this cycle", never "wait").
        let due_for_telemetry = match self.store.try_lock() {
            Ok(store) => !matches!(
                store.network.latest_block_number(),
                crate::chain::telemetry::Freshness::Fresh { age, .. }
                    if age < NETWORK_TELEMETRY_MIN_INTERVAL
            ),
            Err(_) => false,
        };
        if !due_for_telemetry {
            return result;
        }

        if let Some(client) = self.network_source {
            if let Ok(mut store) = self.store.try_lock() {
                store.record_endpoint_identity(
                    client.label().unwrap_or("(unlabeled send-pool endpoint)"),
                    client.role(),
                );
            }
            if let Ok(block) = client.latest_block().await {
                let priority_fee = client.max_priority_fee_per_gas().await.ok();
                if let Some(base_fee) = block.base_fee_per_gas
                    && let Ok(mut store) = self.store.try_lock()
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
    rehearsal: bool,
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
        arm_threshold: poll_config.arm_threshold,
    };
    // Round 6 (final hardening pass) item 1: every progress event from
    // here through dispatch is emitted through a non-blocking reporter
    // (`ProgressReporter::emit` is a `try_send`, never awaited, never
    // blocking) -- a stalled stderr consumer can no longer delay a
    // MANDATORY stage observation or any step of the dispatch-critical
    // path. The dedicated consumer task owns all the actual `eprintln!`
    // work, running independently.
    let reporter = crate::cli::progress_reporter::ProgressReporter::spawn(|state: WatchState| {
        print_state(&state)
    });
    let stage_start = wait_for_stage_with_reresolution(
        &probe,
        poll_config,
        &target,
        &plan_args,
        config_path,
        excluded_stage_ids,
        safety_caps,
        &currently_selected,
        |state| reporter.emit(state),
    )
    .await?;
    // NOTE: no telemetry/reporting output here -- this is the boundary
    // between "stage detected as open" and dispatch preparation. Nothing
    // optional runs between here and the broadcast; the telemetry
    // summary is printed only after the whole send/receipt sequence
    // completes, below.
    reporter.emit(WatchState::Arming);

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
    // See `execution::live::LiveMintConfig::rehearsal`'s doc comment --
    // everything up to and including local signing/serialization runs
    // exactly as it would for a real send; only the final
    // `eth_sendRawTransaction` dispatch is skipped.
    config.rehearsal = rehearsal;

    let outcome = run_live_mint(&mut pool, signer, &request, &config, |progress| {
        reporter.emit(live_progress_to_watch_state(&progress))
    })
    .await?;

    reporter.emit(WatchState::Success);
    // Only now, after dispatch/receipt, is it safe to block briefly:
    // flush the reporter (bounded, never more than
    // `progress_reporter::FINISH_TIMEOUT`) so the summary lines above
    // aren't lost, then print the telemetry summary directly -- never
    // between stage-open detection and broadcast. See the module's
    // regression test proving this ordering.
    reporter.finish().await;
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
        rehearsal,
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
    rehearsal: bool,
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
        arm_threshold: poll_config.arm_threshold,
    };
    // Per the OpenSea engine's own design, only stage timing/supply is
    // knowable ahead of T0 -- wallet-specific eligibility/proof/
    // authorization is only ever obtained from the real mint-request call
    // `run_opensea_mint` makes below, never fabricated here.
    //
    // Same non-blocking reporter design as `run_public_watch` -- see its
    // identical comment.
    let reporter = crate::cli::progress_reporter::ProgressReporter::spawn(|state: WatchState| {
        print_state(&state)
    });
    wait_for_stage_with_reresolution(
        &probe,
        poll_config,
        &target,
        &plan_args,
        config_path,
        excluded_stage_ids,
        safety_caps,
        &currently_selected,
        |state| reporter.emit(state),
    )
    .await?;
    // No telemetry/reporting output here -- see run_public_watch's
    // identical comment; printed only after dispatch/receipt, below.
    reporter.emit(WatchState::Arming);

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
        rehearsal,
    };

    let outcome = run_opensea_mint(&opensea, &mut pool, signer, &request, |progress| {
        reporter.emit(opensea_progress_to_watch_state(&progress))
    })
    .await?;

    reporter.emit(WatchState::Success);
    reporter.finish().await;
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
        rehearsal,
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

#[cfg(test)]
mod reresolution_change_detection_tests {
    use super::*;

    /// Round 6 item 10.C: `wait_for_stage_with_reresolution` detects a
    /// "material change" purely via `ResolvedWatchEngine`'s `PartialEq` --
    /// this pins the exact equality semantics that mechanism depends on,
    /// independent of the slower e2e re-resolution scenario covering
    /// item 10.A.
    #[test]
    fn a_changed_opensea_stage_uuid_for_the_same_slug_is_a_material_change() {
        let original = ResolvedWatchEngine::OpenSea {
            slug: "same-collection".to_string(),
            stage_uuid: Some("uuid-original".to_string()),
        };
        let replaced = ResolvedWatchEngine::OpenSea {
            slug: "same-collection".to_string(),
            stage_uuid: Some("uuid-replaced".to_string()),
        };
        assert_ne!(
            original, replaced,
            "a different stage UUID for the same collection slug must be detected as a \
             material change, even though the slug itself did not change"
        );
    }

    #[test]
    fn an_unchanged_resolution_is_not_a_material_change() {
        let a = ResolvedWatchEngine::OpenSea {
            slug: "same-collection".to_string(),
            stage_uuid: Some("uuid-stable".to_string()),
        };
        let b = ResolvedWatchEngine::OpenSea {
            slug: "same-collection".to_string(),
            stage_uuid: Some("uuid-stable".to_string()),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn public_and_opensea_are_always_a_material_change_from_each_other() {
        assert_ne!(
            ResolvedWatchEngine::Public,
            ResolvedWatchEngine::OpenSea {
                slug: "whatever".to_string(),
                stage_uuid: None,
            }
        );
    }
}

#[cfg(test)]
mod telemetry_probe_critical_path_tests {
    //! Regression coverage for the bug fixed in this pass:
    //! `TelemetryProbe::probe` used to always run its optional network
    //! telemetry reads before returning, even when the inner probe's
    //! result was the exact one `wait_for_stage` was about to use to hand
    //! off to execution -- meaning a slow/hung telemetry RPC call could
    //! delay delivery of a MANDATORY "stage active" observation. Fixed by
    //! skipping telemetry entirely whenever this probe's own result meets
    //! `wait_for_stage`'s own `remaining <= arm_threshold` handoff
    //! criterion (or the stage has `Ended`).

    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::rpc::RpcClient;
    use crate::domain::timing::StageStatus;
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;

    /// Always reports the stage as already active (`stage_start` in the
    /// past) -- exactly the result that must hand off to execution
    /// without delay.
    struct FakeAboutToHandOffProbe;

    #[async_trait::async_trait]
    impl StageProbe for FakeAboutToHandOffProbe {
        async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
            Ok(StageSnapshot {
                stage_start: OffsetDateTime::now_utc() - Duration::seconds(5),
                status: StageStatus::Active {
                    ends_in: Duration::seconds(3600),
                },
            })
        }
    }

    /// Reports a stage that starts comfortably far in the future -- a
    /// result `wait_for_stage` will keep polling on, never hand off from.
    struct FakeFarFromT0Probe;

    #[async_trait::async_trait]
    impl StageProbe for FakeFarFromT0Probe {
        async fn probe(&self) -> Result<StageSnapshot, KairoxError> {
            Ok(StageSnapshot {
                stage_start: OffsetDateTime::now_utc() + Duration::minutes(30),
                status: StageStatus::NotStarted {
                    starts_in: Duration::minutes(30),
                },
            })
        }
    }

    async fn slow_network_client(delay: StdDuration) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", serde_json::json!("0x1"))
            .respond(
                "eth_getBlockByNumber",
                serde_json::json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x1"}),
            )
            .delay("eth_getBlockByNumber", delay)
            .respond("eth_maxPriorityFeePerGas", serde_json::json!("0x1"))
            .build();
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap()
    }

    async fn erroring_network_client() -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", serde_json::json!("0x1"))
            .error("eth_getBlockByNumber", -32000, "boom")
            .build();
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap()
    }

    /// THE regression test for the bug this pass fixes: a 500ms-delayed
    /// optional telemetry call must never delay delivery of an
    /// already-active stage result.
    #[tokio::test]
    async fn optional_telemetry_never_delays_delivery_of_an_active_stage_result() {
        let inner = FakeAboutToHandOffProbe;
        let client = slow_network_client(StdDuration::from_millis(500)).await;
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: Some(&client),
            arm_threshold: Duration::seconds(10),
        };

        let started = std::time::Instant::now();
        let result = probe.probe().await.unwrap();
        let elapsed = started.elapsed();

        assert!(matches!(result.status, StageStatus::Active { .. }));
        assert!(
            elapsed < StdDuration::from_millis(200),
            "an about-to-hand-off probe result must never be delayed by a 500ms-delayed \
             optional telemetry call, took {elapsed:?}"
        );
        // Telemetry was correctly never even attempted for this cycle.
        assert!(
            store
                .lock()
                .unwrap()
                .network
                .latest_block_number()
                .displayable_value()
                .is_none()
        );
    }

    /// Same scenario with an even longer ("hung") telemetry delay --
    /// still must not delay handoff at all, proving this isn't merely a
    /// race that happens to finish under the 200ms threshold above.
    #[tokio::test]
    async fn a_hung_optional_telemetry_call_never_delays_an_active_stage_result() {
        let inner = FakeAboutToHandOffProbe;
        let client = slow_network_client(StdDuration::from_secs(5)).await;
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: Some(&client),
            arm_threshold: Duration::seconds(10),
        };

        let started = std::time::Instant::now();
        let result = tokio::time::timeout(StdDuration::from_millis(200), probe.probe())
            .await
            .expect("probe() must return well within 200ms even with a 5s-hung telemetry call")
            .unwrap();
        let elapsed = started.elapsed();

        assert!(matches!(result.status, StageStatus::Active { .. }));
        assert!(elapsed < StdDuration::from_millis(200));
    }

    /// A failing optional telemetry read (far from T0, where telemetry
    /// does run) must never alter or fail the real probe result.
    #[tokio::test]
    async fn a_failing_optional_telemetry_call_never_alters_the_stage_result() {
        let inner = FakeFarFromT0Probe;
        let client = erroring_network_client().await;
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: Some(&client),
            arm_threshold: Duration::seconds(10),
        };

        let result = probe.probe().await.unwrap();
        assert!(matches!(result.status, StageStatus::NotStarted { .. }));
        assert!(
            store
                .lock()
                .unwrap()
                .network
                .latest_block_number()
                .displayable_value()
                .is_none(),
            "a failed telemetry read must never fabricate an observation"
        );
    }

    /// A poisoned telemetry mutex (far from T0) must never alter, fail,
    /// or panic the real probe result.
    #[tokio::test]
    async fn a_poisoned_telemetry_lock_never_alters_the_stage_result() {
        let inner = FakeFarFromT0Probe;
        let client = slow_network_client(StdDuration::ZERO).await;
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        // Poison the mutex the same way a panicking holder would.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.lock().unwrap();
            panic!("simulated panic while holding the telemetry lock");
        }));
        assert!(store.is_poisoned());

        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: Some(&client),
            arm_threshold: Duration::seconds(10),
        };

        let result = probe.probe().await.unwrap();
        assert!(matches!(result.status, StageStatus::NotStarted { .. }));
    }

    /// Round 6 item 9: an aggressive poll interval must not turn into
    /// optional network telemetry traffic on every single poll. Two
    /// far-from-T0 probe cycles in quick succession (well under
    /// `NETWORK_TELEMETRY_MIN_INTERVAL`) must issue the underlying
    /// `eth_getBlockByNumber` telemetry read only once, not twice.
    #[tokio::test]
    async fn network_telemetry_is_not_reissued_faster_than_the_minimum_cadence() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let inner = FakeFarFromT0Probe;
        let call_count = std::sync::Arc::new(AtomicU32::new(0));
        let call_count_for_closure = call_count.clone();
        let transport = MockTransport::builder()
            .respond("eth_chainId", serde_json::json!("0x1"))
            .respond_dynamic("eth_getBlockByNumber", move |_params| {
                call_count_for_closure.fetch_add(1, Ordering::SeqCst);
                serde_json::json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x1"})
            })
            .respond("eth_maxPriorityFeePerGas", serde_json::json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: Some(&client),
            arm_threshold: Duration::seconds(10),
        };

        probe.probe().await.unwrap();
        probe.probe().await.unwrap();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "a second probe cycle immediately after the first must not re-issue the network \
             telemetry read before NETWORK_TELEMETRY_MIN_INTERVAL has elapsed"
        );
    }

    /// Final hardening pass item 2: a telemetry mutex held by another
    /// thread for 500ms must never delay delivery of an active-stage
    /// handoff -- `try_lock` skips the sample rather than waiting.
    #[tokio::test]
    async fn a_contended_telemetry_lock_never_delays_an_active_stage_result() {
        let inner = FakeAboutToHandOffProbe;
        let store = std::sync::Arc::new(Mutex::new(
            crate::chain::telemetry::TelemetryStore::default(),
        ));
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: None,
            arm_threshold: Duration::seconds(10),
        };

        // Hold the lock from another (blocking, non-tokio) thread for
        // 500ms while the async probe runs concurrently on this test's
        // own tokio task.
        let held = std::sync::Arc::new(std::sync::Barrier::new(2));
        let store_for_thread = store.clone();
        let held_for_thread = held.clone();
        let holder = std::thread::spawn(move || {
            let _guard = store_for_thread.lock().unwrap();
            held_for_thread.wait();
            std::thread::sleep(StdDuration::from_millis(500));
        });
        held.wait();

        let started = std::time::Instant::now();
        let result = probe.probe().await.unwrap();
        let elapsed = started.elapsed();

        assert!(matches!(result.status, StageStatus::Active { .. }));
        assert!(
            elapsed < StdDuration::from_millis(200),
            "a contended telemetry lock must never delay an active-stage handoff, took {elapsed:?}"
        );
        holder.join().unwrap();
    }

    /// Final hardening pass item 2: a poisoned telemetry lock must also
    /// never delay delivery of an active-stage handoff (complements the
    /// existing `a_poisoned_telemetry_lock_never_alters_the_stage_result`,
    /// which proves correctness far from T0; this proves latency exactly
    /// at the handoff boundary).
    #[tokio::test]
    async fn a_poisoned_telemetry_lock_never_delays_an_active_stage_result() {
        let inner = FakeAboutToHandOffProbe;
        let store = Mutex::new(crate::chain::telemetry::TelemetryStore::default());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.lock().unwrap();
            panic!("simulated panic while holding the telemetry lock");
        }));
        assert!(store.is_poisoned());

        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: None,
            arm_threshold: Duration::seconds(10),
        };

        let started = std::time::Instant::now();
        let result = probe.probe().await.unwrap();
        let elapsed = started.elapsed();

        assert!(matches!(result.status, StageStatus::Active { .. }));
        assert!(elapsed < StdDuration::from_millis(100));
    }

    /// Final hardening pass item 2: far from T0, a busy telemetry lock
    /// causes the sample to be silently dropped -- stage semantics
    /// (the returned snapshot) are unaffected either way.
    #[tokio::test]
    async fn a_busy_telemetry_lock_far_from_t0_drops_the_sample_without_affecting_stage_semantics()
    {
        let inner = FakeFarFromT0Probe;
        let store = std::sync::Arc::new(Mutex::new(
            crate::chain::telemetry::TelemetryStore::default(),
        ));
        let probe = TelemetryProbe {
            inner: &inner,
            label: "test",
            store: &store,
            network_source: None,
            arm_threshold: Duration::seconds(10),
        };

        let held = std::sync::Arc::new(std::sync::Barrier::new(2));
        let store_for_thread = store.clone();
        let held_for_thread = held.clone();
        let holder = std::thread::spawn(move || {
            let _guard = store_for_thread.lock().unwrap();
            held_for_thread.wait();
            std::thread::sleep(StdDuration::from_millis(300));
        });
        held.wait();

        // Stage semantics are correct regardless of the lock contention
        // above -- this is the only load-bearing assertion here; whether
        // the probe/failure sample itself was recorded or silently
        // dropped under contention is unobserved and irrelevant.
        let result = probe.probe().await.unwrap();
        assert!(matches!(result.status, StageStatus::NotStarted { .. }));
        holder.join().unwrap();
    }
}
