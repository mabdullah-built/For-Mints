//! Concrete [`MintAdapter`] implementations for the engines Kairox
//! actually has. Both `mint --engine auto` and `watch --engine auto`
//! build an [`AdapterRegistry`] from these and call
//! [`AdapterRegistry::resolve`] instead of duplicating engine-selection
//! logic -- see `src/execution/resolver.rs` for the resolution
//! hierarchy/ambiguity rules these adapters plug into.
//!
//! [`NormalizedStageAdapter`] (priority 0) is the real decision point for
//! "native SeaDrop vs OpenSea": it discovers every candidate stage from
//! both sources as [`crate::domain::stage::NormalizedStage`] entries and
//! hands the *whole set* to
//! [`crate::execution::stage_resolver::select_for_live_mint`]/
//! [`select_for_watch`] -- the same selection algorithm proven against
//! synthetic fixtures -- rather than an ad-hoc "try OpenSea, then try
//! SeaDrop" priority chain. This is what makes an active, eligible,
//! OpenSea-hosted signed presale outrank a later on-chain public stage:
//! not adapter registration order, but the selection algorithm's own
//! non-public-beats-public ranking rule, applied to real discovered data.
//!
//! [`GenericVerifiedContractAdapter`] (priority 1) covers a schema the
//! operator explicitly declared (never guessed) and that on-chain ERC-165
//! corroborates, or a verified-source/trusted-registry match -- a
//! fundamentally different (bytecode/ABI-based, not stage-timing-based)
//! kind of resolution that does not fit the stage model, so it stays a
//! separate, subsequent tier: only tried once
//! [`NormalizedStageAdapter`] found no stage at all.

use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::args::PlanArgs;
use crate::cli::context::{connect_read_client, resolve_chain_and_runtime};
use crate::domain::stage::{
    EligibilityState, NormalizedStage, StageExecutionRef, StageId, StageProtocol,
};
use crate::domain::timing::PhaseWindow;
use crate::execution::errors::KairoxError;
use crate::execution::generic_schema::GenericMintSchema;
use crate::execution::resolver::{
    Confidence, Detection, MintAdapter, ProtocolEvidence, ResolvedEngine,
};
use crate::execution::stage_resolver::{
    LiveStageDecision, WatchStageDecision, select_for_live_mint, select_for_watch,
};

use super::plan::build_mint_plan;

/// Discovers the collection's native on-chain SeaDrop `PublicDrop` stage,
/// if any, as a [`NormalizedStage`]. `Ok(None)` (not an error) when the
/// contract genuinely isn't a SeaDrop collection.
pub(crate) async fn discover_public_stage(
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
) -> Result<Option<NormalizedStage>, KairoxError> {
    let plan = match build_mint_plan(plan_args, config_path).await {
        Ok(plan) => plan,
        // Only a genuine on-chain call/decode failure (a revert response
        // or a return shape that doesn't decode as PublicDrop) is the
        // expected signal that this contract isn't a SeaDrop collection
        // -- treated as "no stage", not propagated, so an unrelated
        // ERC-721 doesn't abort resolution outright. Anything else (no
        // RPC configured, a bad config file, wrong chain, transport
        // timeout/network failure) is a real infrastructure problem that
        // has nothing to do with which protocol the contract implements,
        // and must surface as itself rather than being misreported as
        // UNSUPPORTED_PROTOCOL.
        Err(
            KairoxError::Rpc(
                crate::chain::rpc::RpcError::RpcReturnedError { .. }
                | crate::chain::rpc::RpcError::MalformedResponse(_),
            )
            | KairoxError::SeaDrop(_),
        ) => return Ok(None),
        Err(e) => return Err(e),
    };

    let price_per_token = if plan.quantity > 0 {
        plan.mint_value / alloy_primitives::U256::from(plan.quantity)
    } else {
        plan.mint_value
    };

    Ok(Some(NormalizedStage {
        id: StageId::OnChainPublic,
        execution: StageExecutionRef::PublicSeaDrop,
        protocol: StageProtocol::Public,
        label: None,
        window: PhaseWindow {
            start: plan.stage_start,
            end: Some(plan.stage_end),
        },
        price_per_token_wei: Some(price_per_token),
        // MintPlan already reports *remaining* allocation/supply rather
        // than a max/used split -- represented here as "all remaining
        // capacity, none used yet", which produces the exact same
        // `remaining_wallet_allocation()`/`has_known_capacity()` results
        // NormalizedStage's own max/used fields would.
        max_per_wallet: Some(plan.wallet_allocation_remaining),
        wallet_minted: Some(0),
        supply_remaining: Some(plan.collection_supply_remaining),
        eligibility: EligibilityState::Eligible,
        evidence: format!(
            "on-chain SeaDrop PublicDrop config read from {}",
            plan_args.collection
        ),
    }))
}

/// Price provenance is not established for a raw OpenSea `stage.price`
/// string: the Drops API schema documents it only as "mint cost per
/// token" with no independently-confirmed unit (wei vs a decimal
/// display value vs the payment token's own smallest unit). Guessing
/// "wei" and using it for spend authorization would be exactly the kind
/// of unit-guessing this trust model forbids -- see
/// `crate::execution::opensea_validate`, which is the one place a
/// signed mint's actual `value` is ever authoritatively established
/// (from the official mint-builder response's own locally-validated
/// `value` field, never from a `stages[]` display string). This
/// deliberately returns `None` -- opaque/unavailable -- rather than a
/// parsed number, so a caller can never mistake it for spend-grade
/// evidence.
fn opensea_display_price_provenance_unavailable(
    _price: &Option<String>,
) -> Option<alloy_primitives::U256> {
    None
}

/// Discovers every OpenSea-hosted non-public stage worth considering (the
/// currently-active one, and -- when `allow_not_yet_started` -- the
/// upcoming one) as [`NormalizedStage`] entries. A plain public OpenSea
/// stage is never included here: the cheaper, dependency-free native
/// route covers that case when one exists, and
/// [`crate::opensea::models::map_stage_type`] never even maps a
/// `"public"`-shaped wire value (see its doc comment).
///
/// A genuinely transient discovery failure (transport/5xx/rate-limit) is
/// distinct from a genuine "no drop for this collection" (404) result:
/// `watch` (`allow_not_yet_started`) retries transient failures a
/// bounded number of times with a short delay before giving up, so a
/// brief OpenSea blip during a long wait never silently and permanently
/// locks the session onto a later native public stage for its entire
/// duration. `mint` (immediate, no time budget to retry) makes exactly
/// one attempt, matching its existing best-effort philosophy. Either
/// way, exhausting attempts still degrades to "no OpenSea stages found"
/// rather than a hard error -- a collection with a working native public
/// stage must never be blocked by OpenSea's availability -- but a
/// diagnostic is printed so an operator can tell "OpenSea genuinely has
/// no drop here" apart from "OpenSea was unreachable" (previously
/// indistinguishable).
async fn discover_opensea_stages(
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    opensea: Option<&crate::opensea::client::OpenSeaClient>,
    allow_not_yet_started: bool,
) -> Result<Vec<NormalizedStage>, KairoxError> {
    let Some(opensea) = opensea else {
        return Ok(Vec::new());
    };
    let registry = crate::chain::registry::ChainRegistry::builtin();
    let (resolved, _runtime) =
        resolve_chain_and_runtime(&registry, &plan_args.chain_args, config_path)?;
    let Some(chain_identifier) =
        crate::opensea::models::opensea_chain_identifier(resolved.info.chain_id)
    else {
        return Ok(Vec::new());
    };

    // Round 6 (final hardening pass) item 5: classified through the
    // typed `OpenSeaDiscoveryOutcome` rather than an ad-hoc
    // `Ok(Some)`/`Ok(None)`/`Err` match -- structurally distinguishes
    // "no drop" from every degraded (auth/rate-limit/transient) outcome,
    // so nothing downstream can conflate "couldn't check" with "checked,
    // nothing there".
    use crate::opensea::discovery::OpenSeaDiscoveryOutcome;
    let max_attempts: u32 = if allow_not_yet_started { 3 } else { 1 };
    let mut details = None;
    let mut last_degraded_outcome = None;
    for attempt in 0..max_attempts {
        let outcome = OpenSeaDiscoveryOutcome::classify(
            crate::opensea::discovery::resolve_drop(
                opensea,
                chain_identifier,
                plan_args.collection,
            )
            .await,
        );
        match outcome {
            OpenSeaDiscoveryOutcome::Available(d) => {
                details = Some(d);
                break;
            }
            // A genuine 404 (or an unmatched candidate) is authoritative,
            // not transient -- retrying it would never change the answer.
            OpenSeaDiscoveryOutcome::NoDrop => break,
            degraded => {
                debug_assert!(degraded.is_degraded());
                last_degraded_outcome = Some(degraded);
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
    }
    let Some(details) = details else {
        if let Some(outcome) = last_degraded_outcome {
            let reason = match outcome {
                OpenSeaDiscoveryOutcome::AuthenticationFailed => {
                    "OPENSEA_DISCOVERY_UNAVAILABLE (authentication failed)".to_string()
                }
                OpenSeaDiscoveryOutcome::RateLimited => {
                    "OPENSEA_DISCOVERY_UNAVAILABLE (rate limited)".to_string()
                }
                OpenSeaDiscoveryOutcome::TransientFailure(e) => {
                    format!("OPENSEA_DISCOVERY_UNAVAILABLE (transient failure: {e})")
                }
                OpenSeaDiscoveryOutcome::Available(_) | OpenSeaDiscoveryOutcome::NoDrop => {
                    unreachable!("only degraded outcomes are ever stored here")
                }
            };
            eprintln!(
                "OpenSea auto-discovery unavailable after {max_attempts} attempt(s): {reason}; \
                 proceeding as if no OpenSea drop was found for this collection -- this is NOT \
                 proof no signed stage exists, only that it could not be checked"
            );
        }
        return Ok(Vec::new());
    };

    let mut candidates = vec![details.active_stage.as_ref()];
    if allow_not_yet_started {
        candidates.push(details.next_stage.as_ref());
    }

    Ok(candidates
        .into_iter()
        .flatten()
        .filter_map(|stage| {
            let protocol = crate::opensea::models::map_stage_type(&stage.stage_type)?;
            let start = OffsetDateTime::parse(&stage.start_time, &Rfc3339).ok()?;
            let end = OffsetDateTime::parse(&stage.end_time, &Rfc3339).ok()?;
            Some(NormalizedStage {
                id: StageId::OpenSea {
                    stage_uuid: stage.uuid.clone(),
                },
                execution: StageExecutionRef::OpenSea {
                    slug: details.collection_slug.clone(),
                },
                protocol,
                label: stage.label.clone(),
                window: PhaseWindow {
                    start,
                    end: Some(end),
                },
                // See opensea_display_price_provenance_unavailable's doc
                // comment -- never spend-authorization-grade.
                price_per_token_wei: opensea_display_price_provenance_unavailable(&stage.price),
                max_per_wallet: stage.max_per_wallet.parse::<u64>().ok(),
                // Genuinely unknown until a real, fresh, wallet-specific
                // OpenSea authorization is requested -- never assumed
                // zero/unused. See EligibilityState::UnknownUntilActive
                // below.
                wallet_minted: None,
                supply_remaining: None,
                eligibility: EligibilityState::UnknownUntilActive,
                evidence: format!(
                    "auto-discovered OpenSea drop {:?} stage {:?} (uuid {:?}, recognized as {protocol:?})",
                    details.collection_slug, stage.stage_type, stage.uuid
                ),
            })
        })
        .collect())
}

/// The outcome of checking whether a temporally-`Active`, otherwise
/// supported OpenSea signed/allowlist/FCFS/FCFA stage is genuinely
/// actionable for one specific wallet/quantity *right now* -- i.e.
/// whether `watch` may honestly refuse with `STAGE_ALREADY_LIVE` for it.
///
/// True-final-release-gate semantic correction: `WatchStageDecision::AlreadyLive`
/// alone only proves a stage is temporally active and not already known
/// to be `Ineligible`/`Unsupported`/exhausted -- `is_candidate` (which
/// `select_for_watch` uses) deliberately treats
/// `EligibilityState::UnknownUntilActive` as a selection candidate, which
/// is correct for *choosing which stage to look at* but is never proof
/// any specific wallet can actually execute it. This is that missing
/// proof step for OpenSea stages (a native SeaDrop public stage needs no
/// equivalent: its `NormalizedStage` capacity fields already come from a
/// real, authoritative on-chain read -- see `discover_public_stage`).
pub(crate) enum OpenSeaLiveActionability {
    /// The official mint-builder response was requested and passed every
    /// check [`crate::execution::opensea_validate::validate_opensea_mint_response`]
    /// performs (chain, target, wallet, quantity, value cap, signer) --
    /// this wallet genuinely can execute this stage right now.
    Actionable,
    /// A clear, unambiguous negative outcome (wallet ineligible,
    /// allocation exhausted, supply exhausted) -- this specific active
    /// stage is not actionable for this wallet, but that is not itself
    /// grounds to give up on the collection: a later supported stage may
    /// still be legitimately watchable.
    NotActionable { detail: String },
    /// A transient or unclassifiable outcome (timeout, rate limit,
    /// server error, or a response that failed local validation) --
    /// Kairox could not establish actionability in either direction and
    /// refuses to guess.
    Ambiguous(KairoxError),
}

/// Performs the actionability check described on [`OpenSeaLiveActionability`].
/// Reuses the exact same request path and error classification the real
/// execution engine uses (`request_mint_with_bounded_retry`,
/// `validate_opensea_mint_response`) -- never a second, ad-hoc parser --
/// so one OpenSea response is guaranteed to mean the same thing here as
/// it would at real T0 dispatch. Stops immediately after local
/// validation: never signs, never simulates (`eth_estimateGas`), never
/// broadcasts, never polls a receipt -- only what is required to prove
/// (or disprove) actionability.
pub(crate) async fn check_opensea_stage_actionable_now(
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    opensea: &crate::opensea::client::OpenSeaClient,
    slug: &str,
    wallet: alloy_primitives::Address,
    quantity: u64,
    safety_caps: crate::domain::fees::SafetyCaps,
) -> OpenSeaLiveActionability {
    let registry = crate::chain::registry::ChainRegistry::builtin();
    let (resolved, runtime) =
        match resolve_chain_and_runtime(&registry, &plan_args.chain_args, config_path) {
            Ok(r) => r,
            Err(e) => return OpenSeaLiveActionability::Ambiguous(e),
        };
    let read_client = match connect_read_client(
        &resolved.info,
        plan_args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return OpenSeaLiveActionability::Ambiguous(e),
    };
    let quantity_u32 = match u32::try_from(quantity) {
        Ok(q) => q,
        Err(_) => {
            return OpenSeaLiveActionability::Ambiguous(KairoxError::Session(
                crate::execution::errors::SessionError::new(format!(
                    "quantity {quantity} does not fit the OpenSea mint API's u32 range"
                )),
            ));
        }
    };

    use crate::opensea::errors::OpenSeaError;
    let mint_response = match crate::execution::opensea_engine::request_mint_with_bounded_retry(
        opensea,
        slug,
        wallet,
        quantity_u32,
    )
    .await
    {
        Ok((response, _retry_count)) => response,
        Err(
            e @ (OpenSeaError::EligibilityRejected { .. }
            | OpenSeaError::AllocationExceeded { .. }
            | OpenSeaError::SupplyExhausted { .. }),
        ) => {
            return OpenSeaLiveActionability::NotActionable {
                detail: e.to_string(),
            };
        }
        Err(e) => return OpenSeaLiveActionability::Ambiguous(KairoxError::OpenSea(e)),
    };

    let input = crate::execution::opensea_validate::OpenSeaValidationInput {
        chain_id: resolved.info.chain_id,
        expected_seadrop_contract: resolved.seadrop_contract,
        expected_collection: plan_args.collection,
        expected_wallet: wallet,
        expected_quantity: quantity,
        safety_caps,
        // Never spend-authorization-grade for OpenSea's own display price
        // -- see `opensea_display_price_provenance_unavailable`. Omitting
        // it only skips the optional cross-check; every other field
        // (target/chain/wallet/quantity/value-cap/signer) is still fully
        // validated.
        expected_price_per_token: None,
    };
    match crate::execution::opensea_validate::validate_opensea_mint_response(
        &mint_response,
        &input,
        &read_client,
    )
    .await
    {
        Ok(_validated) => OpenSeaLiveActionability::Actionable,
        Err(e) => OpenSeaLiveActionability::Ambiguous(e),
    }
}

pub(crate) fn stage_to_detection(stage: &NormalizedStage) -> Detection {
    let (engine, adapter) = match &stage.execution {
        StageExecutionRef::PublicSeaDrop => (ResolvedEngine::Public, "SeaDropAdapter"),
        StageExecutionRef::OpenSea { slug } => {
            let stage_uuid = match &stage.id {
                StageId::OpenSea { stage_uuid } => Some(stage_uuid.clone()),
                StageId::OnChainPublic
                | StageId::ThirdwebMultiPhase { .. }
                | StageId::ThirdwebSinglePhase { .. }
                | StageId::ManifoldClaim { .. } => None,
            };
            (
                ResolvedEngine::OpenSea {
                    slug: slug.clone(),
                    stage_uuid,
                },
                "OpenSeaDropsAdapter",
            )
        }
        // stage_to_detection is only ever called on stages
        // NormalizedStageAdapter discovers (SeaDrop/OpenSea) -- see this
        // function's callers. Thirdweb/Manifold stages come from
        // discover_thirdweb_stages/discover_manifold_stages instead,
        // consumed directly by watch's own resolution, never through
        // this conversion. These arms exist only for match
        // exhaustiveness.
        StageExecutionRef::Thirdweb { drop_contract } => (
            ResolvedEngine::Thirdweb {
                drop_contract: *drop_contract,
            },
            "ThirdwebStageAdapter",
        ),
        StageExecutionRef::Manifold {
            extension_contract,
            creator_contract,
            instance_id,
        } => (
            ResolvedEngine::Manifold {
                extension_contract: *extension_contract,
                creator_contract: *creator_contract,
                instance_id: *instance_id,
            },
            "ManifoldStageAdapter",
        ),
    };
    Detection {
        engine,
        evidence: ProtocolEvidence {
            source: stage.evidence.clone(),
            confidence: Confidence::High,
            adapter,
            matched_interfaces: vec![],
            matched_selectors: vec![],
        },
    }
}

/// The real decision point for "native SeaDrop vs OpenSea": discovers
/// every candidate stage from both sources, then delegates the actual
/// choice to [`select_for_live_mint`]/[`select_for_watch`] -- see this
/// module's doc comment. Priority 0.
pub struct NormalizedStageAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub slug: Option<&'a str>,
    pub opensea: Option<&'a crate::opensea::client::OpenSeaClient>,
    /// `mint --send` wants an already-active stage (an operator running
    /// it right now expects to broadcast immediately); `watch` also
    /// considers a not-yet-started stage (that's exactly what it waits
    /// through) -- see [`select_for_live_mint`] vs [`select_for_watch`].
    pub allow_not_yet_started: bool,
    /// Stage identities (see [`StageId`]) to exclude from selection
    /// entirely, as if never discovered. Set by `watch`'s re-resolution
    /// loop after a fresh, semantically clear OpenSea eligibility
    /// rejection at T0 for that exact stage -- so the same
    /// known-ineligible stage is never selected again, and a later
    /// legitimately-supported stage (e.g. an on-chain public stage, or a
    /// second distinct OpenSea stage) gets a real chance. A bounded list
    /// (not just the single most-recent exclusion), since a watch
    /// session can legitimately reject more than one stage in sequence
    /// before finding a workable one. Empty (the normal case, and always
    /// the case for `mint`) excludes nothing.
    pub excluded_stage_ids: &'a [StageId],
}

#[async_trait::async_trait]
impl MintAdapter for NormalizedStageAdapter<'_> {
    fn name(&self) -> &'static str {
        "NormalizedStageAdapter"
    }

    fn priority(&self) -> u8 {
        0
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        // An operator-provided --slug is still taken at face value
        // outright, exactly as before -- an operator-confirmed fact, not
        // a guess, and not something auto-discovery needs to (or should)
        // re-derive.
        if let Some(slug) = self.slug {
            return Ok(Some(Detection {
                engine: ResolvedEngine::OpenSea {
                    slug: slug.to_string(),
                    // An operator-provided slug identifies the drop, not
                    // one exact stage within it -- there is no stage
                    // identity here to carry.
                    stage_uuid: None,
                },
                evidence: ProtocolEvidence {
                    source: format!("operator-provided OpenSea collection slug {slug:?}"),
                    confidence: Confidence::High,
                    adapter: "OpenSeaDropsAdapter",
                    matched_interfaces: vec![],
                    matched_selectors: vec![],
                },
            }));
        }

        let mut stages = Vec::new();
        stages.extend(discover_public_stage(self.plan_args, self.config_path).await?);
        stages.extend(
            discover_opensea_stages(
                self.plan_args,
                self.config_path,
                self.opensea,
                self.allow_not_yet_started,
            )
            .await?,
        );
        stages.retain(|s| !self.excluded_stage_ids.contains(&s.id));

        let now = OffsetDateTime::now_utc();
        let winner = if self.allow_not_yet_started {
            match select_for_watch(&stages, now) {
                WatchStageDecision::AlreadyLive(stage) | WatchStageDecision::WaitFor(stage) => {
                    Some(*stage)
                }
                WatchStageDecision::NoSupportedFutureStage { .. } => None,
            }
        } else {
            match select_for_live_mint(&stages, now) {
                LiveStageDecision::Selected(stage) => Some(*stage),
                LiveStageDecision::NoActiveEligibleStage { .. } => None,
            }
        };

        Ok(winner.as_ref().map(stage_to_detection))
    }
}

/// True-final-release-gate item 6/7: `watch --engine auto`'s equivalent
/// of [`NormalizedStageAdapter::detect`], but returns the full
/// [`WatchStageDecision`] instead of collapsing
/// `AlreadyLive`/`WaitFor` into the same `Some(stage)` the way
/// `detect()` does for the generic [`MintAdapter`] trait it implements.
/// `select_for_watch`'s own doc comment already specified the intended
/// caller behavior ("report `STAGE_ALREADY_LIVE`, point the operator at
/// `mint`") -- this is what makes that distinction reach the caller at
/// all, since `detect()` alone cannot carry it through the shared
/// `Detection` type every other adapter/engine also produces.
///
/// Never used for an operator-provided `--slug` (that path is a direct,
/// unambiguous fact -- see `NormalizedStageAdapter::detect`'s identical
/// handling -- and remains routed through `detect()` unchanged); only
/// for `--engine auto`'s discovery-driven decision.
pub(crate) async fn resolve_watch_stage_decision(
    plan_args: &PlanArgs,
    config_path: Option<&Path>,
    opensea: Option<&crate::opensea::client::OpenSeaClient>,
    excluded_stage_ids: &[StageId],
) -> Result<WatchStageDecision, KairoxError> {
    let mut stages = Vec::new();
    stages.extend(discover_public_stage(plan_args, config_path).await?);
    stages.extend(discover_opensea_stages(plan_args, config_path, opensea, true).await?);
    stages.retain(|s| !excluded_stage_ids.contains(&s.id));

    let now = OffsetDateTime::now_utc();
    Ok(select_for_watch(&stages, now))
}

/// Detects the generic verified ERC-721/ERC-1155 route, in order:
///
/// 1. **Trusted registry**: the target's (proxy-resolved) implementation
///    bytecode hash exactly matches a manually-reviewed
///    [`TrustedGenericFingerprint`](crate::execution::generic_registry::TrustedGenericFingerprint).
///    `Confidence::High`.
/// 2. **Verified-source semantic resolution**: a
///    [`VerifiedContractMetadataProvider`](crate::metadata::VerifiedContractMetadataProvider)
///    (Blockscout) reports the target's source verified, and
///    `execution::generic_semantics::resolve_mint_function` finds exactly
///    one unambiguous mint function using the verified ABI's parameter
///    *names* as semantic evidence (never types alone) -- corroborated by
///    on-chain ERC-165. `Confidence::High`.
/// 3. **Operator-declared `--generic-schema` alone**: `Confidence::Low`,
///    always -- ERC-165 proves the NFT *standard*, never that any
///    particular selector means what a schema claims, what its arguments
///    mean, or what value it expects. Can never resolve to a live-send
///    path. See `docs/generic-engine.md`'s "Confidence model" section.
///
/// Priority 1 -- only tried once [`NormalizedStageAdapter`] (priority 0)
/// found no candidate stage at all.
pub struct GenericVerifiedContractAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub schema: Option<&'a GenericMintSchema>,
    pub trusted_registry: &'a [crate::execution::generic_registry::TrustedGenericFingerprint],
    pub metadata_provider: Option<&'a dyn crate::metadata::VerifiedContractMetadataProvider>,
}

#[async_trait::async_trait]
impl MintAdapter for GenericVerifiedContractAdapter<'_> {
    fn name(&self) -> &'static str {
        "GenericVerifiedContractAdapter"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        use crate::execution::generic_engine::{ResolvedGenericTarget, ResolvedPrice};
        use crate::execution::generic_semantics::{PriceResolution, SemanticResolution};

        let registry = crate::chain::registry::ChainRegistry::builtin();
        let (resolved, runtime) =
            resolve_chain_and_runtime(&registry, &self.plan_args.chain_args, self.config_path)?;
        let client = connect_read_client(
            &resolved.info,
            self.plan_args.chain_args.rpc_url.as_ref(),
            runtime.config.as_ref(),
        )
        .await?;

        let (implementation, bytecode_hash) =
            crate::execution::generic_engine::resolve_implementation_and_code_hash(
                &client,
                self.plan_args.collection,
            )
            .await?;

        if let Some(fingerprint) = crate::execution::generic_registry::find_fingerprint(
            self.trusted_registry,
            resolved.info.chain_id,
            bytecode_hash,
        ) {
            return Ok(Some(Detection {
                engine: ResolvedEngine::Generic {
                    target: ResolvedGenericTarget {
                        shape: fingerprint.shape,
                        standard: fingerprint.standard,
                        token_id: fingerprint.token_id,
                        price: ResolvedPrice::Fixed(alloy_primitives::U256::from(
                            fingerprint.price_per_token_wei,
                        )),
                        bytecode_hash,
                        source_label: format!("TrustedRegistry:{}", fingerprint.name),
                    },
                },
                evidence: ProtocolEvidence {
                    source: format!(
                        "exact trusted-registry fingerprint match {:?} for implementation {} \
                         (bytecode hash {bytecode_hash})",
                        fingerprint.name, implementation
                    ),
                    confidence: Confidence::High,
                    adapter: "GenericVerifiedContractAdapter",
                    matched_interfaces: vec![],
                    matched_selectors: vec![],
                },
            }));
        }

        // No registry match. Try verified-source semantic resolution next.
        if let Some(provider) = self.metadata_provider {
            let erc721 = crate::protocol::erc_standards::supports_interface(
                &client,
                self.plan_args.collection,
                crate::protocol::erc_standards::ERC721_INTERFACE_ID,
            )
            .await?;
            let erc1155 = if erc721 {
                false
            } else {
                crate::protocol::erc_standards::supports_interface(
                    &client,
                    self.plan_args.collection,
                    crate::protocol::erc_standards::ERC1155_INTERFACE_ID,
                )
                .await?
            };
            let expected_standard = if erc721 {
                Some(crate::execution::generic_schema::GenericStandard::Erc721)
            } else if erc1155 {
                Some(crate::execution::generic_schema::GenericStandard::Erc1155)
            } else {
                None
            };

            // A metadata-provider transport/server error is never treated
            // as verification evidence of any kind (positive or
            // negative) -- but it also never aborts the whole session,
            // exactly like an OpenSea auto-discovery error above: a
            // provider being briefly unreachable must not take down a
            // resolution that still has a safe (never-broadcasting,
            // LOW-confidence) operator-schema fallback available below.
            let metadata = if let Some(standard) = expected_standard {
                match provider.fetch(self.plan_args.collection).await {
                    Ok(metadata) => Some((metadata, standard)),
                    Err(_) => None,
                }
            } else {
                None
            };

            if let Some((metadata, standard)) = metadata {
                match crate::execution::generic_semantics::resolve_mint_function(
                    &metadata, standard,
                ) {
                    SemanticResolution::Resolved(r) => {
                        let price = match r.price {
                            PriceResolution::Getter { selector, .. } => {
                                ResolvedPrice::LiveGetter(selector)
                            }
                            PriceResolution::Unavailable => {
                                return Ok(Some(Detection {
                                    engine: ResolvedEngine::Generic {
                                        target: ResolvedGenericTarget {
                                            shape: r.shape,
                                            standard: r.standard,
                                            token_id: None,
                                            price: ResolvedPrice::Fixed(
                                                alloy_primitives::U256::ZERO,
                                            ),
                                            bytecode_hash,
                                            source_label: "VALUE_UNVERIFIED".to_string(),
                                        },
                                    },
                                    evidence: ProtocolEvidence {
                                        source: format!(
                                            "VALUE_UNVERIFIED: {} resolved a mint function ({}) \
                                             but no unambiguous verified price getter exists; \
                                             refusing to guess a payable value",
                                            provider.name(),
                                            r.evidence
                                        ),
                                        confidence: Confidence::Low,
                                        adapter: "GenericVerifiedContractAdapter",
                                        matched_interfaces: vec![],
                                        matched_selectors: vec![],
                                    },
                                }));
                            }
                        };
                        return Ok(Some(Detection {
                            engine: ResolvedEngine::Generic {
                                target: ResolvedGenericTarget {
                                    shape: r.shape,
                                    standard: r.standard,
                                    token_id: None,
                                    price,
                                    bytecode_hash,
                                    source_label: format!("VerifiedMetadata:{}", provider.name()),
                                },
                            },
                            evidence: ProtocolEvidence {
                                source: r.evidence,
                                confidence: Confidence::High,
                                adapter: "GenericVerifiedContractAdapter",
                                matched_interfaces: vec![format!("{standard:?}")],
                                matched_selectors: vec![format!("0x{}", hex::encode(r.selector))],
                            },
                        }));
                    }
                    SemanticResolution::AmbiguousMintFunction { candidates } => {
                        return Ok(Some(Detection {
                            engine: ResolvedEngine::Generic {
                                target: ResolvedGenericTarget {
                                    shape: crate::execution::generic_schema::GenericMintShape::MintQuantity,
                                    standard,
                                    token_id: None,
                                    price: ResolvedPrice::Fixed(alloy_primitives::U256::ZERO),
                                    bytecode_hash,
                                    source_label: "AMBIGUOUS_MINT_FUNCTION".to_string(),
                                },
                            },
                            evidence: ProtocolEvidence {
                                source: format!(
                                    "AMBIGUOUS_MINT_FUNCTION: {} candidate mint functions found \
                                     ({}); refusing to guess which is authoritative",
                                    candidates.len(),
                                    candidates.join(", ")
                                ),
                                confidence: Confidence::Low,
                                adapter: "GenericVerifiedContractAdapter",
                                matched_interfaces: vec![],
                                matched_selectors: vec![],
                            },
                        }));
                    }
                    SemanticResolution::NotFound => {
                        // Falls through to the operator-schema Low-confidence
                        // path below.
                    }
                }
            }
        }

        // No registry match, no verified-source resolution. An
        // operator-declared schema plus ERC-165 is real evidence of
        // *something* (the operator's intent, and that the contract
        // implements the claimed NFT standard), but it is deliberately
        // never enough to authorize a live-send path -- see this
        // adapter's doc comment.
        let Some(schema) = self.schema else {
            return Ok(None);
        };
        if let Err(e) = schema.validate() {
            return Err(KairoxError::Session(
                crate::execution::errors::SessionError::new(format!(
                    "invalid --generic-schema: {e}"
                )),
            ));
        }
        let standard_name = match schema.standard {
            crate::execution::generic_schema::GenericStandard::Erc721 => "ERC-721",
            crate::execution::generic_schema::GenericStandard::Erc1155 => "ERC-1155",
        };
        let confirmed = crate::protocol::erc_standards::supports_interface(
            &client,
            self.plan_args.collection,
            schema.standard.erc165_interface_id(),
        )
        .await?;

        Ok(Some(Detection {
            engine: ResolvedEngine::Generic {
                target: ResolvedGenericTarget {
                    shape: schema.shape,
                    standard: schema.standard,
                    token_id: schema.token_id,
                    price: ResolvedPrice::Fixed(alloy_primitives::U256::ZERO),
                    bytecode_hash,
                    source_label: "OPERATOR_DECLARED_UNVERIFIED_SCHEMA".to_string(),
                },
            },
            evidence: ProtocolEvidence {
                source: format!(
                    "OPERATOR_DECLARED_UNVERIFIED_SCHEMA: {:?} for {} (on-chain ERC-165 \
                     supportsInterface({standard_name}) = {confirmed}); this is NOT independent \
                     verification of mint-function semantics and can never authorize a live \
                     send -- see docs/generic-engine.md",
                    schema.shape, self.plan_args.collection
                ),
                confidence: Confidence::Low,
                adapter: "GenericVerifiedContractAdapter",
                matched_interfaces: if confirmed {
                    vec![standard_name.to_string()]
                } else {
                    vec![]
                },
                matched_selectors: vec![],
            },
        }))
    }
}

/// Auto-discovery for thirdweb Drop claims. `--collection` is the
/// candidate Drop contract, exactly as for explicit `--engine thirdweb`.
/// Mirrors [`GenericVerifiedContractAdapter`]'s registry-match discipline
/// exactly: selector/`eth_call` compatibility is never sufficient on its
/// own (a custom contract can inherit thirdweb's Drop base extension and
/// override its execution-affecting hooks -- see
/// `execution::thirdweb_engine::establish_provenance`'s doc comment).
/// Only an exact, manually-reviewed
/// [`crate::execution::thirdweb_registry::ThirdwebTrustedFingerprint`]
/// match produces `Confidence::High`; a selector-shaped-but-unverified
/// match is reported as `Confidence::Low` (purely for operator-visible
/// evidence in an `UNSUPPORTED_PROTOCOL` error -- the resolver already
/// refuses to auto-select a lone `Low` match, see
/// `execution::resolver::AdapterRegistry::resolve`).
///
/// Same priority tier as [`GenericVerifiedContractAdapter`] (1): both are
/// bytecode/registry-based resolutions, fundamentally different from
/// [`NormalizedStageAdapter`]'s stage-timing model, and if a target
/// somehow matched both a generic *and* a thirdweb trusted fingerprint
/// that would be a genuine ambiguity worth surfacing, not something to
/// silently prefer one over the other.
pub struct ThirdwebAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub trusted_registry: &'a [crate::execution::thirdweb_registry::ThirdwebTrustedFingerprint],
}

#[async_trait::async_trait]
impl MintAdapter for ThirdwebAdapter<'_> {
    fn name(&self) -> &'static str {
        "ThirdwebAdapter"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        let registry = crate::chain::registry::ChainRegistry::builtin();
        let (resolved, runtime) =
            resolve_chain_and_runtime(&registry, &self.plan_args.chain_args, self.config_path)?;
        let client = connect_read_client(
            &resolved.info,
            self.plan_args.chain_args.rpc_url.as_ref(),
            runtime.config.as_ref(),
        )
        .await?;

        let (_implementation, bytecode_hash) =
            crate::execution::thirdweb_engine::resolve_thirdweb_implementation_and_code_hash(
                &client,
                self.plan_args.collection,
            )
            .await?;

        if let Some(fingerprint) = crate::execution::thirdweb_registry::find_fingerprint(
            self.trusted_registry,
            resolved.info.chain_id,
            bytecode_hash,
        ) {
            return Ok(Some(Detection {
                engine: ResolvedEngine::Thirdweb {
                    drop_contract: self.plan_args.collection,
                },
                evidence: ProtocolEvidence {
                    source: format!(
                        "exact trusted-registry fingerprint match {:?} (flavor {:?}, bytecode \
                         hash {bytecode_hash})",
                        fingerprint.name, fingerprint.flavor
                    ),
                    confidence: Confidence::High,
                    adapter: "ThirdwebAdapter",
                    matched_interfaces: vec![],
                    matched_selectors: vec![],
                },
            }));
        }

        // No registry match -- best-effort selector probing purely for
        // operator-visible evidence. Never authorizes anything on its own
        // (Confidence::Low); Ok(None) if the target isn't even
        // thirdweb-shaped at all.
        match crate::execution::thirdweb_engine::probe_flavor(&client, self.plan_args.collection)
            .await
        {
            Some((flavor, _condition)) => Ok(Some(Detection {
                engine: ResolvedEngine::Thirdweb {
                    drop_contract: self.plan_args.collection,
                },
                evidence: ProtocolEvidence {
                    source: format!(
                        "selectors matching thirdweb flavor {flavor:?} responded, but no \
                         trusted-registry fingerprint confirms this is unmodified thirdweb \
                         execution semantics (bytecode hash {bytecode_hash}); refusing to arm a \
                         live-send path on unconfirmed evidence"
                    ),
                    confidence: Confidence::Low,
                    adapter: "ThirdwebAdapter",
                    matched_interfaces: vec![],
                    matched_selectors: vec![],
                },
            })),
            None => Ok(None),
        }
    }
}

/// Auto-discovery for Manifold `LazyPayableClaim` claims. **Partial
/// auto-discovery only** -- a claim needs three identifiers (extension
/// contract, creator contract, instance id). The extension contract can
/// be auto-discovered via `ICreatorCore::getExtensions()` (a real,
/// bounded, on-chain enumeration -- see
/// `execution::manifold_engine::discover_manifold_extension` and
/// `protocol::manifold`'s module doc comment) when exactly one registered
/// extension responds like a `LazyPayableClaim` for the given
/// `--instance-id`. There is still no verified on-chain enumeration of
/// instance ids themselves, so `--instance-id` is never auto-discovered
/// -- inventing a heuristic for that would repeat exactly the mistake
/// this codebase already corrected once for thirdweb: treating
/// unverified compatibility as proof.
///
/// When `--manifold-extension` is omitted and discovery finds zero or
/// more than one candidate, `detect()` returns `Ok(None)` -- a discovery
/// failure in `--engine auto` mode is "this adapter has nothing to add",
/// never a hard error that aborts the whole resolution.
pub struct ManifoldAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub trusted_registry: &'a [crate::execution::manifold_registry::ManifoldTrustedFingerprint],
}

#[async_trait::async_trait]
impl MintAdapter for ManifoldAdapter<'_> {
    fn name(&self) -> &'static str {
        "ManifoldAdapter"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        let instance_id =
            crate::cli::format::parse_wei("--instance-id", &self.plan_args.instance_id)?;

        let registry = crate::chain::registry::ChainRegistry::builtin();
        let (resolved, runtime) =
            resolve_chain_and_runtime(&registry, &self.plan_args.chain_args, self.config_path)?;
        let client = connect_read_client(
            &resolved.info,
            self.plan_args.chain_args.rpc_url.as_ref(),
            runtime.config.as_ref(),
        )
        .await?;

        let extension_contract = match self.plan_args.manifold_extension {
            Some(extension_contract) => extension_contract,
            None => {
                match crate::execution::manifold_engine::discover_manifold_extension(
                    &client,
                    self.plan_args.collection,
                    instance_id,
                )
                .await
                {
                    Ok(extension_contract) => extension_contract,
                    Err(_) => return Ok(None),
                }
            }
        };

        let bytecode_hash =
            crate::execution::manifold_engine::resolve_manifold_extension_code_hash(
                &client,
                extension_contract,
            )
            .await?;

        if let Some(fingerprint) = crate::execution::manifold_registry::find_fingerprint(
            self.trusted_registry,
            resolved.info.chain_id,
            bytecode_hash,
        ) {
            return Ok(Some(Detection {
                engine: ResolvedEngine::Manifold {
                    extension_contract,
                    creator_contract: self.plan_args.collection,
                    instance_id,
                },
                evidence: ProtocolEvidence {
                    source: format!(
                        "exact trusted-registry fingerprint match {:?} for Manifold extension {} \
                         (bytecode hash {bytecode_hash})",
                        fingerprint.name, extension_contract
                    ),
                    confidence: Confidence::High,
                    adapter: "ManifoldAdapter",
                    matched_interfaces: vec![],
                    matched_selectors: vec![],
                },
            }));
        }

        // No registry match -- best-effort claim read purely for
        // operator-visible evidence, never authorizing anything on its
        // own.
        let evidence_source = match crate::execution::manifold_engine::probe_claim(
            &client,
            extension_contract,
            self.plan_args.collection,
            instance_id,
        )
        .await
        {
            Some(_claim) => format!(
                "a Manifold claim was readable at extension {extension_contract} / creator {} / \
                 instance {instance_id}, but no trusted-registry fingerprint confirms this is an \
                 unmodified Manifold extension deployment (bytecode hash {bytecode_hash}); \
                 refusing to arm a live-send path on unconfirmed evidence",
                self.plan_args.collection
            ),
            None => format!(
                "no readable Manifold claim at extension {extension_contract} / creator {} / \
                 instance {instance_id}, and no trusted-registry fingerprint match either \
                 (bytecode hash {bytecode_hash})",
                self.plan_args.collection
            ),
        };
        Ok(Some(Detection {
            engine: ResolvedEngine::Manifold {
                extension_contract,
                creator_contract: self.plan_args.collection,
                instance_id,
            },
            evidence: ProtocolEvidence {
                source: evidence_source,
                confidence: Confidence::Low,
                adapter: "ManifoldAdapter",
                matched_interfaces: vec![],
                matched_selectors: vec![],
            },
        }))
    }
}

/// Bounded maximum number of multi-phase conditions
/// [`discover_thirdweb_stages`] will ever enumerate/read in one call --
/// see that function's doc comment. Real drops configure a handful of
/// phases; this exists purely as a corruption/DoS backstop (an
/// unreasonable `count` value never turns into an unbounded read loop),
/// not a claim that no real drop could ever exceed it.
const MAX_THIRDWEB_PHASES: u64 = 20;

/// Discovers thirdweb Drop claim condition(s) for `drop_contract` as
/// [`NormalizedStage`] entries, for `--engine thirdweb`'s `watch`
/// support. Purely a **read-only, best-effort discovery** step -- it
/// never authorizes anything; live-send/watch-arm authorization is
/// [`crate::execution::thirdweb_engine::establish_provenance`]'s job
/// alone, applied unconditionally afterward by the caller.
///
/// **Flavor disambiguation**: makes exactly one `claimCondition()` call
/// via [`crate::cli::gather::fetch_thirdweb_claim_condition_or_list`],
/// which decodes the response using the one safe order (see that
/// function's doc comment) -- never infers flavor from selector
/// existence alone.
///
/// **Multi-phase**: reads the list's own authoritative `(currentStartId,
/// count)` metadata directly (via `claimCondition()`'s auto-generated
/// getter, which exposes only the non-mapping fields of the real
/// `ClaimConditionList` struct -- verified against `IDrop.sol` source;
/// this works identically whether or not any phase has started yet,
/// unlike `getActiveClaimConditionId()`, which reverts until the first
/// configured phase opens), then enumerates every id in
/// `[currentStartId, currentStartId + count)` via `getClaimConditionById`
/// -- see [`ThirdwebDiscoveryError::TooManyPhases`] for what happens when
/// `count` exceeds [`MAX_THIRDWEB_PHASES`]. Each condition's `StageId`
/// carries its exact id plus a
/// [`crate::protocol::thirdweb::ClaimCondition::config_fingerprint`], and
/// each condition's effective end is the *real* `startTimestamp` of the
/// next enumerated condition (verified against `getActiveClaimConditionId`'s
/// own backward-iterating "first condition whose startTimestamp has
/// passed" logic -- a later condition's start genuinely does end the
/// previous one for "active" purposes) -- the last enumerated condition
/// gets `end: None` (genuinely open/unknown), never an invented
/// timestamp.
///
/// **Single-phase**: `claimCondition()`'s own long-shape decode success
/// already proves the flavor (see disambiguation above) -- no
/// condition id exists in this flavor's ABI at all, so its
/// [`StageId::ThirdwebSinglePhase`] identity carries the contract
/// address plus a config fingerprint (a single-phase condition can be
/// replaced in place -- see `StageId::ThirdwebSinglePhase`'s doc
/// comment); `end` is always `None` (this protocol supplies no end
/// field for this flavor at all).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ThirdwebDiscoveryError {
    /// `count` exceeded [`MAX_THIRDWEB_PHASES`] -- refused outright,
    /// never partially enumerated. A truncated read would risk two real
    /// bugs: silently hiding configured phases beyond the cutoff from an
    /// operator relying on `watch` to find them, and -- worse --
    /// incorrectly reporting the last *read* phase as open-ended
    /// (`end: None`) when a real, later-configured phase (past the
    /// cutoff) actually ends it. Neither is acceptable; fail closed
    /// instead and let the operator investigate a drop with an
    /// unreasonably large configured phase count.
    #[error(
        "thirdweb Drop at {drop_contract} reports {count} configured multi-phase conditions, \
         exceeding the maximum of {max} this pass will enumerate; refusing to return a \
         possibly-truncated/incorrectly-open-ended stage list"
    )]
    TooManyPhases {
        drop_contract: alloy_primitives::Address,
        count: alloy_primitives::U256,
        max: u64,
    },
}

pub(crate) async fn discover_thirdweb_stages(
    client: &crate::chain::rpc::RpcClient,
    drop_contract: alloy_primitives::Address,
    wallet: alloy_primitives::Address,
) -> Result<Vec<NormalizedStage>, ThirdwebDiscoveryError> {
    use crate::cli::gather::ThirdwebClaimConditionShape;
    use crate::protocol::thirdweb::ClaimCondition;

    fn to_stage(
        drop_contract: alloy_primitives::Address,
        condition_id: alloy_primitives::U256,
        condition: &ClaimCondition,
        end: Option<OffsetDateTime>,
        wallet_claimed: Option<alloy_primitives::U256>,
    ) -> Option<NormalizedStage> {
        let start = crate::execution::plan::unix_timestamp(
            condition.start_timestamp,
            "thirdweb claim condition startTimestamp",
        )
        .ok()?;
        Some(NormalizedStage {
            id: StageId::ThirdwebMultiPhase {
                drop_contract,
                condition_id,
                config_fingerprint: condition.config_fingerprint(),
            },
            execution: StageExecutionRef::Thirdweb { drop_contract },
            protocol: StageProtocol::ThirdwebClaim,
            label: None,
            window: PhaseWindow { start, end },
            price_per_token_wei: if condition.is_native_currency() {
                Some(condition.price_per_token)
            } else {
                None
            },
            max_per_wallet: u64::try_from(condition.quantity_limit_per_wallet).ok(),
            wallet_minted: wallet_claimed.and_then(|w| u64::try_from(w).ok()),
            supply_remaining: u64::try_from(condition.supply_remaining()).ok(),
            eligibility: if condition.merkle_root.is_zero() {
                EligibilityState::Eligible
            } else {
                // A merkle-gated phase's real eligibility can only be
                // established once the operator supplies a proof at
                // execution time -- never guessed here.
                EligibilityState::UnknownUntilActive
            },
            evidence: format!(
                "thirdweb multi-phase condition {condition_id} read from {drop_contract} \
                 (startTimestamp {}, merkleRoot {:#x})",
                condition.start_timestamp, condition.merkle_root
            ),
        })
    }

    let Ok(shape) =
        crate::cli::gather::fetch_thirdweb_claim_condition_or_list(client, drop_contract).await
    else {
        return Ok(Vec::new());
    };

    match shape {
        ThirdwebClaimConditionShape::SinglePhase(condition) => {
            let wallet_claimed =
                crate::cli::gather::fetch_thirdweb_supply_claimed_by_wallet_single_phase(
                    client,
                    drop_contract,
                    wallet,
                )
                .await
                .ok();
            let Ok(start) = crate::execution::plan::unix_timestamp(
                condition.start_timestamp,
                "thirdweb single-phase claimCondition startTimestamp",
            ) else {
                return Ok(Vec::new());
            };
            Ok(vec![NormalizedStage {
                id: StageId::ThirdwebSinglePhase {
                    drop_contract,
                    config_fingerprint: condition.config_fingerprint(),
                },
                execution: StageExecutionRef::Thirdweb { drop_contract },
                protocol: StageProtocol::ThirdwebClaim,
                label: None,
                window: PhaseWindow { start, end: None },
                price_per_token_wei: if condition.is_native_currency() {
                    Some(condition.price_per_token)
                } else {
                    None
                },
                max_per_wallet: u64::try_from(condition.quantity_limit_per_wallet).ok(),
                wallet_minted: wallet_claimed.and_then(|w| u64::try_from(w).ok()),
                supply_remaining: u64::try_from(condition.supply_remaining()).ok(),
                eligibility: if condition.merkle_root.is_zero() {
                    EligibilityState::Eligible
                } else {
                    EligibilityState::UnknownUntilActive
                },
                evidence: format!(
                    "thirdweb single-phase claimCondition read from {drop_contract} \
                     (startTimestamp {}, merkleRoot {:#x})",
                    condition.start_timestamp, condition.merkle_root
                ),
            }])
        }
        ThirdwebClaimConditionShape::MultiPhaseList(current_start_id, count) => {
            if count > alloy_primitives::U256::from(MAX_THIRDWEB_PHASES) {
                return Err(ThirdwebDiscoveryError::TooManyPhases {
                    drop_contract,
                    count,
                    max: MAX_THIRDWEB_PHASES,
                });
            }
            let mut conditions: Vec<(alloy_primitives::U256, ClaimCondition)> = Vec::new();
            let mut id = current_start_id;
            let mut read = alloy_primitives::U256::ZERO;
            while read < count {
                if let Ok(condition) = crate::cli::gather::fetch_thirdweb_claim_condition_by_id(
                    client,
                    drop_contract,
                    id,
                )
                .await
                {
                    conditions.push((id, condition));
                }
                id = id.saturating_add(alloy_primitives::U256::from(1));
                read = read.saturating_add(alloy_primitives::U256::from(1));
            }

            let mut stages = Vec::with_capacity(conditions.len());
            for i in 0..conditions.len() {
                let (condition_id, condition) = &conditions[i];
                let end = match conditions.get(i + 1) {
                    Some((_, next)) => crate::execution::plan::unix_timestamp(
                        next.start_timestamp,
                        "thirdweb next claim condition startTimestamp",
                    )
                    .ok(),
                    None => None,
                };
                let wallet_claimed = crate::cli::gather::fetch_thirdweb_supply_claimed_by_wallet(
                    client,
                    drop_contract,
                    *condition_id,
                    wallet,
                )
                .await
                .ok();
                if let Some(stage) =
                    to_stage(drop_contract, *condition_id, condition, end, wallet_claimed)
                {
                    stages.push(stage);
                }
            }
            Ok(stages)
        }
    }
}

/// Discovers the Manifold `LazyPayableClaim` claim at
/// `(extension_contract, creator_contract, instance_id)` as a
/// [`NormalizedStage`], for `--engine manifold`'s `watch` support.
/// `instance_id` is always operator-supplied (see
/// `execution::manifold_engine::discover_manifold_extension`'s doc
/// comment for why no on-chain instance enumeration exists) --
/// read-only, best-effort, never authorizes anything on its own.
pub(crate) async fn discover_manifold_stage(
    client: &crate::chain::rpc::RpcClient,
    extension_contract: alloy_primitives::Address,
    creator_contract: alloy_primitives::Address,
    instance_id: alloy_primitives::U256,
    wallet: alloy_primitives::Address,
) -> Option<NormalizedStage> {
    let claim = crate::execution::manifold_engine::probe_claim(
        client,
        extension_contract,
        creator_contract,
        instance_id,
    )
    .await?;

    let start =
        crate::execution::plan::unix_timestamp(claim.start_date, "Manifold claim startDate")
            .ok()?;
    let end =
        crate::execution::plan::unix_timestamp(claim.end_date, "Manifold claim endDate").ok()?;

    let wallet_claimed = crate::cli::gather::fetch_manifold_total_mints(
        client,
        extension_contract,
        wallet,
        creator_contract,
        instance_id,
    )
    .await
    .ok();

    Some(NormalizedStage {
        id: StageId::ManifoldClaim {
            extension_contract,
            creator_contract,
            instance_id,
        },
        execution: StageExecutionRef::Manifold {
            extension_contract,
            creator_contract,
            instance_id,
        },
        protocol: StageProtocol::ManifoldClaim,
        label: None,
        window: PhaseWindow {
            start,
            end: Some(end),
        },
        price_per_token_wei: if claim.is_native_currency() {
            Some(claim.cost)
        } else {
            None
        },
        max_per_wallet: if claim.wallet_max == 0 {
            None
        } else {
            Some(u64::from(claim.wallet_max))
        },
        wallet_minted: wallet_claimed.map(u64::from),
        supply_remaining: Some(u64::from(claim.supply_remaining())),
        eligibility: if claim.is_gated() {
            EligibilityState::UnknownUntilActive
        } else {
            EligibilityState::Eligible
        },
        evidence: format!(
            "Manifold claim (extension {extension_contract}, creator {creator_contract}, \
             instance {instance_id}) read (startDate {}, endDate {}, merkleRoot {:#x})",
            claim.start_date, claim.end_date, claim.merkle_root
        ),
    })
}

#[cfg(test)]
mod stage_identity_tests {
    use super::*;
    use time::macros::datetime;

    fn window() -> PhaseWindow {
        PhaseWindow {
            start: datetime!(2020-01-01 00:00:00 UTC),
            end: Some(datetime!(2999-01-01 00:00:00 UTC)),
        }
    }

    fn opensea_stage(uuid: &str, slug: &str) -> NormalizedStage {
        NormalizedStage {
            id: StageId::OpenSea {
                stage_uuid: uuid.to_string(),
            },
            execution: StageExecutionRef::OpenSea {
                slug: slug.to_string(),
            },
            protocol: StageProtocol::SignedPresale,
            label: None,
            window: window(),
            price_per_token_wei: None,
            max_per_wallet: Some(10),
            wallet_minted: None,
            supply_remaining: None,
            eligibility: EligibilityState::UnknownUntilActive,
            evidence: "test fixture".to_string(),
        }
    }

    #[test]
    fn same_slug_two_uuids_rejecting_first_excludes_only_first() {
        let a = opensea_stage("uuid-a", "collection");
        let b = opensea_stage("uuid-b", "collection");
        let excluded = [a.id.clone()];
        let stages: Vec<NormalizedStage> = vec![a, b.clone()]
            .into_iter()
            .filter(|s| !excluded.contains(&s.id))
            .collect();
        assert_eq!(
            stages.len(),
            1,
            "excluding uuid-a must leave uuid-b selectable"
        );
        assert_eq!(stages[0].id, b.id);
    }

    #[test]
    fn stage_to_detection_uses_execution_slug_never_the_stage_uuid_as_slug() {
        // Regression test for the exact bug reported: an earlier version
        // used NormalizedStage::id (which held the collection slug) as
        // the exclusion key AND as the POST /mint slug, collapsing every
        // OpenSea stage of one drop into a single identity. id is now the
        // stage's own unique identity; execution::OpenSea::slug is the
        // separate drop-level routing value.
        let stage = opensea_stage("uuid-a", "the-real-collection-slug");
        let detection = stage_to_detection(&stage);
        match detection.engine {
            ResolvedEngine::OpenSea { slug, stage_uuid } => {
                assert_eq!(slug, "the-real-collection-slug");
                assert_eq!(stage_uuid.as_deref(), Some("uuid-a"));
            }
            other => panic!("expected ResolvedEngine::OpenSea, got {other:?}"),
        }
    }

    #[test]
    fn two_stages_with_same_label_but_different_uuid_remain_distinct_identities() {
        let mut a = opensea_stage("uuid-a", "collection");
        a.label = Some("Presale".to_string());
        let mut b = opensea_stage("uuid-b", "collection");
        b.label = Some("Presale".to_string());
        assert_ne!(
            a.id, b.id,
            "identical display labels must never imply identical stage identity"
        );
    }

    #[test]
    fn sequential_rejection_of_two_stages_leaves_neither_reselectable() {
        let a = opensea_stage("uuid-a", "collection");
        let b = opensea_stage("uuid-b", "collection");
        let excluded = [a.id.clone(), b.id.clone()];
        let stages: Vec<NormalizedStage> = vec![a, b]
            .into_iter()
            .filter(|s| !excluded.contains(&s.id))
            .collect();
        assert!(
            stages.is_empty(),
            "A rejected then B rejected must leave neither selectable -- A must never bounce \
             back into consideration"
        );
    }

    /// Round 6 item 17: "A and B rejected, C survives" -- extends the
    /// pattern above with a third, never-rejected stage present in the
    /// candidate set, proving the exclusion filter removes exactly the
    /// rejected identities and nothing else.
    #[test]
    fn two_sequential_rejections_still_leave_a_third_untouched_stage_selectable() {
        let a = opensea_stage("uuid-a", "collection");
        let b = opensea_stage("uuid-b", "collection");
        let c = opensea_stage("uuid-c", "collection");
        let excluded = [a.id.clone(), b.id.clone()];
        let stages: Vec<NormalizedStage> = vec![a, b, c.clone()]
            .into_iter()
            .filter(|s| !excluded.contains(&s.id))
            .collect();
        assert_eq!(
            stages,
            vec![c],
            "A rejected then B rejected must leave the untouched C stage selectable"
        );
    }

    #[test]
    fn on_chain_public_identity_is_stable_and_distinct_from_any_opensea_stage() {
        let public_a = StageId::OnChainPublic;
        let public_b = StageId::OnChainPublic;
        assert_eq!(public_a, public_b);
        assert_ne!(
            public_a,
            StageId::OpenSea {
                stage_uuid: "on-chain-public".to_string()
            },
            "an OpenSea stage coincidentally uuid'd the same as the old sentinel string must \
             never collide with the on-chain public stage's identity"
        );
    }
}

#[cfg(test)]
mod thirdweb_manifold_stage_discovery_tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::rpc::RpcClient;
    use crate::protocol::manifold::ClaimAbi;
    use crate::protocol::thirdweb::{self as tw, ClaimConditionAbi};
    use alloy_primitives::address;
    use alloy_sol_types::SolCall;
    use serde_json::json;

    const DROP: alloy_primitives::Address = address!("00000000000000000000000000000000000c0DE0");
    const WALLET: alloy_primitives::Address = address!("1111111111111111111111111111111111111111");

    async fn connect(transport: MockTransport) -> RpcClient {
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap()
    }

    fn condition_abi(start: u64, merkle_root: alloy_primitives::B256) -> ClaimConditionAbi {
        ClaimConditionAbi {
            startTimestamp: alloy_primitives::U256::from(start),
            maxClaimableSupply: alloy_primitives::U256::from(1_000u64),
            supplyClaimed: alloy_primitives::U256::from(10u64),
            quantityLimitPerWallet: alloy_primitives::U256::from(5u64),
            merkleRoot: merkle_root,
            pricePerToken: alloy_primitives::U256::from(10_000_000_000_000_000u64),
            currency: tw::NATIVE_TOKEN,
            metadata: String::new(),
        }
    }

    fn eth_call_data(params: &serde_json::Value) -> String {
        params
            .get(0)
            .and_then(|c| c.get("data"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("0x")
            .to_string()
    }

    fn selector_prefix(selector: [u8; 4]) -> String {
        format!("0x{}", hex::encode(selector))
    }

    fn id_suffix(id: u64) -> String {
        format!("{id:064x}")
    }

    fn list_metadata_hex(current_start_id: u64, count: u64) -> String {
        format!(
            "0x{}",
            hex::encode(
                tw::multi_phase_list::claimConditionCall::abi_encode_returns(
                    &tw::multi_phase_list::claimConditionReturn {
                        currentStartId: alloy_primitives::U256::from(current_start_id),
                        count: alloy_primitives::U256::from(count),
                    }
                )
            )
        )
    }

    /// Mocks a multi-phase drop responding to `claimCondition()` with the
    /// list-metadata shape (`currentStartId`, `count`) and to
    /// `getClaimConditionById(id)` for each id in
    /// `[start_id, start_id + conditions.len())` with the given
    /// `(startTimestamp, merkleRoot)` pairs, in order. Also mocks
    /// `getSupplyClaimedByWallet` for every id to return zero.
    fn multi_phase_transport(
        start_id: u64,
        conditions: &[(u64, alloy_primitives::B256)],
    ) -> MockTransport {
        let list_hex = list_metadata_hex(start_id, conditions.len() as u64);
        let mut builder = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_eth_call_selector(tw::claimConditionCall::SELECTOR, json!(list_hex))
            .respond_eth_call_selector(
                tw::getSupplyClaimedByWalletCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(tw::getSupplyClaimedByWalletCall::abi_encode_returns(
                        &alloy_primitives::U256::ZERO
                    ))
                )),
            );
        let condition_by_id_prefix = selector_prefix(tw::getClaimConditionByIdCall::SELECTOR);
        for (offset, (start_ts, merkle_root)) in conditions.iter().enumerate() {
            let id = start_id + offset as u64;
            let condition_hex = format!(
                "0x{}",
                hex::encode(tw::getClaimConditionByIdCall::abi_encode_returns(
                    &condition_abi(*start_ts, *merkle_root)
                ))
            );
            let suffix = id_suffix(id);
            let prefix = condition_by_id_prefix.clone();
            builder = builder.respond_matching(
                "eth_call",
                move |params| {
                    let data = eth_call_data(params);
                    data.starts_with(&prefix) && data.ends_with(&suffix)
                },
                json!(condition_hex),
            );
        }
        builder
            .error("eth_call", -32000, "execution reverted")
            .build()
    }

    #[tokio::test]
    async fn multi_phase_single_configured_condition_has_no_known_end() {
        let transport = multi_phase_transport(0, &[(1_700_000_000, alloy_primitives::B256::ZERO)]);
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert_eq!(stages.len(), 1);
        let expected_fingerprint = crate::protocol::thirdweb::ClaimCondition::from_abi(
            condition_abi(1_700_000_000, alloy_primitives::B256::ZERO),
        )
        .unwrap()
        .config_fingerprint();
        assert_eq!(
            stages[0].id,
            StageId::ThirdwebMultiPhase {
                drop_contract: DROP,
                condition_id: alloy_primitives::U256::from(0u64),
                config_fingerprint: expected_fingerprint,
            }
        );
        assert_eq!(
            stages[0].window.end, None,
            "no invented far-future end -- the last (only) configured condition's real end is \
             genuinely unknown"
        );
    }

    #[tokio::test]
    async fn multi_phase_before_first_phase_starts_all_configured_phases_still_discovered() {
        // Section 8's mandatory regression test: getActiveClaimConditionId
        // would revert here (no condition has started yet), but
        // claimCondition()'s list metadata is read regardless of whether
        // any phase is active -- discovery must not depend on
        // getActiveClaimConditionId at all.
        let transport = multi_phase_transport(
            7,
            &[
                (4_000_000_000, alloy_primitives::B256::ZERO), // far future T1
                (4_100_000_000, alloy_primitives::B256::ZERO), // T2
                (4_200_000_000, alloy_primitives::B256::ZERO), // T3
            ],
        );
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert_eq!(
            stages.len(),
            3,
            "all 3 configured future phases must be discovered"
        );
        match &stages[0].id {
            StageId::ThirdwebMultiPhase {
                drop_contract,
                condition_id,
                ..
            } => {
                assert_eq!(*drop_contract, DROP);
                assert_eq!(*condition_id, alloy_primitives::U256::from(7u64));
            }
            other => panic!("expected ThirdwebMultiPhase, got {other:?}"),
        }
        for stage in &stages {
            assert_eq!(
                stage.eligibility,
                EligibilityState::Eligible,
                "a public (merkleRoot == 0) future phase is eligible, not blocked by its own \
                 not-yet-started status (StageStatus, not EligibilityState, encodes timing)"
            );
        }
    }

    #[tokio::test]
    async fn multi_phase_nonzero_current_start_id_is_never_assumed_to_start_at_zero() {
        let transport = multi_phase_transport(
            20,
            &[
                (1_700_000_000, alloy_primitives::B256::ZERO),
                (1_800_000_000, alloy_primitives::B256::ZERO),
                (1_900_000_000, alloy_primitives::B256::ZERO),
            ],
        );
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert_eq!(stages.len(), 3);
        for (offset, stage) in stages.iter().enumerate() {
            match &stage.id {
                StageId::ThirdwebMultiPhase { condition_id, .. } => {
                    assert_eq!(
                        *condition_id,
                        alloy_primitives::U256::from(20 + offset as u64)
                    );
                }
                other => panic!("expected ThirdwebMultiPhase, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn multi_phase_count_exactly_at_the_max_succeeds_completely() {
        let conditions: Vec<(u64, alloy_primitives::B256)> = (0..MAX_THIRDWEB_PHASES)
            .map(|i| (1_700_000_000 + i * 3600, alloy_primitives::B256::ZERO))
            .collect();
        let transport = multi_phase_transport(0, &conditions);
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .expect("count == MAX must succeed completely, not fail closed");
        assert_eq!(stages.len(), MAX_THIRDWEB_PHASES as usize);
        // The last enumerated phase has no later configured phase beyond
        // it (count == MAX exactly, nothing truncated), so end: None is
        // correct here, not a truncation artifact.
        assert_eq!(stages.last().unwrap().window.end, None);
    }

    #[tokio::test]
    async fn multi_phase_count_exceeding_the_max_fails_closed_with_no_partial_list() {
        // count = MAX + 1, deliberately without registering mocks for
        // every individual condition id -- discovery must refuse before
        // ever attempting to enumerate a single one of them, proving the
        // rejection is a genuine fail-fast, not merely "give up partway
        // through the loop".
        let list_hex = list_metadata_hex(0, MAX_THIRDWEB_PHASES + 1);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_eth_call_selector(tw::claimConditionCall::SELECTOR, json!(list_hex))
            .error(
                "eth_call",
                -32000,
                "must never be called: count exceeds the max, discovery must fail before any \
                 per-condition read",
            )
            .build();
        let client = connect(transport).await;

        let err = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .expect_err("count == MAX + 1 must fail closed, never return a truncated list");
        assert_eq!(
            err,
            ThirdwebDiscoveryError::TooManyPhases {
                drop_contract: DROP,
                count: alloy_primitives::U256::from(MAX_THIRDWEB_PHASES + 1),
                max: MAX_THIRDWEB_PHASES,
            }
        );
    }

    #[tokio::test]
    async fn multi_phase_effective_end_is_exactly_the_next_configured_starttimestamp() {
        let transport = multi_phase_transport(
            0,
            &[
                (1_700_000_000, alloy_primitives::B256::ZERO),
                (1_800_000_000, alloy_primitives::B256::ZERO),
            ],
        );
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert_eq!(stages.len(), 2);
        assert_eq!(
            stages[0].window.end,
            Some(stages[1].window.start),
            "the first condition's effective end must be exactly the second condition's real \
             startTimestamp -- verified against Drop.sol's getActiveClaimConditionId semantics"
        );
        assert_eq!(
            stages[1].window.end, None,
            "the last configured condition has no known end -- never an invented far-future \
             timestamp"
        );
    }

    #[tokio::test]
    async fn multi_phase_config_change_on_same_condition_id_produces_a_different_fingerprint() {
        let unchanged = crate::protocol::thirdweb::ClaimCondition::from_abi(condition_abi(
            1_700_000_000,
            alloy_primitives::B256::ZERO,
        ))
        .unwrap();
        let reconfigured_price = {
            let mut abi = condition_abi(1_700_000_000, alloy_primitives::B256::ZERO);
            abi.pricePerToken = alloy_primitives::U256::from(999_000_000_000_000u64);
            crate::protocol::thirdweb::ClaimCondition::from_abi(abi).unwrap()
        };
        assert_ne!(
            unchanged.config_fingerprint(),
            reconfigured_price.config_fingerprint(),
            "a price change on the same condition id must change the fingerprint -- a watch \
             attempt must be able to detect this and stop"
        );
    }

    #[tokio::test]
    async fn multi_phase_supply_claimed_alone_never_changes_the_fingerprint() {
        let a = crate::protocol::thirdweb::ClaimCondition::from_abi(condition_abi(
            1_700_000_000,
            alloy_primitives::B256::ZERO,
        ))
        .unwrap();
        let mut abi_b = condition_abi(1_700_000_000, alloy_primitives::B256::ZERO);
        abi_b.supplyClaimed = alloy_primitives::U256::from(999u64);
        let b = crate::protocol::thirdweb::ClaimCondition::from_abi(abi_b).unwrap();
        assert_eq!(
            a.config_fingerprint(),
            b.config_fingerprint(),
            "supplyClaimed is a naturally-changing counter, never grounds for treating a \
             watched condition as materially changed"
        );
    }

    #[tokio::test]
    async fn single_phase_stage_is_discovered_when_claim_condition_decodes_as_the_long_shape() {
        let condition_hex = format!(
            "0x{}",
            hex::encode(tw::claimConditionCall::abi_encode_returns(&condition_abi(
                1_700_000_000,
                alloy_primitives::B256::ZERO
            )))
        );
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond_eth_call_selector(tw::claimConditionCall::SELECTOR, json!(condition_hex))
            .respond_eth_call_selector(
                tw::single_phase::getSupplyClaimedByWalletCall::SELECTOR,
                json!(format!(
                    "0x{}",
                    hex::encode(
                        tw::single_phase::getSupplyClaimedByWalletCall::abi_encode_returns(
                            &alloy_primitives::U256::ZERO
                        )
                    )
                )),
            )
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert_eq!(stages.len(), 1);
        match &stages[0].id {
            StageId::ThirdwebSinglePhase { drop_contract, .. } => {
                assert_eq!(*drop_contract, DROP);
            }
            other => panic!("expected ThirdwebSinglePhase, got {other:?}"),
        }
        assert_eq!(
            stages[0].window.end, None,
            "single-phase thirdweb has no end field at all -- never an invented one"
        );
    }

    #[tokio::test]
    async fn single_phase_config_change_produces_a_different_fingerprint() {
        let a = crate::protocol::thirdweb::ClaimCondition::from_abi(condition_abi(
            1_700_000_000,
            alloy_primitives::B256::ZERO,
        ))
        .unwrap();
        let mut abi_b = condition_abi(1_700_000_000, alloy_primitives::B256::ZERO);
        abi_b.quantityLimitPerWallet = alloy_primitives::U256::from(999u64);
        let b = crate::protocol::thirdweb::ClaimCondition::from_abi(abi_b).unwrap();
        assert_ne!(
            a.config_fingerprint(),
            b.config_fingerprint(),
            "replacing a single-phase condition's terms in place must be detectable via its \
             fingerprint"
        );
    }

    #[tokio::test]
    async fn neither_flavor_responding_yields_no_stages() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;
        let stages = discover_thirdweb_stages(&client, DROP, WALLET)
            .await
            .unwrap();
        assert!(stages.is_empty());
    }

    #[tokio::test]
    async fn manifold_readable_claim_is_discovered_with_full_native_identity() {
        let extension: alloy_primitives::Address =
            address!("2222222222222222222222222222222222222222");
        let creator: alloy_primitives::Address =
            address!("3333333333333333333333333333333333333333");
        let instance_id = alloy_primitives::U256::from(7u64);
        let claim_abi = ClaimAbi {
            total: 3,
            totalMax: 100,
            walletMax: 2,
            startDate: alloy_primitives::U256::from(1_700_000_000u64),
            endDate: alloy_primitives::U256::from(1_800_000_000u64),
            storageProtocol: 3,
            contractVersion: 1,
            identical: true,
            merkleRoot: alloy_primitives::B256::ZERO,
            location: "ipfs://abc".to_string(),
            cost: alloy_primitives::U256::from(1_000_000_000_000_000u64),
            paymentReceiver: address!("4444444444444444444444444444444444444444"),
            erc20: alloy_primitives::Address::ZERO,
            signingAddress: alloy_primitives::Address::ZERO,
        };
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_call",
                json!(format!(
                    "0x{}",
                    hex::encode(crate::protocol::manifold::getClaimCall::abi_encode_returns(
                        &claim_abi
                    ))
                )),
            )
            .build();
        let client = connect(transport).await;

        let stage = discover_manifold_stage(&client, extension, creator, instance_id, WALLET)
            .await
            .expect("a readable claim must produce a stage");
        assert_eq!(
            stage.id,
            StageId::ManifoldClaim {
                extension_contract: extension,
                creator_contract: creator,
                instance_id,
            }
        );
        assert_eq!(stage.eligibility, EligibilityState::Eligible);
    }

    #[tokio::test]
    async fn manifold_unreadable_claim_yields_no_stage() {
        let extension: alloy_primitives::Address =
            address!("5555555555555555555555555555555555555555");
        let creator: alloy_primitives::Address =
            address!("6666666666666666666666666666666666666666");
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .error("eth_call", -32000, "execution reverted")
            .build();
        let client = connect(transport).await;

        let stage = discover_manifold_stage(
            &client,
            extension,
            creator,
            alloy_primitives::U256::from(1u64),
            WALLET,
        )
        .await;
        assert!(stage.is_none());
    }
}
