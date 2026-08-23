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
            end: plan.stage_end,
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
                window: PhaseWindow { start, end },
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
                StageId::OnChainPublic => None,
            };
            (
                ResolvedEngine::OpenSea {
                    slug: slug.clone(),
                    stage_uuid,
                },
                "OpenSeaDropsAdapter",
            )
        }
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

/// Auto-discovery for Manifold `LazyPayableClaim` claims. **Deliberately
/// never attempts full auto-discovery** -- a claim needs three
/// identifiers (extension contract, creator contract, instance id), and
/// there is no verified on-chain enumeration of "which
/// `LazyPayableClaim` extensions are registered against this creator
/// contract" (Manifold's creator-contract extension registry was not
/// read/verified this pass -- see `protocol::manifold`'s module doc
/// comment for what was and wasn't verified). Inventing a discovery
/// heuristic here would repeat exactly the mistake this codebase already
/// corrected once for thirdweb: treating unverified compatibility as
/// proof.
///
/// This adapter only ever matches when the operator has *already*
/// supplied `--manifold-extension` (and, implicitly, `--collection` as
/// the creator contract, `--instance-id` as usual) alongside
/// `--engine auto` -- at that point every identifier is already known
/// exactly as it would be for explicit `--engine manifold`, and this
/// adapter's only remaining job is the same registry-provenance check
/// [`ThirdwebAdapter`] performs. Without `--manifold-extension`,
/// `detect()` returns `Ok(None)` unconditionally, every time -- never a
/// guess.
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
        let Some(extension_contract) = self.plan_args.manifold_extension else {
            return Ok(None);
        };
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

#[cfg(test)]
mod stage_identity_tests {
    use super::*;
    use time::macros::datetime;

    fn window() -> PhaseWindow {
        PhaseWindow {
            start: datetime!(2020-01-01 00:00:00 UTC),
            end: datetime!(2999-01-01 00:00:00 UTC),
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
