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
use crate::domain::stage::{EligibilityState, NormalizedStage, StageProtocol};
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
async fn discover_public_stage(
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
        id: "on-chain-public".to_string(),
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

/// Discovers every OpenSea-hosted non-public stage worth considering (the
/// currently-active one, and -- when `allow_not_yet_started` -- the
/// upcoming one) as [`NormalizedStage`] entries. A plain public OpenSea
/// stage is never included here: the cheaper, dependency-free native
/// route covers that case when one exists, and
/// [`crate::opensea::models::map_stage_type`] never even maps a
/// `"public"`-shaped wire value (see its doc comment).
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

    // Auto-discovery is a best-effort enhancement, never a hard
    // requirement: any error here (OpenSea down, rate-limited,
    // misconfigured key) is deliberately treated the same as "no drop
    // discovered", never propagated -- a collection with a working
    // native on-chain public stage must not be blocked by OpenSea's
    // availability.
    let details = match crate::opensea::discovery::resolve_drop(
        opensea,
        chain_identifier,
        plan_args.collection,
    )
    .await
    {
        Ok(Some(details)) => details,
        Ok(None) | Err(_) => return Ok(Vec::new()),
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
                id: details.collection_slug.clone(),
                protocol,
                label: stage.label.clone(),
                window: PhaseWindow { start, end },
                price_per_token_wei: stage
                    .price
                    .as_ref()
                    .and_then(|p| p.parse::<alloy_primitives::U256>().ok()),
                max_per_wallet: stage.max_per_wallet.parse::<u64>().ok(),
                // Genuinely unknown until a real, fresh, wallet-specific
                // OpenSea authorization is requested -- never assumed
                // zero/unused. See EligibilityState::UnknownUntilActive
                // below.
                wallet_minted: None,
                supply_remaining: None,
                eligibility: EligibilityState::UnknownUntilActive,
                evidence: format!(
                    "auto-discovered OpenSea drop {:?}: stage {:?} (recognized as {protocol:?})",
                    details.collection_slug, stage.stage_type
                ),
            })
        })
        .collect())
}

fn stage_to_detection(stage: &NormalizedStage) -> Detection {
    let (engine, adapter) = match stage.protocol {
        StageProtocol::Public => (ResolvedEngine::Public, "SeaDropAdapter"),
        _ => (
            ResolvedEngine::OpenSea {
                slug: stage.id.clone(),
            },
            "OpenSeaDropsAdapter",
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
    /// A stage id (`NormalizedStage::id` -- an OpenSea slug for an
    /// off-chain stage) to exclude from selection entirely, as if it had
    /// never been discovered. Set by `watch`'s re-resolution loop after a
    /// fresh, semantically clear OpenSea eligibility rejection at T0 for
    /// that exact stage -- so the same known-ineligible stage is never
    /// selected again, and a later legitimately-supported stage (e.g. an
    /// on-chain public stage) gets a real chance. `None` (the normal
    /// case, and always the case for `mint`) excludes nothing.
    pub excluded_stage_id: Option<&'a str>,
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
        if let Some(excluded) = self.excluded_stage_id {
            stages.retain(|s| s.id != excluded);
        }

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
