//! Concrete [`MintAdapter`] implementations for the two engines Kairox
//! actually has: native on-chain SeaDrop and the official OpenSea Drops
//! API. Both `mint --engine auto` and `watch --engine auto` build an
//! [`AdapterRegistry`] from these and call [`AdapterRegistry::resolve`]
//! instead of duplicating engine-selection logic -- see
//! `src/execution/resolver.rs` for the resolution hierarchy/ambiguity
//! rules these adapters plug into.
//!
//! [`OpenSeaDropsAdapter`] is tried *before* [`SeaDropAdapter`] (priority 0
//! vs 1): a currently-active, OpenSea-recognized non-public stage
//! (signed-presale/allowlist/FCFS/FCFA) always outranks a later on-chain
//! public stage the wallet might also technically satisfy -- this is the
//! real class of mistake an explicit `--engine public` reproduced in
//! practice (an active eligible signed presale existed, but the
//! explicit-engine command wound up waiting for a later public stage
//! instead). [`OpenSeaDropsAdapter`] only matches on a *plain public*
//! active stage (or no active stage at all) by returning `None`, at which
//! point the registry falls through to [`SeaDropAdapter`] automatically --
//! never triggering `AmbiguousProtocol`, since a tier with zero matches is
//! simply skipped.
//!
//! A third adapter, `GenericVerifiedContractAdapter`, covers a schema the
//! operator explicitly declared (never guessed) and that on-chain ERC-165
//! corroborates. A registered launchpad adapter would plug in below that --
//! see `docs/generic-engine.md`/`docs/resolver-architecture.md` for why
//! that isn't added in this pass.

use std::path::Path;

use crate::cli::args::PlanArgs;
use crate::cli::context::{connect_read_client, resolve_chain_and_runtime};
use crate::domain::stage::StageProtocol;
use crate::domain::timing::StageStatus;
use crate::execution::errors::KairoxError;
use crate::execution::generic_schema::GenericMintSchema;
use crate::execution::resolver::{
    Confidence, Detection, MintAdapter, ProtocolEvidence, ResolvedEngine,
};

use super::plan::build_mint_plan;

/// Detects Kairox's native on-chain SeaDrop `PublicSeaDropEngine` route:
/// the collection's `getPublicDrop()` config is readable and its stage
/// hasn't ended. Priority 1 -- tried only once [`OpenSeaDropsAdapter`]
/// (priority 0) found no currently-active *non-public* OpenSea stage; see
/// this module's docs for why.
pub struct SeaDropAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    /// `mint --send` wants an already-`Active` stage (an operator running
    /// it right now expects to broadcast immediately); `watch` also
    /// accepts `NotStarted` (that's exactly the stage it waits through).
    pub allow_not_yet_started: bool,
}

#[async_trait::async_trait]
impl MintAdapter for SeaDropAdapter<'_> {
    fn name(&self) -> &'static str {
        "SeaDropAdapter"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        let plan = match build_mint_plan(self.plan_args, self.config_path).await {
            Ok(plan) => plan,
            // Only a genuine on-chain call/decode failure (a revert
            // response or a return shape that doesn't decode as
            // PublicDrop) is the expected signal that this contract isn't
            // a SeaDrop collection -- treated as "no match", not
            // propagated, so an unrelated ERC-721 doesn't abort resolution
            // outright. Anything else (no RPC configured, a bad config
            // file, wrong chain, transport timeout/network failure) is a
            // real infrastructure problem that has nothing to do with
            // which protocol the contract implements, and must surface as
            // itself rather than being misreported as
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

        let matched = matches!(
            (plan.stage_status, self.allow_not_yet_started),
            (StageStatus::Active { .. }, _) | (StageStatus::NotStarted { .. }, true)
        );
        if !matched {
            return Ok(None);
        }

        Ok(Some(Detection {
            engine: ResolvedEngine::Public,
            evidence: ProtocolEvidence {
                source: format!(
                    "on-chain SeaDrop PublicDrop config read from {} (stage {:?})",
                    self.plan_args.collection, plan.stage_status
                ),
                confidence: Confidence::High,
                adapter: "SeaDropAdapter",
                matched_interfaces: vec!["ISeaDropTokenContractMetadata".to_string()],
                matched_selectors: vec!["getPublicDrop()".to_string()],
            },
        }))
    }
}

/// Detects the official OpenSea Drops API route, in order:
///
/// 1. **Operator-provided `--slug`**: always matches outright -- an
///    operator-confirmed fact, not a guess.
/// 2. **Automatic slug discovery**: when `--slug` was not given and an
///    [`OpenSeaClient`] is available (an OpenSea API key is configured --
///    auto-discovery is best-effort, never a hard requirement), resolves
///    the collection's OpenSea drop via
///    [`crate::opensea::discovery::resolve_drop`] (which independently
///    verifies any candidate slug against the drop's own reported contract
///    address before trusting it -- see that module's docs). Matches only
///    when the drop reports a currently-active stage whose
///    `stage_type` is recognized ([`crate::opensea::models::map_stage_type`])
///    as something *other than* plain [`StageProtocol::Public`] -- a plain
///    public stage is left to [`SeaDropAdapter`], which needs no off-chain
///    dependency for it. Any OpenSea transport/auth/server error, or an
///    unrecognized `stage_type`, is treated identically to "no match" --
///    never propagated as a hard failure, so OpenSea being unreachable can
///    never block a collection whose native on-chain public stage still
///    works.
///
/// Priority 0 -- see this module's docs for why this is tried *before*
/// [`SeaDropAdapter`].
pub struct OpenSeaDropsAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub slug: Option<&'a str>,
    pub opensea: Option<&'a crate::opensea::client::OpenSeaClient>,
    /// `watch` (`true`) also matches a currently-*upcoming*
    /// (`next_stage`, not yet started) non-public stage, so it can
    /// auto-discover a future signed presale to wait for -- exactly the
    /// same distinction [`SeaDropAdapter::allow_not_yet_started`] makes
    /// for the native route. `mint` (`false`) only ever matches an
    /// already-active stage, since it means "act now".
    pub allow_not_yet_started: bool,
}

#[async_trait::async_trait]
impl MintAdapter for OpenSeaDropsAdapter<'_> {
    fn name(&self) -> &'static str {
        "OpenSeaDropsAdapter"
    }

    fn priority(&self) -> u8 {
        0
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
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

        let Some(opensea) = self.opensea else {
            return Ok(None);
        };
        let registry = crate::chain::registry::ChainRegistry::builtin();
        let (resolved, _runtime) =
            resolve_chain_and_runtime(&registry, &self.plan_args.chain_args, self.config_path)?;
        let Some(chain_identifier) =
            crate::opensea::models::opensea_chain_identifier(resolved.info.chain_id)
        else {
            return Ok(None);
        };

        // Auto-discovery is a best-effort enhancement, never a hard
        // requirement: any error here (OpenSea down, rate-limited,
        // misconfigured key) is deliberately treated the same as "no
        // drop discovered", never propagated -- a collection with a
        // working native on-chain public stage must not be blocked by
        // OpenSea's availability. See this struct's docs.
        let details = match crate::opensea::discovery::resolve_drop(
            opensea,
            chain_identifier,
            self.plan_args.collection,
        )
        .await
        {
            Ok(Some(details)) => details,
            Ok(None) | Err(_) => return Ok(None),
        };

        // An already-active non-public stage always wins outright,
        // whether called from `mint` or `watch`. `map_stage_type` only
        // ever returns a non-public protocol today (see its doc comment
        // for why "public" was removed as unverified) -- the explicit
        // `!= Public` check is kept as defense in depth for if/when a
        // `Public`-mapping wire value is independently re-verified and
        // added back.
        if let Some(stage) = details.active_stage.as_ref()
            && let Some(protocol) = crate::opensea::models::map_stage_type(&stage.stage_type)
            && protocol != StageProtocol::Public
        {
            return Ok(Some(auto_discovered_detection(
                &details.collection_slug,
                stage,
                protocol,
                "active",
            )));
        }

        // `watch` also considers a genuinely *upcoming* non-public stage
        // -- OpenSea's own `next_stage` -- so it can discover a future
        // signed presale to wait for instead of falling through to a
        // later native public stage. `mint` never does: it means "act
        // now", and a stage that has not opened yet is never a match for
        // it.
        if self.allow_not_yet_started
            && let Some(stage) = details.next_stage.as_ref()
            && let Some(protocol) = crate::opensea::models::map_stage_type(&stage.stage_type)
            && protocol != StageProtocol::Public
        {
            return Ok(Some(auto_discovered_detection(
                &details.collection_slug,
                stage,
                protocol,
                "upcoming",
            )));
        }

        Ok(None)
    }
}

fn auto_discovered_detection(
    slug: &str,
    stage: &crate::opensea::models::DropStageResponse,
    protocol: StageProtocol,
    timing: &str,
) -> Detection {
    Detection {
        engine: ResolvedEngine::OpenSea {
            slug: slug.to_string(),
        },
        evidence: ProtocolEvidence {
            source: format!(
                "auto-discovered OpenSea drop {slug:?}: {timing} stage {:?} (recognized as {protocol:?})",
                stage.stage_type
            ),
            confidence: Confidence::High,
            adapter: "OpenSeaDropsAdapter",
            matched_interfaces: vec![],
            matched_selectors: vec![],
        },
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
/// Priority 2 -- only tried once neither native SeaDrop nor the OpenSea
/// Drops route matched.
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
        2
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
