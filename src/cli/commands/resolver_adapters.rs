//! Concrete [`MintAdapter`] implementations for the two engines Kairox
//! actually has: native on-chain SeaDrop and the official OpenSea Drops
//! API. Both `mint --engine auto` and `watch --engine auto` build an
//! [`AdapterRegistry`] from these and call [`AdapterRegistry::resolve`]
//! instead of duplicating engine-selection logic -- see
//! `src/execution/resolver.rs` for the resolution hierarchy/ambiguity
//! rules these adapters plug into.
//!
//! A third adapter, `GenericVerifiedContractAdapter`, covers a schema the
//! operator explicitly declared (never guessed) and that on-chain ERC-165
//! corroborates. A registered launchpad adapter would plug in below that --
//! see `docs/generic-engine.md`/`docs/resolver-architecture.md` for why
//! that isn't added in this pass.

use std::path::Path;

use crate::cli::args::PlanArgs;
use crate::cli::context::{connect_read_client, resolve_chain_and_runtime};
use crate::domain::timing::StageStatus;
use crate::execution::errors::KairoxError;
use crate::execution::generic_schema::GenericMintSchema;
use crate::execution::resolver::{
    Confidence, Detection, MintAdapter, ProtocolEvidence, ResolvedEngine,
};

use super::plan::build_mint_plan;

/// Detects Kairox's native on-chain SeaDrop `PublicSeaDropEngine` route:
/// the collection's `getPublicDrop()` config is readable and its stage
/// hasn't ended. Priority 0 -- tried first, since it needs no off-chain
/// API and is independently verifiable from chain state alone.
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
        0
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

/// Detects the official OpenSea Drops API route. Kairox never discovers a
/// slug from unverified sources -- this only matches when the operator
/// explicitly supplied `--slug`, which is itself the evidence (an
/// operator-confirmed fact, not a guess). Priority 1 -- only tried once no
/// higher-priority (native on-chain) route matched.
pub struct OpenSeaDropsAdapter<'a> {
    pub slug: Option<&'a str>,
}

#[async_trait::async_trait]
impl MintAdapter for OpenSeaDropsAdapter<'_> {
    fn name(&self) -> &'static str {
        "OpenSeaDropsAdapter"
    }

    fn priority(&self) -> u8 {
        1
    }

    async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
        let Some(slug) = self.slug else {
            return Ok(None);
        };
        Ok(Some(Detection {
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
        }))
    }
}

/// Detects the generic verified ERC-721/ERC-1155 route.
///
/// **`Confidence::High` requires an exact
/// [`TrustedGenericFingerprint`](crate::execution::generic_registry::TrustedGenericFingerprint)
/// match** -- the target's (proxy-resolved) implementation bytecode hash
/// exactly equals a manually-reviewed registry entry's. That entry alone
/// carries the mint call semantics (selector, argument meanings, payable,
/// price) that get executed; an operator-supplied `--generic-schema`, if
/// also given, only ever acts as an optional maximum-price ceiling check
/// on top (see `execution::generic_engine::GenericMintRequest`).
///
/// An operator-declared `--generic-schema` plus ERC-165 confirmation
/// *alone* (no registry match) is **only ever `Confidence::Low`** and can
/// never resolve to a live-send path -- ERC-165 proves the NFT *standard*
/// a contract implements, never that any particular function selector
/// means what a schema claims, what its arguments mean, or what value it
/// expects. See `docs/generic-engine.md`'s "Confidence model" section.
///
/// Priority 2 -- only tried once neither native SeaDrop nor the OpenSea
/// Drops route matched.
pub struct GenericVerifiedContractAdapter<'a> {
    pub plan_args: &'a PlanArgs,
    pub config_path: Option<&'a Path>,
    pub schema: Option<&'a GenericMintSchema>,
    pub trusted_registry: &'a [crate::execution::generic_registry::TrustedGenericFingerprint],
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
                    fingerprint,
                    bytecode_hash,
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

        // No registry match. An operator-declared schema plus ERC-165 is
        // real evidence of *something* (the operator's intent, and that
        // the contract implements the claimed NFT standard), but it is
        // deliberately never enough to authorize a live-send path -- see
        // this adapter's doc comment.
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
                // Placeholder, never reachable: this branch always
                // carries `Confidence::Low`, and the resolver only ever
                // returns a `High`-confidence detection -- see
                // `AdapterRegistry::resolve`.
                fingerprint: crate::execution::generic_registry::TrustedGenericFingerprint {
                    name: "OPERATOR_DECLARED_UNVERIFIED_SCHEMA",
                    chain_id: resolved.info.chain_id,
                    implementation_bytecode_hash: bytecode_hash,
                    standard: schema.standard,
                    shape: schema.shape,
                    token_id: schema.token_id,
                    price_per_token_wei: 0,
                },
                bytecode_hash,
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
