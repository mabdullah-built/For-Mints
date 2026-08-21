//! The mint-protocol resolver: turns "this collection, this wallet" into
//! exactly one confidently-recognized [`ResolvedEngine`], or refuses with
//! `UNSUPPORTED_PROTOCOL`/`AMBIGUOUS_PROTOCOL` rather than guessing.
//!
//! [`MintAdapter::detect`] is deliberately the *only* thing this module
//! asks an adapter to do. Real adapters ([`crate::cli::commands::resolver_adapters`])
//! wrap the two already-hardened, already-tested execution engines
//! ([`super::live::run_live_mint`], [`super::opensea_engine::run_opensea_mint`])
//! unchanged -- this module only decides *which* of them legitimately
//! applies, never how they sign/broadcast/verify. Nothing here constructs
//! calldata, calls `eth_estimateGas`, or touches a signer.
//!
//! Every adapter is tried, in registration order, and every match is
//! collected before a decision is made: exactly one `High`-confidence match
//! resolves; zero matches is `UnsupportedProtocol`; more than one match
//! (of any confidence) is `AmbiguousProtocol` -- the resolver never guesses
//! between two plausible protocols, and a `Low`-confidence match alone
//! never becomes a live-send path (see [`Confidence`]).

use super::errors::{KairoxError, SessionError, SessionErrorKind};

/// How trustworthy a [`MintAdapter`]'s detection is. Only [`Confidence::High`]
/// can resolve to a live engine on its own; a lone [`Confidence::Low`] match
/// is reported as `UNSUPPORTED_PROTOCOL` (with the low-confidence evidence
/// included in the error, so an operator can see *why* it wasn't enough)
/// rather than silently activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Low,
}

/// Why an adapter believes its protocol applies. Every field is filled with
/// real, checkable facts -- never invented to make a match look stronger
/// than it is.
#[derive(Debug, Clone)]
pub struct ProtocolEvidence {
    /// Human-readable description of what was actually checked, e.g.
    /// "on-chain SeaDrop PublicDrop config readable and not ended".
    pub source: String,
    pub confidence: Confidence,
    /// The adapter name that produced this evidence.
    pub adapter: &'static str,
    /// Any ERC-165/known interfaces this evidence matched. Empty when the
    /// adapter's detection method doesn't involve interface checks (e.g.
    /// the OpenSea Drops adapter, which is off-chain-API-based).
    pub matched_interfaces: Vec<String>,
    /// Any function selectors this evidence matched.
    pub matched_selectors: Vec<String>,
}

/// Exactly one concrete engine a caller can execute against. Intentionally
/// only the two engines Kairox actually implements today -- see
/// `docs/resolver-architecture.md` for what a future
/// `GenericVerifiedContractEngine`/launchpad-adapter addition would extend
/// this with, and why none is added in this pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedEngine {
    Public,
    OpenSea {
        slug: String,
    },
    /// A generic verified ERC-721/ERC-1155 mint -- only ever produced when
    /// the target's implementation bytecode exactly matched a
    /// manually-reviewed [`super::generic_registry::TrustedGenericFingerprint`],
    /// or when verified source (via a
    /// [`crate::metadata::VerifiedContractMetadataProvider`]) semantically
    /// resolved to exactly one unambiguous mint function (see
    /// `cli::commands::resolver_adapters::GenericVerifiedContractAdapter`).
    /// An operator-declared `--generic-schema` alone can never produce
    /// this variant -- see `docs/generic-engine.md`'s "Confidence model".
    Generic {
        target: super::generic_engine::ResolvedGenericTarget,
    },
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub engine: ResolvedEngine,
    pub evidence: ProtocolEvidence,
}

/// Detects whether one protocol/route legitimately applies to a target.
/// Implemented once per real engine ([`crate::cli::commands::resolver_adapters`]);
/// a fake implementation drives this module's own deterministic unit tests.
#[async_trait::async_trait]
pub trait MintAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    /// This adapter's position in the resolution hierarchy -- lower runs
    /// first. Adapters sharing a priority are peers: if more than one of
    /// them matches, that is a genuine ambiguity, not a fallback. Adapters
    /// at different priorities are a hierarchy: a lower-priority adapter is
    /// never even asked once a higher-priority tier already matched. This
    /// mirrors "native SeaDrop, then the official OpenSea Drops route,
    /// then ..." rather than treating every route as equally authoritative.
    fn priority(&self) -> u8;
    async fn detect(&self) -> Result<Option<Detection>, KairoxError>;
}

/// Tries registered adapters tier by tier (ascending `priority()`), stops
/// at the first tier that produces any match, and returns that tier's
/// unique high-confidence match -- or a fail-closed
/// `UNSUPPORTED_PROTOCOL`/`AMBIGUOUS_PROTOCOL` error. Never falls back past
/// a tier that matched, and never picks between two same-tier matches.
pub struct AdapterRegistry<'a> {
    adapters: Vec<Box<dyn MintAdapter + 'a>>,
}

impl<'a> AdapterRegistry<'a> {
    pub fn new(adapters: Vec<Box<dyn MintAdapter + 'a>>) -> Self {
        Self { adapters }
    }

    pub async fn resolve(&self) -> Result<Detection, KairoxError> {
        let mut ordered: Vec<&Box<dyn MintAdapter + 'a>> = self.adapters.iter().collect();
        ordered.sort_by_key(|a| a.priority());

        let mut tried = Vec::new();
        let mut low_confidence_seen = Vec::new();
        let mut idx = 0;
        while idx < ordered.len() {
            let tier = ordered[idx].priority();
            let mut tier_matches = Vec::new();
            while idx < ordered.len() && ordered[idx].priority() == tier {
                let adapter = ordered[idx];
                tried.push(adapter.name());
                if let Some(detection) = adapter.detect().await? {
                    match detection.evidence.confidence {
                        Confidence::High => tier_matches.push(detection),
                        Confidence::Low => low_confidence_seen.push(detection),
                    }
                }
                idx += 1;
            }
            match tier_matches.len() {
                0 => continue,
                1 => return Ok(tier_matches.into_iter().next().expect("len == 1")),
                _ => {
                    return Err(KairoxError::Session(SessionError::with_kind(
                        SessionErrorKind::AmbiguousProtocol,
                        format!(
                            "more than one protocol matched with equal, high-confidence \
                             priority ({}); refusing to guess which is authoritative",
                            tier_matches
                                .iter()
                                .map(|d| d.evidence.adapter)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )));
                }
            }
        }

        if low_confidence_seen.is_empty() {
            Err(KairoxError::Session(SessionError::with_kind(
                SessionErrorKind::UnsupportedProtocol,
                format!(
                    "no supported mint protocol/route was confidently detected for this \
                     target; adapters tried: {}",
                    tried.join(", ")
                ),
            )))
        } else {
            Err(KairoxError::Session(SessionError::with_kind(
                SessionErrorKind::UnsupportedProtocol,
                format!(
                    "only low-confidence evidence was found ({}); refusing to arm a live-send \
                     path on unconfirmed evidence",
                    low_confidence_seen
                        .iter()
                        .map(|d| format!("{}: {}", d.evidence.adapter, d.evidence.source))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeAdapter {
        name: &'static str,
        priority: u8,
        result: Option<Detection>,
    }

    #[async_trait::async_trait]
    impl MintAdapter for FakeAdapter {
        fn name(&self) -> &'static str {
            self.name
        }
        fn priority(&self) -> u8 {
            self.priority
        }
        async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
            Ok(self.result.clone())
        }
    }

    fn evidence(adapter: &'static str, confidence: Confidence) -> ProtocolEvidence {
        ProtocolEvidence {
            source: "test evidence".to_string(),
            confidence,
            adapter,
            matched_interfaces: vec![],
            matched_selectors: vec![],
        }
    }

    #[tokio::test]
    async fn single_high_confidence_match_resolves() {
        let registry = AdapterRegistry::new(vec![Box::new(FakeAdapter {
            name: "SeaDropAdapter",
            priority: 0,
            result: Some(Detection {
                engine: ResolvedEngine::Public,
                evidence: evidence("SeaDropAdapter", Confidence::High),
            }),
        })]);
        let result = registry.resolve().await;
        assert!(matches!(
            result,
            Ok(Detection {
                engine: ResolvedEngine::Public,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn no_match_is_unsupported_protocol() {
        let registry = AdapterRegistry::new(vec![Box::new(FakeAdapter {
            name: "SeaDropAdapter",
            priority: 0,
            result: None,
        })]);
        let err = registry.resolve().await.unwrap_err();
        assert_eq!(err.code().to_string(), "UNSUPPORTED_PROTOCOL");
    }

    #[tokio::test]
    async fn low_confidence_alone_never_resolves() {
        let registry = AdapterRegistry::new(vec![Box::new(FakeAdapter {
            name: "GenericAdapter",
            priority: 0,
            result: Some(Detection {
                engine: ResolvedEngine::Public,
                evidence: evidence("GenericAdapter", Confidence::Low),
            }),
        })]);
        let err = registry.resolve().await.unwrap_err();
        assert_eq!(err.code().to_string(), "UNSUPPORTED_PROTOCOL");
    }

    #[tokio::test]
    async fn two_same_tier_high_confidence_matches_is_ambiguous_not_a_guess() {
        let registry = AdapterRegistry::new(vec![
            Box::new(FakeAdapter {
                name: "AdapterA",
                priority: 0,
                result: Some(Detection {
                    engine: ResolvedEngine::Public,
                    evidence: evidence("AdapterA", Confidence::High),
                }),
            }),
            Box::new(FakeAdapter {
                name: "AdapterB",
                priority: 0,
                result: Some(Detection {
                    engine: ResolvedEngine::OpenSea {
                        slug: "x".to_string(),
                    },
                    evidence: evidence("AdapterB", Confidence::High),
                }),
            }),
        ]);
        let err = registry.resolve().await.unwrap_err();
        assert_eq!(err.code().to_string(), "AMBIGUOUS_PROTOCOL");
    }

    #[tokio::test]
    async fn higher_priority_tier_match_short_circuits_lower_tier_adapters() {
        // A lower-priority (larger number) match existing alongside a
        // higher-priority (smaller number) match must never trigger
        // AMBIGUOUS_PROTOCOL -- this is the "native SeaDrop first, OpenSea
        // Drops as fallback" hierarchy, not a tie.
        let registry = AdapterRegistry::new(vec![
            Box::new(FakeAdapter {
                name: "SeaDropAdapter",
                priority: 0,
                result: Some(Detection {
                    engine: ResolvedEngine::Public,
                    evidence: evidence("SeaDropAdapter", Confidence::High),
                }),
            }),
            Box::new(FakeAdapter {
                name: "OpenSeaDropsAdapter",
                priority: 1,
                result: Some(Detection {
                    engine: ResolvedEngine::OpenSea {
                        slug: "x".to_string(),
                    },
                    evidence: evidence("OpenSeaDropsAdapter", Confidence::High),
                }),
            }),
        ]);
        let result = registry.resolve().await.unwrap();
        assert_eq!(result.evidence.adapter, "SeaDropAdapter");
    }

    #[tokio::test]
    async fn adapter_error_propagates_instead_of_being_swallowed() {
        struct FailingAdapter;
        #[async_trait::async_trait]
        impl MintAdapter for FailingAdapter {
            fn name(&self) -> &'static str {
                "FailingAdapter"
            }
            fn priority(&self) -> u8 {
                0
            }
            async fn detect(&self) -> Result<Option<Detection>, KairoxError> {
                Err(KairoxError::Session(SessionError::new("transport failed")))
            }
        }
        let registry = AdapterRegistry::new(vec![Box::new(FailingAdapter)]);
        assert!(registry.resolve().await.is_err());
    }
}
