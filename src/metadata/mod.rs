//! `VerifiedContractMetadataProvider`: fetches a contract's verified
//! source/ABI from a legitimate, public, unauthenticated block-explorer
//! API -- never a private/authenticated page, never bypassing an API key.
//!
//! The only implementation this pass ships is [`blockscout::BlockscoutProvider`],
//! against Blockscout's public v2 REST API
//! (`GET /api/v2/smart-contracts/{address}`), which requires no API key for
//! read access on any public Blockscout instance (verified directly
//! against a live instance -- see `docs/generic-engine.md`). Robinhood
//! Chain mainnet's own deployment (`robinhoodchain.blockscout.com`) is the
//! priority target per this pass's request; Ethereum and Base map to their
//! well-known public Blockscout subdomains as a secondary, lower-priority
//! convenience (only Ethereum's shape was independently re-verified this
//! pass against a live response; Base's is the same well-established
//! Blockscout API shape but wasn't separately queried).

pub mod blockscout;
pub mod transport;

use alloy_primitives::Address;
use serde::Deserialize;

use crate::chain::registry::ChainId;

/// One ABI entry's input/output parameter -- the human-readable `name`
/// (when the verified source compiled with it) is exactly the evidence
/// Kairox's semantic resolution ([`crate::execution::generic_semantics`])
/// depends on; an unnamed or oddly-named parameter is a signal semantics
/// are *not* independently established, not something to guess past.
#[derive(Debug, Clone, Deserialize)]
pub struct AbiParam {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<AbiParam>,
    #[serde(default)]
    pub outputs: Vec<AbiParam>,
    #[serde(default, rename = "stateMutability")]
    pub state_mutability: String,
}

impl AbiEntry {
    pub fn is_function(&self) -> bool {
        self.entry_type == "function"
    }
}

/// Structured evidence returned by a [`VerifiedContractMetadataProvider`].
/// `abi`/`implementation`/`runtime_bytecode_hash` are `None`/empty exactly
/// when the provider genuinely doesn't know them (e.g. an unverified
/// contract has no ABI) -- never a placeholder standing in for missing
/// data.
#[derive(Debug, Clone)]
pub struct VerifiedContractMetadata {
    pub chain_id: ChainId,
    pub address: Address,
    pub source_verified: bool,
    /// The EIP-1967 (or Blockscout-recognized proxy pattern) implementation
    /// address, if this is a proxy and Blockscout resolved it.
    pub implementation: Option<Address>,
    pub proxy_type: Option<String>,
    pub abi: Vec<AbiEntry>,
    pub compiler_version: Option<String>,
    pub name: Option<String>,
    pub provider: &'static str,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum MetadataError {
    #[error("no known verified-metadata provider is configured for chain id {0}")]
    NoProviderForChain(ChainId),
    #[error("metadata provider transport error: {0}")]
    Transport(String),
    #[error("metadata provider returned a malformed response: {0}")]
    MalformedResponse(String),
}

/// Fetches verified contract metadata from one specific source. Chain-aware
/// and swappable -- `resolve_provider_for_chain` picks the right
/// implementation for a given chain id, and nothing in the resolver
/// depends on `BlockscoutProvider` directly.
#[async_trait::async_trait]
pub trait VerifiedContractMetadataProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn fetch(&self, address: Address) -> Result<VerifiedContractMetadata, MetadataError>;
}
