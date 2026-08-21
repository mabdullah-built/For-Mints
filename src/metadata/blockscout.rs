//! `BlockscoutProvider`: fetches verified contract source/ABI from a
//! public Blockscout v2 REST API instance
//! (`GET /api/v2/smart-contracts/{address}`). No API key, no
//! authentication -- verified directly against a live public instance
//! (`eth.blockscout.com`) during this pass: the endpoint is a plain
//! unauthenticated GET, and returns `is_verified`, `abi` (standard
//! Solidity ABI JSON, including parameter names when the source compiled
//! with them), `compiler_version`, `implementations` (for a resolved
//! proxy), and `proxy_type`.

use std::time::Duration;

use alloy_primitives::Address;
use serde::Deserialize;

use crate::chain::registry::ChainId;

use super::transport::{HttpMetadataTransport, MetadataTransport};
use super::{AbiEntry, MetadataError, VerifiedContractMetadata, VerifiedContractMetadataProvider};

/// Public Blockscout base URLs Kairox knows about. Robinhood Chain mainnet
/// (this pass's priority target, per its own official docs) is the only
/// one independently re-verified as a live, real Blockscout deployment
/// this pass (`https://robinhoodchain.blockscout.com`, confirmed live).
/// Ethereum's API *shape* (field names below) was independently verified
/// against a live response from `eth.blockscout.com` this pass. Base's
/// entry uses the same well-established public Blockscout subdomain
/// convention but was not separately queried this pass.
pub fn default_base_url_for_chain(chain_id: ChainId) -> Option<&'static str> {
    match chain_id {
        4663 => Some("https://robinhoodchain.blockscout.com"),
        1 => Some("https://eth.blockscout.com"),
        8453 => Some("https://base.blockscout.com"),
        _ => None,
    }
}

pub struct BlockscoutProvider {
    chain_id: ChainId,
    transport: Box<dyn MetadataTransport>,
}

impl BlockscoutProvider {
    /// Real HTTP provider for `chain_id`, using its default public
    /// Blockscout base URL. Returns `None` if no base URL is known for
    /// this chain -- callers should treat that as "no provider available",
    /// per this pass's rule that generic AUTO execution on such a chain
    /// requires a pre-registered trusted fingerprint instead.
    pub fn for_chain(chain_id: ChainId, timeout: Duration) -> Option<Self> {
        let base = default_base_url_for_chain(chain_id)?;
        let base_url = base.parse().expect("hardcoded base URLs are always valid");
        Some(Self {
            chain_id,
            transport: Box::new(HttpMetadataTransport::new(base_url, timeout)),
        })
    }

    /// For tests: an explicit transport (real or mocked) instead of a real
    /// HTTP client.
    pub fn with_transport(chain_id: ChainId, transport: Box<dyn MetadataTransport>) -> Self {
        Self {
            chain_id,
            transport,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SmartContractResponse {
    #[serde(default)]
    is_verified: bool,
    #[serde(default)]
    abi: Option<Vec<AbiEntry>>,
    #[serde(default)]
    compiler_version: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    proxy_type: Option<String>,
    #[serde(default)]
    implementations: Vec<ImplementationEntry>,
}

#[derive(Debug, Deserialize)]
struct ImplementationEntry {
    address: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
}

#[async_trait::async_trait]
impl VerifiedContractMetadataProvider for BlockscoutProvider {
    fn name(&self) -> &'static str {
        "Blockscout"
    }

    async fn fetch(&self, address: Address) -> Result<VerifiedContractMetadata, MetadataError> {
        let path = format!("/api/v2/smart-contracts/{address}");
        let response = self
            .transport
            .get(&path)
            .await
            .map_err(|e| MetadataError::Transport(e.to_string()))?;

        // A 404 (Blockscout hasn't indexed this address as a contract at
        // all, or it's an EOA) is exactly "not verified" -- not an error.
        if response.status == 404 {
            return Ok(VerifiedContractMetadata {
                chain_id: self.chain_id,
                address,
                source_verified: false,
                implementation: None,
                proxy_type: None,
                abi: Vec::new(),
                compiler_version: None,
                name: None,
                provider: self.name(),
            });
        }
        if response.status != 200 {
            return Err(MetadataError::Transport(format!(
                "Blockscout returned HTTP {}",
                response.status
            )));
        }

        let parsed: SmartContractResponse = serde_json::from_value(response.body)
            .map_err(|e| MetadataError::MalformedResponse(e.to_string()))?;

        let implementation = parsed
            .implementations
            .first()
            .and_then(|imp| imp.address.parse::<Address>().ok());

        Ok(VerifiedContractMetadata {
            chain_id: self.chain_id,
            address,
            source_verified: parsed.is_verified,
            implementation,
            proxy_type: parsed.proxy_type,
            abi: parsed.abi.unwrap_or_default(),
            compiler_version: parsed.compiler_version,
            name: parsed.name,
            provider: self.name(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::transport::{HttpResponse, MetadataTransportError};
    use serde_json::json;

    struct FakeTransport {
        status: u16,
        body: serde_json::Value,
    }

    #[async_trait::async_trait]
    impl MetadataTransport for FakeTransport {
        async fn get(&self, _path: &str) -> Result<HttpResponse, MetadataTransportError> {
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
    }

    fn addr() -> Address {
        Address::from([0x11; 20])
    }

    #[tokio::test]
    async fn parses_a_verified_contract_response() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 200,
                body: json!({
                    "is_verified": true,
                    "name": "TestCollection",
                    "compiler_version": "v0.8.20+commit.a1b79de6",
                    "proxy_type": null,
                    "implementations": [],
                    "abi": [
                        {"type": "function", "name": "mint", "stateMutability": "payable",
                         "inputs": [{"name": "quantity", "type": "uint256"}], "outputs": []}
                    ]
                }),
            }),
        );
        let metadata = provider.fetch(addr()).await.unwrap();
        assert!(metadata.source_verified);
        assert_eq!(metadata.name.as_deref(), Some("TestCollection"));
        assert_eq!(metadata.abi.len(), 1);
        assert_eq!(metadata.abi[0].inputs[0].name, "quantity");
    }

    #[tokio::test]
    async fn parses_an_unverified_contract_response() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 200,
                body: json!({"is_verified": false, "abi": null, "implementations": []}),
            }),
        );
        let metadata = provider.fetch(addr()).await.unwrap();
        assert!(!metadata.source_verified);
        assert!(metadata.abi.is_empty());
    }

    #[tokio::test]
    async fn a_404_is_reported_as_unverified_not_an_error() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 404,
                body: json!({}),
            }),
        );
        let metadata = provider.fetch(addr()).await.unwrap();
        assert!(!metadata.source_verified);
    }

    #[tokio::test]
    async fn a_server_error_is_a_real_error_not_silently_unverified() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 500,
                body: json!({}),
            }),
        );
        assert!(provider.fetch(addr()).await.is_err());
    }

    #[tokio::test]
    async fn malformed_response_is_an_error() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 200,
                body: json!("not an object"),
            }),
        );
        assert!(provider.fetch(addr()).await.is_err());
    }

    #[tokio::test]
    async fn resolves_a_proxy_implementation_address() {
        let provider = BlockscoutProvider::with_transport(
            1,
            Box::new(FakeTransport {
                status: 200,
                body: json!({
                    "is_verified": true,
                    "proxy_type": "eip1967",
                    "implementations": [{"address": "0x2222222222222222222222222222222222222222", "name": "Impl"}],
                    "abi": []
                }),
            }),
        );
        let metadata = provider.fetch(addr()).await.unwrap();
        assert_eq!(
            metadata.implementation,
            Some(Address::from([0x22; 20]))
        );
    }

    #[test]
    fn robinhood_chain_maps_to_the_verified_official_blockscout_url() {
        assert_eq!(
            default_base_url_for_chain(4663),
            Some("https://robinhoodchain.blockscout.com")
        );
    }
}
