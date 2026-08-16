//! Chain/RPC resolution shared by every CLI command that touches the
//! network.

use url::Url;

use crate::chain::config::{ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::registry::{ChainInfo, ChainRegistry};
use crate::chain::rpc::{HttpTransport, RpcClient};
use crate::execution::errors::{KairoxError, SessionError};

use super::args::ChainArgs;

pub struct ResolvedChain {
    pub info: ChainInfo,
    pub seadrop_contract: alloy_primitives::Address,
}

/// Resolve `--chain`/`--seadrop-contract` against the built-in chain
/// registry.
pub fn resolve_chain(
    registry: &ChainRegistry,
    args: &ChainArgs,
) -> Result<ResolvedChain, KairoxError> {
    let info = if let Ok(id) = args.chain.parse::<u64>() {
        registry.by_id(id)
    } else {
        registry.by_name(&args.chain)
    }
    .cloned()
    .ok_or_else(|| {
        KairoxError::Session(SessionError(format!(
            "unknown chain '{}'; known chains: {}",
            args.chain,
            registry
                .all()
                .iter()
                .map(|c| format!("{} ({})", c.name, c.chain_id))
                .collect::<Vec<_>>()
                .join(", ")
        )))
    })?;

    let seadrop_contract = args
        .seadrop_contract
        .or(info.default_seadrop_address)
        .ok_or_else(|| {
            KairoxError::Session(SessionError(format!(
                "no SeaDrop contract configured for chain '{}'; pass --seadrop-contract",
                info.name
            )))
        })?;

    Ok(ResolvedChain {
        info,
        seadrop_contract,
    })
}

/// Resolve which RPC endpoint to use: an explicit `--rpc-url` override, else
/// the first endpoint configured via `KAIROX_RPC_<chainId>_*` that permits
/// reads.
pub fn resolve_read_endpoint(
    chain: &ChainInfo,
    rpc_url_override: Option<&Url>,
) -> Result<RpcEndpoint, KairoxError> {
    if let Some(url) = rpc_url_override {
        return Ok(RpcEndpoint::new(url.clone(), EndpointRole::ReadWrite));
    }

    let endpoints = load_chain_endpoints(&ProcessEnv, chain.chain_id)?;
    endpoints.preferred_read_endpoint().cloned().ok_or_else(|| {
        KairoxError::Session(SessionError(format!(
            "no RPC endpoint configured for chain '{}' (chain id {}); pass --rpc-url or set KAIROX_RPC_{}_0_URL",
            chain.name, chain.chain_id, chain.chain_id
        )))
    })
}

/// Resolve an endpoint and connect a chain-id-verified [`RpcClient`] to it.
pub async fn connect_read_client(
    chain: &ChainInfo,
    rpc_url_override: Option<&Url>,
) -> Result<RpcClient, KairoxError> {
    let endpoint = resolve_read_endpoint(chain, rpc_url_override)?;
    let transport = HttpTransport::new(endpoint.url.clone(), endpoint.timeout);
    let client = RpcClient::connect(
        Box::new(transport),
        chain.chain_id,
        endpoint.role,
        endpoint.label.clone(),
    )
    .await?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_chain_by_name() {
        let registry = ChainRegistry::builtin();
        let args = ChainArgs {
            chain: "base".into(),
            rpc_url: None,
            seadrop_contract: None,
        };
        let resolved = resolve_chain(&registry, &args).unwrap();
        assert_eq!(resolved.info.chain_id, 8453);
    }

    #[test]
    fn resolve_chain_by_numeric_id() {
        let registry = ChainRegistry::builtin();
        let args = ChainArgs {
            chain: "4663".into(),
            rpc_url: None,
            seadrop_contract: None,
        };
        let resolved = resolve_chain(&registry, &args).unwrap();
        assert_eq!(resolved.info.name, "Robinhood Chain");
    }

    #[test]
    fn resolve_chain_rejects_unknown_chain() {
        let registry = ChainRegistry::builtin();
        let args = ChainArgs {
            chain: "not-a-chain".into(),
            rpc_url: None,
            seadrop_contract: None,
        };
        assert!(resolve_chain(&registry, &args).is_err());
    }

    #[test]
    fn resolve_chain_honors_seadrop_contract_override() {
        let registry = ChainRegistry::builtin();
        let custom = alloy_primitives::address!("0000000000000000000000000000000000012345");
        let args = ChainArgs {
            chain: "ethereum".into(),
            rpc_url: None,
            seadrop_contract: Some(custom),
        };
        let resolved = resolve_chain(&registry, &args).unwrap();
        assert_eq!(resolved.seadrop_contract, custom);
    }

    #[test]
    fn resolve_read_endpoint_uses_explicit_override() {
        let chain = ChainRegistry::builtin().by_id(1).unwrap().clone();
        let url = Url::parse("https://example.invalid").unwrap();
        let endpoint = resolve_read_endpoint(&chain, Some(&url)).unwrap();
        assert_eq!(endpoint.url, url);
    }

    #[test]
    fn resolve_read_endpoint_fails_without_config_or_override() {
        // NOTE: this test depends on no KAIROX_RPC_1_* variables being set
        // in the test process environment, which is true for a clean CI/dev run.
        let chain = ChainRegistry::builtin().by_id(1).unwrap().clone();
        assert!(resolve_read_endpoint(&chain, None).is_err());
    }
}
