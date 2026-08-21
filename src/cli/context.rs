//! Chain/RPC resolution shared by every CLI command that touches the
//! network. [`resolve_chain_and_runtime`] is the ONE place command-level
//! config/env/CLI precedence is decided -- individual commands never
//! re-implement that ordering themselves.

use url::Url;

use crate::chain::config::{ProcessEnv, load_chain_endpoints};
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};
use crate::chain::registry::{ChainInfo, ChainRegistry};
use crate::chain::rpc::{HttpTransport, RpcClient};
use crate::config::{KairoxConfig, ResolvedRuntimeConfig, resolve_chain_rpc_endpoints};
use crate::execution::errors::{KairoxError, SessionError, SessionErrorKind};

use super::args::ChainArgs;

pub struct ResolvedChain {
    pub info: ChainInfo,
    pub seadrop_contract: alloy_primitives::Address,
}

/// Resolve a chain (by name or numeric id) and its SeaDrop contract against
/// the built-in chain registry. `chain` is expected to already be the
/// fully precedence-resolved value (see [`resolve_chain_and_runtime`]).
pub fn resolve_chain(
    registry: &ChainRegistry,
    chain: &str,
    seadrop_override: Option<alloy_primitives::Address>,
) -> Result<ResolvedChain, KairoxError> {
    let info = if let Ok(id) = chain.parse::<u64>() {
        registry.by_id(id)
    } else {
        registry.by_name(chain)
    }
    .cloned()
    .ok_or_else(|| {
        KairoxError::Session(SessionError::new(format!(
            "unknown chain '{}'; known chains: {}",
            chain,
            registry
                .all()
                .iter()
                .map(|c| format!("{} ({})", c.name, c.chain_id))
                .collect::<Vec<_>>()
                .join(", ")
        )))
    })?;

    let seadrop_contract = seadrop_override
        .or(info.default_seadrop_address)
        .ok_or_else(|| {
            KairoxError::Session(SessionError::new(format!(
                "no SeaDrop contract configured for chain '{}'; pass --seadrop-contract",
                info.name
            )))
        })?;

    Ok(ResolvedChain {
        info,
        seadrop_contract,
    })
}

/// Resolve the effective config (per [`crate::config::resolve_runtime_config`])
/// and the chain it names, in one call. This is the single entry point
/// every network-touching command should use instead of calling
/// [`resolve_chain`] directly with a raw CLI string, so `--config`/
/// `KAIROX_CHAIN`/`defaults.chain` precedence is applied uniformly.
pub fn resolve_chain_and_runtime(
    registry: &ChainRegistry,
    chain_args: &ChainArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(ResolvedChain, ResolvedRuntimeConfig), KairoxError> {
    let runtime = crate::config::resolve_runtime_config(
        config_path,
        chain_args.chain.as_deref(),
        None,
        &ProcessEnv,
    )?;
    let resolved = resolve_chain(registry, &runtime.chain, chain_args.seadrop_contract)?;
    Ok((resolved, runtime))
}

/// Resolve which RPC endpoint to use for reads, in priority order: an
/// explicit `--rpc-url` override, else the first read-capable endpoint
/// named by the resolved config's `[chains.*].read_rpc_env`, else the
/// first endpoint configured via `KAIROX_RPC_<chainId>_*`.
pub fn resolve_read_endpoint(
    chain: &ChainInfo,
    rpc_url_override: Option<&Url>,
    config: Option<&KairoxConfig>,
) -> Result<RpcEndpoint, KairoxError> {
    if let Some(url) = rpc_url_override {
        return Ok(RpcEndpoint::new(url.clone(), EndpointRole::ReadWrite));
    }

    if let Some(config) = config
        && let Some(entry) = config_chain_entry(config, chain)
    {
        let endpoints = resolve_chain_rpc_endpoints(entry, &ProcessEnv)?;
        if let Some(endpoint) = endpoints
            .iter()
            .find(|e| e.role.can_read())
            .or_else(|| endpoints.first())
        {
            return Ok(endpoint.clone());
        }
    }

    let endpoints = load_chain_endpoints(&ProcessEnv, chain.chain_id)?;
    endpoints.preferred_read_endpoint().cloned().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::NoVerifiedReadRpc,
            format!(
                "no RPC endpoint configured for chain '{}' (chain id {}); pass --rpc-url, add a [chains.*] entry to your config, or set KAIROX_RPC_{}_0_URL",
                chain.name, chain.chain_id, chain.chain_id
            ),
        ))
    })
}

/// Find the config chain entry matching `chain`, by lowercase name or by
/// numeric chain id (config keys like `[chains.ethereum]` are names, not
/// ids -- matched case-insensitively against the chain's registry name).
fn config_chain_entry<'a>(
    config: &'a KairoxConfig,
    chain: &ChainInfo,
) -> Option<&'a crate::config::ChainConfigEntry> {
    config
        .chains
        .iter()
        .find(|(name, _)| {
            name.eq_ignore_ascii_case(chain.name) || **name == chain.chain_id.to_string()
        })
        .map(|(_, entry)| entry)
}

/// Resolve every endpoint the resolved config names for `chain` (both read
/// and send), or an empty list when there is no config, no matching
/// `[chains.*]` entry, or none of its named variables are actually set.
/// The ONE place `bench`/`mint`/`mint --wallet-manifest` look up
/// config-driven endpoint sets, so none of them re-implement this lookup.
/// Never errors: an unparseable URL in a config-named variable is reported
/// by `doctor`, not silently surfaced here as a fatal failure of an
/// unrelated command -- callers fall back to `KAIROX_RPC_*` when this
/// returns empty.
pub fn config_endpoints_for_chain(
    chain: &ChainInfo,
    config: Option<&KairoxConfig>,
) -> Vec<RpcEndpoint> {
    let Some(config) = config else {
        return Vec::new();
    };
    let Some(entry) = config_chain_entry(config, chain) else {
        return Vec::new();
    };
    resolve_chain_rpc_endpoints(entry, &ProcessEnv).unwrap_or_default()
}

/// Resolve an endpoint and connect a chain-id-verified [`RpcClient`] to it.
pub async fn connect_read_client(
    chain: &ChainInfo,
    rpc_url_override: Option<&Url>,
    config: Option<&KairoxConfig>,
) -> Result<RpcClient, KairoxError> {
    let endpoint = resolve_read_endpoint(chain, rpc_url_override, config)?;
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
        let resolved = resolve_chain(&registry, "base", None).unwrap();
        assert_eq!(resolved.info.chain_id, 8453);
    }

    #[test]
    fn resolve_chain_by_numeric_id() {
        let registry = ChainRegistry::builtin();
        let resolved = resolve_chain(&registry, "4663", None).unwrap();
        assert_eq!(resolved.info.name, "Robinhood Chain");
    }

    #[test]
    fn resolve_chain_rejects_unknown_chain() {
        let registry = ChainRegistry::builtin();
        assert!(resolve_chain(&registry, "not-a-chain", None).is_err());
    }

    #[test]
    fn resolve_chain_honors_seadrop_contract_override() {
        let registry = ChainRegistry::builtin();
        let custom = alloy_primitives::address!("0000000000000000000000000000000000012345");
        let resolved = resolve_chain(&registry, "ethereum", Some(custom)).unwrap();
        assert_eq!(resolved.seadrop_contract, custom);
    }

    #[test]
    fn resolve_read_endpoint_uses_explicit_override() {
        let chain = ChainRegistry::builtin().by_id(1).unwrap().clone();
        let url = Url::parse("https://example.invalid").unwrap();
        let endpoint = resolve_read_endpoint(&chain, Some(&url), None).unwrap();
        assert_eq!(endpoint.url, url);
    }

    #[test]
    fn resolve_read_endpoint_fails_without_config_or_override() {
        // NOTE: this test depends on no KAIROX_RPC_1_* variables being set
        // in the test process environment, which is true for a clean CI/dev run.
        let chain = ChainRegistry::builtin().by_id(1).unwrap().clone();
        assert!(resolve_read_endpoint(&chain, None, None).is_err());
    }

    #[test]
    fn resolve_chain_and_runtime_applies_config_default_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n[defaults]\nchain = \"base\"\n").unwrap();
        let registry = ChainRegistry::builtin();
        let chain_args = ChainArgs {
            chain: None,
            rpc_url: None,
            seadrop_contract: None,
        };
        let (resolved, runtime) =
            resolve_chain_and_runtime(&registry, &chain_args, Some(&path)).unwrap();
        assert_eq!(resolved.info.chain_id, 8453);
        assert_eq!(runtime.chain, "base");
    }

    #[test]
    fn resolve_chain_and_runtime_explicit_cli_chain_overrides_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n[defaults]\nchain = \"base\"\n").unwrap();
        let registry = ChainRegistry::builtin();
        let chain_args = ChainArgs {
            chain: Some("ethereum".into()),
            rpc_url: None,
            seadrop_contract: None,
        };
        let (resolved, runtime) =
            resolve_chain_and_runtime(&registry, &chain_args, Some(&path)).unwrap();
        assert_eq!(resolved.info.chain_id, 1);
        assert_eq!(runtime.chain, "ethereum");
    }

    #[test]
    fn resolve_read_endpoint_uses_config_named_env_var() {
        // Exercises the same "a config [chains.*] entry names an env var,
        // which is then read for its URL" logic that
        // `resolve_read_endpoint` delegates to, but through
        // `resolve_chain_rpc_endpoints` directly with an injected FakeEnv --
        // never mutating real process env, so this cannot race any other
        // test regardless of `cargo test` parallelism.
        let entry = crate::config::ChainConfigEntry {
            read_rpc_env: vec!["KAIROX_CONTEXT_TEST_READ_URL".into()],
            send_rpc_env: vec![],
        };
        let env = crate::chain::config::testing::FakeEnv(
            [(
                "KAIROX_CONTEXT_TEST_READ_URL".to_string(),
                "https://from-config.example".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let endpoints = crate::config::resolve_chain_rpc_endpoints(&entry, &env).unwrap();
        let endpoint = endpoints
            .iter()
            .find(|e| e.role.can_read())
            .expect("one read-capable endpoint from the config-named env var");
        assert_eq!(endpoint.url.as_str(), "https://from-config.example/");
    }
}
