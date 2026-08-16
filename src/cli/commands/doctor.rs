//! `kairox doctor` — environment inspection only. Never broadcasts.

use time::OffsetDateTime;

use crate::chain::config::{
    ProcessEnv, SIGNING_KEY_ENV_VAR, load_chain_endpoints, secret_env_var_present,
};
use crate::chain::registry::ChainRegistry;
use crate::chain::rpc::{HttpTransport, RpcClient};
use crate::cli::format::mask_url;

pub async fn run() {
    println!("Kairox v{}", crate::VERSION);
    println!("OS: {} ({})", std::env::consts::OS, std::env::consts::ARCH);
    println!("System UTC time: {}", OffsetDateTime::now_utc());
    println!();
    println!("Dry-run mode: ENABLED — Phase 1 has no transaction-broadcast path.");
    println!();

    let signing_key_configured =
        secret_env_var_present(&ProcessEnv, SIGNING_KEY_ENV_VAR).unwrap_or(false);
    println!(
        "Signing key configured: {} (not required in Phase 1; reserved for a later phase)",
        if signing_key_configured { "yes" } else { "no" }
    );
    println!();

    let registry = ChainRegistry::builtin();
    println!("Configured chains:");
    for chain in registry.all() {
        println!("  {} (chain id {})", chain.name, chain.chain_id);

        let endpoints = match load_chain_endpoints(&ProcessEnv, chain.chain_id) {
            Ok(endpoints) => endpoints,
            Err(e) => {
                println!("    RPC config error: {e}");
                continue;
            }
        };

        if endpoints.is_empty() {
            println!(
                "    RPC: not configured (set KAIROX_RPC_{}_0_URL, or pass --rpc-url per command)",
                chain.chain_id
            );
            continue;
        }

        for (i, endpoint) in endpoints.endpoints.iter().enumerate() {
            print!(
                "    RPC[{i}] {} role={:?} timeout={:?}",
                mask_url(&endpoint.url),
                endpoint.role,
                endpoint.timeout
            );
            let transport = HttpTransport::new(endpoint.url.clone(), endpoint.timeout);
            match RpcClient::connect(
                Box::new(transport),
                chain.chain_id,
                endpoint.role,
                endpoint.label.clone(),
            )
            .await
            {
                Ok(_client) => println!(" -> reachable, chainId={} MATCHES", chain.chain_id),
                Err(e) => println!(" -> UNREACHABLE or MISMATCHED: {e}"),
            }
        }
    }
}
