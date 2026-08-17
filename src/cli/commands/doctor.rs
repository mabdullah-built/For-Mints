//! `kairox doctor` — environment inspection only. Never broadcasts.

use time::OffsetDateTime;

use crate::chain::config::{
    ProcessEnv, SIGNING_KEY_ENV_VAR, load_chain_endpoints, secret_env_var_present,
};
use crate::chain::pool::RpcPool;
use crate::chain::registry::ChainRegistry;
use crate::cli::format::{format_endpoint_status, mask_url};
use crate::opensea::client::OPENSEA_API_KEY_ENV;

pub async fn run() {
    println!("Kairox v{}", crate::VERSION);
    println!("OS: {} ({})", std::env::consts::OS, std::env::consts::ARCH);
    println!("System UTC time: {}", OffsetDateTime::now_utc());
    println!();
    println!("Dry-run mode: DEFAULT — `mint` only broadcasts with --send (plus confirmation).");
    println!();

    let signing_key_configured =
        secret_env_var_present(&ProcessEnv, SIGNING_KEY_ENV_VAR).unwrap_or(false);
    println!(
        "Signing key configured: {} (only read for `mint --send`; never logged)",
        if signing_key_configured { "yes" } else { "no" }
    );

    let opensea_api_key_configured =
        secret_env_var_present(&ProcessEnv, OPENSEA_API_KEY_ENV).unwrap_or(false);
    println!(
        "OpenSea API key configured: {} (only used for --engine opensea; never logged)",
        if opensea_api_key_configured {
            "yes"
        } else {
            "no"
        }
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

        println!("    endpoint count: {}", endpoints.endpoints.len());
        let (pool, reports) = RpcPool::connect_all(chain.chain_id, &endpoints.endpoints).await;
        for (endpoint, report) in endpoints.endpoints.iter().zip(reports.iter()) {
            let label = report
                .label
                .clone()
                .unwrap_or_else(|| "(unlabeled)".to_string());
            let masked_url = mask_url(&endpoint.url);
            let block = format_endpoint_status(
                &label,
                &masked_url,
                report.role,
                chain.chain_id,
                &report.outcome,
            );
            for line in block.lines() {
                println!("    {line}");
            }
        }
        println!(
            "    summary: {}/{} connected, {} read-capable, {} send-capable",
            pool.len(),
            endpoints.endpoints.len(),
            pool.read_capable().len(),
            pool.send_capable().len()
        );
    }
}
