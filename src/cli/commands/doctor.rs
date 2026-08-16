//! `kairox doctor` — environment inspection only. Never broadcasts.

use time::OffsetDateTime;

use crate::chain::config::{
    ProcessEnv, SIGNING_KEY_ENV_VAR, load_chain_endpoints, secret_env_var_present,
};
use crate::chain::pool::{ConnectOutcome, RpcPool};
use crate::chain::registry::ChainRegistry;
use crate::cli::format::mask_url;

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
            match &report.outcome {
                ConnectOutcome::Connected { latency_ms } => {
                    println!(
                        "    [{label}] {masked_url} role={:?} -> reachable in {latency_ms} ms, chainId MATCHES",
                        report.role
                    );
                }
                ConnectOutcome::Failed { latency_ms, error } => {
                    println!(
                        "    [{label}] {masked_url} role={:?} -> UNREACHABLE or MISMATCHED after {latency_ms} ms: {error}",
                        report.role
                    );
                }
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
