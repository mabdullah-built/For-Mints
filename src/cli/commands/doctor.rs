//! `kairox doctor` — environment inspection only. Never broadcasts.

use serde::Serialize;
use time::OffsetDateTime;

use crate::chain::config::{
    ProcessEnv, SIGNING_KEY_ENV_VAR, load_chain_endpoints, secret_env_var_present,
};
use crate::chain::pool::RpcPool;
use crate::chain::registry::ChainRegistry;
use crate::cli::args::DoctorArgs;
use crate::cli::format::{format_endpoint_status, mask_url};
use crate::config::resolve_config_path;
use crate::opensea::client::OPENSEA_API_KEY_ENV;

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    kairox_version: String,
    os: String,
    arch: String,
    utc_time: String,
    dry_run_default: bool,
    signing_key_configured: bool,
    opensea_api_key_configured: bool,
    config_path: Option<String>,
    config_status: String,
    chains: Vec<ChainReport>,
}

#[derive(Debug, Serialize)]
struct ChainReport {
    name: String,
    chain_id: u64,
    status: String,
    endpoint_count: usize,
    connected_count: usize,
    read_capable_count: usize,
    send_capable_count: usize,
    /// Human-readable per-endpoint detail lines. Present in JSON mode too
    /// (kept simple rather than hidden), but `doctor`'s JSON schema treats
    /// this as an opaque diagnostic array, not a field callers should
    /// parse structurally.
    endpoint_details: Vec<String>,
    /// `None` for a chain with no `op_stack_gas_price_oracle` configured
    /// (every chain except Ink today) -- never populated, never
    /// misleadingly "checked: false". For Ink, a live, read-only,
    /// best-effort summary of the `GasPriceOracle`'s reported upgrade
    /// state (`isEcotone`/`isFjord`/`isIsthmus`/`isJovian`), or an
    /// explicit failure message if the oracle could not be read -- never
    /// silently omitted, since Kairox's fee-bounding logic depends on
    /// exactly this state being genuinely live and current (see
    /// `execution::op_stack_fees`).
    op_stack_fee_oracle_status: Option<String>,
}

/// `--json` mode must emit ONLY the JSON object on stdout -- gathering is
/// therefore side-effect-free (no `println!`), and text rendering is a
/// separate step applied only in human mode.
pub async fn run(args: DoctorArgs, config_path: Option<&std::path::Path>) {
    let report = gather(config_path).await;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("DoctorReport is always serializable")
        );
        return;
    }

    print_human(&report);
}

fn print_human(report: &DoctorReport) {
    println!("Kairox v{}", report.kairox_version);
    println!("OS: {} ({})", report.os, report.arch);
    println!("System UTC time: {}", report.utc_time);
    println!();
    println!("Dry-run mode: DEFAULT — `mint` only broadcasts with --send (plus confirmation).");
    println!();

    println!(
        "Signing key configured: {} (only read for `mint --send`; never logged)",
        if report.signing_key_configured {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "OpenSea API key configured: {} (only used for --engine opensea; never logged)",
        if report.opensea_api_key_configured {
            "yes"
        } else {
            "no"
        }
    );
    println!();

    match &report.config_path {
        Some(path) => println!("Config file: {path} [{}]", report.config_status),
        None => println!(
            "Config file: none (pass --config, set KAIROX_CONFIG, or run `kairox init`) [{}]",
            report.config_status
        ),
    }
    println!();

    println!("Configured chains:");
    for chain in &report.chains {
        println!(
            "  {} (chain id {}) [{}]",
            chain.name, chain.chain_id, chain.status
        );
        if chain.endpoint_count == 0 {
            println!(
                "    RPC: not configured (set KAIROX_RPC_{}_0_URL, or pass --rpc-url per command)",
                chain.chain_id
            );
            continue;
        }
        for line in &chain.endpoint_details {
            println!("    {line}");
        }
        println!(
            "    summary: {}/{} connected, {} read-capable, {} send-capable",
            chain.connected_count,
            chain.endpoint_count,
            chain.read_capable_count,
            chain.send_capable_count
        );
    }
}

/// Read-only, best-effort summary of an OP Stack `GasPriceOracle`'s
/// reported upgrade state -- purely diagnostic (never used to authorize
/// anything; the actual pre-sign fee bound in
/// `execution::op_stack_fees` always re-reads live, independent of this
/// output). Requires `isFjord` specifically, since
/// `getL1FeeUpperBound` (the method Kairox's fee bound uses) itself
/// requires it and reverts otherwise -- surfacing that clearly here
/// rather than only as an opaque failure deep in a live `mint --send`.
async fn read_op_stack_fee_oracle_status(
    client: &crate::chain::rpc::RpcClient,
    oracle: alloy_primitives::Address,
) -> Result<String, crate::chain::rpc::RpcError> {
    use crate::protocol::op_stack;
    use alloy_sol_types::SolCall;

    let is_fjord_calldata: alloy_primitives::Bytes = op_stack::isFjordCall {}.abi_encode().into();
    let is_isthmus_calldata: alloy_primitives::Bytes =
        op_stack::isIsthmusCall {}.abi_encode().into();
    let is_jovian_calldata: alloy_primitives::Bytes = op_stack::isJovianCall {}.abi_encode().into();
    let (fjord_raw, isthmus_raw, jovian_raw) = tokio::try_join!(
        client.eth_call(oracle, &is_fjord_calldata),
        client.eth_call(oracle, &is_isthmus_calldata),
        client.eth_call(oracle, &is_jovian_calldata),
    )?;

    let decode_bool = |raw: &[u8]| raw.last().copied().unwrap_or(0) != 0;
    let is_fjord = decode_bool(&fjord_raw);
    let is_isthmus = decode_bool(&isthmus_raw);
    let is_jovian = decode_bool(&jovian_raw);

    if !is_fjord {
        return Ok(format!(
            "WARN: isFjord=false -- Kairox's L1-data-fee bounding (getL1FeeUpperBound) requires \
             Fjord; live send on this chain would fail closed at fee-bounding time \
             (isIsthmus={is_isthmus}, isJovian={is_jovian})"
        ));
    }
    Ok(format!(
        "PASS (isFjord={is_fjord}, isIsthmus={is_isthmus}, isJovian={is_jovian})"
    ))
}

async fn gather(config_path: Option<&std::path::Path>) -> DoctorReport {
    let signing_key_configured =
        secret_env_var_present(&ProcessEnv, SIGNING_KEY_ENV_VAR).unwrap_or(false);
    let opensea_api_key_configured =
        secret_env_var_present(&ProcessEnv, OPENSEA_API_KEY_ENV).unwrap_or(false);

    let resolved_config_path = resolve_config_path(config_path, &ProcessEnv);
    let config_status = match &resolved_config_path {
        None => "not configured".to_string(),
        Some(path) => match crate::config::load_config(path) {
            Ok(cfg) => format!(
                "PASS (schema v{}, {} chain entries)",
                cfg.version,
                cfg.chains.len()
            ),
            Err(e) => format!("FAIL ({e})"),
        },
    };

    let registry = ChainRegistry::builtin();
    let mut chains = Vec::new();
    for chain in registry.all() {
        let endpoints = match load_chain_endpoints(&ProcessEnv, chain.chain_id) {
            Ok(e) => e,
            Err(e) => {
                chains.push(ChainReport {
                    name: chain.name.to_string(),
                    chain_id: chain.chain_id,
                    status: format!("CONFIG ERROR: {e}"),
                    endpoint_count: 0,
                    connected_count: 0,
                    read_capable_count: 0,
                    send_capable_count: 0,
                    endpoint_details: Vec::new(),
                    op_stack_fee_oracle_status: None,
                });
                continue;
            }
        };

        if endpoints.is_empty() {
            chains.push(ChainReport {
                name: chain.name.to_string(),
                chain_id: chain.chain_id,
                status: "WARN: no RPC configured".to_string(),
                endpoint_count: 0,
                connected_count: 0,
                read_capable_count: 0,
                send_capable_count: 0,
                endpoint_details: Vec::new(),
                op_stack_fee_oracle_status: None,
            });
            continue;
        }

        let (pool, reports) = RpcPool::connect_all(chain.chain_id, &endpoints.endpoints).await;

        let mut endpoint_details = Vec::new();
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
            endpoint_details.extend(block.lines().map(str::to_string));
        }

        let status = if pool.len() == endpoints.endpoints.len() {
            "PASS".to_string()
        } else if !pool.is_empty() {
            "WARN: some endpoints failed to connect".to_string()
        } else {
            "FAIL: no endpoint connected".to_string()
        };

        let op_stack_fee_oracle_status = match chain.op_stack_gas_price_oracle {
            None => None,
            Some(oracle) => Some(match pool.preferred_read() {
                None => "FAIL: no read-capable endpoint connected -- cannot verify OP Stack fee \
                         oracle state"
                    .to_string(),
                Some(client) => match read_op_stack_fee_oracle_status(client, oracle).await {
                    Ok(summary) => summary,
                    Err(e) => format!("FAIL: could not read GasPriceOracle at {oracle:#x} ({e})"),
                },
            }),
        };

        chains.push(ChainReport {
            name: chain.name.to_string(),
            chain_id: chain.chain_id,
            status,
            endpoint_count: endpoints.endpoints.len(),
            connected_count: pool.len(),
            read_capable_count: pool.read_capable().len(),
            send_capable_count: pool.send_capable().len(),
            endpoint_details,
            op_stack_fee_oracle_status,
        });
    }

    DoctorReport {
        schema_version: 1,
        kairox_version: crate::VERSION.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        utc_time: OffsetDateTime::now_utc().to_string(),
        dry_run_default: true,
        signing_key_configured,
        opensea_api_key_configured,
        config_path: resolved_config_path.map(|p| p.display().to_string()),
        config_status,
        chains,
    }
}
