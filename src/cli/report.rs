//! Structured, secret-free report types shared by `--json`/`--output`
//! across `kairox plan`/`kairox mint`, plus the atomic-ish file-write
//! helper both use.
//!
//! Every report here follows the same rules: `schema_version` first, no
//! private keys/API key values/raw `Authorization` headers/raw signed
//! transactions, U256/u128 wei amounts as decimal strings (never a JSON
//! float, which cannot losslessly represent them), addresses as
//! `0x`-prefixed lowercase hex, and timestamps as RFC3339 UTC.

use alloy_primitives::Address;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::execution::plan::MintPlan;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

fn format_addr(addr: Address) -> String {
    format!("{addr:#x}")
}

fn format_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339)
        .unwrap_or_else(|_| "INVALID_TIMESTAMP".to_string())
}

/// Deterministic, secret-free identifier for a planned mint intent.
///
/// Deliberately does NOT include a generation timestamp, nonce, gas
/// estimate, or any other value that fluctuates between two calls made
/// moments apart for the same underlying intent -- two `kairox plan`
/// invocations for the same chain/collection/engine/wallet/quantity/stage
/// therefore produce the SAME `plan_id`. This makes the id useful as a
/// stable identity for "this planned mint," not merely a per-invocation
/// correlation token; a separate `generated_at` field on the report
/// carries per-invocation timing. Computed as a truncated (128-bit)
/// keccak256 digest over the listed fields -- collision-resistant for
/// Kairox's purposes, and cheap since it only ever runs after a plan is
/// already built (never on the T=0 hot path).
pub struct PlanIdInputs<'a> {
    pub chain_id: u64,
    pub collection: Address,
    pub engine: &'a str,
    pub wallets: &'a [Address],
    pub quantities: &'a [u64],
    pub stage_start_unix: i64,
    pub stage_end_unix: i64,
    pub config_fingerprint: &'a str,
}

pub fn compute_plan_id(inputs: PlanIdInputs<'_>) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&inputs.chain_id.to_be_bytes());
    buf.extend_from_slice(inputs.collection.as_slice());
    buf.extend_from_slice(inputs.engine.as_bytes());
    buf.push(0);
    for w in inputs.wallets {
        buf.extend_from_slice(w.as_slice());
    }
    buf.push(0);
    for q in inputs.quantities {
        buf.extend_from_slice(&q.to_be_bytes());
    }
    buf.extend_from_slice(&inputs.stage_start_unix.to_be_bytes());
    buf.extend_from_slice(&inputs.stage_end_unix.to_be_bytes());
    buf.extend_from_slice(inputs.config_fingerprint.as_bytes());
    let digest = alloy_primitives::keccak256(&buf);
    format!("plan_{}", hex::encode(&digest.0[..16]))
}

/// A safe, non-secret fingerprint of which config (if any) contributed to
/// a plan/session -- the config file's path, never its contents. Purely
/// for `plan_id` stability/debugging, not a security boundary.
pub fn config_fingerprint(config_path: Option<&std::path::Path>) -> String {
    config_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "no-config".to_string())
}

/// The authoritative, machine-readable dry-run plan for a single wallet.
/// Never contains a private key, API key value, `Authorization` header, or
/// signed transaction -- a plan is, by construction, unsigned.
#[derive(Debug, Serialize)]
pub struct ExecutionPlanReport {
    pub schema_version: u32,
    pub plan_id: String,
    pub generated_at: String,
    pub chain: String,
    pub chain_id: u64,
    pub collection: String,
    pub target_contract: String,
    pub engine: String,
    pub wallet: String,
    pub quantity: u64,
    pub fee_recipient: String,
    pub mint_value_wei: String,
    pub wallet_allocation_remaining: u64,
    pub collection_supply_remaining: u64,
    pub nonce: Option<u64>,
    pub gas_estimate: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas_wei: String,
    pub max_priority_fee_per_gas_wei: String,
    pub max_fee_per_gas_wei: String,
    pub worst_case_gas_cost_wei: String,
    pub worst_case_total_spend_wei: String,
    pub calldata_selector: String,
    pub stage_start: String,
    pub stage_end: String,
    pub stage_status: String,
    pub dry_run: bool,
}

/// Build the JSON-safe report for one wallet's plan. `engine` is the raw
/// engine name ("public"/"opensea") the caller actually selected.
pub fn build_execution_plan_report(
    plan: &MintPlan,
    engine: &str,
    wallet: Address,
    config_path: Option<&std::path::Path>,
) -> ExecutionPlanReport {
    let plan_id = compute_plan_id(PlanIdInputs {
        chain_id: plan.chain.chain_id,
        collection: plan.nft_contract,
        engine,
        wallets: &[wallet],
        quantities: &[plan.quantity],
        stage_start_unix: plan.stage_start.unix_timestamp(),
        stage_end_unix: plan.stage_end.unix_timestamp(),
        config_fingerprint: &config_fingerprint(config_path),
    });
    ExecutionPlanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        plan_id,
        generated_at: format_rfc3339(OffsetDateTime::now_utc()),
        chain: plan.chain.name.to_string(),
        chain_id: plan.chain.chain_id,
        collection: format_addr(plan.nft_contract),
        target_contract: format_addr(plan.target_contract),
        engine: engine.to_string(),
        wallet: format_addr(wallet),
        quantity: plan.quantity,
        fee_recipient: format_addr(plan.fee_recipient),
        mint_value_wei: plan.mint_value.to_string(),
        wallet_allocation_remaining: plan.wallet_allocation_remaining,
        collection_supply_remaining: plan.collection_supply_remaining,
        nonce: plan.nonce,
        gas_estimate: plan.gas_estimate,
        gas_limit: plan.gas_limit,
        base_fee_per_gas_wei: plan.base_fee_per_gas.to_string(),
        max_priority_fee_per_gas_wei: plan.max_priority_fee_per_gas.to_string(),
        max_fee_per_gas_wei: plan.max_fee_per_gas.to_string(),
        worst_case_gas_cost_wei: plan.worst_case_gas_cost.to_string(),
        worst_case_total_spend_wei: plan.worst_case_total_spend.to_string(),
        calldata_selector: format!("0x{}", hex::encode(plan.calldata_selector)),
        stage_start: format_rfc3339(plan.stage_start),
        stage_end: format_rfc3339(plan.stage_end),
        stage_status: format!("{:?}", plan.stage_status),
        dry_run: plan.dry_run,
    }
}

/// Write `contents` to `path` via a temp file in the same directory
/// followed by a rename, so a write failure (disk full, permissions,
/// process killed mid-write) can never leave a truncated/corrupt file
/// where a previously-successful report used to be. Not fully atomic
/// across all filesystems/OSes (true atomicity is out of scope), but
/// meaningfully safer than a direct truncating write -- the documented
/// goal in the Phase 6 spec is "prefer temp file + flush + rename," not an
/// unconditional cross-platform atomicity guarantee.
pub fn write_report_atomic(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_path = match dir {
        Some(dir) => dir.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "kairox-report".to_string()),
            std::process::id()
        )),
        None => std::path::PathBuf::from(format!(".kairox-report.tmp-{}", std::process::id())),
    };
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        use std::io::Write;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn base_inputs() -> PlanIdInputs<'static> {
        PlanIdInputs {
            chain_id: 1,
            collection: Address::ZERO,
            engine: "public",
            wallets: &[Address::ZERO],
            quantities: &[1],
            stage_start_unix: 0,
            stage_end_unix: 100,
            config_fingerprint: "x",
        }
    }

    #[test]
    fn plan_id_is_deterministic_for_identical_inputs() {
        let a = compute_plan_id(base_inputs());
        let b = compute_plan_id(base_inputs());
        assert_eq!(a, b);
    }

    #[test]
    fn plan_id_changes_when_quantity_changes() {
        let a = compute_plan_id(base_inputs());
        let b = compute_plan_id(PlanIdInputs {
            quantities: &[2],
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn plan_id_changes_when_wallet_changes() {
        let w2 = address!("0000000000000000000000000000000000000002");
        let a = compute_plan_id(base_inputs());
        let b = compute_plan_id(PlanIdInputs {
            wallets: &[w2],
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn plan_id_changes_when_engine_changes() {
        let a = compute_plan_id(base_inputs());
        let b = compute_plan_id(PlanIdInputs {
            engine: "opensea",
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn write_report_atomic_leaves_no_tmp_file_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        write_report_atomic(&path, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":1}");
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftover.is_empty());
    }

    #[test]
    fn write_report_atomic_overwrites_an_existing_file_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, "old").unwrap();
        write_report_atomic(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
