//! `kairox receipt` — read-only recheck of a known transaction's receipt
//! and expected mint evidence. Never submits a transaction; uses only a
//! verified read-capable RPC endpoint, exactly like every other read in
//! Kairox.

use serde::Serialize;

use crate::chain::registry::ChainRegistry;
use crate::cli::args::ReceiptArgs;
use crate::cli::context::{connect_read_client, resolve_chain_and_runtime};
use crate::execution::errors::KairoxError;
use crate::execution::receipt::{ReceiptState, poll_receipt};

/// Stable, secret-free, machine-readable result of a receipt recheck.
#[derive(Debug, Serialize)]
pub struct ReceiptCheckReport {
    pub schema_version: u32,
    pub tx_hash: String,
    pub collection: String,
    pub wallet: String,
    pub expected_quantity: u64,
    pub state: String,
    /// Stable error code for the outcome (see
    /// [`crate::execution::errors::KairoxErrorCode`]); `None` only for
    /// `CONFIRMED_SUCCESS`, which is not an error.
    pub error_code: Option<String>,
    pub minted: Vec<MintedTokenReport>,
}

#[derive(Debug, Serialize)]
pub struct MintedTokenReport {
    pub token_id: String,
    pub amount: String,
}

pub async fn run(
    args: ReceiptArgs,
    config_path: Option<&std::path::Path>,
) -> Result<(), KairoxError> {
    let registry = ChainRegistry::builtin();
    let (resolved, runtime) = resolve_chain_and_runtime(&registry, &args.chain_args, config_path)?;
    let read_client = connect_read_client(
        &resolved.info,
        args.chain_args.rpc_url.as_ref(),
        runtime.config.as_ref(),
    )
    .await?;

    let state = poll_receipt(
        &read_client,
        args.tx,
        args.collection,
        args.wallet,
        args.quantity,
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(args.timeout_secs),
        || {},
    )
    .await;

    let (state_name, minted) = match &state {
        ReceiptState::ConfirmedSuccess { minted } => ("CONFIRMED_SUCCESS", minted.as_slice()),
        ReceiptState::ConfirmedExecutionMismatch { minted, .. } => {
            ("CONFIRMED_EXECUTION_MISMATCH", minted.as_slice())
        }
        ReceiptState::ConfirmedRevert => ("CONFIRMED_REVERT", [].as_slice()),
        ReceiptState::ReceiptUnknown => ("RECEIPT_UNKNOWN", [].as_slice()),
    };

    let report = ReceiptCheckReport {
        schema_version: 1,
        tx_hash: format!("{:#x}", args.tx),
        collection: format!("{:#x}", args.collection),
        wallet: format!("{:#x}", args.wallet),
        expected_quantity: args.quantity,
        state: state_name.to_string(),
        error_code: state.error_code().map(|c| c.to_string()),
        minted: minted
            .iter()
            .map(|m| MintedTokenReport {
                token_id: m.token_id.to_string(),
                amount: m.amount.to_string(),
            })
            .collect(),
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("ReceiptCheckReport is always serializable")
        );
        return Ok(());
    }

    println!("tx:         {}", report.tx_hash);
    println!("collection: {}", report.collection);
    println!("wallet:     {}", report.wallet);
    println!("expected quantity: {}", report.expected_quantity);
    println!("state: {}", report.state);
    match &state {
        ReceiptState::ConfirmedExecutionMismatch { .. } => {
            println!(
                "  BLOCKCHAIN EXECUTION CONFIRMED BUT EXPECTED MINT NOT PROVEN -- do not treat this as a network-uncertain outcome; the transaction definitely executed."
            );
        }
        ReceiptState::ReceiptUnknown => {
            println!(
                "  Still unknown after {}s -- do NOT automatically resend a mint. Recheck later, or confirm the transaction's status via a block explorer.",
                args.timeout_secs
            );
        }
        _ => {}
    }
    for m in &report.minted {
        println!("  minted token id {} (amount {})", m.token_id, m.amount);
    }
    Ok(())
}
