//! Bounded receipt polling and Transfer-log mint verification.
//!
//! Kairox never trusts RPC broadcast acceptance alone, and never trusts an
//! off-chain source for a minted token id — only a confirmed receipt's own
//! logs, decoded locally.

use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256};

use crate::chain::rpc::RpcClient;
use crate::protocol::logs::{MintedAsset, extract_minted_assets};

/// The terminal state of a receipt poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptState {
    /// The transaction landed on-chain, its status is success, AND the
    /// expected mint evidence was fully observed: exactly `expected_quantity`
    /// unique-token-id `Transfer` events from `nft_contract`, each with
    /// `from == 0x0` and `to == minter`. Receipt status alone is never
    /// sufficient — a successful receipt only proves the transaction did not
    /// revert, not that the expected NFT was minted to the expected wallet.
    ConfirmedSuccess { minted: Vec<MintedAsset> },
    /// The transaction landed on-chain and its status is success, but the
    /// expected mint evidence was NOT fully observed (missing, wrong
    /// quantity, or duplicate token ids). BLOCKCHAIN EXECUTION IS CONFIRMED
    /// — only the expected application-level mint result is unproven. This
    /// is terminal for this transaction: it must never trigger a
    /// replacement transaction, and must never be treated like network-send
    /// uncertainty (the tx definitely executed; only its observed result
    /// didn't match what was expected).
    ConfirmedExecutionMismatch {
        minted: Vec<MintedAsset>,
        expected_quantity: u64,
    },
    /// The transaction landed on-chain but reverted.
    ConfirmedRevert,
    /// No receipt appeared before the poll deadline. Genuinely unknown —
    /// the transaction may still be pending, may have been dropped, or may
    /// have landed after Kairox stopped watching.
    ReceiptUnknown,
}

/// `minted` proves the expected mint iff it contains exactly
/// `expected_quantity` entries with pairwise-distinct token ids. (Wrong
/// contract, wrong recipient, and non-mint transfers are already excluded by
/// [`extract_minted_assets`] itself.)
fn mint_evidence_matches(minted: &[MintedAsset], expected_quantity: u64) -> bool {
    if minted.len() as u64 != expected_quantity {
        return false;
    }
    let mut seen = std::collections::HashSet::with_capacity(minted.len());
    minted.iter().all(|asset| seen.insert(asset.token_id))
}

/// Poll `client` for `tx_hash`'s receipt, sleeping `poll_interval` between
/// attempts, until either a receipt appears or `timeout` elapses (measured
/// on a monotonic clock). `on_pending` is called once per unsuccessful poll
/// so a caller can report "still pending" without this function needing to
/// print anything itself.
///
/// `expected_quantity` is the number of tokens this transaction was meant to
/// mint to `minter`; a successful receipt is only classified
/// [`ReceiptState::ConfirmedSuccess`] when that many unique, attributable
/// mint `Transfer` events from `nft_contract` are actually present.
#[allow(clippy::too_many_arguments)]
pub async fn poll_receipt(
    client: &RpcClient,
    tx_hash: B256,
    nft_contract: Address,
    minter: Address,
    expected_quantity: u64,
    poll_interval: Duration,
    timeout: Duration,
    mut on_pending: impl FnMut(),
) -> ReceiptState {
    let deadline = Instant::now() + timeout;

    loop {
        match client.get_transaction_receipt(tx_hash).await {
            Ok(Some(receipt)) if receipt.transaction_hash != tx_hash => {
                // Never trust a receipt whose own hash doesn't match what
                // we asked for — treat it the same as no receipt yet.
                on_pending();
            }
            Ok(Some(receipt)) => {
                if !receipt.status_success {
                    return ReceiptState::ConfirmedRevert;
                }
                let minted =
                    extract_minted_assets(&receipt.logs, nft_contract, minter).unwrap_or_default();
                if mint_evidence_matches(&minted, expected_quantity) {
                    return ReceiptState::ConfirmedSuccess { minted };
                }
                return ReceiptState::ConfirmedExecutionMismatch {
                    minted,
                    expected_quantity,
                };
            }
            Ok(None) | Err(_) => {
                on_pending();
            }
        }

        if Instant::now() >= deadline {
            return ReceiptState::ReceiptUnknown;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(poll_interval.min(remaining.max(Duration::from_millis(1)))).await;
        if Instant::now() >= deadline {
            return ReceiptState::ReceiptUnknown;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use alloy_primitives::{U256, address, keccak256};
    use serde_json::json;

    fn nft() -> Address {
        address!("000000000000000000000000000000000000c0de")
    }

    fn minter() -> Address {
        address!("0000000000000000000000000000000000000aaa")
    }

    fn mint_log_json(token_id: u64) -> serde_json::Value {
        mint_log_json_to(minter(), token_id)
    }

    fn mint_log_json_to(to: Address, token_id: u64) -> serde_json::Value {
        let mut topic_to = [0u8; 32];
        topic_to[12..32].copy_from_slice(to.as_slice());
        let mut topic_id = [0u8; 32];
        topic_id[24..32].copy_from_slice(&token_id.to_be_bytes());
        json!({
            "address": nft().to_string(),
            "topics": [
                format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
                format!("0x{}", hex::encode([0u8; 32])),
                format!("0x{}", hex::encode(topic_to)),
                format!("0x{}", hex::encode(topic_id)),
            ],
            "data": "0x"
        })
    }

    fn mint_log_json_from(from: Address, token_id: u64) -> serde_json::Value {
        let mut topic_from = [0u8; 32];
        topic_from[12..32].copy_from_slice(from.as_slice());
        let mut topic_to = [0u8; 32];
        topic_to[12..32].copy_from_slice(minter().as_slice());
        let mut topic_id = [0u8; 32];
        topic_id[24..32].copy_from_slice(&token_id.to_be_bytes());
        json!({
            "address": nft().to_string(),
            "topics": [
                format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
                format!("0x{}", hex::encode(topic_from)),
                format!("0x{}", hex::encode(topic_to)),
                format!("0x{}", hex::encode(topic_id)),
            ],
            "data": "0x"
        })
    }

    fn receipt_with_logs(
        tx_hash: B256,
        status: &str,
        logs: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        json!({
            "transactionHash": format!("0x{}", hex::encode(tx_hash)),
            "status": status,
            "blockNumber": "0x1",
            "logs": logs
        })
    }

    async fn client_with_receipt(receipt: serde_json::Value) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_getTransactionReceipt", receipt)
            .build();
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn confirmed_success_extracts_minted_token_id() {
        let tx_hash = B256::repeat_byte(0x11);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [mint_log_json(42)]
                }),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedSuccess {
                minted: vec![MintedAsset {
                    token_id: U256::from(42u64),
                    amount: U256::from(1u8)
                }]
            }
        );
    }

    #[tokio::test]
    async fn confirmed_revert_on_zero_status() {
        let tx_hash = B256::repeat_byte(0x11);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x0",
                    "blockNumber": "0x1",
                    "logs": []
                }),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(state, ReceiptState::ConfirmedRevert);
    }

    #[tokio::test]
    async fn receipt_unknown_after_timeout_when_always_pending() {
        let tx_hash = B256::repeat_byte(0x11);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_getTransactionReceipt", json!(null))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();

        let mut pending_count = 0;
        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(5),
            Duration::from_millis(30),
            || pending_count += 1,
        )
        .await;

        assert_eq!(state, ReceiptState::ReceiptUnknown);
        assert!(pending_count >= 1);
    }

    // Section 5 regression matrix: receipt status alone is never sufficient
    // for ConfirmedSuccess -- exact, attributable mint evidence is required.

    #[tokio::test]
    async fn status_1_with_correct_mint_transfer_is_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let client =
            client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![mint_log_json(42)])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedSuccess {
                minted: vec![MintedAsset {
                    token_id: U256::from(42u64),
                    amount: U256::from(1u8)
                }]
            }
        );
    }

    #[tokio::test]
    async fn status_1_with_no_logs_is_not_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                minted: vec![],
                expected_quantity: 1
            }
        );
        assert!(!matches!(state, ReceiptState::ConfirmedSuccess { .. }));
    }

    #[tokio::test]
    async fn status_1_with_transfer_from_wrong_nft_contract_is_not_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let wrong_contract = address!("000000000000000000000000000000000000bad0");
        let mut log = mint_log_json(42);
        log["address"] = json!(wrong_contract.to_string());
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![log])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                minted: vec![],
                expected_quantity: 1
            }
        );
    }

    #[tokio::test]
    async fn status_1_with_transfer_to_wrong_wallet_is_not_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let other_wallet = address!("000000000000000000000000000000000000bbbb");
        let log = mint_log_json_to(other_wallet, 42);
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![log])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                minted: vec![],
                expected_quantity: 1
            }
        );
    }

    #[tokio::test]
    async fn status_1_with_from_nonzero_is_not_mint_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let prior_owner = address!("000000000000000000000000000000000000cccc");
        let log = mint_log_json_from(prior_owner, 42);
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![log])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                minted: vec![],
                expected_quantity: 1
            }
        );
    }

    #[tokio::test]
    async fn status_1_quantity_2_with_two_correct_unique_transfers_is_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let logs = vec![mint_log_json(101), mint_log_json(102)];
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", logs)).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            2,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedSuccess {
                minted: vec![
                    MintedAsset {
                        token_id: U256::from(101u64),
                        amount: U256::from(1u8)
                    },
                    MintedAsset {
                        token_id: U256::from(102u64),
                        amount: U256::from(1u8)
                    },
                ]
            }
        );
    }

    #[tokio::test]
    async fn status_1_quantity_2_with_only_one_correct_transfer_is_not_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let client =
            client_with_receipt(receipt_with_logs(tx_hash, "0x1", vec![mint_log_json(101)])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            2,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                minted: vec![MintedAsset {
                    token_id: U256::from(101u64),
                    amount: U256::from(1u8)
                }],
                expected_quantity: 2
            }
        );
    }

    #[tokio::test]
    async fn status_1_with_duplicate_token_id_evidence_is_not_confirmed_success() {
        let tx_hash = B256::repeat_byte(0x11);
        let logs = vec![mint_log_json(101), mint_log_json(101)];
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x1", logs)).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            2,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert!(matches!(
            state,
            ReceiptState::ConfirmedExecutionMismatch {
                expected_quantity: 2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn status_0_is_confirmed_revert() {
        let tx_hash = B256::repeat_byte(0x11);
        let client = client_with_receipt(receipt_with_logs(tx_hash, "0x0", vec![])).await;

        let state = poll_receipt(
            &client,
            tx_hash,
            nft(),
            minter(),
            1,
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(state, ReceiptState::ConfirmedRevert);
    }
}
