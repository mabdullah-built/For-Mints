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
    /// The transaction landed on-chain and its status is success.
    ConfirmedSuccess { minted: Vec<MintedAsset> },
    /// The transaction landed on-chain but reverted.
    ConfirmedRevert,
    /// No receipt appeared before the poll deadline. Genuinely unknown —
    /// the transaction may still be pending, may have been dropped, or may
    /// have landed after Kairox stopped watching.
    ReceiptUnknown,
}

/// Poll `client` for `tx_hash`'s receipt, sleeping `poll_interval` between
/// attempts, until either a receipt appears or `timeout` elapses (measured
/// on a monotonic clock). `on_pending` is called once per unsuccessful poll
/// so a caller can report "still pending" without this function needing to
/// print anything itself.
pub async fn poll_receipt(
    client: &RpcClient,
    tx_hash: B256,
    nft_contract: Address,
    minter: Address,
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
                return ReceiptState::ConfirmedSuccess { minted };
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
        let mut topic_to = [0u8; 32];
        topic_to[12..32].copy_from_slice(minter().as_slice());
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
            Duration::from_millis(5),
            Duration::from_millis(30),
            || pending_count += 1,
        )
        .await;

        assert_eq!(state, ReceiptState::ReceiptUnknown);
        assert!(pending_count >= 1);
    }

    #[tokio::test]
    async fn confirmed_success_with_no_matching_logs_yields_empty_minted() {
        let tx_hash = B256::repeat_byte(0x11);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x1",
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
            Duration::from_millis(1),
            Duration::from_millis(200),
            || {},
        )
        .await;

        assert_eq!(state, ReceiptState::ConfirmedSuccess { minted: vec![] });
    }
}
