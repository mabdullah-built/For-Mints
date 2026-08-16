//! JSON-RPC transport abstraction and a typed client over it.
//!
//! [`Transport`] is intentionally narrow so it can be swapped for a mock in
//! tests without any real network access, and so a chain-id-verifying
//! [`RpcClient`] can be built once and reused for every subsequent call.

use std::time::Duration;

use alloy_primitives::{Address, Bytes, U256};
use async_trait::async_trait;
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::execution::errors::{Categorize, ErrorCategory};

use super::registry::ChainId;

/// A transport failure, independent of any JSON-RPC-level error returned by
/// a node.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("network error: {0}")]
    Network(String),
    #[error("response was not valid JSON: {0}")]
    InvalidJson(String),
}

/// Something a JSON-RPC call can go wrong in, above the transport layer.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("RPC error {code}: {message}")]
    RpcReturnedError { code: i64, message: String },
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    #[error("endpoint reported chain id {reported} but {expected} was expected")]
    ChainIdMismatch {
        expected: ChainId,
        reported: ChainId,
    },
}

impl Categorize for RpcError {
    fn category(&self) -> ErrorCategory {
        match self {
            RpcError::Transport(TransportError::Timeout(_)) => ErrorCategory::Retryable,
            RpcError::Transport(TransportError::Network(_)) => ErrorCategory::Retryable,
            RpcError::Transport(TransportError::InvalidJson(_)) => ErrorCategory::Fatal,
            RpcError::RpcReturnedError { .. } => ErrorCategory::Fatal,
            RpcError::MalformedResponse(_) => ErrorCategory::Fatal,
            RpcError::ChainIdMismatch { .. } => ErrorCategory::Fatal,
        }
    }
}

/// A pluggable JSON-RPC transport. `HttpTransport` is the real
/// implementation; tests inject [`crate::chain::mock::MockTransport`]
/// instead.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn call(&self, method: &str, params: Value) -> Result<Value, TransportError>;
}

/// A `reqwest`-backed transport with a bounded per-call timeout. Never
/// retries internally — retry policy belongs to the caller, with an
/// explicit, bounded attempt count.
pub struct HttpTransport {
    client: reqwest::Client,
    url: Url,
    timeout: Duration,
}

impl HttpTransport {
    pub fn new(url: Url, timeout: Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            timeout,
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(&self, method: &str, params: Value) -> Result<Value, TransportError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let request = self.client.post(self.url.clone()).json(&body).send();

        let response = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
            .map_err(|e| TransportError::Network(e.to_string()))?;

        let value: Value = tokio::time::timeout(self.timeout, response.json())
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
            .map_err(|e| TransportError::InvalidJson(e.to_string()))?;

        Ok(value)
    }
}

/// Latest block header fields Kairox actually needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee_per_gas: Option<u128>,
}

/// A single endpoint, wrapped with the chain id it has been verified
/// against. Construction is the only place a chain-id mismatch is checked
/// and rejected.
pub struct RpcClient {
    transport: Box<dyn Transport>,
    expected_chain_id: ChainId,
    role: super::endpoint::EndpointRole,
    label: Option<String>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("expected_chain_id", &self.expected_chain_id)
            .field("role", &self.role)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Connect and verify the endpoint reports `expected_chain_id`. Rejects
    /// (does not construct a client for) any mismatched endpoint.
    pub async fn connect(
        transport: Box<dyn Transport>,
        expected_chain_id: ChainId,
        role: super::endpoint::EndpointRole,
        label: Option<String>,
    ) -> Result<Self, RpcError> {
        let client = RpcClient {
            transport,
            expected_chain_id,
            role,
            label,
        };
        let reported = client.chain_id().await?;
        if reported != expected_chain_id {
            return Err(RpcError::ChainIdMismatch {
                expected: expected_chain_id,
                reported,
            });
        }
        Ok(client)
    }

    pub fn role(&self) -> super::endpoint::EndpointRole {
        self.role
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    async fn raw_call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let response = self.transport.call(method, params).await?;
        let obj = response
            .as_object()
            .ok_or_else(|| RpcError::MalformedResponse("response was not a JSON object".into()))?;

        if let Some(error) = obj.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string();
            return Err(RpcError::RpcReturnedError { code, message });
        }

        obj.get("result")
            .cloned()
            .ok_or_else(|| RpcError::MalformedResponse("response had no result field".into()))
    }

    fn hex_to_u64(value: &Value, field: &str) -> Result<u64, RpcError> {
        let s = value
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse(format!("{field} was not a string")))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16)
            .map_err(|e| RpcError::MalformedResponse(format!("{field} was not valid hex: {e}")))
    }

    fn hex_to_u128(value: &Value, field: &str) -> Result<u128, RpcError> {
        let s = value
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse(format!("{field} was not a string")))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        u128::from_str_radix(s, 16)
            .map_err(|e| RpcError::MalformedResponse(format!("{field} was not valid hex: {e}")))
    }

    /// `eth_chainId`.
    pub async fn chain_id(&self) -> Result<ChainId, RpcError> {
        let result = self.raw_call("eth_chainId", json!([])).await?;
        Self::hex_to_u64(&result, "chainId")
    }

    /// `eth_blockNumber`.
    pub async fn block_number(&self) -> Result<u64, RpcError> {
        let result = self.raw_call("eth_blockNumber", json!([])).await?;
        Self::hex_to_u64(&result, "blockNumber")
    }

    /// `eth_getBlockByNumber("latest", false)`, reduced to the fields
    /// Kairox needs.
    pub async fn latest_block(&self) -> Result<BlockHeader, RpcError> {
        let result = self
            .raw_call("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let obj = result
            .as_object()
            .ok_or_else(|| RpcError::MalformedResponse("block was not an object".into()))?;

        let number = obj
            .get("number")
            .ok_or_else(|| RpcError::MalformedResponse("block missing number".into()))?;
        let timestamp = obj
            .get("timestamp")
            .ok_or_else(|| RpcError::MalformedResponse("block missing timestamp".into()))?;
        let base_fee_per_gas = match obj.get("baseFeePerGas") {
            Some(v) if !v.is_null() => Some(Self::hex_to_u128(v, "baseFeePerGas")?),
            _ => None,
        };

        Ok(BlockHeader {
            number: Self::hex_to_u64(number, "number")?,
            timestamp: Self::hex_to_u64(timestamp, "timestamp")?,
            base_fee_per_gas,
        })
    }

    /// `eth_getTransactionCount(address, "pending")`.
    pub async fn transaction_count(&self, address: Address) -> Result<u64, RpcError> {
        let result = self
            .raw_call(
                "eth_getTransactionCount",
                json!([address.to_string(), "pending"]),
            )
            .await?;
        Self::hex_to_u64(&result, "transactionCount")
    }

    /// `eth_maxPriorityFeePerGas`.
    pub async fn max_priority_fee_per_gas(&self) -> Result<u128, RpcError> {
        let result = self.raw_call("eth_maxPriorityFeePerGas", json!([])).await?;
        Self::hex_to_u128(&result, "maxPriorityFeePerGas")
    }

    /// `eth_call` against `to` with `data`, at the `"latest"` block.
    pub async fn eth_call(&self, to: Address, data: &Bytes) -> Result<Bytes, RpcError> {
        let call_object = json!({
            "to": to.to_string(),
            "data": format!("0x{}", hex::encode(data)),
        });
        let result = self
            .raw_call("eth_call", json!([call_object, "latest"]))
            .await?;
        let s = result.as_str().ok_or_else(|| {
            RpcError::MalformedResponse("eth_call result was not a string".into())
        })?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| {
            RpcError::MalformedResponse(format!("eth_call result was not valid hex: {e}"))
        })?;
        Ok(Bytes::from(bytes))
    }

    /// `eth_estimateGas`.
    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        data: &Bytes,
        value: U256,
    ) -> Result<u64, RpcError> {
        let call_object = json!({
            "from": from.to_string(),
            "to": to.to_string(),
            "data": format!("0x{}", hex::encode(data)),
            "value": format!("0x{:x}", value),
        });
        let result = self
            .raw_call("eth_estimateGas", json!([call_object]))
            .await?;
        Self::hex_to_u64(&result, "estimateGas")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;

    #[tokio::test]
    async fn connect_succeeds_when_chain_id_matches() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        assert_eq!(client.chain_id().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn connect_rejects_mismatched_chain_id() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x2"))
            .build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RpcError::ChainIdMismatch {
                expected: 1,
                reported: 2
            }
        ));
        assert!(matches!(err.category(), ErrorCategory::Fatal));
    }

    #[tokio::test]
    async fn timeout_is_retryable() {
        let transport = MockTransport::builder()
            .delay("eth_chainId", Duration::from_millis(50))
            .respond("eth_chainId", json!("0x1"))
            .build();
        let transport = transport.with_call_timeout(Duration::from_millis(1));
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Timeout(_))
        ));
        assert!(matches!(err.category(), ErrorCategory::Retryable));
    }

    #[tokio::test]
    async fn malformed_response_is_fatal() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!({"unexpected": true}))
            .build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap_err();
        assert!(matches!(err, RpcError::MalformedResponse(_)));
        assert!(matches!(err.category(), ErrorCategory::Fatal));
    }

    #[tokio::test]
    async fn rpc_error_object_is_surfaced() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .error("eth_blockNumber", -32000, "execution reverted")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let err = client.block_number().await.unwrap_err();
        assert!(matches!(
            err,
            RpcError::RpcReturnedError { code: -32000, .. }
        ));
    }

    #[tokio::test]
    async fn latest_block_parses_base_fee() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x10", "timestamp": "0x64", "baseFeePerGas": "0x3b9aca00"}),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let block = client.latest_block().await.unwrap();
        assert_eq!(block.number, 16);
        assert_eq!(block.timestamp, 100);
        assert_eq!(block.base_fee_per_gas, Some(1_000_000_000));
    }

    #[tokio::test]
    async fn latest_block_without_base_fee_field_is_none() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getBlockByNumber",
                json!({"number": "0x10", "timestamp": "0x64"}),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let block = client.latest_block().await.unwrap();
        assert_eq!(block.base_fee_per_gas, None);
    }
}
