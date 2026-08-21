//! JSON-RPC transport abstraction and a typed client over it.
//!
//! [`Transport`] is intentionally narrow so it can be swapped for a mock in
//! tests without any real network access, and so a chain-id-verifying
//! [`RpcClient`] can be built once and reused for every subsequent call.

use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use serde_json::{Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

use crate::execution::errors::{Categorize, ErrorCategory};
use crate::protocol::logs::RawLog;

use super::endpoint::{EndpointRole, EndpointVerification};
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
    #[error("endpoint role {role:?} does not permit {attempted}; refusing to call it")]
    CapabilityDenied {
        role: EndpointRole,
        attempted: &'static str,
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
            RpcError::CapabilityDenied { .. } => ErrorCategory::Fatal,
        }
    }
}

/// A pluggable JSON-RPC transport. `HttpTransport` is the real
/// implementation; tests inject [`crate::chain::mock::MockTransport`]
/// instead.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn call(&self, method: &str, params: Value) -> Result<Value, TransportError>;

    /// Send an already fully-serialized JSON-RPC request body verbatim —
    /// no reconstruction, no re-serialization, no hex-encoding. This exists
    /// specifically for the latency-critical `eth_sendRawTransaction`
    /// fan-out (see [`PreparedBroadcast`]); every other RPC call continues
    /// to go through [`Self::call`], which builds its request normally.
    async fn send_prebuilt_request(&self, body: &Bytes) -> Result<Value, TransportError>;
}

/// An immutable, fully prebuilt `eth_sendRawTransaction` broadcast payload.
///
/// Built exactly once, before the stage-open instant, from the signed
/// transaction produced by [`crate::execution::prepared::prepare_live_transaction`].
/// The T=0 hot path only ever reads these bytes over the wire — it never
/// hex-encodes, never constructs or serializes JSON, and never touches the
/// signing/ABI/fee/nonce machinery again. One prepared transaction always
/// yields exactly one `PreparedBroadcast`, dispatched identically to every
/// send-capable endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBroadcast {
    pub tx_hash: B256,
    pub raw_signed_tx: Bytes,
    pub raw_tx_hex: String,
    pub json_rpc_body: Bytes,
    pub prepared_at: OffsetDateTime,
}

impl PreparedBroadcast {
    /// Hex-encode `raw_signed_tx` once and serialize the complete
    /// `eth_sendRawTransaction` JSON-RPC request body once. Everything
    /// downstream (broadcast fan-out to N endpoints) reuses these same
    /// bytes verbatim.
    pub fn build(tx_hash: B256, raw_signed_tx: Bytes) -> Self {
        let raw_tx_hex = format!("0x{}", hex::encode(&raw_signed_tx));
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex.clone()],
        });
        let json_rpc_body = Bytes::from(
            serde_json::to_vec(&envelope).expect("serializing a JSON-RPC envelope never fails"),
        );
        Self {
            tx_hash,
            raw_signed_tx,
            raw_tx_hex,
            json_rpc_body,
            prepared_at: OffsetDateTime::now_utc(),
        }
    }
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

    /// Describe a `reqwest::Error` WITHOUT ever using its top-level
    /// `Display`/`to_string()` -- `reqwest::Error` embeds the full request
    /// URL (including any userinfo credentials or query-string token) in
    /// its own `Display` output, which would otherwise flow straight into
    /// `TransportError::Network` and out to `doctor`/error text. The
    /// underlying cause (`source()`) describes the failure (DNS, connect,
    /// TLS, etc.) without the URL, so this is used instead; `mask_url` is
    /// the only place a configured endpoint's URL is ever meant to reach
    /// output, deliberately redacted.
    fn describe_network_error(e: &reqwest::Error) -> String {
        let kind = if e.is_timeout() {
            "timeout"
        } else if e.is_connect() {
            "connect error"
        } else if e.is_request() {
            "request error"
        } else if e.is_body() {
            "body error"
        } else if e.is_decode() {
            "decode error"
        } else {
            "network error"
        };
        match std::error::Error::source(e) {
            Some(source) => format!("{kind}: {source}"),
            None => kind.to_string(),
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
            .map_err(|e| TransportError::Network(Self::describe_network_error(&e)))?;

        let value: Value = tokio::time::timeout(self.timeout, response.json())
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
            .map_err(|e| TransportError::InvalidJson(Self::describe_network_error(&e)))?;

        Ok(value)
    }

    async fn send_prebuilt_request(&self, body: &Bytes) -> Result<Value, TransportError> {
        // No `json!`/serde construction here — `body` is already the exact
        // bytes to send. Only the network round trip happens in this
        // function.
        let request = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send();

        let response = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
            .map_err(|e| TransportError::Network(Self::describe_network_error(&e)))?;

        let value: Value = tokio::time::timeout(self.timeout, response.json())
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?
            .map_err(|e| TransportError::InvalidJson(Self::describe_network_error(&e)))?;

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

/// The fields Kairox needs from `eth_getTransactionReceipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub status_success: bool,
    pub block_number: u64,
    pub logs: Vec<RawLog>,
}

/// A single endpoint, wrapped with the chain id it has been verified
/// against. Construction is the only place a chain-id mismatch is checked
/// and rejected.
pub struct RpcClient {
    transport: Box<dyn Transport>,
    expected_chain_id: ChainId,
    role: EndpointRole,
    label: Option<String>,
    verification: EndpointVerification,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("expected_chain_id", &self.expected_chain_id)
            .field("role", &self.role)
            .field("label", &self.label)
            .field("verification", &self.verification)
            .finish_non_exhaustive()
    }
}

/// Standard JSON-RPC error code for "the method does not exist / is not
/// available" (EIP-1474 / the original JSON-RPC 2.0 spec). This is the
/// clearest, structured signal that an endpoint is *responsive* but simply
/// doesn't implement `eth_chainId` — as opposed to being unreachable.
const JSON_RPC_METHOD_NOT_FOUND: i64 = -32601;

/// Whether `error` is responsive evidence that the endpoint explicitly does
/// not support the method just called, rather than evidence the endpoint
/// couldn't be reached at all.
///
/// Only [`RpcError::RpcReturnedError`] — a well-formed JSON-RPC error
/// envelope the endpoint actually sent back — can indicate this. Every
/// other `RpcError` variant (`Transport::Network` for DNS/TCP/TLS
/// failures, `Transport::Timeout`, `Transport::InvalidJson` for
/// non-JSON/garbage bodies, or `MalformedResponse` for JSON that isn't a
/// valid JSON-RPC envelope) gives no proof the endpoint is alive, and must
/// never be treated as "responsive but unsupported."
///
/// The standard code (`-32601`) is checked first. A small, explicitly
/// documented set of message substrings is also accepted, because some
/// production nodes return a non-standard code (commonly `-32000`) with a
/// message that still unambiguously says the method is unknown — this is a
/// narrow, conservative fallback, not general string matching on arbitrary
/// errors.
fn indicates_unsupported_method(error: &RpcError) -> bool {
    match error {
        RpcError::RpcReturnedError { code, message } => {
            *code == JSON_RPC_METHOD_NOT_FOUND || message_indicates_unsupported_method(message)
        }
        _ => false,
    }
}

fn message_indicates_unsupported_method(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("method not found")
        || lower.contains("method not supported")
        || lower.contains("unsupported method")
        // Erigon and some other production nodes phrase this as
        // "the method X does not exist/is not available" under a
        // non-standard error code.
        || (lower.contains("does not exist") && lower.contains("method"))
}

impl RpcClient {
    /// Connect and establish trust in the endpoint, according to its role:
    ///
    /// - Read-capable roles (`ReadWrite`, `ReadOnly`, `Public`) **must**
    ///   report a matching `eth_chainId`. Any failure whatsoever — network,
    ///   timeout, malformed body, or an RPC error of any kind — rejects the
    ///   endpoint outright. There is no degraded path for these roles.
    /// - Send-only-capable roles (`SendOnly`, `Sequencer`, `Private`) are
    ///   verified via `eth_chainId` exactly like a read-capable endpoint
    ///   when it succeeds, and rejected on a *mismatch* the same way. The
    ///   only degraded path is narrow and specific: the endpoint must have
    ///   actually **responded** with a well-formed JSON-RPC error that
    ///   [`indicates_unsupported_method`] recognizes as "method not
    ///   supported" (see that function for exactly what qualifies). Only
    ///   then is the endpoint accepted as
    ///   [`EndpointVerification::ConfiguredSendOnly`], bound to
    ///   `expected_chain_id` purely through having been configured under
    ///   that exact chain id. A DNS failure, TCP refusal, TLS failure,
    ///   connection timeout, or unparseable response is **not** evidence
    ///   of anything except "we could not talk to this endpoint" — those
    ///   always reject, for every role, with no exception.
    ///
    /// A `ConfiguredSendOnly` endpoint is never usable for any state read
    /// (enforced at each read method below, not just by caller discipline).
    pub async fn connect(
        transport: Box<dyn Transport>,
        expected_chain_id: ChainId,
        role: EndpointRole,
        label: Option<String>,
    ) -> Result<Self, RpcError> {
        let mut client = RpcClient {
            transport,
            expected_chain_id,
            role,
            label,
            verification: EndpointVerification::ConfiguredSendOnly,
        };

        match client.chain_id().await {
            Ok(reported) if reported == expected_chain_id => {
                client.verification = if role.can_read() {
                    if role.can_send() {
                        EndpointVerification::VerifiedReadWrite
                    } else {
                        EndpointVerification::VerifiedReadOnly
                    }
                } else {
                    EndpointVerification::VerifiedSend
                };
                Ok(client)
            }
            Ok(reported) => Err(RpcError::ChainIdMismatch {
                expected: expected_chain_id,
                reported,
            }),
            Err(e) => {
                let eligible_for_submission_only =
                    !role.can_read() && role.can_send() && indicates_unsupported_method(&e);
                if eligible_for_submission_only {
                    client.verification = EndpointVerification::ConfiguredSendOnly;
                    Ok(client)
                } else {
                    // Read-capable roles never get a degraded path; and for
                    // send-only-capable roles, anything short of a
                    // responsive "method not supported" reply (network
                    // failure, timeout, malformed body, or a JSON-RPC error
                    // that doesn't clearly mean "unsupported method") is
                    // simply unproven — reject rather than guess.
                    Err(e)
                }
            }
        }
    }

    pub fn role(&self) -> EndpointRole {
        self.role
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// How trust in this endpoint was established. See
    /// [`EndpointVerification`].
    pub fn verification(&self) -> EndpointVerification {
        self.verification
    }

    fn require_read_capability(&self, attempted: &'static str) -> Result<(), RpcError> {
        if self.role.can_read() {
            Ok(())
        } else {
            Err(RpcError::CapabilityDenied {
                role: self.role,
                attempted,
            })
        }
    }

    fn require_send_capability(&self, attempted: &'static str) -> Result<(), RpcError> {
        if self.role.can_send() {
            Ok(())
        } else {
            Err(RpcError::CapabilityDenied {
                role: self.role,
                attempted,
            })
        }
    }

    async fn raw_call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let response = self.transport.call(method, params).await?;
        Self::extract_result(response)
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
        self.require_read_capability("eth_blockNumber")?;
        let result = self.raw_call("eth_blockNumber", json!([])).await?;
        Self::hex_to_u64(&result, "blockNumber")
    }

    /// `eth_getBlockByNumber("latest", false)`, reduced to the fields
    /// Kairox needs.
    pub async fn latest_block(&self) -> Result<BlockHeader, RpcError> {
        self.require_read_capability("eth_getBlockByNumber")?;
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
        self.require_read_capability("eth_getTransactionCount")?;
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
        self.require_read_capability("eth_maxPriorityFeePerGas")?;
        let result = self.raw_call("eth_maxPriorityFeePerGas", json!([])).await?;
        Self::hex_to_u128(&result, "maxPriorityFeePerGas")
    }

    /// `eth_call` against `to` with `data`, at the `"latest"` block.
    pub async fn eth_call(&self, to: Address, data: &Bytes) -> Result<Bytes, RpcError> {
        self.require_read_capability("eth_call")?;
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
        self.require_read_capability("eth_estimateGas")?;
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

    /// `eth_getStorageAt(address, slot, "latest")` -- used only for reading
    /// well-known standard storage slots (e.g. the EIP-1967 proxy
    /// implementation slot), never for anything execution-critical.
    pub async fn get_storage_at(
        &self,
        address: Address,
        slot: alloy_primitives::B256,
    ) -> Result<alloy_primitives::B256, RpcError> {
        self.require_read_capability("eth_getStorageAt")?;
        let result = self
            .raw_call(
                "eth_getStorageAt",
                json!([address.to_string(), slot.to_string(), "latest"]),
            )
            .await?;
        let s = result
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse("storage value was not a string".into()))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(format!("{s:0>64}")).map_err(|e| {
            RpcError::MalformedResponse(format!("storage value was not valid hex: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(RpcError::MalformedResponse(format!(
                "storage value was {} bytes, expected 32",
                bytes.len()
            )));
        }
        Ok(alloy_primitives::B256::from_slice(&bytes))
    }

    /// `eth_getBalance(address, "latest")`.
    pub async fn get_balance(&self, address: Address) -> Result<U256, RpcError> {
        self.require_read_capability("eth_getBalance")?;
        let result = self
            .raw_call("eth_getBalance", json!([address.to_string(), "latest"]))
            .await?;
        let s = result
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse("balance was not a string".into()))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        U256::from_str_radix(s, 16)
            .map_err(|e| RpcError::MalformedResponse(format!("balance was not valid hex: {e}")))
    }

    /// `eth_sendRawTransaction`, building its request the normal way (used
    /// by ad-hoc/test call sites). The T=0 broadcast hot path uses
    /// [`Self::broadcast_prepared`] instead, which sends an already-built
    /// [`PreparedBroadcast`] with no per-call encoding. Returns the
    /// transaction hash the node reports accepting — callers must compare
    /// this against the locally computed hash, never assume the two match.
    pub async fn send_raw_transaction(&self, raw: &Bytes) -> Result<B256, RpcError> {
        self.require_send_capability("eth_sendRawTransaction")?;
        let result = self
            .raw_call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw))]),
            )
            .await?;
        Self::parse_tx_hash_result(&result)
    }

    /// Broadcast an already fully prebuilt `eth_sendRawTransaction`
    /// request. Performs **no** hex-encoding, JSON construction, or
    /// serialization — `prepared.json_rpc_body` is sent to the wire
    /// exactly as it was built ahead of time. This is the T=0 hot-path
    /// entry point used by [`crate::execution::broadcast::broadcast_to_all`].
    pub async fn broadcast_prepared(&self, prepared: &PreparedBroadcast) -> Result<B256, RpcError> {
        self.require_send_capability("eth_sendRawTransaction")?;
        let response = self
            .transport
            .send_prebuilt_request(&prepared.json_rpc_body)
            .await?;
        let result = Self::extract_result(response)?;
        Self::parse_tx_hash_result(&result)
    }

    fn extract_result(response: Value) -> Result<Value, RpcError> {
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

    fn parse_tx_hash_result(result: &Value) -> Result<B256, RpcError> {
        let s = result
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse("tx hash was not a string".into()))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| RpcError::MalformedResponse(format!("tx hash was not valid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(RpcError::MalformedResponse(format!(
                "tx hash had {} bytes, expected 32",
                bytes.len()
            )));
        }
        Ok(B256::from_slice(&bytes))
    }

    /// `eth_getTransactionReceipt`. Returns `Ok(None)` while the
    /// transaction is still pending (a `null` result is not an error).
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<Option<TransactionReceipt>, RpcError> {
        self.require_read_capability("eth_getTransactionReceipt")?;
        let result = self
            .raw_call(
                "eth_getTransactionReceipt",
                json!([format!("0x{}", hex::encode(tx_hash))]),
            )
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let obj = result
            .as_object()
            .ok_or_else(|| RpcError::MalformedResponse("receipt was not an object".into()))?;

        let reported_hash = obj
            .get("transactionHash")
            .ok_or_else(|| RpcError::MalformedResponse("receipt missing transactionHash".into()))?;
        let reported_hash = Self::hex_to_b256(reported_hash, "transactionHash")?;

        let status = obj
            .get("status")
            .ok_or_else(|| RpcError::MalformedResponse("receipt missing status".into()))?;
        let status_success = Self::hex_to_u64(status, "status")? == 1;

        let block_number = obj
            .get("blockNumber")
            .ok_or_else(|| RpcError::MalformedResponse("receipt missing blockNumber".into()))?;
        let block_number = Self::hex_to_u64(block_number, "blockNumber")?;

        let logs_value = obj
            .get("logs")
            .ok_or_else(|| RpcError::MalformedResponse("receipt missing logs".into()))?;
        let logs_array = logs_value
            .as_array()
            .ok_or_else(|| RpcError::MalformedResponse("receipt logs was not an array".into()))?;
        let logs = logs_array
            .iter()
            .map(Self::decode_log)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(TransactionReceipt {
            transaction_hash: reported_hash,
            status_success,
            block_number,
            logs,
        }))
    }

    fn hex_to_b256(value: &Value, field: &str) -> Result<B256, RpcError> {
        let s = value
            .as_str()
            .ok_or_else(|| RpcError::MalformedResponse(format!("{field} was not a string")))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| RpcError::MalformedResponse(format!("{field} was not valid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(RpcError::MalformedResponse(format!(
                "{field} had {} bytes, expected 32",
                bytes.len()
            )));
        }
        Ok(B256::from_slice(&bytes))
    }

    fn decode_log(value: &Value) -> Result<RawLog, RpcError> {
        let obj = value
            .as_object()
            .ok_or_else(|| RpcError::MalformedResponse("log was not an object".into()))?;

        let address = obj
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::MalformedResponse("log missing address".into()))?;
        let address = address
            .parse::<Address>()
            .map_err(|e| RpcError::MalformedResponse(format!("log address invalid: {e}")))?;

        let topics_array = obj
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::MalformedResponse("log missing topics array".into()))?;
        let topics = topics_array
            .iter()
            .map(|t| Self::hex_to_b256(t, "log topic"))
            .collect::<Result<Vec<_>, _>>()?;

        let data_str = obj
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::MalformedResponse("log missing data".into()))?;
        let data_str = data_str.strip_prefix("0x").unwrap_or(data_str);
        let data = hex::decode(data_str)
            .map_err(|e| RpcError::MalformedResponse(format!("log data was not valid hex: {e}")))?;

        Ok(RawLog {
            address,
            topics,
            data: Bytes::from(data),
        })
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

    #[tokio::test]
    async fn get_balance_parses_hex() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_getBalance", json!("0xde0b6b3a7640000"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let balance = client.get_balance(Address::ZERO).await.unwrap();
        assert_eq!(balance, U256::from(1_000_000_000_000_000_000u128));
    }

    #[tokio::test]
    async fn send_raw_transaction_parses_tx_hash() {
        let expected = B256::repeat_byte(0xab);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_sendRawTransaction",
                json!(format!("0x{}", hex::encode(expected))),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let hash = client
            .send_raw_transaction(&Bytes::from(vec![0x02, 0xde, 0xad]))
            .await
            .unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn send_raw_transaction_rejects_malformed_hash_length() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_sendRawTransaction", json!("0xdead"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let err = client
            .send_raw_transaction(&Bytes::from(vec![0x02]))
            .await
            .unwrap_err();
        assert!(matches!(err, RpcError::MalformedResponse(_)));
    }

    #[tokio::test]
    async fn get_transaction_receipt_returns_none_when_pending() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_getTransactionReceipt", json!(null))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let receipt = client
            .get_transaction_receipt(B256::repeat_byte(0x11))
            .await
            .unwrap();
        assert!(receipt.is_none());
    }

    #[tokio::test]
    async fn get_transaction_receipt_decodes_success_with_logs() {
        let tx_hash = B256::repeat_byte(0x22);
        let nft = Address::repeat_byte(0x33);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x1",
                    "blockNumber": "0x64",
                    "logs": [{
                        "address": nft.to_string(),
                        "topics": [format!("0x{}", hex::encode(alloy_primitives::keccak256(b"Transfer(address,address,uint256)")))],
                        "data": "0x"
                    }]
                }),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let receipt = client
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(receipt.status_success);
        assert_eq!(receipt.block_number, 100);
        assert_eq!(receipt.transaction_hash, tx_hash);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].address, nft);
    }

    #[tokio::test]
    async fn get_transaction_receipt_decodes_revert_status() {
        let tx_hash = B256::repeat_byte(0x22);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x0",
                    "blockNumber": "0x64",
                    "logs": []
                }),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let receipt = client
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .unwrap();
        assert!(!receipt.status_success);
    }

    #[tokio::test]
    async fn get_transaction_receipt_rejects_malformed_logs() {
        let tx_hash = B256::repeat_byte(0x22);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_getTransactionReceipt",
                json!({
                    "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                    "status": "0x1",
                    "blockNumber": "0x64",
                    "logs": [{"address": "not-an-address", "topics": [], "data": "0x"}]
                }),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let err = client.get_transaction_receipt(tx_hash).await.unwrap_err();
        assert!(matches!(err, RpcError::MalformedResponse(_)));
    }

    // --- send-only / sequencer hardening ---------------------------------

    #[tokio::test]
    async fn send_only_endpoint_with_working_chain_id_is_fully_verified() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        assert_eq!(client.verification(), EndpointVerification::VerifiedSend);
        assert!(client.verification().chain_id_confirmed());
    }

    #[tokio::test]
    async fn send_only_endpoint_with_responsive_method_not_found_is_accepted_as_configured() {
        // The endpoint DID respond, with a well-formed JSON-RPC error
        // saying the method is unsupported -> this is exactly the
        // "responsive but doesn't implement eth_chainId" case that must be
        // accepted as ConfiguredSendOnly.
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .expect("a responsive submission-only endpoint must still be accepted");
        assert_eq!(
            client.verification(),
            EndpointVerification::ConfiguredSendOnly
        );
        assert!(!client.verification().chain_id_confirmed());
    }

    #[tokio::test]
    async fn sequencer_endpoint_with_responsive_method_not_found_is_accepted_as_configured() {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 4663, EndpointRole::Sequencer, None)
            .await
            .expect("a responsive sequencer must still be accepted without eth_chainId");
        assert_eq!(
            client.verification(),
            EndpointVerification::ConfiguredSendOnly
        );
    }

    #[tokio::test]
    async fn private_endpoint_with_non_standard_unsupported_method_message_is_accepted_as_configured()
     {
        // Some nodes return a non-standard code with a message that still
        // clearly says the method is unknown -- the narrow, documented
        // message-substring fallback must catch this too.
        let transport = MockTransport::builder()
            .error(
                "eth_chainId",
                -32000,
                "the method eth_chainId does not exist/is not available",
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::Private, None)
            .await
            .expect(
                "a non-standard but unambiguous 'unsupported method' response must still qualify",
            );
        assert_eq!(
            client.verification(),
            EndpointVerification::ConfiguredSendOnly
        );
    }

    #[tokio::test]
    async fn send_only_endpoint_with_network_failure_is_rejected_not_accepted() {
        // No "eth_chainId" response configured at all -> the mock reports a
        // network-style transport failure. This must NEVER be treated as
        // "responsive but unsupported" -- a genuinely dead endpoint must be
        // rejected outright, even for a send-only-capable role.
        let transport = MockTransport::builder().build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .expect_err("an unreachable endpoint must never become ConfiguredSendOnly");
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Network(_))
        ));
    }

    #[tokio::test]
    async fn sequencer_endpoint_with_connection_timeout_is_rejected_not_accepted() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .delay("eth_chainId", Duration::from_millis(50))
            .build()
            .with_call_timeout(Duration::from_millis(1));
        let err = RpcClient::connect(Box::new(transport), 4663, EndpointRole::Sequencer, None)
            .await
            .expect_err("a connection timeout must never become ConfiguredSendOnly");
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn sequencer_endpoint_with_malformed_json_is_rejected_not_accepted() {
        let transport = MockTransport::builder()
            .respond(
                "eth_chainId",
                json!({"this is not": "a valid envelope shape"}),
            )
            .build();
        // eth_chainId responding with a JSON object lacking "result"/"error"
        // is treated as MalformedResponse by RpcClient::raw_call, not as a
        // structured "method not found" -- must fail closed, not qualify
        // for ConfiguredSendOnly.
        let err = RpcClient::connect(Box::new(transport), 4663, EndpointRole::Sequencer, None)
            .await
            .expect_err("a malformed response must never become ConfiguredSendOnly");
        assert!(matches!(err, RpcError::MalformedResponse(_)));
    }

    #[test]
    fn indicates_unsupported_method_rejects_generic_rpc_errors() {
        let err = RpcError::RpcReturnedError {
            code: -32000,
            message: "execution reverted".into(),
        };
        assert!(!indicates_unsupported_method(&err));
    }

    #[test]
    fn indicates_unsupported_method_accepts_standard_code() {
        let err = RpcError::RpcReturnedError {
            code: JSON_RPC_METHOD_NOT_FOUND,
            message: "anything".into(),
        };
        assert!(indicates_unsupported_method(&err));
    }

    #[tokio::test]
    async fn read_only_endpoint_with_unsupported_chain_id_is_rejected() {
        let transport = MockTransport::builder().build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .expect_err("read-capable roles must never degrade to unverified");
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Network(_))
        ));
    }

    #[tokio::test]
    async fn read_write_endpoint_with_unsupported_chain_id_is_rejected() {
        let transport = MockTransport::builder().build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
            .await
            .expect_err("read-capable roles must never degrade to unverified");
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Network(_))
        ));
    }

    #[tokio::test]
    async fn send_only_endpoint_rejected_on_chain_id_mismatch() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x2"))
            .build();
        let err = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RpcError::ChainIdMismatch {
                expected: 1,
                reported: 2
            }
        ));
    }

    #[tokio::test]
    async fn configured_send_only_client_rejects_eth_call() {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let err = client
            .eth_call(Address::ZERO, &Bytes::new())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RpcError::CapabilityDenied {
                role: EndpointRole::SendOnly,
                attempted: "eth_call"
            }
        ));
    }

    #[tokio::test]
    async fn configured_send_only_client_rejects_transaction_count() {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::Sequencer, None)
            .await
            .unwrap();
        let err = client.transaction_count(Address::ZERO).await.unwrap_err();
        assert!(matches!(
            err,
            RpcError::CapabilityDenied {
                attempted: "eth_getTransactionCount",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn configured_send_only_client_rejects_priority_fee_and_balance_and_receipt() {
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::Private, None)
            .await
            .unwrap();

        assert!(matches!(
            client.max_priority_fee_per_gas().await.unwrap_err(),
            RpcError::CapabilityDenied {
                attempted: "eth_maxPriorityFeePerGas",
                ..
            }
        ));
        assert!(matches!(
            client.get_balance(Address::ZERO).await.unwrap_err(),
            RpcError::CapabilityDenied {
                attempted: "eth_getBalance",
                ..
            }
        ));
        assert!(matches!(
            client
                .get_transaction_receipt(B256::ZERO)
                .await
                .unwrap_err(),
            RpcError::CapabilityDenied {
                attempted: "eth_getTransactionReceipt",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn configured_send_only_client_can_still_broadcast() {
        let expected = B256::repeat_byte(0x55);
        let transport = MockTransport::builder()
            .error("eth_chainId", -32601, "Method not found")
            .respond(
                "eth_sendRawTransaction",
                json!(format!("0x{}", hex::encode(expected))),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let hash = client
            .send_raw_transaction(&Bytes::from(vec![0x02]))
            .await
            .unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn read_only_client_rejects_send_raw_transaction() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let err = client
            .send_raw_transaction(&Bytes::from(vec![0x02]))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RpcError::CapabilityDenied {
                attempted: "eth_sendRawTransaction",
                ..
            }
        ));
    }

    // --- PreparedBroadcast: prebuilt hot-path payload ---------------------

    #[test]
    fn prepared_broadcast_body_targets_eth_send_raw_transaction() {
        let raw = Bytes::from(vec![0x02, 0xde, 0xad, 0xbe, 0xef]);
        let tx_hash = B256::repeat_byte(0x11);
        let prepared = PreparedBroadcast::build(tx_hash, raw);

        let parsed: Value = serde_json::from_slice(&prepared.json_rpc_body).unwrap();
        assert_eq!(parsed["method"], json!("eth_sendRawTransaction"));
        assert_eq!(parsed["jsonrpc"], json!("2.0"));
    }

    #[test]
    fn prepared_broadcast_body_contains_the_exact_signed_raw_transaction() {
        let raw = Bytes::from(vec![0x02, 0x01, 0x02, 0x03, 0xff]);
        let prepared = PreparedBroadcast::build(B256::ZERO, raw.clone());

        assert_eq!(prepared.raw_tx_hex, format!("0x{}", hex::encode(&raw)));
        assert_eq!(prepared.raw_signed_tx, raw);

        let parsed: Value = serde_json::from_slice(&prepared.json_rpc_body).unwrap();
        assert_eq!(parsed["params"][0], json!(prepared.raw_tx_hex));
    }

    #[test]
    fn prepared_broadcast_tx_hash_matches_keccak_of_raw_signed_bytes() {
        let raw = Bytes::from(vec![0x02, 0xaa, 0xbb, 0xcc]);
        let tx_hash = alloy_primitives::keccak256(&raw);
        let prepared = PreparedBroadcast::build(tx_hash, raw.clone());

        assert_eq!(
            prepared.tx_hash,
            alloy_primitives::keccak256(&prepared.raw_signed_tx)
        );
    }

    #[test]
    fn prepared_broadcast_build_is_deterministic() {
        let raw = Bytes::from(vec![0x02, 0x10, 0x20]);
        let tx_hash = B256::repeat_byte(0x22);
        let a = PreparedBroadcast::build(tx_hash, raw.clone());
        let b = PreparedBroadcast::build(tx_hash, raw);
        assert_eq!(
            a.json_rpc_body, b.json_rpc_body,
            "no hidden state across builds"
        );
    }

    #[tokio::test]
    async fn broadcast_prepared_rejects_read_only_client() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap();
        let prepared = PreparedBroadcast::build(B256::ZERO, Bytes::from(vec![0x02]));
        let err = client.broadcast_prepared(&prepared).await.unwrap_err();
        assert!(matches!(
            err,
            RpcError::CapabilityDenied {
                attempted: "eth_sendRawTransaction",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn broadcast_prepared_sends_the_prebuilt_body_verbatim() {
        let raw = Bytes::from(vec![0x02, 0x55, 0x66]);
        let tx_hash = alloy_primitives::keccak256(&raw);
        let prepared = PreparedBroadcast::build(tx_hash, raw);

        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .echo_raw_transaction_hash()
            .build();
        let capture = transport.capture_handle();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();

        let hash = client.broadcast_prepared(&prepared).await.unwrap();
        assert_eq!(hash, tx_hash);
        assert_eq!(
            capture.prebuilt_bodies(),
            vec![prepared.json_rpc_body.clone()]
        );
    }

    #[tokio::test]
    async fn broadcast_prepared_timeout_is_retryable_category() {
        let raw = Bytes::from(vec![0x02]);
        let prepared = PreparedBroadcast::build(B256::ZERO, raw);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond("eth_sendRawTransaction", json!("0xabc"))
            .delay("eth_sendRawTransaction", Duration::from_millis(50))
            .build()
            .with_call_timeout(Duration::from_millis(1));
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let err = client.broadcast_prepared(&prepared).await.unwrap_err();
        assert!(matches!(
            err,
            RpcError::Transport(TransportError::Timeout(_))
        ));
        assert!(matches!(err.category(), ErrorCategory::Retryable));
    }
}
