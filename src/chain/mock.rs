//! A deterministic, in-memory [`Transport`] for tests. No network access,
//! no external process (e.g. Anvil) required — every JSON-RPC response is
//! specified up front by the test.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::rpc::{Transport, TransportError};

#[derive(Default)]
struct MockEntry {
    response: Option<Value>,
    error: Option<(i64, String)>,
    delay: Option<Duration>,
}

/// A shared, cloneable record of every call a [`MockTransport`] received.
/// Cloned from the transport *before* it is moved into an `RpcClient`, so
/// tests can still inspect what was actually sent afterwards.
#[derive(Clone, Default)]
pub struct CaptureHandle(Arc<Mutex<Vec<(String, Value)>>>);

impl CaptureHandle {
    /// All `(method, params)` pairs received, in call order.
    pub fn all(&self) -> Vec<(String, Value)> {
        self.0.lock().expect("capture mutex poisoned").clone()
    }

    /// Params of every call made to `method`, in call order.
    pub fn calls_for(&self, method: &str) -> Vec<Value> {
        self.all()
            .into_iter()
            .filter(|(m, _)| m == method)
            .map(|(_, p)| p)
            .collect()
    }
}

type DynamicResponder = Box<dyn Fn(&Value) -> Value + Send + Sync>;

struct RoutedEntry {
    method: String,
    matcher: Box<dyn Fn(&Value) -> bool + Send + Sync>,
    response: Option<Value>,
    error: Option<(i64, String)>,
}

/// A canned-response transport, configured per JSON-RPC method name.
///
/// Most methods only need one canned response (`respond`/`error`). Methods
/// called multiple times with different meanings encoded only in their
/// params — chiefly `eth_call`, where the target contract/function selector
/// lives inside `params[0].data`/`params[0].to` rather than in the method
/// name — use [`MockTransportBuilder::respond_matching`] instead, checked
/// in registration order before the method-wide default.
pub struct MockTransport {
    entries: HashMap<String, MockEntry>,
    routed: Vec<RoutedEntry>,
    dynamic: HashMap<String, DynamicResponder>,
    call_timeout: Duration,
    capture: CaptureHandle,
}

pub struct MockTransportBuilder {
    entries: HashMap<String, MockEntry>,
    routed: Vec<RoutedEntry>,
    dynamic: HashMap<String, DynamicResponder>,
}

impl MockTransport {
    pub fn builder() -> MockTransportBuilder {
        MockTransportBuilder {
            entries: HashMap::new(),
            routed: Vec::new(),
            dynamic: HashMap::new(),
        }
    }

    /// Configure how long a call is allowed to take before this transport
    /// itself reports a timeout, independent of any timeout the caller
    /// applies around it.
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// A clone of this transport's call-capture handle. Take this *before*
    /// moving the transport into an `RpcClient` (which takes ownership of
    /// it as a `Box<dyn Transport>`), then inspect it afterwards.
    pub fn capture_handle(&self) -> CaptureHandle {
        self.capture.clone()
    }
}

impl MockTransportBuilder {
    pub fn respond(mut self, method: &str, value: Value) -> Self {
        self.entries.entry(method.to_string()).or_default().response = Some(value);
        self
    }

    pub fn error(mut self, method: &str, code: i64, message: &str) -> Self {
        self.entries.entry(method.to_string()).or_default().error =
            Some((code, message.to_string()));
        self
    }

    pub fn delay(mut self, method: &str, delay: Duration) -> Self {
        self.entries.entry(method.to_string()).or_default().delay = Some(delay);
        self
    }

    /// Respond to `method` with `value`, but only when `matcher(params)` is
    /// true. Checked in registration order, before the method-wide default
    /// set by [`Self::respond`]. Primarily for `eth_call`, whose meaning
    /// depends on `params[0].to`/`params[0].data`, not the method name.
    pub fn respond_matching(
        mut self,
        method: &str,
        matcher: impl Fn(&Value) -> bool + Send + Sync + 'static,
        value: Value,
    ) -> Self {
        self.routed.push(RoutedEntry {
            method: method.to_string(),
            matcher: Box::new(matcher),
            response: Some(value),
            error: None,
        });
        self
    }

    /// Convenience for the common `eth_call` case: respond to calls whose
    /// `params[0].data` starts with the given 4-byte ABI function selector,
    /// regardless of which contract address they target.
    pub fn respond_eth_call_selector(self, selector: [u8; 4], value: Value) -> Self {
        let prefix = format!("0x{}", hex::encode(selector));
        self.respond_matching(
            "eth_call",
            move |params| {
                params
                    .get(0)
                    .and_then(|c| c.get("data"))
                    .and_then(Value::as_str)
                    .is_some_and(|d| d.starts_with(&prefix))
            },
            value,
        )
    }

    /// Respond to every call to `method` by computing the response from its
    /// params, rather than a fixed canned value. Used to make
    /// `eth_sendRawTransaction` echo back the real keccak256 hash of
    /// whatever raw bytes it received (see
    /// [`Self::echo_raw_transaction_hash`]), so tests don't need to
    /// predict a signature-dependent hash ahead of time.
    pub fn respond_dynamic(
        mut self,
        method: &str,
        f: impl Fn(&Value) -> Value + Send + Sync + 'static,
    ) -> Self {
        self.dynamic.insert(method.to_string(), Box::new(f));
        self
    }

    /// Convenience: make `eth_sendRawTransaction` return the real
    /// keccak256 hash of the raw bytes it was called with.
    pub fn echo_raw_transaction_hash(self) -> Self {
        self.respond_dynamic("eth_sendRawTransaction", |params| {
            let raw_hex = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .trim_start_matches("0x");
            let bytes = hex::decode(raw_hex).unwrap_or_default();
            let hash = alloy_primitives::keccak256(&bytes);
            json!(format!("0x{}", hex::encode(hash)))
        })
    }

    pub fn build(self) -> MockTransport {
        MockTransport {
            entries: self.entries,
            routed: self.routed,
            dynamic: self.dynamic,
            call_timeout: Duration::from_secs(3600),
            capture: CaptureHandle::default(),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn call(&self, method: &str, params: Value) -> Result<Value, TransportError> {
        self.capture
            .0
            .lock()
            .expect("capture mutex poisoned")
            .push((method.to_string(), params.clone()));

        if let Some(f) = self.dynamic.get(method) {
            let result = f(&params);
            return Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}));
        }

        if let Some(routed) = self
            .routed
            .iter()
            .find(|r| r.method == method && (r.matcher)(&params))
        {
            if let Some((code, message)) = &routed.error {
                return Ok(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": code, "message": message},
                }));
            }
            let result = routed
                .response
                .clone()
                .ok_or_else(|| TransportError::Network(format!("no mock response for {method}")))?;
            return Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}));
        }

        let entry = self
            .entries
            .get(method)
            .ok_or_else(|| TransportError::Network(format!("no mock response for {method}")))?;

        if let Some(delay) = entry.delay {
            if delay > self.call_timeout {
                tokio::time::sleep(self.call_timeout).await;
                return Err(TransportError::Timeout(self.call_timeout));
            }
            tokio::time::sleep(delay).await;
        }

        if let Some((code, message)) = &entry.error {
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": code, "message": message},
            }));
        }

        let result = entry
            .response
            .clone()
            .ok_or_else(|| TransportError::Network(format!("no mock response for {method}")))?;
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_configured_response_envelope() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let envelope = transport.call("eth_chainId", json!([])).await.unwrap();
        assert_eq!(envelope["result"], json!("0x1"));
    }

    #[tokio::test]
    async fn returns_configured_error_envelope() {
        let transport = MockTransport::builder()
            .error("eth_call", -32000, "reverted")
            .build();
        let envelope = transport.call("eth_call", json!([])).await.unwrap();
        assert_eq!(envelope["error"]["code"], json!(-32000));
    }

    #[tokio::test]
    async fn unconfigured_method_is_a_network_error() {
        let transport = MockTransport::builder().build();
        let err = transport
            .call("eth_blockNumber", json!([]))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Network(_)));
    }

    #[tokio::test]
    async fn delay_exceeding_call_timeout_yields_timeout_error() {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .delay("eth_chainId", Duration::from_millis(50))
            .build()
            .with_call_timeout(Duration::from_millis(1));
        let err = transport.call("eth_chainId", json!([])).await.unwrap_err();
        assert!(matches!(err, TransportError::Timeout(_)));
    }

    #[tokio::test]
    async fn capture_handle_records_method_and_params() {
        let transport = MockTransport::builder()
            .respond("eth_sendRawTransaction", json!("0xabc"))
            .build();
        let capture = transport.capture_handle();
        transport
            .call("eth_sendRawTransaction", json!(["0xdeadbeef"]))
            .await
            .unwrap();
        let calls = capture.calls_for("eth_sendRawTransaction");
        assert_eq!(calls, vec![json!(["0xdeadbeef"])]);
    }
}
