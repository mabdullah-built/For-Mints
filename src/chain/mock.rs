//! A deterministic, in-memory [`Transport`] for tests. No network access,
//! no external process (e.g. Anvil) required — every JSON-RPC response is
//! specified up front by the test.

use std::collections::HashMap;
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

/// A canned-response transport, configured per JSON-RPC method name.
pub struct MockTransport {
    entries: HashMap<String, MockEntry>,
    call_timeout: Duration,
}

pub struct MockTransportBuilder {
    entries: HashMap<String, MockEntry>,
}

impl MockTransport {
    pub fn builder() -> MockTransportBuilder {
        MockTransportBuilder {
            entries: HashMap::new(),
        }
    }

    /// Configure how long a call is allowed to take before this transport
    /// itself reports a timeout, independent of any timeout the caller
    /// applies around it.
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
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

    pub fn build(self) -> MockTransport {
        MockTransport {
            entries: self.entries,
            call_timeout: Duration::from_secs(3600),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn call(&self, method: &str, _params: Value) -> Result<Value, TransportError> {
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
}
