//! A deterministic, in-memory [`OpenSeaTransport`] for tests. No network
//! access required — every response (or transport failure) is specified up
//! front by the test. Mirrors [`crate::chain::mock::MockTransport`]'s
//! shape/conventions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::transport::{HttpResponse, OpenSeaTransport, OpenSeaTransportError};

#[derive(Clone)]
enum Canned {
    Response { status: u16, body: Value },
    Timeout,
    Network(String),
}

/// One captured `(method, path, body)` request.
type CapturedRequest = (String, String, Option<Value>);

/// A shared, cloneable record of every request a [`MockOpenSeaTransport`]
/// received, so tests can assert on what was actually sent (e.g. that the
/// mint endpoint is never called with a larger quantity than requested).
#[derive(Clone, Default)]
pub struct OpenSeaCaptureHandle {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl OpenSeaCaptureHandle {
    /// All `(method, path, body)` triples received, in call order.
    pub fn all(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .expect("capture mutex poisoned")
            .clone()
    }

    pub fn call_count(&self) -> usize {
        self.requests.lock().expect("capture mutex poisoned").len()
    }
}

/// A canned-response OpenSea transport, keyed by exact `"METHOD path"`.
pub struct MockOpenSeaTransport {
    entries: HashMap<String, Canned>,
    capture: OpenSeaCaptureHandle,
}

pub struct MockOpenSeaTransportBuilder {
    entries: HashMap<String, Canned>,
}

impl MockOpenSeaTransport {
    pub fn builder() -> MockOpenSeaTransportBuilder {
        MockOpenSeaTransportBuilder {
            entries: HashMap::new(),
        }
    }

    pub fn capture_handle(&self) -> OpenSeaCaptureHandle {
        self.capture.clone()
    }

    fn key(method: &str, path: &str) -> String {
        format!("{method} {path}")
    }

    fn record(&self, method: &str, path: &str, body: Option<&Value>) {
        self.capture
            .requests
            .lock()
            .expect("capture mutex poisoned")
            .push((method.to_string(), path.to_string(), body.cloned()));
    }

    fn resolve(&self, method: &str, path: &str) -> Result<HttpResponse, OpenSeaTransportError> {
        match self.entries.get(&Self::key(method, path)) {
            Some(Canned::Response { status, body }) => Ok(HttpResponse {
                status: *status,
                body: body.clone(),
            }),
            Some(Canned::Timeout) => Err(OpenSeaTransportError::Timeout(Duration::from_secs(0))),
            Some(Canned::Network(msg)) => Err(OpenSeaTransportError::Network(msg.clone())),
            None => Err(OpenSeaTransportError::Network(format!(
                "no mock response configured for {method} {path}"
            ))),
        }
    }
}

impl MockOpenSeaTransportBuilder {
    pub fn respond(mut self, method: &str, path: &str, status: u16, body: Value) -> Self {
        self.entries.insert(
            MockOpenSeaTransport::key(method, path),
            Canned::Response { status, body },
        );
        self
    }

    pub fn timeout(mut self, method: &str, path: &str) -> Self {
        self.entries
            .insert(MockOpenSeaTransport::key(method, path), Canned::Timeout);
        self
    }

    pub fn network_error(mut self, method: &str, path: &str, message: &str) -> Self {
        self.entries.insert(
            MockOpenSeaTransport::key(method, path),
            Canned::Network(message.to_string()),
        );
        self
    }

    pub fn build(self) -> MockOpenSeaTransport {
        MockOpenSeaTransport {
            entries: self.entries,
            capture: OpenSeaCaptureHandle::default(),
        }
    }
}

#[async_trait]
impl OpenSeaTransport for MockOpenSeaTransport {
    async fn get(&self, path: &str) -> Result<HttpResponse, OpenSeaTransportError> {
        self.record("GET", path, None);
        self.resolve("GET", path)
    }

    async fn post_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<HttpResponse, OpenSeaTransportError> {
        self.record("POST", path, Some(body));
        self.resolve("POST", path)
    }
}
