//! A pluggable HTTP transport for the OpenSea Drops API, mirroring
//! [`crate::chain::rpc::Transport`]'s shape: a narrow trait so tests can
//! inject [`super::mock::MockOpenSeaTransport`] instead of real network
//! access, and so [`super::client::OpenSeaClient`] reuses one real
//! `reqwest::Client` (built once) rather than a fresh client per request.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

/// A transport-level failure, independent of any HTTP-status-coded
/// response from OpenSea.
#[derive(Debug, thiserror::Error)]
pub enum OpenSeaTransportError {
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("network error: {0}")]
    Network(String),
    #[error("response was not valid JSON: {0}")]
    InvalidJson(String),
}

/// One HTTP response: status code plus parsed JSON body (or `Value::Null`
/// for an empty body).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

/// A pluggable OpenSea HTTP transport. `HttpOpenSeaTransport` is the real
/// implementation; tests inject [`super::mock::MockOpenSeaTransport`]
/// instead.
#[async_trait]
pub trait OpenSeaTransport: Send + Sync {
    async fn get(&self, path: &str) -> Result<HttpResponse, OpenSeaTransportError>;
    async fn post_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<HttpResponse, OpenSeaTransportError>;
}

/// A `reqwest`-backed transport reusing one client/connection pool across
/// every request, with a bounded per-call timeout and the API key sent
/// only as a header value (never logged, never included in any error
/// message this module produces).
pub struct HttpOpenSeaTransport {
    client: reqwest::Client,
    base_url: Url,
    api_key: String,
    timeout: Duration,
}

impl std::fmt::Debug for HttpOpenSeaTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOpenSeaTransport")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl HttpOpenSeaTransport {
    pub fn new(base_url: Url, api_key: String, timeout: Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            api_key,
            timeout,
        }
    }

    fn url_for(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .expect("base_url must be a valid base for path joining");
            for segment in path.split('/').filter(|s| !s.is_empty()) {
                segments.push(segment);
            }
        }
        url
    }

    async fn parse_response(
        &self,
        response: reqwest::Response,
    ) -> Result<HttpResponse, OpenSeaTransportError> {
        let status = response.status().as_u16();
        let bytes = tokio::time::timeout(self.timeout, response.bytes())
            .await
            .map_err(|_| OpenSeaTransportError::Timeout(self.timeout))?
            .map_err(|e| OpenSeaTransportError::Network(e.to_string()))?;
        if bytes.is_empty() {
            return Ok(HttpResponse {
                status,
                body: Value::Null,
            });
        }
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| OpenSeaTransportError::InvalidJson(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

#[async_trait]
impl OpenSeaTransport for HttpOpenSeaTransport {
    async fn get(&self, path: &str) -> Result<HttpResponse, OpenSeaTransportError> {
        let request = self
            .client
            .get(self.url_for(path))
            .header("x-api-key", &self.api_key)
            .send();
        let response = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| OpenSeaTransportError::Timeout(self.timeout))?
            .map_err(|e| OpenSeaTransportError::Network(e.to_string()))?;
        self.parse_response(response).await
    }

    async fn post_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<HttpResponse, OpenSeaTransportError> {
        let request = self
            .client
            .post(self.url_for(path))
            .header("x-api-key", &self.api_key)
            .json(body)
            .send();
        let response = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| OpenSeaTransportError::Timeout(self.timeout))?
            .map_err(|e| OpenSeaTransportError::Network(e.to_string()))?;
        self.parse_response(response).await
    }
}
