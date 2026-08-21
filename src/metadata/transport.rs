//! A pluggable HTTP transport for verified-metadata providers, mirroring
//! [`crate::opensea::transport::OpenSeaTransport`]'s shape. No API key --
//! Blockscout's public v2 REST API requires none for read access
//! (verified directly against a live instance).

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum MetadataTransportError {
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("network error: {0}")]
    Network(String),
    #[error("response was not valid JSON: {0}")]
    InvalidJson(String),
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

/// A pluggable metadata-provider HTTP transport. `HttpMetadataTransport` is
/// the real implementation; tests inject a mock instead.
#[async_trait]
pub trait MetadataTransport: Send + Sync {
    async fn get(&self, path: &str) -> Result<HttpResponse, MetadataTransportError>;
}

pub struct HttpMetadataTransport {
    client: reqwest::Client,
    base_url: Url,
    timeout: Duration,
}

impl HttpMetadataTransport {
    pub fn new(base_url: Url, timeout: Duration) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
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
}

#[async_trait]
impl MetadataTransport for HttpMetadataTransport {
    async fn get(&self, path: &str) -> Result<HttpResponse, MetadataTransportError> {
        let request = self.client.get(self.url_for(path)).send();
        let response = tokio::time::timeout(self.timeout, request)
            .await
            .map_err(|_| MetadataTransportError::Timeout(self.timeout))?
            .map_err(|e| MetadataTransportError::Network(e.to_string()))?;
        let status = response.status().as_u16();
        let bytes = tokio::time::timeout(self.timeout, response.bytes())
            .await
            .map_err(|_| MetadataTransportError::Timeout(self.timeout))?
            .map_err(|e| MetadataTransportError::Network(e.to_string()))?;
        if bytes.is_empty() {
            return Ok(HttpResponse {
                status,
                body: Value::Null,
            });
        }
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| MetadataTransportError::InvalidJson(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}
