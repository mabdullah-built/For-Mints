//! RPC endpoint configuration: an endpoint's declared *role* determines how
//! Kairox is allowed to use it. Roles exist now so Phase 2's broadcast
//! fan-out has a stable shape to build on; Phase 1 only reads.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use super::registry::ChainId;

/// What an endpoint may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointRole {
    /// May be used for both state reads and (in later phases) sending.
    ReadWrite,
    /// Reads only (balances, nonces, calldata simulation, receipts).
    ReadOnly,
    /// Accepts `eth_sendRawTransaction` but is unsuitable/unreliable for
    /// reads (e.g. a sequencer ingress that doesn't serve state).
    SendOnly,
    /// A chain sequencer's direct ingress endpoint.
    Sequencer,
    /// A private/paid relay (e.g. MEV-protect style submission endpoint).
    Private,
    /// A public, unauthenticated endpoint.
    Public,
}

impl EndpointRole {
    /// Whether this role may be used to read chain state.
    pub fn can_read(self) -> bool {
        matches!(self, Self::ReadWrite | Self::ReadOnly | Self::Public)
    }

    /// Whether this role may be used to submit transactions.
    pub fn can_send(self) -> bool {
        matches!(
            self,
            Self::ReadWrite | Self::SendOnly | Self::Sequencer | Self::Private | Self::Public
        )
    }
}

/// A single configured RPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEndpoint {
    pub url: Url,
    pub role: EndpointRole,
    pub label: Option<String>,
    pub timeout: Duration,
}

/// Default bound on any single RPC round-trip. Kairox never retries
/// unboundedly; callers choose a small, explicit attempt count on top of
/// this per-call timeout.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

impl RpcEndpoint {
    pub fn new(url: Url, role: EndpointRole) -> Self {
        Self {
            url,
            role,
            label: None,
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// All configured endpoints for one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEndpoints {
    pub chain_id: ChainId,
    pub endpoints: Vec<RpcEndpoint>,
}

impl ChainEndpoints {
    pub fn new(chain_id: ChainId, endpoints: Vec<RpcEndpoint>) -> Self {
        Self {
            chain_id,
            endpoints,
        }
    }

    /// The first endpoint whose role permits reads, if any.
    pub fn preferred_read_endpoint(&self) -> Option<&RpcEndpoint> {
        self.endpoints.iter().find(|e| e.role.can_read())
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_only_cannot_read() {
        assert!(!EndpointRole::SendOnly.can_read());
        assert!(EndpointRole::SendOnly.can_send());
    }

    #[test]
    fn read_only_cannot_send() {
        assert!(EndpointRole::ReadOnly.can_read());
        assert!(!EndpointRole::ReadOnly.can_send());
    }

    #[test]
    fn read_write_can_do_both() {
        assert!(EndpointRole::ReadWrite.can_read());
        assert!(EndpointRole::ReadWrite.can_send());
    }

    #[test]
    fn preferred_read_endpoint_skips_send_only() {
        let send_only = RpcEndpoint::new(
            Url::parse("https://sequencer.example").unwrap(),
            EndpointRole::SendOnly,
        );
        let read_only = RpcEndpoint::new(
            Url::parse("https://reader.example").unwrap(),
            EndpointRole::ReadOnly,
        );
        let chain = ChainEndpoints::new(1, vec![send_only, read_only.clone()]);
        assert_eq!(chain.preferred_read_endpoint(), Some(&read_only));
    }

    #[test]
    fn preferred_read_endpoint_none_when_all_send_only() {
        let send_only = RpcEndpoint::new(
            Url::parse("https://sequencer.example").unwrap(),
            EndpointRole::SendOnly,
        );
        let chain = ChainEndpoints::new(1, vec![send_only]);
        assert!(chain.preferred_read_endpoint().is_none());
    }
}
