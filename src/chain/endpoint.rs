//! RPC endpoint configuration: an endpoint's declared *role* determines how
//! Kairox is allowed to use it -- reads, sends, or both -- and gates the
//! broadcast fan-out in [`crate::execution::broadcast`].

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

/// The outcome of establishing trust in one endpoint at connect time.
///
/// A read-capable role (`ReadWrite`, `ReadOnly`, `Public`) always requires a
/// successful, matching `eth_chainId` — there is no degraded state for
/// those roles; they either become `VerifiedReadWrite`/`VerifiedReadOnly`
/// or the connection attempt fails outright.
///
/// A send-only-capable role (`SendOnly`, `Sequencer`, `Private`) is allowed
/// to lack `eth_chainId` support entirely — many real sequencer/relay
/// ingress endpoints only implement `eth_sendRawTransaction` — but such an
/// endpoint is never treated as chain-verified. It is trusted for
/// broadcasting only because it was explicitly configured under that exact
/// chain id (`KAIROX_RPC_<chainId>_<index>_URL`), never because Kairox
/// guessed or defaulted its chain association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointVerification {
    /// Read+send role, `eth_chainId` succeeded and matched.
    VerifiedReadWrite,
    /// Read-only role, `eth_chainId` succeeded and matched.
    VerifiedReadOnly,
    /// Send-only-capable role, `eth_chainId` succeeded and matched anyway
    /// (some sequencer/relay endpoints do implement it).
    VerifiedSend,
    /// Send-only-capable role, `eth_chainId` is unsupported or failed.
    /// Trusted for broadcast only via its explicit chain-id configuration
    /// binding — never used for any state read.
    ConfiguredSendOnly,
}

impl EndpointVerification {
    /// Whether `eth_chainId` was independently confirmed for this
    /// endpoint. `false` means chain association rests entirely on
    /// configuration (only ever true for `ConfiguredSendOnly`).
    pub fn chain_id_confirmed(self) -> bool {
        !matches!(self, Self::ConfiguredSendOnly)
    }

    /// A short, stable label for display (`doctor`/`bench`).
    pub fn status_label(self) -> &'static str {
        match self {
            Self::VerifiedReadWrite | Self::VerifiedReadOnly | Self::VerifiedSend => "VERIFIED",
            Self::ConfiguredSendOnly => "SUBMISSION_ONLY",
        }
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
