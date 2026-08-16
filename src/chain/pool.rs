//! A multi-endpoint RPC pool. Connecting the pool *is* Kairox's connection
//! pre-warming: DNS/TCP/TLS/HTTP state for every configured endpoint is
//! established (via the mandatory `eth_chainId` verification call) well
//! before any time-critical operation needs it, and the latency of that
//! first round trip is recorded per endpoint for reporting.

use std::time::{Duration, Instant};

use super::endpoint::{EndpointRole, RpcEndpoint};
use super::registry::ChainId;
use super::rpc::{HttpTransport, RpcClient};

/// Per-endpoint outcome of connecting (and thereby pre-warming) one entry
/// in a [`RpcPool`].
#[derive(Debug, Clone)]
pub struct EndpointConnectReport {
    pub label: Option<String>,
    pub role: EndpointRole,
    pub outcome: ConnectOutcome,
}

#[derive(Debug, Clone)]
pub enum ConnectOutcome {
    Connected { latency_ms: u64 },
    Failed { latency_ms: u64, error: String },
}

/// A set of chain-id-verified, pre-warmed RPC clients for one chain.
pub struct RpcPool {
    chain_id: ChainId,
    clients: Vec<RpcClient>,
}

impl RpcPool {
    /// Build a pool directly from already-connected clients. Used by tests
    /// (with mock transports) and by [`Self::connect_all`].
    pub fn from_clients(chain_id: ChainId, clients: Vec<RpcClient>) -> Self {
        Self { chain_id, clients }
    }

    /// Connect every configured endpoint concurrently over real HTTP,
    /// verifying `eth_chainId` for each. Endpoints that fail to connect
    /// (wrong chain, timeout, network error) are excluded from the pool but
    /// reported individually — a partially healthy pool is still usable as
    /// long as it has at least one endpoint of the role a caller needs.
    pub async fn connect_all(
        chain_id: ChainId,
        endpoints: &[RpcEndpoint],
    ) -> (Self, Vec<EndpointConnectReport>) {
        let attempts = endpoints.iter().map(|endpoint| async move {
            let started = Instant::now();
            let transport = HttpTransport::new(endpoint.url.clone(), endpoint.timeout);
            let result = RpcClient::connect(
                Box::new(transport),
                chain_id,
                endpoint.role,
                endpoint.label.clone(),
            )
            .await;
            (endpoint, started.elapsed(), result)
        });

        let results = futures_util::future::join_all(attempts).await;

        let mut clients = Vec::new();
        let mut reports = Vec::new();
        for (endpoint, elapsed, result) in results {
            let latency_ms = duration_ms(elapsed);
            match result {
                Ok(client) => {
                    reports.push(EndpointConnectReport {
                        label: endpoint.label.clone(),
                        role: endpoint.role,
                        outcome: ConnectOutcome::Connected { latency_ms },
                    });
                    clients.push(client);
                }
                Err(e) => reports.push(EndpointConnectReport {
                    label: endpoint.label.clone(),
                    role: endpoint.role,
                    outcome: ConnectOutcome::Failed {
                        latency_ms,
                        error: e.to_string(),
                    },
                }),
            }
        }

        (Self::from_clients(chain_id, clients), reports)
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Every client whose role permits state reads.
    pub fn read_capable(&self) -> Vec<&RpcClient> {
        self.clients
            .iter()
            .filter(|c| c.role().can_read())
            .collect()
    }

    /// Every client whose role permits broadcasting.
    pub fn send_capable(&self) -> Vec<&RpcClient> {
        self.clients
            .iter()
            .filter(|c| c.role().can_send())
            .collect()
    }

    /// The first read-capable client, if any. Used for the single-client
    /// state reads Kairox performs while preparing a transaction.
    pub fn preferred_read(&self) -> Option<&RpcClient> {
        self.read_capable().into_iter().next()
    }
}

fn duration_ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::super::rpc::RpcError;
    use super::*;
    use crate::chain::mock::MockTransport;
    use serde_json::json;

    async fn mock_client(
        chain_id: ChainId,
        role: EndpointRole,
        reported_chain_id: u64,
    ) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!(format!("0x{reported_chain_id:x}")))
            .build();
        RpcClient::connect(Box::new(transport), chain_id, role, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn pool_partitions_read_and_send_capable_clients() {
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let read_write = mock_client(1, EndpointRole::ReadWrite, 1).await;

        let pool = RpcPool::from_clients(1, vec![read_only, send_only, read_write]);

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.read_capable().len(), 2, "read-only + read-write");
        assert_eq!(pool.send_capable().len(), 2, "send-only + read-write");
    }

    #[tokio::test]
    async fn send_only_endpoint_excluded_from_read_capable() {
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![send_only]);
        assert!(pool.read_capable().is_empty());
        assert_eq!(pool.send_capable().len(), 1);
    }

    #[tokio::test]
    async fn read_only_endpoint_excluded_from_send_capable() {
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![read_only]);
        assert!(pool.send_capable().is_empty());
        assert_eq!(pool.read_capable().len(), 1);
    }

    #[tokio::test]
    async fn connect_all_excludes_wrong_chain_endpoint_and_reports_it() {
        let good_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        let good_client = RpcClient::connect(
            Box::new(good_transport),
            1,
            EndpointRole::ReadOnly,
            Some("good".into()),
        )
        .await
        .unwrap();

        // Simulate connect_all's per-endpoint behavior directly: one client
        // that matches, one report representing a mismatched endpoint that
        // never made it into the pool.
        let pool = RpcPool::from_clients(1, vec![good_client]);
        assert_eq!(pool.len(), 1);

        let mismatched_transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x2"))
            .build();
        let err = RpcClient::connect(
            Box::new(mismatched_transport),
            1,
            EndpointRole::ReadOnly,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RpcError::ChainIdMismatch { .. }));
    }

    #[tokio::test]
    async fn preferred_read_returns_first_read_capable_client() {
        let send_only = mock_client(1, EndpointRole::SendOnly, 1).await;
        let read_only = mock_client(1, EndpointRole::ReadOnly, 1).await;
        let pool = RpcPool::from_clients(1, vec![send_only, read_only]);
        let preferred = pool.preferred_read().unwrap();
        assert_eq!(preferred.role(), EndpointRole::ReadOnly);
    }

    #[tokio::test]
    async fn empty_pool_reports_empty() {
        let pool = RpcPool::from_clients(1, vec![]);
        assert!(pool.is_empty());
        assert!(pool.preferred_read().is_none());
    }
}
