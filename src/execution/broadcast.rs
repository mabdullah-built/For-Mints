//! Concurrent, identical-raw-transaction fan-out and result classification.
//!
//! Exactly one signed transaction is ever produced upstream (see
//! [`super::prepared`]); this module only ever broadcasts that same raw
//! byte string to every send-capable endpoint. It never signs a second
//! variant, and it never manufactures a second transaction hash for one
//! intended attempt.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use time::OffsetDateTime;

use crate::chain::rpc::{PreparedBroadcast, RpcClient, RpcError, TransportError};

use super::errors::{KairoxError, SessionError};

/// The classified result of one endpoint's `eth_sendRawTransaction`
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// The endpoint accepted the transaction and echoed back the expected
    /// hash.
    Accepted { tx_hash: B256 },
    /// The endpoint reported the transaction as already known to it (e.g.
    /// another endpoint's broadcast already propagated here). Evidence the
    /// transaction may be in flight — not proof the mint itself succeeded.
    AlreadyKnown,
    /// A rejection that, on its own and without further chain state,
    /// appears to reflect a transient condition (e.g. fee too low right
    /// now). Kairox does not automatically retry.
    RetryableRejection { message: String },
    /// A rejection that reflects a condition this exact transaction cannot
    /// recover from (e.g. nonce too low, insufficient funds).
    FatalRejection { message: String },
    /// The request timed out with no response. Whether the node received
    /// and is holding the transaction is genuinely unknown.
    TimeoutUnknown,
    /// A transport-level failure (connection reset, DNS failure, etc.)
    /// with no response. Outcome unknown.
    TransportUnknown { message: String },
}

impl BroadcastOutcome {
    /// Whether this outcome is direct evidence the transaction reached (or
    /// was already known to) this endpoint's mempool view.
    pub fn is_propagation_evidence(&self) -> bool {
        matches!(self, Self::Accepted { .. } | Self::AlreadyKnown)
    }

    /// Whether the true outcome at this endpoint is unknown (timeout or
    /// transport failure with no response).
    pub fn is_uncertain(&self) -> bool {
        matches!(self, Self::TimeoutUnknown | Self::TransportUnknown { .. })
    }
}

/// Classify a failed `eth_sendRawTransaction` call. `Ok` responses are
/// handled by the caller (they carry the accepted hash directly).
pub fn classify_send_error(error: &RpcError) -> BroadcastOutcome {
    match error {
        RpcError::Transport(TransportError::Timeout(_)) => BroadcastOutcome::TimeoutUnknown,
        RpcError::Transport(TransportError::Network(message)) => {
            BroadcastOutcome::TransportUnknown {
                message: message.clone(),
            }
        }
        RpcError::Transport(TransportError::InvalidJson(message)) => {
            BroadcastOutcome::TransportUnknown {
                message: message.clone(),
            }
        }
        RpcError::ChainIdMismatch { .. } => BroadcastOutcome::FatalRejection {
            message: error.to_string(),
        },
        // Should never actually occur: `broadcast_to_all` only calls
        // `send_raw_transaction` on send-capable clients. If it somehow
        // does, this is a Kairox bug, not a chain condition — fatal either
        // way, never silently retried.
        RpcError::CapabilityDenied { .. } => BroadcastOutcome::FatalRejection {
            message: error.to_string(),
        },
        RpcError::MalformedResponse(message) => BroadcastOutcome::TransportUnknown {
            message: message.clone(),
        },
        RpcError::RpcReturnedError { message, .. } => classify_rpc_rejection_message(message),
    }
}

fn classify_rpc_rejection_message(message: &str) -> BroadcastOutcome {
    let lower = message.to_ascii_lowercase();
    if lower.contains("already known") || lower.contains("already exists") {
        return BroadcastOutcome::AlreadyKnown;
    }
    const FATAL_PATTERNS: [&str; 5] = [
        "nonce too low",
        "insufficient funds",
        "invalid signature",
        "invalid sender",
        "gas limit reached",
    ];
    if FATAL_PATTERNS.iter().any(|p| lower.contains(p)) {
        return BroadcastOutcome::FatalRejection {
            message: message.to_string(),
        };
    }
    const RETRYABLE_PATTERNS: [&str; 3] = [
        "underpriced",
        "fee too low",
        "replacement transaction underpriced",
    ];
    if RETRYABLE_PATTERNS.iter().any(|p| lower.contains(p)) {
        return BroadcastOutcome::RetryableRejection {
            message: message.to_string(),
        };
    }
    // Unrecognized rejection reasons are treated as fatal for this attempt
    // rather than silently retried.
    BroadcastOutcome::FatalRejection {
        message: message.to_string(),
    }
}

/// One endpoint's full broadcast record: identity, timing, and outcome.
#[derive(Debug, Clone)]
pub struct EndpointBroadcastResult {
    pub label: String,
    pub role: crate::chain::endpoint::EndpointRole,
    pub dispatched_at: OffsetDateTime,
    pub responded_at: Option<OffsetDateTime>,
    pub latency_ms: Option<u64>,
    pub outcome: BroadcastOutcome,
}

/// Dispatch the exact same prebuilt `eth_sendRawTransaction` request to
/// every client in `clients`, concurrently. This is the T=0 hot path: no
/// hex-encoding, JSON construction, or serialization happens here or in
/// anything it calls — `prepared.json_rpc_body` was already built once,
/// ahead of time (see [`crate::execution::prepared::prepare_live_transaction`]),
/// and is sent to every endpoint byte-for-byte identical.
pub async fn broadcast_to_all(
    clients: &[&RpcClient],
    prepared: &PreparedBroadcast,
) -> Vec<EndpointBroadcastResult> {
    let attempts = clients.iter().enumerate().map(|(i, client)| async move {
        let label = client
            .label()
            .map(str::to_string)
            .unwrap_or_else(|| format!("endpoint[{i}]"));
        let dispatched_at = OffsetDateTime::now_utc();
        let started = Instant::now();
        let result = client.broadcast_prepared(prepared).await;
        let elapsed = started.elapsed();
        let responded_at = Some(OffsetDateTime::now_utc());
        let latency_ms = Some(duration_ms(elapsed));

        let outcome = match result {
            Ok(reported_hash) if reported_hash == prepared.tx_hash => BroadcastOutcome::Accepted {
                tx_hash: reported_hash,
            },
            Ok(reported_hash) => BroadcastOutcome::FatalRejection {
                message: format!(
                    "endpoint returned unexpected tx hash {reported_hash} (expected {})",
                    prepared.tx_hash
                ),
            },
            Err(e) => classify_send_error(&e),
        };

        EndpointBroadcastResult {
            label,
            role: client.role(),
            dispatched_at,
            responded_at,
            latency_ms,
            outcome,
        }
    });

    futures_util::future::join_all(attempts).await
}

fn duration_ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

/// The overall verdict across every endpoint's broadcast attempt for one
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastSummary {
    /// At least one endpoint confirms the transaction reached a mempool.
    Confirmed { tx_hash: B256 },
    /// Every endpoint definitively rejected the transaction; none reported
    /// acceptance and none were uncertain. Safe to conclude nothing was
    /// broadcast.
    AllRejected,
    /// At least one endpoint's outcome is unknown (timeout/transport
    /// failure) and no endpoint confirmed propagation. The transaction may
    /// or may not have reached a mempool — this is the
    /// `MUST_STOP_SESSION` case.
    Uncertain,
}

pub fn summarize_broadcast(results: &[EndpointBroadcastResult]) -> BroadcastSummary {
    if let Some(tx_hash) = results.iter().find_map(|r| match &r.outcome {
        BroadcastOutcome::Accepted { tx_hash } => Some(*tx_hash),
        _ => None,
    }) {
        return BroadcastSummary::Confirmed { tx_hash };
    }
    if results
        .iter()
        .any(|r| r.outcome == BroadcastOutcome::AlreadyKnown)
    {
        // AlreadyKnown carries no hash of its own but is still direct
        // propagation evidence; we don't have a locally-observed hash to
        // attach beyond what the caller already knows was intended.
        return BroadcastSummary::Confirmed {
            tx_hash: B256::ZERO,
        };
    }
    if results.iter().any(|r| r.outcome.is_uncertain()) {
        return BroadcastSummary::Uncertain;
    }
    BroadcastSummary::AllRejected
}

/// Convert a [`BroadcastSummary::Uncertain`] into the mandatory
/// `MUST_STOP_SESSION` error. Kairox never automatically constructs a
/// replacement transaction when a prior attempt's outcome is unknown.
pub fn uncertain_outcome_error(results: &[EndpointBroadcastResult]) -> KairoxError {
    let detail = results
        .iter()
        .map(|r| format!("{}: {:?}", r.label, r.outcome))
        .collect::<Vec<_>>()
        .join("; ");
    KairoxError::Session(SessionError(format!(
        "broadcast outcome uncertain across all endpoints — refusing to construct a replacement \
         transaction until this is manually resolved. Per-endpoint results: {detail}"
    )))
}

#[cfg(test)]
mod tests {
    use super::super::errors::{Categorize, ErrorCategory};
    use super::*;
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use serde_json::json;

    fn expected_hash() -> B256 {
        B256::repeat_byte(0xaa)
    }

    async fn accepting_client(label: &str) -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_sendRawTransaction",
                json!(format!("0x{}", hex::encode(expected_hash()))),
            )
            .build();
        RpcClient::connect(
            Box::new(transport),
            1,
            EndpointRole::SendOnly,
            Some(label.to_string()),
        )
        .await
        .unwrap()
    }

    #[test]
    fn classify_timeout_as_unknown() {
        let err = RpcError::Transport(TransportError::Timeout(Duration::from_secs(1)));
        assert_eq!(classify_send_error(&err), BroadcastOutcome::TimeoutUnknown);
    }

    #[test]
    fn classify_already_known() {
        let err = RpcError::RpcReturnedError {
            code: -32000,
            message: "already known".into(),
        };
        assert_eq!(classify_send_error(&err), BroadcastOutcome::AlreadyKnown);
    }

    #[test]
    fn classify_nonce_too_low_as_fatal() {
        let err = RpcError::RpcReturnedError {
            code: -32000,
            message: "nonce too low".into(),
        };
        assert!(matches!(
            classify_send_error(&err),
            BroadcastOutcome::FatalRejection { .. }
        ));
    }

    #[test]
    fn classify_underpriced_as_retryable() {
        let err = RpcError::RpcReturnedError {
            code: -32000,
            message: "transaction underpriced".into(),
        };
        assert!(matches!(
            classify_send_error(&err),
            BroadcastOutcome::RetryableRejection { .. }
        ));
    }

    #[tokio::test]
    async fn broadcast_to_all_sends_identical_raw_bytes_and_matching_hash() {
        let client_a = accepting_client("a").await;
        let client_b = accepting_client("b").await;
        let raw = alloy_primitives::Bytes::from(vec![0x02, 0xde, 0xad, 0xbe, 0xef]);
        let prepared = PreparedBroadcast::build(expected_hash(), raw);

        let results = broadcast_to_all(&[&client_a, &client_b], &prepared).await;

        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(
                r.outcome,
                BroadcastOutcome::Accepted {
                    tx_hash: expected_hash()
                }
            );
        }
    }

    #[tokio::test]
    async fn broadcast_to_all_flags_mismatched_returned_hash_as_fatal() {
        let wrong_hash = B256::repeat_byte(0x99);
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .respond(
                "eth_sendRawTransaction",
                json!(format!("0x{}", hex::encode(wrong_hash))),
            )
            .build();
        let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::SendOnly, None)
            .await
            .unwrap();
        let raw = alloy_primitives::Bytes::from(vec![0x02]);
        let prepared = PreparedBroadcast::build(expected_hash(), raw);

        let results = broadcast_to_all(&[&client], &prepared).await;
        assert!(matches!(
            results[0].outcome,
            BroadcastOutcome::FatalRejection { .. }
        ));
    }

    #[tokio::test]
    async fn broadcast_to_all_sends_byte_identical_prebuilt_json_bodies() {
        let transport_a = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .echo_raw_transaction_hash()
            .build();
        let capture_a = transport_a.capture_handle();
        let client_a = RpcClient::connect(
            Box::new(transport_a),
            1,
            EndpointRole::SendOnly,
            Some("a".into()),
        )
        .await
        .unwrap();

        let transport_b = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .echo_raw_transaction_hash()
            .build();
        let capture_b = transport_b.capture_handle();
        let client_b = RpcClient::connect(
            Box::new(transport_b),
            1,
            EndpointRole::Sequencer,
            Some("b".into()),
        )
        .await
        .unwrap();

        let raw = alloy_primitives::Bytes::from(vec![0x02, 0x01, 0x02, 0x03]);
        let tx_hash = alloy_primitives::keccak256(&raw);
        let prepared = PreparedBroadcast::build(tx_hash, raw);

        let results = broadcast_to_all(&[&client_a, &client_b], &prepared).await;
        for r in &results {
            assert_eq!(r.outcome, BroadcastOutcome::Accepted { tx_hash });
        }

        let body_a = capture_a.prebuilt_bodies();
        let body_b = capture_b.prebuilt_bodies();
        assert_eq!(body_a.len(), 1);
        assert_eq!(body_b.len(), 1);
        assert_eq!(
            body_a[0], body_b[0],
            "every endpoint must receive the byte-identical prebuilt JSON-RPC body"
        );
        assert_eq!(body_a[0], prepared.json_rpc_body);
    }

    #[test]
    fn summarize_confirmed_when_any_accepted() {
        let results = vec![EndpointBroadcastResult {
            label: "a".into(),
            role: EndpointRole::SendOnly,
            dispatched_at: OffsetDateTime::now_utc(),
            responded_at: None,
            latency_ms: None,
            outcome: BroadcastOutcome::Accepted {
                tx_hash: expected_hash(),
            },
        }];
        assert_eq!(
            summarize_broadcast(&results),
            BroadcastSummary::Confirmed {
                tx_hash: expected_hash()
            }
        );
    }

    #[test]
    fn summarize_all_rejected_when_every_endpoint_fatal() {
        let results = vec![EndpointBroadcastResult {
            label: "a".into(),
            role: EndpointRole::SendOnly,
            dispatched_at: OffsetDateTime::now_utc(),
            responded_at: None,
            latency_ms: None,
            outcome: BroadcastOutcome::FatalRejection {
                message: "nonce too low".into(),
            },
        }];
        assert_eq!(summarize_broadcast(&results), BroadcastSummary::AllRejected);
    }

    #[test]
    fn summarize_uncertain_when_timeout_present_and_nothing_confirmed() {
        let results = vec![
            EndpointBroadcastResult {
                label: "a".into(),
                role: EndpointRole::SendOnly,
                dispatched_at: OffsetDateTime::now_utc(),
                responded_at: None,
                latency_ms: None,
                outcome: BroadcastOutcome::TimeoutUnknown,
            },
            EndpointBroadcastResult {
                label: "b".into(),
                role: EndpointRole::SendOnly,
                dispatched_at: OffsetDateTime::now_utc(),
                responded_at: None,
                latency_ms: None,
                outcome: BroadcastOutcome::FatalRejection {
                    message: "boom".into(),
                },
            },
        ];
        assert_eq!(summarize_broadcast(&results), BroadcastSummary::Uncertain);
    }

    #[test]
    fn uncertain_outcome_maps_to_must_stop_session() {
        let results = vec![EndpointBroadcastResult {
            label: "a".into(),
            role: EndpointRole::SendOnly,
            dispatched_at: OffsetDateTime::now_utc(),
            responded_at: None,
            latency_ms: None,
            outcome: BroadcastOutcome::TimeoutUnknown,
        }];
        let err = uncertain_outcome_error(&results);
        assert!(matches!(err.category(), ErrorCategory::MustStopSession));
    }
}
