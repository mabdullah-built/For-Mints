//! Small, dependency-free display helpers shared by CLI commands.

use alloy_primitives::{Address, U256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use crate::chain::benchmark::{BroadcastLatency, EndpointBenchmark};
use crate::chain::endpoint::EndpointRole;
use crate::chain::pool::ConnectOutcome;
use crate::chain::registry::ChainId;
use crate::execution::errors::{KairoxError, SessionError};

/// Parse a base-10 wei amount from a CLI argument, with a clear error
/// message naming the offending field.
pub fn parse_wei(field: &str, value: &str) -> Result<U256, KairoxError> {
    U256::from_str_radix(value, 10)
        .map_err(|e| KairoxError::Session(SessionError(format!("invalid {field} '{value}': {e}"))))
}

/// Parse an integer-gwei CLI argument into wei.
pub fn parse_gwei_to_wei(field: &str, value: &str) -> Result<u128, KairoxError> {
    let gwei: u128 = value.parse().map_err(|_| {
        KairoxError::Session(SessionError(format!(
            "invalid {field} '{value}': expected an integer number of gwei"
        )))
    })?;
    gwei.checked_mul(1_000_000_000).ok_or_else(|| {
        KairoxError::Session(SessionError(format!(
            "{field} '{value}' overflows when converted to wei"
        )))
    })
}

pub fn format_unix(seconds: u64) -> String {
    let Ok(secs_i64) = i64::try_from(seconds) else {
        return format!("<invalid unix timestamp {seconds}>");
    };
    match OffsetDateTime::from_unix_timestamp(secs_i64) {
        Ok(dt) => dt
            .format(&Rfc3339)
            .unwrap_or_else(|_| format!("unix {seconds}")),
        Err(_) => format!("<invalid unix timestamp {seconds}>"),
    }
}

pub fn format_addr_list(addrs: &[Address]) -> String {
    if addrs.is_empty() {
        "none".to_string()
    } else {
        addrs
            .iter()
            .map(Address::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub fn format_selector(selector: [u8; 4]) -> String {
    format!("0x{}", hex::encode(selector))
}

/// Redact an RPC URL's query string (where API keys typically live) before
/// printing it, e.g. in `kairox doctor` output.
pub fn mask_url(url: &Url) -> String {
    let mut masked = url.clone();
    if masked.query().is_some() {
        masked.set_query(Some("REDACTED"));
    }
    masked.to_string()
}

/// Render one endpoint's connection/capability report, deliberately never
/// collapsing a `ConfiguredSendOnly` (unverifiable, submission-only)
/// endpoint into the same "chainId MATCHES"-style display as a genuinely
/// `eth_chainId`-verified one. Shared by `doctor` and `bench` so both stay
/// consistent.
pub fn format_endpoint_status(
    label: &str,
    masked_url: &str,
    role: EndpointRole,
    chain_id: ChainId,
    outcome: &ConnectOutcome,
) -> String {
    match outcome {
        ConnectOutcome::Connected {
            latency_ms,
            verification,
        } => {
            let eth_chain_id = if verification.chain_id_confirmed() {
                "verified"
            } else {
                "unsupported"
            };
            format!(
                "{label} {masked_url}\n    role={role:?} read={} send={} chain_binding=configured:{chain_id} eth_chainId={eth_chain_id} status={} latency={latency_ms}ms",
                yes_no(role.can_read()),
                yes_no(role.can_send()),
                verification.status_label(),
            )
        }
        ConnectOutcome::Failed { latency_ms, error } => {
            format!(
                "{label} {masked_url}\n    role={role:?} read={} send={} chain_binding=configured:{chain_id} status=UNREACHABLE latency={latency_ms}ms error={error}",
                yes_no(role.can_read()),
                yes_no(role.can_send()),
            )
        }
        ConnectOutcome::WrongChain {
            latency_ms,
            expected,
            reported,
        } => {
            format!(
                "{label} {masked_url}\n    role={role:?} read={} send={} chain_binding=configured:{chain_id} status=WRONG_CHAIN expected={expected} reported={reported} latency={latency_ms}ms",
                yes_no(role.can_read()),
                yes_no(role.can_send()),
            )
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Render one endpoint's full Phase 3 benchmark/selection report: role,
/// verification, capability, latency statistics (when measurable), and
/// whether it was actually selected for reads/sends. Never labels a
/// `ConfiguredSendOnly` endpoint's unmeasurable read/broadcast latency as
/// anything but explicitly unknown.
pub fn format_benchmark_report(
    masked_url: &str,
    chain_id: ChainId,
    bench: &EndpointBenchmark,
    selected_read: bool,
    selected_send: bool,
) -> String {
    let mut lines = vec![
        format!(
            "{} {}",
            bench.label.as_deref().unwrap_or("(unlabeled)"),
            masked_url
        ),
        format!("    role={:?}", bench.role),
        format!("    verification={}", bench.verification.status_label()),
        format!("    read={}", yes_no(bench.role.can_read())),
        format!("    send={}", yes_no(bench.role.can_send())),
        format!("    chain_binding=configured:{chain_id}"),
    ];

    match &bench.read_latency {
        Some(stats) if stats.sample_count > 0 => {
            lines.push(format!(
                "    read_latency: samples={} median={} p90={} p95={} failures={} timeouts={}",
                stats.sample_count,
                fmt_opt_ms(stats.median_ms),
                fmt_opt_ms(stats.p90_ms),
                fmt_opt_ms(stats.p95_ms),
                stats.failures,
                stats.timeouts,
            ));
        }
        _ => lines.push("    read_latency=N/A".to_string()),
    }

    let broadcast_latency = match bench.broadcast_latency {
        BroadcastLatency::NotApplicable => "N/A",
        BroadcastLatency::UnknownUntilRealAttempt => "UNKNOWN_UNTIL_REAL_ATTEMPT",
    };
    lines.push(format!("    broadcast_latency={broadcast_latency}"));

    if let Some(ms) = bench.connection_latency_ms {
        lines.push(format!("    connection_latency={ms}ms"));
    }

    lines.push(format!("    selected_read={}", yes_no(selected_read)));
    lines.push(format!("    selected_send={}", yes_no(selected_send)));

    lines.join("\n")
}

fn fmt_opt_ms(v: Option<u64>) -> String {
    match v {
        Some(ms) => format!("{ms}ms"),
        None => "n/a".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::endpoint::EndpointVerification;

    #[test]
    fn parse_wei_accepts_decimal() {
        assert_eq!(parse_wei("x", "1000").unwrap(), U256::from(1000u64));
    }

    #[test]
    fn parse_wei_rejects_garbage() {
        assert!(parse_wei("x", "not-a-number").is_err());
    }

    #[test]
    fn parse_gwei_to_wei_multiplies_by_1e9() {
        assert_eq!(parse_gwei_to_wei("x", "2").unwrap(), 2_000_000_000u128);
    }

    #[test]
    fn mask_url_redacts_query() {
        let url = Url::parse("https://example.com/v1?apikey=SECRET").unwrap();
        let masked = mask_url(&url);
        assert!(!masked.contains("SECRET"));
        assert!(masked.contains("REDACTED"));
    }

    #[test]
    fn mask_url_leaves_url_without_query_unchanged() {
        let url = Url::parse("https://example.com/v1").unwrap();
        assert_eq!(mask_url(&url), "https://example.com/v1");
    }

    #[test]
    fn format_selector_is_0x_prefixed_hex() {
        assert_eq!(format_selector([0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
    }

    #[test]
    fn format_endpoint_status_distinguishes_submission_only_from_verified() {
        let verified = format_endpoint_status(
            "reader",
            "https://rpc.example",
            EndpointRole::ReadOnly,
            1,
            &ConnectOutcome::Connected {
                latency_ms: 12,
                verification: EndpointVerification::VerifiedReadOnly,
            },
        );
        assert!(verified.contains("status=VERIFIED"));
        assert!(verified.contains("eth_chainId=verified"));
        assert!(!verified.contains("SUBMISSION_ONLY"));

        let submission_only = format_endpoint_status(
            "robinhood-sequencer",
            "https://sequencer.example",
            EndpointRole::Sequencer,
            4663,
            &ConnectOutcome::Connected {
                latency_ms: 8,
                verification: EndpointVerification::ConfiguredSendOnly,
            },
        );
        assert!(submission_only.contains("status=SUBMISSION_ONLY"));
        assert!(submission_only.contains("eth_chainId=unsupported"));
        assert!(submission_only.contains("chain_binding=configured:4663"));
        assert!(submission_only.contains("read=no"));
        assert!(submission_only.contains("send=yes"));
        assert!(!submission_only.contains("status=VERIFIED"));
    }

    #[test]
    fn format_endpoint_status_distinguishes_wrong_chain_from_unreachable() {
        let wrong_chain = format_endpoint_status(
            "mismatched",
            "https://rpc.example",
            EndpointRole::ReadOnly,
            4663,
            &ConnectOutcome::WrongChain {
                latency_ms: 15,
                expected: 4663,
                reported: 1,
            },
        );
        assert!(wrong_chain.contains("status=WRONG_CHAIN"));
        assert!(wrong_chain.contains("expected=4663"));
        assert!(wrong_chain.contains("reported=1"));
        assert!(!wrong_chain.contains("status=UNREACHABLE"));

        let unreachable = format_endpoint_status(
            "dead",
            "https://dead.example",
            EndpointRole::SendOnly,
            4663,
            &ConnectOutcome::Failed {
                latency_ms: 30,
                error: "network error".into(),
            },
        );
        assert!(unreachable.contains("status=UNREACHABLE"));
        assert!(!unreachable.contains("WRONG_CHAIN"));
    }

    #[test]
    fn format_endpoint_status_never_labels_submission_only_as_matches() {
        let submission_only = format_endpoint_status(
            "seq",
            "https://sequencer.example",
            EndpointRole::SendOnly,
            1,
            &ConnectOutcome::Connected {
                latency_ms: 5,
                verification: EndpointVerification::ConfiguredSendOnly,
            },
        );
        assert!(!submission_only.to_uppercase().contains("MATCHES"));
    }

    #[test]
    fn format_benchmark_report_shows_na_for_unmeasurable_submission_only_endpoint() {
        use crate::chain::endpoint::EndpointRole;

        let bench = EndpointBenchmark {
            label: Some("robinhood-sequencer".into()),
            role: EndpointRole::Sequencer,
            verification: EndpointVerification::ConfiguredSendOnly,
            connection_latency_ms: Some(8),
            read_latency: None,
            broadcast_latency: BroadcastLatency::UnknownUntilRealAttempt,
            prewarm_status: None,
            prewarm_latency_ms: None,
        };
        let report =
            format_benchmark_report("https://sequencer.example", 4663, &bench, false, true);
        assert!(report.contains("read_latency=N/A"));
        assert!(report.contains("broadcast_latency=UNKNOWN_UNTIL_REAL_ATTEMPT"));
        assert!(report.contains("selected_read=no"));
        assert!(report.contains("selected_send=yes"));
        assert!(report.contains("chain_binding=configured:4663"));
    }

    #[test]
    fn format_benchmark_report_shows_latency_stats_for_verified_read_endpoint() {
        use crate::chain::benchmark::LatencyStats;
        use crate::chain::endpoint::EndpointRole;

        let bench = EndpointBenchmark {
            label: Some("robinhood-rpc-1".into()),
            role: EndpointRole::ReadWrite,
            verification: EndpointVerification::VerifiedReadWrite,
            connection_latency_ms: Some(20),
            read_latency: Some(LatencyStats {
                sample_count: 5,
                successes: 5,
                failures: 0,
                timeouts: 0,
                min_ms: Some(30),
                max_ms: Some(52),
                mean_ms: Some(40),
                median_ms: Some(38),
                p90_ms: Some(50),
                p95_ms: Some(52),
            }),
            broadcast_latency: BroadcastLatency::UnknownUntilRealAttempt,
            prewarm_status: None,
            prewarm_latency_ms: None,
        };
        let report = format_benchmark_report("https://rpc.example", 4663, &bench, true, true);
        assert!(report.contains("median=38ms"));
        assert!(report.contains("p95=52ms"));
        assert!(report.contains("selected_read=yes"));
    }
}
