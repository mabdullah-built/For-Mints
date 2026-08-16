//! Small, dependency-free display helpers shared by CLI commands.

use alloy_primitives::{Address, U256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

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
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
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
}
