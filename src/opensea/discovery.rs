//! Automatic OpenSea slug discovery for a given chain/collection address --
//! so `mint --engine auto`/`watch --engine auto` never require an operator
//! to manually pass `--slug` for a collection Kairox can discover on its
//! own, per the official public REST API only (no private GraphQL, no
//! undocumented endpoints).

use alloy_primitives::Address;

use super::client::OpenSeaClient;
use super::errors::OpenSeaError;
use super::models::DropDetailedResponse;

/// Resolve `collection`'s OpenSea drop, if any, without an
/// operator-supplied `--slug`. Tries, in order:
///
/// 1. `GET /api/v2/chain/{chain}/contract/{address}`'s `collection` field
///    as a candidate slug (see
///    [`crate::opensea::models::ContractResponse`]'s docs for why this is
///    only ever a *candidate*, never trusted on its own).
/// 2. The collection's own lowercase hex address as a candidate slug --
///    independently observed on real Robinhood-mainnet acceptance
///    evidence, where a collection's OpenSea slug literally was its
///    contract address.
///
/// Each candidate is only trusted once `GET /api/v2/drops/{slug}`'s own
/// `contract_address` field is independently confirmed to match
/// `collection` -- never on the candidate string alone.
///
/// Returns `Ok(None)` when no candidate resolves to a genuine, matching
/// drop -- not every collection has an OpenSea drop, and that is not an
/// error. Returns `Err` only for a genuine transport/auth/server problem
/// talking to OpenSea; callers that treat OpenSea auto-discovery as an
/// optional enhancement (never a hard requirement when a native fallback
/// exists) are expected to decide for themselves whether to swallow that
/// as "discovery unavailable" too -- this function itself never hides a
/// real infrastructure error behind `Ok(None)`.
pub async fn resolve_drop(
    opensea: &OpenSeaClient,
    chain_identifier: &str,
    collection: Address,
) -> Result<Option<DropDetailedResponse>, OpenSeaError> {
    let mut candidates = Vec::new();
    if let Some(contract) = opensea.get_contract(chain_identifier, collection).await? {
        candidates.push(contract.collection);
    }
    let address_candidate = format!("{collection:#x}");
    if !candidates.contains(&address_candidate) {
        candidates.push(address_candidate);
    }

    for slug in candidates {
        match opensea.get_drop_details(&slug).await {
            Ok(details) if contract_matches(&details.contract_address, collection) => {
                return Ok(Some(details));
            }
            // Resolved to a real drop for a *different* contract, or no
            // drop at all for this slug -- never trusted; try the next
            // candidate (or fall through to `Ok(None)`).
            Ok(_) | Err(OpenSeaError::DropNotFound { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn contract_matches(reported: &str, expected: Address) -> bool {
    reported.parse::<Address>().is_ok_and(|a| a == expected)
}

/// A structured classification of one [`resolve_drop`] attempt --
/// final hardening pass item 5. Nothing in Kairox's actual control flow
/// (exclusion lists, re-resolution comparisons) has ever depended on
/// parsing diagnostic text; this type exists so that fact is also true
/// by construction going forward, and so a caller reasoning about "what
/// happened" never has to pattern-match on `Result<Option<T>, E>`
/// directly. It never fabricates a stage -- `Available` is the only
/// variant that carries drop data, and it is only ever produced from a
/// genuine `resolve_drop` success.
#[derive(Debug)]
pub enum OpenSeaDiscoveryOutcome {
    /// A genuine, contract-matched drop was found.
    Available(Box<DropDetailedResponse>),
    /// OpenSea authoritatively reports no drop for this collection (a
    /// real 404, or no candidate slug matched) -- distinct from every
    /// other variant, none of which permit this conclusion.
    NoDrop,
    /// OpenSea rejected the configured API key.
    AuthenticationFailed,
    /// OpenSea rate-limited this request.
    RateLimited,
    /// A transport, timeout, server, or malformed-response problem --
    /// discovery could not be completed. Never evidence of "no drop".
    TransientFailure(OpenSeaError),
}

impl OpenSeaDiscoveryOutcome {
    /// Classify one `resolve_drop` result. Exhaustive over every
    /// [`OpenSeaError`] variant `resolve_drop` can actually produce, so
    /// this can never silently miscategorize a new error case as
    /// `NoDrop` by falling through a wildcard arm.
    pub fn classify(result: Result<Option<DropDetailedResponse>, OpenSeaError>) -> Self {
        match result {
            Ok(Some(details)) => Self::Available(Box::new(details)),
            Ok(None) => Self::NoDrop,
            Err(OpenSeaError::AuthenticationFailed) => Self::AuthenticationFailed,
            Err(OpenSeaError::RateLimited) => Self::RateLimited,
            Err(e) => Self::TransientFailure(e),
        }
    }

    /// `true` only for a result that is itself proof of "no drop" --
    /// never true for a degraded/uncheckable outcome, which must never
    /// be treated as equivalent evidence.
    pub fn is_authoritative_no_drop(&self) -> bool {
        matches!(self, Self::NoDrop)
    }

    /// `true` for any outcome where discovery could not be completed at
    /// all (as opposed to completing and finding nothing) -- the class
    /// of outcomes a caller should retry (bounded) rather than trust as
    /// a final answer.
    pub fn is_degraded(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed | Self::RateLimited | Self::TransientFailure(_)
        )
    }
}

#[cfg(test)]
mod discovery_outcome_tests {
    use super::*;

    fn drop() -> DropDetailedResponse {
        DropDetailedResponse {
            collection_slug: "test".to_string(),
            collection_name: None,
            chain: "ethereum".to_string(),
            contract_address: "0x0".to_string(),
            drop_type: "seadrop_v1_erc721".to_string(),
            is_minting: true,
            active_stage: None,
            next_stage: None,
            stages: vec![],
            total_supply: None,
            max_supply: None,
        }
    }

    #[test]
    fn a_genuine_drop_classifies_as_available_and_is_never_degraded() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Ok(Some(drop())));
        assert!(matches!(outcome, OpenSeaDiscoveryOutcome::Available(_)));
        assert!(!outcome.is_authoritative_no_drop());
        assert!(!outcome.is_degraded());
    }

    #[test]
    fn a_genuine_404_classifies_as_authoritative_no_drop_and_is_never_degraded() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Ok(None));
        assert!(outcome.is_authoritative_no_drop());
        assert!(!outcome.is_degraded());
    }

    #[test]
    fn a_server_error_is_degraded_never_no_drop() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Err(OpenSeaError::ServerError {
            detail: "internal error".to_string(),
        }));
        assert!(outcome.is_degraded());
        assert!(!outcome.is_authoritative_no_drop());
        assert!(matches!(
            outcome,
            OpenSeaDiscoveryOutcome::TransientFailure(_)
        ));
    }

    #[test]
    fn a_timeout_is_degraded_never_no_drop() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Err(OpenSeaError::ApiTimeout));
        assert!(outcome.is_degraded());
        assert!(!outcome.is_authoritative_no_drop());
    }

    #[test]
    fn a_rate_limit_is_its_own_distinct_degraded_variant_never_no_drop() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Err(OpenSeaError::RateLimited));
        assert!(matches!(outcome, OpenSeaDiscoveryOutcome::RateLimited));
        assert!(outcome.is_degraded());
        assert!(!outcome.is_authoritative_no_drop());
    }

    #[test]
    fn an_auth_failure_is_its_own_distinct_degraded_variant_never_no_drop() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Err(OpenSeaError::AuthenticationFailed));
        assert!(matches!(
            outcome,
            OpenSeaDiscoveryOutcome::AuthenticationFailed
        ));
        assert!(outcome.is_degraded());
        assert!(!outcome.is_authoritative_no_drop());
    }

    #[test]
    fn a_transport_failure_is_degraded_never_no_drop() {
        let outcome = OpenSeaDiscoveryOutcome::classify(Err(OpenSeaError::ApiUnavailable {
            detail: "connection reset".to_string(),
        }));
        assert!(outcome.is_degraded());
        assert!(!outcome.is_authoritative_no_drop());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opensea::mock::MockOpenSeaTransport;
    use serde_json::json;

    fn client(transport: MockOpenSeaTransport) -> OpenSeaClient {
        OpenSeaClient::with_transport(Box::new(transport))
    }

    fn drop_json(contract_address: &str) -> serde_json::Value {
        json!({
            "collection_slug": "hide",
            "chain": "robinhood",
            "contract_address": contract_address,
            "drop_type": "seadrop_v1_erc721",
            "is_minting": true,
            "stages": [],
        })
    }

    #[tokio::test]
    async fn resolves_via_contract_lookup_when_it_independently_matches() {
        let collection = Address::repeat_byte(0x11);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{collection:#x}"),
                200,
                json!({
                    "address": format!("{collection:#x}"),
                    "chain": "robinhood",
                    "collection": "hide",
                    "contract_standard": "erc721",
                    "name": "HIDE",
                }),
            )
            .respond(
                "GET",
                "/api/v2/drops/hide",
                200,
                drop_json(&format!("{collection:#x}")),
            )
            .build();

        let details = resolve_drop(&client(transport), "robinhood", collection)
            .await
            .unwrap()
            .expect("should resolve");
        assert_eq!(details.collection_slug, "hide");
    }

    #[tokio::test]
    async fn falls_back_to_address_as_slug_when_contract_lookup_has_no_record() {
        let collection = Address::repeat_byte(0x22);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{collection:#x}"),
                404,
                json!({}),
            )
            .respond(
                "GET",
                &format!("/api/v2/drops/{collection:#x}"),
                200,
                drop_json(&format!("{collection:#x}")),
            )
            .build();

        let details = resolve_drop(&client(transport), "robinhood", collection)
            .await
            .unwrap()
            .expect("should resolve via address-as-slug fallback");
        assert_eq!(details.collection_slug, "hide");
    }

    #[tokio::test]
    async fn a_candidate_resolving_to_a_different_contract_is_never_trusted() {
        let collection = Address::repeat_byte(0x33);
        let different_contract = Address::repeat_byte(0x44);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{collection:#x}"),
                200,
                json!({
                    "address": format!("{collection:#x}"),
                    "chain": "robinhood",
                    "collection": "wrong-collection",
                    "contract_standard": "erc721",
                    "name": "Wrong",
                }),
            )
            .respond(
                "GET",
                "/api/v2/drops/wrong-collection",
                200,
                // A real drop exists at this slug, but for a DIFFERENT
                // contract -- must never be trusted for `collection`.
                drop_json(&format!("{different_contract:#x}")),
            )
            .respond(
                "GET",
                &format!("/api/v2/drops/{collection:#x}"),
                404,
                json!({}),
            )
            .build();

        let result = resolve_drop(&client(transport), "robinhood", collection)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn no_opensea_record_at_all_is_none_not_an_error() {
        let collection = Address::repeat_byte(0x55);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{collection:#x}"),
                404,
                json!({}),
            )
            .respond(
                "GET",
                &format!("/api/v2/drops/{collection:#x}"),
                404,
                json!({}),
            )
            .build();

        let result = resolve_drop(&client(transport), "robinhood", collection)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn a_genuine_server_error_propagates_rather_than_being_hidden() {
        let collection = Address::repeat_byte(0x66);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{collection:#x}"),
                500,
                json!({"errors": ["boom"]}),
            )
            .build();

        let err = resolve_drop(&client(transport), "robinhood", collection)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::ServerError { .. }));
    }
}
