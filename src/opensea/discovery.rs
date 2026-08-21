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
