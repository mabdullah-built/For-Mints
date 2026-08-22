//! Wire types for the official OpenSea Drops REST API, and normalized
//! Kairox domain types derived from them.
//!
//! Field names below were verified directly against the current live
//! `https://api.opensea.io/api/v2/openapi.json` (fetched during Phase 4
//! research) — notably the mint response uses `to`/`data`/`value`/`chain`,
//! not `target`/`calldata`/`value` as an earlier draft of this spec
//! assumed. See the Phase 4 final report's "OpenSea API sources inspected"
//! section for the full diff against that assumption.

use serde::{Deserialize, Serialize};

use crate::chain::registry::ChainId;
use crate::domain::stage::StageProtocol;

/// `POST /api/v2/drops/{slug}/mint` request body (`DropMintRequest`).
#[derive(Debug, Clone, Serialize)]
pub struct DropMintRequest {
    pub minter: String,
    pub quantity: u32,
}

/// `POST /api/v2/drops/{slug}/mint` response body (`DropMintResponse`).
/// Field names (`to`/`data`/`value`/`chain`) are exactly as documented in
/// the current official OpenAPI spec.
#[derive(Debug, Clone, Deserialize)]
pub struct DropMintResponse {
    pub to: String,
    pub data: String,
    pub value: String,
    pub chain: String,
}

/// One entry of `V1ErrorWrapper.errors` — the current official error body
/// shape for the Drops endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct V1ErrorWrapper {
    #[serde(default)]
    pub errors: Vec<String>,
}

/// `GET /api/v2/drops/{slug}` response body (`DropDetailedResponse`).
#[derive(Debug, Clone, Deserialize)]
pub struct DropDetailedResponse {
    pub collection_slug: String,
    #[serde(default)]
    pub collection_name: Option<String>,
    pub chain: String,
    pub contract_address: String,
    pub drop_type: String,
    pub is_minting: bool,
    #[serde(default)]
    pub active_stage: Option<DropStageResponse>,
    #[serde(default)]
    pub next_stage: Option<DropStageResponse>,
    pub stages: Vec<DropStageResponse>,
    #[serde(default)]
    pub total_supply: Option<String>,
    #[serde(default)]
    pub max_supply: Option<String>,
}

/// One `DropStageResponse` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct DropStageResponse {
    pub uuid: String,
    pub stage_type: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub price: Option<String>,
    pub price_currency_address: String,
    pub start_time: String,
    pub end_time: String,
    pub max_per_wallet: String,
}

/// `GET /api/v2/chain/{chain}/contract/{address}` response body
/// (`ContractResponse`). Verified directly against the current live
/// `https://api.opensea.io/api/v2/openapi.json`/reference docs: the
/// endpoint exists, and its schema is exactly `{address, chain, collection,
/// contract_standard, name}` (all required strings) -- `collection` is
/// OpenSea's collection identifier (used elsewhere in the v2 API as the
/// `{slug}` path parameter, e.g. `GET /api/v2/collections/{collection}`),
/// which is why [`super::discovery::resolve_drop`] treats it as a *candidate*
/// slug rather than an assumption: it is only trusted once the resulting
/// drop lookup independently confirms the same contract address.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractResponse {
    pub address: String,
    pub chain: String,
    pub collection: String,
    #[serde(default)]
    pub contract_standard: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Mapping from OpenSea's `DropStageResponse.stage_type` wire string to a
/// [`StageProtocol`] -- deliberately containing **only** wire values with
/// genuine, first-party evidence, per Kairox's fail-closed trust model:
/// a UI label or SeaDrop's own terminology is never treated as protocol
/// semantics.
///
/// `"signed_presale"` is the one value here: it is quoted verbatim in real
/// Robinhood-mainnet acceptance evidence (`GET /api/v2/drops/{slug}`'s
/// actual response for a real signed-presale-then-public collection).
///
/// An earlier version of this function also mapped `"public"`,
/// `"presale"`, `"allowlist"`, `"whitelist"`, `"fcfs"`, and `"fcfa"`. Those
/// were removed on review: none had genuine first-party evidence --
/// `"presale"`/`"allowlist"`/`"whitelist"`/`"fcfs"`/`"fcfa"` were inferred
/// from SeaDrop's own terminology (exactly the kind of UI-label-as-protocol
/// guess this trust model forbids), and `"public"` was asserted as
/// "independently confirmed" in that version's doc comment when the actual
/// acceptance evidence only ever quotes the *signed presale* stage's
/// `stage_type` string -- the public stage's wire value was never actually
/// observed. Independent research this pass (OpenSea's own reference docs)
/// found a documented example value of `"public_sale"`, not `"public"`,
/// reinforcing that the removed mapping would likely have been wrong.
///
/// Removing an entry here is always safe, never a regression: an
/// unrecognized `stage_type` (including a genuinely public one) simply
/// returns `None`, and [`super::super::cli::commands::resolver_adapters::OpenSeaDropsAdapter`]
/// treats `None` as "do not auto-prefer this stage over native SeaDrop" --
/// never as "assume public" or any other guess. A real public-only OpenSea
/// stage with no on-chain SeaDrop fallback would, with this narrower
/// mapping, need an explicit `--slug` rather than being auto-routed; that
/// is the correct fail-closed tradeoff until `"public_sale"` (or whatever
/// the real value is) is independently re-verified and added back with its
/// own evidence.
///
/// Misclassifying (or failing to classify) a stage here only ever affects
/// Kairox's own routing *preference* -- the actual mint transaction OpenSea
/// returns is always independently re-validated (target/collection/wallet/
/// quantity/value) before signing, regardless of what this function
/// decided.
pub fn map_stage_type(stage_type: &str) -> Option<StageProtocol> {
    match stage_type.to_ascii_lowercase().as_str() {
        "signed_presale" => Some(StageProtocol::SignedPresale),
        _ => None,
    }
}

/// Map a Kairox [`ChainId`] to the `ChainIdentifier` string the official
/// OpenSea API expects. Verified directly against the current
/// `ChainIdentifier` enum in the live OpenAPI spec, which does include
/// `"robinhood"` — Robinhood Chain (4663) genuinely is supported, so it is
/// mapped rather than assumed unsupported.
///
/// Deliberately a fixed, explicit table: Kairox never invents an OpenSea
/// chain identifier for a chain that hasn't been confirmed against the
/// official spec.
pub fn opensea_chain_identifier(chain_id: ChainId) -> Option<&'static str> {
    match chain_id {
        1 => Some("ethereum"),
        8453 => Some("base"),
        4663 => Some("robinhood"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_chains() {
        assert_eq!(opensea_chain_identifier(1), Some("ethereum"));
        assert_eq!(opensea_chain_identifier(8453), Some("base"));
        assert_eq!(opensea_chain_identifier(4663), Some("robinhood"));
    }

    #[test]
    fn unknown_chain_is_none_never_invented() {
        assert_eq!(opensea_chain_identifier(999_999), None);
    }

    #[test]
    fn drop_mint_request_serializes_documented_field_names() {
        let req = DropMintRequest {
            minter: "0xabc".into(),
            quantity: 2,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["minter"], "0xabc");
        assert_eq!(json["quantity"], 2);
    }

    #[test]
    fn contract_response_deserializes_documented_field_names() {
        let json = serde_json::json!({
            "address": "0x1e3e0922ea99e365f1b434391c81fefee345d1d9",
            "chain": "robinhood",
            "collection": "hide",
            "contract_standard": "erc721",
            "name": "HIDE",
        });
        let resp: ContractResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.collection, "hide");
        assert_eq!(resp.chain, "robinhood");
    }

    #[test]
    fn map_stage_type_recognizes_only_the_evidenced_signed_presale_value() {
        assert_eq!(
            map_stage_type("signed_presale"),
            Some(StageProtocol::SignedPresale)
        );
        assert_eq!(
            map_stage_type("SIGNED_PRESALE"),
            Some(StageProtocol::SignedPresale)
        );
    }

    #[test]
    fn map_stage_type_never_guesses_an_unrecognized_string() {
        assert_eq!(map_stage_type("mystery_stage"), None);
        assert_eq!(map_stage_type(""), None);
    }

    #[test]
    fn map_stage_type_no_longer_infers_public_or_seadrop_terminology() {
        // Regression test for the trust-model fix: these were all removed
        // because none had genuine first-party wire-value evidence -- see
        // map_stage_type's doc comment. A human-facing label/SeaDrop
        // terminology must never be treated as protocol semantics.
        for unverified in [
            "public",
            "public_sale",
            "presale",
            "allowlist",
            "whitelist",
            "fcfs",
            "fcfa",
        ] {
            assert_eq!(
                map_stage_type(unverified),
                None,
                "{unverified:?} must not be auto-routed without independent evidence"
            );
        }
    }

    #[test]
    fn drop_mint_response_deserializes_documented_field_names() {
        let json = serde_json::json!({
            "to": "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
            "data": "0xdeadbeef",
            "value": "0x0",
            "chain": "ethereum",
        });
        let resp: DropMintResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.to, "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5");
        assert_eq!(resp.data, "0xdeadbeef");
    }
}
