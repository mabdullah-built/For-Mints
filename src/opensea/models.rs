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
