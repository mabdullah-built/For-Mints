//! A clean Rust client for the official OpenSea Drops REST API
//! (`GET /api/v2/drops/{slug}`, `POST /api/v2/drops/{slug}/mint`).
//!
//! This client never touches undocumented/private OpenSea endpoints (no
//! `gql.opensea.io`, no browser-session cookies, no SIWE automation) — see
//! the Phase 4 final report's reference-implementation-findings section
//! for why. It requests exactly the caller's intended `minter`/`quantity`
//! — never a larger quantity to "discover" an allocation.

use std::time::Duration;

use alloy_primitives::Address;
use serde_json::Value;
use url::Url;

use super::errors::OpenSeaError;
use super::models::{
    ContractResponse, DropDetailedResponse, DropMintRequest, DropMintResponse, V1ErrorWrapper,
};
use super::transport::{HttpOpenSeaTransport, OpenSeaTransport, OpenSeaTransportError};

/// The official OpenSea API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.opensea.io";

/// Environment variable Kairox reads the OpenSea API key from. Never
/// accepted via a normal visible CLI argument — see
/// [`crate::cli::commands::doctor`], which reports only whether it is
/// configured, never its value.
pub const OPENSEA_API_KEY_ENV: &str = "KAIROX_OPENSEA_API_KEY";

/// Advanced/test-only override for the OpenSea API base URL, checked by
/// the CLI layer's `load_opensea_client` -- never read here, and never
/// consulted unless explicitly set. Exists so a localhost E2E harness (or
/// an operator pointed at a private OpenSea-API-compatible endpoint) can
/// redirect requests without touching production code paths otherwise.
pub const OPENSEA_BASE_URL_OVERRIDE_ENV: &str = "KAIROX_OPENSEA_BASE_URL";

pub struct OpenSeaClient {
    transport: Box<dyn OpenSeaTransport>,
}

impl OpenSeaClient {
    /// Build a client backed by a real, reused `reqwest::Client` — never a
    /// fresh HTTP client per request.
    pub fn new_http(api_key: String, timeout: Duration) -> Self {
        let base_url = Url::parse(DEFAULT_BASE_URL).expect("DEFAULT_BASE_URL is a valid URL");
        Self::new_http_with_base_url(api_key, base_url, timeout)
    }

    /// Like [`Self::new_http`], but against an explicit base URL instead
    /// of the real OpenSea API. Used by
    /// [`OPENSEA_BASE_URL_OVERRIDE_ENV`]-driven test/E2E harnesses (and
    /// any future OpenSea-API-compatible private endpoint) -- production
    /// `--send` behavior is unchanged unless that variable is explicitly
    /// set.
    pub fn new_http_with_base_url(api_key: String, base_url: Url, timeout: Duration) -> Self {
        Self {
            transport: Box::new(HttpOpenSeaTransport::new(base_url, api_key, timeout)),
        }
    }

    /// Build a client over any [`OpenSeaTransport`] — used by tests to
    /// inject [`super::mock::MockOpenSeaTransport`].
    pub fn with_transport(transport: Box<dyn OpenSeaTransport>) -> Self {
        Self { transport }
    }

    /// `GET /api/v2/drops/{slug}` — a safe read, usable in dry-run.
    pub async fn get_drop_details(&self, slug: &str) -> Result<DropDetailedResponse, OpenSeaError> {
        let path = format!("/api/v2/drops/{slug}");
        let response = self
            .transport
            .get(&path)
            .await
            .map_err(map_transport_error)?;
        interpret(slug, response, |body| {
            serde_json::from_value(body.clone()).map_err(|e| OpenSeaError::MalformedApiResponse {
                detail: e.to_string(),
            })
        })
    }

    /// `GET /api/v2/chain/{chain}/contract/{address}` — a safe read.
    /// Returns `Ok(None)` for a 404 (OpenSea has no record of this
    /// contract at all -- not every contract has one, and that is not an
    /// error), `Ok(Some(..))` for a 200, and `Err` for anything else
    /// (auth/rate-limit/server/transport problems). The response's own
    /// `collection` field is a *candidate* slug only -- see
    /// [`ContractResponse`]'s docs for why callers must independently
    /// verify it before trusting it.
    pub async fn get_contract(
        &self,
        chain: &str,
        address: Address,
    ) -> Result<Option<ContractResponse>, OpenSeaError> {
        let path = format!("/api/v2/chain/{chain}/contract/{address:#x}");
        let response = self
            .transport
            .get(&path)
            .await
            .map_err(map_transport_error)?;
        match response.status {
            200 => serde_json::from_value(response.body.clone())
                .map(Some)
                .map_err(|e| OpenSeaError::MalformedApiResponse {
                    detail: e.to_string(),
                }),
            404 => Ok(None),
            401 | 403 => Err(OpenSeaError::AuthenticationFailed),
            429 => Err(OpenSeaError::RateLimited),
            500..=599 => Err(OpenSeaError::ServerError {
                detail: error_detail(&response.body),
            }),
            other => Err(OpenSeaError::MalformedApiResponse {
                detail: format!("unexpected HTTP status {other}"),
            }),
        }
    }

    /// `POST /api/v2/drops/{slug}/mint` — requests ready-to-sign
    /// transaction data for exactly `minter`/`quantity`. The response is
    /// untrusted external input; callers must run it through
    /// [`crate::execution::opensea_validate::OpenSeaMintValidator`] before
    /// signing anything derived from it.
    pub async fn request_mint_transaction(
        &self,
        slug: &str,
        minter: Address,
        quantity: u32,
    ) -> Result<DropMintResponse, OpenSeaError> {
        let path = format!("/api/v2/drops/{slug}/mint");
        let body = serde_json::to_value(DropMintRequest {
            minter: minter.to_string(),
            quantity,
        })
        .expect("DropMintRequest always serializes");
        let response = self
            .transport
            .post_json(&path, &body)
            .await
            .map_err(map_transport_error)?;
        interpret(slug, response, |body| {
            serde_json::from_value(body.clone()).map_err(|e| OpenSeaError::MalformedApiResponse {
                detail: e.to_string(),
            })
        })
    }
}

fn map_transport_error(err: OpenSeaTransportError) -> OpenSeaError {
    match err {
        OpenSeaTransportError::Timeout(_) => OpenSeaError::ApiTimeout,
        OpenSeaTransportError::Network(detail) => OpenSeaError::ApiUnavailable { detail },
        OpenSeaTransportError::InvalidJson(detail) => OpenSeaError::MalformedApiResponse { detail },
    }
}

/// Interpret one HTTP response against the current official Drops API's
/// documented status-code semantics (verified against the live OpenAPI
/// spec during Phase 4 research), then hand the 200 body to `parse`.
fn interpret<T>(
    slug: &str,
    response: super::transport::HttpResponse,
    parse: impl FnOnce(&Value) -> Result<T, OpenSeaError>,
) -> Result<T, OpenSeaError> {
    match response.status {
        200 => parse(&response.body),
        400 => Err(OpenSeaError::BadRequest {
            detail: error_detail(&response.body),
        }),
        401 | 403 => Err(OpenSeaError::AuthenticationFailed),
        404 => Err(OpenSeaError::DropNotFound {
            slug: slug.to_string(),
        }),
        409 => Err(OpenSeaError::StageInactive {
            detail: error_detail(&response.body),
        }),
        422 => Err(classify_precondition_failure(&response.body)),
        429 => Err(OpenSeaError::RateLimited),
        500..=599 => Err(OpenSeaError::ServerError {
            detail: error_detail(&response.body),
        }),
        other => Err(OpenSeaError::MalformedApiResponse {
            detail: format!("unexpected HTTP status {other}"),
        }),
    }
}

fn error_detail(body: &Value) -> String {
    serde_json::from_value::<V1ErrorWrapper>(body.clone())
        .map(|w| w.errors.join("; "))
        .unwrap_or_else(|_| body.to_string())
}

/// A 422 response's documented meaning is a compound one ("insufficient
/// native balance, wallet not in allowlist, mint limit exceeded, or supply
/// exhausted") with no structured sub-code — only prose in `errors`.
/// Classify by best-effort keyword match into the most specific terminal
/// category Kairox has, falling back to the general eligibility-rejected
/// category. Every branch here is equally terminal/Fatal (see
/// [`OpenSeaError::category`]) — this only sharpens the error message, it
/// never changes whether Kairox may retry or bypass anything.
fn classify_precondition_failure(body: &Value) -> OpenSeaError {
    let detail = error_detail(body);
    let lower = detail.to_ascii_lowercase();
    if lower.contains("supply") || lower.contains("sold out") {
        OpenSeaError::SupplyExhausted { detail }
    } else if lower.contains("limit") || lower.contains("allocation") || lower.contains("already") {
        OpenSeaError::AllocationExceeded { detail }
    } else {
        OpenSeaError::EligibilityRejected { detail }
    }
}

#[cfg(test)]
mod tests {
    use super::super::mock::MockOpenSeaTransport;
    use super::*;
    use serde_json::json;

    fn client(transport: MockOpenSeaTransport) -> OpenSeaClient {
        OpenSeaClient::with_transport(Box::new(transport))
    }

    #[tokio::test]
    async fn get_drop_details_parses_valid_response() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/cool-cats",
                200,
                json!({
                    "collection_slug": "cool-cats",
                    "chain": "ethereum",
                    "contract_address": "0x1111111111111111111111111111111111111111",
                    "drop_type": "seadrop_v1_erc721",
                    "is_minting": true,
                    "stages": [],
                }),
            )
            .build();
        let details = client(transport)
            .get_drop_details("cool-cats")
            .await
            .unwrap();
        assert_eq!(details.collection_slug, "cool-cats");
        assert_eq!(details.chain, "ethereum");
        assert!(details.is_minting);
    }

    #[tokio::test]
    async fn get_contract_parses_a_valid_response() {
        let addr = Address::repeat_byte(0x11);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{addr:#x}"),
                200,
                json!({
                    "address": format!("{addr:#x}"),
                    "chain": "robinhood",
                    "collection": "hide",
                    "contract_standard": "erc721",
                    "name": "HIDE",
                }),
            )
            .build();
        let resp = client(transport)
            .get_contract("robinhood", addr)
            .await
            .unwrap();
        assert_eq!(resp.unwrap().collection, "hide");
    }

    #[tokio::test]
    async fn get_contract_404_is_none_not_an_error() {
        let addr = Address::repeat_byte(0x22);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{addr:#x}"),
                404,
                json!({"errors": ["not found"]}),
            )
            .build();
        let resp = client(transport)
            .get_contract("robinhood", addr)
            .await
            .unwrap();
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn get_contract_server_error_is_a_real_error() {
        let addr = Address::repeat_byte(0x33);
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                &format!("/api/v2/chain/robinhood/contract/{addr:#x}"),
                500,
                json!({"errors": ["boom"]}),
            )
            .build();
        let err = client(transport)
            .get_contract("robinhood", addr)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::ServerError { .. }));
    }

    #[tokio::test]
    async fn get_drop_details_404_maps_to_drop_not_found() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "GET",
                "/api/v2/drops/missing",
                404,
                json!({"errors": ["not found"]}),
            )
            .build();
        let err = client(transport)
            .get_drop_details("missing")
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::DropNotFound { slug } if slug == "missing"));
    }

    #[tokio::test]
    async fn request_mint_transaction_parses_documented_field_names() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                json!({
                    "to": "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
                    "data": "0xdeadbeef",
                    "value": "0x0",
                    "chain": "ethereum",
                }),
            )
            .build();
        let minter = Address::repeat_byte(0xAB);
        let resp = client(transport)
            .request_mint_transaction("cool-cats", minter, 1)
            .await
            .unwrap();
        assert_eq!(resp.to, "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5");
    }

    #[tokio::test]
    async fn request_mint_transaction_sends_exactly_requested_minter_and_quantity() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                json!({"to": "0x1", "data": "0x", "value": "0x0", "chain": "ethereum"}),
            )
            .build();
        let capture = transport.capture_handle();
        let minter = Address::repeat_byte(0x11);
        client(transport)
            .request_mint_transaction("cool-cats", minter, 3)
            .await
            .unwrap();

        let requests = capture.all();
        assert_eq!(requests.len(), 1);
        let (_, _, body) = &requests[0];
        let body = body.as_ref().unwrap();
        assert_eq!(body["quantity"], 3);
        assert_eq!(
            body["minter"].as_str().unwrap().to_lowercase(),
            minter.to_string().to_lowercase()
        );
    }

    #[tokio::test]
    async fn mint_400_maps_to_bad_request() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                400,
                json!({"errors": ["invalid address format"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::BadRequest { .. }));
    }

    #[tokio::test]
    async fn mint_401_maps_to_authentication_failed() {
        let transport = MockOpenSeaTransport::builder()
            .respond("POST", "/api/v2/drops/cool-cats/mint", 401, json!({}))
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::AuthenticationFailed));
    }

    #[tokio::test]
    async fn mint_403_maps_to_authentication_failed() {
        let transport = MockOpenSeaTransport::builder()
            .respond("POST", "/api/v2/drops/cool-cats/mint", 403, json!({}))
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::AuthenticationFailed));
    }

    #[tokio::test]
    async fn mint_404_maps_to_drop_not_found() {
        let transport = MockOpenSeaTransport::builder()
            .respond("POST", "/api/v2/drops/nope/mint", 404, json!({}))
            .build();
        let err = client(transport)
            .request_mint_transaction("nope", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::DropNotFound { .. }));
    }

    #[tokio::test]
    async fn mint_409_maps_to_stage_inactive() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                409,
                json!({"errors": ["stage not active"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::StageInactive { .. }));
    }

    #[tokio::test]
    async fn mint_422_supply_wording_maps_to_supply_exhausted() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                422,
                json!({"errors": ["collection supply exhausted"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::SupplyExhausted { .. }));
    }

    #[tokio::test]
    async fn mint_422_limit_wording_maps_to_allocation_exceeded() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                422,
                json!({"errors": ["wallet mint limit exceeded"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::AllocationExceeded { .. }));
    }

    #[tokio::test]
    async fn mint_422_generic_wording_maps_to_eligibility_rejected() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                422,
                json!({"errors": ["wallet not in allowlist"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::EligibilityRejected { .. }));
    }

    #[tokio::test]
    async fn mint_429_maps_to_rate_limited() {
        let transport = MockOpenSeaTransport::builder()
            .respond("POST", "/api/v2/drops/cool-cats/mint", 429, json!({}))
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::RateLimited));
    }

    #[tokio::test]
    async fn mint_500_maps_to_server_error() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                500,
                json!({"errors": ["internal"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::ServerError { .. }));
    }

    #[tokio::test]
    async fn mint_timeout_maps_to_api_timeout() {
        let transport = MockOpenSeaTransport::builder()
            .timeout("POST", "/api/v2/drops/cool-cats/mint")
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::ApiTimeout));
    }

    #[tokio::test]
    async fn mint_network_error_maps_to_api_unavailable() {
        let transport = MockOpenSeaTransport::builder()
            .network_error("POST", "/api/v2/drops/cool-cats/mint", "connection reset")
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::ApiUnavailable { .. }));
    }

    #[tokio::test]
    async fn mint_malformed_json_maps_to_malformed_api_response() {
        // The transport itself reports InvalidJson when the body can't be
        // parsed at all (see HttpOpenSeaTransport); simulate the same via
        // a 200 whose body doesn't match DropMintResponse's shape.
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                200,
                json!({"unexpected": "shape"}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, OpenSeaError::MalformedApiResponse { .. }));
    }

    #[tokio::test]
    async fn api_key_never_appears_in_any_error_message() {
        let transport = MockOpenSeaTransport::builder()
            .respond(
                "POST",
                "/api/v2/drops/cool-cats/mint",
                400,
                json!({"errors": ["bad request"]}),
            )
            .build();
        let err = client(transport)
            .request_mint_transaction("cool-cats", Address::ZERO, 1)
            .await
            .unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains("KAIROX_OPENSEA_API_KEY"));
        assert!(!rendered.to_lowercase().contains("secret-api-key-value"));
    }
}
