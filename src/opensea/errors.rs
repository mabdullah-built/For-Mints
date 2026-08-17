//! Typed OpenSea client/engine errors.
//!
//! Every variant maps to Kairox's existing Retryable / Fatal /
//! MustStopSession philosophy (see [`crate::execution::errors`]). API-side
//! uncertainty (a timeout before any valid response was received) is
//! distinct from blockchain possible-send uncertainty: an API timeout
//! *before signing* may be retried under a bounded policy, while an
//! uncertain broadcast outcome after signing always remains
//! `MustStopSession` — this module only ever represents the former.

use thiserror::Error;

use crate::execution::errors::{Categorize, ErrorCategory};

/// Everything that can go wrong requesting or interpreting data from the
/// official OpenSea Drops API, or validating/executing what it returned.
#[derive(Debug, Error)]
pub enum OpenSeaError {
    #[error("KAIROX_OPENSEA_API_KEY is not set; the OpenSea engine requires an API key")]
    ApiKeyMissing,
    #[error("OpenSea rejected the API key (401/403)")]
    AuthenticationFailed,
    #[error("OpenSea rate-limited this request (429)")]
    RateLimited,
    #[error("OpenSea reports no drop for slug '{slug}' (404)")]
    DropNotFound { slug: String },
    #[error("drop stage is not currently active (409): {detail}")]
    StageInactive { detail: String },
    #[error("wallet is not eligible for this drop/stage (422): {detail}")]
    EligibilityRejected { detail: String },
    #[error("wallet mint allocation exceeded (422): {detail}")]
    AllocationExceeded { detail: String },
    #[error("collection supply exhausted (422): {detail}")]
    SupplyExhausted { detail: String },
    #[error("OpenSea request was malformed (400): {detail}")]
    BadRequest { detail: String },
    #[error("timed out waiting for an OpenSea API response")]
    ApiTimeout,
    #[error("OpenSea API is unavailable (network/transport error): {detail}")]
    ApiUnavailable { detail: String },
    #[error("OpenSea returned a response Kairox could not parse: {detail}")]
    MalformedApiResponse { detail: String },
    #[error("OpenSea server error (5xx): {detail}")]
    ServerError { detail: String },
    #[error(
        "OpenSea's returned mint transaction uses an unrecognized/unsupported calldata selector 0x{selector}"
    )]
    UnsupportedSelector { selector: String },
    #[error(
        "OpenSea's returned mint transaction targets {actual}, which is not a target Kairox can validate as this collection's SeaDrop contract (expected {expected})"
    )]
    UnexpectedTarget {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
    #[error(
        "OpenSea's returned mint transaction's decoded nftContract {actual} does not match the requested collection {expected}"
    )]
    CollectionMismatch {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
    #[error(
        "OpenSea's returned mint transaction's decoded minter/recipient {actual} does not match the requested wallet {expected}"
    )]
    WalletMismatch {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
    #[error(
        "OpenSea's returned mint transaction's decoded quantity {actual} does not match the requested quantity {expected}"
    )]
    QuantityMismatch { expected: u64, actual: u64 },
    #[error("OpenSea's returned mint transaction value is unsafe: {detail}")]
    UnsafeValue { detail: String },
    #[error(
        "this mint stage requires server-signed-mint signature verification, which Kairox does not implement in Phase 4; refusing to sign an unverifiable server signature"
    )]
    SignatureValidationUnavailable,
    #[error("on-chain simulation of the OpenSea-provided transaction failed: {detail}")]
    SimulationFailure { detail: String },
    #[error("the requested chain is not supported by the official OpenSea Drops API: {chain}")]
    UnsupportedChain { chain: String },
    #[error(
        "collection address to OpenSea slug resolution is not available through official interfaces; pass --slug explicitly"
    )]
    SlugRequired,
}

impl Categorize for OpenSeaError {
    fn category(&self) -> ErrorCategory {
        match self {
            // Before signing, an API-side timeout/unavailability/server
            // error/rate-limit may be retried under a bounded policy -- see
            // module docs. Never confused with post-signing broadcast
            // uncertainty.
            OpenSeaError::ApiTimeout
            | OpenSeaError::ApiUnavailable { .. }
            | OpenSeaError::ServerError { .. }
            | OpenSeaError::RateLimited => ErrorCategory::Retryable,

            // Terminal for this attempt: retrying without changing
            // something will not help, and several of these are explicit
            // eligibility/safety outcomes that must never be bypassed by
            // retrying.
            OpenSeaError::ApiKeyMissing
            | OpenSeaError::AuthenticationFailed
            | OpenSeaError::DropNotFound { .. }
            | OpenSeaError::StageInactive { .. }
            | OpenSeaError::EligibilityRejected { .. }
            | OpenSeaError::AllocationExceeded { .. }
            | OpenSeaError::SupplyExhausted { .. }
            | OpenSeaError::BadRequest { .. }
            | OpenSeaError::MalformedApiResponse { .. }
            | OpenSeaError::UnsupportedSelector { .. }
            | OpenSeaError::UnexpectedTarget { .. }
            | OpenSeaError::CollectionMismatch { .. }
            | OpenSeaError::WalletMismatch { .. }
            | OpenSeaError::QuantityMismatch { .. }
            | OpenSeaError::UnsafeValue { .. }
            | OpenSeaError::SignatureValidationUnavailable
            | OpenSeaError::SimulationFailure { .. }
            | OpenSeaError::UnsupportedChain { .. }
            | OpenSeaError::SlugRequired => ErrorCategory::Fatal,
        }
    }
}
