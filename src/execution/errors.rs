//! Execution-safety error classification.
//!
//! Every error that can surface from a Kairox operation is bucketed into
//! one of three categories. This concept is independently designed for
//! Kairox (not ported from any reference implementation): the important
//! property is that once real broadcasting exists (a later phase), any
//! error representing an *unknown* transaction outcome must classify as
//! `MustStopSession` rather than being silently retried — retrying a
//! broadcast whose outcome is unknown risks a double-send.

use std::fmt;

use thiserror::Error;

/// How a caller should react to an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Transient; the same operation may be attempted again, subject to a
    /// caller-defined bounded attempt count. Never retried unboundedly.
    Retryable,
    /// Permanent for the given inputs; retrying without changing something
    /// (config, quantity, fee, etc.) will not help.
    Fatal,
    /// The true outcome of a state-changing operation cannot be safely
    /// determined. The entire session must stop rather than guess — a
    /// later attempt could double-broadcast, double-spend, or otherwise
    /// diverge from on-chain reality.
    MustStopSession,
}

/// Anything that can report which [`ErrorCategory`] it belongs to.
pub trait Categorize {
    fn category(&self) -> ErrorCategory;
}

/// A top-level Kairox error, aggregating every domain/chain/protocol error
/// type behind one `Categorize` implementation. CLI commands surface this
/// type; nothing downstream needs to know which module an error originated
/// in to decide how to react to it.
#[derive(Debug, Error)]
pub enum KairoxError {
    #[error(transparent)]
    Rpc(#[from] crate::chain::rpc::RpcError),
    #[error(transparent)]
    Config(#[from] crate::chain::config::ConfigError),
    /// A config-*file* error (`kairox init`/`--config`'s own TOML schema,
    /// version, or secret-looking-value checks) -- distinct from
    /// [`Self::Config`], which is the older env-var-only RPC config path.
    /// Both map to the same [`KairoxErrorCode::ConfigInvalid`].
    #[error(transparent)]
    ConfigFile(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Fee(#[from] crate::domain::fees::FeeError),
    #[error(transparent)]
    SafetyCap(#[from] crate::domain::fees::SafetyCapError),
    #[error(transparent)]
    Supply(#[from] crate::domain::supply::SupplyError),
    #[error(transparent)]
    SeaDrop(#[from] crate::protocol::seadrop::SeaDropError),
    #[error(transparent)]
    Log(#[from] crate::protocol::logs::LogError),
    #[error(transparent)]
    Signing(#[from] crate::signing::signer::SigningError),
    #[error(transparent)]
    OpenSea(#[from] crate::opensea::errors::OpenSeaError),
    #[error("{0}")]
    Session(SessionError),
}

/// A structured classification for [`SessionError`], so callers that need
/// to react differently to specific session-abort reasons (e.g.
/// `execution::multi_wallet::classify_prepare_error`) can match on this
/// instead of parsing the human `message` text -- and so
/// [`KairoxError::code`] can report a precise [`KairoxErrorCode`] for the
/// cases that matter most, rather than collapsing every `SessionError`
/// into one generic fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorKind {
    /// Not otherwise classified. Still a real, specific human message --
    /// only the *machine-readable* kind is generic.
    Generic,
    /// A loaded/derived signing key resolves to a different address than
    /// the wallet it was meant to sign for.
    WalletKeyMismatch,
    /// A wallet's balance cannot cover the worst-case total spend its own
    /// finalized plan requires.
    InsufficientBalance,
    /// A multi-wallet session's configured aggregate spend ceiling would
    /// be exceeded by the real, finalized worst-case cost across every
    /// eligible wallet.
    SessionCapExceeded,
    /// The aggregate requested quantity across a wallet set would exceed
    /// verified remaining collection/stage supply.
    AggregateSupplyExceeded,
    /// No RPC endpoint configured/connected for the requested chain, so no
    /// verified read was possible at all.
    NoVerifiedReadRpc,
    /// A manifest file failed to load or validate.
    InvalidManifest,
    /// A multi-wallet participant skipped due to another wallet's shared
    /// resource (e.g. the OpenSea API key) having already failed -- never
    /// this wallet's own eligibility, so callers must not classify it the
    /// same way as an `Ineligible` outcome.
    SkippedSharedResourceFailure,
}

/// An error representing a state Kairox has explicitly decided must halt
/// the whole session, independent of any single underlying operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub message: String,
    pub kind: SessionErrorKind,
}

impl SessionError {
    /// A session error with no specific structured kind -- still a
    /// specific, real message, just not one of the classified cases.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: SessionErrorKind::Generic,
        }
    }

    /// A session error carrying a specific, structured kind for callers
    /// that need to react to it (see [`SessionErrorKind`]).
    pub fn with_kind(kind: SessionErrorKind, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }
}

impl From<String> for SessionError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for SessionError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session must stop: {}", self.message)
    }
}

impl Categorize for SessionError {
    fn category(&self) -> ErrorCategory {
        ErrorCategory::MustStopSession
    }
}

/// A stable, external-facing classification for a [`KairoxError`] --
/// intended for SessionReport/`--json` output and other tooling that
/// should match on a fixed code, never on `Display` text (which may change
/// wording without notice). Deliberately coarser than the internal error
/// types: several internal variants collapse onto the same code when they
/// represent the same actionable category from an operator's perspective.
///
/// Two related outcome families are represented by their own typed enums
/// instead of routing through `KairoxError` at all, because they are not
/// errors: [`crate::execution::broadcast::BroadcastOutcome::error_code`]
/// covers `BROADCAST_FATAL`/`BROADCAST_UNCERTAIN`, and
/// [`crate::execution::receipt::ReceiptState::error_code`] covers
/// `RECEIPT_REVERT`/`RECEIPT_MINT_MISMATCH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KairoxErrorCode {
    ConfigInvalid,
    ChainMismatch,
    RpcTransportError,
    FeeInvariantViolated,
    SafetyCapExceeded,
    AllocationExceeded,
    SupplyExhausted,
    SupplyStateInvalid,
    ProtocolDecodeError,
    SigningError,
    OpenSeaAuthFailed,
    OpenSeaRateLimited,
    NotEligible,
    SimulationRevert,
    OpenSeaApiError,
    WalletKeyMismatch,
    InsufficientBalance,
    SessionCapExceeded,
    NoVerifiedReadRpc,
    /// A [`SessionError`] not otherwise classified (`SessionErrorKind::Generic`,
    /// `InvalidManifest`, or `SkippedSharedResourceFailure`).
    SessionAborted,
}

impl std::fmt::Display for KairoxErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::ChainMismatch => "CHAIN_MISMATCH",
            Self::RpcTransportError => "RPC_TRANSPORT_ERROR",
            Self::FeeInvariantViolated => "FEE_INVARIANT_VIOLATED",
            Self::SafetyCapExceeded => "SAFETY_CAP_EXCEEDED",
            Self::AllocationExceeded => "ALLOCATION_EXCEEDED",
            Self::SupplyExhausted => "SUPPLY_EXHAUSTED",
            Self::SupplyStateInvalid => "SUPPLY_STATE_INVALID",
            Self::ProtocolDecodeError => "PROTOCOL_DECODE_ERROR",
            Self::SigningError => "SIGNING_ERROR",
            Self::OpenSeaAuthFailed => "OPENSEA_AUTH_FAILED",
            Self::OpenSeaRateLimited => "OPENSEA_RATE_LIMITED",
            Self::NotEligible => "NOT_ELIGIBLE",
            Self::SimulationRevert => "SIMULATION_REVERT",
            Self::OpenSeaApiError => "OPENSEA_API_ERROR",
            Self::WalletKeyMismatch => "WALLET_KEY_MISMATCH",
            Self::InsufficientBalance => "INSUFFICIENT_BALANCE",
            Self::SessionCapExceeded => "SESSION_CAP_EXCEEDED",
            Self::NoVerifiedReadRpc => "NO_VERIFIED_READ_RPC",
            Self::SessionAborted => "SESSION_ABORTED",
        };
        f.write_str(s)
    }
}

impl KairoxError {
    /// Map this error onto a stable [`KairoxErrorCode`]. Never panics.
    pub fn code(&self) -> KairoxErrorCode {
        use crate::domain::supply::SupplyError;
        use crate::opensea::errors::OpenSeaError;

        match self {
            KairoxError::Config(_) | KairoxError::ConfigFile(_) => KairoxErrorCode::ConfigInvalid,
            KairoxError::Rpc(crate::chain::rpc::RpcError::ChainIdMismatch { .. }) => {
                KairoxErrorCode::ChainMismatch
            }
            KairoxError::Rpc(_) => KairoxErrorCode::RpcTransportError,
            KairoxError::Fee(_) => KairoxErrorCode::FeeInvariantViolated,
            KairoxError::SafetyCap(_) => KairoxErrorCode::SafetyCapExceeded,
            KairoxError::Supply(e) => match e {
                SupplyError::WalletAllocationExhausted
                | SupplyError::ExceedsWalletAllocation { .. } => {
                    KairoxErrorCode::AllocationExceeded
                }
                SupplyError::CollectionSoldOut | SupplyError::ExceedsCollectionSupply { .. } => {
                    KairoxErrorCode::SupplyExhausted
                }
                SupplyError::WalletStateInconsistent { .. }
                | SupplyError::CollectionStateInconsistent { .. }
                | SupplyError::ZeroQuantity
                | SupplyError::UnknownCollectionSupply => KairoxErrorCode::SupplyStateInvalid,
            },
            KairoxError::SeaDrop(_) | KairoxError::Log(_) => KairoxErrorCode::ProtocolDecodeError,
            KairoxError::Signing(_) => KairoxErrorCode::SigningError,
            KairoxError::OpenSea(e) => match e {
                OpenSeaError::ApiKeyMissing | OpenSeaError::AuthenticationFailed => {
                    KairoxErrorCode::OpenSeaAuthFailed
                }
                OpenSeaError::RateLimited => KairoxErrorCode::OpenSeaRateLimited,
                OpenSeaError::DropNotFound { .. }
                | OpenSeaError::StageInactive { .. }
                | OpenSeaError::EligibilityRejected { .. } => KairoxErrorCode::NotEligible,
                OpenSeaError::AllocationExceeded { .. } => KairoxErrorCode::AllocationExceeded,
                OpenSeaError::SupplyExhausted { .. } => KairoxErrorCode::SupplyExhausted,
                OpenSeaError::SimulationFailure { .. } => KairoxErrorCode::SimulationRevert,
                OpenSeaError::MerkleProofInvalid
                | OpenSeaError::SignerNotAuthorized { .. }
                | OpenSeaError::SignerValidationParamsRejected { .. }
                | OpenSeaError::UnexpectedTarget { .. }
                | OpenSeaError::CollectionMismatch { .. }
                | OpenSeaError::WalletMismatch { .. }
                | OpenSeaError::QuantityMismatch { .. }
                | OpenSeaError::UnsafeValue { .. }
                | OpenSeaError::UnsupportedSelector { .. }
                | OpenSeaError::MalformedSignature
                | OpenSeaError::FeeRecipientNotAllowed { .. } => {
                    KairoxErrorCode::ProtocolDecodeError
                }
                OpenSeaError::BadRequest { .. }
                | OpenSeaError::MalformedApiResponse { .. }
                | OpenSeaError::ApiTimeout
                | OpenSeaError::ApiUnavailable { .. }
                | OpenSeaError::ServerError { .. }
                | OpenSeaError::UnsupportedChain { .. }
                | OpenSeaError::SlugRequired
                | OpenSeaError::OnChainStateUnavailable { .. } => KairoxErrorCode::OpenSeaApiError,
            },
            KairoxError::Session(e) => match e.kind {
                SessionErrorKind::WalletKeyMismatch => KairoxErrorCode::WalletKeyMismatch,
                SessionErrorKind::InsufficientBalance => KairoxErrorCode::InsufficientBalance,
                SessionErrorKind::SessionCapExceeded => KairoxErrorCode::SessionCapExceeded,
                SessionErrorKind::AggregateSupplyExceeded => KairoxErrorCode::SupplyExhausted,
                SessionErrorKind::NoVerifiedReadRpc => KairoxErrorCode::NoVerifiedReadRpc,
                SessionErrorKind::Generic
                | SessionErrorKind::InvalidManifest
                | SessionErrorKind::SkippedSharedResourceFailure => KairoxErrorCode::SessionAborted,
            },
        }
    }
}

impl Categorize for KairoxError {
    fn category(&self) -> ErrorCategory {
        match self {
            KairoxError::Rpc(e) => e.category(),
            KairoxError::Config(_) | KairoxError::ConfigFile(_) => ErrorCategory::Fatal,
            KairoxError::Fee(_) => ErrorCategory::Fatal,
            KairoxError::SafetyCap(_) => ErrorCategory::Fatal,
            KairoxError::Supply(_) => ErrorCategory::Fatal,
            KairoxError::SeaDrop(_) => ErrorCategory::Fatal,
            KairoxError::Log(_) => ErrorCategory::Fatal,
            KairoxError::Signing(_) => ErrorCategory::Fatal,
            KairoxError::OpenSea(e) => e.category(),
            KairoxError::Session(e) => e.category(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::rpc::{RpcError, TransportError};

    #[test]
    fn timeout_wrapped_in_kairox_error_is_retryable() {
        let err: KairoxError =
            RpcError::Transport(TransportError::Timeout(std::time::Duration::from_secs(1))).into();
        assert_eq!(err.category(), ErrorCategory::Retryable);
    }

    #[test]
    fn chain_id_mismatch_is_fatal() {
        let err: KairoxError = RpcError::ChainIdMismatch {
            expected: 1,
            reported: 2,
        }
        .into();
        assert_eq!(err.category(), ErrorCategory::Fatal);
    }

    #[test]
    fn session_error_is_must_stop_session() {
        let err = KairoxError::Session(SessionError::new("broadcast outcome uncertain"));
        assert_eq!(err.category(), ErrorCategory::MustStopSession);
    }
}
