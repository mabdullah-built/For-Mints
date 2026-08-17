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

/// An error representing a state Kairox has explicitly decided must halt
/// the whole session, independent of any single underlying operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError(pub String);

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session must stop: {}", self.0)
    }
}

impl Categorize for SessionError {
    fn category(&self) -> ErrorCategory {
        ErrorCategory::MustStopSession
    }
}

impl Categorize for KairoxError {
    fn category(&self) -> ErrorCategory {
        match self {
            KairoxError::Rpc(e) => e.category(),
            KairoxError::Config(_) => ErrorCategory::Fatal,
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
        let err = KairoxError::Session(SessionError("broadcast outcome uncertain".into()));
        assert_eq!(err.category(), ErrorCategory::MustStopSession);
    }
}
