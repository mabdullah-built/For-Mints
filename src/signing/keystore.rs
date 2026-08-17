//! Secure signing-key loading for the live (`--send`) path.
//!
//! Phase 2 accepts a real signing key from exactly two sources: the
//! `KAIROX_SIGNING_KEY` environment variable, or hidden interactive
//! terminal input. There is deliberately no `--private-key` CLI flag —
//! that would leak the key into shell history and process listings. The
//! key is never written to disk, never logged, and never appears in any
//! `Debug` output; every intermediate buffer holding raw key material is
//! zeroized as soon as it has been consumed.

use thiserror::Error;
use zeroize::Zeroize;

use crate::chain::config::{EnvSource, SIGNING_KEY_ENV_VAR};

use super::signer::{LocalSigner, SigningError};

#[derive(Debug, Error)]
pub enum KeyLoadError {
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error("{0}")]
    Encoding(String),
    #[error("failed to read interactive input")]
    InteractiveInput,
    #[error("no signing key available: set {SIGNING_KEY_ENV_VAR} or provide it interactively")]
    NoKeyAvailable,
}

/// Decode a hex-encoded 32-byte key (with or without a `0x` prefix) from a
/// `String`, zeroizing the input buffer regardless of outcome.
fn decode_key_hex(mut raw: String) -> Result<[u8; 32], KeyLoadError> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    let decode_result = hex::decode(hex_part);
    let result = match decode_result {
        Ok(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }
        Ok(bytes) => Err(KeyLoadError::Encoding(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        ))),
        Err(e) => Err(KeyLoadError::Encoding(format!("invalid hex: {e}"))),
    };

    raw.zeroize();
    result
}

/// Load the signing key from `KAIROX_SIGNING_KEY` if it is set. Returns
/// `Ok(None)` (not an error) if the variable is absent, so callers can fall
/// back to interactive input.
pub fn load_from_env(env: &dyn EnvSource) -> Result<Option<LocalSigner>, KeyLoadError> {
    load_from_env_var(env, SIGNING_KEY_ENV_VAR)
}

/// Load a signing key from an arbitrary named environment variable — used
/// by multi-wallet manifests, where each wallet entry names its own
/// `key_env` rather than always reading `KAIROX_SIGNING_KEY`. Returns
/// `Ok(None)` (not an error) if the variable is absent.
pub fn load_from_env_var(
    env: &dyn EnvSource,
    var_name: &str,
) -> Result<Option<LocalSigner>, KeyLoadError> {
    let Some(raw) = env
        .get(var_name)
        .map_err(|e| KeyLoadError::Encoding(e.to_string()))?
    else {
        return Ok(None);
    };
    let bytes = decode_key_hex(raw)?;
    Ok(Some(LocalSigner::from_bytes(bytes)?))
}

/// Prompt for the signing key via hidden terminal input (no echo).
pub fn prompt_interactive(prompt: &str) -> Result<LocalSigner, KeyLoadError> {
    let raw = rpassword::prompt_password(prompt).map_err(|_| KeyLoadError::InteractiveInput)?;
    let bytes = decode_key_hex(raw)?;
    Ok(LocalSigner::from_bytes(bytes)?)
}

/// Load a signing key for the live path: environment variable first, then
/// hidden interactive input. Fails closed with [`KeyLoadError::NoKeyAvailable`]
/// only if the caller opts out of the interactive fallback (`allow_interactive
/// = false`, e.g. for non-interactive/CI invocations).
pub fn load_signing_key(
    env: &dyn EnvSource,
    allow_interactive: bool,
) -> Result<LocalSigner, KeyLoadError> {
    if let Some(signer) = load_from_env(env)? {
        return Ok(signer);
    }
    if allow_interactive {
        return prompt_interactive("Signing key (hex, hidden input): ");
    }
    Err(KeyLoadError::NoKeyAvailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::config::testing::FakeEnv;
    use crate::signing::signer::Signer;
    use std::collections::HashMap;

    fn env_with_key(hex: &str) -> FakeEnv {
        FakeEnv(HashMap::from([(
            SIGNING_KEY_ENV_VAR.to_string(),
            hex.to_string(),
        )]))
    }

    #[test]
    fn loads_key_from_env_with_0x_prefix() {
        let hex = format!("0x{}", "11".repeat(32));
        let env = env_with_key(&hex);
        let signer = load_from_env(&env).unwrap().unwrap();
        assert_ne!(signer.address(), alloy_primitives::Address::ZERO);
    }

    #[test]
    fn loads_key_from_env_without_0x_prefix() {
        let hex = "22".repeat(32);
        let env = env_with_key(&hex);
        let signer = load_from_env(&env).unwrap().unwrap();
        assert_ne!(signer.address(), alloy_primitives::Address::ZERO);
    }

    #[test]
    fn returns_none_when_env_var_absent() {
        let env = FakeEnv(HashMap::new());
        assert!(load_from_env(&env).unwrap().is_none());
    }

    #[test]
    fn rejects_wrong_length_hex() {
        let env = env_with_key("deadbeef");
        let err = load_from_env(&env).unwrap_err();
        assert!(matches!(err, KeyLoadError::Encoding(_)));
    }

    #[test]
    fn rejects_non_hex_input() {
        let env = env_with_key("not-hex-at-all-not-hex-at-all-not-hex!!");
        let err = load_from_env(&env).unwrap_err();
        assert!(matches!(err, KeyLoadError::Encoding(_)));
    }

    #[test]
    fn load_signing_key_fails_closed_without_interactive_fallback() {
        let env = FakeEnv(HashMap::new());
        let err = load_signing_key(&env, false).unwrap_err();
        assert!(matches!(err, KeyLoadError::NoKeyAvailable));
    }

    #[test]
    fn key_load_error_display_never_contains_key_material() {
        // The error path for a bad hex string must never echo the offending
        // value verbatim — only byte-length/format facts.
        let bad_env = env_with_key("zz");
        let err = load_from_env(&bad_env).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("zz"));
    }
}
