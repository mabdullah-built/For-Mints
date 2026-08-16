//! Loads RPC endpoint configuration from the environment. Never reads or
//! stores private key material — see [`secret_env_var_present`], which only
//! checks presence, never a value.

use std::env::VarError;
use std::time::Duration;

use thiserror::Error;
use url::Url;

use super::endpoint::{ChainEndpoints, EndpointRole, RpcEndpoint};
use super::registry::ChainId;

/// The reserved environment variable name Phase 2 will use for a signing
/// key. Phase 1 never reads its value — only whether it is set, purely for
/// `kairox doctor` reporting.
pub const SIGNING_KEY_ENV_VAR: &str = "KAIROX_SIGNING_KEY";

/// Environment variable prefix under which RPC endpoints are configured:
/// `KAIROX_RPC_<chain_id>_<index>_URL`, `..._ROLE`, `..._LABEL`,
/// `..._TIMEOUT_MS`.
const RPC_ENV_PREFIX: &str = "KAIROX_RPC";
/// Upper bound on how many indexed endpoints are scanned per chain, so a
/// misconfiguration can never cause unbounded env-var probing.
const MAX_ENDPOINTS_PER_CHAIN: u32 = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{var}: invalid URL: {reason}")]
    InvalidUrl { var: String, reason: String },
    #[error(
        "{var}: unrecognized role '{value}' (expected one of READ_WRITE, READ_ONLY, SEND_ONLY, SEQUENCER, PRIVATE, PUBLIC)"
    )]
    InvalidRole { var: String, value: String },
    #[error("{var}: invalid timeout milliseconds: {value}")]
    InvalidTimeoutMs { var: String, value: String },
    #[error("{var}: environment variable was not valid UTF-8")]
    NotUnicode { var: String },
}

fn parse_role(var: &str, raw: &str) -> Result<EndpointRole, ConfigError> {
    match raw {
        "READ_WRITE" => Ok(EndpointRole::ReadWrite),
        "READ_ONLY" => Ok(EndpointRole::ReadOnly),
        "SEND_ONLY" => Ok(EndpointRole::SendOnly),
        "SEQUENCER" => Ok(EndpointRole::Sequencer),
        "PRIVATE" => Ok(EndpointRole::Private),
        "PUBLIC" => Ok(EndpointRole::Public),
        other => Err(ConfigError::InvalidRole {
            var: var.to_string(),
            value: other.to_string(),
        }),
    }
}

fn read_optional(var: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NotUnicode {
            var: var.to_string(),
        }),
    }
}

/// A minimal env-reading abstraction so config loading is unit-testable
/// without mutating real process environment variables.
pub trait EnvSource {
    fn get(&self, key: &str) -> Result<Option<String>, ConfigError>;
}

/// Reads from the real process environment.
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Result<Option<String>, ConfigError> {
        read_optional(key)
    }
}

/// Load configured endpoints for a single chain id from `env`.
pub fn load_chain_endpoints(
    env: &dyn EnvSource,
    chain_id: ChainId,
) -> Result<ChainEndpoints, ConfigError> {
    let mut endpoints = Vec::new();

    for index in 0..MAX_ENDPOINTS_PER_CHAIN {
        let url_var = format!("{RPC_ENV_PREFIX}_{chain_id}_{index}_URL");
        let Some(raw_url) = env.get(&url_var)? else {
            break;
        };
        let url = Url::parse(&raw_url).map_err(|e| ConfigError::InvalidUrl {
            var: url_var.clone(),
            reason: e.to_string(),
        })?;

        let role_var = format!("{RPC_ENV_PREFIX}_{chain_id}_{index}_ROLE");
        let role = match env.get(&role_var)? {
            Some(raw) => parse_role(&role_var, &raw)?,
            None => EndpointRole::ReadWrite,
        };

        let label_var = format!("{RPC_ENV_PREFIX}_{chain_id}_{index}_LABEL");
        let label = env.get(&label_var)?;

        let timeout_var = format!("{RPC_ENV_PREFIX}_{chain_id}_{index}_TIMEOUT_MS");
        let timeout = match env.get(&timeout_var)? {
            Some(raw) => {
                let millis: u64 = raw.parse().map_err(|_| ConfigError::InvalidTimeoutMs {
                    var: timeout_var.clone(),
                    value: raw.clone(),
                })?;
                Duration::from_millis(millis)
            }
            None => super::endpoint::DEFAULT_RPC_TIMEOUT,
        };

        let mut endpoint = RpcEndpoint::new(url, role).with_timeout(timeout);
        if let Some(label) = label {
            endpoint = endpoint.with_label(label);
        }
        endpoints.push(endpoint);
    }

    Ok(ChainEndpoints::new(chain_id, endpoints))
}

/// Whether a secret-holding environment variable is present, without ever
/// reading or returning its value. Used only for status reporting (e.g.
/// `kairox doctor`).
pub fn secret_env_var_present(env: &dyn EnvSource, var: &str) -> Result<bool, ConfigError> {
    Ok(env.get(var)?.is_some())
}

#[cfg(test)]
pub mod testing {
    use super::ConfigError;
    use super::EnvSource;
    use std::collections::HashMap;

    /// An in-memory [`EnvSource`] for deterministic config tests.
    #[derive(Default)]
    pub struct FakeEnv(pub HashMap<String, String>);

    impl EnvSource for FakeEnv {
        fn get(&self, key: &str) -> Result<Option<String>, ConfigError> {
            Ok(self.0.get(key).cloned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeEnv;
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> FakeEnv {
        FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn no_endpoints_configured_yields_empty() {
        let env = env(&[]);
        let endpoints = load_chain_endpoints(&env, 1).unwrap();
        assert!(endpoints.is_empty());
    }

    #[test]
    fn loads_single_endpoint_with_defaults() {
        let env = env(&[("KAIROX_RPC_1_0_URL", "https://eth.example")]);
        let endpoints = load_chain_endpoints(&env, 1).unwrap();
        assert_eq!(endpoints.endpoints.len(), 1);
        assert_eq!(endpoints.endpoints[0].role, EndpointRole::ReadWrite);
        assert_eq!(
            endpoints.endpoints[0].timeout,
            super::super::endpoint::DEFAULT_RPC_TIMEOUT
        );
    }

    #[test]
    fn loads_role_label_and_timeout() {
        let env = env(&[
            ("KAIROX_RPC_1_0_URL", "https://eth.example"),
            ("KAIROX_RPC_1_0_ROLE", "SEND_ONLY"),
            ("KAIROX_RPC_1_0_LABEL", "primary"),
            ("KAIROX_RPC_1_0_TIMEOUT_MS", "2500"),
        ]);
        let endpoints = load_chain_endpoints(&env, 1).unwrap();
        assert_eq!(endpoints.endpoints[0].role, EndpointRole::SendOnly);
        assert_eq!(endpoints.endpoints[0].label.as_deref(), Some("primary"));
        assert_eq!(endpoints.endpoints[0].timeout, Duration::from_millis(2500));
    }

    #[test]
    fn loads_multiple_indexed_endpoints_and_stops_at_first_gap() {
        let env = env(&[
            ("KAIROX_RPC_1_0_URL", "https://eth-a.example"),
            ("KAIROX_RPC_1_1_URL", "https://eth-b.example"),
            // index 2 missing -> scan stops even if index 3 exists
            ("KAIROX_RPC_1_3_URL", "https://eth-d.example"),
        ]);
        let endpoints = load_chain_endpoints(&env, 1).unwrap();
        assert_eq!(endpoints.endpoints.len(), 2);
    }

    #[test]
    fn rejects_invalid_url() {
        let env = env(&[("KAIROX_RPC_1_0_URL", "not-a-url")]);
        let err = load_chain_endpoints(&env, 1).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidUrl { .. }));
    }

    #[test]
    fn rejects_invalid_role() {
        let env = env(&[
            ("KAIROX_RPC_1_0_URL", "https://eth.example"),
            ("KAIROX_RPC_1_0_ROLE", "NOT_A_ROLE"),
        ]);
        let err = load_chain_endpoints(&env, 1).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRole { .. }));
    }

    #[test]
    fn rejects_invalid_timeout() {
        let env = env(&[
            ("KAIROX_RPC_1_0_URL", "https://eth.example"),
            ("KAIROX_RPC_1_0_TIMEOUT_MS", "not-a-number"),
        ]);
        let err = load_chain_endpoints(&env, 1).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTimeoutMs { .. }));
    }

    #[test]
    fn secret_presence_check_never_returns_value() {
        let present = env(&[(SIGNING_KEY_ENV_VAR, "super-secret-value")]);
        assert!(secret_env_var_present(&present, SIGNING_KEY_ENV_VAR).unwrap());

        let empty = env(&[]);
        assert!(!secret_env_var_present(&empty, SIGNING_KEY_ENV_VAR).unwrap());
    }
}
