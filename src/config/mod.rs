//! Kairox operator configuration.
//!
//! A TOML file that documents *how* Kairox is set up for an operator --
//! which chains, which environment-variable names carry RPC endpoints and
//! the OpenSea API key, and preferred defaults. It is deliberately NOT a
//! place secrets can live: every field that names sensitive material is a
//! `*_env` field naming an environment variable, never the value itself.
//! [`validate_no_secret_looking_values`] fails closed if a field looks like
//! a raw secret was pasted in by mistake.
//!
//! Config location precedence, highest first: `--config PATH` (handled by
//! the CLI layer), then the `KAIROX_CONFIG` environment variable, then the
//! conventional `~/.config/kairox/config.toml` path (used only if it
//! actually exists). A fresh install with no config file and no
//! `--config`/`KAIROX_CONFIG` simply runs with compiled defaults --
//! nothing is silently required.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The environment variable naming an explicit config file path, checked
/// when `--config` was not passed on the command line.
pub const CONFIG_ENV_VAR: &str = "KAIROX_CONFIG";

/// The only schema version Kairox currently understands. A config file
/// declaring any other `version` is rejected outright rather than guessed
/// at -- silently misinterpreting a future or unknown schema is worse than
/// a clear error.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KairoxConfig {
    pub version: u32,
    #[serde(default)]
    pub defaults: ConfigDefaults,
    #[serde(default)]
    pub chains: BTreeMap<String, ChainConfigEntry>,
    #[serde(default)]
    pub opensea: OpenSeaConfigEntry,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDefaults {
    pub chain: Option<String>,
    pub engine: Option<String>,
}

/// Names of environment variables carrying RPC endpoint URLs for one
/// chain -- documentation and cross-checking for `doctor`, not a second
/// mechanism that itself supplies URLs. The URLs are still read from the
/// environment by [`crate::chain::config::load_chain_endpoints`], exactly
/// as before; this only records which variable names an operator intends
/// to use, so `doctor` can point out a configured-but-unset variable.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfigEntry {
    #[serde(default)]
    pub read_rpc_env: Vec<String>,
    #[serde(default)]
    pub send_rpc_env: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSeaConfigEntry {
    pub api_key_env: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error(
        "unsupported config schema version {found} (Kairox currently supports version {supported}); refusing to guess at an unknown schema"
    )]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error(
        "config field '{field}' looks like it contains a secret value directly rather than an environment variable name -- use a *_env field naming a variable instead, never the secret itself"
    )]
    SecretLookingValue { field: String },
}

/// Resolve which config file (if any) applies for this run, following the
/// documented precedence: `--config` (passed in by the caller) >
/// `KAIROX_CONFIG` > the conventional per-user path, used only if it
/// already exists. Returns `None` when nothing applies -- not an error,
/// since Kairox must run with zero configuration.
pub fn resolve_config_path(cli_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = cli_path {
        return Some(p.to_path_buf());
    }
    if let Ok(p) = std::env::var(CONFIG_ENV_VAR)
        && !p.is_empty()
    {
        return Some(PathBuf::from(p));
    }
    conventional_config_path().filter(|p| p.exists())
}

/// `~/.config/kairox/config.toml`, using whichever of `HOME`/`USERPROFILE`
/// is set -- never hardcoding a specific developer's home directory.
pub fn conventional_config_path() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("kairox")
            .join("config.toml"),
    )
}

/// Load and validate a config file from `path`. Fails closed on: missing
/// file, malformed TOML, unknown fields, an unsupported schema version, or
/// any field that looks like a secret was pasted in directly.
pub fn load_config(path: &Path) -> Result<KairoxConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let config: KairoxConfig = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if config.version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigError::UnsupportedVersion {
            found: config.version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    validate_no_secret_looking_values(&config)?;
    Ok(config)
}

/// Conservative heuristic shared in spirit with
/// [`crate::execution::manifest`]'s `key_env` check: a value that is
/// itself long hex or looks like a multi-word BIP-39 mnemonic is almost
/// certainly a pasted secret, not an environment variable name (which is
/// conventionally short, uppercase, alphanumeric/underscore).
fn looks_like_secret_value(value: &str) -> bool {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let is_long_hex = stripped.len() >= 32 && stripped.chars().all(|c| c.is_ascii_hexdigit());
    let looks_like_mnemonic = value.split_whitespace().count() >= 8;
    is_long_hex || looks_like_mnemonic
}

fn validate_no_secret_looking_values(config: &KairoxConfig) -> Result<(), ConfigError> {
    if let Some(env_name) = &config.opensea.api_key_env
        && looks_like_secret_value(env_name)
    {
        return Err(ConfigError::SecretLookingValue {
            field: "opensea.api_key_env".into(),
        });
    }
    for (name, entry) in &config.chains {
        for v in entry.read_rpc_env.iter().chain(entry.send_rpc_env.iter()) {
            if looks_like_secret_value(v) {
                return Err(ConfigError::SecretLookingValue {
                    field: format!("chains.{name}"),
                });
            }
        }
    }
    Ok(())
}

/// The starter config `kairox init` writes -- safe to commit to version
/// control (references environment variable NAMES only), and documents
/// the expected variable naming convention already used by
/// [`crate::chain::config`].
pub fn default_config_toml() -> String {
    r#"# Kairox configuration.
#
# This file names environment VARIABLES only -- never put a private key,
# API key value, mnemonic, or RPC credential directly in this file.
# Kairox validates this and refuses to load a config file where a *_env
# field looks like a secret was pasted in by mistake.

version = 1

[defaults]
chain = "ethereum"
engine = "auto"

[chains.ethereum]
read_rpc_env = ["KAIROX_RPC_1_0_URL"]
send_rpc_env = ["KAIROX_RPC_1_0_URL"]

[chains.base]
read_rpc_env = ["KAIROX_RPC_8453_0_URL"]
send_rpc_env = ["KAIROX_RPC_8453_0_URL"]

[chains.robinhood]
read_rpc_env = ["KAIROX_RPC_4663_0_URL"]
send_rpc_env = ["KAIROX_RPC_4663_0_URL"]

[opensea]
api_key_env = "KAIROX_OPENSEA_API_KEY"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_default_starter_config() {
        let toml_text = default_config_toml();
        let parsed: KairoxConfig = toml::from_str(&toml_text).unwrap();
        assert_eq!(parsed.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(parsed.defaults.chain.as_deref(), Some("ethereum"));
        assert_eq!(
            parsed.opensea.api_key_env.as_deref(),
            Some("KAIROX_OPENSEA_API_KEY")
        );
        assert!(parsed.chains.contains_key("ethereum"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = "version = 1\nsome_unknown_field = true\n";
        assert!(toml::from_str::<KairoxConfig>(text).is_err());
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 99\n").unwrap();
        let err = load_config(&path).unwrap_err();
        assert!(matches!(err, ConfigError::UnsupportedVersion { .. }));
    }

    #[test]
    fn rejects_raw_hex_pasted_as_opensea_api_key_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n[opensea]\napi_key_env = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
        )
        .unwrap();
        let err = load_config(&path).unwrap_err();
        assert!(matches!(err, ConfigError::SecretLookingValue { .. }));
    }

    #[test]
    fn rejects_mnemonic_looking_chain_rpc_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n[chains.ethereum]\nread_rpc_env = [\"one two three four five six seven eight\"]\n",
        )
        .unwrap();
        let err = load_config(&path).unwrap_err();
        assert!(matches!(err, ConfigError::SecretLookingValue { .. }));
    }

    #[test]
    fn missing_file_fails_closed_with_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let err = load_config(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn resolve_config_path_prefers_explicit_cli_path_over_env() {
        // SAFETY (test-only): no other test in this process reads/writes
        // KAIROX_CONFIG concurrently within the same thread; std::env
        // mutation is inherently process-global, so this is scoped tightly
        // to avoid flakiness under parallel test execution.
        unsafe {
            std::env::set_var(CONFIG_ENV_VAR, "/should/not/be/used.toml");
        }
        let cli_path = PathBuf::from("/explicit/path.toml");
        let resolved = resolve_config_path(Some(&cli_path));
        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);
        }
        assert_eq!(resolved, Some(cli_path));
    }

    #[test]
    fn resolve_config_path_falls_back_to_env_var() {
        unsafe {
            std::env::set_var(CONFIG_ENV_VAR, "/from/env/config.toml");
        }
        let resolved = resolve_config_path(None);
        unsafe {
            std::env::remove_var(CONFIG_ENV_VAR);
        }
        assert_eq!(resolved, Some(PathBuf::from("/from/env/config.toml")));
    }
}
