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

use crate::chain::config::EnvSource;
use crate::chain::endpoint::{EndpointRole, RpcEndpoint};

/// The environment variable naming an explicit config file path, checked
/// when `--config` was not passed on the command line.
pub const CONFIG_ENV_VAR: &str = "KAIROX_CONFIG";

/// The environment variable that can override the effective chain
/// (`defaults.chain` in a config file, or the compiled default
/// `"ethereum"`) without an explicit `--chain`. See
/// [`resolve_runtime_config`] for the full precedence.
pub const CHAIN_ENV_VAR: &str = "KAIROX_CHAIN";

/// The environment variable that can override the effective engine
/// selection the same way [`CHAIN_ENV_VAR`] overrides the chain.
pub const ENGINE_ENV_VAR: &str = "KAIROX_ENGINE";

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
    #[error(transparent)]
    Env(#[from] crate::chain::config::ConfigError),
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

/// Every setting `Kairox` resolves through the config system after loading
/// (if any) has already happened, so no CLI command duplicates its own
/// precedence logic. Built once per invocation by [`resolve_runtime_config`]
/// and threaded down into whichever command needs it.
#[derive(Debug, Clone)]
pub struct ResolvedRuntimeConfig {
    /// The config file actually used, if any (already validated).
    pub config_path: Option<PathBuf>,
    pub config: Option<KairoxConfig>,
    /// Final chain setting: `--chain` > `KAIROX_CHAIN` > `defaults.chain` >
    /// the compiled default `"ethereum"`.
    pub chain: String,
    /// Final engine setting, as a raw string (`"auto"`/`"public"`/
    /// `"opensea"`); the CLI layer is responsible for parsing it into
    /// [`crate::cli::args::EngineSelection`]. Same precedence as `chain`.
    pub engine: String,
}

/// CLI explicit value > environment variable > config `defaults.*` >
/// compiled default. This is the ONE place that precedence is decided;
/// every command that needs a chain or engine default goes through this
/// function (via [`crate::cli::context::resolve_chain_and_runtime`]) rather
/// than re-implementing the ordering itself.
fn resolve_string_setting(
    cli_value: Option<&str>,
    env: &dyn EnvSource,
    env_var: &str,
    config_value: Option<&str>,
    compiled_default: &str,
) -> Result<String, crate::chain::config::ConfigError> {
    if let Some(v) = cli_value {
        return Ok(v.to_string());
    }
    if let Some(v) = env.get(env_var)?
        && !v.is_empty()
    {
        return Ok(v);
    }
    if let Some(v) = config_value {
        return Ok(v.to_string());
    }
    Ok(compiled_default.to_string())
}

/// Resolve the config file (if any), load and validate it (failing closed
/// on a bad file rather than silently falling back to defaults), then
/// derive the final chain/engine settings using the documented precedence:
/// CLI > environment > config `[defaults]` > compiled default.
pub fn resolve_runtime_config(
    cli_config_path: Option<&Path>,
    cli_chain: Option<&str>,
    cli_engine: Option<&str>,
    env: &dyn EnvSource,
) -> Result<ResolvedRuntimeConfig, ConfigError> {
    let config_path = resolve_config_path(cli_config_path);
    let config = match &config_path {
        Some(path) => Some(load_config(path)?),
        None => None,
    };

    let config_chain = config.as_ref().and_then(|c| c.defaults.chain.as_deref());
    let config_engine = config.as_ref().and_then(|c| c.defaults.engine.as_deref());

    let chain = resolve_string_setting(cli_chain, env, CHAIN_ENV_VAR, config_chain, "ethereum")?;
    let engine = resolve_string_setting(cli_engine, env, ENGINE_ENV_VAR, config_engine, "auto")?;

    Ok(ResolvedRuntimeConfig {
        config_path,
        config,
        chain,
        engine,
    })
}

/// Resolve RPC endpoints for one chain from a config entry's named
/// environment variables (`read_rpc_env`/`send_rpc_env`), each read
/// directly as a full URL value (unlike
/// [`crate::chain::config::load_chain_endpoints`]'s indexed
/// `KAIROX_RPC_<chainId>_<n>_URL` convention -- config-driven endpoints
/// name whichever variable the operator already has set). Read-only
/// variables become [`EndpointRole::ReadOnly`] endpoints, send variables
/// become [`EndpointRole::SendOnly`] -- a variable listed in both becomes
/// one [`EndpointRole::ReadWrite`] endpoint. Never reads a raw URL value
/// out of the config file itself, only the variable's current value.
pub fn resolve_chain_rpc_endpoints(
    entry: &ChainConfigEntry,
    env: &dyn EnvSource,
) -> Result<Vec<RpcEndpoint>, crate::chain::config::ConfigError> {
    let mut endpoints = Vec::new();
    let mut send_only: std::collections::HashSet<&str> =
        entry.send_rpc_env.iter().map(String::as_str).collect();

    for var in &entry.read_rpc_env {
        let Some(raw_url) = env.get(var)? else {
            continue;
        };
        let url = url::Url::parse(&raw_url).map_err(|e| {
            crate::chain::config::ConfigError::InvalidUrl {
                var: var.clone(),
                reason: e.to_string(),
            }
        })?;
        let role = if send_only.remove(var.as_str()) {
            EndpointRole::ReadWrite
        } else {
            EndpointRole::ReadOnly
        };
        endpoints.push(RpcEndpoint::new(url, role).with_label(var.clone()));
    }

    for var in &entry.send_rpc_env {
        if !send_only.contains(var.as_str()) {
            // already consumed above as a combined read+write endpoint
            continue;
        }
        let Some(raw_url) = env.get(var)? else {
            continue;
        };
        let url = url::Url::parse(&raw_url).map_err(|e| {
            crate::chain::config::ConfigError::InvalidUrl {
                var: var.clone(),
                reason: e.to_string(),
            }
        })?;
        endpoints.push(RpcEndpoint::new(url, EndpointRole::SendOnly).with_label(var.clone()));
    }

    Ok(endpoints)
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

    fn fake_env(pairs: &[(&str, &str)]) -> crate::chain::config::testing::FakeEnv {
        crate::chain::config::testing::FakeEnv(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn write_config(dir: &tempfile::TempDir, chain: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!("version = 1\n[defaults]\nchain = \"{chain}\"\n"),
        )
        .unwrap();
        path
    }

    #[test]
    fn chain_precedence_cli_wins_over_env_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "base");
        let env = fake_env(&[(CHAIN_ENV_VAR, "robinhood")]);
        let resolved =
            resolve_runtime_config(Some(&config_path), Some("ethereum"), None, &env).unwrap();
        assert_eq!(resolved.chain, "ethereum");
    }

    #[test]
    fn chain_precedence_env_wins_over_config_when_cli_absent() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "base");
        let env = fake_env(&[(CHAIN_ENV_VAR, "robinhood")]);
        let resolved = resolve_runtime_config(Some(&config_path), None, None, &env).unwrap();
        assert_eq!(resolved.chain, "robinhood");
    }

    #[test]
    fn chain_precedence_config_wins_over_compiled_default() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "base");
        let env = fake_env(&[]);
        let resolved = resolve_runtime_config(Some(&config_path), None, None, &env).unwrap();
        assert_eq!(resolved.chain, "base");
    }

    #[test]
    fn chain_precedence_compiled_default_when_nothing_else_set() {
        let env = fake_env(&[]);
        let resolved = resolve_runtime_config(None, None, None, &env).unwrap();
        assert_eq!(resolved.chain, "ethereum");
        assert_eq!(resolved.engine, "auto");
        assert!(resolved.config.is_none());
    }

    #[test]
    fn engine_follows_the_same_precedence_as_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n[defaults]\nengine = \"public\"\n").unwrap();
        let env = fake_env(&[]);
        let resolved = resolve_runtime_config(Some(&path), None, None, &env).unwrap();
        assert_eq!(resolved.engine, "public");

        let env_override = fake_env(&[(ENGINE_ENV_VAR, "opensea")]);
        let resolved = resolve_runtime_config(Some(&path), None, None, &env_override).unwrap();
        assert_eq!(resolved.engine, "opensea");

        let resolved =
            resolve_runtime_config(Some(&path), None, Some("public"), &env_override).unwrap();
        assert_eq!(resolved.engine, "public");
    }

    #[test]
    fn resolve_runtime_config_fails_closed_on_a_broken_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 99\n").unwrap();
        let env = fake_env(&[]);
        let err = resolve_runtime_config(Some(&path), None, None, &env).unwrap_err();
        assert!(matches!(err, ConfigError::UnsupportedVersion { .. }));
    }

    #[test]
    fn resolve_chain_rpc_endpoints_reads_named_env_vars_as_urls() {
        let entry = ChainConfigEntry {
            read_rpc_env: vec!["MY_READ_URL".into()],
            send_rpc_env: vec!["MY_SEND_URL".into()],
        };
        let env = fake_env(&[
            ("MY_READ_URL", "https://read.example"),
            ("MY_SEND_URL", "https://send.example"),
        ]);
        let endpoints = resolve_chain_rpc_endpoints(&entry, &env).unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(
            endpoints
                .iter()
                .any(|e| e.role == EndpointRole::ReadOnly
                    && e.url.as_str() == "https://read.example/")
        );
        assert!(
            endpoints
                .iter()
                .any(|e| e.role == EndpointRole::SendOnly
                    && e.url.as_str() == "https://send.example/")
        );
    }

    #[test]
    fn resolve_chain_rpc_endpoints_merges_a_variable_listed_in_both_roles() {
        let entry = ChainConfigEntry {
            read_rpc_env: vec!["SHARED_URL".into()],
            send_rpc_env: vec!["SHARED_URL".into()],
        };
        let env = fake_env(&[("SHARED_URL", "https://shared.example")]);
        let endpoints = resolve_chain_rpc_endpoints(&entry, &env).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].role, EndpointRole::ReadWrite);
    }

    #[test]
    fn resolve_chain_rpc_endpoints_skips_unset_variables() {
        let entry = ChainConfigEntry {
            read_rpc_env: vec!["NOT_SET_AT_ALL".into()],
            send_rpc_env: vec![],
        };
        let env = fake_env(&[]);
        let endpoints = resolve_chain_rpc_endpoints(&entry, &env).unwrap();
        assert!(endpoints.is_empty());
    }
}
