//! Multi-wallet manifest: strict, secret-free JSON describing which
//! self-funded wallets participate in a session, and where (not what) their
//! signing key can be found at runtime.
//!
//! A manifest file is never trusted with key material. It can only ever
//! *name* an environment variable (`key_env`) to read at runtime; the key
//! itself is loaded, wrapped in the existing [`crate::signing::signer::LocalSigner`]
//! architecture, and zeroized exactly like the single-wallet `--send` path.

use std::path::Path;

use alloy_primitives::Address;
use serde::Deserialize;
use thiserror::Error;

/// Hard ceiling on manifest wallet count, independent of any configured
/// smaller limit. Chosen deliberately conservative for Phase 5:
///
/// - Every wallet fans out to every send-capable endpoint at broadcast
///   time (`wallet_count * send_endpoint_count` HTTP submissions at T=0),
///   and to the OpenSea API independently in OpenSea mode -- 50 wallets
///   against a realistic 3-5 endpoint pool is already a few hundred
///   near-simultaneous requests, which is the outer edge of what bounded
///   concurrency here is designed/tested for.
/// - It keeps the manifest, its validation, and its test fixtures easy to
///   reason about and keep deterministic.
/// - It is far below the scale of a sybil-automation tool, while still
///   comfortably covering realistic legitimate small-team multi-wallet
///   participation.
///
/// This is a hard ceiling Kairox enforces itself, not a value borrowed from
/// any reference implementation.
pub const MAX_WALLETS: usize = 50;

/// The only manifest schema version Kairox currently understands.
pub const SUPPORTED_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to read manifest file '{path}': {detail}")]
    Io { path: String, detail: String },
    #[error("failed to parse manifest JSON: {0}")]
    Parse(String),
    #[error(
        "unsupported manifest version {found} (Kairox understands version {SUPPORTED_MANIFEST_VERSION})"
    )]
    UnsupportedVersion { found: u32 },
    #[error("manifest has no wallets")]
    EmptyWalletSet,
    #[error("manifest has {found} wallets, exceeding the maximum of {MAX_WALLETS}")]
    TooManyWallets { found: usize },
    #[error("wallet entry {index} has an invalid address '{address}': {detail}")]
    MalformedAddress {
        index: usize,
        address: String,
        detail: String,
    },
    #[error(
        "wallet entry {index} ({address}) has quantity 0; every wallet must request at least one mint"
    )]
    ZeroQuantity { index: usize, address: Address },
    #[error(
        "duplicate wallet address {address} (entries {first_index} and {second_index}); each address may appear only once, to avoid nonce ambiguity"
    )]
    DuplicateAddress {
        address: Address,
        first_index: usize,
        second_index: usize,
    },
    #[error("wallet entry {index} ({address}) has an empty key_env")]
    EmptyKeyEnv { index: usize, address: Address },
    #[error(
        "wallet entry {index} ({address})'s key_env value '{value}' looks like raw key material, not an environment variable name; the manifest must only ever reference where a key is loaded from, never contain it"
    )]
    KeyEnvLooksLikeSecret {
        index: usize,
        address: Address,
        value: String,
    },
    #[error("wallet entry {index} ({address}) has an empty label")]
    EmptyLabel { index: usize, address: Address },
}

/// The raw on-disk shape. `deny_unknown_fields` is the primary structural
/// defense against a manifest ever carrying key material under some
/// unexpected field name (`private_key`, `secret_key`, `mnemonic`, `seed`,
/// etc. would all be rejected as unknown fields before ever reaching
/// application logic).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletManifestFile {
    version: u32,
    wallets: Vec<WalletManifestEntryRaw>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletManifestEntryRaw {
    #[serde(default)]
    label: Option<String>,
    address: String,
    quantity: u64,
    key_env: String,
}

/// One validated, normalized manifest wallet entry. Identity is the
/// (normalized) `address` — never `label`, which is operator-supplied and
/// may be absent, duplicated across a session's display, or changed
/// between runs. See [`crate::execution::multi_wallet`] for why label
/// equality must never be used for execution/security correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletManifestEntry {
    pub label: Option<String>,
    pub address: Address,
    pub quantity: u64,
    /// Name of the environment variable to read this wallet's signing key
    /// from at runtime. Never the key itself.
    pub key_env: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletManifest {
    pub wallets: Vec<WalletManifestEntry>,
}

/// Load and fully validate a manifest file from disk.
pub fn load_manifest_file(path: &Path) -> Result<WalletManifest, ManifestError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ManifestError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    parse_and_validate_manifest(&raw)
}

/// Parse and validate manifest JSON text directly — the file-reading path
/// factored out so tests exercise the validation logic without touching
/// the filesystem.
pub fn parse_and_validate_manifest(raw: &str) -> Result<WalletManifest, ManifestError> {
    let file: WalletManifestFile =
        serde_json::from_str(raw).map_err(|e| ManifestError::Parse(e.to_string()))?;
    validate(file)
}

fn validate(file: WalletManifestFile) -> Result<WalletManifest, ManifestError> {
    if file.version != SUPPORTED_MANIFEST_VERSION {
        return Err(ManifestError::UnsupportedVersion {
            found: file.version,
        });
    }
    if file.wallets.is_empty() {
        return Err(ManifestError::EmptyWalletSet);
    }
    if file.wallets.len() > MAX_WALLETS {
        return Err(ManifestError::TooManyWallets {
            found: file.wallets.len(),
        });
    }

    let mut wallets = Vec::with_capacity(file.wallets.len());
    let mut seen: Vec<(Address, usize)> = Vec::with_capacity(file.wallets.len());

    for (index, entry) in file.wallets.into_iter().enumerate() {
        let address =
            entry
                .address
                .parse::<Address>()
                .map_err(|e| ManifestError::MalformedAddress {
                    index,
                    address: entry.address.clone(),
                    detail: e.to_string(),
                })?;

        if entry.quantity == 0 {
            return Err(ManifestError::ZeroQuantity { index, address });
        }

        if let Some((_, first_index)) = seen.iter().find(|(a, _)| *a == address) {
            return Err(ManifestError::DuplicateAddress {
                address,
                first_index: *first_index,
                second_index: index,
            });
        }
        seen.push((address, index));

        let key_env = entry.key_env.trim();
        if key_env.is_empty() {
            return Err(ManifestError::EmptyKeyEnv { index, address });
        }
        if looks_like_key_material(key_env) {
            return Err(ManifestError::KeyEnvLooksLikeSecret {
                index,
                address,
                value: mask_suspicious_value(key_env),
            });
        }

        if let Some(label) = &entry.label
            && label.trim().is_empty()
        {
            return Err(ManifestError::EmptyLabel { index, address });
        }

        wallets.push(WalletManifestEntry {
            label: entry.label.map(|l| l.trim().to_string()),
            address,
            quantity: entry.quantity,
            key_env: key_env.to_string(),
        });
    }

    Ok(WalletManifest { wallets })
}

/// Conservative heuristic: a `key_env` value that is itself long hex (with
/// or without `0x`) or looks like a BIP-39 mnemonic (many space-separated
/// lowercase words) is almost certainly a pasted secret, not an
/// environment variable name. Environment variable names are conventionally
/// short, uppercase, and alphanumeric/underscore.
fn looks_like_key_material(value: &str) -> bool {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let is_long_hex = stripped.len() >= 32 && stripped.chars().all(|c| c.is_ascii_hexdigit());
    let looks_like_mnemonic = value.split_whitespace().count() >= 8;
    is_long_hex || looks_like_mnemonic
}

/// Never echo a suspected secret value verbatim, even in an error message.
fn mask_suspicious_value(value: &str) -> String {
    format!("<redacted, {} chars>", value.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_json() -> String {
        r#"{
            "version": 1,
            "wallets": [
                {"label": "wallet-01", "address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_WALLET_01"},
                {"label": "wallet-02", "address": "0x000000000000000000000000000000000000beef", "quantity": 2, "key_env": "KAIROX_KEY_WALLET_02"}
            ]
        }"#
        .to_string()
    }

    #[test]
    fn accepts_a_valid_manifest() {
        let manifest = parse_and_validate_manifest(&valid_manifest_json()).unwrap();
        assert_eq!(manifest.wallets.len(), 2);
        assert_eq!(manifest.wallets[0].label.as_deref(), Some("wallet-01"));
        assert_eq!(manifest.wallets[1].quantity, 2);
    }

    #[test]
    fn rejects_unsupported_version() {
        let json = valid_manifest_json().replace("\"version\": 1", "\"version\": 2");
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::UnsupportedVersion { found: 2 }
        ));
    }

    #[test]
    fn rejects_empty_wallet_set() {
        let json = r#"{"version": 1, "wallets": []}"#;
        let err = parse_and_validate_manifest(json).unwrap_err();
        assert!(matches!(err, ManifestError::EmptyWalletSet));
    }

    #[test]
    fn rejects_too_many_wallets() {
        let mut wallets = Vec::new();
        for i in 0..(MAX_WALLETS + 1) {
            wallets.push(format!(
                r#"{{"address": "0x{:040x}", "quantity": 1, "key_env": "KAIROX_KEY_{i}"}}"#,
                i + 1
            ));
        }
        let json = format!(r#"{{"version": 1, "wallets": [{}]}}"#, wallets.join(","));
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::TooManyWallets { .. }));
    }

    #[test]
    fn rejects_malformed_address() {
        let json = valid_manifest_json().replace(
            "0x000000000000000000000000000000000000c0de",
            "not-an-address",
        );
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::MalformedAddress { .. }));
    }

    #[test]
    fn rejects_zero_quantity() {
        let json = valid_manifest_json().replace("\"quantity\": 1,", "\"quantity\": 0,");
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::ZeroQuantity { .. }));
    }

    #[test]
    fn rejects_duplicate_address_even_with_different_labels() {
        let json = r#"{
            "version": 1,
            "wallets": [
                {"label": "a", "address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_A"},
                {"label": "b-different-label", "address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_B"}
            ]
        }"#;
        let err = parse_and_validate_manifest(json).unwrap_err();
        assert!(matches!(err, ManifestError::DuplicateAddress { .. }));
    }

    #[test]
    fn duplicate_detection_normalizes_address_case() {
        let json = r#"{
            "version": 1,
            "wallets": [
                {"address": "0x000000000000000000000000000000000000C0DE", "quantity": 1, "key_env": "KAIROX_KEY_A"},
                {"address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_B"}
            ]
        }"#;
        let err = parse_and_validate_manifest(json).unwrap_err();
        assert!(matches!(err, ManifestError::DuplicateAddress { .. }));
    }

    #[test]
    fn rejects_empty_key_env() {
        let json = valid_manifest_json().replace("\"KAIROX_KEY_WALLET_01\"", "\"\"");
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::EmptyKeyEnv { .. }));
    }

    #[test]
    fn rejects_key_env_that_looks_like_a_raw_hex_private_key() {
        let json = valid_manifest_json().replace(
            "\"KAIROX_KEY_WALLET_01\"",
            &format!("\"{}\"", "a".repeat(64)),
        );
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::KeyEnvLooksLikeSecret { .. }));
    }

    #[test]
    fn key_env_looking_like_secret_error_never_echoes_the_value() {
        let secret = "b".repeat(64);
        let json =
            valid_manifest_json().replace("\"KAIROX_KEY_WALLET_01\"", &format!("\"{secret}\""));
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(!err.to_string().contains(&secret));
    }

    #[test]
    fn rejects_key_env_that_looks_like_a_mnemonic() {
        let mnemonic = "abandon ability able about above absent absorb abstract";
        let json =
            valid_manifest_json().replace("\"KAIROX_KEY_WALLET_01\"", &format!("\"{mnemonic}\""));
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::KeyEnvLooksLikeSecret { .. }));
    }

    #[test]
    fn manifest_with_unknown_field_is_rejected_structurally() {
        // The primary defense: any unexpected field -- including
        // "private_key" -- fails to parse at all.
        let json = r#"{
            "version": 1,
            "wallets": [
                {"address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_A", "private_key": "0xdeadbeef"}
            ]
        }"#;
        let err = parse_and_validate_manifest(json).unwrap_err();
        assert!(matches!(err, ManifestError::Parse(_)));
    }

    #[test]
    fn manifest_json_never_accepted_with_secret_key_field() {
        for field in ["secret_key", "mnemonic", "seed_phrase", "seed", "raw_key"] {
            let json = format!(
                r#"{{"version": 1, "wallets": [{{"address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "K", "{field}": "x"}}]}}"#
            );
            let err = parse_and_validate_manifest(&json).unwrap_err();
            assert!(
                matches!(err, ManifestError::Parse(_)),
                "field '{field}' should have been rejected structurally"
            );
        }
    }

    #[test]
    fn rejects_malformed_json() {
        let err = parse_and_validate_manifest("not json").unwrap_err();
        assert!(matches!(err, ManifestError::Parse(_)));
    }

    #[test]
    fn rejects_empty_label_when_provided() {
        let json = valid_manifest_json().replace("\"wallet-01\"", "\"   \"");
        let err = parse_and_validate_manifest(&json).unwrap_err();
        assert!(matches!(err, ManifestError::EmptyLabel { .. }));
    }

    #[test]
    fn accepts_manifest_with_no_label() {
        let json = r#"{
            "version": 1,
            "wallets": [
                {"address": "0x000000000000000000000000000000000000c0de", "quantity": 1, "key_env": "KAIROX_KEY_A"}
            ]
        }"#;
        let manifest = parse_and_validate_manifest(json).unwrap();
        assert_eq!(manifest.wallets[0].label, None);
    }

    #[test]
    fn accepts_exactly_max_wallets() {
        let mut wallets = Vec::new();
        for i in 0..MAX_WALLETS {
            wallets.push(format!(
                r#"{{"address": "0x{:040x}", "quantity": 1, "key_env": "KAIROX_KEY_{i}"}}"#,
                i + 1
            ));
        }
        let json = format!(r#"{{"version": 1, "wallets": [{}]}}"#, wallets.join(","));
        let manifest = parse_and_validate_manifest(&json).unwrap();
        assert_eq!(manifest.wallets.len(), MAX_WALLETS);
    }
}
