//! The trusted SeaDrop deployment-fingerprint registry.
//!
//! Distinct from [`super::thirdweb_registry`]/[`super::manifold_registry`]
//! in one important way: those exist because a chain-registry-level
//! `default_seadrop_address`-style shortcut was never available for
//! thirdweb/Manifold at all (there is no per-chain "default thirdweb
//! Drop"/"default Manifold extension" -- every deployment is discovered
//! or operator-supplied). SeaDrop, by contrast, already has
//! [`crate::chain::registry::ChainInfo::default_seadrop_address`] as its
//! own, older, chain-registry-level trust mechanism -- but that field is
//! a blunt "trust this address unconditionally, forever, on this chain"
//! switch, set at compile time by a human maintainer, with no runtime
//! re-verification. It is deliberately `None` for Ink (see
//! `chain::registry::ink`'s doc comment): the official
//! `ProjectOpenSea/seadrop` deployment table does not list Ink, so
//! blanket-trusting the canonical singleton address there the same way
//! Ethereum/Base do would mean trusting *bytecode-similarity-only*
//! evidence forever, with no ongoing check.
//!
//! This registry is Ink's real trust mechanism instead: a narrower,
//! re-verified-on-every-attempt fingerprint binding **address AND
//! runtime bytecode hash AND chain id** together, populated only after
//! independently proving semantic code identity against the pinned
//! official `ProjectOpenSea/seadrop` release (see this module's
//! `BUILTIN_REGISTRY` entry doc comment for the exact proof). Unlike
//! `default_seadrop_address`, a chain whose `ChainInfo` sets
//! [`crate::chain::registry::ChainInfo::seadrop_requires_trusted_fingerprint`]
//! to `true` (currently only Ink) has its SeaDrop contract's *live*
//! runtime bytecode re-hashed and re-checked against this registry
//! immediately before every signing attempt (see
//! `execution::prepared::gather_unsigned_plan`) -- one changed byte, a
//! wrong address, or an unrecognized deployment all refuse, with no
//! fallback to "selector-compatible, so probably fine."
//!
//! Every existing chain (Ethereum, Base, Robinhood Chain, Robinhood Chain
//! Testnet) keeps `seadrop_requires_trusted_fingerprint: false` and is
//! completely unaffected by this registry's contents -- adding entries
//! here changes nothing about their behavior.
//!
//! **Naming discipline**: this is `TrustedSeaDropFingerprint`, never
//! `OfficialSeaDropDeployment`. An entry here proves *semantic code
//! identity* (the runtime bytecode is, byte for byte modulo expected
//! chain-specific immutables, the pinned SeaDrop 1.0 release) -- it does
//! NOT prove *official deployment provenance* (that OpenSea/ProjectOpenSea
//! themselves performed or sanctioned this specific deployment). The Ink
//! entry below was deployed via the same public, permissionless
//! `ImmutableCreate2Factory` (`0x0000000000FFe8B47B3e2130213B802212439497`)
//! used for the genuine official deployments on Ethereum/Base, but by a
//! *different* calling EOA than Ethereum's -- consistent with (but not
//! proof of) an unrelated third party permissionlessly redeploying the
//! exact same, genuine, unmodified SeaDrop bytecode using the publicly
//! known salt and init code. Kairox reports these two provenance
//! concepts (`SEMANTIC_CODE_PROVENANCE` and `OFFICIAL_DEPLOYMENT_PROVENANCE`)
//! separately everywhere and never collapses them into one label.

use alloy_primitives::{Address, B256, address};

use crate::chain::registry::ChainId;

/// One manually-reviewed, trusted SeaDrop deployment, bound to an exact
/// address, chain, and runtime bytecode hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedSeaDropFingerprint {
    /// Human-readable label, shown in resolution evidence and reports --
    /// never used for matching.
    pub name: &'static str,
    pub chain_id: ChainId,
    /// The SeaDrop contract's own address -- SeaDrop 1.0 is never a
    /// proxy (independently confirmed for the Ink entry below: both
    /// EIP-1967 implementation/admin storage slots read as zero), so
    /// this is a direct address match, not an implementation-resolved
    /// one the way thirdweb's per-collection-proxy fingerprints are.
    pub address: Address,
    /// `keccak256` of the exact live runtime bytecode at `address` on
    /// `chain_id`.
    pub runtime_bytecode_hash: B256,
    /// Which SeaDrop protocol version this fingerprint was reviewed
    /// against.
    pub protocol_version: &'static str,
    /// Exactly which pinned upstream release this fingerprint's runtime-
    /// bytecode equivalence was proven against -- kept as a plain string
    /// so the review trail is self-documenting in the registry entry
    /// itself, not only in a commit message.
    pub source_provenance: &'static str,
}

/// The built-in trusted registry.
///
/// One entry: the SeaDrop 1.0 singleton at
/// `0x00005EA00Ac477B1030CE78506496e8C2dE24bf5` on Ink (chain 57073).
///
/// **Proof this pass established** (full detail in the session's audit,
/// summarized here for the permanent record):
///
/// 1. Pinned the exact official release: `ProjectOpenSea/seadrop` tag
///    `seadrop-1.0`, commit `368b005b78cbcf35752983eb257afe3a37387285`
///    (verified via `git rev-parse`/`git log`, not assumed from a prompt
///    value), compiled with the pinned `foundry.toml` settings: solc
///    `0.8.17`, optimizer enabled, `runs = 1_000_000`, `via_ir = false`.
/// 2. Compiling that exact pinned source with `forge build` reproduced
///    the exact real Ethereum-mainnet official-deployment creation-tx
///    init code byte-for-byte (verified against the real creation
///    transaction's `raw_input`, fetched live).
/// 3. Ink's live runtime bytecode (`eth_getCode` on chain 57073,
///    `keccak256` = the hash below) differs from the locally-compiled
///    deployed bytecode in **exactly 34 of 21,081 bytes**, clustered
///    into precisely two regions, both fully and exclusively explained
///    by `SeaDrop.sol`'s own two `immutable` fields:
///    `_CHAIN_ID = block.chainid` (57073 = `0xdef1`) and
///    `_DOMAIN_SEPARATOR = keccak256(abi.encode(_EIP_712_DOMAIN_TYPEHASH,
///    _NAME_HASH, _VERSION_HASH, block.chainid, address(this)))` --
///    independently recomputed for chain id 57073 and
///    `address(this) = 0x00005EA00Ac477B1030CE78506496e8C2dE24bf5`, and
///    matched **byte-for-byte** against the live on-chain value. Zero
///    unexplained bytes remain anywhere in the runtime bytecode.
/// 4. Confirmed not a proxy: both the EIP-1967 implementation slot
///    (`0x360894a1...382bb`) and admin slot (`0xb5312768...5d6d4`) read
///    as all-zero on Ink; the 21,081-byte runtime bytecode is itself
///    the full SeaDrop logic, not a delegatecall stub.
/// 5. Deployer/CREATE2 provenance (supplementary, does not affect
///    `SEMANTIC_CODE_PROVENANCE`): the same `ImmutableCreate2Factory`
///    (`0x0000000000FFe8B47B3e2130213B802212439497`) that deployed the
///    genuine official SeaDrop singleton on Ethereum and Base also
///    deployed the Ink instance -- but via a different calling EOA than
///    Ethereum's known deployer, so this does NOT establish
///    `OFFICIAL_DEPLOYMENT_PROVENANCE = YES` (a third party could
///    permissionlessly redeploy identical bytecode via the same public
///    factory). Real, successful, on-chain mint activity through this
///    exact address was also independently observed (a genuine ERC721
///    `Transfer` plus SeaDrop mint-event pair in a real transaction).
///
/// This proof standard -- pinned source, exact compiler config, creation-
/// bytecode equivalence, every runtime difference explained solely by
/// named immutables with independently-recomputed expected values, and
/// confirmed non-proxy status -- is what `SEMANTIC_CODE_PROVENANCE = HIGH`
/// means for this entry. `OFFICIAL_DEPLOYMENT_PROVENANCE` remains
/// `UNKNOWN` and this registry entry must never be described as an
/// official OpenSea-sanctioned deployment.
pub const BUILTIN_REGISTRY: &[TrustedSeaDropFingerprint] = &[TrustedSeaDropFingerprint {
    name: "seadrop-1.0-ink-mainnet",
    chain_id: 57073,
    address: address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5"),
    runtime_bytecode_hash: alloy_primitives::b256!(
        "b9008e66da7b6c74e86aa37d02f3b35ef8acc9fde66fa49d5b70a89f7b6dc996"
    ),
    protocol_version: "SeaDrop 1.0",
    source_provenance: "ProjectOpenSea/seadrop@368b005b78cbcf35752983eb257afe3a37387285 (tag seadrop-1.0)",
}];

/// Find a registry entry matching `chain_id`, `address`, AND
/// `bytecode_hash` all exactly. Wrong chain, wrong address, or one
/// differing byte in the live bytecode -- any of the three -- is not a
/// match; no partial/selector-only fallback, mirroring
/// `thirdweb_registry::find_fingerprint`/`manifold_registry::find_fingerprint`'s
/// identical design.
pub fn find_fingerprint(
    registry: &[TrustedSeaDropFingerprint],
    chain_id: ChainId,
    address: Address,
    bytecode_hash: B256,
) -> Option<TrustedSeaDropFingerprint> {
    registry
        .iter()
        .find(|f| {
            f.chain_id == chain_id
                && f.address == address
                && f.runtime_bytecode_hash == bytecode_hash
        })
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ADDRESS: Address = address!("1111111111111111111111111111111111111111");

    fn sample(chain_id: ChainId, address: Address, hash: B256) -> TrustedSeaDropFingerprint {
        TrustedSeaDropFingerprint {
            name: "test-fixture",
            chain_id,
            address,
            runtime_bytecode_hash: hash,
            protocol_version: "SeaDrop 1.0",
            source_provenance: "test-fixture",
        }
    }

    #[test]
    fn builtin_registry_has_exactly_the_one_reviewed_ink_entry() {
        assert_eq!(BUILTIN_REGISTRY.len(), 1);
        let entry = &BUILTIN_REGISTRY[0];
        assert_eq!(entry.chain_id, 57073);
        assert_eq!(
            entry.address,
            address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5")
        );
    }

    #[test]
    fn exact_match_found() {
        let hash = B256::repeat_byte(0xAB);
        let registry = [sample(1, SAMPLE_ADDRESS, hash)];
        assert!(find_fingerprint(&registry, 1, SAMPLE_ADDRESS, hash).is_some());
    }

    #[test]
    fn wrong_chain_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let registry = [sample(1, SAMPLE_ADDRESS, hash)];
        assert!(find_fingerprint(&registry, 2, SAMPLE_ADDRESS, hash).is_none());
    }

    #[test]
    fn wrong_address_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let other_address: Address = address!("2222222222222222222222222222222222222222");
        let registry = [sample(1, SAMPLE_ADDRESS, hash)];
        assert!(find_fingerprint(&registry, 1, other_address, hash).is_none());
    }

    #[test]
    fn wrong_bytecode_hash_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let other_hash = B256::repeat_byte(0xCD);
        let registry = [sample(1, SAMPLE_ADDRESS, hash)];
        assert!(find_fingerprint(&registry, 1, SAMPLE_ADDRESS, other_hash).is_none());
    }

    #[test]
    fn one_byte_bytecode_mutation_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let mut mutated = hash;
        mutated.0[31] ^= 0x01;
        let registry = [sample(1, SAMPLE_ADDRESS, hash)];
        assert!(find_fingerprint(&registry, 1, SAMPLE_ADDRESS, mutated).is_none());
    }
}
