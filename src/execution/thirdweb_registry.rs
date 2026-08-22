//! The trusted thirdweb Drop implementation-fingerprint registry.
//!
//! Mirrors [`super::generic_registry`]'s exact model and rationale --
//! selector compatibility and a successful `eth_call` are not evidence
//! that a given address runs *unmodified* thirdweb Drop semantics. A
//! thirdweb Drop base extension can be inherited, and its execution-
//! affecting hooks (`_beforeClaim`, `_afterClaim`,
//! `_collectPriceOnClaim`, `_transferTokensOnClaim`, `_dropMsgSender`)
//! can be overridden by a custom contract that merely happens to expose
//! selector-compatible `claim()`/`ClaimCondition` functions. This is the
//! *only* route to authorizing a real (non-rehearsal, non-dry-run) live
//! send through the thirdweb engine -- see
//! `execution::thirdweb_engine::establish_provenance`.
//!
//! An entry here represents one specific deployed **implementation**
//! contract (the proxy-resolved target, per
//! `protocol::erc_standards::eip1167_clone_implementation`/
//! `eip1967_implementation` -- thirdweb's own factory-clone deployment
//! pattern uses EIP-1167 minimal proxies, not EIP-1967) whose exact
//! runtime bytecode a human has manually verified corresponds to an
//! official, unmodified thirdweb prebuilt Drop contract of the named
//! flavor -- no custom hook overrides, no unreviewed logic.
//!
//! [`BUILTIN_REGISTRY`] ships **empty**: no implementation has been
//! manually reviewed and registered as part of this pass. That is the
//! correct, honest state -- it means the thirdweb engine currently has
//! no route to a real live send anywhere, by design, until a real
//! implementation is reviewed and added here. Dry-run (`kairox mint
//! --engine thirdweb`, no `--send`/`--rehearsal`) is unaffected: it only
//! reports what flavor/state was found, and never needed provenance to
//! begin with. Test call sites take the registry to search as a
//! parameter specifically so tests can inject entries and prove the
//! *mechanism* without needing this list to ship non-empty.

use alloy_primitives::B256;

use crate::chain::registry::ChainId;

/// Which thirdweb Drop ABI flavor a fingerprint entry corresponds to --
/// see `protocol::thirdweb`'s module doc comment for the exact,
/// source-verified ABI differences between these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThirdwebFlavor {
    /// `Drop.sol` / `IClaimConditionMultiPhase` -- `getActiveClaimConditionId()`,
    /// `getClaimConditionById(uint256)`, `getSupplyClaimedByWallet(uint256,address)`.
    DropMultiPhase721,
    /// `DropSinglePhase.sol` -- `claimCondition()` (no-argument public
    /// state variable getter), `getSupplyClaimedByWallet(address)`
    /// (single-argument).
    DropSinglePhase721,
}

/// One manually-reviewed, trusted thirdweb Drop implementation, bound to
/// an exact runtime bytecode hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThirdwebTrustedFingerprint {
    /// Human-readable label, shown in resolution evidence and reports --
    /// never used for matching.
    pub name: &'static str,
    pub chain_id: ChainId,
    /// `keccak256` of the exact runtime bytecode at the resolved
    /// implementation address (the EIP-1167-clone-resolved or
    /// EIP-1967-proxy-resolved address, or the target's own address if
    /// it is not a recognized proxy pattern at all).
    pub implementation_bytecode_hash: B256,
    pub flavor: ThirdwebFlavor,
}

/// The built-in trusted registry. Empty by design -- see module docs.
pub const BUILTIN_REGISTRY: &[ThirdwebTrustedFingerprint] = &[];

/// Find a registry entry matching `chain_id` and `bytecode_hash` exactly.
/// An exact fingerprint match is the only thing this function looks for
/// -- no partial/selector-only matching, mirroring
/// `generic_registry::find_fingerprint`'s identical design.
pub fn find_fingerprint(
    registry: &[ThirdwebTrustedFingerprint],
    chain_id: ChainId,
    bytecode_hash: B256,
) -> Option<ThirdwebTrustedFingerprint> {
    registry
        .iter()
        .find(|f| f.chain_id == chain_id && f.implementation_bytecode_hash == bytecode_hash)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(chain_id: ChainId, hash: B256, flavor: ThirdwebFlavor) -> ThirdwebTrustedFingerprint {
        ThirdwebTrustedFingerprint {
            name: "test-fixture",
            chain_id,
            implementation_bytecode_hash: hash,
            flavor,
        }
    }

    #[test]
    fn builtin_registry_ships_empty() {
        assert!(
            BUILTIN_REGISTRY.is_empty(),
            "no implementation has been manually reviewed and registered in this pass -- see \
             module docs"
        );
    }

    #[test]
    fn exact_match_found() {
        let hash = B256::repeat_byte(0xAB);
        let registry = [sample(1, hash, ThirdwebFlavor::DropMultiPhase721)];
        assert!(find_fingerprint(&registry, 1, hash).is_some());
    }

    #[test]
    fn wrong_chain_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let registry = [sample(1, hash, ThirdwebFlavor::DropMultiPhase721)];
        assert!(find_fingerprint(&registry, 2, hash).is_none());
    }

    #[test]
    fn wrong_bytecode_hash_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let other_hash = B256::repeat_byte(0xCD);
        let registry = [sample(1, hash, ThirdwebFlavor::DropSinglePhase721)];
        assert!(find_fingerprint(&registry, 1, other_hash).is_none());
    }
}
