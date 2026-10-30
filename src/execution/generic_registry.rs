//! The trusted generic-schema fingerprint registry.
//!
//! This is the *only* route to `Confidence::High` for a generic (non-
//! SeaDrop, non-OpenSea) mint. An operator-declared schema plus ERC-165
//! confirmation is deliberately **not** sufficient -- ERC-165 proves the
//! NFT *standard* a contract implements, not that any particular function
//! selector means what a schema claims it means, what its arguments mean,
//! or what value it expects. See `docs/generic-engine.md`'s "Confidence
//! model" section for the incident this module exists to close.
//!
//! An entry here represents a specific deployed implementation's mint
//! semantics that a human has manually read the verified source/ABI for
//! and confirmed matches exactly -- selector, argument meanings, payable
//! semantics, and price. It is bound to that implementation's exact
//! runtime bytecode hash, so an upgraded or different contract can never
//! match it by accident (see [`super::generic_engine`]'s pre-sign
//! bytecode re-check).
//!
//! [`BUILTIN_REGISTRY`] ships **empty**: no contract has been manually
//! reviewed and registered as part of this pass. That is the correct,
//! honest state -- it means generic AUTO execution currently has no route
//! to a real live send anywhere, by design, until either a real
//! implementation is reviewed and added here, or a verified-ABI/explorer
//! provider integration (out of scope this pass, see
//! `docs/generic-engine.md`) supplies equivalent independent evidence.
//! [`GenericVerifiedContractAdapter`](crate::cli::commands::resolver_adapters::GenericVerifiedContractAdapter)
//! takes the registry to search as a parameter specifically so tests can
//! inject entries and prove the *mechanism* without needing this list to
//! ship non-empty.

use alloy_primitives::B256;

use crate::chain::registry::ChainId;

use super::generic_schema::{GenericMintShape, GenericStandard};

/// One manually-reviewed, trusted mint schema, bound to an exact
/// implementation's runtime bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedGenericFingerprint {
    /// Human-readable label, shown in resolution evidence and reports --
    /// never used for matching.
    pub name: &'static str,
    pub chain_id: ChainId,
    /// `keccak256` of the exact runtime bytecode at the implementation
    /// address (the proxy-resolved address, if the target is an EIP-1967
    /// proxy -- see [`super::generic_engine::resolve_implementation_and_code_hash`]).
    pub implementation_bytecode_hash: B256,
    pub standard: GenericStandard,
    pub shape: GenericMintShape,
    pub token_id: Option<u64>,
    /// The authoritative, manually-verified price per token, in wei. An
    /// operator-supplied `price_per_token_wei` (if also given) may only
    /// ever act as a maximum-acceptable-price check against this value,
    /// never as the source of truth for what gets signed -- see
    /// [`super::generic_engine::prepare_generic_transaction`].
    pub price_per_token_wei: u128,
}

/// The built-in trusted registry. Empty by design -- see module docs.
pub const BUILTIN_REGISTRY: &[TrustedGenericFingerprint] = &[];

/// Find a registry entry matching `chain_id` and `bytecode_hash` exactly.
/// An exact fingerprint match is the only thing this function looks for --
/// no partial/selector-only matching exists here, by design (see Part
/// 2/5 of the correction this module implements).
pub fn find_fingerprint(
    registry: &[TrustedGenericFingerprint],
    chain_id: ChainId,
    bytecode_hash: B256,
) -> Option<TrustedGenericFingerprint> {
    registry
        .iter()
        .find(|f| f.chain_id == chain_id && f.implementation_bytecode_hash == bytecode_hash)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(chain_id: ChainId, hash: B256) -> TrustedGenericFingerprint {
        TrustedGenericFingerprint {
            name: "test-fixture",
            chain_id,
            implementation_bytecode_hash: hash,
            standard: GenericStandard::Erc721,
            shape: GenericMintShape::MintQuantity,
            token_id: None,
            price_per_token_wei: 0,
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
        let registry = [sample(1, hash)];
        assert!(find_fingerprint(&registry, 1, hash).is_some());
    }

    #[test]
    fn wrong_chain_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let registry = [sample(1, hash)];
        assert!(find_fingerprint(&registry, 2, hash).is_none());
    }

    #[test]
    fn wrong_bytecode_hash_is_not_a_match() {
        let hash = B256::repeat_byte(0xAB);
        let other_hash = B256::repeat_byte(0xCD);
        let registry = [sample(1, hash)];
        assert!(find_fingerprint(&registry, 1, other_hash).is_none());
    }
}
