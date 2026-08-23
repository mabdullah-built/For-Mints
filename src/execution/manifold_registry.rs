//! The trusted Manifold `LazyPayableClaim` extension-fingerprint registry.
//!
//! Mirrors [`super::thirdweb_registry`]'s exact model and rationale --
//! selector compatibility and a successful `eth_call` are not evidence
//! that a given address runs unmodified Manifold extension semantics.
//! This is the *only* route to authorizing a real (non-rehearsal,
//! non-dry-run) live send through the Manifold engine -- see
//! `execution::manifold_engine::establish_provenance`.
//!
//! **Genuinely different provenance model from thirdweb's**: a Manifold
//! `LazyPayableClaim` extension is not deployed per-collection behind a
//! proxy -- it is a shared, non-upgradeable singleton contract (typically
//! one canonical deployment per chain, registered as an approved
//! extension on many different creator contracts). There is no
//! per-collection implementation to resolve via EIP-1167/EIP-1967; an
//! entry here hashes the extension contract's *own* runtime bytecode
//! directly, at the address the operator supplies as `--manifold-extension`.
//!
//! [`BUILTIN_REGISTRY`] ships **empty**, for the same reason
//! `thirdweb_registry::BUILTIN_REGISTRY` does: no extension deployment has
//! been manually reviewed and registered as part of this pass. Dry-run
//! (`kairox mint --engine manifold`, no `--send`/`--rehearsal`) is
//! unaffected.

use alloy_primitives::B256;

use crate::chain::registry::ChainId;

/// One manually-reviewed, trusted Manifold `LazyPayableClaim` extension
/// deployment, bound to an exact runtime bytecode hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifoldTrustedFingerprint {
    /// Human-readable label, shown in resolution evidence and reports --
    /// never used for matching.
    pub name: &'static str,
    pub chain_id: ChainId,
    /// `keccak256` of the extension contract's own runtime bytecode (no
    /// proxy resolution -- see this module's doc comment).
    pub extension_bytecode_hash: B256,
}

/// The built-in trusted registry. Empty by design -- see module docs.
pub const BUILTIN_REGISTRY: &[ManifoldTrustedFingerprint] = &[];

/// Find a registry entry matching `chain_id` and `bytecode_hash` exactly.
/// No partial/selector-only matching, mirroring
/// `thirdweb_registry::find_fingerprint`'s identical design.
pub fn find_fingerprint(
    registry: &[ManifoldTrustedFingerprint],
    chain_id: ChainId,
    bytecode_hash: B256,
) -> Option<ManifoldTrustedFingerprint> {
    registry
        .iter()
        .find(|f| f.chain_id == chain_id && f.extension_bytecode_hash == bytecode_hash)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(chain_id: ChainId, hash: B256) -> ManifoldTrustedFingerprint {
        ManifoldTrustedFingerprint {
            name: "test-fixture",
            chain_id,
            extension_bytecode_hash: hash,
        }
    }

    #[test]
    fn builtin_registry_ships_empty() {
        assert!(
            BUILTIN_REGISTRY.is_empty(),
            "no extension deployment has been manually reviewed and registered in this pass -- \
             see module docs"
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
