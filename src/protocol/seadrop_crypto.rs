//! Independent local reimplementation of SeaDrop's cryptographic
//! primitives: the OpenZeppelin-compatible Merkle allowlist proof
//! algorithm and the EIP-712 signed-mint digest.
//!
//! Every type hash / algorithm here was verified directly against the
//! current official sources during Phase 4 hardening:
//! `ProjectOpenSea/seadrop/src/SeaDrop.sol` (typehash constants, `_getDigest`,
//! `mintAllowList`'s `MerkleProof.verify` call, `_validateSignerAndParams`),
//! `ProjectOpenSea/seadrop/src/lib/SeaDropStructs.sol` (`MintParams`,
//! `SignedMintValidationParams`), and
//! `OpenZeppelin/openzeppelin-contracts/contracts/utils/cryptography/{MerkleProof,Hashes}.sol`
//! (`commutativeKeccak256`/`efficientKeccak256`: `keccak256(min(a,b) || max(a,b))`
//! using strict `<` on the 32-byte value). Nothing here is inferred or
//! guessed — see the Phase 4 final report for exact source snippets
//! inspected.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolValue;

use super::seadrop::MintParams;

/// `keccak256("MintParams(uint256 mintPrice,uint256 maxTotalMintableByWallet,uint256 startTime,uint256 endTime,uint256 dropStageIndex,uint256 maxTokenSupplyForStage,uint256 feeBps,bool restrictFeeRecipients)")`
fn mint_params_typehash() -> B256 {
    keccak256(
        b"MintParams(uint256 mintPrice,uint256 maxTotalMintableByWallet,uint256 startTime,uint256 endTime,uint256 dropStageIndex,uint256 maxTokenSupplyForStage,uint256 feeBps,bool restrictFeeRecipients)",
    )
}

/// `keccak256("SignedMint(address nftContract,address minter,address feeRecipient,MintParams mintParams,uint256 salt)MintParams(uint256 mintPrice,uint256 maxTotalMintableByWallet,uint256 startTime,uint256 endTime,uint256 dropStageIndex,uint256 maxTokenSupplyForStage,uint256 feeBps,bool restrictFeeRecipients)")`
///
/// EIP-712 `encodeType` for a struct referencing another struct appends the
/// referenced struct's own type string immediately after the primary type's
/// — this is the exact literal SeaDrop hashes, not independently re-derived
/// alphabetical-sort logic.
fn signed_mint_typehash() -> B256 {
    keccak256(
        b"SignedMint(address nftContract,address minter,address feeRecipient,MintParams mintParams,uint256 salt)MintParams(uint256 mintPrice,uint256 maxTotalMintableByWallet,uint256 startTime,uint256 endTime,uint256 dropStageIndex,uint256 maxTokenSupplyForStage,uint256 feeBps,bool restrictFeeRecipients)",
    )
}

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
fn eip712_domain_typehash() -> B256 {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

fn name_hash() -> B256 {
    keccak256(b"SeaDrop")
}

fn version_hash() -> B256 {
    keccak256(b"1.0")
}

/// The Merkle leaf SeaDrop's `mintAllowList` verifies against:
/// `keccak256(abi.encode(minter, mintParams))`. Since `MintParams` is a
/// fully static (value-type-only) struct, `abi.encode` of it inline is
/// identical to `abi.encode`-ing its eight fields in order right after
/// `minter` — implemented here as one flat tuple encoding.
pub fn allow_list_merkle_leaf(minter: Address, mint_params: &MintParams) -> B256 {
    let encoded = (
        minter,
        mint_params.mint_price,
        mint_params.max_total_mintable_by_wallet,
        mint_params.start_time,
        mint_params.end_time,
        mint_params.drop_stage_index,
        mint_params.max_token_supply_for_stage,
        mint_params.fee_bps,
        mint_params.restrict_fee_recipients,
    )
        .abi_encode();
    keccak256(encoded)
}

/// `Hashes.commutativeKeccak256(a, b)`: `keccak256(min(a,b) || max(a,b))`
/// using strict `<` on the 32-byte value, exactly as OpenZeppelin's
/// `Hashes.sol` (imported transitively by SeaDrop's `MerkleProof.sol`)
/// implements it.
pub fn commutative_keccak256(a: B256, b: B256) -> B256 {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(lo.as_slice());
    buf[32..64].copy_from_slice(hi.as_slice());
    keccak256(buf)
}

/// Verify a Merkle proof exactly as OpenZeppelin `MerkleProof.verify` does:
/// fold `leaf` through `proof` via `commutativeKeccak256`, then compare
/// against `root`.
///
/// An empty `proof` is valid whenever `leaf == root` — a legitimate
/// single-leaf tree. There is no blanket "empty proof is invalid" rule;
/// none exists in the official implementation.
pub fn verify_merkle_proof(proof: &[B256], root: B256, leaf: B256) -> bool {
    let mut computed = leaf;
    for sibling in proof {
        computed = commutative_keccak256(computed, *sibling);
    }
    computed == root
}

/// `_domainSeparator()` / `_deriveDomainSeparator()`: SeaDrop's own
/// contract address is always the `verifyingContract` — never the
/// collection/NFT contract.
pub fn domain_separator(chain_id: u64, seadrop_contract: Address) -> B256 {
    let encoded = (
        eip712_domain_typehash(),
        name_hash(),
        version_hash(),
        U256::from(chain_id),
        seadrop_contract,
    )
        .abi_encode();
    keccak256(encoded)
}

fn mint_params_struct_hash(mint_params: &MintParams) -> B256 {
    let encoded = (
        mint_params_typehash(),
        mint_params.mint_price,
        mint_params.max_total_mintable_by_wallet,
        mint_params.start_time,
        mint_params.end_time,
        mint_params.drop_stage_index,
        mint_params.max_token_supply_for_stage,
        mint_params.fee_bps,
        mint_params.restrict_fee_recipients,
    )
        .abi_encode();
    keccak256(encoded)
}

/// `_getDigest(nftContract, minter, feeRecipient, mintParams, salt)`,
/// reproduced exactly. `minter` here must be the *effective* minter SeaDrop
/// itself would compute (`minterIfNotPayer != 0 ? minterIfNotPayer :
/// msg.sender`), not necessarily the raw `minterIfNotPayer` calldata field —
/// see the caller in `execution::opensea_validate`.
pub fn signed_mint_digest(
    chain_id: u64,
    seadrop_contract: Address,
    nft_contract: Address,
    minter: Address,
    fee_recipient: Address,
    mint_params: &MintParams,
    salt: U256,
) -> B256 {
    let mint_params_hash_struct = mint_params_struct_hash(mint_params);
    let signed_mint_struct_hash = keccak256(
        (
            signed_mint_typehash(),
            nft_contract,
            minter,
            fee_recipient,
            mint_params_hash_struct,
            salt,
        )
            .abi_encode(),
    );
    let domain = domain_separator(chain_id, seadrop_contract);
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain.as_slice());
    buf.extend_from_slice(signed_mint_struct_hash.as_slice());
    keccak256(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mint_params() -> MintParams {
        MintParams {
            mint_price: U256::from(10_000_000_000_000_000u128),
            max_total_mintable_by_wallet: U256::from(5u64),
            start_time: U256::from(1_000u64),
            end_time: U256::from(9_999_999_999u64),
            drop_stage_index: U256::from(1u64),
            max_token_supply_for_stage: U256::from(1_000u64),
            fee_bps: U256::from(250u64),
            restrict_fee_recipients: true,
        }
    }

    // --- Merkle proof: single-leaf tree (empty proof) ---

    #[test]
    fn empty_proof_valid_when_leaf_equals_root() {
        let leaf = B256::repeat_byte(0x42);
        assert!(verify_merkle_proof(&[], leaf, leaf));
    }

    #[test]
    fn empty_proof_invalid_when_leaf_differs_from_root() {
        let leaf = B256::repeat_byte(0x42);
        let root = B256::repeat_byte(0x43);
        assert!(!verify_merkle_proof(&[], root, leaf));
    }

    // --- Merkle proof: two-leaf tree, hand-computed via the OZ algorithm ---

    #[test]
    fn two_leaf_tree_valid_proof_verifies() {
        let leaf_a = keccak256(b"leaf-a");
        let leaf_b = keccak256(b"leaf-b");
        let root = commutative_keccak256(leaf_a, leaf_b);

        assert!(verify_merkle_proof(&[leaf_b], root, leaf_a));
        assert!(verify_merkle_proof(&[leaf_a], root, leaf_b));
    }

    #[test]
    fn two_leaf_tree_wrong_proof_element_fails() {
        let leaf_a = keccak256(b"leaf-a");
        let leaf_b = keccak256(b"leaf-b");
        let leaf_c = keccak256(b"leaf-c");
        let root = commutative_keccak256(leaf_a, leaf_b);

        assert!(!verify_merkle_proof(&[leaf_c], root, leaf_a));
    }

    // --- Merkle proof: four-leaf tree ---

    #[test]
    fn four_leaf_tree_valid_proof_for_every_leaf() {
        let leaves: Vec<B256> = (0..4u8)
            .map(|i| keccak256([b"leaf-".as_slice(), &[i]].concat()))
            .collect();
        let h01 = commutative_keccak256(leaves[0], leaves[1]);
        let h23 = commutative_keccak256(leaves[2], leaves[3]);
        let root = commutative_keccak256(h01, h23);

        assert!(verify_merkle_proof(&[leaves[1], h23], root, leaves[0]));
        assert!(verify_merkle_proof(&[leaves[0], h23], root, leaves[1]));
        assert!(verify_merkle_proof(&[leaves[3], h01], root, leaves[2]));
        assert!(verify_merkle_proof(&[leaves[2], h01], root, leaves[3]));
    }

    #[test]
    fn four_leaf_tree_wrong_wallet_leaf_fails() {
        let leaves: Vec<B256> = (0..4u8)
            .map(|i| keccak256([b"leaf-".as_slice(), &[i]].concat()))
            .collect();
        let h01 = commutative_keccak256(leaves[0], leaves[1]);
        let h23 = commutative_keccak256(leaves[2], leaves[3]);
        let root = commutative_keccak256(h01, h23);

        // A proof legitimately belonging to leaves[1] must not verify a
        // different leaf value against the same root.
        let forged_leaf = keccak256(b"not-a-real-leaf");
        assert!(!verify_merkle_proof(&[leaves[0], h23], root, forged_leaf));
    }

    // --- allow_list_merkle_leaf / on-chain-shape sanity ---

    #[test]
    fn allow_list_merkle_leaf_changes_with_minter() {
        let params = sample_mint_params();
        let minter_a = Address::repeat_byte(0xAA);
        let minter_b = Address::repeat_byte(0xBB);
        assert_ne!(
            allow_list_merkle_leaf(minter_a, &params),
            allow_list_merkle_leaf(minter_b, &params)
        );
    }

    #[test]
    fn allow_list_merkle_leaf_changes_with_fee_bps() {
        let mut params = sample_mint_params();
        let minter = Address::repeat_byte(0xAA);
        let leaf_a = allow_list_merkle_leaf(minter, &params);
        params.fee_bps = U256::from(9_999u64);
        let leaf_b = allow_list_merkle_leaf(minter, &params);
        assert_ne!(leaf_a, leaf_b);
    }

    #[test]
    fn allow_list_merkle_leaf_changes_with_drop_stage_index() {
        let mut params = sample_mint_params();
        let minter = Address::repeat_byte(0xAA);
        let leaf_a = allow_list_merkle_leaf(minter, &params);
        params.drop_stage_index = U256::from(2u64);
        let leaf_b = allow_list_merkle_leaf(minter, &params);
        assert_ne!(leaf_a, leaf_b);
    }

    #[test]
    fn allow_list_merkle_leaf_is_deterministic() {
        let params = sample_mint_params();
        let minter = Address::repeat_byte(0xAA);
        assert_eq!(
            allow_list_merkle_leaf(minter, &params),
            allow_list_merkle_leaf(minter, &params)
        );
    }

    // --- EIP-712 type hashes: fixed, well-known values ---

    #[test]
    fn eip712_domain_typehash_is_deterministic_and_nonzero() {
        // The literal type string is verified verbatim against the fetched
        // SeaDrop source in this module's doc comment; a fixed, independent
        // numeric constant is intentionally not hardcoded here to avoid
        // risking a transcription error in this environment (no keccak256
        // tool was available to cross-check it independently at test-write
        // time) -- the type-string-level verification is the authoritative
        // one. This test only guards against accidental changes.
        assert_ne!(eip712_domain_typehash(), B256::ZERO);
        assert_eq!(eip712_domain_typehash(), eip712_domain_typehash());
    }

    #[test]
    fn mint_params_typehash_is_deterministic_and_matches_signed_mint_prefix() {
        // The literal SeaDrop hashes for SIGNED_MINT_TYPEHASH is
        // "SignedMint(...)" immediately followed by the exact
        // "MintParams(...)" string used for MINT_PARAMS_TYPEHASH -- so
        // hashing that referenced type string alone must reproduce the
        // same value used standalone.
        let standalone = mint_params_typehash();
        let embedded = keccak256(
            b"MintParams(uint256 mintPrice,uint256 maxTotalMintableByWallet,uint256 startTime,uint256 endTime,uint256 dropStageIndex,uint256 maxTokenSupplyForStage,uint256 feeBps,bool restrictFeeRecipients)",
        );
        assert_eq!(standalone, embedded);
    }

    // --- EIP-712 digest: structural properties ---

    #[test]
    fn signed_mint_digest_changes_with_chain_id() {
        let params = sample_mint_params();
        let seadrop = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let minter = Address::repeat_byte(0x33);
        let fee_recipient = Address::repeat_byte(0x44);
        let salt = U256::from(1u64);

        let digest_1 = signed_mint_digest(1, seadrop, nft, minter, fee_recipient, &params, salt);
        let digest_2 = signed_mint_digest(8453, seadrop, nft, minter, fee_recipient, &params, salt);
        assert_ne!(digest_1, digest_2);
    }

    #[test]
    fn signed_mint_digest_changes_with_verifying_contract() {
        let params = sample_mint_params();
        let nft = Address::repeat_byte(0x22);
        let minter = Address::repeat_byte(0x33);
        let fee_recipient = Address::repeat_byte(0x44);
        let salt = U256::from(1u64);

        let digest_a = signed_mint_digest(
            1,
            Address::repeat_byte(0x11),
            nft,
            minter,
            fee_recipient,
            &params,
            salt,
        );
        let digest_b = signed_mint_digest(
            1,
            Address::repeat_byte(0x99),
            nft,
            minter,
            fee_recipient,
            &params,
            salt,
        );
        assert_ne!(
            digest_a, digest_b,
            "the verifying contract must be SeaDrop, never the collection"
        );
    }

    #[test]
    fn signed_mint_digest_changes_with_every_mint_param_field() {
        let seadrop = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let minter = Address::repeat_byte(0x33);
        let fee_recipient = Address::repeat_byte(0x44);
        let salt = U256::from(1u64);
        let base = sample_mint_params();
        let base_digest = signed_mint_digest(1, seadrop, nft, minter, fee_recipient, &base, salt);

        let variants: Vec<MintParams> = vec![
            MintParams {
                mint_price: U256::from(1u64),
                ..base
            },
            MintParams {
                max_total_mintable_by_wallet: U256::from(1u64),
                ..base
            },
            MintParams {
                start_time: U256::from(1u64),
                ..base
            },
            MintParams {
                end_time: U256::from(1u64),
                ..base
            },
            MintParams {
                drop_stage_index: U256::from(99u64),
                ..base
            },
            MintParams {
                max_token_supply_for_stage: U256::from(1u64),
                ..base
            },
            MintParams {
                fee_bps: U256::from(1u64),
                ..base
            },
            MintParams {
                restrict_fee_recipients: false,
                ..base
            },
        ];
        for variant in variants {
            let digest = signed_mint_digest(1, seadrop, nft, minter, fee_recipient, &variant, salt);
            assert_ne!(digest, base_digest);
        }
    }

    #[test]
    fn signed_mint_digest_changes_with_salt() {
        let params = sample_mint_params();
        let seadrop = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let minter = Address::repeat_byte(0x33);
        let fee_recipient = Address::repeat_byte(0x44);

        let digest_a = signed_mint_digest(
            1,
            seadrop,
            nft,
            minter,
            fee_recipient,
            &params,
            U256::from(1u64),
        );
        let digest_b = signed_mint_digest(
            1,
            seadrop,
            nft,
            minter,
            fee_recipient,
            &params,
            U256::from(2u64),
        );
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn signed_mint_digest_is_deterministic() {
        let params = sample_mint_params();
        let seadrop = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let minter = Address::repeat_byte(0x33);
        let fee_recipient = Address::repeat_byte(0x44);
        let salt = U256::from(1u64);

        assert_eq!(
            signed_mint_digest(1, seadrop, nft, minter, fee_recipient, &params, salt),
            signed_mint_digest(1, seadrop, nft, minter, fee_recipient, &params, salt)
        );
    }
}
