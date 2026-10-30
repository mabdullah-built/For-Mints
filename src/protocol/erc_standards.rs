//! Independent, on-chain-only contract fingerprinting: ERC-165
//! `supportsInterface`, and EIP-1967 proxy implementation resolution.
//! Deliberately does not depend on any external explorer/ABI API -- see
//! `docs/generic-engine.md` for why that integration is out of scope this
//! pass. Every fact here is read directly from the chain and independently
//! checkable; nothing is inferred from a function *name*.

use alloy_primitives::{Address, B256};
use alloy_sol_types::{SolCall, sol};

use crate::chain::rpc::{RpcClient, RpcError};

sol! {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// `bytes4(keccak256("supportsInterface(bytes4)"))`-encoded ERC-721 and
/// ERC-1155 interface ids, per EIP-721/EIP-1155.
pub const ERC721_INTERFACE_ID: [u8; 4] = [0x80, 0xac, 0x58, 0xcd];
pub const ERC1155_INTERFACE_ID: [u8; 4] = [0xd9, 0xb6, 0x7a, 0x26];

/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`, the
/// EIP-1967 standard proxy implementation storage slot.
pub const EIP1967_IMPLEMENTATION_SLOT: B256 = B256::new([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);

/// Encode `supportsInterface(bytes4)` calldata for the given interface id.
pub fn encode_supports_interface(interface_id: [u8; 4]) -> alloy_primitives::Bytes {
    let call = supportsInterfaceCall {
        interfaceId: interface_id.into(),
    };
    call.abi_encode().into()
}

fn decode_supports_interface(data: &[u8]) -> Result<bool, RpcError> {
    // A conforming ERC-165 return is exactly one right-padded bool word.
    // A contract that doesn't implement ERC-165 at all typically reverts
    // (surfaced by the RPC layer as an error before this function is ever
    // called) or returns something that isn't 32 bytes ending in 0x00/0x01
    // -- treated as "does not support", never guessed as true.
    if data.len() != 32 {
        return Ok(false);
    }
    Ok(data[31] == 1 && data[..31].iter().all(|b| *b == 0))
}

/// Calls `supportsInterface(interfaceId)` and returns `Ok(bool)` for a
/// well-formed response, or `Ok(false)` (never an error) if the call
/// reverts or returns something malformed -- a contract that doesn't
/// implement ERC-165 at all behaves exactly like one that returns `false`,
/// which is the correct "not detected" outcome for fingerprinting.
pub async fn supports_interface(
    client: &RpcClient,
    contract: Address,
    interface_id: [u8; 4],
) -> Result<bool, RpcError> {
    let calldata = encode_supports_interface(interface_id);
    match client.eth_call(contract, &calldata).await {
        Ok(data) => decode_supports_interface(&data),
        Err(RpcError::RpcReturnedError { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Reads the EIP-1967 proxy implementation slot. Returns `None` when the
/// slot is all-zero (the overwhelmingly common "this is not a proxy, or is
/// a proxy pattern Kairox doesn't recognize" case) rather than an error --
/// most contracts are not EIP-1967 proxies, and that is not a failure.
pub async fn eip1967_implementation(
    client: &RpcClient,
    contract: Address,
) -> Result<Option<Address>, RpcError> {
    let slot_value = client
        .get_storage_at(contract, EIP1967_IMPLEMENTATION_SLOT)
        .await?;
    let bytes = slot_value.as_slice();
    // An address occupies the low 20 bytes of the 32-byte slot.
    if bytes[..12].iter().any(|b| *b != 0) {
        // Non-zero high bytes: not a plausible address-shaped value.
        return Ok(None);
    }
    let addr = Address::from_slice(&bytes[12..]);
    if addr.is_zero() {
        Ok(None)
    } else {
        Ok(Some(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_supports_interface_starts_with_the_correct_selector() {
        let calldata = encode_supports_interface(ERC721_INTERFACE_ID);
        assert_eq!(&calldata[0..4], supportsInterfaceCall::SELECTOR);
        assert_eq!(&calldata[4..8], &ERC721_INTERFACE_ID);
    }

    #[test]
    fn decode_supports_interface_true_word() {
        let mut word = [0u8; 32];
        word[31] = 1;
        assert!(decode_supports_interface(&word).unwrap());
    }

    #[test]
    fn decode_supports_interface_false_word() {
        let word = [0u8; 32];
        assert!(!decode_supports_interface(&word).unwrap());
    }

    #[test]
    fn decode_supports_interface_malformed_length_is_false_not_error() {
        assert!(!decode_supports_interface(&[0u8; 5]).unwrap());
    }

    #[test]
    fn decode_supports_interface_nonzero_high_bits_is_false() {
        let mut word = [0u8; 32];
        word[0] = 1;
        word[31] = 1;
        assert!(!decode_supports_interface(&word).unwrap());
    }

    #[test]
    fn eip1967_slot_constant_matches_the_documented_value() {
        // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
        let hash = alloy_primitives::keccak256(b"eip1967.proxy.implementation");
        let expected =
            alloy_primitives::U256::from_be_bytes(hash.0) - alloy_primitives::U256::from(1);
        assert_eq!(
            EIP1967_IMPLEMENTATION_SLOT,
            B256::from(expected.to_be_bytes())
        );
    }
}
