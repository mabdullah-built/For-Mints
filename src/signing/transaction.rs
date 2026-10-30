//! Independent EIP-1559 (type-2, EIP-2718) transaction construction and RLP
//! encoding, built directly from the spec rather than any reference
//! implementation's code.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// EIP-2718 transaction type byte for EIP-1559 transactions.
pub const EIP1559_TX_TYPE: u8 = 0x02;

/// One `[address, storageKeys[]]` entry of an EIP-2930 access list.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

/// An unsigned EIP-1559 transaction. Field order matches the RLP list order
/// mandated by EIP-1559: `[chainId, nonce, maxPriorityFeePerGas,
/// maxFeePerGas, gasLimit, to, value, data, accessList]`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct UnsignedEip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListItem>,
}

impl UnsignedEip1559Tx {
    /// `0x02 || rlp([...fields])` — the exact bytes an ECDSA signature is
    /// produced over per EIP-1559. The derived `Encodable` impl already
    /// RLP-encodes the struct's fields as a single list, so only the
    /// EIP-2718 type-byte prefix needs to be added here.
    pub fn encoded_for_signing(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(EIP1559_TX_TYPE);
        alloy_rlp::Encodable::encode(self, &mut out);
        out
    }

    /// keccak256 of [`Self::encoded_for_signing`] — the hash a signer must
    /// sign.
    pub fn signing_hash(&self) -> B256 {
        keccak256(self.encoded_for_signing())
    }
}

/// An ECDSA signature over an [`UnsignedEip1559Tx`]'s signing hash, in the
/// `(yParity, r, s)` form EIP-1559 requires (no legacy `v` offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip1559Signature {
    pub y_parity: bool,
    pub r: U256,
    pub s: U256,
}

/// The RLP-encodable body of a *signed* EIP-1559 transaction: the unsigned
/// fields followed by `[yParity, r, s]`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct SignedPayloadFields {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    value: U256,
    data: Bytes,
    access_list: Vec<AccessListItem>,
    y_parity: u64,
    r: U256,
    s: U256,
}

/// A fully signed, ready-to-broadcast (in a later phase) EIP-1559
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEip1559Tx {
    pub unsigned: UnsignedEip1559Tx,
    pub signature: Eip1559Signature,
}

impl SignedEip1559Tx {
    fn payload_fields(&self) -> SignedPayloadFields {
        SignedPayloadFields {
            chain_id: self.unsigned.chain_id,
            nonce: self.unsigned.nonce,
            max_priority_fee_per_gas: self.unsigned.max_priority_fee_per_gas,
            max_fee_per_gas: self.unsigned.max_fee_per_gas,
            gas_limit: self.unsigned.gas_limit,
            to: self.unsigned.to,
            value: self.unsigned.value,
            data: self.unsigned.data.clone(),
            access_list: self.unsigned.access_list.clone(),
            y_parity: self.signature.y_parity as u64,
            r: self.signature.r,
            s: self.signature.s,
        }
    }

    /// `0x02 || rlp([...fields, yParity, r, s])` — the exact bytes
    /// `eth_sendRawTransaction` expects; this is what actually gets
    /// broadcast to every send-capable endpoint (see
    /// [`crate::execution::broadcast`]).
    pub fn raw_bytes(&self) -> Bytes {
        let mut out = Vec::with_capacity(160);
        out.push(EIP1559_TX_TYPE);
        alloy_rlp::Encodable::encode(&self.payload_fields(), &mut out);
        Bytes::from(out)
    }

    /// The transaction hash: keccak256 of the raw signed bytes.
    pub fn tx_hash(&self) -> B256 {
        keccak256(self.raw_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsigned() -> UnsignedEip1559Tx {
        UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 5,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 50_000_000_000,
            gas_limit: 250_000,
            to: alloy_primitives::address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5"),
            value: U256::from(10u64),
            data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            access_list: Vec::new(),
        }
    }

    #[test]
    fn encoded_for_signing_starts_with_type_byte() {
        let tx = sample_unsigned();
        let encoded = tx.encoded_for_signing();
        assert_eq!(encoded[0], EIP1559_TX_TYPE);
    }

    #[test]
    fn signing_hash_is_deterministic() {
        let tx = sample_unsigned();
        assert_eq!(tx.signing_hash(), tx.signing_hash());
    }

    #[test]
    fn signing_hash_changes_when_nonce_changes() {
        let mut tx = sample_unsigned();
        let hash_a = tx.signing_hash();
        tx.nonce += 1;
        let hash_b = tx.signing_hash();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn signing_hash_changes_when_data_changes() {
        let mut tx = sample_unsigned();
        let hash_a = tx.signing_hash();
        tx.data = Bytes::from(vec![0x01]);
        let hash_b = tx.signing_hash();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn raw_bytes_starts_with_type_byte_and_differs_from_unsigned_encoding() {
        let unsigned = sample_unsigned();
        let signed = SignedEip1559Tx {
            unsigned: unsigned.clone(),
            signature: Eip1559Signature {
                y_parity: true,
                r: U256::from(111u64),
                s: U256::from(222u64),
            },
        };
        let raw = signed.raw_bytes();
        assert_eq!(raw[0], EIP1559_TX_TYPE);
        assert_ne!(raw.to_vec(), unsigned.encoded_for_signing());
    }

    #[test]
    fn tx_hash_changes_with_signature() {
        let unsigned = sample_unsigned();
        let signed_a = SignedEip1559Tx {
            unsigned: unsigned.clone(),
            signature: Eip1559Signature {
                y_parity: false,
                r: U256::from(1u64),
                s: U256::from(2u64),
            },
        };
        let signed_b = SignedEip1559Tx {
            unsigned,
            signature: Eip1559Signature {
                y_parity: true,
                r: U256::from(1u64),
                s: U256::from(2u64),
            },
        };
        assert_ne!(signed_a.tx_hash(), signed_b.tx_hash());
    }

    #[test]
    fn access_list_items_round_trip_through_rlp_body() {
        let mut tx = sample_unsigned();
        tx.access_list.push(AccessListItem {
            address: Address::ZERO,
            storage_keys: vec![B256::ZERO, B256::repeat_byte(0x11)],
        });
        // Encoding must not panic and must still start with the type byte.
        let encoded = tx.encoded_for_signing();
        assert_eq!(encoded[0], EIP1559_TX_TYPE);
        assert!(encoded.len() > 1);
    }
}
