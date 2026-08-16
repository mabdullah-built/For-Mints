//! Signing abstraction. Phase 1 exposes only [`LocalSigner`], an in-memory
//! signer built from raw key bytes, and never wires a real private key into
//! the CLI. Its purpose in this phase is architectural: Phase 2's
//! pre-signing pipeline will hold a `Signer` per wallet and sign candidate
//! transactions ahead of a mint window — no broadcast path exists yet.

use std::fmt;

use alloy_primitives::{Address, keccak256};
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use thiserror::Error;
use zeroize::Zeroize;

use super::transaction::{Eip1559Signature, SignedEip1559Tx, UnsignedEip1559Tx};

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid private key bytes")]
    InvalidKeyBytes,
    #[error("signing operation failed")]
    SignFailed,
}

/// Anything capable of signing a Kairox-constructed EIP-1559 transaction.
/// Implementations must never expose their key material through `Debug` or
/// any other trait.
pub trait Signer {
    fn address(&self) -> Address;
    fn sign_transaction(&self, tx: UnsignedEip1559Tx) -> Result<SignedEip1559Tx, SigningError>;
}

/// An in-memory ECDSA signer. Holds a `k256::ecdsa::SigningKey`, which
/// zeroizes its internal scalar on drop (a RustCrypto/`elliptic-curve`
/// guarantee). Kairox additionally zeroizes any raw key-byte buffer it
/// handles directly during construction.
pub struct LocalSigner {
    key: SigningKey,
    address: Address,
}

impl LocalSigner {
    /// Construct a signer from a raw 32-byte secret. The input buffer is
    /// zeroized before returning, regardless of success or failure.
    ///
    /// Deterministic/fixed key bytes should only ever originate from tests
    /// or (in a later phase) an explicit, user-controlled key-loading path —
    /// never from a hardcoded or persisted value in Kairox itself.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, SigningError> {
        let result =
            SigningKey::from_bytes((&bytes).into()).map_err(|_| SigningError::InvalidKeyBytes);
        bytes.zeroize();
        let key = result?;
        let address = address_from_signing_key(&key);
        Ok(Self { key, address })
    }
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("address", &self.address)
            .field("key", &"<redacted>")
            .finish()
    }
}

fn address_from_signing_key(key: &SigningKey) -> Address {
    let verifying_key = key.verifying_key();
    let encoded = verifying_key.to_sec1_point(false);
    // Uncompressed point is 0x04 || X (32 bytes) || Y (32 bytes); Ethereum
    // addresses are the low 20 bytes of keccak256(X || Y).
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Address::from_slice(&hash[12..32])
}

impl Signer for LocalSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn sign_transaction(&self, tx: UnsignedEip1559Tx) -> Result<SignedEip1559Tx, SigningError> {
        let hash = tx.signing_hash();
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = self
            .key
            .sign_prehash(hash.as_slice())
            .map_err(|_| SigningError::SignFailed)?;

        let r = alloy_primitives::U256::from_be_slice(&signature.r().to_bytes());
        let s = alloy_primitives::U256::from_be_slice(&signature.s().to_bytes());

        Ok(SignedEip1559Tx {
            unsigned: tx,
            signature: Eip1559Signature {
                y_parity: recovery_id.is_y_odd(),
                r,
                s,
            },
        })
    }
}

/// Recover the signer address from an [`UnsignedEip1559Tx`] and its
/// [`Eip1559Signature`]. Exposed primarily so tests (and, later, a
/// pre-broadcast self-check) can independently verify that a produced
/// signature actually recovers to the expected wallet.
pub fn recover_signer(
    tx: &UnsignedEip1559Tx,
    signature: &Eip1559Signature,
) -> Result<Address, SigningError> {
    let hash = tx.signing_hash();
    let recovery_id = k256::ecdsa::RecoveryId::new(signature.y_parity, false);

    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(&signature.r.to_be_bytes::<32>());
    sig_bytes[32..64].copy_from_slice(&signature.s.to_be_bytes::<32>());
    let sig =
        k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| SigningError::SignFailed)?;

    let verifying_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(hash.as_slice(), &sig, recovery_id)
            .map_err(|_| SigningError::SignFailed)?;

    let encoded = verifying_key.to_sec1_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    Ok(Address::from_slice(&hash[12..32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::transaction::AccessListItem;
    use alloy_primitives::{Bytes, U256, address};

    /// A fixed, non-secret 32-byte test vector (`keccak256(b"kairox-phase1-test-key")`).
    /// This is a deterministic test key only; it must never be used to hold
    /// real funds and is documented as such everywhere it appears.
    fn test_key_bytes() -> [u8; 32] {
        keccak256(b"kairox-phase1-test-key").0
    }

    fn sample_tx() -> UnsignedEip1559Tx {
        UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 250_000,
            to: address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5"),
            value: U256::ZERO,
            data: Bytes::new(),
            access_list: Vec::<AccessListItem>::new(),
        }
    }

    #[test]
    fn local_signer_debug_never_contains_key_bytes() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let debug = format!("{signer:?}");
        assert!(!debug.contains(&hex::encode(test_key_bytes())));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn sign_transaction_recovers_to_signer_address() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let tx = sample_tx();
        let signed = signer.sign_transaction(tx.clone()).unwrap();

        let recovered = recover_signer(&tx, &signed.signature).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn different_keys_produce_different_addresses_and_signatures() {
        let signer_a = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let mut other_bytes = test_key_bytes();
        other_bytes[0] ^= 0xff;
        let signer_b = LocalSigner::from_bytes(other_bytes).unwrap();

        assert_ne!(signer_a.address(), signer_b.address());

        let tx = sample_tx();
        let sig_a = signer_a.sign_transaction(tx.clone()).unwrap();
        let sig_b = signer_b.sign_transaction(tx).unwrap();
        assert_ne!(sig_a.signature.r, sig_b.signature.r);
    }

    #[test]
    fn signature_changes_when_transaction_changes() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let mut tx = sample_tx();
        let sig_a = signer.sign_transaction(tx.clone()).unwrap();
        tx.nonce += 1;
        let sig_b = signer.sign_transaction(tx).unwrap();
        assert_ne!(sig_a.signature.r, sig_b.signature.r);
    }

    #[test]
    fn rejects_all_zero_key_bytes() {
        let err = LocalSigner::from_bytes([0u8; 32]).unwrap_err();
        assert!(matches!(err, SigningError::InvalidKeyBytes));
    }
}
