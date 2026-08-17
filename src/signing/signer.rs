//! Signing abstraction. [`LocalSigner`] is an in-memory signer built from
//! raw key bytes, loaded only from `KAIROX_SIGNING_KEY` or an interactive
//! prompt (see [`crate::signing::keystore`]), and used by the live
//! pre-signing pipeline to sign a candidate transaction ahead of a mint
//! window before broadcast.

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

/// Recover an Ethereum address from an arbitrary 32-byte prehash digest and
/// a standard 65-byte `r || s || v` signature — the general form needed to
/// verify a signature over something other than an
/// [`UnsignedEip1559Tx`] (e.g. an EIP-712 digest). Accepts both the `v ∈
/// {0, 1}` and legacy `v ∈ {27, 28}` recovery-byte conventions.
///
/// Uses `k256`'s own (well-tested) ECDSA recovery — never a hand-rolled
/// secp256k1 implementation.
pub fn recover_from_prehash(
    digest: alloy_primitives::B256,
    signature: &[u8],
) -> Result<Address, SigningError> {
    if signature.len() != 65 {
        return Err(SigningError::SignFailed);
    }
    let v = signature[64];
    let y_parity = match v {
        0 | 1 => v == 1,
        27 | 28 => v == 28,
        _ => return Err(SigningError::SignFailed),
    };
    let recovery_id = k256::ecdsa::RecoveryId::new(y_parity, false);
    let sig = k256::ecdsa::Signature::from_slice(&signature[0..64])
        .map_err(|_| SigningError::SignFailed)?;
    let verifying_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recovery_id)
            .map_err(|_| SigningError::SignFailed)?;

    let encoded = verifying_key.to_sec1_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let address = Address::from_slice(&hash[12..32]);
    if address == Address::ZERO {
        return Err(SigningError::SignFailed);
    }
    Ok(address)
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

    fn sign_arbitrary_digest(signer: &LocalSigner, digest: alloy_primitives::B256) -> [u8; 65] {
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = signer
            .key
            .sign_prehash(digest.as_slice())
            .expect("sign_prehash never fails for a valid digest");
        let mut out = [0u8; 65];
        out[0..64].copy_from_slice(&signature.to_bytes());
        out[64] = if recovery_id.is_y_odd() { 1 } else { 0 };
        out
    }

    #[test]
    fn recover_from_prehash_recovers_the_correct_signer() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let digest = keccak256(b"arbitrary eip-712 digest");
        let signature = sign_arbitrary_digest(&signer, digest);

        let recovered = recover_from_prehash(digest, &signature).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn recover_from_prehash_accepts_legacy_v_27_28_convention() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let digest = keccak256(b"legacy-v-convention digest");
        let mut signature = sign_arbitrary_digest(&signer, digest);
        signature[64] += 27;

        let recovered = recover_from_prehash(digest, &signature).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn recover_from_prehash_rejects_wrong_length_signature() {
        let digest = keccak256(b"digest");
        let err = recover_from_prehash(digest, &[0u8; 64]).unwrap_err();
        assert!(matches!(err, SigningError::SignFailed));
    }

    #[test]
    fn recover_from_prehash_rejects_invalid_recovery_byte() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let digest = keccak256(b"digest");
        let mut signature = sign_arbitrary_digest(&signer, digest);
        signature[64] = 99;

        let err = recover_from_prehash(digest, &signature).unwrap_err();
        assert!(matches!(err, SigningError::SignFailed));
    }

    #[test]
    fn recover_from_prehash_mutated_signature_recovers_a_different_address() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let digest = keccak256(b"digest");
        let mut signature = sign_arbitrary_digest(&signer, digest);
        signature[0] ^= 0xff;

        // A one-byte mutation either fails recovery outright or recovers to
        // a different (garbage) address -- either way it must never
        // recover to the real signer.
        if let Ok(addr) = recover_from_prehash(digest, &signature) {
            assert_ne!(addr, signer.address());
        }
    }

    #[test]
    fn recover_from_prehash_wrong_digest_recovers_a_different_address() {
        let signer = LocalSigner::from_bytes(test_key_bytes()).unwrap();
        let digest = keccak256(b"original digest");
        let signature = sign_arbitrary_digest(&signer, digest);

        let wrong_digest = keccak256(b"a different digest entirely");
        if let Ok(addr) = recover_from_prehash(wrong_digest, &signature) {
            assert_ne!(addr, signer.address());
        }
    }
}
