//! OP Stack `GasPriceOracle` predeploy bindings -- verified directly
//! against `ethereum-optimism/optimism`'s
//! `packages/contracts-bedrock/src/L2/GasPriceOracle.sol` (source read in
//! full this pass, not assumed from an older formula version).
//!
//! **Fork-gated behavior, read live every time, never cached as a chain
//! constant:**
//!
//! - `getL1Fee(bytes)`/`getL1FeeUpperBound(uint256)` (the L1 data/
//!   security-publication fee): dispatches internally on `isFjord`/
//!   `isEcotone` -- `getL1FeeUpperBound` additionally `require`s
//!   `isFjord` and is the gas-efficient, pre-signing-safe upper bound the
//!   Fjord upgrade added specifically for this use case (an exact
//!   `getL1Fee(bytes)` call is also available but costs more gas and
//!   needs the *signed* transaction bytes it cannot have yet before
//!   signing -- `getL1FeeUpperBound` takes only the *unsigned* encoded
//!   size, which Kairox already knows before signing).
//! - `getOperatorFee(uint256)` (a **third**, separate mandatory fee
//!   component, easy to miss if only L2 execution + L1 data fee are
//!   considered): `0` before the Isthmus upgrade; after Isthmus,
//!   `(gasUsed * operatorFeeScalar / 1e6) + operatorFeeConstant`; after
//!   Jovian, the formula itself changes to
//!   `gasUsed * operatorFeeScalar * 100 + operatorFeeConstant`. Both
//!   `operatorFeeScalar`/`operatorFeeConstant` are live, operator-
//!   controlled `L1Block` state -- currently `0` on Ink (independently
//!   verified via a live `eth_call` this pass), but this is a
//!   configuration value, not a fork-gate constant: it can change without
//!   any chain upgrade, so Kairox must read it fresh immediately before
//!   every signing attempt, never hardcode or cache it as zero.
//!
//! The predeploy itself already implements the correct fork-dispatch
//! logic internally (see `getL1Fee`'s `if (isFjord) {...} else if
//! (isEcotone) {...}` and `getOperatorFee`'s `if (!isIsthmus) { return 0;
//! } ... if (isJovian) {...} else {...}` in the verified source) --
//! Kairox calls the oracle's own getters rather than reimplementing any
//! of these formulas locally, so it automatically tracks whichever
//! upgrade is actually active on a given OP Stack chain.

use alloy_primitives::{Address, U256, address};
use alloy_sol_types::sol;

/// The `GasPriceOracle` predeploy address -- identical across every OP
/// Stack chain (Ethereum mainnet OP Stack chains, Base, Ink, ...); a
/// fixed genesis predeploy, not a per-chain deployment that needs
/// provenance verification the way SeaDrop does.
pub const GAS_PRICE_ORACLE: Address = address!("420000000000000000000000000000000000000F");

sol! {
    /// Returns an upper bound for the L1 data/security fee for a
    /// transaction of `_unsignedTxSize` bytes -- the length of the
    /// *unsigned*, fully RLP-encoded (EIP-2718-prefixed) transaction,
    /// i.e. exactly `UnsignedEip1559Tx::encoded_for_signing().len()`.
    /// Requires the chain to be past the Fjord upgrade (Ink is, verified
    /// live via `isFjord()` this pass); reverts otherwise.
    function getL1FeeUpperBound(uint256 _unsignedTxSize) external view returns (uint256);

    /// Exact L1 data/security fee for a specific, fully-serialized
    /// unsigned transaction. More gas-expensive than
    /// `getL1FeeUpperBound` and not used by Kairox's pre-sign bounding
    /// path (kept here for completeness/diagnostics only).
    function getL1Fee(bytes calldata _data) external view returns (uint256);

    /// The operator fee for `_gasUsed` gas, per whichever fork's formula
    /// is currently active (see this module's doc comment) -- `0` before
    /// Isthmus. Always call this rather than reimplementing the formula.
    function getOperatorFee(uint256 _gasUsed) external view returns (uint256);

    function isEcotone() external view returns (bool);
    function isFjord() external view returns (bool);
    function isIsthmus() external view returns (bool);
    function isJovian() external view returns (bool);
    function version() external view returns (string memory);
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpStackFeeError {
    #[error("failed to decode GasPriceOracle response: {0}")]
    AbiDecode(String),
}

/// Encode a `getL1FeeUpperBound(uint256)` call for `unsigned_tx_size`
/// bytes.
pub fn encode_get_l1_fee_upper_bound(unsigned_tx_size: usize) -> alloy_primitives::Bytes {
    use alloy_sol_types::SolCall;
    getL1FeeUpperBoundCall {
        _unsignedTxSize: U256::from(unsigned_tx_size),
    }
    .abi_encode()
    .into()
}

/// Decode a `getL1FeeUpperBound` response.
pub fn decode_get_l1_fee_upper_bound(raw: &[u8]) -> Result<U256, OpStackFeeError> {
    use alloy_sol_types::SolCall;
    getL1FeeUpperBoundCall::abi_decode_returns(raw)
        .map_err(|e| OpStackFeeError::AbiDecode(e.to_string()))
}

/// Encode a `getOperatorFee(uint256)` call for `gas_used` gas.
pub fn encode_get_operator_fee(gas_used: u64) -> alloy_primitives::Bytes {
    use alloy_sol_types::SolCall;
    getOperatorFeeCall {
        _gasUsed: U256::from(gas_used),
    }
    .abi_encode()
    .into()
}

/// Decode a `getOperatorFee` response.
pub fn decode_get_operator_fee(raw: &[u8]) -> Result<U256, OpStackFeeError> {
    use alloy_sol_types::SolCall;
    getOperatorFeeCall::abi_decode_returns(raw)
        .map_err(|e| OpStackFeeError::AbiDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    #[test]
    fn l1_fee_upper_bound_round_trips_through_encode_decode() {
        let encoded = encode_get_l1_fee_upper_bound(250);
        let decoded_call = getL1FeeUpperBoundCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded_call._unsignedTxSize, U256::from(250u64));

        let response = getL1FeeUpperBoundCall::abi_encode_returns(&U256::from(12_345u64));
        let value = decode_get_l1_fee_upper_bound(&response).unwrap();
        assert_eq!(value, U256::from(12_345u64));
    }

    #[test]
    fn operator_fee_round_trips_through_encode_decode() {
        let encoded = encode_get_operator_fee(60_000);
        let decoded_call = getOperatorFeeCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded_call._gasUsed, U256::from(60_000u64));

        let response = getOperatorFeeCall::abi_encode_returns(&U256::ZERO);
        let value = decode_get_operator_fee(&response).unwrap();
        assert_eq!(value, U256::ZERO);
    }

    #[test]
    fn malformed_response_fails_to_decode_rather_than_defaulting() {
        let err = decode_get_l1_fee_upper_bound(&[0x01, 0x02]).unwrap_err();
        assert!(matches!(err, OpStackFeeError::AbiDecode(_)));
    }
}
