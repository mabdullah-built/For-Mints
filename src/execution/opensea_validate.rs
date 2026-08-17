//! Local validation of an OpenSea Drops mint-transaction response.
//!
//! This is the single most important module in the OpenSea engine: the
//! official OpenSea API response is untrusted external transaction input
//! until Kairox validates it locally. The OpenSea server does not receive
//! authority to make a wallet execute an arbitrary transaction — Kairox
//! never signs a `target`/`calldata`/`value` triple this module has not
//! approved.

use alloy_primitives::{Address, Bytes, U256};

use crate::chain::registry::ChainId;
use crate::domain::fees::SafetyCaps;
use crate::opensea::errors::OpenSeaError;
use crate::opensea::models::{DropMintResponse, opensea_chain_identifier};
use crate::protocol::seadrop::{self, SeaDropMintKind};

/// Everything the validator needs to know about what response would be
/// legitimate — assembled from the caller's own request plus locally
/// known/configured facts, never from anything OpenSea returned.
#[derive(Debug, Clone)]
pub struct OpenSeaValidationInput {
    pub chain_id: ChainId,
    /// The SeaDrop contract Kairox expects this mint to target. Section 13
    /// ("target validation") requires this to be explicit and
    /// protocol-justified, never "any address OpenSea happened to return" —
    /// this is normally the chain's known SeaDrop 1.0 singleton, or an
    /// operator-confirmed variant deployment.
    pub expected_seadrop_contract: Address,
    pub expected_collection: Address,
    pub expected_wallet: Address,
    pub expected_quantity: u64,
    pub safety_caps: SafetyCaps,
    /// Best-effort expected price-per-token from the drop's stage details,
    /// when available (see section 17: cross-check "when enough
    /// trustworthy information is available"; `None` skips this check
    /// rather than fabricating an expectation).
    pub expected_price_per_token: Option<U256>,
}

/// The kind of SeaDrop mint call an OpenSea response decoded to, with just
/// enough summary to report/log — full structural fields already having
/// been checked by [`validate_opensea_mint_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatedMintKind {
    Public,
    AllowList,
}

/// A validated, safe-to-sign mint transaction derived from an OpenSea
/// response. Everything on this struct has passed every check this module
/// implements — see [`validate_opensea_mint_response`].
#[derive(Debug, Clone)]
pub struct ValidatedOpenSeaMint {
    pub target: Address,
    pub calldata: Bytes,
    pub value: U256,
    pub kind: ValidatedMintKind,
}

/// Validate an OpenSea `DropMintResponse` against `input`, decoding and
/// checking every field this module can safely check before Kairox will
/// ever sign anything derived from it.
///
/// Fails closed (returns `Err`) on: malformed hex fields, chain mismatch,
/// unexpected/unverified target, unrecognized calldata selector,
/// collection mismatch, wallet/recipient mismatch, quantity mismatch,
/// value exceeding configured safety caps or materially disagreeing with
/// the expected stage price, a token-gated mint (Phase 4 does not
/// implement token-gated validation), and a server-signed mint (Phase 4
/// does not implement independent signature verification — see
/// [`OpenSeaError::SignatureValidationUnavailable`]'s docs).
pub fn validate_opensea_mint_response(
    response: &DropMintResponse,
    input: &OpenSeaValidationInput,
) -> Result<ValidatedOpenSeaMint, OpenSeaError> {
    // Chain: the response must claim the exact chain we asked about.
    let expected_chain =
        opensea_chain_identifier(input.chain_id).ok_or_else(|| OpenSeaError::UnsupportedChain {
            chain: input.chain_id.to_string(),
        })?;
    if response.chain != expected_chain {
        return Err(OpenSeaError::MalformedApiResponse {
            detail: format!(
                "response chain '{}' does not match requested chain '{expected_chain}'",
                response.chain
            ),
        });
    }

    // Target: never trust an arbitrary address. Must be exactly the
    // explicit, protocol-justified SeaDrop contract Kairox expects.
    let target = parse_hex_address(&response.to)?;
    if target != input.expected_seadrop_contract {
        return Err(OpenSeaError::UnexpectedTarget {
            expected: input.expected_seadrop_contract,
            actual: target,
        });
    }

    let calldata = parse_hex_bytes(&response.data)?;
    let value = parse_hex_u256(&response.value)?;

    let decoded = seadrop::decode_seadrop_mint_calldata(&calldata).map_err(|_| {
        OpenSeaError::UnsupportedSelector {
            selector: calldata
                .get(0..4)
                .map(hex::encode)
                .unwrap_or_else(|| "????????".to_string()),
        }
    })?;

    let kind = match decoded {
        SeaDropMintKind::TokenGated => {
            return Err(OpenSeaError::UnsupportedSelector {
                selector: "mintAllowedTokenHolder (token-gated, unsupported in Phase 4)".into(),
            });
        }
        SeaDropMintKind::ServerSigned(signed) => {
            // Structural checks still run on a server-signed mint before
            // failing closed -- a malformed/mismatched server-signed
            // response is reported with its *specific* problem, not
            // masked by the generic "signature can't be verified" error.
            validate_common_fields(
                input,
                signed.nft_contract,
                signed.minter_if_not_payer,
                signed.quantity,
            )?;
            return Err(OpenSeaError::SignatureValidationUnavailable);
        }
        SeaDropMintKind::Public(public) => {
            validate_common_fields(
                input,
                public.nft_contract,
                public.minter_if_not_payer,
                public.quantity,
            )?;
            ValidatedMintKind::Public
        }
        SeaDropMintKind::AllowList(allow_list) => {
            validate_common_fields(
                input,
                allow_list.nft_contract,
                allow_list.minter_if_not_payer,
                allow_list.quantity,
            )?;
            if allow_list.proof.is_empty() {
                return Err(OpenSeaError::UnsafeValue {
                    detail: "allow-list mint returned with an empty Merkle proof".into(),
                });
            }
            ValidatedMintKind::AllowList
        }
    };

    if value > input.safety_caps.max_mint_value {
        return Err(OpenSeaError::UnsafeValue {
            detail: format!(
                "transaction value {value} exceeds configured max_mint_value {}",
                input.safety_caps.max_mint_value
            ),
        });
    }
    if let Some(expected_price) = input.expected_price_per_token {
        let expected_value = expected_price.saturating_mul(U256::from(input.expected_quantity));
        if value != expected_value {
            return Err(OpenSeaError::UnsafeValue {
                detail: format!(
                    "transaction value {value} does not match expected stage price * quantity ({expected_value})"
                ),
            });
        }
    }

    Ok(ValidatedOpenSeaMint {
        target,
        calldata,
        value,
        kind,
    })
}

/// Field checks shared by every decoded mint kind: collection, wallet
/// (`minterIfNotPayer` must designate "mint to msg.sender", i.e. be zero or
/// exactly the requested wallet — anything else would silently redirect
/// minted tokens), and quantity.
fn validate_common_fields(
    input: &OpenSeaValidationInput,
    nft_contract: Address,
    minter_if_not_payer: Address,
    quantity: U256,
) -> Result<(), OpenSeaError> {
    if nft_contract != input.expected_collection {
        return Err(OpenSeaError::CollectionMismatch {
            expected: input.expected_collection,
            actual: nft_contract,
        });
    }
    if minter_if_not_payer != Address::ZERO && minter_if_not_payer != input.expected_wallet {
        return Err(OpenSeaError::WalletMismatch {
            expected: input.expected_wallet,
            actual: minter_if_not_payer,
        });
    }
    let expected_quantity = U256::from(input.expected_quantity);
    if quantity != expected_quantity {
        let actual = u64::try_from(quantity).unwrap_or(u64::MAX);
        return Err(OpenSeaError::QuantityMismatch {
            expected: input.expected_quantity,
            actual,
        });
    }
    Ok(())
}

fn parse_hex_address(s: &str) -> Result<Address, OpenSeaError> {
    s.parse::<Address>()
        .map_err(|e| OpenSeaError::MalformedApiResponse {
            detail: format!("invalid address '{s}': {e}"),
        })
}

fn parse_hex_bytes(s: &str) -> Result<Bytes, OpenSeaError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map(Bytes::from)
        .map_err(|e| OpenSeaError::MalformedApiResponse {
            detail: format!("invalid hex data '{s}': {e}"),
        })
}

fn parse_hex_u256(s: &str) -> Result<U256, OpenSeaError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let stripped = if stripped.is_empty() { "0" } else { stripped };
    U256::from_str_radix(stripped, 16).map_err(|e| OpenSeaError::MalformedApiResponse {
        detail: format!("invalid hex value '{s}': {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use alloy_sol_types::SolCall;

    const CHAIN_ID: ChainId = 1;
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");
    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const WALLET: Address = address!("000000000000000000000000000000000000bee5");

    fn input() -> OpenSeaValidationInput {
        OpenSeaValidationInput {
            chain_id: CHAIN_ID,
            expected_seadrop_contract: SEADROP,
            expected_collection: NFT,
            expected_wallet: WALLET,
            expected_quantity: 1,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
            expected_price_per_token: None,
        }
    }

    fn public_mint_response(
        nft: Address,
        minter_if_not_payer: Address,
        quantity: u64,
        value_wei: u128,
    ) -> DropMintResponse {
        let calldata = seadrop::encode_mint_public(
            nft,
            address!("0000000000000000000000000000000000fee000"),
            minter_if_not_payer,
            quantity,
        )
        .unwrap();
        DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(&calldata)),
            value: format!("0x{value_wei:x}"),
            chain: "ethereum".to_string(),
        }
    }

    #[test]
    fn accepts_a_valid_public_mint_response() {
        let resp = public_mint_response(NFT, Address::ZERO, 1, 10_000_000_000_000_000);
        let validated = validate_opensea_mint_response(&resp, &input()).unwrap();
        assert_eq!(validated.target, SEADROP);
        assert_eq!(validated.kind, ValidatedMintKind::Public);
        assert_eq!(validated.value, U256::from(10_000_000_000_000_000u128));
    }

    #[test]
    fn accepts_minter_if_not_payer_equal_to_wallet() {
        let resp = public_mint_response(NFT, WALLET, 1, 0);
        assert!(validate_opensea_mint_response(&resp, &input()).is_ok());
    }

    #[test]
    fn rejects_wrong_target() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.to = "0x00000000000000000000000000000000000dead0".to_string();
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnexpectedTarget { .. }));
    }

    #[test]
    fn rejects_wrong_collection() {
        let other_nft = address!("00000000000000000000000000000000000dead0");
        let resp = public_mint_response(other_nft, Address::ZERO, 1, 0);
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::CollectionMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_wallet_recipient() {
        let stranger = address!("00000000000000000000000000000000000beef0");
        let resp = public_mint_response(NFT, stranger, 1, 0);
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::WalletMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_quantity() {
        let resp = public_mint_response(NFT, Address::ZERO, 5, 0);
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::QuantityMismatch { .. }));
    }

    #[test]
    fn rejects_excessive_value() {
        let resp = public_mint_response(NFT, Address::ZERO, 1, 5_000_000_000_000_000_000);
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnsafeValue { .. }));
    }

    #[test]
    fn rejects_value_disagreeing_with_expected_stage_price() {
        let mut cfg = input();
        cfg.expected_price_per_token = Some(U256::from(10_000_000_000_000_000u128));
        let resp = public_mint_response(NFT, Address::ZERO, 1, 1);
        let err = validate_opensea_mint_response(&resp, &cfg).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnsafeValue { .. }));
    }

    #[test]
    fn rejects_unknown_selector() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.data = "0xdeadbeef00".to_string();
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnsupportedSelector { .. }));
    }

    #[test]
    fn rejects_malformed_calldata_hex() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.data = "0xzzzz".to_string();
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::MalformedApiResponse { .. }));
    }

    #[test]
    fn rejects_chain_mismatch() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.chain = "base".to_string();
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::MalformedApiResponse { .. }));
    }

    #[test]
    fn rejects_token_gated_mint_as_unsupported() {
        use crate::protocol::seadrop::TokenGatedMintParamsAbi;
        let call = seadrop::mintAllowedTokenHolderCall {
            nftContract: NFT,
            feeRecipient: address!("0000000000000000000000000000000000fee000"),
            minterIfNotPayer: Address::ZERO,
            mintParams: TokenGatedMintParamsAbi {
                allowedNftToken: NFT,
                allowedNftTokenIds: vec![U256::from(1u64)],
            },
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnsupportedSelector { .. }));
    }

    #[test]
    fn rejects_server_signed_mint_as_unverifiable_but_checks_structure_first() {
        use crate::protocol::seadrop::MintParamsAbi;
        let call = seadrop::mintSignedCall {
            nftContract: NFT,
            feeRecipient: address!("0000000000000000000000000000000000fee000"),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(0u64),
                maxTotalMintableByWallet: U256::from(5u64),
                startTime: U256::from(0u64),
                endTime: U256::from(9_999_999_999u64),
                dropStageIndex: U256::from(3u64),
                maxTokenSupplyForStage: U256::from(1_000u64),
                feeBps: U256::from(0u64),
                restrictFeeRecipients: false,
            },
            salt: U256::from(1u64),
            signature: Bytes::from(vec![0u8; 65]),
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::SignatureValidationUnavailable));
    }

    #[test]
    fn server_signed_mint_with_wrong_collection_reports_collection_mismatch_not_signature_error() {
        use crate::protocol::seadrop::MintParamsAbi;
        let other_nft = address!("00000000000000000000000000000000000dead0");
        let call = seadrop::mintSignedCall {
            nftContract: other_nft,
            feeRecipient: address!("0000000000000000000000000000000000fee000"),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(0u64),
                maxTotalMintableByWallet: U256::from(5u64),
                startTime: U256::from(0u64),
                endTime: U256::from(9_999_999_999u64),
                dropStageIndex: U256::from(3u64),
                maxTokenSupplyForStage: U256::from(1_000u64),
                feeBps: U256::from(0u64),
                restrictFeeRecipients: false,
            },
            salt: U256::from(1u64),
            signature: Bytes::from(vec![0u8; 65]),
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::CollectionMismatch { .. }));
    }

    #[test]
    fn rejects_allow_list_mint_with_empty_proof() {
        use crate::protocol::seadrop::MintParamsAbi;
        let call = seadrop::mintAllowListCall {
            nftContract: NFT,
            feeRecipient: address!("0000000000000000000000000000000000fee000"),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(0u64),
                maxTotalMintableByWallet: U256::from(5u64),
                startTime: U256::from(0u64),
                endTime: U256::from(9_999_999_999u64),
                dropStageIndex: U256::from(1u64),
                maxTokenSupplyForStage: U256::from(1_000u64),
                feeBps: U256::from(0u64),
                restrictFeeRecipients: false,
            },
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let err = validate_opensea_mint_response(&resp, &input()).unwrap_err();
        assert!(matches!(err, OpenSeaError::UnsafeValue { .. }));
    }

    #[test]
    fn accepts_valid_allow_list_mint() {
        use crate::protocol::seadrop::MintParamsAbi;
        use alloy_primitives::B256;
        let call = seadrop::mintAllowListCall {
            nftContract: NFT,
            feeRecipient: address!("0000000000000000000000000000000000fee000"),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(0u64),
                maxTotalMintableByWallet: U256::from(5u64),
                startTime: U256::from(0u64),
                endTime: U256::from(9_999_999_999u64),
                dropStageIndex: U256::from(1u64),
                maxTokenSupplyForStage: U256::from(1_000u64),
                feeBps: U256::from(0u64),
                restrictFeeRecipients: false,
            },
            proof: vec![B256::repeat_byte(0xAB)],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let validated = validate_opensea_mint_response(&resp, &input()).unwrap();
        assert_eq!(validated.kind, ValidatedMintKind::AllowList);
    }
}
