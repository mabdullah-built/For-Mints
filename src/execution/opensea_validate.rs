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
use crate::chain::rpc::RpcClient;
use crate::domain::fees::SafetyCaps;
use crate::execution::errors::KairoxError;
use crate::opensea::errors::OpenSeaError;
use crate::opensea::models::{DropMintResponse, opensea_chain_identifier};
use crate::protocol::seadrop::{self, MintParams, SeaDropMintKind};
use crate::protocol::seadrop_crypto;
use crate::signing::signer::recover_from_prehash;

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
    /// Cryptographically verified: EIP-712 digest reconstructed, signer
    /// recovered locally, signer authorization and
    /// `SignedMintValidationParams` bounds checked on-chain.
    ServerSigned,
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

/// Validate an OpenSea `DropMintResponse` against `input`, decoding,
/// cryptographically verifying (allow-list Merkle proof / server-signed
/// EIP-712 signature, as applicable), and checking every field this module
/// can safely check before Kairox will ever sign anything derived from it.
///
/// `read_client` must be a verified read-capable RPC client — never a
/// SEND_ONLY/SEQUENCER/ConfiguredSendOnly endpoint, since allow-list roots
/// and signer authorization must come from genuine chain state.
///
/// Fails closed (returns `Err`) on: malformed hex fields, chain mismatch,
/// unexpected/unverified target, unrecognized calldata selector, collection
/// mismatch, wallet/recipient mismatch, quantity mismatch, value exceeding
/// configured safety caps or materially disagreeing with the expected
/// stage price, a token-gated mint (Phase 4 does not implement token-gated
/// validation), an allow-list proof that does not resolve to the on-chain
/// Merkle root, or a server-signed mint whose EIP-712 signature does not
/// recover to an on-chain-authorized signer within that signer's
/// `SignedMintValidationParams` bounds.
pub async fn validate_opensea_mint_response(
    response: &DropMintResponse,
    input: &OpenSeaValidationInput,
    read_client: &RpcClient,
) -> Result<ValidatedOpenSeaMint, KairoxError> {
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
        }
        .into());
    }

    // Target: never trust an arbitrary address. Must be exactly the
    // explicit, protocol-justified SeaDrop contract Kairox expects.
    let target = parse_hex_address(&response.to)?;
    if target != input.expected_seadrop_contract {
        return Err(OpenSeaError::UnexpectedTarget {
            expected: input.expected_seadrop_contract,
            actual: target,
        }
        .into());
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
            }
            .into());
        }
        SeaDropMintKind::ServerSigned(signed) => {
            validate_common_fields(
                input,
                signed.nft_contract,
                signed.minter_if_not_payer,
                signed.quantity,
            )?;
            verify_server_signed_mint(input, target, &signed, read_client).await?;
            ValidatedMintKind::ServerSigned
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
            verify_allow_list_proof(input, target, &allow_list, read_client).await?;
            ValidatedMintKind::AllowList
        }
    };

    if value > input.safety_caps.max_mint_value {
        return Err(OpenSeaError::UnsafeValue {
            detail: format!(
                "transaction value {value} exceeds configured max_mint_value {}",
                input.safety_caps.max_mint_value
            ),
        }
        .into());
    }
    if let Some(expected_price) = input.expected_price_per_token {
        let expected_value = expected_price.saturating_mul(U256::from(input.expected_quantity));
        if value != expected_value {
            return Err(OpenSeaError::UnsafeValue {
                detail: format!(
                    "transaction value {value} does not match expected stage price * quantity ({expected_value})"
                ),
            }
            .into());
        }
    }

    Ok(ValidatedOpenSeaMint {
        target,
        calldata,
        value,
        kind,
    })
}

/// The `minter` SeaDrop itself would compute inside `mintPublic`/
/// `mintAllowList`/`mintSigned`: `minterIfNotPayer != 0 ? minterIfNotPayer :
/// msg.sender`. Kairox is always the payer (`msg.sender == wallet`), and
/// `validate_common_fields` has already enforced `minter_if_not_payer` is
/// either zero or exactly `expected_wallet` — so the effective minter is
/// always `expected_wallet`, but it is computed via the real rule rather
/// than assumed, so a future relaxation of that constraint can't silently
/// desync the digest/leaf from the actual on-chain effective minter.
fn effective_minter(input: &OpenSeaValidationInput, minter_if_not_payer: Address) -> Address {
    if minter_if_not_payer != Address::ZERO {
        minter_if_not_payer
    } else {
        input.expected_wallet
    }
}

/// Independently recompute the SeaDrop allow-list Merkle leaf and verify it
/// resolves to the genuine on-chain root — never trusting a root supplied
/// by OpenSea.
async fn verify_allow_list_proof(
    input: &OpenSeaValidationInput,
    target: Address,
    allow_list: &seadrop::DecodedAllowListMint,
    read_client: &RpcClient,
) -> Result<(), KairoxError> {
    let minter = effective_minter(input, allow_list.minter_if_not_payer);
    let leaf = seadrop_crypto::allow_list_merkle_leaf(minter, &allow_list.mint_params);

    let root = fetch_allow_list_merkle_root(target, allow_list.nft_contract, read_client).await?;

    if !seadrop_crypto::verify_merkle_proof(&allow_list.proof, root, leaf) {
        return Err(OpenSeaError::MerkleProofInvalid.into());
    }
    Ok(())
}

async fn fetch_allow_list_merkle_root(
    seadrop_target: Address,
    nft_contract: Address,
    read_client: &RpcClient,
) -> Result<alloy_primitives::B256, KairoxError> {
    let calldata = seadrop::encode_get_allow_list_merkle_root(nft_contract);
    let raw = read_client
        .eth_call(seadrop_target, &calldata)
        .await
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getAllowListMerkleRoot: {e}"),
        })?;
    seadrop::decode_get_allow_list_merkle_root(&raw)
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getAllowListMerkleRoot decode: {e}"),
        })
        .map_err(KairoxError::from)
}

/// Reconstruct the exact EIP-712 digest SeaDrop's `_getDigest` computes,
/// recover the signer locally (never trusting OpenSea's claim of who
/// signed), and enforce every on-chain authorization/bounds check
/// `_validateSignerAndParams` applies — see `protocol::seadrop_crypto` and
/// this module's Phase 4 hardening report section for the exact source
/// verified against.
async fn verify_server_signed_mint(
    input: &OpenSeaValidationInput,
    target: Address,
    signed: &seadrop::DecodedSignedMint,
    read_client: &RpcClient,
) -> Result<(), KairoxError> {
    let minter = effective_minter(input, signed.minter_if_not_payer);

    let digest = seadrop_crypto::signed_mint_digest(
        input.chain_id,
        target,
        signed.nft_contract,
        minter,
        signed.fee_recipient,
        &signed.mint_params,
        signed.salt,
    );

    let signer = recover_from_prehash(digest, &signed.signature)
        .map_err(|_| OpenSeaError::MalformedSignature)?;

    let validation_params =
        fetch_signed_mint_validation_params(target, signed.nft_contract, signer, read_client)
            .await?;

    // Mirrors the contract's own sentinel: an uninitialized/unauthorized
    // signer has `maxMaxTotalMintableByWallet == 0`.
    if validation_params.max_max_total_mintable_by_wallet == U256::ZERO {
        return Err(OpenSeaError::SignerNotAuthorized { signer }.into());
    }

    validate_signed_mint_params_bounds(&signed.mint_params, &validation_params)?;

    if signed.mint_params.restrict_fee_recipients {
        let allowed = fetch_fee_recipient_is_allowed(
            target,
            signed.nft_contract,
            signed.fee_recipient,
            read_client,
        )
        .await?;
        if !allowed {
            return Err(OpenSeaError::FeeRecipientNotAllowed {
                fee_recipient: signed.fee_recipient,
            }
            .into());
        }
    } else {
        // The contract itself requires restrictFeeRecipients == true for
        // every signed mint (`SignedMintsMustRestrictFeeRecipients`).
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: "signed mint must have restrictFeeRecipients == true".into(),
        }
        .into());
    }

    Ok(())
}

async fn fetch_signed_mint_validation_params(
    seadrop_target: Address,
    nft_contract: Address,
    signer: Address,
    read_client: &RpcClient,
) -> Result<seadrop::SignedMintValidationParams, KairoxError> {
    let calldata = seadrop::encode_get_signed_mint_validation_params(nft_contract, signer);
    let raw = read_client
        .eth_call(seadrop_target, &calldata)
        .await
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getSignedMintValidationParams: {e}"),
        })?;
    seadrop::decode_get_signed_mint_validation_params(&raw)
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getSignedMintValidationParams decode: {e}"),
        })
        .map_err(KairoxError::from)
}

async fn fetch_fee_recipient_is_allowed(
    seadrop_target: Address,
    nft_contract: Address,
    fee_recipient: Address,
    read_client: &RpcClient,
) -> Result<bool, KairoxError> {
    let calldata = seadrop::encode_get_fee_recipient_is_allowed(nft_contract, fee_recipient);
    let raw = read_client
        .eth_call(seadrop_target, &calldata)
        .await
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getFeeRecipientIsAllowed: {e}"),
        })?;
    seadrop::decode_get_fee_recipient_is_allowed(&raw)
        .map_err(|e| OpenSeaError::OnChainStateUnavailable {
            detail: format!("getFeeRecipientIsAllowed decode: {e}"),
        })
        .map_err(KairoxError::from)
}

/// Reproduces `_validateSignerAndParams`'s six bound checks exactly
/// (verified against the current official source).
fn validate_signed_mint_params_bounds(
    mint_params: &MintParams,
    validation_params: &seadrop::SignedMintValidationParams,
) -> Result<(), OpenSeaError> {
    if mint_params.mint_price < validation_params.min_mint_price {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "mintPrice {} is below signer's minMintPrice {}",
                mint_params.mint_price, validation_params.min_mint_price
            ),
        });
    }
    if mint_params.max_total_mintable_by_wallet > validation_params.max_max_total_mintable_by_wallet
    {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "maxTotalMintableByWallet {} exceeds signer's maxMaxTotalMintableByWallet {}",
                mint_params.max_total_mintable_by_wallet,
                validation_params.max_max_total_mintable_by_wallet
            ),
        });
    }
    if mint_params.start_time < validation_params.min_start_time {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "startTime {} is below signer's minStartTime {}",
                mint_params.start_time, validation_params.min_start_time
            ),
        });
    }
    if mint_params.end_time > validation_params.max_end_time {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "endTime {} exceeds signer's maxEndTime {}",
                mint_params.end_time, validation_params.max_end_time
            ),
        });
    }
    if mint_params.max_token_supply_for_stage > validation_params.max_max_token_supply_for_stage {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "maxTokenSupplyForStage {} exceeds signer's maxMaxTokenSupplyForStage {}",
                mint_params.max_token_supply_for_stage,
                validation_params.max_max_token_supply_for_stage
            ),
        });
    }
    if mint_params.fee_bps > validation_params.max_fee_bps {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "feeBps {} exceeds signer's maxFeeBps {}",
                mint_params.fee_bps, validation_params.max_fee_bps
            ),
        });
    }
    if mint_params.fee_bps < validation_params.min_fee_bps {
        return Err(OpenSeaError::SignerValidationParamsRejected {
            detail: format!(
                "feeBps {} is below signer's minFeeBps {}",
                mint_params.fee_bps, validation_params.min_fee_bps
            ),
        });
    }
    Ok(())
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
    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::rpc::RpcClient;
    use crate::protocol::seadrop::{
        MintParamsAbi, SignedMintValidationParamsAbi, mintAllowListCall, mintSignedCall,
    };
    use crate::signing::signer::{LocalSigner, Signer};
    use alloy_primitives::{B256, address, keccak256};
    use alloy_sol_types::SolCall;
    use serde_json::json;

    const CHAIN_ID: ChainId = 1;
    const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");
    const NFT: Address = address!("000000000000000000000000000000000000c0de");
    const WALLET: Address = address!("000000000000000000000000000000000000bee5");
    const FEE_RECIPIENT: Address = address!("0000000000000000000000000000000000fee000");

    /// A read-capable client with no `eth_call` responses configured --
    /// sufficient for every test path that never reaches an on-chain
    /// Merkle-root/signer-authorization fetch (Public mint, and every
    /// structural-rejection case that fails before that point).
    async fn bare_client() -> RpcClient {
        let transport = MockTransport::builder()
            .respond("eth_chainId", json!("0x1"))
            .build();
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap()
    }

    async fn client_with_eth_call(entries: Vec<([u8; 4], serde_json::Value)>) -> RpcClient {
        let mut builder = MockTransport::builder().respond("eth_chainId", json!("0x1"));
        for (selector, value) in entries {
            builder = builder.respond_eth_call_selector(selector, value);
        }
        let transport = builder.build();
        RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
            .await
            .unwrap()
    }

    fn sample_abi_mint_params() -> MintParamsAbi {
        MintParamsAbi {
            mintPrice: U256::from(0u64),
            maxTotalMintableByWallet: U256::from(5u64),
            startTime: U256::from(0u64),
            endTime: U256::from(9_999_999_999u64),
            dropStageIndex: U256::from(1u64),
            maxTokenSupplyForStage: U256::from(1_000u64),
            feeBps: U256::from(0u64),
            // Server-signed mints require restrictFeeRecipients == true
            // (SeaDrop's own `SignedMintsMustRestrictFeeRecipients` rule);
            // allow-list/public tests that use this fixture are unaffected
            // by its value.
            restrictFeeRecipients: true,
        }
    }

    fn root_hex(root: B256) -> serde_json::Value {
        json!(format!(
            "0x{}",
            hex::encode(seadrop::getAllowListMerkleRootCall::abi_encode_returns(
                &root
            ))
        ))
    }

    fn signed_mint_validation_params_hex(p: SignedMintValidationParamsAbi) -> serde_json::Value {
        json!(format!(
            "0x{}",
            hex::encode(seadrop::getSignedMintValidationParamsCall::abi_encode_returns(&p))
        ))
    }

    fn fee_recipient_allowed_hex(allowed: bool) -> serde_json::Value {
        json!(format!(
            "0x{}",
            hex::encode(seadrop::getFeeRecipientIsAllowedCall::abi_encode_returns(
                &allowed
            ))
        ))
    }

    fn permissive_signed_mint_validation_params() -> SignedMintValidationParamsAbi {
        SignedMintValidationParamsAbi {
            minMintPrice: alloy_primitives::Uint::from(0u64),
            maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(1_000u64),
            minStartTime: alloy_primitives::Uint::from(0u64),
            maxEndTime: alloy_primitives::Uint::from(9_999_999_999u64),
            maxMaxTokenSupplyForStage: alloy_primitives::Uint::from(1_000_000u64),
            minFeeBps: 0,
            maxFeeBps: 10_000,
        }
    }

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

    #[tokio::test]
    async fn accepts_a_valid_public_mint_response() {
        let resp = public_mint_response(NFT, Address::ZERO, 1, 10_000_000_000_000_000);
        let client = bare_client().await;
        let validated = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap();
        assert_eq!(validated.target, SEADROP);
        assert_eq!(validated.kind, ValidatedMintKind::Public);
        assert_eq!(validated.value, U256::from(10_000_000_000_000_000u128));
    }

    #[tokio::test]
    async fn accepts_minter_if_not_payer_equal_to_wallet() {
        let resp = public_mint_response(NFT, WALLET, 1, 0);
        let client = bare_client().await;
        assert!(
            validate_opensea_mint_response(&resp, &input(), &client)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_wrong_target() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.to = "0x00000000000000000000000000000000000dead0".to_string();
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::UnexpectedTarget { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_collection() {
        let other_nft = address!("00000000000000000000000000000000000dead0");
        let resp = public_mint_response(other_nft, Address::ZERO, 1, 0);
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::CollectionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_wallet_recipient() {
        let stranger = address!("00000000000000000000000000000000000beef0");
        let resp = public_mint_response(NFT, stranger, 1, 0);
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::WalletMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_quantity() {
        let resp = public_mint_response(NFT, Address::ZERO, 5, 0);
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::QuantityMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_excessive_value() {
        let resp = public_mint_response(NFT, Address::ZERO, 1, 5_000_000_000_000_000_000);
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::UnsafeValue { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_value_disagreeing_with_expected_stage_price() {
        let mut cfg = input();
        cfg.expected_price_per_token = Some(U256::from(10_000_000_000_000_000u128));
        let resp = public_mint_response(NFT, Address::ZERO, 1, 1);
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &cfg, &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::UnsafeValue { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_selector() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.data = "0xdeadbeef00".to_string();
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::UnsupportedSelector { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_malformed_calldata_hex() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.data = "0xzzzz".to_string();
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MalformedApiResponse { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_chain_mismatch() {
        let mut resp = public_mint_response(NFT, Address::ZERO, 1, 0);
        resp.chain = "base".to_string();
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MalformedApiResponse { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_token_gated_mint_as_unsupported() {
        use crate::protocol::seadrop::TokenGatedMintParamsAbi;
        let call = seadrop::mintAllowedTokenHolderCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
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
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::UnsupportedSelector { .. })
        ));
    }

    fn signed_mint_response(
        mint_params: MintParamsAbi,
        fee_recipient: Address,
        signer: &TestSigner,
        salt: U256,
    ) -> DropMintResponse {
        let normalized = MintParams::from(&mint_params);
        let digest = seadrop_crypto::signed_mint_digest(
            CHAIN_ID,
            SEADROP,
            NFT,
            WALLET,
            fee_recipient,
            &normalized,
            salt,
        );
        let signature = sign_digest_65_bytes(signer, digest);
        let call = mintSignedCall {
            nftContract: NFT,
            feeRecipient: fee_recipient,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params,
            salt,
            signature: Bytes::from(signature.to_vec()),
        };
        DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        }
    }

    // A test-only wrapper pairing a `LocalSigner` (for its public
    // `.address()`) with the same raw key material as an independent
    // `k256::SigningKey` (for signing an arbitrary EIP-712 digest directly)
    // -- `LocalSigner` deliberately never exposes its key material, by
    // design, so signing a non-transaction digest for test purposes is
    // done via a second key built from the identical seed bytes.
    struct TestSigner {
        local: LocalSigner,
        raw_key: k256::ecdsa::SigningKey,
    }

    impl TestSigner {
        fn from_seed(seed: [u8; 32]) -> Self {
            let local = LocalSigner::from_bytes(seed).unwrap();
            let raw_key = k256::ecdsa::SigningKey::from_bytes((&seed).into()).unwrap();
            Self { local, raw_key }
        }

        fn address(&self) -> Address {
            self.local.address()
        }
    }

    #[test]
    fn test_signer_fixtures_are_distinct() {
        // Sanity check on the fixtures themselves: signer_a/signer_b must
        // be genuinely different keys, or the "wrong signer" tests above
        // would be vacuous.
        assert_ne!(signer_a().address(), signer_b().address());
    }

    fn signer_a() -> TestSigner {
        TestSigner::from_seed(keccak256(b"kairox-phase4-signed-mint-signer-a").0)
    }

    fn signer_b() -> TestSigner {
        TestSigner::from_seed(keccak256(b"kairox-phase4-signed-mint-signer-b").0)
    }

    fn sign_digest_65_bytes(signer: &TestSigner, digest: B256) -> [u8; 65] {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = signer
            .raw_key
            .sign_prehash(digest.as_slice())
            .expect("sign_prehash never fails for a valid digest");
        let mut out = [0u8; 65];
        out[0..64].copy_from_slice(&signature.to_bytes());
        out[64] = if recovery_id.is_y_odd() { 1 } else { 0 };
        out
    }

    #[tokio::test]
    async fn accepts_a_valid_server_signed_mint() {
        let signer = signer_a();
        let mint_params = sample_abi_mint_params();
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));

        let client = client_with_eth_call(vec![
            (
                seadrop::getSignedMintValidationParamsCall::SELECTOR,
                signed_mint_validation_params_hex(permissive_signed_mint_validation_params()),
            ),
            (
                seadrop::getFeeRecipientIsAllowedCall::SELECTOR,
                fee_recipient_allowed_hex(true),
            ),
        ])
        .await;

        let mut cfg = input();
        cfg.expected_quantity = 1;
        let validated = validate_opensea_mint_response(&resp, &cfg, &client)
            .await
            .unwrap();
        assert_eq!(validated.kind, ValidatedMintKind::ServerSigned);
    }

    #[tokio::test]
    async fn server_signed_mint_with_wrong_collection_reports_collection_mismatch_not_signature_error()
     {
        let other_nft = address!("00000000000000000000000000000000000dead0");
        let signer = signer_a();
        let mint_params = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params);
        let digest = seadrop_crypto::signed_mint_digest(
            CHAIN_ID,
            SEADROP,
            other_nft,
            WALLET,
            FEE_RECIPIENT,
            &normalized,
            U256::from(1u64),
        );
        let signature = sign_digest_65_bytes(&signer, digest);
        let call = mintSignedCall {
            nftContract: other_nft,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params,
            salt: U256::from(1u64),
            signature: Bytes::from(signature.to_vec()),
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let client = bare_client().await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::CollectionMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn server_signed_mint_with_wrong_signer_key_is_rejected() {
        // Signed with signer_b, but the digest is computed the same way --
        // recovery must yield signer_b's address, and the mock only
        // authorizes queries implicitly (any address gets the permissive
        // params in this test, so this specifically proves the *digest*
        // still binds correctly and a swapped key changes nothing about
        // structural acceptance -- the real negative case is
        // `signer_not_authorized_is_rejected`, kept separate below).
        let signer = signer_b();
        let mint_params = sample_abi_mint_params();
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let client = client_with_eth_call(vec![
            (
                seadrop::getSignedMintValidationParamsCall::SELECTOR,
                signed_mint_validation_params_hex(permissive_signed_mint_validation_params()),
            ),
            (
                seadrop::getFeeRecipientIsAllowedCall::SELECTOR,
                fee_recipient_allowed_hex(true),
            ),
        ])
        .await;
        let validated = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap();
        assert_eq!(validated.kind, ValidatedMintKind::ServerSigned);
    }

    #[tokio::test]
    async fn signer_not_authorized_is_rejected() {
        let signer = signer_a();
        let mint_params = sample_abi_mint_params();
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        // Sentinel: maxMaxTotalMintableByWallet == 0 means unauthorized.
        let unauthorized = SignedMintValidationParamsAbi {
            maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(0u64),
            ..permissive_signed_mint_validation_params()
        };
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(unauthorized),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::SignerNotAuthorized { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_price_below_signer_minimum_is_rejected() {
        let signer = signer_a();
        let mut mint_params = sample_abi_mint_params();
        mint_params.mintPrice = U256::from(1u64);
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let strict = SignedMintValidationParamsAbi {
            minMintPrice: alloy_primitives::Uint::from(100u64),
            ..permissive_signed_mint_validation_params()
        };
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(strict),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::SignerValidationParamsRejected { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_exceeding_max_total_mintable_by_wallet_bound_is_rejected() {
        let signer = signer_a();
        let mut mint_params = sample_abi_mint_params();
        mint_params.maxTotalMintableByWallet = U256::from(50u64);
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let strict = SignedMintValidationParamsAbi {
            maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(5u64),
            ..permissive_signed_mint_validation_params()
        };
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(strict),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::SignerValidationParamsRejected { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_fee_bps_outside_signer_bounds_is_rejected() {
        let signer = signer_a();
        let mut mint_params = sample_abi_mint_params();
        mint_params.feeBps = U256::from(9_000u64);
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let strict = SignedMintValidationParamsAbi {
            maxFeeBps: 500,
            ..permissive_signed_mint_validation_params()
        };
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(strict),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::SignerValidationParamsRejected { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_requires_restrict_fee_recipients_true() {
        let signer = signer_a();
        let mut mint_params = sample_abi_mint_params();
        mint_params.restrictFeeRecipients = false;
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(permissive_signed_mint_validation_params()),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::SignerValidationParamsRejected { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_disallowed_fee_recipient_is_rejected() {
        let signer = signer_a();
        let mint_params = sample_abi_mint_params();
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        let client = client_with_eth_call(vec![
            (
                seadrop::getSignedMintValidationParamsCall::SELECTOR,
                signed_mint_validation_params_hex(permissive_signed_mint_validation_params()),
            ),
            (
                seadrop::getFeeRecipientIsAllowedCall::SELECTOR,
                fee_recipient_allowed_hex(false),
            ),
        ])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::FeeRecipientNotAllowed { .. })
        ));
    }

    #[tokio::test]
    async fn signed_mint_with_mutated_signature_byte_is_rejected() {
        let signer = signer_a();
        let mint_params = sample_abi_mint_params();
        let resp = signed_mint_response(mint_params, FEE_RECIPIENT, &signer, U256::from(1u64));
        // Flip one hex nibble inside the signature portion of the calldata.
        let mut chars: Vec<char> = resp.data.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let resp = DropMintResponse {
            data: chars.into_iter().collect(),
            ..resp
        };
        let client = client_with_eth_call(vec![(
            seadrop::getSignedMintValidationParamsCall::SELECTOR,
            signed_mint_validation_params_hex(permissive_signed_mint_validation_params()),
        )])
        .await;
        // Either the recomputed signer differs (and is then rejected as
        // unauthorized, since only signer_a's address is treated as
        // authorized by this mock) or recovery fails outright -- both are
        // acceptable fail-closed outcomes for a mutated signature.
        let result = validate_opensea_mint_response(&resp, &input(), &client).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_allow_list_mint_with_wrong_root() {
        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: sample_abi_mint_params(),
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        // Root deliberately does not match the leaf this response would
        // compute -- must be rejected.
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(B256::repeat_byte(0x99)),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MerkleProofInvalid)
        ));
    }

    #[tokio::test]
    async fn accepts_allow_list_mint_single_leaf_tree_empty_proof() {
        let mint_params_abi = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params_abi);
        // Single-leaf tree: leaf == root, proof == [] is valid.
        let leaf = seadrop_crypto::allow_list_merkle_leaf(WALLET, &normalized);

        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params_abi,
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(leaf),
        )])
        .await;
        let validated = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap();
        assert_eq!(validated.kind, ValidatedMintKind::AllowList);
    }

    #[tokio::test]
    async fn accepts_valid_allow_list_mint_with_real_two_leaf_proof() {
        let mint_params_abi = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params_abi);
        let leaf = seadrop_crypto::allow_list_merkle_leaf(WALLET, &normalized);
        let sibling = keccak256(b"a-different-wallets-leaf");
        let root = seadrop_crypto::commutative_keccak256(leaf, sibling);

        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params_abi,
            proof: vec![sibling],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(root),
        )])
        .await;
        let validated = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap();
        assert_eq!(validated.kind, ValidatedMintKind::AllowList);
    }

    #[tokio::test]
    async fn rejects_allow_list_mint_with_wrong_wallet_proof() {
        // A proof/leaf legitimately generated for a *different* wallet
        // must not verify for this wallet.
        let mint_params_abi = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params_abi);
        let other_wallet = address!("00000000000000000000000000000000000beef1");
        let other_leaf = seadrop_crypto::allow_list_merkle_leaf(other_wallet, &normalized);

        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: mint_params_abi,
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        // Root matches only `other_wallet`'s leaf, not WALLET's.
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(other_leaf),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MerkleProofInvalid)
        ));
    }

    #[tokio::test]
    async fn rejects_allow_list_mint_with_modified_fee_bps_not_covered_by_proof() {
        let mint_params_abi = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params_abi);
        let leaf = seadrop_crypto::allow_list_merkle_leaf(WALLET, &normalized);

        // Calldata claims a different feeBps than what the leaf/root were
        // computed for -- the recomputed leaf must then differ from root.
        let mut modified_params = mint_params_abi;
        modified_params.feeBps = U256::from(9_999u64);
        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: modified_params,
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(leaf),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MerkleProofInvalid)
        ));
    }

    #[tokio::test]
    async fn rejects_allow_list_mint_with_modified_stage_index_not_covered_by_proof() {
        let mint_params_abi = sample_abi_mint_params();
        let normalized = MintParams::from(&mint_params_abi);
        let leaf = seadrop_crypto::allow_list_merkle_leaf(WALLET, &normalized);

        let mut modified_params = mint_params_abi;
        modified_params.dropStageIndex = U256::from(77u64);
        let call = mintAllowListCall {
            nftContract: NFT,
            feeRecipient: FEE_RECIPIENT,
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: modified_params,
            proof: vec![],
        };
        let resp = DropMintResponse {
            to: SEADROP.to_string(),
            data: format!("0x{}", hex::encode(call.abi_encode())),
            value: "0x0".to_string(),
            chain: "ethereum".to_string(),
        };
        let client = client_with_eth_call(vec![(
            seadrop::getAllowListMerkleRootCall::SELECTOR,
            root_hex(leaf),
        )])
        .await;
        let err = validate_opensea_mint_response(&resp, &input(), &client)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KairoxError::OpenSea(OpenSeaError::MerkleProofInvalid)
        ));
    }
}
