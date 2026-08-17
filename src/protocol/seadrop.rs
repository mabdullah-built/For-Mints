//! Independent local encoding/decoding of the standard SeaDrop public-mint
//! ABI. Kairox never asks any third-party API for this calldata — the
//! interface is fixed, well-known, and encoded here directly from the ABI
//! signature.

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};
use thiserror::Error;

sol! {
    struct PublicDropAbi {
        uint80 mintPrice;
        uint48 startTime;
        uint48 endTime;
        uint16 maxTotalMintableByWallet;
        uint16 feeBps;
        bool restrictFeeRecipients;
    }

    function getPublicDrop(address nftContract) external view returns (PublicDropAbi memory);
    function getAllowedFeeRecipients(address nftContract) external view returns (address[] memory);
    function mintPublic(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity
    ) external payable;
    function getMintStats(address minter)
        external
        view
        returns (uint256 minterNumMinted, uint256 currentTotalSupply, uint256 maxSupply);

    // The official SeaDrop ABI (ProjectOpenSea/seadrop, `src/SeaDrop.sol`),
    // verified directly against the current repository during Phase 4
    // research. `MintParams` is shared by the allow-list and server-signed
    // mint paths.
    struct MintParamsAbi {
        uint256 mintPrice;
        uint256 maxTotalMintableByWallet;
        uint256 startTime;
        uint256 endTime;
        uint256 dropStageIndex;
        uint256 maxTokenSupplyForStage;
        uint256 feeBps;
        bool restrictFeeRecipients;
    }

    function mintAllowList(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParamsAbi calldata mintParams,
        bytes32[] calldata proof
    ) external payable;

    function mintSigned(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        uint256 quantity,
        MintParamsAbi calldata mintParams,
        uint256 salt,
        bytes calldata signature
    ) external payable;

    struct TokenGatedMintParamsAbi {
        address allowedNftToken;
        uint256[] allowedNftTokenIds;
    }

    /// The real official signature (needed so the 4-byte selector matches
    /// exactly) — but only the selector is ever used, to recognize (and
    /// immediately treat as Phase-4-unsupported, see
    /// [`SeaDropMintKind::TokenGated`]) a token-gated mint transaction.
    /// Kairox never decodes its full argument list in this phase.
    function mintAllowedTokenHolder(
        address nftContract,
        address feeRecipient,
        address minterIfNotPayer,
        TokenGatedMintParamsAbi calldata mintParams
    ) external payable;

    function getAllowListMerkleRoot(address nftContract) external view returns (bytes32);

    // Verified directly against ProjectOpenSea/seadrop `src/lib/SeaDropStructs.sol`
    // and `src/SeaDrop.sol` during Phase 4 hardening.
    struct SignedMintValidationParamsAbi {
        uint80 minMintPrice;
        uint24 maxMaxTotalMintableByWallet;
        uint40 minStartTime;
        uint40 maxEndTime;
        uint40 maxMaxTokenSupplyForStage;
        uint16 minFeeBps;
        uint16 maxFeeBps;
    }

    function getSigners(address nftContract) external view returns (address[] memory);
    function getSignedMintValidationParams(address nftContract, address signer)
        external
        view
        returns (SignedMintValidationParamsAbi memory);
    function getFeeRecipientIsAllowed(address nftContract, address feeRecipient)
        external
        view
        returns (bool);
}

/// Basis-point denominator; a `feeBps` above this is not a valid percentage.
const BPS_DENOMINATOR: u16 = 10_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeaDropError {
    #[error("nft contract address must not be the zero address")]
    ZeroNftContract,
    #[error("seadrop contract address must not be the zero address")]
    ZeroSeaDropContract,
    #[error("feeBps {0} exceeds 10000 (100%); refusing to trust this state")]
    InvalidFeeBps(u16),
    #[error("mintPrice does not fit safely in a U256/u128 conversion")]
    MintPriceOverflow,
    #[error("startTime/endTime does not fit safely in a u64 conversion")]
    TimestampOverflow,
    #[error("failed to decode ABI return data: {0}")]
    AbiDecode(String),
    #[error("restrictFeeRecipients is true but no allowed fee recipients were returned")]
    NoAllowedFeeRecipients,
    #[error(
        "preferred fee recipient {preferred} is not in the allowed set, and restrictFeeRecipients is true"
    )]
    PreferredFeeRecipientNotAllowed { preferred: Address },
    #[error("collection maximum supply does not fit safely in a u64 conversion")]
    SupplyOverflow,
    #[error(
        "calldata selector 0x{} does not match any recognized SeaDrop mint function; refusing to decode",
        hex::encode(.0)
    )]
    UnrecognizedSelector([u8; 4]),
}

/// Normalized, validated `PublicDrop` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDropConfig {
    pub mint_price: U256,
    pub start_time: u64,
    pub end_time: u64,
    pub max_total_mintable_by_wallet: u16,
    pub fee_bps: u16,
    pub restrict_fee_recipients: bool,
}

impl PublicDropConfig {
    fn from_abi(abi: PublicDropAbi) -> Result<Self, SeaDropError> {
        if abi.feeBps > BPS_DENOMINATOR {
            return Err(SeaDropError::InvalidFeeBps(abi.feeBps));
        }
        Ok(Self {
            mint_price: U256::from(abi.mintPrice),
            start_time: abi
                .startTime
                .try_into()
                .map_err(|_| SeaDropError::TimestampOverflow)?,
            end_time: abi
                .endTime
                .try_into()
                .map_err(|_| SeaDropError::TimestampOverflow)?,
            max_total_mintable_by_wallet: abi.maxTotalMintableByWallet,
            fee_bps: abi.feeBps,
            restrict_fee_recipients: abi.restrictFeeRecipients,
        })
    }
}

/// Normalized wallet/collection mint statistics from `getMintStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintStats {
    pub minter_num_minted: u64,
    pub current_total_supply: u64,
    pub max_supply: u64,
}

/// Build the calldata for `getPublicDrop(address)`.
pub fn encode_get_public_drop(nft_contract: Address) -> Result<Bytes, SeaDropError> {
    validate_address(nft_contract, SeaDropError::ZeroNftContract)?;
    Ok(Bytes::from(
        getPublicDropCall {
            nftContract: nft_contract,
        }
        .abi_encode(),
    ))
}

/// Decode the return data of `getPublicDrop(address)`.
pub fn decode_get_public_drop(data: &[u8]) -> Result<PublicDropConfig, SeaDropError> {
    let decoded = getPublicDropCall::abi_decode_returns(data)
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
    PublicDropConfig::from_abi(decoded)
}

/// Build the calldata for `getAllowedFeeRecipients(address)`.
pub fn encode_get_allowed_fee_recipients(nft_contract: Address) -> Result<Bytes, SeaDropError> {
    validate_address(nft_contract, SeaDropError::ZeroNftContract)?;
    Ok(Bytes::from(
        getAllowedFeeRecipientsCall {
            nftContract: nft_contract,
        }
        .abi_encode(),
    ))
}

/// Decode the return data of `getAllowedFeeRecipients(address)`.
pub fn decode_get_allowed_fee_recipients(data: &[u8]) -> Result<Vec<Address>, SeaDropError> {
    let decoded = getAllowedFeeRecipientsCall::abi_decode_returns(data)
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
    Ok(decoded)
}

/// Build the calldata for `getMintStats(address)`, called against the NFT
/// token contract (not the SeaDrop singleton).
pub fn encode_get_mint_stats(minter: Address) -> Bytes {
    Bytes::from(getMintStatsCall { minter }.abi_encode())
}

/// Decode the return data of `getMintStats(address)`.
pub fn decode_get_mint_stats(data: &[u8]) -> Result<MintStats, SeaDropError> {
    let decoded = getMintStatsCall::abi_decode_returns(data)
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
    Ok(MintStats {
        minter_num_minted: decoded
            .minterNumMinted
            .try_into()
            .map_err(|_| SeaDropError::SupplyOverflow)?,
        current_total_supply: decoded
            .currentTotalSupply
            .try_into()
            .map_err(|_| SeaDropError::SupplyOverflow)?,
        max_supply: decoded
            .maxSupply
            .try_into()
            .map_err(|_| SeaDropError::SupplyOverflow)?,
    })
}

fn validate_address(address: Address, err: SeaDropError) -> Result<(), SeaDropError> {
    if address.is_zero() { Err(err) } else { Ok(()) }
}

/// Select which fee recipient to mint with, given the drop's restriction
/// state and an optional caller preference.
///
/// - If `restrict_fee_recipients` is true, the chosen address must be a
///   member of `allowed` (the caller's preference is honored only if it is
///   in that set; otherwise the first allowed recipient is used).
/// - If false, the caller's preference is used if given, else the first
///   allowed recipient if one exists, else the `fallback` (typically the
///   minting wallet's own address, which is always a legal fee recipient
///   when the drop is unrestricted).
pub fn select_fee_recipient(
    allowed: &[Address],
    restrict_fee_recipients: bool,
    preferred: Option<Address>,
    fallback: Address,
) -> Result<Address, SeaDropError> {
    if restrict_fee_recipients {
        if allowed.is_empty() {
            return Err(SeaDropError::NoAllowedFeeRecipients);
        }
        if let Some(preferred) = preferred {
            if allowed.contains(&preferred) {
                return Ok(preferred);
            }
            return Err(SeaDropError::PreferredFeeRecipientNotAllowed { preferred });
        }
        return Ok(allowed[0]);
    }

    if let Some(preferred) = preferred {
        return Ok(preferred);
    }
    if let Some(first) = allowed.first() {
        return Ok(*first);
    }
    Ok(fallback)
}

/// Build the calldata for `mintPublic(nftContract, feeRecipient,
/// minterIfNotPayer, quantity)`.
///
/// `minter_if_not_payer` should be the zero address when the payer wallet is
/// itself the intended minter (the common case), which additionally has the
/// benefit of making calldata identical across every wallet in a batch.
pub fn encode_mint_public(
    nft_contract: Address,
    fee_recipient: Address,
    minter_if_not_payer: Address,
    quantity: u64,
) -> Result<Bytes, SeaDropError> {
    validate_address(nft_contract, SeaDropError::ZeroNftContract)?;
    let call = mintPublicCall {
        nftContract: nft_contract,
        feeRecipient: fee_recipient,
        minterIfNotPayer: minter_if_not_payer,
        quantity: U256::from(quantity),
    };
    Ok(Bytes::from(call.abi_encode()))
}

/// The 4-byte selector for `mintPublic(...)`, exposed for plan display.
pub fn mint_public_selector() -> [u8; 4] {
    mintPublicCall::SELECTOR
}

/// Normalized `MintParams` (shared by allow-list and server-signed mint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintParams {
    pub mint_price: U256,
    pub max_total_mintable_by_wallet: U256,
    pub start_time: U256,
    pub end_time: U256,
    pub drop_stage_index: U256,
    pub max_token_supply_for_stage: U256,
    pub fee_bps: U256,
    pub restrict_fee_recipients: bool,
}

impl From<&MintParamsAbi> for MintParams {
    fn from(p: &MintParamsAbi) -> Self {
        Self {
            mint_price: p.mintPrice,
            max_total_mintable_by_wallet: p.maxTotalMintableByWallet,
            start_time: p.startTime,
            end_time: p.endTime,
            drop_stage_index: p.dropStageIndex,
            max_token_supply_for_stage: p.maxTokenSupplyForStage,
            fee_bps: p.feeBps,
            restrict_fee_recipients: p.restrictFeeRecipients,
        }
    }
}

/// A decoded `mintAllowList(...)` call. Kept fully structural — Kairox
/// decodes it, but does not itself cryptographically verify `proof`
/// against an on-chain Merkle root in Phase 4 (see the caller-side
/// validator for what *is* checked, and why the full proof-to-root
/// verification was judged not practical to safely reimplement this
/// phase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAllowListMint {
    pub nft_contract: Address,
    pub fee_recipient: Address,
    pub minter_if_not_payer: Address,
    pub quantity: U256,
    pub mint_params: MintParams,
    pub proof: Vec<B256>,
}

/// A decoded `mintSigned(...)` call. Kairox does not implement independent
/// cryptographic verification of the server signature in Phase 4 — see
/// [`SeaDropMintKind::ServerSigned`]'s docs. Decoded purely so the request
/// can be inspected/audited and so every other structural check (target,
/// collection, wallet, quantity, value) can still run before failing
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSignedMint {
    pub nft_contract: Address,
    pub fee_recipient: Address,
    pub minter_if_not_payer: Address,
    pub quantity: U256,
    pub mint_params: MintParams,
    pub salt: U256,
    pub signature: Bytes,
}

/// Which SeaDrop mint function a piece of calldata invokes, reasoned from
/// the calldata's own 4-byte selector — never from an OpenSea stage label
/// (`"WL"`, `"FCFS"`, `"GTD"` are marketing names, not protocol truth).
/// A decoded `mintPublic(...)` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPublicMint {
    pub nft_contract: Address,
    pub fee_recipient: Address,
    pub minter_if_not_payer: Address,
    pub quantity: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeaDropMintKind {
    Public(DecodedPublicMint),
    AllowList(DecodedAllowListMint),
    /// Decoded structurally, but Kairox does not implement independent
    /// verification of the server signature — see
    /// [`decode_seadrop_mint_calldata`]'s caller-side handling.
    ServerSigned(DecodedSignedMint),
    /// Recognized by its correct selector, but Phase 4 does not implement
    /// token-gated mint validation at all — always Unsupported.
    TokenGated,
}

/// Decode arbitrary calldata (as returned by an untrusted external source,
/// e.g. the OpenSea Drops mint API) into a recognized SeaDrop mint call by
/// inspecting its 4-byte selector against the official ABI. An unknown
/// selector — including anything that isn't one of the four function
/// signatures above — fails closed with
/// [`SeaDropError::UnrecognizedSelector`]. Never partial-matches or
/// guesses from calldata length alone.
pub fn decode_seadrop_mint_calldata(calldata: &Bytes) -> Result<SeaDropMintKind, SeaDropError> {
    if calldata.len() < 4 {
        return Err(SeaDropError::UnrecognizedSelector([0; 4]));
    }
    let selector: [u8; 4] = calldata[0..4].try_into().expect("checked length >= 4");

    if selector == mintPublicCall::SELECTOR {
        let call = mintPublicCall::abi_decode(calldata)
            .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
        return Ok(SeaDropMintKind::Public(DecodedPublicMint {
            nft_contract: call.nftContract,
            fee_recipient: call.feeRecipient,
            minter_if_not_payer: call.minterIfNotPayer,
            quantity: call.quantity,
        }));
    }
    if selector == mintAllowListCall::SELECTOR {
        let call = mintAllowListCall::abi_decode(calldata)
            .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
        return Ok(SeaDropMintKind::AllowList(DecodedAllowListMint {
            nft_contract: call.nftContract,
            fee_recipient: call.feeRecipient,
            minter_if_not_payer: call.minterIfNotPayer,
            quantity: call.quantity,
            mint_params: MintParams::from(&call.mintParams),
            proof: call.proof,
        }));
    }
    if selector == mintSignedCall::SELECTOR {
        let call = mintSignedCall::abi_decode(calldata)
            .map_err(|e| SeaDropError::AbiDecode(e.to_string()))?;
        return Ok(SeaDropMintKind::ServerSigned(DecodedSignedMint {
            nft_contract: call.nftContract,
            fee_recipient: call.feeRecipient,
            minter_if_not_payer: call.minterIfNotPayer,
            quantity: call.quantity,
            mint_params: MintParams::from(&call.mintParams),
            salt: call.salt,
            signature: call.signature,
        }));
    }
    if selector == mintAllowedTokenHolderCall::SELECTOR {
        return Ok(SeaDropMintKind::TokenGated);
    }
    Err(SeaDropError::UnrecognizedSelector(selector))
}

/// Build the calldata for `getAllowListMerkleRoot(nftContract)`.
pub fn encode_get_allow_list_merkle_root(nft_contract: Address) -> Bytes {
    Bytes::from(
        getAllowListMerkleRootCall {
            nftContract: nft_contract,
        }
        .abi_encode(),
    )
}

/// Decode `getAllowListMerkleRoot`'s return value.
pub fn decode_get_allow_list_merkle_root(raw: &Bytes) -> Result<B256, SeaDropError> {
    getAllowListMerkleRootCall::abi_decode_returns(raw)
        .map(|root| B256::from(root.0))
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))
}

/// Normalized `SignedMintValidationParams`, verified field-for-field against
/// `SeaDropStructs.sol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedMintValidationParams {
    pub min_mint_price: U256,
    pub max_max_total_mintable_by_wallet: U256,
    pub min_start_time: U256,
    pub max_end_time: U256,
    pub max_max_token_supply_for_stage: U256,
    pub min_fee_bps: U256,
    pub max_fee_bps: U256,
}

impl From<SignedMintValidationParamsAbi> for SignedMintValidationParams {
    fn from(p: SignedMintValidationParamsAbi) -> Self {
        Self {
            min_mint_price: U256::from(p.minMintPrice),
            max_max_total_mintable_by_wallet: U256::from(p.maxMaxTotalMintableByWallet),
            min_start_time: U256::from(p.minStartTime),
            max_end_time: U256::from(p.maxEndTime),
            max_max_token_supply_for_stage: U256::from(p.maxMaxTokenSupplyForStage),
            min_fee_bps: U256::from(p.minFeeBps),
            max_fee_bps: U256::from(p.maxFeeBps),
        }
    }
}

/// Build the calldata for `getSigners(nftContract)`.
pub fn encode_get_signers(nft_contract: Address) -> Bytes {
    Bytes::from(
        getSignersCall {
            nftContract: nft_contract,
        }
        .abi_encode(),
    )
}

/// Decode `getSigners`' return value.
pub fn decode_get_signers(raw: &Bytes) -> Result<Vec<Address>, SeaDropError> {
    getSignersCall::abi_decode_returns(raw).map_err(|e| SeaDropError::AbiDecode(e.to_string()))
}

/// Build the calldata for `getSignedMintValidationParams(nftContract, signer)`.
pub fn encode_get_signed_mint_validation_params(nft_contract: Address, signer: Address) -> Bytes {
    Bytes::from(
        getSignedMintValidationParamsCall {
            nftContract: nft_contract,
            signer,
        }
        .abi_encode(),
    )
}

/// Decode `getSignedMintValidationParams`' return value.
pub fn decode_get_signed_mint_validation_params(
    raw: &Bytes,
) -> Result<SignedMintValidationParams, SeaDropError> {
    getSignedMintValidationParamsCall::abi_decode_returns(raw)
        .map(SignedMintValidationParams::from)
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))
}

/// Build the calldata for `getFeeRecipientIsAllowed(nftContract, feeRecipient)`.
pub fn encode_get_fee_recipient_is_allowed(nft_contract: Address, fee_recipient: Address) -> Bytes {
    Bytes::from(
        getFeeRecipientIsAllowedCall {
            nftContract: nft_contract,
            feeRecipient: fee_recipient,
        }
        .abi_encode(),
    )
}

/// Decode `getFeeRecipientIsAllowed`'s return value.
pub fn decode_get_fee_recipient_is_allowed(raw: &Bytes) -> Result<bool, SeaDropError> {
    getFeeRecipientIsAllowedCall::abi_decode_returns(raw)
        .map_err(|e| SeaDropError::AbiDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn encode_mint_public_round_trips_selector_and_args() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let fee_recipient = address!("0000000000000000000000000000000000fee000");
        let calldata = encode_mint_public(nft_contract, fee_recipient, Address::ZERO, 3).unwrap();

        assert_eq!(&calldata[0..4], mint_public_selector());

        let decoded = mintPublicCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.nftContract, nft_contract);
        assert_eq!(decoded.feeRecipient, fee_recipient);
        assert_eq!(decoded.minterIfNotPayer, Address::ZERO);
        assert_eq!(decoded.quantity, U256::from(3u64));
    }

    #[test]
    fn encode_mint_public_rejects_zero_nft_contract() {
        let err = encode_mint_public(Address::ZERO, Address::ZERO, Address::ZERO, 1).unwrap_err();
        assert_eq!(err, SeaDropError::ZeroNftContract);
    }

    #[test]
    fn encode_and_decode_get_public_drop_calldata() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let calldata = encode_get_public_drop(nft_contract).unwrap();
        let decoded = getPublicDropCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.nftContract, nft_contract);
    }

    #[test]
    fn decode_public_drop_returns_normalized_config() {
        let abi = PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(1_000_000_000_000_000u128),
            startTime: alloy_primitives::Uint::from(1_000u64),
            endTime: alloy_primitives::Uint::from(2_000u64),
            maxTotalMintableByWallet: 5,
            feeBps: 250,
            restrictFeeRecipients: true,
        };
        let encoded = getPublicDropCall::abi_encode_returns(&abi);
        let config = decode_get_public_drop(&encoded).unwrap();
        assert_eq!(config.mint_price, U256::from(1_000_000_000_000_000u128));
        assert_eq!(config.start_time, 1_000);
        assert_eq!(config.end_time, 2_000);
        assert_eq!(config.max_total_mintable_by_wallet, 5);
        assert_eq!(config.fee_bps, 250);
        assert!(config.restrict_fee_recipients);
    }

    #[test]
    fn decode_public_drop_rejects_invalid_fee_bps() {
        let abi = PublicDropAbi {
            mintPrice: alloy_primitives::Uint::from(0u128),
            startTime: alloy_primitives::Uint::from(0u64),
            endTime: alloy_primitives::Uint::from(0u64),
            maxTotalMintableByWallet: 0,
            feeBps: 10_001,
            restrictFeeRecipients: false,
        };
        let encoded = getPublicDropCall::abi_encode_returns(&abi);
        let err = decode_get_public_drop(&encoded).unwrap_err();
        assert_eq!(err, SeaDropError::InvalidFeeBps(10_001));
    }

    #[test]
    fn decode_public_drop_rejects_malformed_data() {
        let err = decode_get_public_drop(&[0xde, 0xad]).unwrap_err();
        assert!(matches!(err, SeaDropError::AbiDecode(_)));
    }

    #[test]
    fn decode_allowed_fee_recipients_round_trip() {
        let a = address!("0000000000000000000000000000000000000aaa");
        let b = address!("0000000000000000000000000000000000000bbb");
        let encoded = getAllowedFeeRecipientsCall::abi_encode_returns(&vec![a, b]);
        let decoded = decode_get_allowed_fee_recipients(&encoded).unwrap();
        assert_eq!(decoded, vec![a, b]);
    }

    #[test]
    fn decode_mint_stats_round_trip() {
        let ret = getMintStatsReturn {
            minterNumMinted: U256::from(2u64),
            currentTotalSupply: U256::from(400u64),
            maxSupply: U256::from(10_000u64),
        };
        let encoded = getMintStatsCall::abi_encode_returns(&ret);
        let decoded = decode_get_mint_stats(&encoded).unwrap();
        assert_eq!(decoded.minter_num_minted, 2);
        assert_eq!(decoded.current_total_supply, 400);
        assert_eq!(decoded.max_supply, 10_000);
    }

    #[test]
    fn select_fee_recipient_restricted_uses_preferred_when_allowed() {
        let a = address!("0000000000000000000000000000000000000aaa");
        let b = address!("0000000000000000000000000000000000000bbb");
        let chosen = select_fee_recipient(&[a, b], true, Some(b), Address::ZERO).unwrap();
        assert_eq!(chosen, b);
    }

    #[test]
    fn select_fee_recipient_restricted_rejects_preferred_not_in_allowed_set() {
        let a = address!("0000000000000000000000000000000000000aaa");
        let outsider = address!("0000000000000000000000000000000000000ccc");
        let err = select_fee_recipient(&[a], true, Some(outsider), Address::ZERO).unwrap_err();
        assert_eq!(
            err,
            SeaDropError::PreferredFeeRecipientNotAllowed {
                preferred: outsider
            }
        );
    }

    #[test]
    fn select_fee_recipient_restricted_defaults_to_first_allowed() {
        let a = address!("0000000000000000000000000000000000000aaa");
        let b = address!("0000000000000000000000000000000000000bbb");
        let chosen = select_fee_recipient(&[a, b], true, None, Address::ZERO).unwrap();
        assert_eq!(chosen, a);
    }

    #[test]
    fn select_fee_recipient_restricted_fails_with_no_allowed_recipients() {
        let err = select_fee_recipient(&[], true, None, Address::ZERO).unwrap_err();
        assert_eq!(err, SeaDropError::NoAllowedFeeRecipients);
    }

    #[test]
    fn select_fee_recipient_unrestricted_uses_preferred() {
        let preferred = address!("0000000000000000000000000000000000000ddd");
        let chosen = select_fee_recipient(&[], false, Some(preferred), Address::ZERO).unwrap();
        assert_eq!(chosen, preferred);
    }

    #[test]
    fn select_fee_recipient_unrestricted_falls_back_to_minter() {
        let fallback = address!("0000000000000000000000000000000000000eee");
        let chosen = select_fee_recipient(&[], false, None, fallback).unwrap();
        assert_eq!(chosen, fallback);
    }

    fn nft() -> Address {
        address!("000000000000000000000000000000000000c0de")
    }
    fn fee_recipient() -> Address {
        address!("0000000000000000000000000000000000fee000")
    }

    #[test]
    fn decode_seadrop_mint_calldata_recognizes_public_mint() {
        let calldata = encode_mint_public(nft(), fee_recipient(), Address::ZERO, 2).unwrap();
        let decoded = decode_seadrop_mint_calldata(&calldata).unwrap();
        match decoded {
            SeaDropMintKind::Public(p) => {
                assert_eq!(p.nft_contract, nft());
                assert_eq!(p.quantity, U256::from(2u64));
            }
            other => panic!("expected Public, got {other:?}"),
        }
    }

    #[test]
    fn decode_seadrop_mint_calldata_recognizes_allow_list_mint() {
        let call = mintAllowListCall {
            nftContract: nft(),
            feeRecipient: fee_recipient(),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(1_000u64),
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
        let calldata = Bytes::from(call.abi_encode());
        let decoded = decode_seadrop_mint_calldata(&calldata).unwrap();
        match decoded {
            SeaDropMintKind::AllowList(a) => {
                assert_eq!(a.nft_contract, nft());
                assert_eq!(a.proof.len(), 1);
                assert_eq!(a.mint_params.drop_stage_index, U256::from(1u64));
            }
            other => panic!("expected AllowList, got {other:?}"),
        }
    }

    #[test]
    fn decode_seadrop_mint_calldata_recognizes_server_signed_mint() {
        let call = mintSignedCall {
            nftContract: nft(),
            feeRecipient: fee_recipient(),
            minterIfNotPayer: Address::ZERO,
            quantity: U256::from(1u64),
            mintParams: MintParamsAbi {
                mintPrice: U256::from(1_000u64),
                maxTotalMintableByWallet: U256::from(5u64),
                startTime: U256::from(0u64),
                endTime: U256::from(9_999_999_999u64),
                dropStageIndex: U256::from(2u64),
                maxTokenSupplyForStage: U256::from(1_000u64),
                feeBps: U256::from(0u64),
                restrictFeeRecipients: false,
            },
            salt: U256::from(42u64),
            signature: Bytes::from(vec![0xAA; 65]),
        };
        let calldata = Bytes::from(call.abi_encode());
        let decoded = decode_seadrop_mint_calldata(&calldata).unwrap();
        match decoded {
            SeaDropMintKind::ServerSigned(s) => {
                assert_eq!(s.salt, U256::from(42u64));
                assert_eq!(s.signature.len(), 65);
            }
            other => panic!("expected ServerSigned, got {other:?}"),
        }
    }

    #[test]
    fn decode_seadrop_mint_calldata_recognizes_token_gated_mint_as_unsupported() {
        let call = mintAllowedTokenHolderCall {
            nftContract: nft(),
            feeRecipient: fee_recipient(),
            minterIfNotPayer: Address::ZERO,
            mintParams: TokenGatedMintParamsAbi {
                allowedNftToken: nft(),
                allowedNftTokenIds: vec![U256::from(1u64)],
            },
        };
        let calldata = Bytes::from(call.abi_encode());
        let decoded = decode_seadrop_mint_calldata(&calldata).unwrap();
        assert_eq!(decoded, SeaDropMintKind::TokenGated);
    }

    #[test]
    fn decode_seadrop_mint_calldata_fails_closed_on_unknown_selector() {
        let calldata = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        let err = decode_seadrop_mint_calldata(&calldata).unwrap_err();
        assert!(matches!(err, SeaDropError::UnrecognizedSelector(_)));
    }

    #[test]
    fn decode_seadrop_mint_calldata_fails_closed_on_too_short_calldata() {
        let calldata = Bytes::from(vec![0x01, 0x02]);
        let err = decode_seadrop_mint_calldata(&calldata).unwrap_err();
        assert!(matches!(err, SeaDropError::UnrecognizedSelector(_)));
    }

    #[test]
    fn encode_and_decode_get_allow_list_merkle_root_round_trips() {
        let calldata = encode_get_allow_list_merkle_root(nft());
        assert_eq!(&calldata[0..4], getAllowListMerkleRootCall::SELECTOR);

        let root = B256::repeat_byte(0x77);
        let raw = Bytes::from(getAllowListMerkleRootCall::abi_encode_returns(&root));
        let decoded = decode_get_allow_list_merkle_root(&raw).unwrap();
        assert_eq!(decoded, root);
    }
}
