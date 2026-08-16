//! Receipt/log decoding infrastructure.
//!
//! Kairox never trusts an off-chain service's claim about what a mint
//! produced. Instead it derives minted token ids (and, for ERC-1155,
//! amounts) purely from the standard `Transfer`/`TransferSingle` event logs
//! present in the transaction receipt itself.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use thiserror::Error;

/// A single decoded log entry, in the shape every JSON-RPC receipt exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// One minted asset recovered from a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintedAsset {
    pub token_id: U256,
    /// `1` for an ERC-721 mint; the transferred quantity for ERC-1155.
    pub amount: U256,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogError {
    #[error("log declares Transfer topic0 but has {actual} topics (expected 4)")]
    UnexpectedTopicCount { actual: usize },
    #[error("ERC-721 Transfer log must have empty data, got {len} bytes")]
    Erc721TransferHasData { len: usize },
    #[error("ERC-1155 TransferSingle log must have 64 bytes of data, got {len}")]
    Erc1155TransferSingleBadDataLength { len: usize },
    #[error("indexed address topic has non-zero padding in its upper 12 bytes")]
    NonZeroAddressPadding,
}

fn transfer_erc721_topic0() -> B256 {
    keccak256(b"Transfer(address,address,uint256)")
}

fn transfer_single_erc1155_topic0() -> B256 {
    keccak256(b"TransferSingle(address,address,address,uint256,uint256)")
}

/// Extract an `Address` from an indexed event topic, validating that the
/// upper 12 bytes (the padding) are actually zero rather than silently
/// truncating.
fn address_from_topic(topic: &B256) -> Result<Address, LogError> {
    let bytes = topic.as_slice();
    if bytes[0..12].iter().any(|b| *b != 0) {
        return Err(LogError::NonZeroAddressPadding);
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes[12..32]);
    Ok(Address::from(addr))
}

fn u256_from_topic(topic: &B256) -> U256 {
    U256::from_be_bytes(topic.0)
}

/// Decode one log as an ERC-721 `Transfer(address,address,uint256)` event,
/// if its `topics[0]` matches. Returns `Ok(None)` for logs that are simply
/// not this event (different topic0) rather than treating that as an error;
/// returns `Err` only when the topic0 matches but the log's shape is
/// otherwise malformed.
pub fn try_decode_erc721_transfer(
    log: &RawLog,
) -> Result<Option<(Address, Address, U256)>, LogError> {
    let Some(topic0) = log.topics.first() else {
        return Ok(None);
    };
    if *topic0 != transfer_erc721_topic0() {
        return Ok(None);
    }
    if log.topics.len() != 4 {
        return Err(LogError::UnexpectedTopicCount {
            actual: log.topics.len(),
        });
    }
    if !log.data.is_empty() {
        return Err(LogError::Erc721TransferHasData {
            len: log.data.len(),
        });
    }
    let from = address_from_topic(&log.topics[1])?;
    let to = address_from_topic(&log.topics[2])?;
    let token_id = u256_from_topic(&log.topics[3]);
    Ok(Some((from, to, token_id)))
}

/// Decode one log as an ERC-1155
/// `TransferSingle(address,address,address,uint256,uint256)` event, if its
/// `topics[0]` matches.
pub fn try_decode_erc1155_transfer_single(
    log: &RawLog,
) -> Result<Option<(Address, Address, U256, U256)>, LogError> {
    let Some(topic0) = log.topics.first() else {
        return Ok(None);
    };
    if *topic0 != transfer_single_erc1155_topic0() {
        return Ok(None);
    }
    if log.topics.len() != 4 {
        return Err(LogError::UnexpectedTopicCount {
            actual: log.topics.len(),
        });
    }
    if log.data.len() != 64 {
        return Err(LogError::Erc1155TransferSingleBadDataLength {
            len: log.data.len(),
        });
    }
    // topics[1] is the operator, unused for mint-detection purposes.
    let from = address_from_topic(&log.topics[2])?;
    let to = address_from_topic(&log.topics[3])?;
    let id = U256::from_be_slice(&log.data[0..32]);
    let value = U256::from_be_slice(&log.data[32..64]);
    Ok(Some((from, to, id, value)))
}

/// Scan every log in a receipt for mints of `nft_contract` to `minter`.
///
/// A "mint" is a `Transfer`/`TransferSingle` event emitted by `nft_contract`
/// with `from == 0x0` and `to == minter`. Any log whose shape is malformed
/// once its topic0 has matched a known event is a hard error — Kairox would
/// rather fail than guess at a token id.
pub fn extract_minted_assets(
    logs: &[RawLog],
    nft_contract: Address,
    minter: Address,
) -> Result<Vec<MintedAsset>, LogError> {
    let mut minted = Vec::new();

    for log in logs {
        if log.address != nft_contract {
            continue;
        }

        if let Some((from, to, token_id)) = try_decode_erc721_transfer(log)? {
            if from.is_zero() && to == minter {
                minted.push(MintedAsset {
                    token_id,
                    amount: U256::from(1u8),
                });
            }
            continue;
        }

        if let Some((from, to, id, value)) = try_decode_erc1155_transfer_single(log)?
            && from.is_zero()
            && to == minter
        {
            minted.push(MintedAsset {
                token_id: id,
                amount: value,
            });
        }
    }

    Ok(minted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn topic_from_address(addr: Address) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(addr.as_slice());
        B256::from(bytes)
    }

    fn topic_from_u256(value: U256) -> B256 {
        B256::from(value.to_be_bytes())
    }

    fn erc721_mint_log(nft_contract: Address, to: Address, token_id: U256) -> RawLog {
        RawLog {
            address: nft_contract,
            topics: vec![
                transfer_erc721_topic0(),
                topic_from_address(Address::ZERO),
                topic_from_address(to),
                topic_from_u256(token_id),
            ],
            data: Bytes::new(),
        }
    }

    #[test]
    fn decodes_erc721_mint_and_attributes_to_minter() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let log = erc721_mint_log(nft_contract, minter, U256::from(7u64));

        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert_eq!(
            minted,
            vec![MintedAsset {
                token_id: U256::from(7u64),
                amount: U256::from(1u8)
            }]
        );
    }

    #[test]
    fn ignores_transfer_not_addressed_to_minter() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let someone_else = address!("0000000000000000000000000000000000000bbb");
        let log = erc721_mint_log(nft_contract, someone_else, U256::from(7u64));

        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert!(minted.is_empty());
    }

    #[test]
    fn ignores_secondary_transfer_not_a_mint() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let prior_owner = address!("0000000000000000000000000000000000000bbb");
        let log = RawLog {
            address: nft_contract,
            topics: vec![
                transfer_erc721_topic0(),
                topic_from_address(prior_owner),
                topic_from_address(minter),
                topic_from_u256(U256::from(1u64)),
            ],
            data: Bytes::new(),
        };

        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert!(minted.is_empty(), "from != 0x0 is a transfer, not a mint");
    }

    #[test]
    fn ignores_logs_from_other_contracts() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let other_contract = address!("0000000000000000000000000000000000000fff");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let log = erc721_mint_log(other_contract, minter, U256::from(1u64));

        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert!(minted.is_empty());
    }

    #[test]
    fn ignores_unrelated_event_topics() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let log = RawLog {
            address: nft_contract,
            topics: vec![keccak256(b"SomeOtherEvent(uint256)")],
            data: Bytes::new(),
        };
        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert!(minted.is_empty());
    }

    #[test]
    fn rejects_erc721_transfer_with_wrong_topic_count() {
        let log = RawLog {
            address: Address::ZERO,
            topics: vec![transfer_erc721_topic0(), topic_from_address(Address::ZERO)],
            data: Bytes::new(),
        };
        let err = try_decode_erc721_transfer(&log).unwrap_err();
        assert_eq!(err, LogError::UnexpectedTopicCount { actual: 2 });
    }

    #[test]
    fn rejects_erc721_transfer_with_nonempty_data() {
        let log = RawLog {
            address: Address::ZERO,
            topics: vec![
                transfer_erc721_topic0(),
                topic_from_address(Address::ZERO),
                topic_from_address(Address::ZERO),
                topic_from_u256(U256::ZERO),
            ],
            data: Bytes::from(vec![0u8; 32]),
        };
        let err = try_decode_erc721_transfer(&log).unwrap_err();
        assert_eq!(err, LogError::Erc721TransferHasData { len: 32 });
    }

    #[test]
    fn rejects_address_topic_with_nonzero_padding() {
        let mut bad_topic = [0u8; 32];
        bad_topic[0] = 0xff; // padding byte should always be zero
        let log = RawLog {
            address: Address::ZERO,
            topics: vec![
                transfer_erc721_topic0(),
                B256::from(bad_topic),
                topic_from_address(Address::ZERO),
                topic_from_u256(U256::ZERO),
            ],
            data: Bytes::new(),
        };
        let err = try_decode_erc721_transfer(&log).unwrap_err();
        assert_eq!(err, LogError::NonZeroAddressPadding);
    }

    #[test]
    fn decodes_erc1155_transfer_single_mint() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let operator = address!("0000000000000000000000000000000000000ccc");

        let mut data = [0u8; 64];
        data[0..32].copy_from_slice(&U256::from(42u64).to_be_bytes::<32>());
        data[32..64].copy_from_slice(&U256::from(3u64).to_be_bytes::<32>());

        let log = RawLog {
            address: nft_contract,
            topics: vec![
                transfer_single_erc1155_topic0(),
                topic_from_address(operator),
                topic_from_address(Address::ZERO),
                topic_from_address(minter),
            ],
            data: Bytes::from(data.to_vec()),
        };

        let minted = extract_minted_assets(&[log], nft_contract, minter).unwrap();
        assert_eq!(
            minted,
            vec![MintedAsset {
                token_id: U256::from(42u64),
                amount: U256::from(3u64)
            }]
        );
    }

    #[test]
    fn rejects_erc1155_transfer_single_with_wrong_data_length() {
        let log = RawLog {
            address: Address::ZERO,
            topics: vec![
                transfer_single_erc1155_topic0(),
                topic_from_address(Address::ZERO),
                topic_from_address(Address::ZERO),
                topic_from_address(Address::ZERO),
            ],
            data: Bytes::from(vec![0u8; 32]),
        };
        let err = try_decode_erc1155_transfer_single(&log).unwrap_err();
        assert_eq!(
            err,
            LogError::Erc1155TransferSingleBadDataLength { len: 32 }
        );
    }

    #[test]
    fn multiple_logs_yield_multiple_minted_assets_in_order() {
        let nft_contract = address!("000000000000000000000000000000000000c0de");
        let minter = address!("0000000000000000000000000000000000000aaa");
        let logs = vec![
            erc721_mint_log(nft_contract, minter, U256::from(1u64)),
            erc721_mint_log(nft_contract, minter, U256::from(2u64)),
            erc721_mint_log(nft_contract, minter, U256::from(3u64)),
        ];
        let minted = extract_minted_assets(&logs, nft_contract, minter).unwrap();
        assert_eq!(minted.len(), 3);
        assert_eq!(minted[0].token_id, U256::from(1u64));
        assert_eq!(minted[2].token_id, U256::from(3u64));
    }
}
