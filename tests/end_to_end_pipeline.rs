//! An end-to-end integration test that exercises the full Phase 1 pipeline
//! — chain-id-verified RPC client, SeaDrop ABI decoding, planning, and
//! receipt log decoding — against a deterministic mock chain, standing in
//! for a real node (no Anvil binary is available in this sandboxed build
//! environment; see the Phase 1 report for details).

use alloy_primitives::{Address, U256, address, keccak256};
use kairox::chain::endpoint::EndpointRole;
use kairox::chain::mock::MockTransport;
use kairox::chain::rpc::RpcClient;
use kairox::domain::fees::SafetyCaps;
use kairox::execution::plan::{PlanInputs, build_plan};
use kairox::protocol::logs::{RawLog, extract_minted_assets};
use kairox::protocol::seadrop::{self, PublicDropAbi};
use serde_json::json;
use time::OffsetDateTime;

fn nft_contract() -> Address {
    address!("000000000000000000000000000000000000c0de")
}

fn seadrop_contract() -> Address {
    address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5")
}

fn wallet() -> Address {
    address!("0000000000000000000000000000000000000aaa")
}

#[tokio::test]
async fn full_pipeline_from_mock_rpc_to_validated_plan() {
    use alloy_sol_types::SolCall;

    let now = OffsetDateTime::now_utc();
    let start = now - time::Duration::minutes(5);
    let end = now + time::Duration::hours(1);

    let public_drop = PublicDropAbi {
        mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
        startTime: alloy_primitives::Uint::from(start.unix_timestamp() as u64),
        endTime: alloy_primitives::Uint::from(end.unix_timestamp() as u64),
        maxTotalMintableByWallet: 5,
        feeBps: 250,
        restrictFeeRecipients: false,
    };
    let public_drop_return = seadrop::getPublicDropCall::abi_encode_returns(&public_drop);

    let allowed_fee_recipients: Vec<Address> = vec![];
    let allowed_return =
        seadrop::getAllowedFeeRecipientsCall::abi_encode_returns(&allowed_fee_recipients);

    let mint_stats_return =
        seadrop::getMintStatsCall::abi_encode_returns(&seadrop::getMintStatsReturn {
            minterNumMinted: U256::from(1u64),
            currentTotalSupply: U256::from(100u64),
            maxSupply: U256::from(1_000u64),
        });

    // The mock transport is method-keyed, not call-content-keyed, so a
    // single `eth_call` response can't distinguish between the three
    // different on-chain reads this pipeline needs. We use it here only to
    // prove `RpcClient`'s chain-id verification against a real `Transport`
    // impl, then exercise the ABI encode/decode + planning pipeline
    // directly against fixtures matching what each real call would return.
    let transport = MockTransport::builder()
        .respond("eth_chainId", json!("0x1"))
        .build();
    let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadOnly, None)
        .await
        .expect("chain id 1 must be accepted");
    assert_eq!(client.chain_id().await.unwrap(), 1);

    // Decode each fixture exactly as `cli::gather` would from a real
    // `eth_call` result.
    let decoded_public_drop =
        seadrop::decode_get_public_drop(&public_drop_return).expect("public drop decodes");
    let decoded_allowed = seadrop::decode_get_allowed_fee_recipients(&allowed_return)
        .expect("allowed fee recipients decode");
    let decoded_stats =
        seadrop::decode_get_mint_stats(&mint_stats_return).expect("mint stats decode");

    let inputs = PlanInputs {
        chain: kairox::chain::registry::ChainRegistry::builtin()
            .by_id(1)
            .unwrap()
            .clone(),
        nft_contract: nft_contract(),
        seadrop_contract: seadrop_contract(),
        minter_address: wallet(),
        quantity: 2,
        public_drop: decoded_public_drop,
        allowed_fee_recipients: decoded_allowed,
        preferred_fee_recipient: None,
        wallet_already_minted: decoded_stats.minter_num_minted,
        current_total_supply: decoded_stats.current_total_supply,
        max_supply: Some(decoded_stats.max_supply),
        nonce: Some(7),
        base_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_estimate: 180_000,
        gas_limit: 220_000,
        safety_caps: SafetyCaps {
            max_mint_value: U256::from(1_000_000_000_000_000_000u128),
            max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
            max_total_spend: U256::from(1_000_000_000_000_000_000u128),
        },
        now,
    };

    let plan = build_plan(inputs).expect("plan should build");

    assert_eq!(plan.wallet_allocation_remaining, 4);
    assert_eq!(plan.collection_supply_remaining, 900);
    assert_eq!(plan.mint_value, U256::from(20_000_000_000_000_000u128));
    assert_eq!(&plan.calldata[0..4], seadrop::mint_public_selector());

    // Now simulate the receipt this mint would produce, and confirm Kairox
    // recovers the correct minted token ids purely from Transfer logs.
    let minted_token_id = U256::from(555u64);
    let log = mint_log(nft_contract(), wallet(), minted_token_id);
    let minted =
        extract_minted_assets(&[log], nft_contract(), wallet()).expect("log decode succeeds");
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0].token_id, minted_token_id);
    assert_eq!(minted[0].amount, U256::from(1u8));
}

fn mint_log(nft_contract: Address, to: Address, token_id: U256) -> RawLog {
    fn topic_from_address(addr: Address) -> alloy_primitives::B256 {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(addr.as_slice());
        alloy_primitives::B256::from(bytes)
    }
    fn topic_from_u256(value: U256) -> alloy_primitives::B256 {
        alloy_primitives::B256::from(value.to_be_bytes())
    }

    RawLog {
        address: nft_contract,
        topics: vec![
            keccak256(b"Transfer(address,address,uint256)"),
            topic_from_address(Address::ZERO),
            topic_from_address(to),
            topic_from_u256(token_id),
        ],
        data: alloy_primitives::Bytes::new(),
    }
}
