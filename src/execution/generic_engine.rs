//! Generic verified ERC-721/ERC-1155 mint execution.
//!
//! Activates only for a target matched against
//! [`super::generic_registry::TrustedGenericFingerprint`] -- an exact,
//! manually-reviewed implementation-bytecode match. An operator-declared
//! `--generic-schema` plus ERC-165 alone is deliberately **not** enough to
//! reach this path; see `docs/generic-engine.md`'s "Confidence model"
//! section for why (ERC-165 proves the NFT *standard*, never a specific
//! function's argument meanings, payable semantics, or price).
//!
//! Everything after calldata construction reuses the exact same
//! primitives the SeaDrop PUBLIC engine's
//! [`super::prepared::finalize_signed_transaction`] uses
//! (`UnsignedEip1559Tx`, `PreparedBroadcast`), and receipt truth reuses
//! [`super::receipt::poll_receipt`]/[`crate::protocol::logs::extract_minted_assets`]
//! unchanged -- including its `TransferBatch` decoding, so a
//! [`GenericMintShape::MintIdQuantity`] mint's receipt is verified whether
//! the implementation emits `TransferSingle` or `TransferBatch`.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use time::OffsetDateTime;

use crate::chain::registry::ChainInfo;
use crate::chain::rpc::{PreparedBroadcast, RpcClient};
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::protocol::erc_standards::eip1967_implementation;
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::generic_registry::TrustedGenericFingerprint;
use super::generic_schema::{GenericMintSchema, GenericMintShape};
use super::prepared::PreparedTransaction;

/// Resolves the address whose runtime bytecode actually executes a call to
/// `collection` (the EIP-1967 implementation, if `collection` is such a
/// proxy; `collection` itself otherwise), and that bytecode's `keccak256`
/// fingerprint. Calls to a proxy are transparently delegated on-chain, so
/// this is the address a fingerprint must be verified against -- and the
/// hash that must be re-checked immediately before every signing (a
/// malicious/compromised proxy admin could otherwise upgrade the
/// implementation between resolution and signing).
pub async fn resolve_implementation_and_code_hash(
    client: &RpcClient,
    collection: Address,
) -> Result<(Address, B256), KairoxError> {
    let effective_address = eip1967_implementation(client, collection)
        .await?
        .unwrap_or(collection);
    let code = client.get_code(effective_address).await?;
    Ok((effective_address, keccak256(&code)))
}

/// Builds calldata for exactly the schema's declared shape. Each arm is
/// its own `sol!` invocation in its own scope so overlapping Solidity
/// function names (`mint` appears in three of the four shapes, with
/// different argument lists / selectors) never collide as Rust identifiers
/// -- the derived 4-byte selector is unaffected by that scoping and is
/// exactly what the real Solidity signature would hash to.
pub fn encode_calldata(
    schema: &GenericMintSchema,
    wallet: Address,
    quantity: u64,
) -> Result<Bytes, KairoxError> {
    schema.validate().map_err(|e| {
        KairoxError::Session(SessionError::new(format!("invalid generic schema: {e}")))
    })?;
    let quantity = U256::from(quantity);
    match schema.shape {
        GenericMintShape::MintQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(uint256 quantity) external payable; }
            }
            Ok(abi::mintCall { quantity }.abi_encode().into())
        }
        GenericMintShape::PublicMintQuantity => {
            mod abi {
                alloy_sol_types::sol! { function publicMint(uint256 quantity) external payable; }
            }
            Ok(abi::publicMintCall { quantity }.abi_encode().into())
        }
        GenericMintShape::MintToQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(address to, uint256 quantity) external payable; }
            }
            Ok(abi::mintCall {
                to: wallet,
                quantity,
            }
            .abi_encode()
            .into())
        }
        GenericMintShape::MintIdQuantity => {
            mod abi {
                alloy_sol_types::sol! { function mint(uint256 id, uint256 quantity) external payable; }
            }
            let id = schema.token_id.ok_or_else(|| {
                KairoxError::Session(SessionError::new(
                    "generic schema: mint_id_quantity requires token_id",
                ))
            })?;
            Ok(abi::mintCall {
                id: U256::from(id),
                quantity,
            }
            .abi_encode()
            .into())
        }
    }
}

fn schema_from_fingerprint(fp: &TrustedGenericFingerprint) -> GenericMintSchema {
    GenericMintSchema {
        standard: fp.standard,
        shape: fp.shape,
        token_id: fp.token_id,
        price_per_token_wei: fp.price_per_token_wei.to_string(),
    }
}

/// Preflight classification for the `eth_estimateGas` call this engine
/// makes before signing. Only [`SimulationOutcome::Pass`] and
/// [`SimulationOutcome::DefinitiveRevert`] are actually produced by this
/// pass -- `ExpectedPrestartRevert` and `UnsupportedSimulation` are part of
/// the taxonomy `docs/generic-engine.md` describes for a future
/// stage-timing-aware version, and are defined here (rather than added
/// later as a breaking change) but never constructed: nothing in this
/// pass independently establishes a generic contract's stage timing, so
/// there is no principled way to distinguish "expected, still before
/// start" from "genuinely broken" yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationOutcome {
    Pass,
    DefinitiveRevert,
    /// Reserved -- never produced this pass. See enum docs.
    ExpectedPrestartRevert,
    /// Reserved -- never produced this pass. See enum docs.
    UnsupportedSimulation,
}

#[derive(Debug, Clone)]
pub struct GenericMintRequest {
    pub chain: ChainInfo,
    pub collection: Address,
    pub wallet: Address,
    pub quantity: u64,
    /// The exact, manually-reviewed, registry-matched schema -- the only
    /// source of truth for calldata shape and price. Never an
    /// operator-declared schema; see module docs.
    pub fingerprint: TrustedGenericFingerprint,
    /// The bytecode hash observed at resolution time, for the mandatory
    /// pre-sign re-check. Always equal to `fingerprint.implementation_bytecode_hash`
    /// when this request was built from a real registry match -- kept as
    /// a separate field so the re-check is an explicit, visible step
    /// rather than an implicit assumption.
    pub expected_bytecode_hash: B256,
    /// An optional operator-declared *ceiling* on price per token, in wei.
    /// Never the source of truth -- only ever checked as a maximum against
    /// `fingerprint.price_per_token_wei`, so an operator can refuse to
    /// proceed if the verified price is higher than they expected.
    pub operator_max_price_per_token_wei: Option<U256>,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
}

/// Gather fresh live state, re-verify the implementation hasn't changed
/// since resolution, validate, simulate (`eth_estimateGas`), sign, and
/// serialize a generic mint transaction. Fails closed on any missing or
/// invalid required input, a changed implementation
/// (`PROXY_IMPLEMENTATION_CHANGED`), a price exceeding the operator's
/// declared ceiling, or a definitive simulation revert -- mirrors
/// [`super::prepared::prepare_live_transaction`]'s guarantees exactly.
pub async fn prepare_generic_transaction(
    client: &RpcClient,
    signer: &dyn Signer,
    request: &GenericMintRequest,
) -> Result<PreparedTransaction, KairoxError> {
    if signer.address() != request.wallet {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::WalletKeyMismatch,
            format!(
                "loaded signing key resolves to {}, but --wallet was {}; refusing to proceed",
                signer.address(),
                request.wallet
            ),
        )));
    }

    // Immediately-before-signing re-check: a proxy legitimately matched
    // against this fingerprint at resolution time may have since been
    // upgraded to a different implementation. Signing against stale
    // evidence would execute code nobody verified.
    let (_effective_address, current_hash) =
        resolve_implementation_and_code_hash(client, request.collection).await?;
    if current_hash != request.expected_bytecode_hash {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::ProxyImplementationChanged,
            format!(
                "implementation bytecode hash changed since resolution (expected {}, now {}); \
                 refusing to sign against stale evidence",
                request.expected_bytecode_hash, current_hash
            ),
        )));
    }

    let schema = schema_from_fingerprint(&request.fingerprint);
    let calldata = encode_calldata(&schema, request.wallet, request.quantity)?;

    let price_per_token = U256::from(request.fingerprint.price_per_token_wei);
    if let Some(max_price) = request.operator_max_price_per_token_wei
        && price_per_token > max_price
    {
        return Err(KairoxError::Session(SessionError::new(format!(
            "registry-verified price per token {price_per_token} wei exceeds the operator's \
             declared maximum {max_price} wei; refusing to proceed"
        ))));
    }
    let mint_value = price_per_token.saturating_mul(U256::from(request.quantity));

    let block = client.latest_block().await?;
    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "chain does not report an EIP-1559 baseFeePerGas; cannot safely price a live transaction",
        ))
    })?;
    let max_priority_fee_per_gas = client.max_priority_fee_per_gas().await?;
    let max_fee_per_gas = base_fee_per_gas
        .saturating_mul(2)
        .saturating_add(max_priority_fee_per_gas);
    let fees = Eip1559Fees::new(base_fee_per_gas, max_priority_fee_per_gas, max_fee_per_gas)?;

    let nonce = client.transaction_count(request.wallet).await?;
    let balance = client.get_balance(request.wallet).await?;

    let gas_estimate = client
        .estimate_gas(request.wallet, request.collection, &calldata, mint_value)
        .await
        .map_err(|_| {
            // A revert during simulation is a DEFINITIVE_REVERT: there is
            // no independently-established stage-timing model in this
            // pass to excuse it as "not open yet" (see SimulationOutcome
            // docs), so it stops the session here rather than being
            // signed.
            KairoxError::Session(SessionError::new(
                "generic mint simulation (eth_estimateGas) reverted: DEFINITIVE_REVERT; refusing to sign",
            ))
        })?;
    let gas_limit = ((gas_estimate as f64) * request.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let worst_case_gas_cost = fees.worst_case_gas_cost(gas_limit);
    let worst_case_total = worst_case_total_spend(mint_value, worst_case_gas_cost);

    request
        .safety_caps
        .check(mint_value, worst_case_gas_cost, worst_case_total)?;

    if balance < worst_case_total {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::InsufficientBalance,
            format!(
                "wallet balance {balance} wei is insufficient for worst-case total spend {worst_case_total} wei"
            ),
        )));
    }

    let unsigned = UnsignedEip1559Tx {
        chain_id: request.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_limit,
        to: request.collection,
        value: mint_value,
        data: calldata.clone(),
        access_list: Vec::new(),
    };
    let signing_hash = unsigned.signing_hash();
    let signed = signer
        .sign_transaction(unsigned)
        .map_err(KairoxError::Signing)?;
    let raw_signed_bytes = signed.raw_bytes();
    let tx_hash = signed.tx_hash();

    let broadcast_prepare_started = std::time::Instant::now();
    let broadcast = PreparedBroadcast::build(tx_hash, raw_signed_bytes.clone());
    let broadcast_prepare_ms = broadcast_prepare_started.elapsed().as_millis() as u64;

    Ok(PreparedTransaction {
        chain_id: request.chain.chain_id,
        wallet: request.wallet,
        nonce,
        target: request.collection,
        value: mint_value,
        calldata_hash: keccak256(&calldata),
        quantity: request.quantity,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: OffsetDateTime::now_utc(),
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::generic_schema::GenericStandard;
    fn schema(shape: GenericMintShape, token_id: Option<u64>) -> GenericMintSchema {
        GenericMintSchema {
            standard: GenericStandard::Erc721,
            shape,
            token_id,
            price_per_token_wei: "10000000000000000".to_string(),
        }
    }

    fn wallet() -> Address {
        Address::from([1u8; 20])
    }

    #[test]
    fn mint_quantity_encodes_the_real_mint_uint256_selector() {
        let calldata =
            encode_calldata(&schema(GenericMintShape::MintQuantity, None), wallet(), 3).unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::mintCall::SELECTOR);
    }

    #[test]
    fn public_mint_quantity_encodes_the_real_public_mint_selector() {
        let calldata = encode_calldata(
            &schema(GenericMintShape::PublicMintQuantity, None),
            wallet(),
            1,
        )
        .unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function publicMint(uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::publicMintCall::SELECTOR);
    }

    #[test]
    fn mint_to_quantity_encodes_recipient_and_quantity_in_the_right_positions() {
        let calldata =
            encode_calldata(&schema(GenericMintShape::MintToQuantity, None), wallet(), 2).unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(address to, uint256 quantity) external payable; }
        }
        assert_eq!(&calldata[0..4], real_abi::mintCall::SELECTOR);
        let decoded = real_abi::mintCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.to, wallet());
        assert_eq!(decoded.quantity, U256::from(2u64));
    }

    #[test]
    fn mint_id_quantity_requires_token_id_and_encodes_it() {
        let err = encode_calldata(&schema(GenericMintShape::MintIdQuantity, None), wallet(), 1);
        assert!(err.is_err());

        let calldata = encode_calldata(
            &schema(GenericMintShape::MintIdQuantity, Some(42)),
            wallet(),
            1,
        )
        .unwrap();
        mod real_abi {
            alloy_sol_types::sol! { function mint(uint256 id, uint256 quantity) external payable; }
        }
        let decoded = real_abi::mintCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.id, U256::from(42u64));
        assert_eq!(decoded.quantity, U256::from(1u64));
    }

    #[test]
    fn schema_from_fingerprint_carries_the_registry_price_not_any_operator_value() {
        let fp = TrustedGenericFingerprint {
            name: "test",
            chain_id: 1,
            implementation_bytecode_hash: B256::ZERO,
            standard: GenericStandard::Erc721,
            shape: GenericMintShape::MintQuantity,
            token_id: None,
            price_per_token_wei: 42,
        };
        let schema = schema_from_fingerprint(&fp);
        assert_eq!(schema.price_per_token_wei, "42");
    }

    // -- Mechanism-proving tests, MockTransport-backed --
    //
    // `BUILTIN_REGISTRY` (`generic_registry::BUILTIN_REGISTRY`) ships empty
    // -- no real contract has been manually reviewed and registered in
    // this pass -- so the resolver-level (CLI/e2e) tests can only prove
    // the "no match -> UNSUPPORTED_PROTOCOL, never signed" side. These
    // tests inject a fingerprint directly and prove the *mechanism* end to
    // end: an exact bytecode-hash match resolves, a mismatch does not, and
    // a proxy upgrade discovered immediately before signing stops the
    // session rather than executing against stale evidence.

    use crate::chain::endpoint::EndpointRole;
    use crate::chain::mock::MockTransport;
    use crate::chain::registry::ChainRegistry;
    use crate::signing::signer::LocalSigner;

    const FAKE_BYTECODE: &[u8] = &[0x60, 0x80, 0x60, 0x40];

    fn signer() -> LocalSigner {
        LocalSigner::from_bytes(keccak256(b"kairox-generic-engine-test-key").0).unwrap()
    }

    fn fingerprint(hash: B256) -> TrustedGenericFingerprint {
        TrustedGenericFingerprint {
            name: "test-fixture-collection",
            chain_id: 1,
            implementation_bytecode_hash: hash,
            standard: GenericStandard::Erc721,
            shape: GenericMintShape::MintQuantity,
            token_id: None,
            price_per_token_wei: 10_000_000_000_000_000,
        }
    }

    fn base_builder(code_hex: &str) -> crate::chain::mock::MockTransportBuilder {
        MockTransport::builder()
            .respond("eth_chainId", serde_json::json!("0x1"))
            .respond(
                "eth_getStorageAt",
                serde_json::json!(format!("0x{}", "0".repeat(64))),
            )
            .respond("eth_getCode", serde_json::json!(code_hex))
            .respond(
                "eth_getBlockByNumber",
                serde_json::json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"}),
            )
            .respond("eth_maxPriorityFeePerGas", serde_json::json!("0x3b9aca00"))
            .respond("eth_getTransactionCount", serde_json::json!("0x0"))
            .respond("eth_getBalance", serde_json::json!("0xde0b6b3a7640000"))
    }

    async fn client_with(builder: crate::chain::mock::MockTransportBuilder) -> RpcClient {
        RpcClient::connect(Box::new(builder.build()), 1, EndpointRole::ReadWrite, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn full_mechanism_exact_bytecode_match_resolves_prepares_and_signs() {
        let code_hex = format!("0x{}", hex::encode(FAKE_BYTECODE));
        let bytecode_hash = keccak256(FAKE_BYTECODE);
        let client = client_with(
            base_builder(&code_hex).respond("eth_estimateGas", serde_json::json!("0x30d40")),
        )
        .await;

        let (implementation, resolved_hash) =
            resolve_implementation_and_code_hash(&client, Address::from([0x11; 20]))
                .await
                .unwrap();
        assert_eq!(
            implementation,
            Address::from([0x11; 20]),
            "no proxy configured"
        );
        assert_eq!(resolved_hash, bytecode_hash);

        let fp = fingerprint(resolved_hash);
        let signer = signer();
        let request = GenericMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            collection: Address::from([0x11; 20]),
            wallet: signer.address(),
            quantity: 1,
            fingerprint: fp,
            expected_bytecode_hash: resolved_hash,
            operator_max_price_per_token_wei: None,
            gas_buffer_multiplier: 1.25,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(10_000_000_000_000_000u64),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
        };

        let prepared = prepare_generic_transaction(&client, &signer, &request)
            .await
            .expect("registry-matched target should prepare and sign successfully");
        assert_eq!(prepared.value, U256::from(10_000_000_000_000_000u64));
    }

    #[tokio::test]
    async fn proxy_implementation_changed_since_resolution_stops_before_signing() {
        let original_code = format!("0x{}", hex::encode(FAKE_BYTECODE));
        let original_hash = keccak256(FAKE_BYTECODE);
        // The bytecode observed at resolution time no longer matches what
        // eth_getCode reports right now -- simulating a proxy upgrade (or
        // any other change) that happened between resolution and signing.
        let different_bytecode: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let client = client_with(base_builder(&format!(
            "0x{}",
            hex::encode(different_bytecode)
        )))
        .await;

        let fp = fingerprint(original_hash);
        let signer = signer();
        let request = GenericMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            collection: Address::from([0x11; 20]),
            wallet: signer.address(),
            quantity: 1,
            fingerprint: fp,
            expected_bytecode_hash: original_hash,
            operator_max_price_per_token_wei: None,
            gas_buffer_multiplier: 1.25,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(10_000_000_000_000_000u64),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
        };
        let _ = original_code; // only used to document what "unchanged" would have been

        let err = prepare_generic_transaction(&client, &signer, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code().to_string(), "PROXY_IMPLEMENTATION_CHANGED");
    }

    #[tokio::test]
    async fn definitive_simulation_revert_stops_before_signing() {
        let code_hex = format!("0x{}", hex::encode(FAKE_BYTECODE));
        let bytecode_hash = keccak256(FAKE_BYTECODE);
        let client = client_with(base_builder(&code_hex).error(
            "eth_estimateGas",
            -32000,
            "execution reverted",
        ))
        .await;

        let fp = fingerprint(bytecode_hash);
        let signer = signer();
        let request = GenericMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            collection: Address::from([0x11; 20]),
            wallet: signer.address(),
            quantity: 1,
            fingerprint: fp,
            expected_bytecode_hash: bytecode_hash,
            operator_max_price_per_token_wei: None,
            gas_buffer_multiplier: 1.25,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(10_000_000_000_000_000u64),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
        };

        let err = prepare_generic_transaction(&client, &signer, &request)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("DEFINITIVE_REVERT"));
    }

    #[tokio::test]
    async fn registry_price_exceeding_operator_declared_ceiling_is_refused() {
        let code_hex = format!("0x{}", hex::encode(FAKE_BYTECODE));
        let bytecode_hash = keccak256(FAKE_BYTECODE);
        let client = client_with(base_builder(&code_hex)).await;

        let fp = fingerprint(bytecode_hash); // price = 0.01 ETH
        let signer = signer();
        let request = GenericMintRequest {
            chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
            collection: Address::from([0x11; 20]),
            wallet: signer.address(),
            quantity: 1,
            fingerprint: fp,
            expected_bytecode_hash: bytecode_hash,
            // Operator expected at most 0.001 ETH -- the verified price is
            // 10x higher than they were willing to accept.
            operator_max_price_per_token_wei: Some(U256::from(1_000_000_000_000_000u64)),
            gas_buffer_multiplier: 1.25,
            safety_caps: SafetyCaps {
                max_mint_value: U256::from(10_000_000_000_000_000u64),
                max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                max_total_spend: U256::from(2_000_000_000_000_000_000u128),
            },
        };

        let err = prepare_generic_transaction(&client, &signer, &request)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("exceeds the operator's declared maximum"));
    }
}
