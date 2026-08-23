//! Manifold `LazyPayableClaim` mint execution -- the third fully on-chain
//! protocol-specific engine, alongside the native SeaDrop engine
//! ([`super::live`]) and thirdweb ([`super::thirdweb_engine`]). Mirrors
//! `thirdweb_engine`'s structure closely (resolve provenance, fetch
//! state, resolve effective claim, build unsigned tx, broadcast/receipt
//! orchestration), but Manifold's architecture forces two real
//! differences -- see `protocol::manifold`'s module doc comment for the
//! full rationale:
//!
//! - **Three identifiers, not one.** A claim is addressed by
//!   `(extension_contract, creator_contract, instance_id)` -- the
//!   extension contract is the `eth_call`/`eth_sendTransaction` target,
//!   the creator contract is the NFT collection, and neither alone
//!   identifies a claim.
//! - **No proxy to resolve.** The extension contract is a shared,
//!   non-upgradeable singleton -- provenance hashes its own runtime
//!   bytecode directly (see `execution::manifold_registry`'s doc
//!   comment), no EIP-1167/EIP-1967 resolution step.
//!
//! v0.8 first Manifold pass scope (mirrors `protocol::manifold`'s own
//! documented scope exactly): single-token `mint()` only (no
//! `mintBatch`), native-currency claims only, the V1 `ERC721LazyPayableClaim`
//! extension only.

use alloy_primitives::{Address, B256, U256, keccak256};
use time::OffsetDateTime;

use crate::chain::registry::{ChainId, ChainInfo};
use crate::chain::rpc::{PreparedBroadcast, RpcClient};
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::domain::supply::{
    CollectionSupply, SupplyError, WalletAllocation, validate_requested_quantity,
};
use crate::protocol::manifold::{self, ManifoldClaim};
use crate::protocol::seadrop_crypto::verify_merkle_proof;
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::manifold_registry::{ManifoldTrustedFingerprint, find_fingerprint};
use super::prepared::PreparedTransaction;

/// Resolves the address whose runtime bytecode is the real target of
/// trust: the extension contract's own address, always -- see this
/// module's and `execution::manifold_registry`'s doc comments for why no
/// proxy resolution step exists here (unlike thirdweb's per-collection
/// proxy). Returns `keccak256` of its runtime bytecode.
pub(crate) async fn resolve_manifold_extension_code_hash(
    client: &RpcClient,
    extension_contract: Address,
) -> Result<B256, KairoxError> {
    let code = client.get_code(extension_contract).await?;
    Ok(keccak256(&code))
}

/// The **only** route to authorizing a real (non-dry-run) Manifold live
/// send -- see `execution::manifold_registry`'s module doc comment for the
/// full rationale. Hashes the extension contract's own runtime bytecode
/// and requires an exact match against `registry`. No match -- including
/// the default, empty `manifold_registry::BUILTIN_REGISTRY` -- means no
/// live send is authorized; this function returns an error, not a guess.
pub async fn establish_provenance(
    client: &RpcClient,
    chain_id: ChainId,
    extension_contract: Address,
    registry: &[ManifoldTrustedFingerprint],
) -> Result<ManifoldTrustedFingerprint, KairoxError> {
    let bytecode_hash = resolve_manifold_extension_code_hash(client, extension_contract).await?;
    find_fingerprint(registry, chain_id, bytecode_hash).ok_or_else(|| {
        KairoxError::Session(SessionError::new(format!(
            "no trusted implementation fingerprint found for this Manifold extension contract on \
             chain {chain_id} (bytecode hash {bytecode_hash:#x}); refusing to authorize a live \
             send against unverified Manifold execution semantics. Selector compatibility and a \
             successful read are not proof this contract's claim logic is unmodified vanilla \
             Manifold code -- see execution::manifold_registry."
        )))
    })
}

/// Best-effort claim-state read -- used **only** for read-only dry-run
/// reporting, never to authorize a live send (see [`establish_provenance`]
/// for that). A genuine decode failure or revert is treated as "no claim
/// found here", not propagated as an error.
pub async fn probe_claim(
    client: &RpcClient,
    extension_contract: Address,
    creator_contract: Address,
    instance_id: U256,
) -> Option<ManifoldClaim> {
    crate::cli::gather::fetch_manifold_claim(
        client,
        extension_contract,
        creator_contract,
        instance_id,
    )
    .await
    .ok()
}

/// Attempts to auto-discover the `LazyPayableClaim` extension contract
/// for `creator_contract` -- see `protocol::manifold`'s module doc
/// comment for the full rationale and its limits. Reads every extension
/// registered via `ICreatorCore::getExtensions()` (real, bounded, on-chain
/// enumeration), then best-effort-probes each candidate with
/// `getClaim(creator_contract, instance_id)` -- a successful decode is
/// evidence this address speaks the `LazyPayableClaim` ABI shape, never
/// evidence it is safe to sign against (that is
/// [`establish_provenance`]'s job, applied afterward, unconditionally).
///
/// Returns exactly one candidate, or a clear error naming what was found
/// -- zero candidates, or more than one, both refuse rather than guess.
/// `instance_id` must already be known (it is always an explicit,
/// required operator input -- this function never discovers it).
pub async fn discover_manifold_extension(
    client: &RpcClient,
    creator_contract: Address,
    instance_id: U256,
) -> Result<Address, KairoxError> {
    let extensions = crate::cli::gather::fetch_manifold_extensions(client, creator_contract)
        .await
        .map_err(|e| {
            KairoxError::Session(SessionError::new(format!(
                "could not enumerate extensions registered on creator contract {creator_contract} \
                 via ICreatorCore::getExtensions() -- is this a genuine Manifold creator contract? \
                 ({e})"
            )))
        })?;

    let mut candidates = Vec::new();
    for extension in extensions {
        if probe_claim(client, extension, creator_contract, instance_id)
            .await
            .is_some()
        {
            candidates.push(extension);
        }
    }

    match candidates.len() {
        1 => Ok(candidates[0]),
        0 => Err(KairoxError::Session(SessionError::new(format!(
            "no extension registered on creator contract {creator_contract} responded like a \
             LazyPayableClaim extension for instance id {instance_id} (either none are registered \
             at all, or none matched this instance id); pass --manifold-extension explicitly"
        )))),
        n => Err(KairoxError::Session(SessionError::new(format!(
            "{n} registered extensions on creator contract {creator_contract} all responded like \
             a LazyPayableClaim extension for instance id {instance_id} ({candidates:?}); refusing \
             to guess which one -- pass --manifold-extension explicitly"
        )))),
    }
}

/// An operator-supplied proof of this wallet's inclusion in a gated
/// claim's allowlist. Never manufactured, never brute-forced -- Kairox
/// only ever verifies a proof the operator explicitly provides (from a
/// project's own claim page or Manifold Studio export) against the
/// on-chain `merkleRoot`; an invalid proof fails closed before any
/// signing.
#[derive(Debug, Clone)]
pub struct OperatorManifoldAllowlist {
    pub mint_index: u32,
    pub merkle_proof: Vec<B256>,
}

#[derive(Debug, Clone)]
pub struct ManifoldMintRequest {
    pub chain: ChainInfo,
    /// The shared `LazyPayableClaim` extension contract -- the
    /// `eth_call`/`eth_sendTransaction` target.
    pub extension_contract: Address,
    /// The NFT collection contract the claim mints against.
    pub creator_contract: Address,
    pub instance_id: U256,
    pub wallet: Address,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
    /// Required whenever the resolved claim's `merkleRoot` is nonzero;
    /// ignored (and never required) for a public (`merkleRoot == 0`)
    /// claim.
    pub allowlist: Option<OperatorManifoldAllowlist>,
}

/// The exact `mint()` arguments to send, resolved from the claim and (if
/// gated) the operator-supplied proof -- mirrors
/// `thirdweb_engine::resolve_effective_claim`'s role, specialized to
/// Manifold's simpler ABI (no price/quantity override fields to
/// reconcile, since Manifold's `mint()` carries no such arguments at
/// all -- the claim's own `cost`/`walletMax` always apply as read).
fn resolve_mint_index_and_proof(
    wallet: Address,
    claim: &ManifoldClaim,
    operator_allowlist: Option<&OperatorManifoldAllowlist>,
) -> Result<(u32, Vec<B256>), KairoxError> {
    if !claim.is_gated() {
        // Public claim: mintIndex/merkleProof are never consulted
        // on-chain (verified against LazyPayableClaimCore.sol's
        // non-merkle branch) -- pass the zero/empty sentinel values.
        return Ok((0, vec![]));
    }

    let Some(allowlist) = operator_allowlist else {
        return Err(KairoxError::Session(SessionError::new(
            "this claim requires an allowlist proof (merkleRoot is set), but none was provided; \
             refusing to guess eligibility. Supply one via --allowlist-proof/--manifold-mint-index."
                .to_string(),
        )));
    };

    let leaf = manifold::allowlist_leaf(wallet, allowlist.mint_index);
    if !verify_merkle_proof(&allowlist.merkle_proof, claim.merkle_root, leaf) {
        return Err(KairoxError::Session(SessionError::new(
            "the provided allowlist proof does not verify against this claim's on-chain \
             merkleRoot; refusing to sign against an unverified proof"
                .to_string(),
        )));
    }

    Ok((allowlist.mint_index, allowlist.merkle_proof.clone()))
}

fn supply_error_to_kairox(e: SupplyError) -> KairoxError {
    KairoxError::Supply(e)
}

/// Gather fresh on-chain state, validate every safety invariant, sign, and
/// serialize -- producing a [`PreparedTransaction`]. Fails closed (no
/// broadcast-eligible output) on any missing, ambiguous, or invalid
/// required input. Mirrors
/// `thirdweb_engine::prepare_thirdweb_transaction`'s contract exactly.
///
/// `registry` is the trusted-fingerprint registry [`establish_provenance`]
/// is checked against -- callers pass `manifold_registry::BUILTIN_REGISTRY`
/// in production (empty by design) and an injected test registry in
/// tests.
pub async fn prepare_manifold_transaction(
    client: &RpcClient,
    signer: &dyn Signer,
    request: &ManifoldMintRequest,
    registry: &[ManifoldTrustedFingerprint],
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

    // PROVENANCE: the only route to authorizing a live send -- see
    // `establish_provenance`'s doc comment.
    let fingerprint = establish_provenance(
        client,
        request.chain.chain_id,
        request.extension_contract,
        registry,
    )
    .await?;

    // Independent reads with no data dependency on each other, issued
    // concurrently -- same rationale as the SeaDrop/thirdweb engines' own
    // identical optimization.
    let (
        claim,
        wallet_claimed,
        membership_address,
        block,
        max_priority_fee_per_gas,
        nonce,
        balance,
    ) = tokio::try_join!(
        crate::cli::gather::fetch_manifold_claim(
            client,
            request.extension_contract,
            request.creator_contract,
            request.instance_id,
        ),
        crate::cli::gather::fetch_manifold_total_mints(
            client,
            request.extension_contract,
            request.wallet,
            request.creator_contract,
            request.instance_id,
        ),
        crate::cli::gather::fetch_manifold_membership_address(client, request.extension_contract),
        async { client.latest_block().await.map_err(KairoxError::from) },
        async {
            client
                .max_priority_fee_per_gas()
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .transaction_count(request.wallet)
                .await
                .map_err(KairoxError::from)
        },
        async {
            client
                .get_balance(request.wallet)
                .await
                .map_err(KairoxError::from)
        },
    )?;

    if !claim.is_native_currency() {
        return Err(KairoxError::Manifold(
            crate::protocol::manifold::ManifoldError::Erc20CurrencyUnsupported(claim.erc20),
        ));
    }

    let (mint_index, merkle_proof) =
        resolve_mint_index_and_proof(request.wallet, &claim, request.allowlist.as_ref())?;

    // Best-effort membership-exemption read: if MEMBERSHIP_ADDRESS is
    // configured, check whether this wallet is an active member. A
    // failure here is treated conservatively as "not exempt" (fee
    // included) rather than propagated -- overpaying the flat protocol
    // fee is the safe direction (the contract's own `>=` check never
    // reverts on an overpayment), never underpaying it (which would
    // revert). See `protocol::manifold::required_msg_value`'s doc
    // comment.
    let is_active_member = if membership_address.is_zero() {
        false
    } else {
        crate::cli::gather::fetch_manifold_is_active_member(
            client,
            membership_address,
            request.wallet,
        )
        .await
        .unwrap_or(false)
    };

    // Manifold's mint() is single-token only (see this module's and
    // protocol::manifold's documented scope) -- quantity is always 1.
    const QUANTITY: u64 = 1;
    let wallet_allocation = WalletAllocation {
        max_total_mintable_by_wallet: u64::from(claim.wallet_max),
        already_minted: u64::from(wallet_claimed),
    };
    let collection_supply = CollectionSupply {
        max_supply: if claim.total_max == 0 {
            None
        } else {
            Some(u64::from(claim.total_max))
        },
        current_supply: u64::from(claim.total),
    };
    validate_requested_quantity(QUANTITY, &wallet_allocation, &collection_supply)
        .map_err(supply_error_to_kairox)?;

    let base_fee_per_gas = block.base_fee_per_gas.ok_or_else(|| {
        KairoxError::Session(SessionError::new(
            "chain does not report an EIP-1559 baseFeePerGas; cannot safely price a live \
             transaction"
                .to_string(),
        ))
    })?;
    let max_fee_per_gas = base_fee_per_gas
        .saturating_mul(2)
        .saturating_add(max_priority_fee_per_gas);
    let fees = Eip1559Fees::new(base_fee_per_gas, max_priority_fee_per_gas, max_fee_per_gas)?;

    let value = manifold::required_msg_value(&claim, membership_address, is_active_member);

    let calldata = manifold::encode_mint(
        request.creator_contract,
        request.instance_id,
        mint_index,
        &merkle_proof,
        request.wallet,
    )?;

    let gas_estimate = client
        .estimate_gas(request.wallet, request.extension_contract, &calldata, value)
        .await?;
    let gas_limit = ((gas_estimate as f64) * request.gas_buffer_multiplier.max(1.0)).ceil() as u64;

    let worst_case_gas_cost = fees.worst_case_gas_cost(gas_limit);
    let worst_case_total = worst_case_total_spend(value, worst_case_gas_cost);
    request
        .safety_caps
        .check(value, worst_case_gas_cost, worst_case_total)?;

    if balance < worst_case_total {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::InsufficientBalance,
            format!(
                "wallet balance {balance} wei is insufficient for worst-case total spend \
                 {worst_case_total} wei"
            ),
        )));
    }

    // IMMEDIATELY-BEFORE-SIGNING RE-CHECK: the extension contract could in
    // principle have been replaced/self-destructed since provenance was
    // established (several RPC round trips ago). Mirrors
    // `thirdweb_engine::prepare_thirdweb_transaction`'s identical
    // re-check, placed at the identical point.
    let current_hash =
        resolve_manifold_extension_code_hash(client, request.extension_contract).await?;
    if current_hash != fingerprint.extension_bytecode_hash {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::ProxyImplementationChanged,
            format!(
                "extension contract bytecode hash changed since provenance was established \
                 (expected {}, now {current_hash}); refusing to sign against stale evidence",
                fingerprint.extension_bytecode_hash
            ),
        )));
    }

    let unsigned = UnsignedEip1559Tx {
        chain_id: request.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_limit,
        to: request.extension_contract,
        value,
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
        target: request.extension_contract,
        value,
        calldata_hash: keccak256(&calldata),
        quantity: QUANTITY,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: OffsetDateTime::from_unix_timestamp(claim.start_date as i64)
            .unwrap_or_else(|_| OffsetDateTime::now_utc()),
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    })
}

/// The outcome of a full [`run_manifold_mint`] attempt -- mirrors
/// `thirdweb_engine::ThirdwebMintOutcome`'s shape.
#[derive(Debug)]
pub struct ManifoldMintOutcome {
    pub prepared: PreparedTransaction,
    pub broadcast_results: Vec<crate::execution::broadcast::EndpointBroadcastResult>,
    pub broadcast_summary: crate::execution::broadcast::BroadcastSummary,
    pub receipt_state: Option<crate::execution::receipt::ReceiptState>,
}

/// Prepare, sign, and (unless `rehearsal`) broadcast a Manifold claim,
/// then poll for its receipt. `pool` must already be connected by the
/// caller.
#[allow(clippy::too_many_arguments)]
pub async fn run_manifold_mint(
    pool: &crate::chain::pool::RpcPool,
    signer: &dyn Signer,
    request: &ManifoldMintRequest,
    registry: &[ManifoldTrustedFingerprint],
    health: &crate::chain::benchmark::HealthPolicy,
    receipt_poll_interval: std::time::Duration,
    receipt_timeout: std::time::Duration,
    rehearsal: bool,
) -> Result<ManifoldMintOutcome, KairoxError> {
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::NoVerifiedReadRpc,
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely \
             prepare a Manifold claim transaction"
                .to_string(),
        ))
    })?;
    let send_clients = pool.select_send_endpoints(health);
    if send_clients.is_empty() {
        return Err(KairoxError::Session(SessionError::new(
            "no healthy send-capable RPC endpoint available; refusing to prepare a transaction \
             with nowhere to broadcast it"
                .to_string(),
        )));
    }

    let prepared = prepare_manifold_transaction(read_client, signer, request, registry).await?;

    if rehearsal {
        return Ok(ManifoldMintOutcome {
            prepared,
            broadcast_results: Vec::new(),
            broadcast_summary: crate::execution::broadcast::BroadcastSummary::NotSent,
            receipt_state: None,
        });
    }

    let broadcast_results =
        crate::execution::broadcast::broadcast_to_all(&send_clients, &prepared.broadcast).await;
    let summary = crate::execution::broadcast::summarize_broadcast(&broadcast_results);

    let receipt_state = match &summary {
        crate::execution::broadcast::BroadcastSummary::Confirmed { .. } => Some(
            crate::execution::receipt::poll_receipt(
                read_client,
                prepared.tx_hash,
                request.creator_contract,
                request.wallet,
                1,
                receipt_poll_interval,
                receipt_timeout,
                || {},
            )
            .await,
        ),
        crate::execution::broadcast::BroadcastSummary::AllRejected => None,
        crate::execution::broadcast::BroadcastSummary::Uncertain => {
            return Err(crate::execution::broadcast::uncertain_outcome_error(
                &broadcast_results,
            ));
        }
        crate::execution::broadcast::BroadcastSummary::NotSent => None,
    };

    Ok(ManifoldMintOutcome {
        prepared,
        broadcast_results,
        broadcast_summary: summary,
        receipt_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const WALLET: Address = address!("1111111111111111111111111111111111111111");

    fn public_claim() -> ManifoldClaim {
        ManifoldClaim {
            total: 3,
            total_max: 100,
            wallet_max: 2,
            start_date: 1_700_000_000,
            end_date: 1_800_000_000,
            merkle_root: B256::ZERO,
            cost: U256::from(10_000_000_000_000_000u64),
            payment_receiver: WALLET,
            erc20: Address::ZERO,
        }
    }

    fn gated_claim(root: B256) -> ManifoldClaim {
        ManifoldClaim {
            merkle_root: root,
            ..public_claim()
        }
    }

    #[test]
    fn public_claim_needs_no_proof_and_uses_zero_index() {
        let claim = public_claim();
        let (index, proof) = resolve_mint_index_and_proof(WALLET, &claim, None).unwrap();
        assert_eq!(index, 0);
        assert!(proof.is_empty());
    }

    #[test]
    fn gated_claim_without_a_proof_is_refused() {
        let claim = gated_claim(B256::repeat_byte(0x11));
        let err = resolve_mint_index_and_proof(WALLET, &claim, None).unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[test]
    fn gated_claim_with_an_invalid_proof_is_refused() {
        let claim = gated_claim(B256::repeat_byte(0x22));
        let bogus = OperatorManifoldAllowlist {
            mint_index: 5,
            merkle_proof: vec![B256::repeat_byte(0xAA)],
        };
        let err = resolve_mint_index_and_proof(WALLET, &claim, Some(&bogus)).unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[test]
    fn gated_claim_with_a_verified_single_leaf_proof_is_accepted() {
        let leaf = manifold::allowlist_leaf(WALLET, 7);
        let claim = gated_claim(leaf); // single-leaf tree: leaf == root
        let allowlist = OperatorManifoldAllowlist {
            mint_index: 7,
            merkle_proof: vec![],
        };
        let (index, proof) =
            resolve_mint_index_and_proof(WALLET, &claim, Some(&allowlist)).unwrap();
        assert_eq!(index, 7);
        assert!(proof.is_empty());
    }

    // -----------------------------------------------------------------
    // Real, mock-RPC-backed integration tests for
    // `prepare_manifold_transaction` -- mirrors
    // `thirdweb_engine::tests::prepare_integration`'s exact MockTransport
    // pattern.
    // -----------------------------------------------------------------
    mod prepare_integration {
        use super::*;
        use crate::chain::endpoint::EndpointRole;
        use crate::chain::mock::MockTransport;
        use crate::chain::registry::ChainRegistry;
        use crate::protocol::manifold::ClaimAbi;
        use crate::signing::signer::LocalSigner;
        use alloy_sol_types::SolCall;
        use serde_json::json;

        pub(super) const EXTENSION: Address = address!("00000000000000000000000000000000000e0e0e");
        pub(super) const CREATOR: Address = address!("00000000000000000000000000000000000c0DE0");
        pub(super) const INSTANCE_ID: u64 = 1;

        pub(super) fn signer() -> LocalSigner {
            LocalSigner::from_bytes(keccak256(b"kairox-manifold-engine-test-key").0).unwrap()
        }

        pub(super) struct MockOpts {
            total: u32,
            total_max: u32,
            wallet_max: u32,
            wallet_claimed: u32,
            cost_wei: u128,
            merkle_root: B256,
            erc20: Address,
            membership_address: Address,
            is_active_member: bool,
            nonce_hex: &'static str,
            base_fee_hex: &'static str,
            priority_fee_hex: &'static str,
            balance_hex: &'static str,
            estimate_gas: Result<&'static str, (i64, &'static str)>,
        }

        impl Default for MockOpts {
            fn default() -> Self {
                Self {
                    total: 3,
                    total_max: 100,
                    wallet_max: 2,
                    wallet_claimed: 0,
                    cost_wei: 10_000_000_000_000_000,
                    merkle_root: B256::ZERO,
                    erc20: Address::ZERO,
                    membership_address: Address::ZERO,
                    is_active_member: false,
                    nonce_hex: "0x1",
                    base_fee_hex: "0x3b9aca00",
                    priority_fee_hex: "0x3b9aca00",
                    balance_hex: "0xde0b6b3a7640000",
                    estimate_gas: Ok("0x2bf20"),
                }
            }
        }

        /// Deliberately arbitrary, fixed bytecode -- `establish_provenance`
        /// hashes this directly (no proxy resolution for Manifold) and
        /// `trusted_fingerprint()` below is the matching registry entry
        /// for exactly this hash.
        pub(super) fn mock_extension_bytecode() -> Vec<u8> {
            vec![
                0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10,
            ]
        }

        pub(super) fn trusted_fingerprint() -> ManifoldTrustedFingerprint {
            ManifoldTrustedFingerprint {
                name: "test-fixture",
                chain_id: 1,
                extension_bytecode_hash: keccak256(mock_extension_bytecode()),
            }
        }

        pub(super) fn test_registry() -> Vec<ManifoldTrustedFingerprint> {
            vec![trusted_fingerprint()]
        }

        pub(super) fn build_transport(opts: MockOpts) -> MockTransport {
            build_transport_builder(opts).build()
        }

        pub(super) fn build_transport_builder(
            opts: MockOpts,
        ) -> crate::chain::mock::MockTransportBuilder {
            let claim_abi = ClaimAbi {
                total: opts.total,
                totalMax: opts.total_max,
                walletMax: opts.wallet_max,
                startDate: U256::from(1_700_000_000u64),
                endDate: U256::from(1_800_000_000u64),
                storageProtocol: 3,
                contractVersion: 1,
                identical: true,
                merkleRoot: opts.merkle_root,
                location: "ipfs://abc".to_string(),
                cost: U256::from(opts.cost_wei),
                paymentReceiver: CREATOR,
                erc20: opts.erc20,
                signingAddress: Address::ZERO,
            };
            let claim_hex = format!(
                "0x{}",
                hex::encode(manifold::getClaimCall::abi_encode_returns(&claim_abi))
            );
            let total_mints_hex = format!(
                "0x{}",
                hex::encode(manifold::getTotalMintsCall::abi_encode_returns(
                    &opts.wallet_claimed
                ))
            );
            let membership_address_hex = format!(
                "0x{}",
                hex::encode(manifold::MEMBERSHIP_ADDRESSCall::abi_encode_returns(
                    &opts.membership_address
                ))
            );
            let is_active_member_hex = format!(
                "0x{}",
                hex::encode(manifold::isActiveMemberCall::abi_encode_returns(
                    &opts.is_active_member
                ))
            );

            let builder = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond_eth_call_selector(manifold::getClaimCall::SELECTOR, json!(claim_hex))
                .respond_eth_call_selector(
                    manifold::getTotalMintsCall::SELECTOR,
                    json!(total_mints_hex),
                )
                .respond_eth_call_selector(
                    manifold::MEMBERSHIP_ADDRESSCall::SELECTOR,
                    json!(membership_address_hex),
                )
                .respond_eth_call_selector(
                    manifold::isActiveMemberCall::SELECTOR,
                    json!(is_active_member_hex),
                )
                .respond(
                    "eth_getBlockByNumber",
                    json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": opts.base_fee_hex}),
                )
                .respond("eth_maxPriorityFeePerGas", json!(opts.priority_fee_hex))
                .respond("eth_getTransactionCount", json!(opts.nonce_hex))
                .respond("eth_getBalance", json!(opts.balance_hex))
                .respond(
                    "eth_getCode",
                    json!(format!("0x{}", hex::encode(mock_extension_bytecode()))),
                );

            match opts.estimate_gas {
                Ok(hex_value) => builder.respond("eth_estimateGas", json!(hex_value)),
                Err((code, message)) => builder.error("eth_estimateGas", code, message),
            }
        }

        async fn connect(opts: MockOpts) -> RpcClient {
            let transport = build_transport(opts);
            RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap()
        }

        pub(super) fn request(wallet: Address) -> ManifoldMintRequest {
            ManifoldMintRequest {
                chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
                extension_contract: EXTENSION,
                creator_contract: CREATOR,
                instance_id: U256::from(INSTANCE_ID),
                wallet,
                gas_buffer_multiplier: 1.2,
                safety_caps: SafetyCaps {
                    max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                    max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                    max_total_spend: U256::from(1_000_000_000_000_000_000u128),
                },
                allowlist: None,
            }
        }

        #[tokio::test]
        async fn public_claim_native_mint_prepares_and_signs_successfully() {
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let prepared =
                prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                    .await
                    .unwrap();
            assert_eq!(prepared.target, EXTENSION);
            // cost + MINT_FEE_WEI (no membership configured)
            assert_eq!(
                prepared.value,
                U256::from(10_000_000_000_000_000u128) + manifold::MINT_FEE_WEI
            );
            assert_eq!(prepared.wallet, wallet);
        }

        #[tokio::test]
        async fn active_member_omits_the_fee() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                membership_address: address!("dddddddddddddddddddddddddddddddddddddddd"),
                is_active_member: true,
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let prepared =
                prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                    .await
                    .unwrap();
            assert_eq!(prepared.value, U256::from(10_000_000_000_000_000u128));
        }

        #[tokio::test]
        async fn wrong_signing_key_is_rejected_before_any_read() {
            let s = signer();
            let wrong_wallet = address!("9999999999999999999999999999999999999999");
            let client = connect(MockOpts::default()).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wrong_wallet), &[])
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                KairoxError::Session(SessionError {
                    kind: SessionErrorKind::WalletKeyMismatch,
                    ..
                })
            ));
        }

        #[tokio::test]
        async fn no_trusted_fingerprint_refuses_to_authorize_a_live_send() {
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &[])
                .await
                .unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("no trusted implementation fingerprint"),
                "expected a clear provenance-not-established message, got: {message}"
            );
        }

        #[tokio::test]
        async fn wrong_bytecode_hash_fingerprint_does_not_authorize() {
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let wrong_registry = vec![ManifoldTrustedFingerprint {
                name: "wrong",
                chain_id: 1,
                extension_bytecode_hash: B256::repeat_byte(0xEE),
            }];
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &wrong_registry)
                .await
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("no trusted implementation fingerprint")
            );
        }

        #[tokio::test]
        async fn erc20_claim_is_rejected() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                erc20: address!("2222222222222222222222222222222222222222"),
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(err, KairoxError::Manifold(_)));
        }

        #[tokio::test]
        async fn exhausted_wallet_allocation_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                wallet_max: 1,
                wallet_claimed: 1,
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(err, KairoxError::Supply(_)));
        }

        #[tokio::test]
        async fn sold_out_collection_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                total_max: 10,
                total: 10,
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(err, KairoxError::Supply(_)));
        }

        #[tokio::test]
        async fn insufficient_balance_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                balance_hex: "0x0",
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                KairoxError::Session(SessionError {
                    kind: SessionErrorKind::InsufficientBalance,
                    ..
                })
            ));
        }

        #[tokio::test]
        async fn gated_claim_without_a_proof_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                merkle_root: B256::repeat_byte(0x33),
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(err, KairoxError::Session(_)));
        }

        #[tokio::test]
        async fn gated_claim_with_a_valid_proof_prepares_and_signs_successfully() {
            let s = signer();
            let wallet = s.address();
            let leaf = manifold::allowlist_leaf(wallet, 9);
            let opts = MockOpts {
                merkle_root: leaf, // single-leaf tree: leaf == root
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let mut req = request(wallet);
            req.allowlist = Some(OperatorManifoldAllowlist {
                mint_index: 9,
                merkle_proof: vec![],
            });
            let prepared = prepare_manifold_transaction(&client, &s, &req, &test_registry())
                .await
                .unwrap();
            assert_eq!(
                prepared.value,
                U256::from(10_000_000_000_000_000u128) + manifold::MINT_FEE_MERKLE_WEI
            );
        }

        #[tokio::test]
        async fn implementation_changing_after_provenance_is_established_is_rejected_before_signing()
         {
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let trusted_bytecode = mock_extension_bytecode();
            let changed_bytecode: Vec<u8> = vec![0x11, 0x22, 0x33];

            let mut transport = build_transport_builder(MockOpts::default());
            transport = transport.respond_dynamic("eth_getCode", move |_params| {
                let n = call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let bytecode = if n == 0 {
                    &trusted_bytecode
                } else {
                    &changed_bytecode
                };
                serde_json::json!(format!("0x{}", hex::encode(bytecode)))
            });
            let client = RpcClient::connect(
                Box::new(transport.build()),
                1,
                EndpointRole::ReadWrite,
                None,
            )
            .await
            .unwrap();

            let s = signer();
            let wallet = s.address();
            let err = prepare_manifold_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                KairoxError::Session(SessionError {
                    kind: SessionErrorKind::ProxyImplementationChanged,
                    ..
                })
            ));
        }
    }

    mod run_mint_integration {
        use super::prepare_integration::*;
        use super::*;
        use crate::chain::benchmark::HealthPolicy;
        use crate::chain::endpoint::EndpointRole;
        use crate::chain::mock::MockTransport;
        use crate::chain::pool::RpcPool;
        use serde_json::{Value, json};

        fn tx_hash_topic(addr: Address) -> [u8; 32] {
            let mut t = [0u8; 32];
            t[12..32].copy_from_slice(addr.as_slice());
            t
        }

        async fn pool_with_transport(transport: MockTransport) -> RpcPool {
            let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap();
            RpcPool::from_clients(1, vec![client])
        }

        fn transport_with_broadcast(wallet: Address) -> MockTransport {
            build_transport_builder(MockOpts::default())
                .echo_raw_transaction_hash()
                .respond_dynamic("eth_getTransactionReceipt", move |params| {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [{
                            "address": CREATOR.to_string(),
                            "topics": [
                                format!(
                                    "0x{}",
                                    hex::encode(keccak256(b"Transfer(address,address,uint256)"))
                                ),
                                format!("0x{}", hex::encode([0u8; 32])),
                                format!("0x{}", hex::encode(tx_hash_topic(wallet))),
                                format!("0x{}", hex::encode(U256::from(1u64).to_be_bytes::<32>())),
                            ],
                            "data": "0x"
                        }]
                    })
                })
                .build()
        }

        #[tokio::test]
        async fn rehearsal_prepares_and_signs_but_never_broadcasts() {
            let s = signer();
            let wallet = s.address();
            let pool = pool_with_transport(build_transport(MockOpts::default())).await;
            let outcome = run_manifold_mint(
                &pool,
                &s,
                &request(wallet),
                &test_registry(),
                &HealthPolicy::default(),
                std::time::Duration::from_millis(10),
                std::time::Duration::from_secs(1),
                true,
            )
            .await
            .unwrap();
            assert_eq!(
                outcome.broadcast_summary,
                crate::execution::broadcast::BroadcastSummary::NotSent
            );
            assert!(outcome.receipt_state.is_none());
            assert!(outcome.broadcast_results.is_empty());
        }

        #[tokio::test]
        async fn a_real_send_broadcasts_exactly_once_and_confirms_the_receipt() {
            let s = signer();
            let wallet = s.address();
            let pool = pool_with_transport(transport_with_broadcast(wallet)).await;
            let outcome = run_manifold_mint(
                &pool,
                &s,
                &request(wallet),
                &test_registry(),
                &HealthPolicy::default(),
                std::time::Duration::from_millis(10),
                std::time::Duration::from_secs(2),
                false,
            )
            .await
            .unwrap();
            assert_eq!(outcome.broadcast_results.len(), 1);
            assert!(matches!(
                outcome.receipt_state,
                Some(crate::execution::receipt::ReceiptState::ConfirmedSuccess { .. })
            ));
        }
    }

    mod discovery_tests {
        use super::*;
        use crate::chain::endpoint::EndpointRole;
        use crate::chain::mock::MockTransport;
        use crate::protocol::manifold::{self, ClaimAbi};
        use alloy_sol_types::SolCall;
        use serde_json::json;

        const CREATOR: Address = address!("00000000000000000000000000000000000c0DE1");
        const CANDIDATE_A: Address = address!("000000000000000000000000000000000000aAaA");
        const CANDIDATE_B: Address = address!("000000000000000000000000000000000000bBbB");
        const NON_CLAIM_EXTENSION: Address = address!("000000000000000000000000000000000000cCcC");
        const INSTANCE_ID: U256 = U256::from_limbs([1, 0, 0, 0]);

        fn sample_claim_hex() -> String {
            let claim_abi = ClaimAbi {
                total: 0,
                totalMax: 100,
                walletMax: 0,
                startDate: U256::from(1_700_000_000u64),
                endDate: U256::from(1_800_000_000u64),
                storageProtocol: 3,
                contractVersion: 1,
                identical: true,
                merkleRoot: B256::ZERO,
                location: "ipfs://abc".to_string(),
                cost: U256::ZERO,
                paymentReceiver: CREATOR,
                erc20: Address::ZERO,
                signingAddress: Address::ZERO,
            };
            format!(
                "0x{}",
                hex::encode(manifold::getClaimCall::abi_encode_returns(&claim_abi))
            )
        }

        /// Builds a mock where `getExtensions()` on `CREATOR` returns
        /// `extensions`, and `getClaim(CREATOR, INSTANCE_ID)` succeeds only
        /// against addresses in `claim_responders` -- everything else
        /// reverts, exactly as a genuine non-LazyPayableClaim extension
        /// (or an unrelated contract) would.
        async fn client_with_extensions(
            extensions: Vec<Address>,
            claim_responders: Vec<Address>,
        ) -> RpcClient {
            let get_extensions_hex = format!(
                "0x{}",
                hex::encode(manifold::getExtensionsCall::abi_encode_returns(&extensions))
            );
            let claim_hex = sample_claim_hex();
            let get_extensions_sel =
                format!("0x{}", hex::encode(manifold::getExtensionsCall::SELECTOR));
            let get_claim_sel = format!("0x{}", hex::encode(manifold::getClaimCall::SELECTOR));
            let transport = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond_dynamic_result("eth_call", move |params| {
                    let to = params
                        .get(0)
                        .and_then(|c| c.get("to"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    let data = params
                        .get(0)
                        .and_then(|c| c.get("data"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0x");
                    if data.starts_with(&get_extensions_sel) {
                        return Ok(json!(get_extensions_hex));
                    }
                    if data.starts_with(&get_claim_sel) {
                        let target: Address = to.parse().unwrap();
                        return if claim_responders.contains(&target) {
                            Ok(json!(claim_hex))
                        } else {
                            Err((-32000, "execution reverted".into()))
                        };
                    }
                    Err((-32601, "unexpected selector in discovery test".into()))
                })
                .build();
            RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn exactly_one_candidate_resolves() {
            let client = client_with_extensions(vec![CANDIDATE_A], vec![CANDIDATE_A]).await;
            let found = discover_manifold_extension(&client, CREATOR, INSTANCE_ID)
                .await
                .unwrap();
            assert_eq!(found, CANDIDATE_A);
        }

        #[tokio::test]
        async fn zero_candidates_refuses_rather_than_guessing() {
            let client = client_with_extensions(vec![NON_CLAIM_EXTENSION], vec![]).await;
            let err = discover_manifold_extension(&client, CREATOR, INSTANCE_ID)
                .await
                .unwrap_err();
            let message = format!("{err}");
            assert!(message.contains("--manifold-extension"));
        }

        #[tokio::test]
        async fn multiple_candidates_refuses_rather_than_guessing() {
            let client = client_with_extensions(
                vec![CANDIDATE_A, CANDIDATE_B],
                vec![CANDIDATE_A, CANDIDATE_B],
            )
            .await;
            let err = discover_manifold_extension(&client, CREATOR, INSTANCE_ID)
                .await
                .unwrap_err();
            let message = format!("{err}");
            assert!(message.contains("--manifold-extension"));
        }

        #[tokio::test]
        async fn no_extensions_registered_at_all_refuses() {
            let client = client_with_extensions(vec![], vec![]).await;
            let err = discover_manifold_extension(&client, CREATOR, INSTANCE_ID)
                .await
                .unwrap_err();
            let message = format!("{err}");
            assert!(message.contains("--manifold-extension"));
        }
    }
}
