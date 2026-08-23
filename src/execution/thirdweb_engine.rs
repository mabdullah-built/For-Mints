//! Thirdweb Drop (`ClaimCondition`-based) mint execution -- the second
//! fully on-chain protocol-specific engine, alongside the native SeaDrop
//! engine ([`super::live`]). Unlike the OpenSea Drops engine
//! ([`super::opensea_engine`]), every input here is on-chain and
//! authoritative -- there is no untrusted external API response to
//! validate. The one exception is a gated phase's allowlist proof: an
//! operator-supplied [`OperatorAllowlistProof`], always independently
//! verified against the on-chain `merkleRoot` (never trusted merely
//! because it was supplied) before it can influence anything.
//!
//! v0.8 Phase B scope: ERC-721 claims, native-currency payment only. A
//! non-native `currency` on the resolved claim condition is refused
//! (`ThirdwebError::Erc20CurrencyUnsupported`) rather than guessed at.
//! ERC-1155 claims are deferred (see [`crate::protocol::thirdweb`]'s
//! module doc comment) since their per-`tokenId` claim-condition/supply
//! semantics have not yet been verified to the same standard.
//!
//! No elaborate multi-checkpoint scheduler yet (unlike [`super::live`]'s
//! StateCheck/Refresh/Finalize dance) -- this is a first, functionally
//! complete and safe pass: every required value (claim condition, wallet
//! allocation, nonce, fees, balance) is read fresh, once, immediately
//! before signing. Early pool warming and a T-10/T-3/T-1 refresh
//! schedule are explicit later-phase performance work, not required for
//! correctness.

use alloy_primitives::{Address, B256, U256, keccak256};
use time::OffsetDateTime;

use crate::chain::registry::ChainInfo;
use crate::chain::rpc::{PreparedBroadcast, RpcClient};
use crate::domain::fees::{Eip1559Fees, SafetyCaps, worst_case_total_spend};
use crate::domain::supply::{
    CollectionSupply, SupplyError, WalletAllocation, validate_requested_quantity,
};
use crate::protocol::seadrop_crypto::verify_merkle_proof;
use crate::protocol::thirdweb::{self, AllowlistProofAbi, ClaimCondition, NATIVE_TOKEN};
use crate::signing::signer::Signer;
use crate::signing::transaction::UnsignedEip1559Tx;

use super::errors::{KairoxError, SessionError, SessionErrorKind};
use super::prepared::PreparedTransaction;
use super::thirdweb_registry::{ThirdwebFlavor, ThirdwebTrustedFingerprint, find_fingerprint};

/// Resolves the address whose runtime bytecode is the real target of
/// trust: an EIP-1167 minimal-proxy ("clone") implementation if the
/// target's own bytecode matches that exact template (thirdweb's actual
/// factory-clone deployment pattern -- see
/// `protocol::erc_standards`'s module doc comment for why this is
/// checked, not just EIP-1967), otherwise an EIP-1967 storage-slot proxy
/// implementation (defensive, in case of a future/nonstandard
/// upgradeable deployment), otherwise the target's own address (not a
/// recognized proxy pattern at all). Returns the resolved address and
/// `keccak256` of its runtime bytecode.
pub(crate) async fn resolve_thirdweb_implementation_and_code_hash(
    client: &RpcClient,
    target: Address,
) -> Result<(Address, B256), KairoxError> {
    let code = client.get_code(target).await?;
    if let Some(implementation) =
        crate::protocol::erc_standards::eip1167_clone_implementation(&code)
    {
        let implementation_code = client.get_code(implementation).await?;
        return Ok((implementation, keccak256(&implementation_code)));
    }
    if let Some(implementation) =
        crate::protocol::erc_standards::eip1967_implementation(client, target).await?
    {
        let implementation_code = client.get_code(implementation).await?;
        return Ok((implementation, keccak256(&implementation_code)));
    }
    Ok((target, keccak256(&code)))
}

/// The **only** route to authorizing a real (non-dry-run) thirdweb live
/// send -- see `execution::thirdweb_registry`'s module doc comment for
/// the full rationale. Selector compatibility and a successful
/// `eth_call` are never sufficient: a custom contract can inherit a
/// thirdweb Drop base extension and override its execution-affecting
/// hooks (`_beforeClaim`, `_afterClaim`, `_collectPriceOnClaim`,
/// `_transferTokensOnClaim`, `_dropMsgSender`), and Kairox cannot
/// independently verify those overrides do nothing unexpected. Resolves
/// the real implementation (proxy-aware), hashes its runtime bytecode,
/// and requires an exact match against `registry` -- with the registry
/// entry itself declaring which ABI flavor that verified bytecode
/// implements (never inferred separately by selector-probing for the
/// live-send path). No match -- including the default, empty
/// `thirdweb_registry::BUILTIN_REGISTRY` -- means no live send is
/// authorized, full stop; this function returns an error, not a guess.
pub async fn establish_provenance(
    client: &RpcClient,
    chain_id: crate::chain::registry::ChainId,
    drop_contract: Address,
    registry: &[ThirdwebTrustedFingerprint],
) -> Result<ThirdwebTrustedFingerprint, KairoxError> {
    let (_implementation, bytecode_hash) =
        resolve_thirdweb_implementation_and_code_hash(client, drop_contract).await?;
    find_fingerprint(registry, chain_id, bytecode_hash).ok_or_else(|| {
        KairoxError::Session(SessionError::new(format!(
            "no trusted implementation fingerprint found for this contract on chain {chain_id} \
             (resolved implementation bytecode hash {bytecode_hash:#x}); refusing to authorize a \
             live send against unverified thirdweb execution semantics. Selector compatibility \
             and a successful read are not proof this contract's claim logic is unmodified \
             vanilla thirdweb code -- see execution::thirdweb_registry."
        )))
    })
}

/// Best-effort flavor detection by selector-probing -- used **only** for
/// read-only dry-run reporting, never to authorize a live send (see
/// [`establish_provenance`] for that). Tries the multi-phase ERC-721
/// getter first, then the single-phase getter; a genuine decode failure
/// or revert from either is treated as "not this flavor" (mirroring
/// `resolver_adapters::discover_public_stage`'s identical philosophy for
/// SeaDrop), not propagated as an error, so an unrelated or unsupported
/// (e.g. ERC-1155) contract cleanly falls through to `None` rather than
/// aborting.
pub async fn probe_flavor(
    client: &RpcClient,
    drop_contract: Address,
) -> Option<(ThirdwebFlavor, ClaimCondition)> {
    if let Ok(condition_id) =
        crate::cli::gather::fetch_thirdweb_active_claim_condition_id(client, drop_contract).await
        && let Ok(condition) = crate::cli::gather::fetch_thirdweb_claim_condition_by_id(
            client,
            drop_contract,
            condition_id,
        )
        .await
    {
        return Some((ThirdwebFlavor::DropMultiPhase721, condition));
    }
    if let Ok(condition) =
        crate::cli::gather::fetch_thirdweb_claim_condition_single_phase(client, drop_contract).await
    {
        return Some((ThirdwebFlavor::DropSinglePhase721, condition));
    }
    None
}

/// Flavor-aware read of the active claim condition and this wallet's
/// already-claimed count, dispatching to the correct pair of getters for
/// `flavor` -- never assumes one flavor's getter shape works for the
/// other (see `protocol::thirdweb`'s module doc comment).
async fn fetch_condition_and_wallet_claimed(
    client: &RpcClient,
    drop_contract: Address,
    wallet: Address,
    flavor: ThirdwebFlavor,
) -> Result<(ClaimCondition, U256), KairoxError> {
    match flavor {
        ThirdwebFlavor::DropMultiPhase721 => {
            let condition_id =
                crate::cli::gather::fetch_thirdweb_active_claim_condition_id(client, drop_contract)
                    .await
                    .map_err(|_| {
                        KairoxError::Session(SessionError::new(
                    "thirdweb Drop contract reports no active claim condition; nothing to mint \
                     right now"
                        .to_string(),
                ))
                    })?;
            let (condition, wallet_claimed) = tokio::try_join!(
                crate::cli::gather::fetch_thirdweb_claim_condition_by_id(
                    client,
                    drop_contract,
                    condition_id
                ),
                crate::cli::gather::fetch_thirdweb_supply_claimed_by_wallet(
                    client,
                    drop_contract,
                    condition_id,
                    wallet,
                ),
            )?;
            Ok((condition, wallet_claimed))
        }
        ThirdwebFlavor::DropSinglePhase721 => {
            let (condition, wallet_claimed) = tokio::try_join!(
                crate::cli::gather::fetch_thirdweb_claim_condition_single_phase(
                    client,
                    drop_contract
                ),
                crate::cli::gather::fetch_thirdweb_supply_claimed_by_wallet_single_phase(
                    client,
                    drop_contract,
                    wallet,
                ),
            )?;
            Ok((condition, wallet_claimed))
        }
    }
}

/// The sentinel the real contract itself uses to mean "do not override
/// the claim condition's own price/currency" -- verified directly
/// against `Drop.sol`'s `verifyClaim`
/// (`_allowlistProof.pricePerToken != type(uint256).max`). Deliberately
/// **not** zero: a zero price is a legitimate free-mint override, and
/// treating it as "no override" would have been a real fund-safety bug
/// (an earlier draft of this engine assumed a zero-based sentinel before
/// this was verified against source).
pub const NO_PRICE_OVERRIDE: U256 = U256::MAX;

/// An operator-supplied proof of this wallet's inclusion in a gated
/// phase's allowlist. Never manufactured, never brute-forced -- Kairox
/// only ever verifies a proof the operator explicitly provides (from a
/// project's own claim page, thirdweb dashboard export, or equivalent
/// legitimate source) against the on-chain `merkleRoot`; an invalid
/// proof fails closed before any signing.
#[derive(Debug, Clone)]
pub struct OperatorAllowlistProof {
    pub proof: Vec<B256>,
    /// `0` means "use the claim condition's own per-wallet limit" --
    /// verified against `Drop.sol` (a nonzero value always overrides).
    pub quantity_limit_per_wallet: U256,
    /// [`NO_PRICE_OVERRIDE`] means "use the claim condition's own price".
    pub price_per_token: U256,
    /// Only consulted when `price_per_token != NO_PRICE_OVERRIDE`.
    pub currency: Address,
}

#[derive(Debug, Clone)]
pub struct ThirdwebMintRequest {
    pub chain: ChainInfo,
    /// The thirdweb Drop contract -- both the NFT and its claim logic
    /// live in this one deployment, unlike SeaDrop's separate
    /// protocol-singleton/collection split.
    pub drop_contract: Address,
    pub wallet: Address,
    pub quantity: u64,
    pub gas_buffer_multiplier: f64,
    pub safety_caps: SafetyCaps,
    /// Required whenever the resolved claim condition's `merkleRoot` is
    /// nonzero; ignored (and never required) for a public
    /// (`merkleRoot == 0`) phase.
    pub allowlist_proof: Option<OperatorAllowlistProof>,
}

/// The exact top-level `claim()` arguments the real contract itself will
/// independently recompute and compare -- see `resolve_effective_claim`'s
/// doc comment for why every field here must exactly match what
/// `Drop.sol`'s own `verifyClaim` derives.
#[derive(Debug)]
struct ResolvedClaim {
    price_per_token: U256,
    currency: Address,
    allowlist_proof_abi: AllowlistProofAbi,
    wallet_limit: u64,
}

/// Reproduces `Drop.sol`'s own `verifyClaim` override logic exactly (see
/// this module's and [`OperatorAllowlistProof`]'s doc comments for the
/// verified sentinels): the contract independently recomputes
/// `claimPrice`/`claimCurrency`/`claimLimit` from the claim condition and
/// (if the proof verifies) the allowlist proof, then reverts
/// (`DropClaimInvalidTokenPrice`) unless the caller's top-level
/// `currency`/`pricePerToken` arguments match exactly. Kairox must derive
/// the identical values here, or the real transaction simply reverts.
fn resolve_effective_claim(
    wallet: Address,
    condition: &ClaimCondition,
    operator_proof: Option<&OperatorAllowlistProof>,
) -> Result<ResolvedClaim, KairoxError> {
    if condition.merkle_root.is_zero() {
        // Public phase: no allowlist proof required or consulted. The
        // "no override" sentinel proof is passed through unused (the
        // real contract's own merkle check against a zero root, for any
        // real wallet's nonzero leaf, never succeeds -- isOverride stays
        // false regardless of what is passed here).
        return Ok(ResolvedClaim {
            price_per_token: condition.price_per_token,
            currency: condition.currency,
            allowlist_proof_abi: AllowlistProofAbi {
                proof: vec![],
                quantityLimitPerWallet: U256::ZERO,
                pricePerToken: NO_PRICE_OVERRIDE,
                currency: Address::ZERO,
            },
            wallet_limit: clamp_to_u64(condition.quantity_limit_per_wallet),
        });
    }

    let Some(proof) = operator_proof else {
        return Err(KairoxError::Session(SessionError::new(
            "this claim condition requires an allowlist proof (merkleRoot is set), but none was \
             provided; refusing to guess eligibility. Supply one via the operator-provided \
             allowlist proof flag."
                .to_string(),
        )));
    };

    let leaf = thirdweb::allowlist_leaf(
        wallet,
        proof.quantity_limit_per_wallet,
        proof.price_per_token,
        proof.currency,
    );
    if !verify_merkle_proof(&proof.proof, condition.merkle_root, leaf) {
        return Err(KairoxError::Session(SessionError::new(
            "the provided allowlist proof does not verify against this claim condition's \
             on-chain merkleRoot; refusing to sign against an unverified proof"
                .to_string(),
        )));
    }

    // isOverride is true (the proof verified) from here on -- reproduce
    // Drop.sol's exact override conditions.
    let price_per_token = if proof.price_per_token != NO_PRICE_OVERRIDE {
        proof.price_per_token
    } else {
        condition.price_per_token
    };
    let currency = if proof.price_per_token != NO_PRICE_OVERRIDE && !proof.currency.is_zero() {
        proof.currency
    } else {
        condition.currency
    };
    let wallet_limit = if !proof.quantity_limit_per_wallet.is_zero() {
        clamp_to_u64(proof.quantity_limit_per_wallet)
    } else {
        clamp_to_u64(condition.quantity_limit_per_wallet)
    };

    Ok(ResolvedClaim {
        price_per_token,
        currency,
        allowlist_proof_abi: AllowlistProofAbi {
            proof: proof.proof.clone(),
            quantityLimitPerWallet: proof.quantity_limit_per_wallet,
            pricePerToken: proof.price_per_token,
            currency: proof.currency,
        },
        wallet_limit,
    })
}

/// A `U256` cap value that does not fit in `u64` is treated as "no
/// practical limit" (clamped to `u64::MAX`), never an error -- unlike an
/// exact *count* (already-claimed/already-minted), which must convert
/// exactly or fail closed (see `exact_u64`). A project setting an
/// absurdly large per-wallet/collection cap intends "effectively
/// unbounded", not a value Kairox should choke on.
fn clamp_to_u64(v: U256) -> u64 {
    v.try_into().unwrap_or(u64::MAX)
}

/// An exact count (a real already-claimed/already-minted number) must
/// convert exactly -- overflow here would mean a `U256` count larger
/// than the entire history of Ethereum could plausibly produce, a red
/// flag worth failing closed on rather than silently clamping.
fn exact_u64(v: U256) -> Result<u64, KairoxError> {
    v.try_into().map_err(|_| {
        KairoxError::Thirdweb(crate::protocol::thirdweb::ThirdwebError::AbiDecode(
            "on-chain supply/allocation count does not fit safely in a u64 conversion".to_string(),
        ))
    })
}

/// Gather fresh on-chain state, validate every safety invariant, sign,
/// and serialize -- producing a [`PreparedTransaction`]. Fails closed (no
/// broadcast-eligible output) on any missing, ambiguous, or invalid
/// required input. Mirrors [`super::prepared::prepare_live_transaction`]'s
/// contract exactly (same required-fresh-reads philosophy), specialized
/// to the thirdweb Drop interface.
///
/// `registry` is the trusted-fingerprint registry [`establish_provenance`]
/// is checked against -- callers pass `thirdweb_registry::BUILTIN_REGISTRY`
/// in production (empty by design; see that module's doc comment) and an
/// injected test registry in tests, exactly mirroring
/// `GenericVerifiedContractAdapter`'s identical pattern.
pub async fn prepare_thirdweb_transaction(
    client: &RpcClient,
    signer: &dyn Signer,
    request: &ThirdwebMintRequest,
    registry: &[ThirdwebTrustedFingerprint],
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
    // `establish_provenance`'s doc comment. Determines the flavor
    // authoritatively from the matched registry entry, never from
    // separate selector-probing (which is best-effort and reserved for
    // dry-run reporting only, see `probe_flavor`).
    let fingerprint = establish_provenance(
        client,
        request.chain.chain_id,
        request.drop_contract,
        registry,
    )
    .await?;
    let flavor = fingerprint.flavor;

    // Flavor-aware reads (the active claim condition and this wallet's
    // already-claimed count) alongside every other independent read with
    // no data dependency on the others -- issued concurrently, same
    // rationale as the SeaDrop/OpenSea engines' own identical
    // optimization.
    let (condition_and_claimed, block, max_priority_fee_per_gas, nonce, balance) = tokio::try_join!(
        fetch_condition_and_wallet_claimed(client, request.drop_contract, request.wallet, flavor),
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
    let (condition, wallet_claimed) = condition_and_claimed;

    let resolved =
        resolve_effective_claim(request.wallet, &condition, request.allowlist_proof.as_ref())?;

    if resolved.currency != NATIVE_TOKEN {
        return Err(KairoxError::Thirdweb(
            crate::protocol::thirdweb::ThirdwebError::Erc20CurrencyUnsupported(resolved.currency),
        ));
    }

    // Reuses the exact same wallet-allocation/collection-supply
    // arithmetic and error taxonomy (AllocationExceeded/SupplyExhausted)
    // the native SeaDrop engine uses -- consistent operator-facing error
    // codes regardless of which protocol adapter is executing.
    let wallet_allocation = WalletAllocation {
        max_total_mintable_by_wallet: resolved.wallet_limit,
        already_minted: exact_u64(wallet_claimed)?,
    };
    let collection_supply = CollectionSupply {
        max_supply: Some(clamp_to_u64(condition.max_claimable_supply)),
        current_supply: exact_u64(condition.supply_claimed)?,
    };
    validate_requested_quantity(request.quantity, &wallet_allocation, &collection_supply)
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

    let value = resolved
        .price_per_token
        .checked_mul(U256::from(request.quantity))
        .ok_or_else(|| {
            KairoxError::Session(SessionError::new(
                "price_per_token * quantity overflows U256; refusing to proceed".to_string(),
            ))
        })?;

    let calldata = thirdweb::encode_claim_721(
        request.wallet,
        U256::from(request.quantity),
        resolved.currency,
        resolved.price_per_token,
        resolved.allowlist_proof_abi,
    )?;

    let gas_estimate = client
        .estimate_gas(request.wallet, request.drop_contract, &calldata, value)
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

    // IMMEDIATELY-BEFORE-SIGNING RE-CHECK: everything above this point
    // took real time (several RPC round trips) since provenance was
    // established. A proxy that legitimately matched the trusted
    // registry at that point may have since been upgraded to a different
    // implementation -- signing against stale evidence would execute
    // code nobody verified. Mirrors
    // `generic_engine::prepare_generic_transaction`'s identical re-check,
    // placed at the identical point (immediately before constructing the
    // unsigned transaction).
    let (_implementation, current_hash) =
        resolve_thirdweb_implementation_and_code_hash(client, request.drop_contract).await?;
    if current_hash != fingerprint.implementation_bytecode_hash {
        return Err(KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::ProxyImplementationChanged,
            format!(
                "implementation bytecode hash changed since provenance was established \
                 (expected {}, now {current_hash}); refusing to sign against stale evidence",
                fingerprint.implementation_bytecode_hash
            ),
        )));
    }

    let unsigned = UnsignedEip1559Tx {
        chain_id: request.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        max_fee_per_gas: fees.max_fee_per_gas(),
        gas_limit,
        to: request.drop_contract,
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
        target: request.drop_contract,
        value,
        calldata_hash: keccak256(&calldata),
        quantity: request.quantity,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas(),
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas(),
        stage_start: OffsetDateTime::from_unix_timestamp(condition.start_timestamp as i64)
            .unwrap_or_else(|_| OffsetDateTime::now_utc()),
        signing_hash,
        raw_signed_bytes,
        tx_hash,
        broadcast,
        broadcast_prepare_ms,
        prepared_at: OffsetDateTime::now_utc(),
    })
}

fn supply_error_to_kairox(e: SupplyError) -> KairoxError {
    KairoxError::Supply(e)
}

/// The outcome of a full [`run_thirdweb_mint`] attempt -- mirrors
/// [`super::live::LiveMintOutcome`]'s shape (minus fields this engine
/// doesn't yet have a concept of, like prewarm scheduling).
#[derive(Debug)]
pub struct ThirdwebMintOutcome {
    pub prepared: PreparedTransaction,
    pub broadcast_results: Vec<crate::execution::broadcast::EndpointBroadcastResult>,
    pub broadcast_summary: crate::execution::broadcast::BroadcastSummary,
    pub receipt_state: Option<crate::execution::receipt::ReceiptState>,
}

/// Prepare, sign, and (unless `rehearsal`) broadcast a thirdweb claim,
/// then poll for its receipt. `pool` must already be connected (and
/// ideally warmed) by the caller -- this function does no benchmarking
/// or rewarming of its own, matching this module's documented "no
/// elaborate scheduler yet" scope.
#[allow(clippy::too_many_arguments)]
pub async fn run_thirdweb_mint(
    pool: &crate::chain::pool::RpcPool,
    signer: &dyn Signer,
    request: &ThirdwebMintRequest,
    registry: &[ThirdwebTrustedFingerprint],
    health: &crate::chain::benchmark::HealthPolicy,
    receipt_poll_interval: std::time::Duration,
    receipt_timeout: std::time::Duration,
    rehearsal: bool,
) -> Result<ThirdwebMintOutcome, KairoxError> {
    let read_client = pool.preferred_read().ok_or_else(|| {
        KairoxError::Session(SessionError::with_kind(
            SessionErrorKind::NoVerifiedReadRpc,
            "no healthy, chain-verified read-capable RPC endpoint available; cannot safely \
             prepare a thirdweb claim transaction"
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

    let prepared = prepare_thirdweb_transaction(read_client, signer, request, registry).await?;

    // REHEARSAL: everything above (fresh state, validation, real local
    // signing/serialization) already happened exactly as it would for a
    // real send. Stop here -- `eth_sendRawTransaction` is never called.
    if rehearsal {
        return Ok(ThirdwebMintOutcome {
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
                request.drop_contract,
                request.wallet,
                request.quantity,
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
        // Unreachable in practice -- see live.rs's identical comment on
        // its own exhaustive match of the same enum.
        crate::execution::broadcast::BroadcastSummary::NotSent => None,
    };

    Ok(ThirdwebMintOutcome {
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

    fn public_condition() -> ClaimCondition {
        ClaimCondition {
            start_timestamp: 1_700_000_000,
            max_claimable_supply: U256::from(1_000u64),
            supply_claimed: U256::from(10u64),
            quantity_limit_per_wallet: U256::from(5u64),
            merkle_root: B256::ZERO,
            price_per_token: U256::from(10_000_000_000_000_000u64),
            currency: NATIVE_TOKEN,
        }
    }

    fn gated_condition(root: B256) -> ClaimCondition {
        ClaimCondition {
            merkle_root: root,
            ..public_condition()
        }
    }

    fn single_leaf_proof(
        quantity_limit_per_wallet: U256,
        price_per_token: U256,
        currency: Address,
    ) -> (B256, OperatorAllowlistProof) {
        let leaf =
            thirdweb::allowlist_leaf(WALLET, quantity_limit_per_wallet, price_per_token, currency);
        (
            leaf,
            OperatorAllowlistProof {
                proof: vec![],
                quantity_limit_per_wallet,
                price_per_token,
                currency,
            },
        )
    }

    #[test]
    fn public_phase_uses_the_claim_condition_price_and_needs_no_proof() {
        let condition = public_condition();
        let resolved = resolve_effective_claim(WALLET, &condition, None).unwrap();
        assert_eq!(resolved.price_per_token, condition.price_per_token);
        assert_eq!(resolved.currency, NATIVE_TOKEN);
        assert_eq!(resolved.wallet_limit, 5);
    }

    #[test]
    fn gated_phase_without_a_proof_is_refused() {
        let condition = gated_condition(B256::repeat_byte(0x11));
        let err = resolve_effective_claim(WALLET, &condition, None).unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[test]
    fn gated_phase_with_an_invalid_proof_is_refused() {
        let condition = gated_condition(B256::repeat_byte(0x22));
        let bogus_proof = OperatorAllowlistProof {
            proof: vec![B256::repeat_byte(0xAA)],
            quantity_limit_per_wallet: U256::from(2u64),
            price_per_token: NO_PRICE_OVERRIDE,
            currency: Address::ZERO,
        };
        let err = resolve_effective_claim(WALLET, &condition, Some(&bogus_proof)).unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
    }

    #[test]
    fn gated_phase_with_a_verified_proof_and_no_price_override_uses_condition_price() {
        let (leaf, proof) = single_leaf_proof(U256::from(2u64), NO_PRICE_OVERRIDE, Address::ZERO);
        let condition = gated_condition(leaf); // single-leaf tree: leaf == root
        let resolved = resolve_effective_claim(WALLET, &condition, Some(&proof)).unwrap();
        assert_eq!(resolved.price_per_token, condition.price_per_token);
        assert_eq!(resolved.currency, condition.currency);
        assert_eq!(resolved.wallet_limit, 2);
    }

    #[test]
    fn gated_phase_with_a_zero_price_override_is_honored_as_a_free_mint() {
        // The critical regression test: NO_PRICE_OVERRIDE (U256::MAX) is
        // the "don't override" sentinel, so an explicit price of exactly
        // zero must be honored, never mistaken for "no override".
        let (leaf, proof) = single_leaf_proof(U256::from(1u64), U256::ZERO, NATIVE_TOKEN);
        let condition_price_is_nonzero = public_condition().price_per_token;
        assert_ne!(condition_price_is_nonzero, U256::ZERO);
        let condition = gated_condition(leaf);
        let resolved = resolve_effective_claim(WALLET, &condition, Some(&proof)).unwrap();
        assert_eq!(resolved.price_per_token, U256::ZERO);
        assert_eq!(resolved.currency, NATIVE_TOKEN);
    }

    #[test]
    fn gated_phase_price_override_without_a_currency_override_falls_back_to_condition_currency() {
        // Per Drop.sol: claimCurrency only takes the proof's currency
        // when price is ALSO overridden AND currency != address(0).
        let (leaf, proof) = single_leaf_proof(U256::from(1u64), U256::from(1u64), Address::ZERO);
        let condition = gated_condition(leaf);
        let resolved = resolve_effective_claim(WALLET, &condition, Some(&proof)).unwrap();
        assert_eq!(resolved.price_per_token, U256::from(1u64));
        assert_eq!(
            resolved.currency, condition.currency,
            "currency must fall back to the claim condition's own when the proof's currency is \
             the zero address, even though price WAS overridden"
        );
    }

    #[test]
    fn gated_phase_with_zero_quantity_limit_override_falls_back_to_condition_limit() {
        let (leaf, proof) = single_leaf_proof(U256::ZERO, NO_PRICE_OVERRIDE, Address::ZERO);
        let condition = gated_condition(leaf);
        let resolved = resolve_effective_claim(WALLET, &condition, Some(&proof)).unwrap();
        assert_eq!(
            resolved.wallet_limit,
            clamp_to_u64(condition.quantity_limit_per_wallet)
        );
    }

    #[test]
    fn erc20_priced_condition_is_refused_by_the_caller_not_silently_charged() {
        let mut condition = public_condition();
        condition.currency = address!("00000000000000000000000000000000000dEaD0");
        let resolved = resolve_effective_claim(WALLET, &condition, None).unwrap();
        assert_ne!(resolved.currency, NATIVE_TOKEN);
        // prepare_thirdweb_transaction itself rejects this -- verified by
        // the ERC20-currency guard right after resolve_effective_claim.
    }

    #[test]
    fn clamp_to_u64_treats_an_oversized_cap_as_effectively_unbounded() {
        assert_eq!(clamp_to_u64(U256::MAX), u64::MAX);
        assert_eq!(clamp_to_u64(U256::from(7u64)), 7);
    }

    #[test]
    fn exact_u64_fails_closed_on_a_count_that_cannot_fit() {
        assert!(exact_u64(U256::MAX).is_err());
        assert_eq!(exact_u64(U256::from(42u64)).unwrap(), 42);
    }

    // -----------------------------------------------------------------
    // Real, mock-RPC-backed integration tests for
    // `prepare_thirdweb_transaction` -- proves the whole gather/validate/
    // sign pipeline, not just the pure `resolve_effective_claim` logic
    // above. Mirrors `prepared.rs::tests`' exact MockTransport pattern.
    // -----------------------------------------------------------------
    mod prepare_integration {
        use super::*;
        use crate::chain::endpoint::EndpointRole;
        use crate::chain::mock::MockTransport;
        use crate::chain::registry::ChainRegistry;
        use crate::protocol::thirdweb::ClaimConditionAbi;
        use crate::signing::signer::LocalSigner;
        use alloy_sol_types::SolCall;
        use serde_json::json;

        pub(super) const DROP: Address = address!("00000000000000000000000000000000000c0DE0");

        pub(super) fn signer() -> LocalSigner {
            LocalSigner::from_bytes(keccak256(b"kairox-thirdweb-engine-test-key").0).unwrap()
        }

        pub(super) struct MockOpts {
            condition_id: u64,
            max_claimable_supply: u64,
            supply_claimed: u64,
            quantity_limit_per_wallet: u64,
            wallet_claimed: u64,
            price_per_token_wei: u128,
            nonce_hex: &'static str,
            base_fee_hex: &'static str,
            priority_fee_hex: &'static str,
            balance_hex: &'static str,
            estimate_gas: Result<&'static str, (i64, &'static str)>,
        }

        impl Default for MockOpts {
            fn default() -> Self {
                Self {
                    condition_id: 0,
                    max_claimable_supply: 1_000,
                    supply_claimed: 10,
                    quantity_limit_per_wallet: 5,
                    wallet_claimed: 0,
                    price_per_token_wei: 10_000_000_000_000_000, // 0.01 native
                    nonce_hex: "0x1",
                    base_fee_hex: "0x3b9aca00",
                    priority_fee_hex: "0x3b9aca00",
                    balance_hex: "0xde0b6b3a7640000", // 1 native
                    estimate_gas: Ok("0x2bf20"),
                }
            }
        }

        pub(super) fn build_transport(opts: MockOpts) -> MockTransport {
            build_transport_builder(opts).build()
        }

        pub(super) fn build_transport_builder(
            opts: MockOpts,
        ) -> crate::chain::mock::MockTransportBuilder {
            let condition_id_hex = format!(
                "0x{}",
                hex::encode(thirdweb::getActiveClaimConditionIdCall::abi_encode_returns(
                    &U256::from(opts.condition_id)
                ))
            );
            let condition_abi = ClaimConditionAbi {
                startTimestamp: U256::from(1_700_000_000u64),
                maxClaimableSupply: U256::from(opts.max_claimable_supply),
                supplyClaimed: U256::from(opts.supply_claimed),
                quantityLimitPerWallet: U256::from(opts.quantity_limit_per_wallet),
                merkleRoot: B256::ZERO,
                pricePerToken: U256::from(opts.price_per_token_wei),
                currency: NATIVE_TOKEN,
                metadata: String::new(),
            };
            let condition_hex = format!(
                "0x{}",
                hex::encode(thirdweb::getClaimConditionByIdCall::abi_encode_returns(
                    &condition_abi
                ))
            );
            let wallet_claimed_hex = format!(
                "0x{}",
                hex::encode(thirdweb::getSupplyClaimedByWalletCall::abi_encode_returns(
                    &U256::from(opts.wallet_claimed)
                ))
            );

            let builder = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond_eth_call_selector(
                    thirdweb::getActiveClaimConditionIdCall::SELECTOR,
                    json!(condition_id_hex),
                )
                .respond_eth_call_selector(
                    thirdweb::getClaimConditionByIdCall::SELECTOR,
                    json!(condition_hex),
                )
                .respond_eth_call_selector(
                    thirdweb::getSupplyClaimedByWalletCall::SELECTOR,
                    json!(wallet_claimed_hex),
                )
                .respond(
                    "eth_getBlockByNumber",
                    json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": opts.base_fee_hex}),
                )
                .respond("eth_maxPriorityFeePerGas", json!(opts.priority_fee_hex))
                .respond("eth_getTransactionCount", json!(opts.nonce_hex))
                .respond("eth_getBalance", json!(opts.balance_hex))
                // Provenance: not an EIP-1167 clone (bytecode is not 45
                // bytes / not the exact template) and not an EIP-1967
                // proxy (storage slot reads back all-zero) -- so
                // `resolve_thirdweb_implementation_and_code_hash` falls
                // through to hashing `DROP`'s own mocked bytecode
                // directly, exactly as it would for a non-proxy
                // deployment.
                .respond(
                    "eth_getCode",
                    json!(format!("0x{}", hex::encode(mock_implementation_bytecode()))),
                )
                .respond(
                    "eth_getStorageAt",
                    json!(format!("0x{}", hex::encode([0u8; 32]))),
                );

            match opts.estimate_gas {
                Ok(hex_value) => builder.respond("eth_estimateGas", json!(hex_value)),
                Err((code, message)) => builder.error("eth_estimateGas", code, message),
            }
        }

        /// Deliberately not 45 bytes (so it can never accidentally match
        /// the EIP-1167 clone template) and otherwise arbitrary --
        /// `establish_provenance` hashes this directly (no proxy
        /// detected) and `trusted_fingerprint()` below is the matching
        /// registry entry for exactly this hash.
        pub(super) fn mock_implementation_bytecode() -> Vec<u8> {
            vec![
                0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10,
            ]
        }

        /// A trusted-fingerprint entry matching `mock_implementation_bytecode()`'s
        /// hash on chain 1 -- injected by tests that need to get past
        /// `establish_provenance` to exercise what happens afterward
        /// (mirrors `GenericVerifiedContractAdapter`'s tests injecting
        /// their own registry entries rather than needing
        /// `BUILTIN_REGISTRY` to ship non-empty).
        pub(super) fn trusted_fingerprint(
            flavor: crate::execution::thirdweb_registry::ThirdwebFlavor,
        ) -> ThirdwebTrustedFingerprint {
            ThirdwebTrustedFingerprint {
                name: "test-fixture",
                chain_id: 1,
                implementation_bytecode_hash: keccak256(mock_implementation_bytecode()),
                flavor,
            }
        }

        pub(super) fn test_registry() -> Vec<ThirdwebTrustedFingerprint> {
            vec![trusted_fingerprint(
                crate::execution::thirdweb_registry::ThirdwebFlavor::DropMultiPhase721,
            )]
        }

        async fn connect(opts: MockOpts) -> RpcClient {
            let transport = build_transport(opts);
            RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap()
        }

        pub(super) fn request(wallet: Address) -> ThirdwebMintRequest {
            ThirdwebMintRequest {
                chain: ChainRegistry::builtin().by_id(1).unwrap().clone(),
                drop_contract: DROP,
                wallet,
                quantity: 1,
                gas_buffer_multiplier: 1.2,
                safety_caps: SafetyCaps {
                    max_mint_value: U256::from(1_000_000_000_000_000_000u128),
                    max_gas_cost: U256::from(1_000_000_000_000_000_000u128),
                    max_total_spend: U256::from(1_000_000_000_000_000_000u128),
                },
                allowlist_proof: None,
            }
        }

        #[tokio::test]
        async fn public_phase_native_mint_prepares_and_signs_successfully() {
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let prepared =
                prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
                    .await
                    .unwrap();
            assert_eq!(prepared.target, DROP);
            assert_eq!(
                prepared.value,
                U256::from(10_000_000_000_000_000u128) // price * quantity(1)
            );
            assert_eq!(prepared.wallet, wallet);
        }

        #[tokio::test]
        async fn wrong_signing_key_is_rejected_before_any_read() {
            let s = signer();
            let wrong_wallet = address!("9999999999999999999999999999999999999999");
            let client = connect(MockOpts::default()).await;
            // Empty registry deliberately -- the wallet-key check happens
            // before provenance is ever established, so this must fail
            // for the wallet-mismatch reason specifically, not because no
            // fingerprint was found.
            let err = prepare_thirdweb_transaction(&client, &s, &request(wrong_wallet), &[])
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
        async fn exhausted_wallet_allocation_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                quantity_limit_per_wallet: 1,
                wallet_claimed: 1,
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            assert!(matches!(err, KairoxError::Supply(_)));
        }

        #[tokio::test]
        async fn sold_out_collection_is_rejected_before_signing() {
            let s = signer();
            let wallet = s.address();
            let opts = MockOpts {
                max_claimable_supply: 10,
                supply_claimed: 10,
                ..MockOpts::default()
            };
            let client = connect(opts).await;
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
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
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
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
        async fn no_active_claim_condition_is_reported_clearly() {
            let s = signer();
            let wallet = s.address();
            let transport = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                // Provenance is established first (falls through to
                // hashing DROP's own mocked bytecode, matched by
                // test_registry()) -- only *then* does the flavor-aware
                // read hit the mocked eth_call failure.
                .respond(
                    "eth_getCode",
                    json!(format!("0x{}", hex::encode(mock_implementation_bytecode()))),
                )
                .respond(
                    "eth_getStorageAt",
                    json!(format!("0x{}", hex::encode([0u8; 32]))),
                )
                .error(
                    "eth_call",
                    -32000,
                    "execution reverted: DropNoActiveCondition",
                )
                .build();
            let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap();
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
                .await
                .unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("no active claim condition"),
                "expected a clear no-active-condition message, got: {message}"
            );
        }

        #[tokio::test]
        async fn no_trusted_fingerprint_refuses_to_authorize_a_live_send() {
            // The core regression this correction pass exists for:
            // selector compatibility and a successful eth_call must never
            // be enough to authorize signing. An empty registry (the
            // real BUILTIN_REGISTRY's default state) must refuse, even
            // though every read the mock provides would otherwise
            // "succeed".
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &[])
                .await
                .unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("no trusted implementation fingerprint"),
                "expected a clear provenance-not-established message, got: {message}"
            );
        }

        #[tokio::test]
        async fn wrong_flavor_fingerprint_does_not_authorize_a_different_flavor() {
            // A registry entry for the single-phase flavor must not
            // authorize a contract that only responds to the multi-phase
            // getters (or vice versa) -- the flavor comes from the
            // matched fingerprint itself, never re-derived by probing.
            let s = signer();
            let wallet = s.address();
            let client = connect(MockOpts::default()).await;
            let wrong_flavor_registry = vec![trusted_fingerprint(
                crate::execution::thirdweb_registry::ThirdwebFlavor::DropSinglePhase721,
            )];
            let err =
                prepare_thirdweb_transaction(&client, &s, &request(wallet), &wrong_flavor_registry)
                    .await
                    .unwrap_err();
            // The mock only serves multi-phase selectors; routed through
            // the single-phase getters (claimCondition(), no args) it
            // must fail rather than silently decode unrelated data.
            assert!(!matches!(err, KairoxError::Supply(_)));
        }

        #[tokio::test]
        async fn implementation_changing_after_provenance_is_established_is_rejected_before_signing()
         {
            // Simulates the exact race establish_provenance's re-check
            // exists to close: the implementation matched the trusted
            // registry when provenance was first established, but has
            // since changed by the time signing is about to happen.
            // eth_getCode is called twice for the same address
            // (establish_provenance, then the immediately-before-signing
            // re-check) -- the first call returns the trusted bytecode,
            // every call after returns different bytecode.
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let trusted_bytecode = mock_implementation_bytecode();
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
            let err = prepare_thirdweb_transaction(&client, &s, &request(wallet), &test_registry())
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

        #[tokio::test]
        async fn single_phase_flavor_native_mint_prepares_and_signs_successfully() {
            // Proves the single-phase getters (claimCondition(), no
            // args; getSupplyClaimedByWallet(address), one arg) are
            // genuinely exercised end-to-end, not merely encoded --
            // using a mock that only serves the single-phase selectors
            // (the multi-phase getActiveClaimConditionId() is
            // deliberately left unmocked, so this test would fail if
            // resolve_effective_claim's flavor dispatch ever called the
            // wrong getter for this flavor).
            let opts = MockOpts::default();
            let condition_abi = ClaimConditionAbi {
                startTimestamp: U256::from(1_700_000_000u64),
                maxClaimableSupply: U256::from(opts.max_claimable_supply),
                supplyClaimed: U256::from(opts.supply_claimed),
                quantityLimitPerWallet: U256::from(opts.quantity_limit_per_wallet),
                merkleRoot: B256::ZERO,
                pricePerToken: U256::from(opts.price_per_token_wei),
                currency: NATIVE_TOKEN,
                metadata: String::new(),
            };
            let condition_hex = format!(
                "0x{}",
                hex::encode(thirdweb::claimConditionCall::abi_encode_returns(
                    &condition_abi
                ))
            );
            let wallet_claimed_hex = format!(
                "0x{}",
                hex::encode(
                    thirdweb::single_phase::getSupplyClaimedByWalletCall::abi_encode_returns(
                        &U256::from(opts.wallet_claimed)
                    )
                )
            );
            let transport = MockTransport::builder()
                .respond("eth_chainId", json!("0x1"))
                .respond_eth_call_selector(
                    thirdweb::claimConditionCall::SELECTOR,
                    json!(condition_hex),
                )
                .respond_eth_call_selector(
                    thirdweb::single_phase::getSupplyClaimedByWalletCall::SELECTOR,
                    json!(wallet_claimed_hex),
                )
                .respond(
                    "eth_getBlockByNumber",
                    json!({"number": "0x1", "timestamp": "0x1", "baseFeePerGas": opts.base_fee_hex}),
                )
                .respond("eth_maxPriorityFeePerGas", json!(opts.priority_fee_hex))
                .respond("eth_getTransactionCount", json!(opts.nonce_hex))
                .respond("eth_getBalance", json!(opts.balance_hex))
                .respond("eth_estimateGas", json!("0x2bf20"))
                .respond(
                    "eth_getCode",
                    json!(format!("0x{}", hex::encode(mock_implementation_bytecode()))),
                )
                .respond(
                    "eth_getStorageAt",
                    json!(format!("0x{}", hex::encode([0u8; 32]))),
                )
                .build();
            let client = RpcClient::connect(Box::new(transport), 1, EndpointRole::ReadWrite, None)
                .await
                .unwrap();

            let s = signer();
            let wallet = s.address();
            let registry = vec![trusted_fingerprint(
                crate::execution::thirdweb_registry::ThirdwebFlavor::DropSinglePhase721,
            )];
            let prepared = prepare_thirdweb_transaction(&client, &s, &request(wallet), &registry)
                .await
                .unwrap();
            assert_eq!(prepared.target, DROP);
            assert_eq!(prepared.value, U256::from(10_000_000_000_000_000u128));
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

        fn transport_with_broadcast(wallet: Address, quantity: u64) -> MockTransport {
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
                            "address": DROP.to_string(),
                            "topics": [
                                format!(
                                    "0x{}",
                                    hex::encode(keccak256(b"Transfer(address,address,uint256)"))
                                ),
                                format!("0x{}", hex::encode([0u8; 32])),
                                format!("0x{}", hex::encode(tx_hash_topic(wallet))),
                                format!(
                                    "0x{}",
                                    hex::encode(U256::from(quantity).to_be_bytes::<32>())
                                ),
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
            let outcome = run_thirdweb_mint(
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
            let pool = pool_with_transport(transport_with_broadcast(wallet, 1)).await;
            let outcome = run_thirdweb_mint(
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
}
