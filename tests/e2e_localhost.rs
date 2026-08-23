//! Real localhost HTTP end-to-end tests: a genuine TCP listener speaking
//! real HTTP/1.1, driven by the actual compiled `kairox` binary as a
//! subprocess (via `assert_cmd`/`CARGO_BIN_EXE_kairox`) pointed at it with
//! `--rpc-url`/env vars, exercising the real `reqwest`-based
//! `HttpTransport` -- not `MockTransport`, not an injected trait. This
//! file owns both the minimal HTTP/1.1 server harness and the E2E
//! scenarios that use it.
//!
//! The harness is deliberately small and test-only: a blocking
//! `std::net::TcpListener` on an OS-assigned ephemeral port, one thread
//! per accepted connection, hand-rolled HTTP/1.1 request parsing (just
//! enough: request line, headers up to blank line, `Content-Length`
//! body). This is not a general-purpose HTTP server; it exists to give
//! each scenario exact control over what a "localhost RPC/OpenSea
//! endpoint" does -- including deliberately never responding at all,
//! which is the whole point of the uncertain-broadcast scenario and is
//! not expressible through any higher-level HTTP client/server crate
//! without the same amount of raw-socket control this uses directly.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use predicates::prelude::PredicateBooleanExt;
use serde_json::Value;

/// What the harness does with one accepted HTTP request.
pub enum Behavior {
    /// Respond 200 with this exact JSON body.
    Json(Value),
    /// Respond 200 with a JSON-RPC error envelope for this request's id.
    JsonRpcError { code: i64, message: String },
    /// Read the complete request (so the client's request body -- e.g. a
    /// raw `eth_sendRawTransaction` -- has genuinely been received by
    /// this process), then close the connection without writing any
    /// response at all. This is what makes a broadcast outcome truly
    /// possible-send-but-unknown: the transaction reached a node's
    /// door, but the client can never observe whether it was accepted.
    CloseWithoutResponding,
    /// Respond with an explicit HTTP status and JSON body (for OpenSea-
    /// style REST failure responses: 401/403/422/429/500).
    HttpStatus(u16, Value),
}

/// A running localhost HTTP server for one test. Dropping it lets its
/// accept-loop thread wind down on its own next time it wakes (best
/// effort; not joined -- acceptable for test-only harness code that owns
/// an OS-assigned ephemeral port per instance).
pub struct LocalHttpServer {
    port: u16,
    /// Every request this server has actually received, in arrival
    /// order -- (method-or-path, raw JSON body) -- so a test can assert
    /// on what the real HTTP client actually sent, not just what came
    /// back.
    pub received: Arc<Mutex<Vec<(String, Value)>>>,
}

impl LocalHttpServer {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Spawn a JSON-RPC-shaped server: every request's body is parsed as
    /// `{"method": ..., "params": ..., "id": ...}`, and `handler` decides
    /// the response per the JSON-RPC `method` name.
    pub fn spawn_json_rpc(
        handler: impl Fn(&str, &Value) -> Behavior + Send + Sync + 'static,
    ) -> Self {
        Self::spawn_raw(move |_path, body| {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = handler(&method, &params);
            (method, behavior)
        })
    }

    fn spawn_raw(
        route: impl Fn(&str, &Value) -> (String, Behavior) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral local port");
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_for_thread = received.clone();
        let route = Arc::new(route);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let route = route.clone();
                let received = received_for_thread.clone();
                std::thread::spawn(move || {
                    handle_connection(stream, |path, body| {
                        let (key, behavior) = route(path, &body);
                        received.lock().unwrap().push((key, body));
                        behavior
                    });
                });
            }
        });

        // Give the accept loop a moment to actually be listening before
        // the caller starts pointing a real client at it.
        std::thread::sleep(std::time::Duration::from_millis(20));

        Self { port, received }
    }
}

fn handle_connection(mut stream: TcpStream, respond: impl FnOnce(&str, Value) -> Behavior) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body_bytes).is_err() {
        return;
    }
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);

    let behavior = respond(&path, body);

    match behavior {
        Behavior::Json(value) => {
            write_http_json(&mut stream, 200, &value);
        }
        Behavior::JsonRpcError { code, message } => {
            let envelope = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": code, "message": message},
            });
            write_http_json(&mut stream, 200, &envelope);
        }
        Behavior::CloseWithoutResponding => {
            // The request has already been fully read above -- the
            // "possible send" already happened from the client's
            // perspective. Shut the connection down with no response at
            // all, simulating a node that accepted the bytes and then
            // vanished before answering.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Behavior::HttpStatus(status, value) => {
            write_http_json(&mut stream, status, &value);
        }
    }
}

fn write_http_json(stream: &mut TcpStream, status: u16, value: &Value) {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

/// Wrap a JSON-RPC `Behavior::Json` result value in the envelope
/// `HttpTransport` expects: `{"jsonrpc":"2.0","id":1,"result": value}`.
pub fn rpc_ok(result: Value) -> Behavior {
    Behavior::Json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}))
}

fn kairox_bin() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("kairox").expect("kairox binary should build")
}

// ---------------------------------------------------------------------
// Scenario: uncertain broadcast (Phase 6 Section 12 -- mandatory).
// ---------------------------------------------------------------------
//
// NOTE: this scenario alone requires the full public-mint read pipeline
// (getPublicDrop / getAllowedFeeRecipients / getMintStats / fee hint /
// nonce / gas estimate) to succeed before Kairox ever reaches
// eth_sendRawTransaction. That wiring is intentionally deferred to a
// follow-up commit once the exact calldata/response shapes are mapped
// precisely against protocol::seadrop's real encode/decode functions --
// getting a single byte of ABI encoding wrong here would make the
// scenario fail for the wrong reason (a decode error) rather than prove
// what it's meant to prove (uncertain-broadcast handling). This file's
// harness (LocalHttpServer, Behavior::CloseWithoutResponding, rpc_ok) is
// complete and reusable for that follow-up.
#[test]
fn harness_smoke_test_serves_a_real_http_json_rpc_response() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x12d687")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicates::str::contains("Ethereum (chain id 1) [PASS]"));

    let received = server.received.lock().unwrap();
    assert!(received.iter().any(|(m, _)| m == "eth_chainId"));
}

#[test]
fn harness_close_without_responding_is_observed_as_a_network_error() {
    // Not yet wired into the full mint pipeline (see note above) -- this
    // proves the harness primitive itself: a real HTTP client (reqwest,
    // via HttpTransport) really does experience "request sent, then
    // connection closed with no response" as a distinct outcome from
    // either a clean success or a clean JSON-RPC error, when talking to
    // a real socket that behaves that way.
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => Behavior::CloseWithoutResponding,
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .arg("doctor")
        .assert()
        .success() // doctor itself still exits 0; the endpoint just reports unreachable
        .stdout(predicates::str::contains("UNREACHABLE").or(predicates::str::contains("FAIL")));
}

// =======================================================================
// Public single-wallet E2E (Phase 6 Section 4): the real CLI binary,
// through a real HTTP client, against this real localhost JSON-RPC
// server, exercising the actual protocol::seadrop ABI encode/decode
// functions -- ported directly from execution::live's own MockTransport
// test fixture so the response shapes are known-correct, not guessed.
// =======================================================================

use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::SolCall;
use kairox::protocol::seadrop::{self as sd, MintParams as NormalizedMintParams, PublicDropAbi};
use kairox::protocol::seadrop_crypto;
use kairox::signing::signer::{LocalSigner, Signer, recover_from_prehash};
use kairox::signing::transaction::{AccessListItem, UnsignedEip1559Tx};

const NFT: Address = address!("000000000000000000000000000000000000c0de");

const SINGLE_WALLET_SEED: &str = "kairox-phase6-e2e-localhost-wallet";

fn test_signer() -> LocalSigner {
    signer_for_seed(SINGLE_WALLET_SEED)
}

fn signer_for_seed(seed: &str) -> LocalSigner {
    LocalSigner::from_bytes(keccak256(seed.as_bytes()).0).unwrap()
}

/// The hex private key for the signer built from the same `seed` --
/// `LocalSigner` deliberately never exposes its key material back out
/// once constructed, so the only way to also get a `KAIROX_SIGNING_KEY`
/// string is to keep the original seed and re-derive it independently
/// (this must stay in exact lockstep with `signer_for_seed`'s derivation).
fn signing_key_hex_for_seed(seed: &str) -> String {
    format!("0x{}", hex::encode(keccak256(seed.as_bytes())))
}

fn signing_key_hex(_signer: &LocalSigner) -> String {
    signing_key_hex_for_seed(SINGLE_WALLET_SEED)
}

fn transfer_log_for(wallet: Address, token_id: u64) -> Value {
    let mut to_topic = [0u8; 32];
    to_topic[12..32].copy_from_slice(wallet.as_slice());
    serde_json::json!({
        "address": format!("{NFT:#x}"),
        "topics": [
            format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
            format!("0x{}", hex::encode([0u8; 32])),
            format!("0x{}", hex::encode(to_topic)),
            format!("0x{}", hex::encode(U256::from(token_id).to_be_bytes::<32>())),
        ],
        "data": "0x",
    })
}

/// A fully customizable `Transfer` log, for constructing the specific
/// receipt-mismatch shapes Phase 6 Section 15 requires (wrong collection
/// address, wrong recipient, `from != 0x0`).
fn transfer_log_custom(contract: Address, from: Address, to: Address, token_id: u64) -> Value {
    let mut from_topic = [0u8; 32];
    from_topic[12..32].copy_from_slice(from.as_slice());
    let mut to_topic = [0u8; 32];
    to_topic[12..32].copy_from_slice(to.as_slice());
    serde_json::json!({
        "address": format!("{contract:#x}"),
        "topics": [
            format!("0x{}", hex::encode(keccak256(b"Transfer(address,address,uint256)"))),
            format!("0x{}", hex::encode(from_topic)),
            format!("0x{}", hex::encode(to_topic)),
            format!("0x{}", hex::encode(U256::from(token_id).to_be_bytes::<32>())),
        ],
        "data": "0x",
    })
}

/// The standard "happy path" response for every read-only method the
/// public-mint pipeline calls, ported field-for-field from
/// `execution::live`'s own passing MockTransport fixture. `None` for
/// `eth_sendRawTransaction`/`eth_getTransactionReceipt` and anything
/// else -- callers handle those per scenario.
fn standard_read_response(method: &str, params: &Value) -> Option<Behavior> {
    match method {
        "eth_chainId" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_blockNumber" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_call" => {
            let data = params
                .get(0)
                .and_then(|c| c.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let selector_hex = format!("0x{}", hex::encode(sd::getPublicDropCall::SELECTOR));
            let allowed_hex = format!(
                "0x{}",
                hex::encode(sd::getAllowedFeeRecipientsCall::SELECTOR)
            );
            let stats_hex = format!("0x{}", hex::encode(sd::getMintStatsCall::SELECTOR));
            if data.starts_with(&selector_hex) {
                let public_drop = PublicDropAbi {
                    mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
                    startTime: alloy_primitives::Uint::from(1_577_836_800u64), // 2020-01-01
                    endTime: alloy_primitives::Uint::from(32_503_680_000u64),  // 2999-01-01
                    maxTotalMintableByWallet: 5,
                    feeBps: 0,
                    restrictFeeRecipients: false,
                };
                Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(sd::getPublicDropCall::abi_encode_returns(&public_drop))
                ))))
            } else if data.starts_with(&allowed_hex) {
                Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(sd::getAllowedFeeRecipientsCall::abi_encode_returns(&Vec::<
                        Address,
                    >::new(
                    )))
                ))))
            } else if data.starts_with(&stats_hex) {
                Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(sd::getMintStatsCall::abi_encode_returns(
                        &sd::getMintStatsReturn {
                            minterNumMinted: U256::ZERO,
                            currentTotalSupply: U256::from(10u64),
                            maxSupply: U256::from(1_000u64),
                        }
                    ))
                ))))
            } else {
                None
            }
        }
        "eth_getBlockByNumber" => Some(rpc_ok(serde_json::json!({
            "number": "0x1", "timestamp": "0x1", "baseFeePerGas": "0x3b9aca00"
        }))),
        "eth_maxPriorityFeePerGas" => Some(rpc_ok(serde_json::json!("0x3b9aca00"))),
        "eth_getTransactionCount" => Some(rpc_ok(serde_json::json!("0x0"))),
        "eth_getBalance" => Some(rpc_ok(serde_json::json!("0xde0b6b3a7640000"))), // 1 ETH
        "eth_estimateGas" => Some(rpc_ok(serde_json::json!("0x2bf20"))),
        _ => None,
    }
}

fn echo_tx_hash_behavior(params: &Value) -> Behavior {
    let raw_hex = params
        .get(0)
        .and_then(Value::as_str)
        .unwrap_or("0x")
        .trim_start_matches("0x");
    let bytes = hex::decode(raw_hex).unwrap_or_default();
    let hash = keccak256(&bytes);
    rpc_ok(serde_json::json!(format!("0x{}", hex::encode(hash))))
}

#[test]
fn public_single_wallet_dry_run_reads_state_and_broadcasts_nothing() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in dry-run scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("mint value:"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a dry-run plan must never broadcast anything"
    );
}

#[test]
fn public_single_wallet_live_send_signs_and_broadcasts_exactly_one_transaction() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 7)],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in live-send scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("BROADCAST RESULT"))
        .stdout(predicates::str::contains("receipt: CONFIRMED_SUCCESS"));

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "exactly one eth_sendRawTransaction expected, got {sends:?}"
    );
}

#[test]
fn public_single_wallet_rehearsal_prepares_and_signs_but_never_broadcasts() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        // No eth_sendRawTransaction or eth_getTransactionReceipt handler at
        // all -- if rehearsal ever actually broadcasts or polls a receipt,
        // this server errors instead of silently returning a plausible
        // 200, so a bug here cannot masquerade as a pass.
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in rehearsal scenario (must never broadcast or poll a receipt): {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--rehearsal",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"))
        .stdout(predicates::str::contains("tx hash: 0x"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "rehearsal must never call eth_sendRawTransaction"
    );
    assert!(
        !received
            .iter()
            .any(|(m, _)| m == "eth_getTransactionReceipt"),
        "rehearsal must never poll for a receipt -- nothing was broadcast to have one"
    );
    // The real read pipeline (nonce, fee, balance, gas estimate, stage
    // state) genuinely ran -- proves this is not a stub.
    assert!(received.iter().any(|(m, _)| m == "eth_getTransactionCount"));
    assert!(received.iter().any(|(m, _)| m == "eth_estimateGas"));
}

// ---------------------------------------------------------------------
// Round 6 item 14: the OpenSea engine's own local no-broadcast rehearsal
// (mirrors the PUBLIC engine's --rehearsal above, which already existed).
// Real drop-details polling, real EIP-712 signed-mint validation, real
// on-chain simulation, and real local signing/serialization all run
// exactly as they would for a real send; only eth_sendRawTransaction
// (and the receipt poll that would follow it) never happens.
// ---------------------------------------------------------------------
#[test]
fn opensea_signed_mint_rehearsal_prepares_and_signs_but_never_broadcasts() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-rehearsal";
    const SIGNER_SEED: &str = "kairox-e2e-rehearsal-authorized-signer";

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| match method {
            "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
                code: -32000,
                message: format!(
                    "unexpected method in rehearsal scenario (must never broadcast or poll a \
                     receipt): {method}"
                ),
            },
            _ => opensea_read_response(
                method,
                params,
                None,
                Some(permissive_signed_mint_validation_params()),
                Some(true),
            )
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea rehearsal scenario: {method}"),
            }),
        },
        move || {
            rpc_ok_status(signed_mint_response_json(
                wallet,
                sample_mint_params_abi(true),
                SIGNER_SEED,
                U256::from(1u64),
            ))
        },
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--rehearsal",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"))
        .stdout(predicates::str::contains("tx hash: 0x"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "rehearsal must never call eth_sendRawTransaction"
    );
    assert!(
        !received
            .iter()
            .any(|(m, _)| m == "eth_getTransactionReceipt"),
        "rehearsal must never poll for a receipt -- nothing was broadcast to have one"
    );
    // The real pipeline (OpenSea drop details, the real signed-mint
    // authorization request, on-chain simulation) genuinely ran -- proves
    // this is not a stub.
    assert!(
        received
            .iter()
            .any(|(m, _)| *m == format!("/api/v2/drops/{SLUG}/mint"))
    );
    assert!(received.iter().any(|(m, _)| m == "eth_estimateGas"));
}

#[test]
fn public_single_wallet_rehearsal_and_send_are_mutually_exclusive_cli_flags() {
    kairox_bin()
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            "0x000000000000000000000000000000000000dEaD",
            "--send",
            "--rehearsal",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be used with"));
}

#[test]
fn public_single_wallet_uncertain_send_never_retries_or_replaces() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        // The request body (the raw signed tx) is fully read by the
        // harness before the connection is closed -- a genuine
        // possible-send, not a simulated enum value.
        "eth_sendRawTransaction" => Behavior::CloseWithoutResponding,
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in uncertain-send scenario: {method}"),
        }),
    });

    // Kairox correctly treats an uncertain broadcast as a MustStopSession
    // condition: the process exits nonzero, and the uncertain outcome is
    // reported on stderr (see execution::errors module docs) -- this is
    // not a bug in the scenario, it is exactly the "never silently
    // retry/replace" behavior Section 12 requires proving.
    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(
            predicates::str::contains("uncertain").and(
                predicates::str::contains("TransportUnknown")
                    .or(predicates::str::contains("TimeoutUnknown")),
            ),
        );

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "the harness must have genuinely received exactly one send attempt; Kairox must never retry/replace an uncertain broadcast: {sends:?}"
    );
}

#[test]
fn public_single_wallet_definitive_rejection_is_reported_as_fatal_not_uncertain() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => Behavior::JsonRpcError {
            code: -32000,
            message: "nonce too low".into(),
        },
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in fatal-rejection scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("nonce too low"));
}

#[test]
fn public_single_wallet_receipt_revert_is_reported_as_confirmed_revert() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            // status = 0x0 (revert), no logs at all.
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x0",
                "blockNumber": "0x1",
                "logs": [],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in receipt-revert scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("receipt: CONFIRMED_REVERT"));
}

#[test]
fn public_single_wallet_receipt_mismatch_is_not_reported_as_success() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            // status = success, but NO mint Transfer log at all -- the
            // transaction genuinely executed; the expected mint evidence
            // was never observed. Must never be reported as success.
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in receipt-mismatch scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(
            predicates::str::contains("CONFIRMED_EXECUTION_MISMATCH")
                .and(predicates::str::contains("CONFIRMED_SUCCESS").not()),
        );
}

/// Shared body for the four receipt-mismatch variants below: same
/// send/receipt-poll setup, differing only in what the receipt's logs
/// contain.
fn assert_receipt_mismatch_for_logs(test_label: &'static str, logs: Vec<Value>) {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": logs.clone(),
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in {test_label} scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(
            predicates::str::contains("CONFIRMED_EXECUTION_MISMATCH")
                .and(predicates::str::contains("CONFIRMED_SUCCESS").not()),
        );
}

#[test]
fn receipt_mismatch_wrong_collection_address_is_not_confirmed_success() {
    let wallet = test_signer().address();
    let other_collection: Address = address!("00000000000000000000000000000000000dead0");
    assert_receipt_mismatch_for_logs(
        "wrong-collection",
        vec![transfer_log_custom(
            other_collection,
            Address::ZERO,
            wallet,
            1,
        )],
    );
}

#[test]
fn receipt_mismatch_wrong_recipient_is_not_confirmed_success() {
    let stranger: Address = address!("000000000000000000000000000000000000bee1");
    assert_receipt_mismatch_for_logs(
        "wrong-recipient",
        vec![transfer_log_custom(NFT, Address::ZERO, stranger, 1)],
    );
}

#[test]
fn receipt_mismatch_from_not_zero_is_not_confirmed_success() {
    // A secondary transfer (from a real prior owner, not the zero address)
    // is not a mint -- even though the receipt succeeded and a Transfer for
    // this collection/wallet genuinely exists in the logs.
    let wallet = test_signer().address();
    let prior_owner: Address = address!("000000000000000000000000000000000000bee2");
    assert_receipt_mismatch_for_logs(
        "from-not-zero",
        vec![transfer_log_custom(NFT, prior_owner, wallet, 1)],
    );
}

#[test]
fn receipt_mismatch_wrong_quantity_is_not_confirmed_success() {
    // Requested quantity defaults to 1; a receipt reporting a genuine mint
    // Transfer for a *different* token id count than requested is still
    // evaluated against the requested quantity=1, so this instead proves
    // the inverse: requesting quantity=2 while only one genuine mint
    // Transfer landed must not be confirmed success.
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 1)],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in wrong-quantity scenario: {method}"),
        }),
    });

    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);
    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--quantity",
            "2",
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(
            predicates::str::contains("CONFIRMED_EXECUTION_MISMATCH")
                .and(predicates::str::contains("CONFIRMED_SUCCESS").not()),
        );
}

#[test]
fn plan_json_success_path_is_exactly_one_valid_json_object_over_real_http() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in plan --json scenario: {method}"),
        })
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must be exactly one JSON line over real HTTP, got: {stdout:?}"
    );
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["wallet"], format!("{wallet:#x}").to_lowercase());
    assert!(parsed["plan_id"].as_str().unwrap().starts_with("plan_"));
}

#[test]
fn config_named_rpc_env_var_actually_connects_to_the_localhost_server() {
    // Proves config::resolve_chain_rpc_endpoints end to end: a config
    // file names an environment variable (never a URL directly), that
    // variable is set to point at the real localhost server, and the
    // real CLI process connects through it -- no --rpc-url involved.
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "version = 1\n[chains.ethereum]\nread_rpc_env = [\"E2E_TEST_RPC_URL\"]\n",
    )
    .unwrap();

    kairox_bin()
        .env("E2E_TEST_RPC_URL", server.url())
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("mint value:"));

    let received = server.received.lock().unwrap();
    assert!(received.iter().any(|(m, _)| m == "eth_chainId"));
}

// =======================================================================
// Public multi-wallet E2E (Phase 6 Section 5-7): three wallets, a real
// secret-free manifest file, real per-wallet key_env variables, driven
// through the real localhost server.
// =======================================================================

fn write_manifest(
    dir: &std::path::Path,
    wallets: &[(Address, u64, &str, &str)],
) -> std::path::PathBuf {
    let entries: Vec<Value> = wallets
        .iter()
        .map(|(addr, qty, label, key_env)| {
            serde_json::json!({
                "label": label,
                "address": format!("{addr:#x}"),
                "quantity": qty,
                "key_env": key_env,
            })
        })
        .collect();
    let manifest = serde_json::json!({"version": 1, "wallets": entries});
    let path = dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    path
}

#[test]
fn multi_wallet_dry_run_json_reports_planned_state_for_every_wallet_deterministically() {
    let a = signer_for_seed("kairox-e2e-multi-a").address();
    let b = signer_for_seed("kairox-e2e-multi-b").address();
    let c = signer_for_seed("kairox-e2e-multi-c").address();

    let dir = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(
        dir.path(),
        &[
            (a, 1, "wallet-a", "E2E_KEY_A"),
            (b, 2, "wallet-b", "E2E_KEY_B"),
            (c, 3, "wallet-c", "E2E_KEY_C"),
        ],
    );

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in multi-wallet dry-run scenario: {method}"),
        })
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet-manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout must be exactly one JSON line");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["dry_run"], true);
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 3);
    // Deterministic manifest order (A, B, C), regardless of anything else.
    assert_eq!(wallets[0]["label"], "wallet-a");
    assert_eq!(wallets[1]["label"], "wallet-b");
    assert_eq!(wallets[2]["label"], "wallet-c");
    for w in wallets {
        assert_eq!(w["state"], "PLANNED");
        assert!(w["tx_hash"].is_null());
    }

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a multi-wallet dry run must never broadcast anything"
    );
}

#[test]
fn multi_wallet_live_send_reports_three_independent_confirmed_wallets_in_manifest_order() {
    let signer_a = signer_for_seed("kairox-e2e-multi-a");
    let signer_b = signer_for_seed("kairox-e2e-multi-b");
    let signer_c = signer_for_seed("kairox-e2e-multi-c");
    let wallet_a = signer_a.address();
    let wallet_b = signer_b.address();
    let wallet_c = signer_c.address();

    let dir = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(
        dir.path(),
        &[
            (wallet_a, 1, "wallet-a", "E2E_KEY_A"),
            (wallet_b, 1, "wallet-b", "E2E_KEY_B"),
            (wallet_c, 1, "wallet-c", "E2E_KEY_C"),
        ],
    );

    // Every wallet's nonce read returns 0x0 (fine -- the harness doesn't
    // track per-wallet nonces, it only needs to serve a valid response);
    // eth_sendRawTransaction echoes back the real keccak256 hash of
    // whatever raw bytes it received, so three DIFFERENT wallets signing
    // three different transactions genuinely produce three different
    // hashes, proven below.
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            // Token id doesn't matter for this scenario; every receipt
            // mints to whichever wallet address is embedded in the
            // request we can't easily recover here, so instead credit
            // all three known wallets' Transfer logs -- the receipt
            // verifier only accepts the one matching the queried wallet
            // anyway (protocol::logs filters by `to`).
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [
                    transfer_log_for(wallet_a, 101),
                    transfer_log_for(wallet_b, 102),
                    transfer_log_for(wallet_c, 103),
                ],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in multi-wallet live-send scenario: {method}"),
        }),
    });

    let key_a = signing_key_hex_for_seed("kairox-e2e-multi-a");
    let key_b = signing_key_hex_for_seed("kairox-e2e-multi-b");
    let key_c = signing_key_hex_for_seed("kairox-e2e-multi-c");

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("E2E_KEY_A", &key_a)
        .env("E2E_KEY_B", &key_b)
        .env("E2E_KEY_C", &key_c)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet-manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--send",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout must be exactly one JSON line");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    assert_eq!(parsed["dry_run"], false);
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 3);
    assert_eq!(wallets[0]["label"], "wallet-a");
    assert_eq!(wallets[1]["label"], "wallet-b");
    assert_eq!(wallets[2]["label"], "wallet-c");
    let hashes: Vec<&str> = wallets
        .iter()
        .map(|w| w["tx_hash"].as_str().unwrap())
        .collect();
    assert_eq!(
        hashes
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3,
        "three distinct wallets must produce three distinct transaction hashes: {hashes:?}"
    );
    for w in wallets {
        assert_eq!(
            w["state"], "CONFIRMED_SUCCESS",
            "wallet {w:?} did not confirm"
        );
    }

    let received = server.received.lock().unwrap();
    let sends = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .count();
    assert_eq!(sends, 3, "exactly one send per wallet expected");
}

// =======================================================================
// OpenSea API failure E2E (Phase 6 Section 10): a real localhost REST
// endpoint, with the real CLI's OpenSea client redirected to it via
// KAIROX_OPENSEA_BASE_URL (an advanced/test-only override -- see
// opensea::client::OPENSEA_BASE_URL_OVERRIDE_ENV -- added specifically to
// make this possible; production behavior is unchanged unless it is
// explicitly set). One combined server answers both JSON-RPC (path "/")
// and the OpenSea REST paths, so a single localhost port stands in for
// both "the chain" and "OpenSea" the same way it would in a real session.
// =======================================================================

fn opensea_drop_details_json(slug: &str) -> Value {
    serde_json::json!({
        "collection_slug": slug,
        "collection_name": "Test Collection",
        "chain": "ethereum",
        "contract_address": format!("{NFT:#x}"),
        "drop_type": "public",
        "is_minting": true,
        "active_stage": null,
        "next_stage": null,
        "stages": [],
        "total_supply": null,
        "max_supply": null,
    })
}

fn spawn_combined_rpc_and_opensea_server(
    rpc_handler: impl Fn(&str, &Value) -> Behavior + Send + Sync + 'static,
    opensea_mint_behavior: impl Fn() -> Behavior + Send + Sync + 'static,
    slug: &'static str,
) -> LocalHttpServer {
    LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = rpc_handler(&method, &params);
            (method, behavior)
        } else if path == format!("/api/v2/drops/{slug}") {
            (
                path.to_string(),
                rpc_ok_status(opensea_drop_details_json(slug)),
            )
        } else if path == format!("/api/v2/drops/{slug}/mint") {
            (path.to_string(), opensea_mint_behavior())
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    })
}

/// Plain 200 + JSON body -- unlike `rpc_ok`, no JSON-RPC envelope, for
/// OpenSea's own REST response shape.
fn rpc_ok_status(value: Value) -> Behavior {
    Behavior::Json(value)
}

#[test]
fn opensea_401_is_reported_as_authentication_failed_before_any_signing() {
    let wallet = test_signer().address();
    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);
    const SLUG: &str = "kairox-e2e-opensea-401";

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea-401 scenario: {method}"),
            })
        },
        || Behavior::HttpStatus(401, serde_json::json!({"errors": ["invalid API key"]})),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("OpenSea rejected the API key"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a terminal OpenSea auth failure must never reach Ethereum signing"
    );
}

#[test]
fn opensea_422_eligibility_rejection_is_terminal_not_retried() {
    let wallet = test_signer().address();
    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);
    const SLUG: &str = "kairox-e2e-opensea-422";

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea-422 scenario: {method}"),
            })
        },
        || {
            Behavior::HttpStatus(
                422,
                serde_json::json!({"errors": ["wallet is not eligible for this stage"]}),
            )
        },
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not eligible"));

    let received = server.received.lock().unwrap();
    let mint_attempts = received
        .iter()
        .filter(|(p, _)| p.ends_with("/mint"))
        .count();
    assert_eq!(
        mint_attempts, 1,
        "a terminal 422 must not be retried: expected exactly one mint POST, got {mint_attempts}"
    );
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

#[test]
fn opensea_403_is_reported_as_authentication_failed_before_any_signing() {
    // 403, distinct from 401, maps to the same terminal AuthenticationFailed
    // outcome (see opensea::client::interpret) -- proven separately since
    // the spec calls both out explicitly.
    let wallet = test_signer().address();
    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);
    const SLUG: &str = "kairox-e2e-opensea-403";

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea-403 scenario: {method}"),
            })
        },
        || Behavior::HttpStatus(403, serde_json::json!({"errors": ["forbidden"]})),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("OpenSea rejected the API key"));

    let received = server.received.lock().unwrap();
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

// =======================================================================
// JSON stdout purity (Phase 6 Section 17), output-file E2E (Section 18),
// secret-leak E2E over real HTTP (Section 19), config precedence / bad
// config E2E (Sections 15-16), and `inspect` E2E (Section 2 completeness).
// =======================================================================

fn assert_stdout_is_exactly_one_json_object(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must be exactly one JSON line over real HTTP, got: {text:?}"
    );
    serde_json::from_str(lines[0]).expect("valid JSON")
}

#[test]
fn doctor_json_is_exactly_one_valid_json_object_over_real_http() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args(["doctor", "--json"])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    assert_eq!(parsed["schema_version"], 1);
}

#[test]
fn single_wallet_mint_json_dry_run_is_exactly_one_valid_json_object_over_real_http() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--json",
        ])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    assert_eq!(parsed["schema_version"], 1);
    assert!(parsed["plan_id"].as_str().unwrap().starts_with("plan_"));

    let received = server.received.lock().unwrap();
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

#[test]
fn single_wallet_mint_json_live_send_is_exactly_one_valid_json_object_over_real_http() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 7)],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        }),
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["dry_run"], false);
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0]["state"], "CONFIRMED_SUCCESS");
}

#[test]
fn receipt_json_is_exactly_one_valid_json_object_over_real_http() {
    let wallet = test_signer().address();
    let tx_hash = B256::repeat_byte(0xAB);

    let server = LocalHttpServer::spawn_json_rpc(move |method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        "eth_getTransactionReceipt" => rpc_ok(serde_json::json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "status": "0x1",
            "blockNumber": "0x1",
            "logs": [transfer_log_for(wallet, 3)],
        })),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "receipt",
            "--tx",
            &format!("{tx_hash:#x}"),
            "--collection",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--json",
        ])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["state"], "CONFIRMED_SUCCESS");
}

#[test]
fn inspect_reports_normalized_public_drop_state_over_real_http() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in inspect scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "inspect",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("mint price"));
}

// --- Output-file E2E (Section 18) ---

#[test]
fn plan_output_file_writes_valid_schema_1_json() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("plan-report.json");

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON on disk");
    assert_eq!(parsed["schema_version"], 1);
}

#[test]
fn single_wallet_mint_output_file_writes_valid_schema_1_json() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 5)],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        }),
    });
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("mint-report.json");

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON on disk");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["wallets"][0]["state"], "CONFIRMED_SUCCESS");
}

fn erc165_and_seadrop_revert_response(
    method: &str,
    params: &Value,
    supports_erc721: bool,
) -> Option<Behavior> {
    if method == "eth_call" {
        let data = params
            .get(0)
            .and_then(|c| c.get("data"))
            .and_then(Value::as_str)
            .unwrap_or("0x");
        let supports_hex = format!(
            "0x{}",
            hex::encode(
                &kairox::protocol::erc_standards::encode_supports_interface([0, 0, 0, 0])[0..4]
            )
        );
        // `supportsInterface` selector alone (any interface id) -- the
        // fixture only ever gets asked about ERC-721 in these tests.
        if data.starts_with(&supports_hex) {
            let mut word = [0u8; 32];
            word[31] = supports_erc721 as u8;
            return Some(rpc_ok(serde_json::json!(format!(
                "0x{}",
                hex::encode(word)
            ))));
        }
        // Never a SeaDrop collection -- getPublicDrop/etc. all revert.
        let seadrop_selectors = [
            sd::getPublicDropCall::SELECTOR,
            sd::getAllowedFeeRecipientsCall::SELECTOR,
            sd::getMintStatsCall::SELECTOR,
        ];
        if seadrop_selectors
            .iter()
            .any(|sel| data.starts_with(&format!("0x{}", hex::encode(sel))))
        {
            return Some(Behavior::JsonRpcError {
                code: -32000,
                message: "execution reverted: not a SeaDrop collection".into(),
            });
        }
    }
    // Not an EIP-1967 proxy (zero slot), and some arbitrary non-empty
    // runtime bytecode -- BUILTIN_REGISTRY ships empty, so no hash could
    // ever match it regardless of what's returned here.
    if method == "eth_getStorageAt" {
        return Some(rpc_ok(serde_json::json!(format!("0x{}", "0".repeat(64)))));
    }
    if method == "eth_getCode" {
        return Some(rpc_ok(serde_json::json!("0x6080604052")));
    }
    None
}

#[test]
fn generic_engine_requires_both_schema_and_erc165_confirmation() {
    let wallet = test_signer().address();
    // ERC-165 says "no" (not ERC-721) even though a schema was declared --
    // Low confidence alone must never resolve a live-send path.
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        erc165_and_seadrop_revert_response(method, params, false)
            .or_else(|| standard_read_response(method, params))
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method: {method}"),
            })
    });

    let dir = tempfile::tempdir().unwrap();
    let schema_path = dir.path().join("schema.toml");
    std::fs::write(
        &schema_path,
        "standard = \"erc721\"\nshape = \"mint_quantity\"\nprice_per_token_wei = \"0\"\n",
    )
    .unwrap();

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--generic-schema",
            schema_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"));
}

/// Mandatory adversarial test (correction pass): a perfectly valid ERC-721
/// contract (ERC-165 confirms it) that does NOT actually implement the
/// operator-declared mint semantics. ERC-165 + an operator schema must
/// never be enough to authorize a live send -- confirmed here by proving
/// the CLI never even reaches signing/broadcast, regardless of what
/// `--send --yes` and matching caps say, because no trusted-registry
/// fingerprint exists for this (or any, in this build) contract.
#[test]
fn generic_engine_erc165_true_plus_operator_schema_alone_never_signs_or_broadcasts() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_estimateGas" || method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: format!(
                    "must never be called: no independent evidence the declared mint schema is \
                     correct ({method})"
                ),
            };
        }
        // ERC-165 genuinely confirms ERC-721 -- a "perfectly valid" NFT
        // contract by that one measure alone.
        erc165_and_seadrop_revert_response(method, params, true)
            .or_else(|| standard_read_response(method, params))
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method: {method}"),
            })
    });

    let dir = tempfile::tempdir().unwrap();
    let schema_path = dir.path().join("schema.toml");
    std::fs::write(
        &schema_path,
        "standard = \"erc721\"\nshape = \"mint_quantity\"\nprice_per_token_wei = \"10000000000000000\"\n",
    )
    .unwrap();

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--generic-schema",
            schema_path.to_str().unwrap(),
            "--send",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"))
        .stderr(predicates::str::contains(
            "OPERATOR_DECLARED_UNVERIFIED_SCHEMA",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_estimateGas"),
        "must never even attempt to simulate against an unverified schema"
    );
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

/// Mandatory adversarial test (correction pass): an ERC-721 contract with a
/// permissive `fallback()` that accepts arbitrary calldata -- so
/// `eth_estimateGas` against the operator's declared (but unverified)
/// `mint(uint256)` selector would genuinely succeed. A successful
/// simulation must never be treated as proof the declared selector is
/// really a mint function: resolution must still stop before ever
/// attempting that simulation.
#[test]
fn generic_engine_permissive_fallback_estimate_gas_success_is_never_treated_as_proof() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_estimateGas" {
            // The permissive fallback would genuinely accept this and
            // report a plausible gas estimate -- which is exactly why
            // resolution must never reach this call at all for an
            // unverified schema.
            return rpc_ok(serde_json::json!("0x30d40"));
        }
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called".into(),
            };
        }
        erc165_and_seadrop_revert_response(method, params, true)
            .or_else(|| standard_read_response(method, params))
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method: {method}"),
            })
    });

    let dir = tempfile::tempdir().unwrap();
    let schema_path = dir.path().join("schema.toml");
    std::fs::write(
        &schema_path,
        "standard = \"erc721\"\nshape = \"mint_quantity\"\nprice_per_token_wei = \"10000000000000000\"\n",
    )
    .unwrap();

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--generic-schema",
            schema_path.to_str().unwrap(),
            "--send",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_estimateGas"),
        "a permissive fallback's willingness to accept the calldata must never even be probed \
         for an unverified schema"
    );
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

#[test]
fn multi_wallet_mint_output_file_writes_valid_schema_1_json_in_manifest_order() {
    let a = signer_for_seed("kairox-e2e-output-a").address();
    let b = signer_for_seed("kairox-e2e-output-b").address();
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(
        dir.path(),
        &[
            (a, 1, "wallet-a", "E2E_OUT_KEY_A"),
            (b, 1, "wallet-b", "E2E_OUT_KEY_B"),
        ],
    );
    let out_path = dir.path().join("multi-mint-report.json");

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet-manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON on disk");
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["dry_run"], true);
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets[0]["label"], "wallet-a");
    assert_eq!(wallets[1]["label"], "wallet-b");
}

// --- Secret-leak E2E over real HTTP success and failure paths (Section 19) ---

const PRIVATE_KEY_SENTINEL_SUFFIX: &str =
    "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";
const OPENSEA_KEY_SENTINEL: &str = "sentinel-opensea-api-key-must-never-leak-9f3a";
const RPC_QUERY_TOKEN_SENTINEL: &str = "sentinel-rpc-query-token-must-never-leak-7c21";
// A provider-style API key embedded as a URL *path segment* rather than a
// query parameter or basic-auth credential -- the shape real providers
// like Alchemy actually use (`.../v2/<key>`), which `mask_url`'s original
// query-only/userinfo-only redaction did not cover.
const RPC_PATH_TOKEN_SENTINEL: &str = "SentinelRpcPathToken00MustNeverLeak99";

fn assert_no_sentinels_leaked(haystack: &[u8]) {
    let text = String::from_utf8_lossy(haystack);
    assert!(
        !text.contains(PRIVATE_KEY_SENTINEL_SUFFIX),
        "private key sentinel leaked: {text}"
    );
    assert!(
        !text.contains(OPENSEA_KEY_SENTINEL),
        "OpenSea API key sentinel leaked: {text}"
    );
    assert!(
        !text.contains(RPC_QUERY_TOKEN_SENTINEL),
        "RPC query-token sentinel leaked: {text}"
    );
    assert!(
        !text.contains(RPC_PATH_TOKEN_SENTINEL),
        "RPC path-embedded token sentinel leaked: {text}"
    );
}

#[test]
fn secrets_never_leak_on_a_rejected_live_send_over_real_http() {
    // A syntactically valid but deliberately wrong signing key (it will
    // never resolve to `wallet`, so this fails closed on
    // WalletKeyMismatch) -- proves the attempted secret material never
    // leaks even on a failure path that has already loaded it.
    let wallet = test_signer().address();
    let key_hex = format!("0x{PRIVATE_KEY_SENTINEL_SUFFIX}");
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });

    let assert = kairox_bin()
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("{}?token={RPC_QUERY_TOKEN_SENTINEL}", server.url()),
        )
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert();
    let output = assert.get_output();
    assert_no_sentinels_leaked(&output.stdout);
    assert_no_sentinels_leaked(&output.stderr);
}

#[test]
fn secrets_never_leak_on_a_successful_live_send_over_real_http() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 11)],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        }),
    });

    let assert = kairox_bin()
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("{}?token={RPC_QUERY_TOKEN_SENTINEL}", server.url()),
        )
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--send",
            "--yes",
        ])
        .assert()
        .success();
    let output = assert.get_output();
    assert_no_sentinels_leaked(&output.stdout);
    assert_no_sentinels_leaked(&output.stderr);
}

#[test]
fn secrets_never_leak_on_doctor_with_a_query_token_rpc_url() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("{}?token={RPC_QUERY_TOKEN_SENTINEL}", server.url()),
        )
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env(
            "KAIROX_SIGNING_KEY",
            format!("0x{PRIVATE_KEY_SENTINEL_SUFFIX}"),
        )
        .arg("doctor")
        .assert()
        .success();
    let output = assert.get_output();
    assert_no_sentinels_leaked(&output.stdout);
    assert_no_sentinels_leaked(&output.stderr);
}

/// Regression test for a real defect found during a mainnet-hardening
/// operational session: `mask_url` originally only redacted a query
/// string or basic-auth userinfo, not a provider API key embedded as a
/// URL *path segment* (`.../v2/<key>`, the shape Alchemy and similar
/// providers actually use) -- so this exact scenario would have leaked a
/// real production key into `doctor`'s output before the fix.
#[test]
fn secrets_never_leak_on_doctor_with_a_path_embedded_rpc_token_url() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("{}/v2/{RPC_PATH_TOKEN_SENTINEL}", server.url()),
        )
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env(
            "KAIROX_SIGNING_KEY",
            format!("0x{PRIVATE_KEY_SENTINEL_SUFFIX}"),
        )
        .args(["doctor", "--json"])
        .assert()
        .success();
    let output = assert.get_output();
    assert_no_sentinels_leaked(&output.stdout);
    assert_no_sentinels_leaked(&output.stderr);
    // The endpoint must still genuinely have connected (this proves the
    // request really went to `/v2/<token>`, not that the path was simply
    // dropped or the connection silently failed).
    let parsed = assert_stdout_is_exactly_one_json_object(&output.stdout);
    let chains = parsed["chains"].as_array().unwrap();
    let ethereum = chains
        .iter()
        .find(|c| c["chain_id"] == 1)
        .expect("chain 1 must be listed");
    assert_eq!(ethereum["status"], "PASS");
}

#[test]
fn secrets_never_leak_on_an_opensea_401_failure_over_real_http() {
    let wallet = test_signer().address();
    let key_hex = format!("0x{PRIVATE_KEY_SENTINEL_SUFFIX}");
    const SLUG: &str = "kairox-e2e-secret-leak-401";

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method: {method}"),
            })
        },
        || Behavior::HttpStatus(401, serde_json::json!({"errors": ["invalid API key"]})),
        SLUG,
    );

    let assert = kairox_bin()
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("{}?token={RPC_QUERY_TOKEN_SENTINEL}", server.url()),
        )
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure();
    let output = assert.get_output();
    assert_no_sentinels_leaked(&output.stdout);
    assert_no_sentinels_leaked(&output.stderr);
}

// --- Bad-config E2E (Section 16) ---

// NOTE: `doctor` deliberately never fails the process on a bad config --
// it is a diagnostic tool that reports a `[FAIL (...)]` line inline and
// keeps going (see its own real-HTTP tests above), so it cannot be used
// to prove "invalid config -> nonzero exit". `plan` genuinely depends on
// config resolution succeeding before it can do anything, so a bad config
// there is a real, unrecoverable error with a real nonzero exit code.
fn bad_config_kairox_bin(config_path: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = kairox_bin();
    cmd.args([
        "--config",
        config_path.to_str().unwrap(),
        "plan",
        "0x000000000000000000000000000000000000c0de",
        "--wallet",
        "0x0000000000000000000000000000000000000aaa",
    ]);
    cmd
}

#[test]
fn bad_config_unknown_field_is_rejected_with_config_invalid_and_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "version = 1\nsome_unknown_field = true\n").unwrap();

    bad_config_kairox_bin(&path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("CONFIG_INVALID"));
}

#[test]
fn bad_config_unsupported_schema_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "version = 99\n").unwrap();

    bad_config_kairox_bin(&path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("CONFIG_INVALID"));
}

#[test]
fn bad_config_malformed_toml_is_rejected_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "this is not valid TOML at all {{{\n").unwrap();

    bad_config_kairox_bin(&path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("CONFIG_INVALID"));
}

#[test]
fn bad_config_secret_looking_value_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "version = 1\n[opensea]\napi_key_env = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
    )
    .unwrap();

    bad_config_kairox_bin(&path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("CONFIG_INVALID"));
}

// --- Config precedence E2E (Section 15): CLI > env > config > default ---

#[test]
fn config_precedence_cli_rpc_url_wins_over_env_and_config() {
    // Two distinct real servers: the config/env-named one must never
    // receive any traffic once --rpc-url is given explicitly on the CLI --
    // proving the CLI > env > config precedence link, on top of the
    // existing `config_named_rpc_env_var_actually_connects_to_the_localhost_server`
    // test (which proves the env > config link).
    let wallet = test_signer().address();
    let winning = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method: {method}"),
        })
    });
    let losing = LocalHttpServer::spawn_json_rpc(|_method, _p| Behavior::JsonRpcError {
        code: -32000,
        message: "this endpoint must never be contacted".into(),
    });

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "version = 1\n[chains.ethereum]\nread_rpc_env = [\"E2E_PRECEDENCE_LOSING_URL\"]\n",
    )
    .unwrap();

    kairox_bin()
        .env("E2E_PRECEDENCE_LOSING_URL", losing.url())
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--rpc-url",
            &winning.url(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("mint value:"));

    assert!(
        losing
            .received
            .lock()
            .unwrap()
            .iter()
            .all(|(m, _)| m != "eth_chainId"),
        "the config/env-resolved endpoint must never be contacted once --rpc-url is given"
    );
    assert!(
        winning
            .received
            .lock()
            .unwrap()
            .iter()
            .any(|(m, _)| m == "eth_chainId"),
        "the explicit --rpc-url endpoint must have been contacted"
    );
}

#[test]
fn opensea_429_is_bounded_retried_then_terminal_rate_limited() {
    const SLUG: &str = "kairox-e2e-opensea-429";
    let wallet = test_signer().address();
    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea-429 scenario: {method}"),
            })
        },
        || Behavior::HttpStatus(429, serde_json::json!({"errors": ["rate limited"]})),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("rate-limited"));

    let received = server.received.lock().unwrap();
    let mint_attempts = received
        .iter()
        .filter(|(p, _)| p.ends_with("/mint"))
        .count();
    assert_eq!(
        mint_attempts, 3,
        "429 is retryable up to the bounded MAX_ATTEMPTS=3, then terminal: got {mint_attempts}"
    );
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

#[test]
fn opensea_500_is_bounded_retried_then_terminal_server_error() {
    const SLUG: &str = "kairox-e2e-opensea-500";
    let wallet = test_signer().address();
    let key_hex = signing_key_hex_for_seed(SINGLE_WALLET_SEED);

    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in opensea-500 scenario: {method}"),
            })
        },
        || Behavior::HttpStatus(500, serde_json::json!({"errors": ["internal error"]})),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("OpenSea server error"));

    let received = server.received.lock().unwrap();
    let mint_attempts = received
        .iter()
        .filter(|(p, _)| p.ends_with("/mint"))
        .count();
    assert_eq!(mint_attempts, 3, "500 is bounded-retried, never unbounded");
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

// =======================================================================
// OpenSea allow-list and server-signed E2E (Phase 6 Sections 8-9): real
// Merkle-proof / EIP-712 material, generated locally, verified through the
// real localhost RPC (getAllowListMerkleRoot / getSignedMintValidationParams
// / getFeeRecipientIsAllowed), through the real CLI, ending in a real
// broadcast + receipt over the real localhost server.
// =======================================================================

const SEADROP: Address = address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");
const FEE_RECIPIENT: Address = address!("0000000000000000000000000000000000fee000");

fn sample_mint_params_abi(restrict_fee_recipients: bool) -> sd::MintParamsAbi {
    sd::MintParamsAbi {
        mintPrice: U256::from(0u64),
        maxTotalMintableByWallet: U256::from(5u64),
        startTime: U256::from(0u64),
        endTime: U256::from(9_999_999_999u64),
        dropStageIndex: U256::from(1u64),
        maxTokenSupplyForStage: U256::from(1_000u64),
        feeBps: U256::from(0u64),
        restrictFeeRecipients: restrict_fee_recipients,
    }
}

fn root_hex(root: B256) -> Value {
    serde_json::json!(format!(
        "0x{}",
        hex::encode(sd::getAllowListMerkleRootCall::abi_encode_returns(&root))
    ))
}

fn permissive_signed_mint_validation_params() -> sd::SignedMintValidationParamsAbi {
    sd::SignedMintValidationParamsAbi {
        minMintPrice: alloy_primitives::Uint::from(0u64),
        maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(1_000u64),
        minStartTime: alloy_primitives::Uint::from(0u64),
        maxEndTime: alloy_primitives::Uint::from(9_999_999_999u64),
        maxMaxTokenSupplyForStage: alloy_primitives::Uint::from(1_000_000u64),
        minFeeBps: 0,
        maxFeeBps: 10_000,
    }
}

fn validation_params_hex(p: sd::SignedMintValidationParamsAbi) -> Value {
    serde_json::json!(format!(
        "0x{}",
        hex::encode(sd::getSignedMintValidationParamsCall::abi_encode_returns(
            &p
        ))
    ))
}

fn fee_recipient_allowed_hex(allowed: bool) -> Value {
    serde_json::json!(format!(
        "0x{}",
        hex::encode(sd::getFeeRecipientIsAllowedCall::abi_encode_returns(
            &allowed
        ))
    ))
}

/// eth_call dispatch for the OpenSea-specific on-chain reads
/// (getAllowListMerkleRoot / getSignedMintValidationParams /
/// getFeeRecipientIsAllowed), falling back to `standard_read_response` for
/// everything else (chainId, block, priority fee, nonce, balance, gas
/// estimate).
fn opensea_read_response(
    method: &str,
    params: &Value,
    allow_list_root: Option<B256>,
    validation_params: Option<sd::SignedMintValidationParamsAbi>,
    fee_recipient_allowed: Option<bool>,
) -> Option<Behavior> {
    if method == "eth_call" {
        let data = params
            .get(0)
            .and_then(|c| c.get("data"))
            .and_then(Value::as_str)
            .unwrap_or("0x");
        let root_sel = format!(
            "0x{}",
            hex::encode(sd::getAllowListMerkleRootCall::SELECTOR)
        );
        let val_sel = format!(
            "0x{}",
            hex::encode(sd::getSignedMintValidationParamsCall::SELECTOR)
        );
        let fee_sel = format!(
            "0x{}",
            hex::encode(sd::getFeeRecipientIsAllowedCall::SELECTOR)
        );
        if data.starts_with(&root_sel) {
            return Some(rpc_ok(root_hex(
                allow_list_root.expect("allow_list_root must be configured for this scenario"),
            )));
        }
        if data.starts_with(&val_sel) {
            return Some(rpc_ok(validation_params_hex(
                validation_params.expect("validation_params must be configured for this scenario"),
            )));
        }
        if data.starts_with(&fee_sel) {
            return Some(rpc_ok(fee_recipient_allowed_hex(
                fee_recipient_allowed
                    .expect("fee_recipient_allowed must be configured for this scenario"),
            )));
        }
    }
    standard_read_response(method, params)
}

fn allow_list_mint_response_json(mint_params: sd::MintParamsAbi) -> Value {
    let call = sd::mintAllowListCall {
        nftContract: NFT,
        feeRecipient: FEE_RECIPIENT,
        minterIfNotPayer: Address::ZERO,
        quantity: U256::from(1u64),
        mintParams: mint_params,
        proof: vec![],
    };
    serde_json::json!({
        "to": format!("{SEADROP:#x}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
        "value": "0x0",
        "chain": "ethereum",
    })
}

fn allow_list_leaf(wallet: Address, mint_params: &sd::MintParamsAbi) -> B256 {
    seadrop_crypto::allow_list_merkle_leaf(wallet, &NormalizedMintParams::from(mint_params))
}

/// A raw k256 signing key built from the same seed bytes as a
/// `LocalSigner`, used only to sign an arbitrary EIP-712 digest directly
/// for test fixtures (`LocalSigner` deliberately never exposes its key
/// material for anything but signing a real `UnsignedEip1559Tx`).
fn raw_signing_key_for_seed(seed: &str) -> k256::ecdsa::SigningKey {
    let bytes = keccak256(seed.as_bytes()).0;
    k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap()
}

/// Decode a single `address` argument from `0x<selector><32-byte-word>...`
/// calldata: the address occupies the low 20 bytes of that first word.
fn decode_single_address_arg(data: &str) -> Address {
    let stripped = data.trim_start_matches("0x");
    let word = &stripped[8..8 + 64];
    let addr_hex = &word[24..64];
    format!("0x{addr_hex}").parse().unwrap()
}

fn sign_digest_65_bytes(key: &k256::ecdsa::SigningKey, digest: B256) -> [u8; 65] {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let (signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash(digest.as_slice()).unwrap();
    let mut out = [0u8; 65];
    out[0..64].copy_from_slice(&signature.to_bytes());
    out[64] = if recovery_id.is_y_odd() { 1 } else { 0 };
    out
}

fn signed_mint_response_json(
    wallet: Address,
    mint_params: sd::MintParamsAbi,
    signer_seed: &str,
    salt: U256,
) -> Value {
    let normalized = NormalizedMintParams::from(&mint_params);
    let digest = seadrop_crypto::signed_mint_digest(
        1,
        SEADROP,
        NFT,
        wallet,
        FEE_RECIPIENT,
        &normalized,
        salt,
    );
    let key = raw_signing_key_for_seed(signer_seed);
    let signature = sign_digest_65_bytes(&key, digest);
    let call = sd::mintSignedCall {
        nftContract: NFT,
        feeRecipient: FEE_RECIPIENT,
        minterIfNotPayer: Address::ZERO,
        quantity: U256::from(1u64),
        mintParams: mint_params,
        salt,
        signature: Bytes::from(signature.to_vec()),
    };
    serde_json::json!({
        "to": format!("{SEADROP:#x}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
        "value": "0x0",
        "chain": "ethereum",
    })
}

#[test]
fn opensea_allow_list_mint_verifies_real_merkle_proof_and_completes_end_to_end() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-allowlist";

    let mint_params = sample_mint_params_abi(false);
    // Single-leaf tree: leaf == root, proof == [] -- the simplest genuine
    // Merkle verification (still a real recomputation against a real
    // on-chain-reported root, not a bypass).
    let leaf = allow_list_leaf(wallet, &mint_params);
    let response = allow_list_mint_response_json(mint_params);

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| match method {
            "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
            "eth_getTransactionReceipt" => {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                rpc_ok(serde_json::json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [transfer_log_for(wallet, 42)],
                }))
            }
            _ => opensea_read_response(method, params, Some(leaf), None, None).unwrap_or(
                Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method in allow-list scenario: {method}"),
                },
            ),
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("BROADCAST RESULT"))
        .stdout(predicates::str::contains("receipt: CONFIRMED_SUCCESS"));

    let received = server.received.lock().unwrap();
    assert_eq!(
        received
            .iter()
            .filter(|(m, _)| m == "eth_sendRawTransaction")
            .count(),
        1
    );
    assert!(
        received.iter().any(|(m, _)| m == "eth_call"),
        "the on-chain allow-list root must genuinely have been fetched via eth_call"
    );
}

#[test]
fn opensea_server_signed_mint_verifies_real_eip712_signature_and_completes_end_to_end() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-signed";
    const SIGNER_SEED: &str = "kairox-e2e-signed-mint-authorized-signer";

    let mint_params = sample_mint_params_abi(true);

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| match method {
            "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
            "eth_getTransactionReceipt" => {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                rpc_ok(serde_json::json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [transfer_log_for(wallet, 99)],
                }))
            }
            _ => opensea_read_response(
                method,
                params,
                None,
                Some(permissive_signed_mint_validation_params()),
                Some(true),
            )
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in signed-mint scenario: {method}"),
            }),
        },
        move || {
            rpc_ok_status(signed_mint_response_json(
                wallet,
                sample_mint_params_abi(true),
                SIGNER_SEED,
                U256::from(1u64),
            ))
        },
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("BROADCAST RESULT"))
        .stdout(predicates::str::contains("receipt: CONFIRMED_SUCCESS"));

    let received = server.received.lock().unwrap();
    assert_eq!(
        received
            .iter()
            .filter(|(m, _)| m == "eth_sendRawTransaction")
            .count(),
        1
    );
    let _ = mint_params;
}

// =======================================================================
// Malicious OpenSea response E2E (Phase 6 Section 11): every case must
// fail closed before Kairox ever signs an Ethereum transaction.
// =======================================================================

#[test]
fn opensea_response_with_invalid_merkle_proof_is_rejected_before_signing() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-bad-proof";

    let mint_params = sample_mint_params_abi(false);
    let response = allow_list_mint_response_json(mint_params);
    // The on-chain root deliberately does not match this wallet's leaf.
    let wrong_root = keccak256(b"a-root-that-does-not-match-any-real-leaf");

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            opensea_read_response(method, params, Some(wrong_root), None, None).unwrap_or(
                Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method in bad-proof scenario: {method}"),
                },
            )
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Merkle"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an invalid Merkle proof must never reach Ethereum signing"
    );
}

#[test]
fn opensea_response_targeting_wrong_collection_is_rejected_before_signing() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-wrong-collection";
    let other_collection: Address = address!("00000000000000000000000000000000000dead0");

    let mint_params = sample_mint_params_abi(false);
    let call = sd::mintAllowListCall {
        nftContract: other_collection, // wrong: does not match the requested NFT
        feeRecipient: FEE_RECIPIENT,
        minterIfNotPayer: Address::ZERO,
        quantity: U256::from(1u64),
        mintParams: mint_params,
        proof: vec![],
    };
    let response = serde_json::json!({
        "to": format!("{SEADROP:#x}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
        "value": "0x0",
        "chain": "ethereum",
    });

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in wrong-collection scenario: {method}"),
            })
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "does not match the requested collection",
        ));

    let received = server.received.lock().unwrap();
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
    // Wrong-collection is rejected purely from decoded calldata -- it must
    // never even reach the on-chain Merkle-root lookup.
    assert!(!received.iter().any(|(p, _)| p == "getAllowListMerkleRoot"));
}

#[test]
fn opensea_response_with_mutated_server_signature_is_rejected_before_signing() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-bad-signature";
    const SIGNER_SEED: &str = "kairox-e2e-mutated-signature-signer";

    let mint_params = sample_mint_params_abi(true);
    let response = signed_mint_response_json(wallet, mint_params, SIGNER_SEED, U256::from(1u64));
    // Flip a hex nibble squarely inside the signature's real 64 `r`/`s`
    // bytes (the dynamic `bytes signature` ABI encoding right-pads its
    // final partial word with zeros -- mutating the very last character
    // would land in that padding and be a silent no-op, so this targets a
    // position well clear of it: 100 hex characters from the end is inside
    // the second-to-last full 32-byte word, entirely real signature data).
    let mut data = response["data"].as_str().unwrap().to_string();
    let target = data.len() - 100;
    let mutated_char = if data.as_bytes()[target] == b'0' {
        '1'
    } else {
        '0'
    };
    data.replace_range(target..target + 1, &mutated_char.to_string());
    let mut response = response;
    response["data"] = serde_json::json!(data);

    // Critical: validation params must be permissive ONLY for the genuine
    // authorized signer's address. Otherwise a mutated signature that
    // still happens to recover to *some* valid-looking (but wrong)
    // address would incorrectly pass "authorization" against a
    // constant-regardless-of-address mock -- proving nothing about the
    // signature check. Any other queried address gets the real contract's
    // own "unauthorized" sentinel (`maxMaxTotalMintableByWallet == 0`).
    let authorized_signer = LocalSigner::from_bytes(keccak256(SIGNER_SEED.as_bytes()).0)
        .unwrap()
        .address();
    let zero_sentinel = sd::SignedMintValidationParamsAbi {
        minMintPrice: alloy_primitives::Uint::from(0u64),
        maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(0u64),
        minStartTime: alloy_primitives::Uint::from(0u64),
        maxEndTime: alloy_primitives::Uint::from(0u64),
        maxMaxTokenSupplyForStage: alloy_primitives::Uint::from(0u64),
        minFeeBps: 0,
        maxFeeBps: 0,
    };

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            if method == "eth_call" {
                let data = params
                    .get(0)
                    .and_then(|c| c.get("data"))
                    .and_then(Value::as_str)
                    .unwrap_or("0x");
                let val_sel = format!(
                    "0x{}",
                    hex::encode(sd::getSignedMintValidationParamsCall::SELECTOR)
                );
                if data.starts_with(&val_sel) {
                    let queried_signer = decode_single_address_arg(data);
                    let params_to_return = if queried_signer == authorized_signer {
                        permissive_signed_mint_validation_params()
                    } else {
                        zero_sentinel.clone()
                    };
                    return rpc_ok(validation_params_hex(params_to_return));
                }
                let fee_sel = format!(
                    "0x{}",
                    hex::encode(sd::getFeeRecipientIsAllowedCall::SELECTOR)
                );
                if data.starts_with(&fee_sel) {
                    return rpc_ok(fee_recipient_allowed_hex(true));
                }
            }
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in bad-signature scenario: {method}"),
            })
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure();

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a mutated server-mint signature must never reach Ethereum signing"
    );
}

#[test]
fn opensea_response_with_unsupported_token_gated_selector_is_rejected_before_signing() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-token-gated";

    let call = sd::mintAllowedTokenHolderCall {
        nftContract: NFT,
        feeRecipient: FEE_RECIPIENT,
        minterIfNotPayer: Address::ZERO,
        mintParams: sd::TokenGatedMintParamsAbi {
            allowedNftToken: NFT,
            allowedNftTokenIds: vec![U256::from(1u64)],
        },
    };
    let response = serde_json::json!({
        "to": format!("{SEADROP:#x}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
        "value": "0x0",
        "chain": "ethereum",
    });

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in token-gated scenario: {method}"),
            })
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("token-gated"));

    let received = server.received.lock().unwrap();
    assert!(!received.iter().any(|(m, _)| m == "eth_sendRawTransaction"));
}

fn public_mint_response_json(
    nft_contract: Address,
    fee_recipient: Address,
    minter_if_not_payer: Address,
    quantity: u64,
    value: U256,
    chain: &str,
    to: Address,
) -> Value {
    let call = sd::mintPublicCall {
        nftContract: nft_contract,
        feeRecipient: fee_recipient,
        minterIfNotPayer: minter_if_not_payer,
        quantity: U256::from(quantity),
    };
    serde_json::json!({
        "to": format!("{to:#x}"),
        "data": format!("0x{}", hex::encode(call.abi_encode())),
        "value": format!("0x{value:x}"),
        "chain": chain,
    })
}

/// Runs one malicious-response scenario end to end and asserts: the
/// OpenSea HTTP request genuinely happened, the response was genuinely
/// parsed (an `eth_call` for other on-chain reads may or may not occur
/// depending on how early rejection happens), the CLI failed with the
/// given stderr substring, and zero `eth_sendRawTransaction` occurred.
fn assert_malicious_opensea_response_rejected(
    test_label: &'static str,
    slug: &'static str,
    response: Value,
    expected_stderr_substring: &str,
) {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in {test_label} scenario: {method}"),
            })
        },
        move || rpc_ok_status(response.clone()),
        slug,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            slug,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            expected_stderr_substring.to_string(),
        ));

    let received = server.received.lock().unwrap();
    assert!(
        received.iter().any(|(m, _)| m.ends_with("/mint")),
        "[{test_label}] the OpenSea mint request must genuinely have been made"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "[{test_label}] a malicious OpenSea response must never reach Ethereum signing"
    );
}

#[test]
fn opensea_response_targeting_wrong_target_address_is_rejected_before_signing() {
    let not_the_seadrop_contract: Address = address!("00000000000000000000000000000000000bad00");
    let response = public_mint_response_json(
        NFT,
        FEE_RECIPIENT,
        Address::ZERO,
        1,
        U256::ZERO,
        "ethereum",
        not_the_seadrop_contract,
    );
    assert_malicious_opensea_response_rejected(
        "wrong-target",
        "kairox-e2e-malicious-wrong-target",
        response,
        "is not a target Kairox can validate",
    );
}

#[test]
fn opensea_response_with_wrong_chain_is_rejected_before_signing() {
    let response = public_mint_response_json(
        NFT,
        FEE_RECIPIENT,
        Address::ZERO,
        1,
        U256::ZERO,
        "base", // Kairox was asked to mint on chain id 1 (ethereum), not base.
        SEADROP,
    );
    assert_malicious_opensea_response_rejected(
        "wrong-chain",
        "kairox-e2e-malicious-wrong-chain",
        response,
        "does not match requested chain",
    );
}

#[test]
fn opensea_response_with_wrong_minter_is_rejected_before_signing() {
    let someone_elses_wallet: Address = address!("0000000000000000000000000000000000005e1f");
    let response = public_mint_response_json(
        NFT,
        FEE_RECIPIENT,
        someone_elses_wallet, // not zero, not the requested wallet
        1,
        U256::ZERO,
        "ethereum",
        SEADROP,
    );
    assert_malicious_opensea_response_rejected(
        "wrong-minter",
        "kairox-e2e-malicious-wrong-minter",
        response,
        "does not match the requested wallet",
    );
}

#[test]
fn opensea_response_with_wrong_quantity_is_rejected_before_signing() {
    let response = public_mint_response_json(
        NFT,
        FEE_RECIPIENT,
        Address::ZERO,
        2, // CLI was asked to mint 1 (the default --quantity)
        U256::ZERO,
        "ethereum",
        SEADROP,
    );
    assert_malicious_opensea_response_rejected(
        "wrong-quantity",
        "kairox-e2e-malicious-wrong-quantity",
        response,
        "does not match the requested quantity",
    );
}

#[test]
fn opensea_response_with_unsafe_value_exceeding_safety_cap_is_rejected_before_signing() {
    // Default --max-mint-value-wei is 1e18 (1 ETH); this response claims a
    // 2 ETH transaction value for an otherwise well-formed public mint.
    let response = public_mint_response_json(
        NFT,
        FEE_RECIPIENT,
        Address::ZERO,
        1,
        U256::from(2_000_000_000_000_000_000u128),
        "ethereum",
        SEADROP,
    );
    assert_malicious_opensea_response_rejected(
        "unsafe-value",
        "kairox-e2e-malicious-unsafe-value",
        response,
        "unsafe",
    );
}

#[test]
fn opensea_response_signed_by_an_unauthorized_signer_is_rejected_before_signing() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-opensea-unauthorized-signer";
    const AUTHORIZED_SEED: &str = "kairox-e2e-unauthorized-signer-test-authorized";
    const UNAUTHORIZED_SEED: &str = "kairox-e2e-unauthorized-signer-test-actual-signer";

    let mint_params = sample_mint_params_abi(true);
    // A cryptographically VALID EIP-712 signature -- just from a signer the
    // mocked on-chain state never authorizes. Distinct from the
    // mutated-signature scenario, which corrupts the bytes themselves;
    // this proves authorization is checked against the genuinely recovered
    // signer's address, not merely "does some signature verify."
    let response =
        signed_mint_response_json(wallet, mint_params, UNAUTHORIZED_SEED, U256::from(7u64));

    let authorized_signer = LocalSigner::from_bytes(keccak256(AUTHORIZED_SEED.as_bytes()).0)
        .unwrap()
        .address();
    let zero_sentinel = sd::SignedMintValidationParamsAbi {
        minMintPrice: alloy_primitives::Uint::from(0u64),
        maxMaxTotalMintableByWallet: alloy_primitives::Uint::from(0u64),
        minStartTime: alloy_primitives::Uint::from(0u64),
        maxEndTime: alloy_primitives::Uint::from(0u64),
        maxMaxTokenSupplyForStage: alloy_primitives::Uint::from(0u64),
        minFeeBps: 0,
        maxFeeBps: 0,
    };

    let server = spawn_combined_rpc_and_opensea_server(
        move |method, params| {
            if method == "eth_call" {
                let data = params
                    .get(0)
                    .and_then(|c| c.get("data"))
                    .and_then(Value::as_str)
                    .unwrap_or("0x");
                let val_sel = format!(
                    "0x{}",
                    hex::encode(sd::getSignedMintValidationParamsCall::SELECTOR)
                );
                if data.starts_with(&val_sel) {
                    let queried_signer = decode_single_address_arg(data);
                    let params_to_return = if queried_signer == authorized_signer {
                        permissive_signed_mint_validation_params()
                    } else {
                        zero_sentinel.clone()
                    };
                    return rpc_ok(validation_params_hex(params_to_return));
                }
                let fee_sel = format!(
                    "0x{}",
                    hex::encode(sd::getFeeRecipientIsAllowedCall::SELECTOR)
                );
                if data.starts_with(&fee_sel) {
                    return rpc_ok(fee_recipient_allowed_hex(true));
                }
            }
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method in unauthorized-signer scenario: {method}"),
            })
        },
        move || rpc_ok_status(response.clone()),
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not an authorized signer"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unauthorized (but validly-signing) signer must never reach Ethereum signing"
    );
}

// =======================================================================
// Multi-wallet uncertain-send + out-of-order completion (Phase 6 Sections
// 13/24): every case decodes the REAL raw signed transaction bytes
// `eth_sendRawTransaction` received and cryptographically recovers the
// actual sending wallet from its signature -- never inferred from request
// order, which is not guaranteed under real concurrent dispatch.
// =======================================================================

/// The RLP field layout `SignedEip1559Tx::raw_bytes` produces (see
/// `kairox::signing::transaction`), decodable here since that module's
/// own decodable mirror struct is private to it.
#[derive(alloy_rlp::RlpDecodable)]
struct DecodedSignedTxFields {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Address,
    value: U256,
    data: Bytes,
    access_list: Vec<AccessListItem>,
    y_parity: u64,
    r: U256,
    s: U256,
}

/// Decode a real raw signed EIP-1559 transaction (as received by
/// `eth_sendRawTransaction`) and cryptographically recover the address
/// that actually signed it -- the only trustworthy way to know which
/// manifest wallet a given broadcast request belongs to, since concurrent
/// multi-wallet dispatch gives no ordering or connection-identity
/// guarantee.
fn decode_raw_tx_sender(raw_hex: &str) -> Address {
    let bytes = hex::decode(raw_hex.trim_start_matches("0x")).expect("valid raw tx hex");
    assert_eq!(
        bytes[0], 0x02,
        "expected an EIP-1559 (type 0x02) transaction"
    );
    let mut body = &bytes[1..];
    let decoded: DecodedSignedTxFields =
        alloy_rlp::Decodable::decode(&mut body).expect("valid RLP-encoded signed tx body");

    let unsigned = UnsignedEip1559Tx {
        chain_id: decoded.chain_id,
        nonce: decoded.nonce,
        max_priority_fee_per_gas: decoded.max_priority_fee_per_gas,
        max_fee_per_gas: decoded.max_fee_per_gas,
        gas_limit: decoded.gas_limit,
        to: decoded.to,
        value: decoded.value,
        data: decoded.data,
        access_list: decoded.access_list,
    };
    let signing_hash = unsigned.signing_hash();

    let mut sig65 = [0u8; 65];
    sig65[0..32].copy_from_slice(&decoded.r.to_be_bytes::<32>());
    sig65[32..64].copy_from_slice(&decoded.s.to_be_bytes::<32>());
    sig65[64] = decoded.y_parity as u8;

    recover_from_prehash(signing_hash, &sig65).expect("valid ECDSA signature recovers a sender")
}

#[test]
fn multi_wallet_uncertain_send_isolates_exactly_the_uncertain_wallet() {
    let signer_a = signer_for_seed("kairox-e2e-uncertain-multi-a");
    let signer_b = signer_for_seed("kairox-e2e-uncertain-multi-b");
    let signer_c = signer_for_seed("kairox-e2e-uncertain-multi-c");
    let wallet_a = signer_a.address();
    let wallet_b = signer_b.address();
    let wallet_c = signer_c.address();

    let dir = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(
        dir.path(),
        &[
            (wallet_a, 1, "wallet-a", "E2E_UNCERTAIN_KEY_A"),
            (wallet_b, 1, "wallet-b", "E2E_UNCERTAIN_KEY_B"),
            (wallet_c, 1, "wallet-c", "E2E_UNCERTAIN_KEY_C"),
        ],
    );

    // Track exactly one send attempt per wallet, so a bug that retried or
    // resent wallet B's transaction (a second signature, a replacement, a
    // same-nonce altered transaction) would be caught here even though the
    // process only observes the connection close, not a "no" answer.
    let sends_by_wallet: Arc<Mutex<std::collections::HashMap<Address, u32>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let sends_by_wallet_for_handler = sends_by_wallet.clone();

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => {
            let raw_hex = params.get(0).and_then(Value::as_str).unwrap_or("0x");
            let sender = decode_raw_tx_sender(raw_hex);
            *sends_by_wallet_for_handler
                .lock()
                .unwrap()
                .entry(sender)
                .or_insert(0) += 1;
            if sender == wallet_b {
                // The full raw transaction has already been read by this
                // point (decode_raw_tx_sender only works on bytes actually
                // received) -- now simulate a node that accepted the bytes
                // and then vanished before answering.
                Behavior::CloseWithoutResponding
            } else {
                echo_tx_hash_behavior(params)
            }
        }
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [
                    transfer_log_for(wallet_a, 201),
                    transfer_log_for(wallet_c, 203),
                ],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in uncertain-multi scenario: {method}"),
        }),
    });

    let key_a = signing_key_hex_for_seed("kairox-e2e-uncertain-multi-a");
    let key_b = signing_key_hex_for_seed("kairox-e2e-uncertain-multi-b");
    let key_c = signing_key_hex_for_seed("kairox-e2e-uncertain-multi-c");

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("E2E_UNCERTAIN_KEY_A", &key_a)
        .env("E2E_UNCERTAIN_KEY_B", &key_b)
        .env("E2E_UNCERTAIN_KEY_C", &key_c)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet-manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--send",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout must be exactly one JSON line");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 3);
    // Manifest order preserved regardless of which wallet was uncertain.
    assert_eq!(wallets[0]["label"], "wallet-a");
    assert_eq!(wallets[1]["label"], "wallet-b");
    assert_eq!(wallets[2]["label"], "wallet-c");

    assert_eq!(wallets[0]["state"], "CONFIRMED_SUCCESS");
    assert_eq!(wallets[1]["state"], "UNCERTAIN");
    assert_eq!(wallets[1]["error_code"], "BROADCAST_UNCERTAIN");
    assert_eq!(wallets[2]["state"], "CONFIRMED_SUCCESS");

    let sends = sends_by_wallet.lock().unwrap();
    assert_eq!(
        *sends.get(&wallet_b).unwrap_or(&0),
        1,
        "wallet B must have been sent exactly once -- no retry, no replacement, no second signature"
    );
    assert_eq!(*sends.get(&wallet_a).unwrap_or(&0), 1);
    assert_eq!(*sends.get(&wallet_c).unwrap_or(&0), 1);
}

#[test]
fn multi_wallet_out_of_order_completion_still_reports_manifest_order() {
    let signer_a = signer_for_seed("kairox-e2e-reorder-multi-a");
    let signer_b = signer_for_seed("kairox-e2e-reorder-multi-b");
    let signer_c = signer_for_seed("kairox-e2e-reorder-multi-c");
    let wallet_a = signer_a.address();
    let wallet_b = signer_b.address();
    let wallet_c = signer_c.address();

    let dir = tempfile::tempdir().unwrap();
    let manifest_path = write_manifest(
        dir.path(),
        &[
            (wallet_a, 1, "wallet-a", "E2E_REORDER_KEY_A"),
            (wallet_b, 1, "wallet-b", "E2E_REORDER_KEY_B"),
            (wallet_c, 1, "wallet-c", "E2E_REORDER_KEY_C"),
        ],
    );

    // Track the order in which sends actually reached the server (by real
    // wallet identity, cryptographically recovered) -- then deliberately
    // delay responding to whichever send arrives *first* and *second* so
    // the real completion order is forced to differ from manifest order
    // (A, B, C): C's send is answered immediately, then B, then A last,
    // producing a genuine completion order of roughly C, B, A.
    let completion_order: Arc<Mutex<Vec<Address>>> = Arc::new(Mutex::new(Vec::new()));
    let completion_order_for_handler = completion_order.clone();

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => {
            let raw_hex = params.get(0).and_then(Value::as_str).unwrap_or("0x");
            let sender = decode_raw_tx_sender(raw_hex);
            // Stagger responses so wallet A (first in manifest order) is
            // deliberately the slowest to actually get its HTTP response,
            // forcing the real *completion* order away from manifest
            // order -- recorded below, AFTER the stagger, since it is the
            // order responses are actually sent back that must differ
            // from manifest order for this test to be meaningful (the
            // order requests *arrive in* is expected to already roughly
            // match manifest order, since that's dispatch/connect order,
            // not completion order).
            // Margins are wide (not just "a few ms") deliberately: under
            // `cargo test`'s default parallelism, many other tests' OS
            // threads compete for CPU at the same time, and a narrow
            // margin was observed to occasionally not reorder completion
            // at all under that contention.
            if sender == wallet_a {
                std::thread::sleep(std::time::Duration::from_millis(600));
            } else if sender == wallet_b {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            completion_order_for_handler.lock().unwrap().push(sender);
            echo_tx_hash_behavior(params)
        }
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [
                    transfer_log_for(wallet_a, 301),
                    transfer_log_for(wallet_b, 302),
                    transfer_log_for(wallet_c, 303),
                ],
            }))
        }
        _ => standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in out-of-order scenario: {method}"),
        }),
    });

    let key_a = signing_key_hex_for_seed("kairox-e2e-reorder-multi-a");
    let key_b = signing_key_hex_for_seed("kairox-e2e-reorder-multi-b");
    let key_c = signing_key_hex_for_seed("kairox-e2e-reorder-multi-c");

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("E2E_REORDER_KEY_A", &key_a)
        .env("E2E_REORDER_KEY_B", &key_b)
        .env("E2E_REORDER_KEY_C", &key_c)
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet-manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--send",
            "--yes",
            "--json",
            "--broadcast-concurrency",
            "3",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout must be exactly one JSON line");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    let wallets = parsed["wallets"].as_array().unwrap();
    assert_eq!(wallets.len(), 3);

    // The SessionReport must stay in manifest order (A, B, C) no matter
    // what real completion order the server observed.
    assert_eq!(wallets[0]["label"], "wallet-a");
    assert_eq!(wallets[1]["label"], "wallet-b");
    assert_eq!(wallets[2]["label"], "wallet-c");
    for w in wallets {
        assert_eq!(
            w["state"], "CONFIRMED_SUCCESS",
            "wallet {w:?} did not confirm"
        );
    }

    let order = completion_order.lock().unwrap();
    assert_eq!(
        order.len(),
        3,
        "all three wallets must have genuinely reached eth_sendRawTransaction"
    );
    assert_ne!(
        *order,
        vec![wallet_a, wallet_b, wallet_c],
        "this test is only meaningful if real dispatch/response order actually differed from \
         manifest order -- if it didn't, the staggered delays above need adjusting, not the \
         report-ordering assertion above"
    );
}

// =======================================================================
// Robinhood Chain Testnet enablement: chain id 46630 must appear
// separately from Robinhood Chain mainnet (4663) in real CLI output, and
// chain-id mismatch protection must apply to it exactly like every other
// chain -- no special-cased fallback to 4663.
// =======================================================================

#[test]
fn doctor_json_shows_robinhood_testnet_separately_from_mainnet() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args(["doctor", "--json"])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    let chains = parsed["chains"].as_array().unwrap();

    let mainnet = chains
        .iter()
        .find(|c| c["chain_id"] == 4663)
        .expect("Robinhood Chain mainnet must be listed");
    assert_eq!(mainnet["name"], "Robinhood Chain");

    let testnet = chains
        .iter()
        .find(|c| c["chain_id"] == 46630)
        .expect("Robinhood Chain Testnet must be listed");
    assert_eq!(testnet["name"], "Robinhood Chain Testnet");
    assert_ne!(mainnet["name"], testnet["name"]);
    assert_ne!(mainnet["chain_id"], testnet["chain_id"]);
}

#[test]
fn doctor_json_connects_both_robinhood_testnet_endpoints_with_the_documented_env_vars() {
    // Exactly the two-endpoint configuration documented for operators:
    // a READ_WRITE public RPC and a SEQUENCER endpoint.
    let public_server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0xb626")),
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });
    let sequencer_server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0xb626")),
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_46630_0_URL", public_server.url())
        .env("KAIROX_RPC_46630_0_ROLE", "READ_WRITE")
        .env("KAIROX_RPC_46630_0_LABEL", "robinhood-testnet-public")
        .env("KAIROX_RPC_46630_1_URL", sequencer_server.url())
        .env("KAIROX_RPC_46630_1_ROLE", "SEQUENCER")
        .env("KAIROX_RPC_46630_1_LABEL", "robinhood-testnet-sequencer")
        .args(["doctor", "--json"])
        .assert()
        .success();
    let parsed = assert_stdout_is_exactly_one_json_object(&assert.get_output().stdout);
    let chains = parsed["chains"].as_array().unwrap();
    let testnet = chains
        .iter()
        .find(|c| c["chain_id"] == 46630)
        .expect("Robinhood Chain Testnet must be listed");
    assert_eq!(testnet["endpoint_count"], 2);
    assert_eq!(testnet["connected_count"], 2);
    let details = testnet["endpoint_details"].as_array().unwrap();
    let joined = details
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("robinhood-testnet-public"));
    assert!(joined.contains("robinhood-testnet-sequencer"));
}

#[test]
fn bench_chain_46630_connects_to_a_real_local_endpoint_reporting_the_right_chain_id() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0xb626")), // 46630 in hex
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_46630_0_URL", server.url())
        .args(["bench", "--chain", "46630"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Robinhood Chain Testnet"))
        .stdout(predicates::str::contains("chain id 46630"))
        .stdout(predicates::str::contains("1 of 1 endpoints connected"));
}

#[test]
fn bench_chain_robinhood_dash_testnet_alias_resolves_the_same_as_46630() {
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0xb626")),
        "eth_blockNumber" => rpc_ok(serde_json::json!("0x1")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_46630_0_URL", server.url())
        .args(["bench", "--chain", "robinhood-testnet"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Robinhood Chain Testnet"))
        .stdout(predicates::str::contains("chain id 46630"));
}

#[test]
fn bench_chain_46630_fails_closed_when_the_endpoint_actually_reports_4663() {
    // A real localhost endpoint that (mistakenly, or as a misconfigured
    // testnet operator error) reports Robinhood Chain MAINNET's id (4663)
    // when Kairox asked for Robinhood Chain TESTNET (46630). This must be
    // reported as a wrong-chain endpoint, never silently accepted and
    // never silently treated as a fallback to 4663.
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1237")), // 4663 in hex
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_46630_0_URL", server.url())
        .args(["bench", "--chain", "46630"])
        .assert()
        .success()
        .stdout(predicates::str::contains("WRONG_CHAIN"))
        .stdout(predicates::str::contains("expected=46630"))
        .stdout(predicates::str::contains("reported=4663"))
        .stdout(predicates::str::contains("0 of 1 endpoints connected"));
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A `getPublicDrop` responder with caller-chosen start/end times, otherwise
/// identical to [`standard_read_response`]'s fixture.
fn read_response_with_stage_window(
    method: &str,
    params: &Value,
    start_time: u64,
    end_time: u64,
) -> Option<Behavior> {
    if method == "eth_call" {
        let data = params
            .get(0)
            .and_then(|c| c.get("data"))
            .and_then(Value::as_str)
            .unwrap_or("0x");
        let selector_hex = format!("0x{}", hex::encode(sd::getPublicDropCall::SELECTOR));
        if data.starts_with(&selector_hex) {
            let public_drop = PublicDropAbi {
                mintPrice: alloy_primitives::Uint::from(10_000_000_000_000_000u128),
                startTime: alloy_primitives::Uint::from(start_time),
                endTime: alloy_primitives::Uint::from(end_time),
                maxTotalMintableByWallet: 5,
                feeBps: 0,
                restrictFeeRecipients: false,
            };
            return Some(rpc_ok(serde_json::json!(format!(
                "0x{}",
                hex::encode(sd::getPublicDropCall::abi_encode_returns(&public_drop))
            ))));
        }
    }
    standard_read_response(method, params)
}

#[test]
fn watch_public_future_stage_waits_then_executes_at_t0() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let stage_start = unix_now() + 2; // a genuine, short future stage

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        match method {
            "eth_sendRawTransaction" => return echo_tx_hash_behavior(params),
            "eth_getTransactionReceipt" => {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                return rpc_ok(serde_json::json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [transfer_log_for(wallet, 9)],
                }));
            }
            _ => {}
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in watch scenario: {method}"),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stdout(predicates::str::contains("BROADCAST RESULT"))
        .stdout(predicates::str::contains("receipt: CONFIRMED_SUCCESS"));

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "watch must broadcast exactly one transaction, got {sends:?}"
    );
}

// ---------------------------------------------------------------------
// Final hardening pass items 3-4: `watch --rehearsal` exercises the
// actual watch pipeline (resolve, early pool connect, full benchmark,
// stage polling, near-T0 rewarm, fresh state, sign, serialize) and stops
// immediately before eth_sendRawTransaction. Scenario A: PUBLIC engine.
// ---------------------------------------------------------------------
#[test]
fn watch_public_rehearsal_prepares_and_signs_but_never_broadcasts() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let stage_start = unix_now() + 2;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" || method == "eth_getTransactionReceipt" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: format!("must never be called in a rehearsal scenario: {method}"),
            };
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in watch rehearsal scenario: {method}"),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--rehearsal",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"))
        .stdout(predicates::str::contains("tx hash: 0x"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never call eth_sendRawTransaction"
    );
    assert!(
        !received
            .iter()
            .any(|(m, _)| m == "eth_getTransactionReceipt"),
        "watch --rehearsal must never poll for a receipt"
    );
    // The real pipeline (early full benchmark, fresh nonce/gas-estimate
    // reads) genuinely ran -- proves this is not a stub.
    assert!(received.iter().any(|(m, _)| m == "eth_getTransactionCount"));
    assert!(received.iter().any(|(m, _)| m == "eth_estimateGas"));
}

// ---------------------------------------------------------------------
// Final hardening pass item 4, scenario B: OPENSEA signed engine. Auto
// -discovery finds an already-active signed presale; watch waits (near
// -instantly, since it's already active), requests the real mint
// -builder authorization, validates it locally, simulates on-chain,
// signs, and serializes -- then stops before ever broadcasting.
// ---------------------------------------------------------------------
#[test]
fn watch_opensea_signed_rehearsal_prepares_and_signs_but_never_broadcasts() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-watch-opensea-rehearsal";
    const SIGNER_SEED: &str = "kairox-e2e-watch-rehearsal-authorized-signer";
    // Already active -- watch's wait completes near-instantly, keeping
    // this test fast and deterministic.
    let stage_start = unix_now() - 60;
    let stage_end = unix_now() + 3600;
    let start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let end_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_end as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
                    code: -32000,
                    message: format!("must never be called in a rehearsal scenario: {method}"),
                },
                _ => opensea_read_response(
                    &method,
                    &params,
                    None,
                    Some(permissive_signed_mint_validation_params()),
                    Some(true),
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!(
                        "unexpected RPC method in watch-opensea-rehearsal scenario: {method}"
                    ),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "collection_slug": SLUG,
                    "collection_name": "Test Collection",
                    "chain": "ethereum",
                    "contract_address": format!("{NFT:#x}"),
                    "drop_type": "signed_presale",
                    "is_minting": true,
                    "active_stage": {
                        "uuid": "stage-1",
                        "stage_type": "signed_presale",
                        "label": null,
                        "price": "0",
                        "price_currency_address": "0x0000000000000000000000000000000000000000",
                        "start_time": start_rfc3339,
                        "end_time": end_rfc3339,
                        "max_per_wallet": "10",
                    },
                    "next_stage": null,
                    "stages": [],
                    "total_supply": null,
                    "max_supply": null,
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            (
                path.to_string(),
                rpc_ok_status(signed_mint_response_json(
                    wallet,
                    sample_mint_params_abi(true),
                    SIGNER_SEED,
                    U256::from(1u64),
                )),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--rehearsal",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"))
        .stdout(predicates::str::contains("tx hash: 0x"));

    let received = server.received.lock().unwrap();
    assert!(
        received.iter().any(|(p, _)| p.ends_with("/mint")),
        "rehearsal should have requested the real mint-builder authorization"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never call eth_sendRawTransaction"
    );
    assert!(
        !received
            .iter()
            .any(|(m, _)| m == "eth_getTransactionReceipt"),
        "watch --rehearsal must never poll for a receipt"
    );
    assert!(received.iter().any(|(m, _)| m == "eth_estimateGas"));
}

#[test]
fn watch_without_auto_send_or_rehearsal_refuses_to_run_and_touches_no_endpoint() {
    let wallet = test_signer().address();
    kairox_bin()
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--auto-send"))
        .stderr(predicates::str::contains("--rehearsal"));
}

// ---------------------------------------------------------------------
// Round 6 items 1 + 3(A/B/C): the watch RpcPool must run its full,
// multi-sample benchmark entirely *before* the stage wait begins (not
// after), that full benchmark must never repeat once the wait is over,
// and no full benchmark/telemetry work may land after dispatch --
// telemetry summary printing is off the dispatch-critical path, and the
// only latency check remaining near T0 is the always-unconditional
// single-sample `rewarm_all` liveness probe.
// ---------------------------------------------------------------------
#[test]
fn watch_public_runs_the_full_benchmark_before_the_wait_never_repeats_it_and_touches_no_endpoint_after_dispatch()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let stage_start = unix_now() + 2;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        match method {
            "eth_sendRawTransaction" => return echo_tx_hash_behavior(params),
            "eth_getTransactionReceipt" => {
                let queried_hash = params
                    .get(0)
                    .and_then(Value::as_str)
                    .unwrap_or("0x")
                    .to_string();
                return rpc_ok(serde_json::json!({
                    "transactionHash": queried_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "logs": [transfer_log_for(wallet, 9)],
                }));
            }
            _ => {}
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!(
                    "unexpected method in watch benchmark-ordering scenario: {method}"
                ),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();

    let received = server.received.lock().unwrap();
    let methods: Vec<&str> = received.iter().map(|(m, _)| m.as_str()).collect();

    // `eth_blockNumber` is used for exactly two purposes anywhere in this
    // codebase: `RpcPool::benchmark_all` (one sample per configured
    // sample_count) and `RpcPool::rewarm_all` (exactly one sample). No
    // other read ever calls it, so its call pattern alone is enough to
    // prove the ordering these items require, independent of the
    // unrelated `eth_call`/fee/nonce clusters that `resolve_watch_engine`
    // and each `wait_for_stage` poll cycle also produce on their own,
    // separate connections.
    //
    // No chain-id override was given, so the reported "0x1" chain id
    // resolves to the Ethereum execution profile, whose benchmark policy
    // is 6 samples -- see `execution::profile::ethereum`.
    const FULL_BENCHMARK_SAMPLES: usize = 6;

    let send_idx = methods
        .iter()
        .position(|m| *m == "eth_sendRawTransaction")
        .expect("watch must broadcast exactly one transaction");

    // Group eth_blockNumber indices into maximal consecutive runs.
    let mut runs: Vec<(usize, usize)> = Vec::new(); // (start_idx, len)
    let mut i = 0;
    while i < methods.len() {
        if methods[i] == "eth_blockNumber" {
            let start = i;
            while i < methods.len() && methods[i] == "eth_blockNumber" {
                i += 1;
            }
            runs.push((start, i - start));
        } else {
            i += 1;
        }
    }

    // Item A / item 3's "benchmark count == 1 before the stage wait":
    // exactly one run is long enough to be the full multi-sample
    // benchmark (it will actually measure sample_count + 1, since the
    // immediately-following `rewarm_all` call fuses onto the same run).
    let full_runs: Vec<&(usize, usize)> = runs
        .iter()
        .filter(|(_, len)| *len >= FULL_BENCHMARK_SAMPLES)
        .collect();
    assert_eq!(
        full_runs.len(),
        1,
        "expected exactly one full multi-sample benchmark burst (>= {FULL_BENCHMARK_SAMPLES} \
         consecutive eth_blockNumber calls), got runs {runs:?} in {methods:?}"
    );
    let (full_run_start, full_run_len) = *full_runs[0];
    let full_run_end = full_run_start + full_run_len;

    // Item B / item C: every other eth_blockNumber call, taken together,
    // is exactly one single sample -- the always-unconditional near-T0
    // `rewarm_all` inside run_live_mint -- and it happens strictly after
    // the full benchmark, strictly before dispatch. No second full
    // benchmark, and nothing benchmark-shaped after the send.
    let other_block_number_indices: Vec<usize> = methods
        .iter()
        .enumerate()
        .filter(|(idx, m)| {
            **m == "eth_blockNumber" && !(*idx >= full_run_start && *idx < full_run_end)
        })
        .map(|(idx, _)| idx)
        .collect();
    assert_eq!(
        other_block_number_indices,
        vec![
            *other_block_number_indices
                .first()
                .expect("expected exactly one near-T0 rewarm sample outside the full benchmark")
        ],
        "expected exactly one eth_blockNumber call outside the full benchmark burst (the \
         near-T0 rewarm), never a second full benchmark and never one after dispatch, got \
         {other_block_number_indices:?} in {methods:?}"
    );
    let near_t0_rewarm_idx = other_block_number_indices[0];
    assert!(
        full_run_end <= near_t0_rewarm_idx,
        "the full benchmark burst must complete strictly before the near-T0 rewarm sample"
    );
    assert!(
        near_t0_rewarm_idx < send_idx,
        "the near-T0 rewarm must happen strictly before dispatch, never after"
    );
}

#[test]
fn watch_public_stage_already_ended_stops_before_any_send() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let now = unix_now();

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called: stage already ended".into(),
            };
        }
        // Both start and end are in the past -- a genuinely ended stage.
        read_response_with_stage_window(method, params, now.saturating_sub(200), now - 100)
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in ended-stage watch scenario: {method}"),
            })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "public",
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("ended"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an already-ended stage must never be broadcast to"
    );
}

#[test]
fn watch_auto_send_without_explicit_spend_caps_refuses_before_touching_anything() {
    let wallet = test_signer().address();
    // No KAIROX_SIGNING_KEY set, and no server pointed at all -- if the cap
    // check isn't the very first thing watch does, this test would either
    // hang trying to connect or fail with a different, misleading error.
    kairox_bin()
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("MISSING_SPEND_CAPS"))
        .stderr(predicates::str::contains("failed to load signing key").not());
}

#[test]
fn watch_manifest_target_missing_spend_caps_is_rejected_before_any_target_runs() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("watchlist.toml");
    std::fs::write(
        &manifest_path,
        format!(
            r#"
[[target]]
collection = "{NFT:#x}"
wallet = "0x000000000000000000000000000000000000dEaD"
max_mint_value_wei = "0"
max_gas_cost_wei = "1000000000000000000"
# max_total_spend_wei intentionally omitted
"#
        ),
    )
    .unwrap();

    kairox_bin()
        .args([
            "watch",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--auto-send",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("MISSING_SPEND_CAPS"))
        .stderr(predicates::str::contains("max-total-spend-wei"));
}

#[test]
fn auto_engine_resolves_seadrop_public_with_evidence_reported() {
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in auto-resolve scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "plan",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .success();

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: Public"))
        .stderr(predicates::str::contains("SeaDropAdapter"))
        .stderr(predicates::str::contains("confidence: High"));
}

#[test]
fn auto_engine_unrecognized_contract_fails_closed_as_unsupported_protocol() {
    let wallet = test_signer().address();
    // getPublicDrop reverts on this contract (as it genuinely would for an
    // arbitrary non-SeaDrop ERC-721) and no --slug was given, so neither
    // adapter can produce a confident match.
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        "eth_call" => Behavior::JsonRpcError {
            code: -32000,
            message: "execution reverted".into(),
        },
        // The generic-engine adapter always resolves an implementation
        // bytecode hash to check against the (empty) trusted registry,
        // regardless of whether --generic-schema was given.
        "eth_getStorageAt" => rpc_ok(serde_json::json!(format!("0x{}", "0".repeat(64)))),
        "eth_getCode" => rpc_ok(serde_json::json!("0x6080604052")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unrecognized protocol must never be sent to, calldata-guessed or not"
    );
}

#[test]
fn auto_engine_thirdweb_shaped_contract_without_registry_match_is_unsupported() {
    // A target that responds correctly to thirdweb's Drop selectors, but
    // is not SeaDrop-shaped (getPublicDrop reverts) and no --slug was
    // given. execution::thirdweb_registry::BUILTIN_REGISTRY ships empty
    // by design, so ThirdwebAdapter can find selector-level evidence but
    // never a trusted-registry match -- proving `--engine auto` engages
    // thirdweb detection at all, and correctly refuses to auto-select it
    // on selector compatibility alone.
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_call" {
            // Only thirdweb-shaped selectors succeed (via the shared
            // helper); anything else -- SeaDrop's getPublicDrop included
            // -- reverts, exactly as a real non-SeaDrop contract would.
            return thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32000,
                message: "execution reverted".into(),
            });
        }
        thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in auto-thirdweb scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{THIRDWEB_DROP:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"))
        .stderr(predicates::str::contains("ThirdwebAdapter"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "selector-only thirdweb evidence must never authorize a live send"
    );
}

#[test]
fn auto_engine_ignores_manifold_entirely_without_manifold_extension_flag() {
    // ManifoldAdapter must never attempt any read, let alone match,
    // unless --manifold-extension was explicitly supplied -- there is no
    // verified way to auto-discover a Manifold claim's three identifiers
    // from a bare collection address. This proves `--engine auto`
    // against an otherwise-unrecognized contract behaves identically
    // whether or not ManifoldAdapter is registered.
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1")),
        "eth_call" => Behavior::JsonRpcError {
            code: -32000,
            message: "execution reverted".into(),
        },
        "eth_getStorageAt" => rpc_ok(serde_json::json!(format!("0x{}", "0".repeat(64)))),
        "eth_getCode" => rpc_ok(serde_json::json!("0x6080604052")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("UNSUPPORTED_PROTOCOL"))
        // ManifoldAdapter is still listed among "adapters tried" (it was
        // asked, and correctly declined instantly) -- what must never
        // appear is any evidence implying it actually read/matched
        // anything, since no --manifold-extension was given.
        .stderr(predicates::str::contains("Manifold claim").not())
        .stderr(predicates::str::contains("trusted-registry fingerprint match").not());
}

#[test]
fn watchlist_concurrency_never_exceeds_the_configured_bound() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const BOUND: usize = 2;
    const TARGET_COUNT: usize = 6;

    let current = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let current_h = current.clone();
    let peak_h = peak.clone();

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        let n = current_h.fetch_add(1, Ordering::SeqCst) + 1;
        peak_h.fetch_max(n, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(25));
        let result = standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in concurrency scenario: {method}"),
        });
        current_h.fetch_sub(1, Ordering::SeqCst);
        result
    });

    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("watchlist.toml");
    let mut manifest = String::new();
    for _ in 0..TARGET_COUNT {
        manifest.push_str(&format!(
            "\n[[target]]\ncollection = \"{NFT:#x}\"\nwallet = \"{wallet:#x}\"\n\
             max_mint_value_wei = \"1\"\nmax_gas_cost_wei = \"1000000000000000000\"\n\
             max_total_spend_wei = \"1000000000000000000\"\n"
        ));
    }
    std::fs::write(&manifest_path, manifest).unwrap();

    // Every target's mint value cap is set to 1 wei -- far below the
    // fixture's mint price, so every target fails closed on
    // SAFETY_CAP_EXCEEDED right after its reads complete, never reaching
    // eth_sendRawTransaction. This isolates the thing under test (read
    // concurrency across the whole watchlist) from broadcast mocking.
    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--engine",
            "public",
            "--auto-send",
            "--max-concurrent-targets",
            &BOUND.to_string(),
        ])
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure();

    let observed_peak = peak.load(Ordering::SeqCst);
    assert!(
        observed_peak <= BOUND,
        "observed peak concurrent RPC connections {observed_peak} exceeded the configured \
         bound {BOUND}"
    );
    assert!(
        observed_peak >= 2,
        "test is meaningless if concurrency never actually overlapped (observed {observed_peak})"
    );
}

#[test]
fn watch_wallet_allocation_exhausted_while_waiting_stops_safely() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    let stage_start = unix_now() + 2;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called: allocation exhausted".into(),
            };
        }
        if method == "eth_call" {
            let data = params
                .get(0)
                .and_then(|c| c.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let stats_hex = format!("0x{}", hex::encode(sd::getMintStatsCall::SELECTOR));
            if data.starts_with(&stats_hex) {
                // This wallet has already minted its full allocation (5, the
                // fixture's maxTotalMintableByWallet) -- discovered only
                // once watch actually polls, not at the very first read.
                return rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(sd::getMintStatsCall::abi_encode_returns(
                        &sd::getMintStatsReturn {
                            minterNumMinted: U256::from(5u64),
                            currentTotalSupply: U256::from(10u64),
                            maxSupply: U256::from(1_000u64),
                        }
                    ))
                )));
            }
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in allocation-exhausted scenario: {method}"),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "public",
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure();

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an exhausted wallet allocation must never be broadcast to"
    );
}

// ---------------------------------------------------------------------
// True-final-release-gate item 8: dedicated STAGE_ALREADY_LIVE tests.
//
// 8A (real, non-rehearsal `watch --auto-send` against an already-live
// eligible PUBLIC stage must refuse with STAGE_ALREADY_LIVE, never sign
// or broadcast) is covered here as a clean, dedicated case. 8B (the
// OpenSea-signed equivalent) requires the real, wallet-specific
// mint-builder preflight to positively verify actionability -- see the
// FINAL SEMANTIC CORRECTION block further below
// (`watch_auto_send_on_an_active_signed_stage_with_verified_eligibility_refuses_with_stage_already_live`
// et al.), which supersedes what used to be here: an earlier version of
// this test suite treated `EligibilityState::UnknownUntilActive` alone
// as sufficient grounds for STAGE_ALREADY_LIVE on an OpenSea stage --
// that was too broad and has been corrected (see the semantic-correction
// section's own comment block for the full explanation). This block
// keeps the exhaustion-must-not-falsely-claim-STAGE_ALREADY_LIVE case
// (8C, wallet allocation) for the PUBLIC engine, which was always
// evidence-based and needed no correction. 8D
// (supply exhaustion) exercises the identical `has_known_capacity()`
// check as 8C with a different field and is intentionally not
// duplicated as a second test. 8E (the rehearsal exception against an
// active stage) is already covered by
// `watch_opensea_signed_rehearsal_prepares_and_signs_but_never_broadcasts`
// and `watch_public_rehearsal_prepares_and_signs_but_never_broadcasts`.
// 8F (mint on an active stage is unaffected) is covered by every
// existing `mint --send` test against an active public/OpenSea stage
// (e.g. `mint_public_stage_signs_and_broadcasts_successfully`) -- none
// of those routes through `watch`'s resolver at all, so item 8 cannot
// regress them by construction.
// ---------------------------------------------------------------------

#[test]
fn watch_auto_send_on_an_already_active_public_stage_refuses_with_stage_already_live() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    // Already active *at the moment watch resolves*, not merely
    // "becomes active during the wait" -- this is 8A's literal scenario.
    let stage_start = unix_now() - 60;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called: stage is already live, watch must refuse".into(),
            };
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in already-live scenario: {method}"),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE"))
        .stderr(predicates::str::contains("kairox mint"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an already-live stage must never be signed or broadcast by a real watch --auto-send run"
    );
}

#[test]
fn watch_auto_send_on_an_exhausted_active_public_stage_does_not_falsely_claim_already_live() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    // Active right now by timestamp alone -- but this wallet has already
    // minted its full allocation (5 of 5). 8C: a naive "is *some* stage
    // active" check would wrongly emit STAGE_ALREADY_LIVE here; the real
    // resolver/eligibility pipeline must instead surface the genuine
    // exhaustion outcome (ALLOCATION_EXCEEDED) -- never fabricate
    // STAGE_ALREADY_LIVE from the timestamp alone, and never send.
    let stage_start = unix_now() - 60;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called: allocation exhausted".into(),
            };
        }
        if method == "eth_call" {
            let data = params
                .get(0)
                .and_then(|c| c.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let stats_hex = format!("0x{}", hex::encode(sd::getMintStatsCall::SELECTOR));
            if data.starts_with(&stats_hex) {
                return rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(sd::getMintStatsCall::abi_encode_returns(
                        &sd::getMintStatsReturn {
                            minterNumMinted: U256::from(5u64),
                            currentTotalSupply: U256::from(10u64),
                            maxSupply: U256::from(1_000u64),
                        }
                    ))
                )));
            }
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in exhausted-active scenario: {method}"),
            },
        )
    });

    let output = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "an exhausted stage must never succeed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains("ALLOCATION_EXCEEDED") || stderr.contains("allocation exhausted"),
        "expected the genuine exhaustion outcome (not a fabricated already-live claim), got: \
         {stderr}"
    );
    assert!(
        !stderr.contains("STAGE_ALREADY_LIVE"),
        "an exhausted stage must never be reported as STAGE_ALREADY_LIVE just because its \
         timestamp window is active -- got: {stderr}"
    );

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an exhausted allocation must never be broadcast to, already-live or not"
    );
}

// ---------------------------------------------------------------------
// KAIROX -- FINAL SEMANTIC CORRECTION: `WatchStageDecision::AlreadyLive`
// alone (temporally active + `EligibilityState::Eligible |
// UnknownUntilActive`) is NOT sufficient evidence for an OpenSea
// signed/allowlist/FCFS/FCFA stage to refuse with STAGE_ALREADY_LIVE --
// `UnknownUntilActive` is not proof any specific wallet can execute it.
// `resolve_watch_engine` now additionally requires
// `resolver_adapters::check_opensea_stage_actionable_now` to positively
// verify a real, wallet-specific mint-builder response (the exact same
// request/validation path `run_opensea_mint` itself uses) before ever
// emitting STAGE_ALREADY_LIVE for an OpenSea stage. This block covers
// every outcome of that preflight, across all three engine-selection
// modes.
// ---------------------------------------------------------------------

/// Shared fixture: an on-chain contract/collection lookup plus a
/// `GET /api/v2/drops/{slug}` reporting one already-active `signed_presale`
/// stage (`start_time` in the past, `end_time` far future) -- exactly what
/// `--engine auto` needs to auto-discover it, and what `--engine opensea
/// --slug` needs to see it as the drop's current `active_stage`. The
/// `mint_behavior` closure controls what `POST /api/v2/drops/{slug}/mint`
/// (the real wallet-specific preflight `check_opensea_stage_actionable_now`
/// performs) returns, so each scenario below only needs to supply that one
/// outcome.
fn spawn_active_signed_stage_server(
    slug: &'static str,
    mint_behavior: impl Fn() -> Behavior + Send + Sync + 'static,
) -> LocalHttpServer {
    LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
                    code: -32000,
                    message: "must never be called: STAGE_ALREADY_LIVE must refuse before any \
                              signing or broadcast"
                        .into(),
                },
                _ => opensea_read_response(
                    &method,
                    &params,
                    None,
                    Some(permissive_signed_mint_validation_params()),
                    Some(true),
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!(
                        "unexpected RPC method in active-signed-stage scenario: {method}"
                    ),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": slug,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{slug}") {
            (
                path.to_string(),
                rpc_ok_status(opensea_stage_json(slug, "signed_presale", NFT)),
            )
        } else if path == format!("/api/v2/drops/{slug}/mint") {
            (path.to_string(), mint_behavior())
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    })
}

#[test]
fn watch_auto_send_on_an_active_signed_stage_with_verified_eligibility_refuses_with_stage_already_live()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-active-signed-verified-eligible";
    const SIGNER_SEED: &str = "kairox-e2e-active-signed-verified-eligible-signer";

    let server = spawn_active_signed_stage_server(SLUG, move || {
        rpc_ok_status(signed_mint_response_json(
            wallet,
            sample_mint_params_abi(true),
            SIGNER_SEED,
            U256::from(1u64),
        ))
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE"))
        .stderr(predicates::str::contains("kairox mint"));

    let received = server.received.lock().unwrap();
    assert!(
        received
            .iter()
            .any(|(m, _)| m == &format!("/api/v2/drops/{SLUG}/mint")),
        "the real wallet-specific preflight must actually have run"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a verified-actionable stage must still never be signed or broadcast by watch itself"
    );
}

#[test]
fn watch_auto_send_on_an_active_signed_stage_with_clear_ineligibility_falls_through_to_a_future_public_stage()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-active-signed-ineligible";
    let public_stage_start = unix_now() + 2;

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" => echo_tx_hash_behavior(&params),
                "eth_getTransactionReceipt" => {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    rpc_ok(serde_json::json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [transfer_log_for(wallet, 7)],
                    }))
                }
                _ => read_response_with_stage_window(
                    &method,
                    &params,
                    public_stage_start,
                    32_503_680_000,
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!(
                        "unexpected RPC method in ineligible-signed scenario: {method}"
                    ),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            (
                path.to_string(),
                rpc_ok_status(opensea_stage_json(SLUG, "signed_presale", NFT)),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            // A clean, unambiguous 422 eligibility rejection -- the exact
            // classification `execution::opensea_engine` itself already
            // produces for this response shape.
            (
                path.to_string(),
                Behavior::HttpStatus(
                    422,
                    serde_json::json!({"errors": ["wallet is not on the allowlist"]}),
                ),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE").not())
        .stdout(predicates::str::contains("BROADCAST RESULT"));

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "an ineligible signed stage must never be dispatched to -- exactly one broadcast, to \
         the legitimately-watched future public stage, expected: {sends:?}"
    );
}

/// Shared assertion for item 5's three ambiguous-preflight scenarios
/// (429, timeout/transport-failure, 5xx): none of them may ever be
/// reported as STAGE_ALREADY_LIVE (that would fabricate positive proof
/// from an outcome that proves nothing) or as a clean ineligibility
/// rejection (that would fabricate a negative proof just as wrongly) --
/// only the distinct, fail-closed `ACTIVE_STAGE_ELIGIBILITY_UNKNOWN`.
fn assert_ambiguous_preflight_refuses_with_eligibility_unknown(
    slug: &'static str,
    mint_behavior: impl Fn() -> Behavior + Send + Sync + 'static,
) {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = spawn_active_signed_stage_server(slug, mint_behavior);

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "ACTIVE_STAGE_ELIGIBILITY_UNKNOWN",
        ))
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE").not());

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an ambiguous preflight outcome must never be signed or broadcast"
    );
}

#[test]
fn watch_auto_send_on_an_active_signed_stage_with_a_rate_limited_preflight_is_eligibility_unknown()
{
    assert_ambiguous_preflight_refuses_with_eligibility_unknown(
        "kairox-e2e-active-signed-429",
        || Behavior::HttpStatus(429, serde_json::json!({"errors": ["rate limited"]})),
    );
}

#[test]
fn watch_auto_send_on_an_active_signed_stage_with_a_server_error_preflight_is_eligibility_unknown()
{
    assert_ambiguous_preflight_refuses_with_eligibility_unknown(
        "kairox-e2e-active-signed-500",
        || Behavior::HttpStatus(500, serde_json::json!({"errors": ["internal error"]})),
    );
}

#[test]
fn watch_auto_send_on_an_active_signed_stage_with_a_transport_failure_preflight_is_eligibility_unknown()
 {
    // The bounded-retry preflight (`request_mint_with_bounded_retry`)
    // treats a connection that closes without responding at all
    // (`ApiUnavailable`/transport failure) exactly like a timeout for
    // retry purposes -- both are transient/no-response outcomes, and
    // both must land as ACTIVE_STAGE_ELIGIBILITY_UNKNOWN, never
    // STAGE_ALREADY_LIVE or a fabricated ineligibility.
    assert_ambiguous_preflight_refuses_with_eligibility_unknown(
        "kairox-e2e-active-signed-transport-failure",
        || Behavior::CloseWithoutResponding,
    );
}

#[test]
fn watch_engine_public_auto_send_on_an_already_active_eligible_stage_refuses_with_stage_already_live()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    // The item 6 audit: explicit `--engine public` must obey the exact
    // same WATCH-vs-LIVE contract `--engine auto` does, not bypass it.
    let stage_start = unix_now() - 60;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        if method == "eth_sendRawTransaction" {
            return Behavior::JsonRpcError {
                code: -32000,
                message: "must never be called: explicit --engine public must also refuse an \
                          already-live stage"
                    .into(),
            };
        }
        read_response_with_stage_window(method, params, stage_start, 32_503_680_000).unwrap_or(
            Behavior::JsonRpcError {
                code: -32601,
                message: format!(
                    "unexpected method in explicit-public-already-live scenario: {method}"
                ),
            },
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "public",
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "explicit --engine public must refuse an already-live stage before any broadcast"
    );
}

#[test]
fn watch_engine_opensea_slug_auto_send_on_an_active_signed_stage_with_verified_eligibility_refuses_with_stage_already_live()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-explicit-slug-active-signed-eligible";
    const SIGNER_SEED: &str = "kairox-e2e-explicit-slug-active-signed-eligible-signer";

    // The item 6 audit: an operator-provided `--slug` must obey the same
    // contract as auto-discovery -- no bypass just because the drop
    // identity was given explicitly rather than discovered.
    let server = spawn_active_signed_stage_server(SLUG, move || {
        rpc_ok_status(signed_mint_response_json(
            wallet,
            sample_mint_params_abi(true),
            SIGNER_SEED,
            U256::from(1u64),
        ))
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE"));

    let received = server.received.lock().unwrap();
    assert!(
        received
            .iter()
            .any(|(m, _)| m == &format!("/api/v2/drops/{SLUG}/mint")),
        "the real wallet-specific preflight must actually have run for the explicit slug too"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an explicit-slug verified-actionable stage must still never be signed or broadcast by \
         watch itself"
    );
}

/// Promotion-gate item 1: the explicit-slug negative case the prior
/// pass's positive test (`..._verified_eligibility_...`) never actually
/// covered -- an active signed stage the wallet is clearly ineligible
/// for, with no future stage inside that same explicitly-requested slug
/// (`next_stage: null`, per `opensea_stage_json`). Must terminate on the
/// genuine ineligibility outcome: never `STAGE_ALREADY_LIVE` (it isn't),
/// never `ACTIVE_STAGE_ELIGIBILITY_UNKNOWN` (the rejection is
/// unambiguous, not ambiguous), never signed/broadcast, never
/// re-resolved/bounced outside the operator's explicit slug (an
/// operator-provided `--slug` carries no discovered stage identity to
/// exclude -- see `is_clear_ineligibility_rejection`'s doc comment --
/// so this is a single, direct, un-retried terminal failure).
#[test]
fn watch_engine_opensea_slug_active_signed_ineligible_with_no_future_stage_in_slug_terminates_cleanly()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-explicit-slug-active-signed-ineligible-no-future";

    let server = spawn_active_signed_stage_server(SLUG, || {
        Behavior::HttpStatus(
            422,
            serde_json::json!({"errors": ["wallet is not on the allowlist"]}),
        )
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE").not())
        .stderr(predicates::str::contains("ACTIVE_STAGE_ELIGIBILITY_UNKNOWN").not());

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a clearly-ineligible active stage must never be signed or broadcast"
    );
    assert!(
        !received
            .iter()
            .any(|(m, _)| m == "eth_getTransactionReceipt"),
        "no receipt polling must ever occur without a broadcast"
    );
}

/// Promotion-gate item 1's second requirement: an explicit `--slug` with
/// a genuine *future* stage (no `active_stage` at all yet -- only
/// `next_stage`) must remain completely unaffected by the new
/// already-live preflight, since `is_temporally_active` is false and the
/// check is never even attempted. Real, non-rehearsal `--auto-send`
/// waits, then dispatches normally once the stage opens.
#[test]
fn watch_engine_opensea_slug_future_stage_waits_then_executes_normally() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-explicit-slug-future-stage";
    const SIGNER_SEED: &str = "kairox-e2e-explicit-slug-future-stage-signer";
    let stage_start = unix_now() + 2;
    let start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" => echo_tx_hash_behavior(&params),
                "eth_getTransactionReceipt" => {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    rpc_ok(serde_json::json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [transfer_log_for(wallet, 11)],
                    }))
                }
                _ => opensea_read_response(
                    &method,
                    &params,
                    None,
                    Some(permissive_signed_mint_validation_params()),
                    Some(true),
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!(
                        "unexpected RPC method in explicit-slug-future scenario: {method}"
                    ),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/drops/{SLUG}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "collection_slug": SLUG,
                    "collection_name": "Test Collection",
                    "chain": "ethereum",
                    "contract_address": format!("{NFT:#x}"),
                    "drop_type": "signed_presale",
                    "is_minting": true,
                    "active_stage": null,
                    "next_stage": {
                        "uuid": "future-stage",
                        "stage_type": "signed_presale",
                        "label": null,
                        "price": "0",
                        "price_currency_address": "0x0000000000000000000000000000000000000000",
                        "start_time": start_rfc3339,
                        "end_time": "2999-01-01T00:00:00Z",
                        "max_per_wallet": "10",
                    },
                    "stages": [],
                    "total_supply": null,
                    "max_supply": null,
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            (
                path.to_string(),
                rpc_ok_status(signed_mint_response_json(
                    wallet,
                    sample_mint_params_abi(true),
                    SIGNER_SEED,
                    U256::from(1u64),
                )),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "opensea",
            "--slug",
            SLUG,
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE").not())
        .stdout(predicates::str::contains("BROADCAST RESULT"));

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(sends.len(), 1, "expected exactly one broadcast: {sends:?}");
}

#[test]
fn watch_wrong_chain_detected_before_any_wait() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    // Reports chain id 4663 (Robinhood mainnet) when watch asked for
    // chain 1 (the compiled default) -- must fail closed, never treated as
    // a "not SeaDrop, try OpenSea next" resolver miss.
    let server = LocalHttpServer::spawn_json_rpc(|method, _params| match method {
        "eth_chainId" => rpc_ok(serde_json::json!("0x1237")),
        _ => Behavior::JsonRpcError {
            code: -32601,
            message: "method not found".into(),
        },
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains("chain").or(predicates::str::contains("CHAIN")));
}

#[test]
fn watch_without_signing_key_fails_closed_instead_of_blocking_on_an_interactive_prompt() {
    let wallet = test_signer().address();
    // No KAIROX_SIGNING_KEY set, and no RPC endpoint reachable either --
    // this is a regression test for a real hang this pass found:
    // `mint --send`'s interactive-prompt fallback (appropriate for an
    // operator sitting at a terminal) must never be reachable from `watch
    // --auto-send`, since nothing is present to answer a hidden-stdin
    // prompt in an unattended run. Bounded by --timeout so a regression
    // fails the test instead of hanging the suite.
    kairox_bin()
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(predicates::str::contains("failed to load signing key"))
        .stderr(predicates::str::contains(
            "never falls back to an interactive prompt",
        ));
}

#[test]
fn watch_json_report_is_exactly_one_valid_json_object_over_real_http() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    // A genuine, short *future* stage -- semantic-correction item 6/7
    // now makes real `watch --engine public --auto-send` refuse with
    // STAGE_ALREADY_LIVE against an already-active stage (the standard
    // fixture's default), which would defeat this test's actual purpose
    // (verifying `--json` stdout plumbing through a real successful
    // watch-then-dispatch run). This is the same short-wait pattern
    // `watch_public_future_stage_waits_then_executes_at_t0` uses.
    let stage_start = unix_now() + 2;

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" => echo_tx_hash_behavior(params),
        "eth_getTransactionReceipt" => {
            let queried_hash = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .to_string();
            rpc_ok(serde_json::json!({
                "transactionHash": queried_hash,
                "status": "0x1",
                "blockNumber": "0x1",
                "logs": [transfer_log_for(wallet, 3)],
            }))
        }
        _ => read_response_with_stage_window(method, params, stage_start, 32_503_680_000)
            .unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected method in watch --json scenario: {method}"),
            }),
    });

    let assert = kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "public",
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
            "--json",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("watch --json stdout was not exactly one JSON object: {e}\nstdout={stdout:?}")
    });
    assert_eq!(parsed["wallets"][0]["state"], "CONFIRMED_SUCCESS");
}

// =======================================================================
// Phase C: automatic OpenSea slug discovery / stage-priority E2E. No
// `--slug` is ever passed in these tests -- the point is proving
// `--engine auto` genuinely discovers the drop and prefers a currently
// -active, OpenSea-recognized non-public stage over native on-chain
// public (the real-world bug class an explicit `--engine public` used to
// reproduce), while never letting OpenSea's own availability block a
// collection whose native on-chain public stage still works. Every
// scenario here is a dry run (no `--send`) -- resolution evidence alone
// is what is being proven.
// =======================================================================

fn opensea_stage_json(slug: &str, stage_type: &str, contract: Address) -> Value {
    serde_json::json!({
        "collection_slug": slug,
        "collection_name": "Test Collection",
        "chain": "ethereum",
        "contract_address": format!("{contract:#x}"),
        "drop_type": stage_type,
        "is_minting": true,
        "active_stage": {
            "uuid": "stage-1",
            "stage_type": stage_type,
            "label": null,
            "price": "0",
            "price_currency_address": "0x0000000000000000000000000000000000000000",
            "start_time": "2020-01-01T00:00:00Z",
            "end_time": "2999-01-01T00:00:00Z",
            "max_per_wallet": "10",
        },
        "next_stage": null,
        "stages": [],
        "total_supply": null,
        "max_supply": null,
    })
}

/// Serves the same "always-active on-chain PublicDrop" RPC responses as
/// [`standard_read_response`], plus a real `GET /api/v2/chain/ethereum/
/// contract/{NFT}` and `GET /api/v2/drops/{slug}` -- so auto-discovery has
/// something genuine to find without an operator-supplied `--slug`.
fn spawn_autodiscovery_server(
    slug: &'static str,
    active_stage_type: &'static str,
) -> LocalHttpServer {
    LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior =
                standard_read_response(&method, &params).unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method in auto-discovery scenario: {method}"),
                });
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": slug,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{slug}") {
            (
                path.to_string(),
                rpc_ok_status(opensea_stage_json(slug, active_stage_type, NFT)),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    })
}

// ---------------------------------------------------------------------
// Round 6 item 10: a long `watch --engine auto` wait must periodically
// re-run resolution rather than staying permanently committed to
// whatever it picked before entering the wait. This scenario models
// item 10.A almost exactly: an on-chain public stage is the only thing
// visible initially (not yet started, several seconds out), and OpenSea
// only reveals a genuine, already-active signed presale on the *second*
// discovery request -- simulating a creator publishing a presale (or
// OpenSea recovering from a transient outage) after `watch` already
// started waiting on the native public stage. Also now doubles as a
// semantic-correction regression test (final release gate item 4): the
// presale's own display metadata claims sold out, and the real
// wallet-specific preflight (`check_opensea_stage_actionable_now`)
// confirms supply exhaustion via the same classification the execution
// engine itself uses -- this must NOT be reported as STAGE_ALREADY_LIVE
// (a sold-out stage is never actionable), and since no other supported
// stage exists once it is excluded, the freshly-restarted attempt's very
// first resolution correctly reports the genuine no-supported-stage
// outcome instead.
// ---------------------------------------------------------------------
#[test]
fn watch_auto_engine_switches_to_a_presale_that_appears_partway_through_a_long_public_wait() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-watch-reresolution-presale";
    // Comfortably beyond arm_threshold/poll_interval so wait_for_stage is
    // genuinely still polling (not yet armed/handed off) when the
    // re-resolution check fires.
    let public_stage_start = unix_now() + 20;
    let opensea_requests: std::sync::Arc<std::sync::atomic::AtomicU32> =
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let opensea_requests_for_closure = opensea_requests.clone();

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                // After the sold-out presale is excluded, watch falls
                // back to legitimately waiting for the still-future
                // public stage -- semantic-correction item 3/4's exact
                // scenario ("active signed [not actionable] + future
                // public -> future public selected"). This *does* now
                // reach real dispatch once the public stage opens, so
                // unlike the presale's own metadata, this is a genuine
                // successful completion, not a forbidden call.
                "eth_sendRawTransaction" => echo_tx_hash_behavior(&params),
                "eth_getTransactionReceipt" => {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    rpc_ok(serde_json::json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [transfer_log_for(wallet, 9)],
                    }))
                }
                _ => read_response_with_stage_window(
                    &method,
                    &params,
                    public_stage_start,
                    32_503_680_000,
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method in reresolution scenario: {method}"),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            // The active presale's own metadata claims sold out
            // (total_supply == max_supply below); a real OpenSea backend
            // would reject the wallet-specific mint-builder request
            // itself with a 422 classified as supply-exhausted -- this is
            // what `check_opensea_stage_actionable_now`'s real preflight
            // is exercised against, never the untrusted display metadata.
            (
                path.to_string(),
                Behavior::HttpStatus(
                    422,
                    serde_json::json!({"errors": ["supply exhausted: sold out"]}),
                ),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            let n = opensea_requests_for_closure.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                // First discovery request (the initial resolution, before
                // the wait even begins): genuinely no drop yet.
                (
                    path.to_string(),
                    Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
                )
            } else {
                // Every request from here on (the periodic re-resolution
                // check, and the fresh attempt it triggers): a real,
                // already-active signed presale. Its total_supply/
                // max_supply claim it's sold out; that display metadata
                // alone is deliberately never trusted for eligibility
                // (see `is_candidate`/`EligibilityState`), so the
                // resolver still treats it as a genuine
                // temporally-active candidate worth checking -- but the
                // real actionability preflight
                // (`check_opensea_stage_actionable_now`, mocked above via
                // the `/mint` endpoint's 422 supply-exhausted response)
                // then correctly determines it is *not* actionable,
                // excludes it, and re-resolves -- never reporting
                // STAGE_ALREADY_LIVE for a stage that cannot actually be
                // minted, and never needing the full signed-mint/EIP-712
                // machinery this test isn't exercising.
                (
                    path.to_string(),
                    rpc_ok_status(serde_json::json!({
                        "collection_slug": SLUG,
                        "collection_name": "Test Collection",
                        "chain": "ethereum",
                        "contract_address": format!("{NFT:#x}"),
                        "drop_type": "signed_presale",
                        "is_minting": true,
                        "active_stage": {
                            "uuid": "presale-appeared-mid-wait",
                            "stage_type": "signed_presale",
                            "label": null,
                            "price": "0",
                            "price_currency_address": "0x0000000000000000000000000000000000000000",
                            "start_time": "2020-01-01T00:00:00Z",
                            "end_time": "2999-01-01T00:00:00Z",
                            "max_per_wallet": "10",
                        },
                        "next_stage": null,
                        "stages": [],
                        "total_supply": "1",
                        "max_supply": "1",
                    })),
                )
            }
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_WATCH_RERESOLUTION_INTERVAL_MS", "300")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "restarting the attempt against the fresh resolution",
        ))
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stderr(predicates::str::contains("STAGE_ALREADY_LIVE").not())
        .stdout(predicates::str::contains("BROADCAST RESULT"));

    let received = server.received.lock().unwrap();
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "the sold-out presale must never be dispatched to -- exactly one broadcast, to the \
         legitimately-watched public stage, expected: {sends:?}"
    );
}

// ---------------------------------------------------------------------
// Final hardening pass item 4, scenario D: identical setup to the
// re-resolution scenario above (OpenSea unavailable initially, native
// public discovered and waited on, OpenSea reveals an earlier signed
// presale mid-wait, watch switches) but with --rehearsal, and this time
// the revealed presale is a genuinely completable signed mint (not sold
// out) -- so the rehearsal actually reaches signing/serialization rather
// than stopping early on a supply check.
// ---------------------------------------------------------------------
#[test]
fn watch_rehearsal_switches_to_a_recovered_presale_and_prepares_without_broadcasting() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-watch-rehearsal-reresolution";
    const SIGNER_SEED: &str = "kairox-e2e-watch-rehearsal-reresolution-signer";
    let public_stage_start = unix_now() + 20;
    let opensea_requests: std::sync::Arc<std::sync::atomic::AtomicU32> =
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let opensea_requests_for_closure = opensea_requests.clone();

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
                    code: -32000,
                    message: "must never be called: this scenario never dispatches".into(),
                },
                // getPublicDrop must report a genuinely far-future
                // NotStarted window (never active) so the public stage
                // never wins outright before the presale is discovered;
                // everything else (including the allow-list-root/
                // validation-params/fee-recipient selectors the signed
                // -mint path needs) falls through to opensea_read_response.
                _ => read_response_with_stage_window(
                    &method,
                    &params,
                    public_stage_start,
                    32_503_680_000,
                )
                .or_else(|| {
                    opensea_read_response(
                        &method,
                        &params,
                        None,
                        Some(permissive_signed_mint_validation_params()),
                        Some(true),
                    )
                })
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!(
                        "unexpected RPC method in watch-rehearsal-reresolution scenario: {method}"
                    ),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            let n = opensea_requests_for_closure.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                (
                    path.to_string(),
                    Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
                )
            } else {
                (
                    path.to_string(),
                    rpc_ok_status(serde_json::json!({
                        "collection_slug": SLUG,
                        "collection_name": "Test Collection",
                        "chain": "ethereum",
                        "contract_address": format!("{NFT:#x}"),
                        "drop_type": "signed_presale",
                        "is_minting": true,
                        "active_stage": {
                            "uuid": "presale-recovered-mid-wait",
                            "stage_type": "signed_presale",
                            "label": null,
                            "price": "0",
                            "price_currency_address": "0x0000000000000000000000000000000000000000",
                            "start_time": "2020-01-01T00:00:00Z",
                            "end_time": "2999-01-01T00:00:00Z",
                            "max_per_wallet": "10",
                        },
                        "next_stage": null,
                        "stages": [],
                        "total_supply": null,
                        "max_supply": null,
                    })),
                )
            }
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            (
                path.to_string(),
                rpc_ok_status(signed_mint_response_json(
                    wallet,
                    sample_mint_params_abi(true),
                    SIGNER_SEED,
                    U256::from(1u64),
                )),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_WATCH_RERESOLUTION_INTERVAL_MS", "300")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--rehearsal",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "restarting the attempt against the fresh resolution",
        ))
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never dispatch, even after switching engines mid-wait"
    );
    assert!(
        received.iter().any(|(p, _)| p.ends_with("/mint")),
        "rehearsal should have reached the recovered presale's mint authorization"
    );
}

#[test]
fn auto_engine_prefers_auto_discovered_signed_presale_over_active_onchain_public() {
    let wallet = test_signer().address();
    const SLUG: &str = "kairox-e2e-auto-signed-presale";
    let server = spawn_autodiscovery_server(SLUG, "signed_presale");

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stderr(predicates::str::contains("OpenSeaDropsAdapter"))
        .stderr(predicates::str::contains(SLUG));
}

#[test]
fn auto_engine_falls_back_to_native_public_when_opensea_active_stage_is_plain_public() {
    // The on-chain PublicDrop is (per standard_read_response) always
    // Active, and OpenSea *also* reports an active stage -- but its
    // stage_type is plain "public", so OpenSeaDropsAdapter must defer to
    // the cheaper, dependency-free native route rather than routing
    // through OpenSea unnecessarily.
    let wallet = test_signer().address();
    const SLUG: &str = "kairox-e2e-auto-plain-public";
    let server = spawn_autodiscovery_server(SLUG, "public");

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: Public"))
        .stderr(predicates::str::contains("SeaDropAdapter"));
}

#[test]
fn auto_engine_native_public_still_resolves_when_opensea_contract_lookup_errors() {
    // OpenSea's contract-lookup endpoint returns a genuine server error --
    // auto-discovery must be swallowed as "no drop discovered", never
    // propagated, so the collection's still-working native on-chain
    // public stage is unaffected by OpenSea's availability.
    let wallet = test_signer().address();
    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior =
                standard_read_response(&method, &params).unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method: {method}"),
                });
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                Behavior::HttpStatus(500, serde_json::json!({"errors": ["internal error"]})),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: Public"))
        .stderr(predicates::str::contains("SeaDropAdapter"))
        // Round 6 item 8: the degraded-discovery evidence must survive
        // all the way to the operator-visible output, distinct from a
        // genuine "no drop" answer -- never silently collapsed into
        // Vec::new() with no trace. Must never claim no signed stage
        // exists; must say discovery was unavailable.
        .stderr(predicates::str::contains(
            "OpenSea auto-discovery unavailable",
        ))
        .stderr(predicates::str::contains(
            "NOT proof no signed stage exists, only that it could not be checked",
        ));
}

#[test]
fn auto_engine_explicit_slug_still_wins_outright_without_auto_discovery() {
    // An operator-provided --slug is still taken at face value, exactly
    // as before auto-discovery existed -- no contract-lookup call is
    // even attempted.
    let wallet = test_signer().address();
    const SLUG: &str = "kairox-e2e-explicit-slug";
    let server = spawn_combined_rpc_and_opensea_server(
        |method, params| {
            standard_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
                code: -32601,
                message: format!("unexpected RPC method: {method}"),
            })
        },
        || {
            Behavior::HttpStatus(
                500,
                serde_json::json!({"errors": ["mint endpoint should not be reached in a dry run"]}),
            )
        },
        SLUG,
    );

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .args([
            "mint",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "auto",
            "--slug",
            SLUG,
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stderr(predicates::str::contains(format!(
            "operator-provided OpenSea collection slug {SLUG:?}"
        )));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(p, _)| p.contains("/contract/")),
        "an explicit --slug must never trigger a contract-lookup auto-discovery call"
    );
}

#[test]
fn watch_engine_auto_discovers_and_waits_for_an_upcoming_signed_presale_over_active_public() {
    // Realistic launch sequencing: the on-chain PublicDrop has not opened
    // yet either (future window, opening shortly after the presale) --
    // both stages are genuinely NotStarted, so the correct pick is the
    // *earlier* one, the signed presale. (An earlier version of this test
    // made the on-chain public stage already Active, which -- correctly,
    // once the normalized stage resolver actually weighs both candidates
    // instead of an ad-hoc adapter-priority chain -- makes
    // AlreadyLive(Public) the right answer, not WaitFor: a stage that is
    // genuinely live right now must never be waited past.)
    //
    // This test also covers item THIRD (watch re-resolution): the presale
    // rejects this wallet as ineligible at its own T0, and watch must
    // re-resolve rather than aborting -- discovering and waiting for the
    // now-open-enough on-chain public stage, and completing a real send
    // through it.
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-watch-auto-presale";
    let stage_start = unix_now() + 2;
    let start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let end_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64 + 3600)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    // Opens shortly after the presale's own T0 (realistic sequencing:
    // presale first, public second) -- by the time re-resolution runs
    // (after the presale's ~2s wait plus one rejected mint request),
    // this is already active, so the test completes quickly and
    // deterministically rather than waiting a long real duration.
    let public_start = unix_now() + 4;
    let public_end = public_start + 3600;

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" => echo_tx_hash_behavior(&params),
                "eth_getTransactionReceipt" => {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    rpc_ok(serde_json::json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [transfer_log_for(wallet, 11)],
                    }))
                }
                _ => read_response_with_stage_window(&method, &params, public_start, public_end)
                    .unwrap_or(Behavior::JsonRpcError {
                        code: -32601,
                        message: format!(
                            "unexpected RPC method in watch-auto-discovery scenario: {method}"
                        ),
                    }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "collection_slug": SLUG,
                    "collection_name": "Test Collection",
                    "chain": "ethereum",
                    "contract_address": format!("{NFT:#x}"),
                    "drop_type": "signed_presale",
                    "is_minting": true,
                    "active_stage": null,
                    "next_stage": {
                        "uuid": "stage-1",
                        "stage_type": "signed_presale",
                        "label": null,
                        "price": "0",
                        "price_currency_address": "0x0000000000000000000000000000000000000000",
                        "start_time": start_rfc3339,
                        "end_time": end_rfc3339,
                        "max_per_wallet": "10",
                    },
                    "stages": [],
                    "total_supply": null,
                    "max_supply": null,
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            // A terminal, semantically clear ineligibility rejection --
            // proves watch::run_single_target's re-resolution loop
            // (item THIRD): a rejection this specific must exclude this
            // stage and re-resolve, never simply abort the session.
            (
                path.to_string(),
                Behavior::HttpStatus(
                    422,
                    serde_json::json!({"errors": ["wallet is not eligible for this stage"]}),
                ),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--auto-send",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stderr(predicates::str::contains("signed_presale"))
        .stderr(predicates::str::contains("re-resolving"))
        .stderr(predicates::str::contains("resolved_engine: Public"))
        .stdout(predicates::str::contains("BROADCAST RESULT"))
        .stdout(predicates::str::contains("receipt: CONFIRMED_SUCCESS"));

    let received = server.received.lock().unwrap();
    assert!(
        received.iter().any(|(p, _)| p.ends_with("/mint")),
        "watch should have waited for the presale and requested a fresh mint authorization at T0"
    );
    let sends: Vec<_> = received
        .iter()
        .filter(|(m, _)| m == "eth_sendRawTransaction")
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "after re-resolving past the ineligible presale, watch must broadcast exactly one \
         transaction via the public stage, got {sends:?}"
    );
}

// ---------------------------------------------------------------------
// Final hardening pass item 4, scenario C: the exact same "ineligible
// signed stage falls through to public" flow as
// watch_engine_auto_discovers_and_waits_for_an_upcoming_signed_presale_over_active_public
// above, but with --rehearsal instead of --auto-send -- the presale's
// exact StageId must still be excluded and re-resolution must still
// reach the public stage, but nothing may ever be broadcast.
// ---------------------------------------------------------------------
#[test]
fn watch_rehearsal_still_excludes_an_ineligible_signed_stage_and_reaches_public_without_broadcasting()
 {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-watch-rehearsal-presale";
    let stage_start = unix_now() + 2;
    let start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let end_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_start as i64 + 3600)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let public_start = unix_now() + 4;
    let public_end = public_start + 3600;

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" | "eth_getTransactionReceipt" => {
                    Behavior::JsonRpcError {
                        code: -32000,
                        message: format!(
                            "must never be called in a rehearsal scenario: {method}"
                        ),
                    }
                }
                _ => read_response_with_stage_window(&method, &params, public_start, public_end)
                    .unwrap_or(Behavior::JsonRpcError {
                        code: -32601,
                        message: format!(
                            "unexpected RPC method in watch-rehearsal-reresolution scenario: {method}"
                        ),
                    }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "collection_slug": SLUG,
                    "collection_name": "Test Collection",
                    "chain": "ethereum",
                    "contract_address": format!("{NFT:#x}"),
                    "drop_type": "signed_presale",
                    "is_minting": true,
                    "active_stage": null,
                    "next_stage": {
                        "uuid": "stage-1",
                        "stage_type": "signed_presale",
                        "label": null,
                        "price": "0",
                        "price_currency_address": "0x0000000000000000000000000000000000000000",
                        "start_time": start_rfc3339,
                        "end_time": end_rfc3339,
                        "max_per_wallet": "10",
                    },
                    "stages": [],
                    "total_supply": null,
                    "max_supply": null,
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            (
                path.to_string(),
                Behavior::HttpStatus(
                    422,
                    serde_json::json!({"errors": ["wallet is not eligible for this stage"]}),
                ),
            )
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--rehearsal",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("resolved_engine: OpenSea"))
        .stderr(predicates::str::contains("re-resolving"))
        .stderr(predicates::str::contains("resolved_engine: Public"))
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"));

    let received = server.received.lock().unwrap();
    assert!(
        received.iter().any(|(p, _)| p.ends_with("/mint")),
        "rehearsal should still have requested a fresh mint authorization for the presale"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never broadcast, even after re-resolving to the public stage"
    );
}

#[test]
fn watch_rejecting_one_opensea_stage_uuid_does_not_exclude_a_second_stage_sharing_the_same_slug() {
    // Regression test for the exact reported bug: NormalizedStage identity
    // used to be the OpenSea collection slug, so rejecting one stage
    // excluded every stage of that drop. Two stages here share one slug
    // but have distinct uuids -- stage A (rejected at T0) must not
    // exclude stage B (a genuinely different stage that later becomes
    // discoverable, e.g. OpenSea's own drop metadata advancing) from
    // being selected and successfully minted through.
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);
    const SLUG: &str = "kairox-e2e-multi-uuid";

    let stage_a_start = unix_now() + 2;
    let stage_b_start = unix_now() + 2; // discovered only after A is rejected
    let a_start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_a_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let a_end_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_a_start as i64 + 3600)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let b_start_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_b_start as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let b_end_rfc3339 = time::OffsetDateTime::from_unix_timestamp(stage_b_start as i64 + 3600)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let mint_rejected_once = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mint_rejected_once_for_server = mint_rejected_once.clone();

    let server = LocalHttpServer::spawn_raw(move |path, body| {
        if path == "/" {
            let method = body
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let params = body.get("params").cloned().unwrap_or(Value::Null);
            let behavior = match method.as_str() {
                "eth_sendRawTransaction" => echo_tx_hash_behavior(&params),
                "eth_getTransactionReceipt" => {
                    let queried_hash = params
                        .get(0)
                        .and_then(Value::as_str)
                        .unwrap_or("0x")
                        .to_string();
                    rpc_ok(serde_json::json!({
                        "transactionHash": queried_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "logs": [transfer_log_for(wallet, 13)],
                    }))
                }
                // Far future -- native public must never win over the
                // OpenSea stages in this scenario.
                _ => read_response_with_stage_window(
                    &method,
                    &params,
                    unix_now() + 3600,
                    unix_now() + 7200,
                )
                .unwrap_or(Behavior::JsonRpcError {
                    code: -32601,
                    message: format!("unexpected RPC method in multi-uuid scenario: {method}"),
                }),
            };
            (method, behavior)
        } else if path == format!("/api/v2/chain/ethereum/contract/{NFT:#x}") {
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "address": format!("{NFT:#x}"),
                    "chain": "ethereum",
                    "collection": SLUG,
                    "contract_standard": "erc721",
                    "name": "Test",
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}") {
            let already_rejected =
                mint_rejected_once_for_server.load(std::sync::atomic::Ordering::SeqCst);
            let next_stage = if already_rejected {
                serde_json::json!({
                    "uuid": "stage-b",
                    "stage_type": "signed_presale",
                    "label": null,
                    "price": "0",
                    "price_currency_address": "0x0000000000000000000000000000000000000000",
                    "start_time": b_start_rfc3339,
                    "end_time": b_end_rfc3339,
                    "max_per_wallet": "10",
                })
            } else {
                serde_json::json!({
                    "uuid": "stage-a",
                    "stage_type": "signed_presale",
                    "label": null,
                    "price": "0",
                    "price_currency_address": "0x0000000000000000000000000000000000000000",
                    "start_time": a_start_rfc3339,
                    "end_time": a_end_rfc3339,
                    "max_per_wallet": "10",
                })
            };
            (
                path.to_string(),
                rpc_ok_status(serde_json::json!({
                    "collection_slug": SLUG,
                    "collection_name": "Test Collection",
                    "chain": "ethereum",
                    "contract_address": format!("{NFT:#x}"),
                    "drop_type": "signed_presale",
                    "is_minting": true,
                    "active_stage": null,
                    "next_stage": next_stage,
                    "stages": [],
                    "total_supply": null,
                    "max_supply": null,
                })),
            )
        } else if path == format!("/api/v2/drops/{SLUG}/mint") {
            let already_rejected =
                mint_rejected_once_for_server.swap(true, std::sync::atomic::Ordering::SeqCst);
            if !already_rejected {
                // Stage A: reject exactly once.
                (
                    path.to_string(),
                    Behavior::HttpStatus(
                        422,
                        serde_json::json!({"errors": ["wallet is not eligible for this stage"]}),
                    ),
                )
            } else {
                // Stage B: a genuine valid signed mint response.
                let calldata = sd::encode_mint_public(
                    NFT,
                    address!("0000000000000000000000000000000000fee000"),
                    Address::ZERO,
                    1,
                )
                .unwrap();
                (
                    path.to_string(),
                    rpc_ok_status(serde_json::json!({
                        "to": format!("{:#x}", address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5")),
                        "data": format!("0x{}", hex::encode(&calldata)),
                        "value": "0x0",
                        "chain": "ethereum",
                    })),
                )
            }
        } else {
            (
                path.to_string(),
                Behavior::HttpStatus(404, serde_json::json!({"errors": ["not found"]})),
            )
        }
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_OPENSEA_BASE_URL", server.url())
        .env("KAIROX_OPENSEA_API_KEY", "test-key-value")
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{NFT:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            // Real wall-clock time elapses between stage A's rejection
            // and stage B's resolution (A's own poll/mint-request cycle),
            // enough that stage B's fixed start_time has itself passed
            // by the time it is resolved -- i.e. it is now genuinely
            // `AlreadyLive` too. `--rehearsal` is used here specifically
            // so that outcome is exercised safely (final release gate
            // item 8E: rehearsal may continue through an already-live
            // stage because it never broadcasts) rather than correctly
            // refusing with STAGE_ALREADY_LIVE the way a real
            // `--auto-send` run now does -- this test's actual point
            // (stage A's rejection never wrongly excludes the distinctly
            // -identified stage B) is unaffected either way.
            "--rehearsal",
            "--poll-interval-secs",
            "1",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success()
        .stderr(predicates::str::contains("\"stage-a\""))
        .stderr(predicates::str::contains("re-resolving"))
        .stdout(predicates::str::contains("REHEARSAL RESULT"))
        .stdout(predicates::str::contains("REHEARSAL COMPLETE"));

    let received = server.received.lock().unwrap();
    let mint_attempts = received
        .iter()
        .filter(|(p, _)| p.ends_with("/mint"))
        .count();
    assert_eq!(
        mint_attempts, 2,
        "expected exactly two mint attempts (stage A rejected, stage B succeeds), got {mint_attempts}"
    );
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never broadcast, even after re-resolving past stage A's \
         rejection to stage B"
    );
}

// =======================================================================
// v0.8 Phase B: thirdweb Drop (ClaimCondition) engine, real CLI binary
// E2E. Exercises the actual protocol::thirdweb ABI encode/decode and
// execution::thirdweb_engine pipeline through a real localhost JSON-RPC
// server -- not just the engine's own mock-transport unit tests.
// =======================================================================

use kairox::protocol::thirdweb::{self as tw, ClaimConditionAbi};

const THIRDWEB_DROP: Address = address!("00000000000000000000000000000000007d40D0");

fn thirdweb_public_condition_response(price_wei: u128) -> Value {
    let condition = ClaimConditionAbi {
        startTimestamp: U256::from(1_700_000_000u64),
        maxClaimableSupply: U256::from(1_000u64),
        supplyClaimed: U256::from(10u64),
        quantityLimitPerWallet: U256::from(5u64),
        merkleRoot: B256::ZERO,
        pricePerToken: U256::from(price_wei),
        currency: tw::NATIVE_TOKEN,
        metadata: String::new(),
    };
    serde_json::json!(format!(
        "0x{}",
        hex::encode(tw::getClaimConditionByIdCall::abi_encode_returns(
            &condition
        ))
    ))
}

fn thirdweb_read_response(method: &str, params: &Value) -> Option<Behavior> {
    match method {
        "eth_chainId" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_call" => {
            let data = params
                .get(0)
                .and_then(|c| c.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let active_id_sel = format!(
                "0x{}",
                hex::encode(tw::getActiveClaimConditionIdCall::SELECTOR)
            );
            let condition_sel =
                format!("0x{}", hex::encode(tw::getClaimConditionByIdCall::SELECTOR));
            let claimed_sel = format!(
                "0x{}",
                hex::encode(tw::getSupplyClaimedByWalletCall::SELECTOR)
            );
            if data.starts_with(&active_id_sel) {
                return Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(tw::getActiveClaimConditionIdCall::abi_encode_returns(
                        &U256::ZERO
                    ))
                ))));
            }
            if data.starts_with(&condition_sel) {
                return Some(rpc_ok(thirdweb_public_condition_response(
                    10_000_000_000_000_000,
                )));
            }
            if data.starts_with(&claimed_sel) {
                return Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(tw::getSupplyClaimedByWalletCall::abi_encode_returns(
                        &U256::ZERO
                    ))
                ))));
            }
            None
        }
        "eth_blockNumber" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_getBlockByNumber" => Some(rpc_ok(serde_json::json!({
            "number": "0x1",
            "timestamp": "0x1",
            "baseFeePerGas": "0x3b9aca00"
        }))),
        "eth_maxPriorityFeePerGas" => Some(rpc_ok(serde_json::json!("0x3b9aca00"))),
        "eth_getTransactionCount" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_getBalance" => Some(rpc_ok(serde_json::json!("0xde0b6b3a7640000"))),
        "eth_estimateGas" => Some(rpc_ok(serde_json::json!("0x2bf20"))),
        // Provenance reads (execution::thirdweb_engine::establish_provenance):
        // arbitrary, non-EIP-1167-shaped bytecode and an all-zero
        // EIP-1967 slot -- not a proxy Kairox recognizes, so provenance
        // resolves to hashing this bytecode directly. The real
        // BUILTIN_REGISTRY ships empty, so no hash can ever match it;
        // this only proves the read plumbing itself, never authorizes a
        // live send.
        "eth_getCode" => Some(rpc_ok(serde_json::json!("0x600160026003"))),
        "eth_getStorageAt" => Some(rpc_ok(serde_json::json!(format!(
            "0x{}",
            hex::encode([0u8; 32])
        )))),
        _ => None,
    }
}

#[test]
fn thirdweb_dry_run_prints_the_active_claim_condition_read_only() {
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in thirdweb dry-run scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{THIRDWEB_DROP:#x}"),
            "--wallet",
            &format!("{:#x}", test_signer().address()),
            "--engine",
            "thirdweb",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("selected engine: THIRDWEB"))
        .stdout(predicates::str::contains("allowlist gated:          false"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a dry run must never broadcast"
    );
}

// ---------------------------------------------------------------------
// Phase B correctness gate: `--engine thirdweb --send`/`--rehearsal`
// must refuse to authorize a live send against any contract whose
// implementation is not a manually-reviewed entry in
// `execution::thirdweb_registry`'s trusted-fingerprint registry --
// selector compatibility and a successful read are never sufficient
// (see that module's doc comment). The real production CLI uses
// `BUILTIN_REGISTRY`, which ships empty by design, so both scenarios
// below refuse through the *actual compiled binary* -- proving the gate
// is real, not merely unit-tested at the engine layer.
// ---------------------------------------------------------------------

#[test]
fn thirdweb_rehearsal_refuses_without_an_established_trusted_fingerprint() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in thirdweb rehearsal scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{THIRDWEB_DROP:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "thirdweb",
            "--rehearsal",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unverified implementation must never be signed or broadcast, rehearsal or not"
    );
}

#[test]
fn thirdweb_real_send_refuses_without_an_established_trusted_fingerprint() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in thirdweb send scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{THIRDWEB_DROP:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "thirdweb",
            "--send",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unverified implementation must never be signed or broadcast against a real --send"
    );
}

// =======================================================================
// v0.8: Manifold LazyPayableClaim engine, real CLI binary E2E. Mirrors
// the thirdweb block above exactly -- exercises the actual
// protocol::manifold ABI encode/decode and execution::manifold_engine
// pipeline through a real localhost JSON-RPC server.
// =======================================================================

use kairox::protocol::manifold::{self as mf, ClaimAbi};

const MANIFOLD_EXTENSION: Address = address!("00000000000000000000000000000000000e0e0e");
const MANIFOLD_CREATOR: Address = address!("00000000000000000000000000000000007d40D0");

fn manifold_public_claim_response(cost_wei: u128) -> Value {
    let claim = ClaimAbi {
        total: 3,
        totalMax: 100,
        walletMax: 2,
        startDate: U256::from(1_700_000_000u64),
        endDate: U256::from(1_800_000_000u64),
        storageProtocol: 3,
        contractVersion: 1,
        identical: true,
        merkleRoot: B256::ZERO,
        location: "ipfs://abc".to_string(),
        cost: U256::from(cost_wei),
        paymentReceiver: MANIFOLD_CREATOR,
        erc20: Address::ZERO,
        signingAddress: Address::ZERO,
    };
    serde_json::json!(format!(
        "0x{}",
        hex::encode(mf::getClaimCall::abi_encode_returns(&claim))
    ))
}

fn manifold_read_response(method: &str, params: &Value) -> Option<Behavior> {
    match method {
        "eth_chainId" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_call" => {
            let data = params
                .get(0)
                .and_then(|c| c.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let claim_sel = format!("0x{}", hex::encode(mf::getClaimCall::SELECTOR));
            let total_mints_sel = format!("0x{}", hex::encode(mf::getTotalMintsCall::SELECTOR));
            let membership_sel = format!("0x{}", hex::encode(mf::MEMBERSHIP_ADDRESSCall::SELECTOR));
            if data.starts_with(&claim_sel) {
                return Some(rpc_ok(manifold_public_claim_response(
                    10_000_000_000_000_000,
                )));
            }
            if data.starts_with(&total_mints_sel) {
                return Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(mf::getTotalMintsCall::abi_encode_returns(&0u32))
                ))));
            }
            if data.starts_with(&membership_sel) {
                return Some(rpc_ok(serde_json::json!(format!(
                    "0x{}",
                    hex::encode(mf::MEMBERSHIP_ADDRESSCall::abi_encode_returns(
                        &Address::ZERO
                    ))
                ))));
            }
            None
        }
        "eth_blockNumber" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_getBlockByNumber" => Some(rpc_ok(serde_json::json!({
            "number": "0x1",
            "timestamp": "0x1",
            "baseFeePerGas": "0x3b9aca00"
        }))),
        "eth_maxPriorityFeePerGas" => Some(rpc_ok(serde_json::json!("0x3b9aca00"))),
        "eth_getTransactionCount" => Some(rpc_ok(serde_json::json!("0x1"))),
        "eth_getBalance" => Some(rpc_ok(serde_json::json!("0xde0b6b3a7640000"))),
        "eth_estimateGas" => Some(rpc_ok(serde_json::json!("0x2bf20"))),
        // Provenance read (execution::manifold_engine::establish_provenance):
        // arbitrary bytecode hashed directly (no proxy resolution for
        // Manifold -- see execution::manifold_registry's doc comment).
        // The real BUILTIN_REGISTRY ships empty, so no hash can ever
        // match it; this only proves the read plumbing itself, never
        // authorizes a live send.
        "eth_getCode" => Some(rpc_ok(serde_json::json!("0x600160026003"))),
        _ => None,
    }
}

#[test]
fn manifold_dry_run_prints_the_claim_state_read_only() {
    let server = LocalHttpServer::spawn_json_rpc(move |method, params| {
        manifold_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in manifold dry-run scenario: {method}"),
        })
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .args([
            "mint",
            &format!("{MANIFOLD_CREATOR:#x}"),
            "--wallet",
            &format!("{:#x}", test_signer().address()),
            "--engine",
            "manifold",
            "--manifold-extension",
            &format!("{MANIFOLD_EXTENSION:#x}"),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("selected engine: MANIFOLD"))
        .stdout(predicates::str::contains("allowlist gated:          false"));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "a dry run must never broadcast"
    );
}

// ---------------------------------------------------------------------
// `--engine manifold --send`/`--rehearsal` must refuse to authorize a
// live send against any extension contract whose bytecode is not a
// manually-reviewed entry in execution::manifold_registry's
// trusted-fingerprint registry -- mirrors the thirdweb correctness gate
// exactly. The real production CLI uses BUILTIN_REGISTRY, which ships
// empty by design, so both scenarios below refuse through the actual
// compiled binary.
// ---------------------------------------------------------------------

#[test]
fn manifold_rehearsal_refuses_without_an_established_trusted_fingerprint() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => manifold_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in manifold rehearsal scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{MANIFOLD_CREATOR:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "manifold",
            "--manifold-extension",
            &format!("{MANIFOLD_EXTENSION:#x}"),
            "--rehearsal",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unverified extension contract must never be signed or broadcast, rehearsal or not"
    );
}

#[test]
fn manifold_real_send_refuses_without_an_established_trusted_fingerprint() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => manifold_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in manifold send scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "mint",
            &format!("{MANIFOLD_CREATOR:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "manifold",
            "--manifold-extension",
            &format!("{MANIFOLD_EXTENSION:#x}"),
            "--send",
            "--yes",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "an unverified extension contract must never be signed or broadcast against a real --send"
    );
}

// =======================================================================
// v0.8 operationalization: thirdweb/Manifold watch stage discovery + T0
// dispatch, real CLI binary E2E. Both real BUILTIN_REGISTRYs ship empty,
// so every one of these correctly refuses at the provenance gate rather
// than ever signing/broadcasting -- proving the full stage-discovery ->
// wait -> arm -> dispatch pipeline runs, not that a live send succeeds.
// =======================================================================

#[test]
fn watch_thirdweb_rehearsal_discovers_the_active_condition_and_refuses_at_provenance() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => thirdweb_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in thirdweb watch rehearsal scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{THIRDWEB_DROP:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "thirdweb",
            "--rehearsal",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never broadcast, even for an already-active condition"
    );
}

#[test]
fn watch_manifold_rehearsal_discovers_the_claim_and_refuses_at_provenance() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(move |method, params| match method {
        "eth_sendRawTransaction" | "eth_getTransactionReceipt" => Behavior::JsonRpcError {
            code: -32000,
            message: "must never be called: provenance is never established for this fixture"
                .into(),
        },
        _ => manifold_read_response(method, params).unwrap_or(Behavior::JsonRpcError {
            code: -32601,
            message: format!("unexpected method in manifold watch rehearsal scenario: {method}"),
        }),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{MANIFOLD_CREATOR:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "manifold",
            "--manifold-extension",
            &format!("{MANIFOLD_EXTENSION:#x}"),
            "--rehearsal",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no trusted implementation fingerprint",
        ));

    let received = server.received.lock().unwrap();
    assert!(
        !received.iter().any(|(m, _)| m == "eth_sendRawTransaction"),
        "watch --rehearsal must never broadcast, even for an already-active claim"
    );
}

#[test]
fn watch_manifold_without_extension_flag_refuses_before_touching_the_network() {
    let signer = test_signer();
    let wallet = signer.address();
    let key_hex = signing_key_hex(&signer);

    let server = LocalHttpServer::spawn_json_rpc(|method, _params| Behavior::JsonRpcError {
        code: -32601,
        message: format!("must never be called: {method}"),
    });

    kairox_bin()
        .env("KAIROX_RPC_1_0_URL", server.url())
        .env("KAIROX_SIGNING_KEY", &key_hex)
        .args([
            "watch",
            &format!("{MANIFOLD_CREATOR:#x}"),
            "--wallet",
            &format!("{wallet:#x}"),
            "--engine",
            "manifold",
            "--rehearsal",
            "--max-mint-value-wei",
            "1000000000000000000",
            "--max-gas-cost-wei",
            "1000000000000000000",
            "--max-total-spend-wei",
            "2000000000000000000",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--manifold-extension"));

    let received = server.received.lock().unwrap();
    assert!(
        received.is_empty(),
        "missing --manifold-extension must be rejected before any network call"
    );
}
