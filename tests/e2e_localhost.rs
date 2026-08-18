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
use kairox::signing::signer::{LocalSigner, Signer};

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
