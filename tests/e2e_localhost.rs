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

use alloy_primitives::{Address, U256, address, keccak256};
use alloy_sol_types::SolCall;
use kairox::protocol::seadrop::{self as sd, PublicDropAbi};
use kairox::signing::signer::{LocalSigner, Signer};

const NFT: Address = address!("000000000000000000000000000000000000c0de");

fn test_signer() -> LocalSigner {
    LocalSigner::from_bytes(keccak256(b"kairox-phase6-e2e-localhost-wallet").0).unwrap()
}

fn signing_key_hex(_signer: &LocalSigner) -> String {
    // Reconstruct the same seed bytes used to build the signer -- the
    // only way to get a hex private key string back out for
    // KAIROX_SIGNING_KEY is to keep the original seed, since LocalSigner
    // deliberately never exposes its key material again once constructed.
    format!(
        "0x{}",
        hex::encode(keccak256(b"kairox-phase6-e2e-localhost-wallet"))
    )
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
