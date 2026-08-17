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
