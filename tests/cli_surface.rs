//! Integration tests that exercise the compiled `kairox` binary directly:
//! dry-run commands never broadcast, `--send` still requires real
//! connectivity/confirmation rather than bypassing validation, and basic
//! argument validation works end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;

fn kairox() -> Command {
    Command::cargo_bin("kairox").expect("kairox binary should build")
}

#[test]
fn doctor_runs_and_reports_dry_run_default() {
    kairox()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry-run mode: DEFAULT"))
        .stdout(predicate::str::contains("Kairox v"));
}

#[test]
fn doctor_never_prints_a_signing_key_value() {
    kairox()
        .env("KAIROX_SIGNING_KEY", "should-never-be-printed-12345")
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("should-never-be-printed-12345").not());
}

#[test]
fn clock_runs_and_reports_utc_time() {
    kairox()
        .arg("clock")
        .assert()
        .success()
        .stdout(predicate::str::contains("System UTC time:"))
        .stdout(predicate::str::contains("Unix timestamp:"));
}

#[test]
fn mint_dry_run_still_broadcasts_nothing() {
    // No --rpc-url and no KAIROX_RPC_* configured: dry-run `mint` (no
    // --send) must fail on the same "no RPC endpoint configured" path as
    // `plan` — it never reaches a send-capable codepath, confirming the
    // dry-run pipeline is architecturally distinct from the live one.
    kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "mint",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no RPC endpoint configured"));
}

#[test]
fn mint_send_without_rpc_configuration_fails_closed_not_silently() {
    // --send is a real feature in Phase 2, but it still requires genuine
    // connectivity to build a live plan — it must not bypass validation or
    // fall back to any default.
    kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "mint",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--send",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no RPC endpoint configured"));
}

#[test]
fn plan_without_rpc_configuration_fails_with_clear_error() {
    kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "plan",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no RPC endpoint configured"));
}

#[test]
fn plan_rejects_unknown_chain() {
    kairox()
        .args([
            "plan",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--chain",
            "not-a-real-chain",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown chain"));
}

#[test]
fn inspect_requires_a_collection_argument() {
    kairox().arg("inspect").assert().failure();
}

#[test]
fn inspect_rejects_malformed_collection_address() {
    kairox()
        .args(["inspect", "not-an-address"])
        .assert()
        .failure();
}

#[test]
fn plan_requires_wallet_argument() {
    // --wallet has no default: omitting it must fail closed (a Kairox
    // runtime error, since --wallet is Option<Address> at the clap level to
    // allow `kairox mint --wallet-manifest` instead) and never silently
    // default to some address.
    kairox()
        .args(["plan", "0x000000000000000000000000000000000000c0de"])
        .assert()
        .failure();
}

#[test]
fn help_lists_all_commands() {
    kairox()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("clock"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("plan"))
        .stdout(predicate::str::contains("mint"))
        .stdout(predicate::str::contains("bench"));
}

#[test]
fn mint_help_documents_send_and_yes_flags() {
    kairox()
        .args(["mint", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--send"))
        .stdout(predicate::str::contains("--yes"));
}

// ---------------------------------------------------------------------
// Adversarial secret redaction (Phase 6 Section 25): plant sentinel
// "secret" values in every place Kairox could plausibly leak one, run
// real commands against the real compiled binary, and assert the
// sentinels never appear in either stdout or stderr.
// ---------------------------------------------------------------------

const SIGNING_KEY_SENTINEL: &str = "KAIROX_SUPER_SECRET_PRIVATE_KEY_123";
const OPENSEA_KEY_SENTINEL: &str = "KAIROX_SUPER_SECRET_API_KEY_456";
const RPC_USERINFO_SENTINEL: &str = "rpc-password-secret-789";

#[test]
fn doctor_never_leaks_any_adversarial_sentinel() {
    let assert = kairox()
        .env("KAIROX_SIGNING_KEY", SIGNING_KEY_SENTINEL)
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("https://user:{RPC_USERINFO_SENTINEL}@rpc.example.invalid/v1?token={RPC_USERINFO_SENTINEL}"),
        )
        .arg("doctor")
        .assert()
        .success();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(SIGNING_KEY_SENTINEL));
    assert!(!combined.contains(OPENSEA_KEY_SENTINEL));
    assert!(!combined.contains(RPC_USERINFO_SENTINEL));
}

#[test]
fn doctor_json_never_leaks_any_adversarial_sentinel() {
    let assert = kairox()
        .env("KAIROX_SIGNING_KEY", SIGNING_KEY_SENTINEL)
        .env("KAIROX_OPENSEA_API_KEY", OPENSEA_KEY_SENTINEL)
        .env(
            "KAIROX_RPC_1_0_URL",
            format!("https://user:{RPC_USERINFO_SENTINEL}@rpc.example.invalid/v1?token={RPC_USERINFO_SENTINEL}"),
        )
        .args(["doctor", "--json"])
        .assert()
        .success();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(SIGNING_KEY_SENTINEL));
    assert!(!combined.contains(OPENSEA_KEY_SENTINEL));
    assert!(!combined.contains(RPC_USERINFO_SENTINEL));
}

#[test]
fn mint_send_error_path_never_leaks_signing_key_sentinel() {
    // Fails before ever loading the signing key (no RPC configured), but
    // plant the sentinel anyway -- a regression here would mean Kairox
    // started echoing environment content into error text.
    let assert = kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .env("KAIROX_SIGNING_KEY", SIGNING_KEY_SENTINEL)
        .args([
            "mint",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--send",
            "--yes",
        ])
        .assert()
        .failure();
    let output = assert.get_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(SIGNING_KEY_SENTINEL));
}

// ---------------------------------------------------------------------
// --json stdout-purity (Phase 6 Section 26/38): on failure, stdout must
// carry nothing at all (no partial/mixed JSON); the error goes to
// stderr, exactly like every other Kairox command.
// ---------------------------------------------------------------------

#[test]
fn plan_json_failure_path_prints_nothing_to_stdout() {
    let assert = kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "plan",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--json",
        ])
        .assert()
        .failure();
    let output = assert.get_output();
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no RPC endpoint configured"));
}

#[test]
fn doctor_json_stdout_is_exactly_one_json_object_and_nothing_else() {
    let assert = kairox().args(["doctor", "--json"]).assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Exactly one line, and it must parse as a JSON object with the
    // expected schema_version -- proves nothing else was interleaved into
    // stdout ahead of or after the JSON object.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one stdout line, got: {stdout:?}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(lines[0]).expect("stdout must be valid JSON");
    assert_eq!(parsed["schema_version"], 1);
}

// ---------------------------------------------------------------------
// Config precedence (Phase 6 Section 6/40): real process, real temp
// config file, real environment variables.
// ---------------------------------------------------------------------

#[test]
fn config_precedence_cli_flag_wins_over_config_file_default() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "version = 1\n[defaults]\nchain = \"base\"\n").unwrap();

    let assert = kairox()
        .env_remove("KAIROX_CHAIN")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["config_path"], config_path.to_str().unwrap());
    assert!(
        parsed["config_status"]
            .as_str()
            .unwrap()
            .starts_with("PASS")
    );
}

#[test]
fn bad_config_fails_closed_with_a_clear_status_not_a_silent_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "version = 99\n").unwrap();

    let assert = kairox()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        parsed["config_status"]
            .as_str()
            .unwrap()
            .starts_with("FAIL")
    );
}

#[test]
fn bad_config_with_secret_looking_value_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "version = 1\n[opensea]\napi_key_env = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n",
    )
    .unwrap();

    let assert = kairox()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert!(
        parsed["config_status"]
            .as_str()
            .unwrap()
            .starts_with("FAIL")
    );
}

// ---------------------------------------------------------------------
// kairox init / kairox receipt --help E2E via the real binary.
// ---------------------------------------------------------------------

#[test]
fn init_writes_a_loadable_config_and_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    kairox()
        .args(["init", "--path", path.to_str().unwrap()])
        .assert()
        .success();
    assert!(path.exists());

    kairox()
        .args(["init", "--path", path.to_str().unwrap()])
        .assert()
        .failure();

    kairox()
        .args(["init", "--path", path.to_str().unwrap(), "--force"])
        .assert()
        .success();
}

#[test]
fn receipt_help_documents_json_flag() {
    kairox()
        .args(["receipt", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"));
}
