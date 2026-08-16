//! Integration tests that exercise the compiled `kairox` binary directly,
//! covering the CLI-level safety guarantees Phase 1 must hold: `--send` is
//! rejected, no command ever broadcasts, and basic argument validation
//! works end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;

fn kairox() -> Command {
    Command::cargo_bin("kairox").expect("kairox binary should build")
}

#[test]
fn doctor_runs_and_reports_dry_run_enabled() {
    kairox()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry-run mode: ENABLED"))
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
fn mint_rejects_send_flag_with_clear_message_and_nonzero_exit() {
    kairox()
        .args([
            "mint",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--send",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "broadcasting is not enabled in Phase 1",
        ));
}

#[test]
fn mint_send_rejection_happens_before_any_rpc_is_required() {
    // No --rpc-url and no KAIROX_RPC_* configured: if --send rejection
    // happened *after* attempting to connect, this would instead fail with
    // an RPC/config error rather than the dedicated --send message.
    kairox()
        .env_remove("KAIROX_RPC_1_0_URL")
        .args([
            "mint",
            "0x000000000000000000000000000000000000c0de",
            "--wallet",
            "0x0000000000000000000000000000000000000aaa",
            "--send",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "broadcasting is not enabled in Phase 1",
        ));
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
    // --wallet has no default: omitting it is a clap-level failure, not a
    // Kairox runtime error, and must never silently default to some address.
    kairox()
        .args(["plan", "0x000000000000000000000000000000000000c0de"])
        .assert()
        .failure();
}

#[test]
fn help_lists_all_phase1_commands() {
    kairox()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("clock"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("plan"))
        .stdout(predicate::str::contains("mint"));
}
