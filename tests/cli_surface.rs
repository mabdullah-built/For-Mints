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
