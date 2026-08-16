//! CLI entry point: argument parsing and dispatch. Every command in Phase 1
//! is either purely informational (`doctor`, `clock`) or dry-run only
//! (`inspect`, `plan`, `mint`) — no code path in this module broadcasts a
//! transaction.

pub mod args;
pub mod commands;
pub mod context;
pub mod format;
pub mod gather;

use clap::Parser;

use args::{Cli, Command};

/// Parse `std::env::args()` and run the selected command. Returns the
/// process exit code.
pub async fn run() -> i32 {
    let cli = Cli::parse();
    run_with(cli.command).await
}

async fn run_with(command: Command) -> i32 {
    let result = match command {
        Command::Doctor => {
            commands::doctor::run().await;
            Ok(())
        }
        Command::Clock => {
            commands::clock::run();
            Ok(())
        }
        Command::Inspect(args) => commands::inspect::run(args).await,
        Command::Plan(args) => commands::plan::run(args).await,
        Command::Mint(args) => commands::mint::run(args).await,
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
