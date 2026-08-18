//! CLI entry point: argument parsing and dispatch. `doctor`, `clock`,
//! `inspect`, `plan`, and `bench` never broadcast anything. `mint` is
//! dry-run by default; only `mint --send` (with confirmation) reaches the
//! live broadcast pipeline in [`crate::execution::live`].

pub mod args;
pub mod commands;
pub mod context;
pub mod format;
pub mod gather;
pub mod report;

use clap::Parser;

use args::{Cli, Command};

/// Parse `std::env::args()` and run the selected command. Returns the
/// process exit code.
pub async fn run() -> i32 {
    let cli = Cli::parse();
    run_with(cli.config, cli.command).await
}

async fn run_with(config_path: Option<std::path::PathBuf>, command: Command) -> i32 {
    let config_path = config_path.as_deref();
    let result = match command {
        Command::Doctor(args) => {
            commands::doctor::run(args, config_path).await;
            Ok(())
        }
        Command::Clock => {
            commands::clock::run();
            Ok(())
        }
        Command::Inspect(args) => commands::inspect::run(args, config_path).await,
        Command::Plan(args) => commands::plan::run(args, config_path).await,
        Command::Mint(args) => commands::mint::run(args, config_path).await,
        Command::Bench(args) => commands::bench::run(args, config_path).await,
        Command::Init(args) => commands::init::run(args),
        Command::Receipt(args) => commands::receipt::run(args, config_path).await,
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error[{}]: {e}", e.code());
            1
        }
    }
}
