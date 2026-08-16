//! `kairox mint` — runs the exact same validation/planning pipeline as
//! `kairox plan`, then stops. Phase 1 has no broadcast path anywhere in
//! this crate; `--send` is rejected outright rather than silently ignored.

use crate::cli::args::MintArgs;
use crate::cli::commands::plan::{build_mint_plan, print_plan};
use crate::execution::errors::{KairoxError, SessionError};

pub async fn run(args: MintArgs) -> Result<(), KairoxError> {
    if args.send {
        return Err(KairoxError::Session(SessionError(
            "broadcasting is not enabled in Phase 1. `kairox mint` is dry-run only in this \
             build; remove --send. A real broadcast path does not exist yet and will only be \
             added in a later, explicitly approved phase."
                .to_string(),
        )));
    }

    let plan = build_mint_plan(&args.plan_args).await?;

    println!("=================================================");
    println!(" DRY RUN — NO TRANSACTION BROADCAST");
    println!("=================================================");
    println!();
    print_plan(&plan);
    println!();
    println!("=================================================");
    println!(" DRY RUN — NO TRANSACTION BROADCAST");
    println!(" Phase 1 does not sign or send this transaction.");
    println!("=================================================");

    Ok(())
}
