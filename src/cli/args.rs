//! CLI argument definitions.

use alloy_primitives::Address;
use clap::{Args, Parser, Subcommand};
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "kairox",
    version,
    about = "Independent public SeaDrop mint execution CLI (Phase 2: pre-signing + multi-RPC broadcast; dry-run by default, --send opts into live broadcast)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Inspect the local Kairox environment. Never broadcasts anything.
    Doctor,
    /// Report system UTC timing information. Never modifies the system clock.
    Clock,
    /// Inspect normalized public SeaDrop state for a collection.
    Inspect(InspectArgs),
    /// Produce a dry-run execution plan for a public mint.
    Plan(PlanArgs),
    /// Dry run by default. Pass --send (with --yes, or interactive confirmation) to broadcast live.
    Mint(MintArgs),
    /// Connect to every configured RPC endpoint for a chain and report latency/role/capability. Never signs or broadcasts.
    Bench(BenchArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ChainArgs {
    /// Chain name ("ethereum", "base", "robinhood chain") or numeric chain id.
    #[arg(long, default_value = "ethereum")]
    pub chain: String,
    /// RPC endpoint URL. Overrides any KAIROX_RPC_<chainId>_* environment configuration.
    #[arg(long)]
    pub rpc_url: Option<Url>,
    /// SeaDrop contract address. Defaults to the chain's known SeaDrop 1.0 singleton.
    #[arg(long)]
    pub seadrop_contract: Option<Address>,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// NFT collection contract address (0x...).
    pub collection: Address,
    #[command(flatten)]
    pub chain_args: ChainArgs,
    /// Wallet address to check per-wallet allocation for (optional; a plain address, never a private key).
    #[arg(long)]
    pub wallet: Option<Address>,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    /// NFT collection contract address (0x...).
    pub collection: Address,
    #[command(flatten)]
    pub chain_args: ChainArgs,
    /// Wallet address to plan a mint for. A plain address only — never a private key (that is loaded separately via KAIROX_SIGNING_KEY or interactive prompt, only when --send is used).
    #[arg(long)]
    pub wallet: Address,
    /// Number of tokens to mint.
    #[arg(long, default_value_t = 1)]
    pub quantity: u64,
    /// Preferred fee recipient address. Must be in the allowed set if the drop restricts fee recipients.
    #[arg(long)]
    pub fee_recipient: Option<Address>,
    /// Maximum acceptable total mint value, in wei (decimal). The plan fails before signing if exceeded.
    #[arg(long, default_value = "1000000000000000000")]
    pub max_mint_value_wei: String,
    /// Maximum acceptable worst-case gas cost, in wei (decimal).
    #[arg(long, default_value = "1000000000000000000")]
    pub max_gas_cost_wei: String,
    /// Maximum acceptable worst-case total spend (mint value + gas cost), in wei (decimal).
    #[arg(long, default_value = "2000000000000000000")]
    pub max_total_spend_wei: String,
    /// Multiplier applied to the RPC's gas estimate to derive the gas limit used in worst-case calculations.
    #[arg(long, default_value_t = 1.25)]
    pub gas_buffer_multiplier: f64,
    /// Override the automatically suggested max priority fee, in gwei (decimal).
    #[arg(long)]
    pub priority_fee_gwei: Option<String>,
    /// Override the automatically computed max fee per gas, in gwei (decimal).
    #[arg(long)]
    pub max_fee_gwei: Option<String>,
}

#[derive(Args, Debug)]
pub struct MintArgs {
    #[command(flatten)]
    pub plan_args: PlanArgs,
    /// Broadcast the transaction live. Without this flag, `mint` is always dry-run only.
    #[arg(long)]
    pub send: bool,
    /// Skip the interactive "type yes to continue" confirmation prompt. Only meaningful with --send.
    #[arg(long)]
    pub yes: bool,
    /// Lead time (seconds) before the state-check checkpoint. Default: 10.
    #[arg(long, default_value_t = 10.0)]
    pub lead_state_check_secs: f64,
    /// Lead time (seconds) before the refresh checkpoint. Default: 3.
    #[arg(long, default_value_t = 3.0)]
    pub lead_refresh_secs: f64,
    /// Lead time (seconds) before the finalize (sign + serialize) checkpoint. Default: 1.
    #[arg(long, default_value_t = 1.0)]
    pub lead_finalize_secs: f64,
    /// How long to poll for a receipt before giving up, in seconds. Default: 60.
    #[arg(long, default_value_t = 60)]
    pub receipt_timeout_secs: u64,
    /// Delay between receipt polls, in milliseconds. Default: 750.
    #[arg(long, default_value_t = 750)]
    pub receipt_poll_interval_ms: u64,
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    #[command(flatten)]
    pub chain_args: ChainArgs,
}
