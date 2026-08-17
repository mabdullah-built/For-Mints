//! CLI argument definitions.

use alloy_primitives::Address;
use clap::{Args, Parser, Subcommand};
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "kairox",
    version,
    about = "Independent public SeaDrop mint execution CLI (dry-run by default, --send opts into live broadcast)"
)]
pub struct Cli {
    /// Path to a Kairox config file (see `kairox init`). Overrides
    /// KAIROX_CONFIG and the conventional ~/.config/kairox/config.toml
    /// path. The config file only ever names environment VARIABLES for
    /// secrets, never secret values themselves. Currently consulted by
    /// `kairox doctor` (which reports its parse/validation status and
    /// contents); RPC endpoint resolution for other commands still comes
    /// directly from --rpc-url/KAIROX_RPC_* as before.
    #[arg(long, global = true)]
    pub config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Inspect the local Kairox environment. Never broadcasts anything.
    Doctor(DoctorArgs),
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
    /// Write a safe starter config file. Never generates wallets, private keys, or API key values.
    Init(InitArgs),
    /// Read-only recheck of a known transaction's receipt and expected mint evidence. Never submits a transaction.
    Receipt(ReceiptArgs),
}

#[derive(Args, Debug, Default)]
pub struct DoctorArgs {
    /// Emit a single JSON object on stdout instead of human-readable text.
    /// Progress/diagnostic text (if any) goes to stderr, never stdout, so
    /// `kairox doctor --json > report.json` always produces valid JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Where to write the starter config. Defaults to the conventional
    /// ~/.config/kairox/config.toml path.
    #[arg(long)]
    pub path: Option<std::path::PathBuf>,
    /// Overwrite an existing file at the target path. Without this flag,
    /// `init` refuses to touch an existing file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ReceiptArgs {
    #[command(flatten)]
    pub chain_args: ChainArgs,
    /// The transaction hash to recheck (0x...).
    #[arg(long)]
    pub tx: alloy_primitives::B256,
    /// The NFT collection contract address expected to have emitted the mint Transfer event(s).
    #[arg(long)]
    pub collection: Address,
    /// The wallet address expected to be the mint recipient.
    #[arg(long)]
    pub wallet: Address,
    /// The number of tokens the original mint attempt requested.
    #[arg(long, default_value_t = 1)]
    pub quantity: u64,
    /// How long to wait for the receipt to appear before reporting it as
    /// still unknown, in seconds. A short bounded wait, not an open-ended
    /// poll -- this command is for rechecking a transaction that may
    /// already have landed, not for watching a brand-new one.
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,
    /// Emit a single JSON object on stdout instead of human-readable text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ChainArgs {
    /// Chain name ("ethereum", "base", "robinhood chain") or numeric chain
    /// id. When omitted, resolved with the documented precedence: the
    /// KAIROX_CHAIN environment variable, then a config file's
    /// [defaults].chain, then the compiled default "ethereum". See
    /// `kairox init` / `--config`.
    #[arg(long)]
    pub chain: Option<String>,
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
    /// OpenSea collection slug. When provided, also fetches and displays
    /// official OpenSea drop metadata, clearly separated from on-chain
    /// verified state.
    #[arg(long)]
    pub slug: Option<String>,
}

/// Which mint execution engine to use.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineSelection {
    /// Choose deterministically: the pure on-chain public engine when a
    /// public on-chain stage is active and can fully prepare the mint,
    /// otherwise the OpenSea engine (which requires --slug).
    #[default]
    Auto,
    /// Pure on-chain PublicSeaDropEngine only.
    Public,
    /// Official OpenSea Drops API engine only (requires --slug).
    Opensea,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    /// NFT collection contract address (0x...).
    pub collection: Address,
    #[command(flatten)]
    pub chain_args: ChainArgs,
    /// Which mint execution engine to use.
    #[arg(long, value_enum, default_value_t = EngineSelection::Auto)]
    pub engine: EngineSelection,
    /// OpenSea collection slug. Required for --engine opensea; used by
    /// --engine auto only when the public on-chain stage is not active.
    #[arg(long)]
    pub slug: Option<String>,
    /// Wallet address to plan a mint for. A plain address only — never a private key (that is loaded separately via KAIROX_SIGNING_KEY or interactive prompt, only when --send is used). Required for `plan`, and for `mint` unless --wallet-manifest is used instead.
    #[arg(long)]
    pub wallet: Option<Address>,
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
    /// Emit a single JSON object on stdout instead of human-readable text.
    /// Progress/warning text always goes to stderr, never stdout, in this
    /// mode. Supported by `plan`, and by `mint` for a single `--wallet`
    /// (not yet for `--wallet-manifest` multi-wallet sessions).
    #[arg(long)]
    pub json: bool,
    /// Also write the same structured report to PATH (via a temp file +
    /// rename in the same directory, so a write failure never leaves a
    /// truncated file where a previous successful report used to be).
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,
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
    /// Lead time (seconds) before the state-check checkpoint. Defaults to the chain's execution profile.
    #[arg(long)]
    pub lead_state_check_secs: Option<f64>,
    /// Lead time (seconds) before the refresh checkpoint. Defaults to the chain's execution profile.
    #[arg(long)]
    pub lead_refresh_secs: Option<f64>,
    /// Lead time (seconds) before the finalize (sign + serialize) checkpoint. Defaults to the chain's execution profile.
    #[arg(long)]
    pub lead_finalize_secs: Option<f64>,
    /// How long to poll for a receipt before giving up, in seconds. Defaults to the chain's execution profile.
    #[arg(long)]
    pub receipt_timeout_secs: Option<u64>,
    /// Delay between receipt polls, in milliseconds. Defaults to the chain's execution profile.
    #[arg(long)]
    pub receipt_poll_interval_ms: Option<u64>,
    /// Number of latency samples per read-capable endpoint during benchmarking. Defaults to the chain's execution profile.
    #[arg(long)]
    pub benchmark_samples: Option<u32>,
    /// Path to a multi-wallet manifest JSON file (see the manifest schema
    /// docs). Mutually exclusive with --wallet; every quantity/cap/timing
    /// flag above applies uniformly to every manifest wallet. Requires an
    /// explicit --engine public or --engine opensea (auto engine
    /// selection is not supported in manifest mode).
    #[arg(long, conflicts_with = "wallet")]
    pub wallet_manifest: Option<std::path::PathBuf>,
    /// Worst-case aggregate spend ceiling across an entire multi-wallet
    /// session, in wei (decimal). Only meaningful with --wallet-manifest.
    /// Checked before any wallet is signed.
    #[arg(long)]
    pub max_session_total_spend_wei: Option<String>,
    /// Maximum number of wallets dispatching/broadcasting concurrently in
    /// a multi-wallet session. Only meaningful with --wallet-manifest.
    #[arg(long)]
    pub broadcast_concurrency: Option<usize>,
    /// Maximum number of concurrent OpenSea API mint requests in a
    /// multi-wallet OpenSea session. Only meaningful with
    /// --wallet-manifest and --engine opensea.
    #[arg(long)]
    pub opensea_api_concurrency: Option<usize>,
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    #[command(flatten)]
    pub chain_args: ChainArgs,
    /// Number of latency samples per read-capable endpoint. Defaults to the chain's execution profile.
    #[arg(long)]
    pub samples: Option<u32>,
    /// Delay between samples, in milliseconds. Defaults to the chain's execution profile.
    #[arg(long)]
    pub sample_delay_ms: Option<u64>,
}
