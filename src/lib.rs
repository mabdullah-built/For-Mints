//! Kairox: an independent, low-latency public SeaDrop mint execution CLI.
//!
//! Supports pure on-chain public SeaDrop mints and OpenSea-hosted
//! (wallet-specific/allowlist/server-signed) drops, single-wallet and
//! multi-wallet (self-funded only), with dry-run as the default mode --
//! `--send` opts into live broadcast.

pub mod chain;
pub mod cli;
pub mod config;
pub mod domain;
pub mod execution;
pub mod metadata;
pub mod opensea;
pub mod protocol;
pub mod signing;

/// The crate version, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
