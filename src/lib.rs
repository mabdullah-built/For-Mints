//! Kairox: an independent, low-latency public SeaDrop mint execution CLI.
//!
//! Phase 1 implements the foundation and a dry-run-only public-mint
//! pipeline. There is no transaction-broadcasting path anywhere in this
//! crate yet.

pub mod chain;
pub mod cli;
pub mod domain;
pub mod execution;
pub mod opensea;
pub mod protocol;
pub mod signing;

/// The crate version, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
