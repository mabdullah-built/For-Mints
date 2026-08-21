//! Chain registry: chain behavior comes from data here, not scattered
//! conditionals elsewhere in the codebase.

use alloy_primitives::Address;

/// EVM chain id.
pub type ChainId = u64;

/// Static, chain-specific configuration. Adding a new chain means adding an
/// entry here (or loading one at runtime), never adding `if chain_id == ...`
/// branches elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainInfo {
    pub chain_id: ChainId,
    pub name: &'static str,
    pub native_symbol: &'static str,
    /// The well-known SeaDrop 1.0 singleton address on this chain, used as a
    /// default. Always overridable per-invocation. `None` when no genuine
    /// SeaDrop deployment on this chain has been independently verified --
    /// callers MUST then require an explicit `--seadrop-contract` rather
    /// than guessing or reusing another chain's address (see
    /// `resolve_chain` in `cli::context`, which already fails closed on
    /// `None` with no override).
    pub default_seadrop_address: Option<Address>,
    /// Additional case-insensitive names this chain resolves by, besides
    /// `name` itself (e.g. a short alias). Never used to *disambiguate* --
    /// each alias must belong to exactly one chain, enforced by a test.
    pub aliases: &'static [&'static str],
}

/// The canonical SeaDrop 1.0 singleton deployment address, identical across
/// every chain it has been deployed to.
pub const SEADROP_V1_SINGLETON: Address =
    alloy_primitives::address!("00005EA00Ac477B1030CE78506496e8C2dE24bf5");

fn ethereum() -> ChainInfo {
    ChainInfo {
        chain_id: 1,
        name: "Ethereum",
        native_symbol: "ETH",
        default_seadrop_address: Some(SEADROP_V1_SINGLETON),
        aliases: &[],
    }
}

fn base() -> ChainInfo {
    ChainInfo {
        chain_id: 8453,
        name: "Base",
        native_symbol: "ETH",
        default_seadrop_address: Some(SEADROP_V1_SINGLETON),
        aliases: &[],
    }
}

fn robinhood() -> ChainInfo {
    ChainInfo {
        chain_id: 4663,
        name: "Robinhood Chain",
        native_symbol: "ETH",
        default_seadrop_address: Some(SEADROP_V1_SINGLETON),
        aliases: &[],
    }
}

/// Robinhood Chain TESTNET -- a distinct chain id from Robinhood Chain
/// mainnet (4663), never to be confused with it. No genuine SeaDrop
/// deployment on this testnet has been independently verified, so this
/// deliberately has `default_seadrop_address: None`: every SeaDrop
/// operation on this chain requires an explicit `--seadrop-contract`
/// (enforced by `cli::context::resolve_chain`, unchanged for this chain).
fn robinhood_testnet() -> ChainInfo {
    ChainInfo {
        chain_id: 46630,
        name: "Robinhood Chain Testnet",
        native_symbol: "ETH",
        default_seadrop_address: None,
        aliases: &["robinhood-testnet", "rh-testnet"],
    }
}

/// A registry of known chains, queryable by id or name.
#[derive(Debug, Clone)]
pub struct ChainRegistry {
    chains: Vec<ChainInfo>,
}

impl ChainRegistry {
    /// The built-in chain set: Ethereum, Base, Robinhood Chain, Robinhood
    /// Chain Testnet.
    pub fn builtin() -> Self {
        Self {
            chains: vec![ethereum(), base(), robinhood(), robinhood_testnet()],
        }
    }

    pub fn by_id(&self, chain_id: ChainId) -> Option<&ChainInfo> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }

    /// Matches a chain's `name` or any of its `aliases`, case-insensitively.
    pub fn by_name(&self, name: &str) -> Option<&ChainInfo> {
        self.chains.iter().find(|c| {
            c.name.eq_ignore_ascii_case(name)
                || c.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
        })
    }

    pub fn all(&self) -> &[ChainInfo] {
        &self.chains
    }

    /// Register (or replace) a chain entry. Lets Kairox be configured for
    /// chains beyond the Phase 1 built-ins without code changes.
    pub fn insert(&mut self, chain: ChainInfo) {
        if let Some(existing) = self
            .chains
            .iter_mut()
            .find(|c| c.chain_id == chain.chain_id)
        {
            *existing = chain;
        } else {
            self.chains.push(chain);
        }
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_contains_ethereum_base_robinhood() {
        let reg = ChainRegistry::builtin();
        assert_eq!(reg.by_id(1).unwrap().name, "Ethereum");
        assert_eq!(reg.by_id(8453).unwrap().name, "Base");
        assert_eq!(reg.by_id(4663).unwrap().name, "Robinhood Chain");
    }

    #[test]
    fn by_name_is_case_insensitive() {
        let reg = ChainRegistry::builtin();
        assert_eq!(reg.by_name("base").unwrap().chain_id, 8453);
        assert_eq!(reg.by_name("ROBINHOOD CHAIN").unwrap().chain_id, 4663);
    }

    #[test]
    fn unknown_chain_id_returns_none() {
        let reg = ChainRegistry::builtin();
        assert!(reg.by_id(999_999).is_none());
    }

    #[test]
    fn insert_replaces_existing_entry_by_chain_id() {
        let mut reg = ChainRegistry::builtin();
        reg.insert(ChainInfo {
            chain_id: 1,
            name: "Ethereum Mainnet",
            native_symbol: "ETH",
            default_seadrop_address: None,
            aliases: &[],
        });
        assert_eq!(reg.by_id(1).unwrap().name, "Ethereum Mainnet");
        assert_eq!(reg.all().iter().filter(|c| c.chain_id == 1).count(), 1);
    }

    #[test]
    fn insert_adds_new_chain() {
        let mut reg = ChainRegistry::builtin();
        reg.insert(ChainInfo {
            chain_id: 137,
            name: "Polygon",
            native_symbol: "MATIC",
            default_seadrop_address: None,
            aliases: &[],
        });
        assert_eq!(reg.by_id(137).unwrap().name, "Polygon");
        assert_eq!(reg.all().len(), 5);
    }

    // -------------------------------------------------------------------
    // Robinhood Chain Testnet (chain id 46630) -- must never be confused
    // with Robinhood Chain mainnet (chain id 4663).
    // -------------------------------------------------------------------

    #[test]
    fn robinhood_testnet_resolves_by_chain_id() {
        let reg = ChainRegistry::builtin();
        let chain = reg.by_id(46630).unwrap();
        assert_eq!(chain.name, "Robinhood Chain Testnet");
        assert_eq!(chain.chain_id, 46630);
        assert!(
            chain.default_seadrop_address.is_none(),
            "no SeaDrop deployment on Robinhood Testnet has been verified -- \
             there must be no compiled default address"
        );
    }

    #[test]
    fn robinhood_testnet_resolves_by_alias() {
        let reg = ChainRegistry::builtin();
        assert_eq!(reg.by_name("robinhood-testnet").unwrap().chain_id, 46630);
        assert_eq!(reg.by_name("rh-testnet").unwrap().chain_id, 46630);
        // Case-insensitive, matching the same convention as chain names.
        assert_eq!(reg.by_name("RH-TESTNET").unwrap().chain_id, 46630);
        assert_eq!(reg.by_name("Robinhood-Testnet").unwrap().chain_id, 46630);
    }

    #[test]
    fn robinhood_testnet_resolves_by_full_name() {
        let reg = ChainRegistry::builtin();
        assert_eq!(
            reg.by_name("robinhood chain testnet").unwrap().chain_id,
            46630
        );
    }

    #[test]
    fn robinhood_mainnet_still_resolves_correctly_and_keeps_its_default_seadrop() {
        let reg = ChainRegistry::builtin();
        let chain = reg.by_id(4663).unwrap();
        assert_eq!(chain.name, "Robinhood Chain");
        assert_eq!(chain.default_seadrop_address, Some(SEADROP_V1_SINGLETON));
    }

    #[test]
    fn robinhood_testnet_and_mainnet_are_never_confused() {
        let reg = ChainRegistry::builtin();
        let mainnet = reg.by_id(4663).unwrap();
        let testnet = reg.by_id(46630).unwrap();
        assert_ne!(mainnet.chain_id, testnet.chain_id);
        assert_ne!(mainnet.name, testnet.name);
        // Neither chain's aliases/name accidentally match the other's.
        assert!(
            reg.by_name("4663").is_none(),
            "by_name must not parse numeric ids"
        );
        assert_ne!(reg.by_name("robinhood chain").unwrap().chain_id, 46630);
        assert_ne!(
            reg.by_name("robinhood chain testnet").unwrap().chain_id,
            4663
        );
        // No alias of one chain is also an alias (or the name) of the other.
        for alias in testnet.aliases {
            assert!(!mainnet.name.eq_ignore_ascii_case(alias));
            assert!(
                !mainnet
                    .aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(alias))
            );
        }
    }

    #[test]
    fn builtin_still_contains_ethereum_base_robinhood_mainnet_unmodified() {
        // Adding the testnet entry must not disturb the pre-existing chains.
        let reg = ChainRegistry::builtin();
        assert_eq!(reg.by_id(1).unwrap().name, "Ethereum");
        assert_eq!(reg.by_id(8453).unwrap().name, "Base");
        assert_eq!(reg.by_id(4663).unwrap().name, "Robinhood Chain");
        assert_eq!(reg.all().len(), 4);
    }
}
