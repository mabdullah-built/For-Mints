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
    /// default. Always overridable per-invocation.
    pub default_seadrop_address: Option<Address>,
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
    }
}

fn base() -> ChainInfo {
    ChainInfo {
        chain_id: 8453,
        name: "Base",
        native_symbol: "ETH",
        default_seadrop_address: Some(SEADROP_V1_SINGLETON),
    }
}

fn robinhood() -> ChainInfo {
    ChainInfo {
        chain_id: 4663,
        name: "Robinhood Chain",
        native_symbol: "ETH",
        default_seadrop_address: Some(SEADROP_V1_SINGLETON),
    }
}

/// A registry of known chains, queryable by id or name.
#[derive(Debug, Clone)]
pub struct ChainRegistry {
    chains: Vec<ChainInfo>,
}

impl ChainRegistry {
    /// The built-in Phase 1 chain set: Ethereum, Base, Robinhood Chain.
    pub fn builtin() -> Self {
        Self {
            chains: vec![ethereum(), base(), robinhood()],
        }
    }

    pub fn by_id(&self, chain_id: ChainId) -> Option<&ChainInfo> {
        self.chains.iter().find(|c| c.chain_id == chain_id)
    }

    pub fn by_name(&self, name: &str) -> Option<&ChainInfo> {
        self.chains
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
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
        });
        assert_eq!(reg.by_id(137).unwrap().name, "Polygon");
        assert_eq!(reg.all().len(), 4);
    }
}
