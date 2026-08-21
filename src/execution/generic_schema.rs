//! An operator-declared mint call schema for the generic verified contract
//! engine ([`super::generic_engine`]). Kairox never infers these semantics
//! from a function *name* or from bytecode alone -- the operator names the
//! exact, already-independently-verified shape (this is the "explicit
//! trusted adapter schema" form of evidence), and
//! `cli::commands::resolver_adapters::GenericVerifiedContractAdapter`
//! additionally requires on-chain ERC-165 corroboration before this schema
//! is allowed to resolve to a live-send path at all.
//!
//! Deliberately a small, closed set of named shapes rather than a
//! parameter-position DSL: each shape below is fully reviewed, tested
//! code, never a runtime-interpreted calldata template.

use serde::Deserialize;

use super::errors::{KairoxError, SessionError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenericStandard {
    Erc721,
    Erc1155,
}

impl GenericStandard {
    pub fn erc165_interface_id(&self) -> [u8; 4] {
        match self {
            GenericStandard::Erc721 => crate::protocol::erc_standards::ERC721_INTERFACE_ID,
            GenericStandard::Erc1155 => crate::protocol::erc_standards::ERC1155_INTERFACE_ID,
        }
    }
}

/// The exact, closed set of conventional mint call shapes Kairox can build
/// calldata for. Adding a new one is a code change (a new reviewed/tested
/// match arm in `generic_engine::encode_calldata`), never a config-only
/// addition -- see `docs/generic-engine.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenericMintShape {
    /// `mint(uint256 quantity) payable`
    MintQuantity,
    /// `publicMint(uint256 quantity) payable`
    PublicMintQuantity,
    /// `mint(address to, uint256 quantity) payable`
    MintToQuantity,
    /// `mint(uint256 id, uint256 quantity) payable` -- ERC-1155 single-id.
    MintIdQuantity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GenericMintSchema {
    pub standard: GenericStandard,
    pub shape: GenericMintShape,
    /// Required, and only meaningful, for [`GenericMintShape::MintIdQuantity`].
    #[serde(default)]
    pub token_id: Option<u64>,
    /// Operator-declared price per token, in wei (decimal string). The
    /// prepared transaction's value is exactly `price_per_token_wei *
    /// quantity` -- Kairox never derives a price from the contract itself
    /// for the generic engine (there is no standard getter to trust).
    pub price_per_token_wei: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GenericSchemaError {
    #[error("generic schema: shape mint_id_quantity requires token_id to be set")]
    MissingTokenId,
    #[error("generic schema: token_id is only meaningful for shape mint_id_quantity")]
    UnexpectedTokenId,
    #[error("generic schema: invalid price_per_token_wei: {0}")]
    InvalidPrice(String),
}

impl GenericMintSchema {
    pub fn validate(&self) -> Result<(), GenericSchemaError> {
        match (self.shape, self.token_id) {
            (GenericMintShape::MintIdQuantity, None) => Err(GenericSchemaError::MissingTokenId),
            (GenericMintShape::MintIdQuantity, Some(_)) => Ok(()),
            (_, Some(_)) => Err(GenericSchemaError::UnexpectedTokenId),
            (_, None) => Ok(()),
        }
    }
}

pub fn load_schema(path: &std::path::Path) -> Result<GenericMintSchema, KairoxError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to read generic mint schema {}: {e}",
            path.display()
        )))
    })?;
    let schema: GenericMintSchema = toml::from_str(&raw).map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "failed to parse generic mint schema {}: {e}",
            path.display()
        )))
    })?;
    schema.validate().map_err(|e| {
        KairoxError::Session(SessionError::new(format!(
            "invalid generic mint schema {}: {e}",
            path.display()
        )))
    })?;
    Ok(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_id_quantity_without_token_id_is_rejected() {
        let schema = GenericMintSchema {
            standard: GenericStandard::Erc1155,
            shape: GenericMintShape::MintIdQuantity,
            token_id: None,
            price_per_token_wei: "0".to_string(),
        };
        assert!(matches!(
            schema.validate(),
            Err(GenericSchemaError::MissingTokenId)
        ));
    }

    #[test]
    fn mint_quantity_with_token_id_is_rejected() {
        let schema = GenericMintSchema {
            standard: GenericStandard::Erc721,
            shape: GenericMintShape::MintQuantity,
            token_id: Some(1),
            price_per_token_wei: "0".to_string(),
        };
        assert!(matches!(
            schema.validate(),
            Err(GenericSchemaError::UnexpectedTokenId)
        ));
    }

    #[test]
    fn valid_schemas_pass() {
        let schema = GenericMintSchema {
            standard: GenericStandard::Erc721,
            shape: GenericMintShape::MintQuantity,
            token_id: None,
            price_per_token_wei: "0".to_string(),
        };
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn erc165_interface_ids_match_the_protocol_module_constants() {
        assert_eq!(
            GenericStandard::Erc721.erc165_interface_id(),
            crate::protocol::erc_standards::ERC721_INTERFACE_ID
        );
        assert_eq!(
            GenericStandard::Erc1155.erc165_interface_id(),
            crate::protocol::erc_standards::ERC1155_INTERFACE_ID
        );
    }
}
