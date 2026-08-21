//! Resolves a [`crate::metadata::VerifiedContractMetadata`]'s ABI into a
//! confidently-understood mint function and (optionally) a live price
//! getter -- using verified-source parameter *names* as the semantic
//! evidence a bare ABI type signature can't provide (`docs/generic-engine.md`'s
//! confidence-model correction: a matching signature like
//! `mint(uint256,uint256)` alone never establishes what its arguments
//! mean).
//!
//! Deliberately conservative: `mint(uint256,uint256)` is never
//! auto-resolved by this module at all, regardless of parameter names --
//! two same-typed arguments are exactly the case the correction pass
//! called out as too easy to mislabel/misjudge even with names attached.
//! That shape stays reachable only through a manually-reviewed
//! [`super::generic_registry::TrustedGenericFingerprint`].

use alloy_primitives::keccak256;

use crate::metadata::{AbiEntry, VerifiedContractMetadata};

use super::generic_schema::{GenericMintShape, GenericStandard};

const QUANTITY_NAMES: &[&str] = &[
    "quantity",
    "amount",
    "numberoftokens",
    "numtokens",
    "qty",
    "count",
    "num",
    "_quantity",
    "_amount",
];
const RECIPIENT_NAMES: &[&str] = &["to", "recipient", "account", "receiver", "wallet", "_to"];
const PRICE_GETTER_NAMES: &[&str] = &["price", "mintprice", "publicprice", "saleprice", "cost"];

fn normalized(name: &str) -> String {
    name.trim_start_matches('_').to_ascii_lowercase()
}

fn name_matches(name: &str, vocabulary: &[&str]) -> bool {
    let n = normalized(name);
    vocabulary.iter().any(|v| v.trim_start_matches('_') == n)
}

/// `bytes4(keccak256(canonical_signature))`.
fn selector_for_signature(name: &str, input_types: &[&str]) -> [u8; 4] {
    let signature = format!("{name}({})", input_types.join(","));
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriceResolution {
    /// A single, unambiguous, no-argument view/pure getter returning
    /// exactly one `uint256`, with a name in the recognized price-getter
    /// vocabulary.
    Getter { name: String, selector: [u8; 4] },
    /// No price could be independently established -- zero candidate
    /// getters, or more than one (ambiguous: which is authoritative?).
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGenericMint {
    pub shape: GenericMintShape,
    pub standard: GenericStandard,
    pub selector: [u8; 4],
    pub payable: bool,
    pub price: PriceResolution,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticResolution {
    Resolved(ResolvedGenericMint),
    /// More than one candidate mint function was found and none can be
    /// preferred -- never guessed between.
    AmbiguousMintFunction {
        candidates: Vec<String>,
    },
    /// No candidate mint function with independently-established argument
    /// semantics was found at all.
    NotFound,
}

fn candidate_signature(entry: &AbiEntry) -> Option<GenericMintShape> {
    if !entry.is_function() {
        return None;
    }
    let name = normalized(&entry.name);
    let types: Vec<&str> = entry.inputs.iter().map(|p| p.type_.as_str()).collect();

    match (name.as_str(), types.as_slice()) {
        ("mint", ["uint256"]) if name_matches(&entry.inputs[0].name, QUANTITY_NAMES) => {
            Some(GenericMintShape::MintQuantity)
        }
        ("publicmint", ["uint256"]) if name_matches(&entry.inputs[0].name, QUANTITY_NAMES) => {
            Some(GenericMintShape::PublicMintQuantity)
        }
        ("mint", ["address", "uint256"])
            if name_matches(&entry.inputs[0].name, RECIPIENT_NAMES)
                && name_matches(&entry.inputs[1].name, QUANTITY_NAMES) =>
        {
            Some(GenericMintShape::MintToQuantity)
        }
        // mint(uint256,uint256) is deliberately never auto-resolved here,
        // regardless of names -- see module docs.
        _ => None,
    }
}

fn is_price_getter_candidate(entry: &AbiEntry) -> bool {
    entry.is_function()
        && entry.inputs.is_empty()
        && matches!(entry.state_mutability.as_str(), "view" | "pure")
        && entry.outputs.len() == 1
        && entry.outputs[0].type_ == "uint256"
        && name_matches(&entry.name, PRICE_GETTER_NAMES)
}

fn resolve_price(metadata: &VerifiedContractMetadata) -> PriceResolution {
    let candidates: Vec<&AbiEntry> = metadata
        .abi
        .iter()
        .filter(|e| is_price_getter_candidate(e))
        .collect();
    match candidates.as_slice() {
        [single] => {
            let selector = selector_for_signature(&single.name, &[]);
            PriceResolution::Getter {
                name: single.name.clone(),
                selector,
            }
        }
        _ => PriceResolution::Unavailable,
    }
}

/// Resolve `metadata`'s ABI against `expected_standard` (already
/// independently confirmed via ERC-165 by the caller -- this function
/// does not re-check it). Returns [`SemanticResolution::NotFound`] if
/// `metadata.source_verified` is false or the ABI is empty.
pub fn resolve_mint_function(
    metadata: &VerifiedContractMetadata,
    expected_standard: GenericStandard,
) -> SemanticResolution {
    if !metadata.source_verified || metadata.abi.is_empty() {
        return SemanticResolution::NotFound;
    }

    let candidates: Vec<(&AbiEntry, GenericMintShape)> = metadata
        .abi
        .iter()
        .filter_map(|e| candidate_signature(e).map(|shape| (e, shape)))
        .collect();

    match candidates.as_slice() {
        [] => SemanticResolution::NotFound,
        [(entry, shape)] => {
            let types: Vec<&str> = entry.inputs.iter().map(|p| p.type_.as_str()).collect();
            let selector = selector_for_signature(&entry.name, &types);
            let payable = entry.state_mutability == "payable";
            let price = resolve_price(metadata);
            let evidence = format!(
                "verified ABI (provider {}) declares {}({}) with recognized parameter name(s) {}; stateMutability={}",
                metadata.provider,
                entry.name,
                types.join(","),
                entry
                    .inputs
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                entry.state_mutability,
            );
            SemanticResolution::Resolved(ResolvedGenericMint {
                shape: *shape,
                standard: expected_standard,
                selector,
                payable,
                price,
                evidence,
            })
        }
        multiple => SemanticResolution::AmbiguousMintFunction {
            candidates: multiple
                .iter()
                .map(|(e, _)| {
                    format!(
                        "{}({})",
                        e.name,
                        e.inputs
                            .iter()
                            .map(|p| p.type_.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                })
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::AbiParam;

    fn param(name: &str, type_: &str) -> AbiParam {
        AbiParam {
            name: name.to_string(),
            type_: type_.to_string(),
        }
    }

    fn function(
        name: &str,
        inputs: Vec<AbiParam>,
        outputs: Vec<AbiParam>,
        state_mutability: &str,
    ) -> AbiEntry {
        AbiEntry {
            entry_type: "function".to_string(),
            name: name.to_string(),
            inputs,
            outputs,
            state_mutability: state_mutability.to_string(),
        }
    }

    fn metadata_with(abi: Vec<AbiEntry>) -> VerifiedContractMetadata {
        VerifiedContractMetadata {
            chain_id: 1,
            address: alloy_primitives::Address::ZERO,
            source_verified: true,
            implementation: None,
            proxy_type: None,
            abi,
            compiler_version: None,
            name: None,
            provider: "test",
        }
    }

    #[test]
    fn resolves_mint_quantity_with_recognized_name() {
        let metadata = metadata_with(vec![function(
            "mint",
            vec![param("quantity", "uint256")],
            vec![],
            "payable",
        )]);
        let result = resolve_mint_function(&metadata, GenericStandard::Erc721);
        match result {
            SemanticResolution::Resolved(r) => {
                assert_eq!(r.shape, GenericMintShape::MintQuantity);
                assert!(r.payable);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn refuses_mint_uint256_with_unrecognized_parameter_name() {
        let metadata = metadata_with(vec![function(
            "mint",
            vec![param("x", "uint256")],
            vec![],
            "payable",
        )]);
        assert_eq!(
            resolve_mint_function(&metadata, GenericStandard::Erc721),
            SemanticResolution::NotFound
        );
    }

    #[test]
    fn never_auto_resolves_mint_uint256_uint256_even_with_recognized_names() {
        let metadata = metadata_with(vec![function(
            "mint",
            vec![param("tokenId", "uint256"), param("quantity", "uint256")],
            vec![],
            "payable",
        )]);
        assert_eq!(
            resolve_mint_function(&metadata, GenericStandard::Erc1155),
            SemanticResolution::NotFound
        );
    }

    #[test]
    fn resolves_mint_to_quantity() {
        let metadata = metadata_with(vec![function(
            "mint",
            vec![param("to", "address"), param("amount", "uint256")],
            vec![],
            "payable",
        )]);
        match resolve_mint_function(&metadata, GenericStandard::Erc721) {
            SemanticResolution::Resolved(r) => {
                assert_eq!(r.shape, GenericMintShape::MintToQuantity)
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn multiple_candidate_mint_functions_is_ambiguous() {
        let metadata = metadata_with(vec![
            function(
                "mint",
                vec![param("quantity", "uint256")],
                vec![],
                "payable",
            ),
            function(
                "mint",
                vec![param("to", "address"), param("quantity", "uint256")],
                vec![],
                "payable",
            ),
        ]);
        match resolve_mint_function(&metadata, GenericStandard::Erc721) {
            SemanticResolution::AmbiguousMintFunction { candidates } => {
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("expected AmbiguousMintFunction, got {other:?}"),
        }
    }

    #[test]
    fn unverified_contract_never_resolves() {
        let mut metadata = metadata_with(vec![function(
            "mint",
            vec![param("quantity", "uint256")],
            vec![],
            "payable",
        )]);
        metadata.source_verified = false;
        assert_eq!(
            resolve_mint_function(&metadata, GenericStandard::Erc721),
            SemanticResolution::NotFound
        );
    }

    #[test]
    fn resolves_a_single_recognized_price_getter() {
        let metadata = metadata_with(vec![
            function(
                "mint",
                vec![param("quantity", "uint256")],
                vec![],
                "payable",
            ),
            function("mintPrice", vec![], vec![param("", "uint256")], "view"),
        ]);
        match resolve_mint_function(&metadata, GenericStandard::Erc721) {
            SemanticResolution::Resolved(r) => match r.price {
                PriceResolution::Getter { name, .. } => assert_eq!(name, "mintPrice"),
                PriceResolution::Unavailable => panic!("expected a resolved price getter"),
            },
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn multiple_price_getter_candidates_is_unavailable_not_a_guess() {
        let metadata = metadata_with(vec![
            function(
                "mint",
                vec![param("quantity", "uint256")],
                vec![],
                "payable",
            ),
            function("price", vec![], vec![param("", "uint256")], "view"),
            function("mintPrice", vec![], vec![param("", "uint256")], "view"),
        ]);
        match resolve_mint_function(&metadata, GenericStandard::Erc721) {
            SemanticResolution::Resolved(r) => {
                assert_eq!(r.price, PriceResolution::Unavailable)
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn no_price_getter_is_unavailable() {
        let metadata = metadata_with(vec![function(
            "mint",
            vec![param("quantity", "uint256")],
            vec![],
            "nonpayable",
        )]);
        match resolve_mint_function(&metadata, GenericStandard::Erc721) {
            SemanticResolution::Resolved(r) => {
                assert_eq!(r.price, PriceResolution::Unavailable)
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }
}
