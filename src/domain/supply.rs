//! Pure wallet-allocation and collection-supply arithmetic.
//!
//! Kairox must fail closed whenever a requested quantity cannot be proven
//! safe against both the per-wallet cap and the collection supply.

use thiserror::Error;

/// A wallet's per-collection mint allocation, as read from on-chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletAllocation {
    pub max_total_mintable_by_wallet: u64,
    pub already_minted: u64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SupplyError {
    #[error(
        "wallet has already minted ({already_minted}) more than its cap ({cap}); refusing to proceed"
    )]
    WalletStateInconsistent { already_minted: u64, cap: u64 },
    #[error(
        "collection current supply ({current}) exceeds max supply ({max}); refusing to proceed"
    )]
    CollectionStateInconsistent { current: u64, max: u64 },
    #[error("wallet allocation exhausted (0 remaining)")]
    WalletAllocationExhausted,
    #[error("collection is sold out (0 remaining)")]
    CollectionSoldOut,
    #[error("requested quantity {requested} exceeds remaining wallet allocation {remaining}")]
    ExceedsWalletAllocation { requested: u64, remaining: u64 },
    #[error("requested quantity {requested} exceeds remaining collection supply {remaining}")]
    ExceedsCollectionSupply { requested: u64, remaining: u64 },
    #[error("requested quantity must be greater than zero")]
    ZeroQuantity,
    #[error("collection maximum supply could not be safely determined; refusing to proceed")]
    UnknownCollectionSupply,
}

impl WalletAllocation {
    /// `remainingWalletAllocation = maxTotalMintableByWallet - alreadyMinted`.
    pub fn remaining(&self) -> Result<u64, SupplyError> {
        self.max_total_mintable_by_wallet
            .checked_sub(self.already_minted)
            .ok_or(SupplyError::WalletStateInconsistent {
                already_minted: self.already_minted,
                cap: self.max_total_mintable_by_wallet,
            })
    }
}

/// Collection-wide supply. `max_supply = None` means Kairox could not (or
/// the collection does not) safely determine an upper bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectionSupply {
    pub max_supply: Option<u64>,
    pub current_supply: u64,
}

impl CollectionSupply {
    /// `remainingCollectionSupply = maxSupply - currentSupply`.
    ///
    /// Fails closed (`UnknownCollectionSupply`) when `max_supply` is not
    /// known, rather than treating an unknown bound as unlimited.
    pub fn remaining(&self) -> Result<u64, SupplyError> {
        let max = self
            .max_supply
            .ok_or(SupplyError::UnknownCollectionSupply)?;
        max.checked_sub(self.current_supply)
            .ok_or(SupplyError::CollectionStateInconsistent {
                current: self.current_supply,
                max,
            })
    }
}

/// Validate a requested mint quantity against both the wallet allocation and
/// the collection supply. Returns the two remaining values on success.
pub fn validate_requested_quantity(
    quantity: u64,
    wallet: &WalletAllocation,
    collection: &CollectionSupply,
) -> Result<(u64, u64), SupplyError> {
    if quantity == 0 {
        return Err(SupplyError::ZeroQuantity);
    }

    let wallet_remaining = wallet.remaining()?;
    if wallet_remaining == 0 {
        return Err(SupplyError::WalletAllocationExhausted);
    }
    if quantity > wallet_remaining {
        return Err(SupplyError::ExceedsWalletAllocation {
            requested: quantity,
            remaining: wallet_remaining,
        });
    }

    let collection_remaining = collection.remaining()?;
    if collection_remaining == 0 {
        return Err(SupplyError::CollectionSoldOut);
    }
    if quantity > collection_remaining {
        return Err(SupplyError::ExceedsCollectionSupply {
            requested: quantity,
            remaining: collection_remaining,
        });
    }

    Ok((wallet_remaining, collection_remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(cap: u64, minted: u64) -> WalletAllocation {
        WalletAllocation {
            max_total_mintable_by_wallet: cap,
            already_minted: minted,
        }
    }

    fn collection(max: Option<u64>, current: u64) -> CollectionSupply {
        CollectionSupply {
            max_supply: max,
            current_supply: current,
        }
    }

    #[test]
    fn wallet_remaining_basic() {
        assert_eq!(wallet(5, 2).remaining().unwrap(), 3);
    }

    #[test]
    fn wallet_remaining_zero_when_fully_minted() {
        assert_eq!(wallet(5, 5).remaining().unwrap(), 0);
    }

    #[test]
    fn wallet_remaining_fails_closed_on_inconsistent_state() {
        let err = wallet(5, 6).remaining().unwrap_err();
        assert_eq!(
            err,
            SupplyError::WalletStateInconsistent {
                already_minted: 6,
                cap: 5
            }
        );
    }

    #[test]
    fn collection_remaining_basic() {
        assert_eq!(collection(Some(100), 40).remaining().unwrap(), 60);
    }

    #[test]
    fn collection_remaining_unknown_fails_closed() {
        let err = collection(None, 40).remaining().unwrap_err();
        assert_eq!(err, SupplyError::UnknownCollectionSupply);
    }

    #[test]
    fn collection_remaining_inconsistent_state() {
        let err = collection(Some(10), 20).remaining().unwrap_err();
        assert_eq!(
            err,
            SupplyError::CollectionStateInconsistent {
                current: 20,
                max: 10
            }
        );
    }

    #[test]
    fn validate_ok_within_both_limits() {
        let (wr, cr) =
            validate_requested_quantity(2, &wallet(5, 1), &collection(Some(100), 90)).unwrap();
        assert_eq!(wr, 4);
        assert_eq!(cr, 10);
    }

    #[test]
    fn validate_rejects_zero_quantity() {
        let err =
            validate_requested_quantity(0, &wallet(5, 0), &collection(Some(100), 0)).unwrap_err();
        assert_eq!(err, SupplyError::ZeroQuantity);
    }

    #[test]
    fn validate_rejects_exhausted_wallet_allocation() {
        let err =
            validate_requested_quantity(1, &wallet(5, 5), &collection(Some(100), 0)).unwrap_err();
        assert_eq!(err, SupplyError::WalletAllocationExhausted);
    }

    #[test]
    fn validate_rejects_quantity_exceeding_wallet_allocation() {
        let err =
            validate_requested_quantity(3, &wallet(5, 3), &collection(Some(100), 0)).unwrap_err();
        assert_eq!(
            err,
            SupplyError::ExceedsWalletAllocation {
                requested: 3,
                remaining: 2
            }
        );
    }

    #[test]
    fn validate_rejects_sold_out_collection() {
        let err =
            validate_requested_quantity(1, &wallet(5, 0), &collection(Some(100), 100)).unwrap_err();
        assert_eq!(err, SupplyError::CollectionSoldOut);
    }

    #[test]
    fn validate_rejects_quantity_exceeding_collection_supply() {
        let err =
            validate_requested_quantity(5, &wallet(10, 0), &collection(Some(100), 97)).unwrap_err();
        assert_eq!(
            err,
            SupplyError::ExceedsCollectionSupply {
                requested: 5,
                remaining: 3
            }
        );
    }

    #[test]
    fn validate_fails_closed_on_unknown_collection_supply() {
        let err = validate_requested_quantity(1, &wallet(10, 0), &collection(None, 0)).unwrap_err();
        assert_eq!(err, SupplyError::UnknownCollectionSupply);
    }
}
