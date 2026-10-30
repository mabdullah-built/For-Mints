//! Pure EIP-1559 fee math and spend safety caps.
//!
//! Nothing in this module performs I/O. All functions are deterministic and
//! safe to exercise with fixed fixtures.

use alloy_primitives::U256;
use thiserror::Error;

/// A validated EIP-1559 fee triple.
///
/// Construction enforces the two invariants Kairox always requires before a
/// transaction may be built:
///
/// - `max_fee_per_gas >= base_fee_per_gas`
/// - `max_priority_fee_per_gas <= max_fee_per_gas`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip1559Fees {
    base_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FeeError {
    #[error("max_fee_per_gas ({max_fee_per_gas}) is below current base fee ({base_fee_per_gas})")]
    MaxFeeBelowBaseFee {
        max_fee_per_gas: u128,
        base_fee_per_gas: u128,
    },
    #[error("max_priority_fee_per_gas ({priority}) exceeds max_fee_per_gas ({max_fee})")]
    PriorityExceedsMaxFee { priority: u128, max_fee: u128 },
}

impl Eip1559Fees {
    /// Build a fee triple, enforcing both required invariants.
    pub fn new(
        base_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
    ) -> Result<Self, FeeError> {
        if max_fee_per_gas < base_fee_per_gas {
            return Err(FeeError::MaxFeeBelowBaseFee {
                max_fee_per_gas,
                base_fee_per_gas,
            });
        }
        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(FeeError::PriorityExceedsMaxFee {
                priority: max_priority_fee_per_gas,
                max_fee: max_fee_per_gas,
            });
        }
        Ok(Self {
            base_fee_per_gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
        })
    }

    pub fn base_fee_per_gas(&self) -> u128 {
        self.base_fee_per_gas
    }

    pub fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    pub fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    /// Worst-case per-gas cost the sender could ever pay: `max_fee_per_gas`.
    pub fn worst_case_gas_cost(&self, gas_limit: u64) -> U256 {
        U256::from(self.max_fee_per_gas) * U256::from(gas_limit)
    }
}

/// Worst-case total upfront requirement: `mintValue + gasLimit * maxFeePerGas`.
pub fn worst_case_total_spend(mint_value: U256, worst_case_gas_cost: U256) -> U256 {
    mint_value.saturating_add(worst_case_gas_cost)
}

/// User-configured spend ceilings. A plan must fail before signing if any
/// cap would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyCaps {
    pub max_mint_value: U256,
    pub max_gas_cost: U256,
    pub max_total_spend: U256,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SafetyCapError {
    #[error("mint value {value} exceeds configured cap {cap}")]
    MintValueExceeded { value: U256, cap: U256 },
    #[error("worst-case gas cost {value} exceeds configured cap {cap}")]
    GasCostExceeded { value: U256, cap: U256 },
    #[error("worst-case total spend {value} exceeds configured cap {cap}")]
    TotalSpendExceeded { value: U256, cap: U256 },
}

impl SafetyCaps {
    /// Enforce all three caps against a computed plan. Fails on the first
    /// violation found (mint value, then gas cost, then total spend).
    pub fn check(
        &self,
        mint_value: U256,
        gas_cost: U256,
        total_spend: U256,
    ) -> Result<(), SafetyCapError> {
        if mint_value > self.max_mint_value {
            return Err(SafetyCapError::MintValueExceeded {
                value: mint_value,
                cap: self.max_mint_value,
            });
        }
        if gas_cost > self.max_gas_cost {
            return Err(SafetyCapError::GasCostExceeded {
                value: gas_cost,
                cap: self.max_gas_cost,
            });
        }
        if total_spend > self.max_total_spend {
            return Err(SafetyCapError::TotalSpendExceeded {
                value: total_spend,
                cap: self.max_total_spend,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_fee_triple() {
        let fees = Eip1559Fees::new(10, 2, 15).unwrap();
        assert_eq!(fees.base_fee_per_gas(), 10);
        assert_eq!(fees.max_priority_fee_per_gas(), 2);
        assert_eq!(fees.max_fee_per_gas(), 15);
    }

    #[test]
    fn rejects_max_fee_below_base_fee() {
        let err = Eip1559Fees::new(20, 1, 15).unwrap_err();
        assert_eq!(
            err,
            FeeError::MaxFeeBelowBaseFee {
                max_fee_per_gas: 15,
                base_fee_per_gas: 20,
            }
        );
    }

    #[test]
    fn rejects_priority_above_max_fee() {
        let err = Eip1559Fees::new(10, 20, 15).unwrap_err();
        assert_eq!(
            err,
            FeeError::PriorityExceedsMaxFee {
                priority: 20,
                max_fee: 15,
            }
        );
    }

    #[test]
    fn accepts_max_fee_equal_to_base_fee() {
        assert!(Eip1559Fees::new(10, 10, 10).is_ok());
    }

    #[test]
    fn worst_case_gas_cost_multiplies_max_fee_by_limit() {
        let fees = Eip1559Fees::new(10, 2, 20).unwrap();
        assert_eq!(
            fees.worst_case_gas_cost(250_000),
            U256::from(20u128) * U256::from(250_000u64)
        );
    }

    #[test]
    fn worst_case_total_spend_adds_mint_value_and_gas_cost() {
        let total = worst_case_total_spend(U256::from(1_000u64), U256::from(500u64));
        assert_eq!(total, U256::from(1_500u64));
    }

    #[test]
    fn safety_caps_pass_when_within_bounds() {
        let caps = SafetyCaps {
            max_mint_value: U256::from(1_000u64),
            max_gas_cost: U256::from(1_000u64),
            max_total_spend: U256::from(2_000u64),
        };
        assert!(
            caps.check(U256::from(500u64), U256::from(500u64), U256::from(1_000u64))
                .is_ok()
        );
    }

    #[test]
    fn safety_caps_reject_mint_value_over_cap() {
        let caps = SafetyCaps {
            max_mint_value: U256::from(100u64),
            max_gas_cost: U256::from(1_000u64),
            max_total_spend: U256::from(2_000u64),
        };
        let err = caps
            .check(U256::from(101u64), U256::from(1u64), U256::from(102u64))
            .unwrap_err();
        assert!(matches!(err, SafetyCapError::MintValueExceeded { .. }));
    }

    #[test]
    fn safety_caps_reject_gas_cost_over_cap() {
        let caps = SafetyCaps {
            max_mint_value: U256::from(1_000u64),
            max_gas_cost: U256::from(100u64),
            max_total_spend: U256::from(2_000u64),
        };
        let err = caps
            .check(U256::from(1u64), U256::from(101u64), U256::from(102u64))
            .unwrap_err();
        assert!(matches!(err, SafetyCapError::GasCostExceeded { .. }));
    }

    #[test]
    fn safety_caps_reject_total_spend_over_cap() {
        let caps = SafetyCaps {
            max_mint_value: U256::from(1_000u64),
            max_gas_cost: U256::from(1_000u64),
            max_total_spend: U256::from(100u64),
        };
        let err = caps
            .check(U256::from(60u64), U256::from(60u64), U256::from(120u64))
            .unwrap_err();
        assert!(matches!(err, SafetyCapError::TotalSpendExceeded { .. }));
    }
}
