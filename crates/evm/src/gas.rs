//! Gas Metering
//!
//! This module provides gas cost calculations, EIP-1559 base fee management,
//! and priority fee handling for Proto Core.

use serde::{Deserialize, Serialize};

/// Gas costs for various operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCosts {
    /// Base cost for a transaction (21000 gas)
    pub tx_base: u64,
    /// Cost per zero byte of calldata
    pub tx_data_zero: u64,
    /// Cost per non-zero byte of calldata
    pub tx_data_non_zero: u64,
    /// Cost per access list address
    pub access_list_address: u64,
    /// Cost per access list storage key
    pub access_list_storage_key: u64,
    /// Contract creation base cost
    pub tx_create: u64,
    /// Cost per init code word (32 bytes) for contract creation
    pub init_code_word: u64,
    /// Cost for SLOAD operation (cold)
    pub sload_cold: u64,
    /// Cost for SLOAD operation (warm)
    pub sload_warm: u64,
    /// Cost for SSTORE operation (set from zero)
    pub sstore_set: u64,
    /// Cost for SSTORE operation (reset)
    pub sstore_reset: u64,
    /// Refund for SSTORE clearing
    pub sstore_clear_refund: u64,
    /// Cost for CALL operation (base)
    pub call_base: u64,
    /// Cost for CALL with value transfer
    pub call_value: u64,
    /// Cost for CALL to new account
    pub call_new_account: u64,
    /// Cost for LOG0 operation (base)
    pub log_base: u64,
    /// Cost per LOG topic
    pub log_topic: u64,
    /// Cost per LOG data byte
    pub log_data: u64,
    /// Cost for KECCAK256 (base)
    pub keccak256_base: u64,
    /// Cost per KECCAK256 word
    pub keccak256_word: u64,
    /// Cost for COPY operations (per word)
    pub copy_word: u64,
    /// Cost for memory expansion (per word)
    pub memory_word: u64,
    /// Cost for EXP operation (base)
    pub exp_base: u64,
    /// Cost per EXP exponent byte
    pub exp_byte: u64,
    /// Cost for EXTCODESIZE (cold)
    pub extcodesize_cold: u64,
    /// Cost for BALANCE (cold)
    pub balance_cold: u64,
    /// Cold account access cost
    pub cold_account_access: u64,
    /// Cold sload cost
    pub cold_sload: u64,
    /// Warm storage read cost
    pub warm_storage_read: u64,
}

impl Default for GasCosts {
    fn default() -> Self {
        Self {
            // EIP-2028, EIP-2929, EIP-3529 values
            tx_base: 21000,
            tx_data_zero: 4,
            tx_data_non_zero: 16,
            access_list_address: 2400,
            access_list_storage_key: 1900,
            tx_create: 32000,
            init_code_word: 2, // EIP-3860
            sload_cold: 2100,
            sload_warm: 100,
            sstore_set: 20000,
            sstore_reset: 2900,
            sstore_clear_refund: 4800,
            call_base: 100,
            call_value: 9000,
            call_new_account: 25000,
            log_base: 375,
            log_topic: 375,
            log_data: 8,
            keccak256_base: 30,
            keccak256_word: 6,
            copy_word: 3,
            memory_word: 3,
            exp_base: 10,
            exp_byte: 50,
            extcodesize_cold: 2600,
            balance_cold: 2600,
            cold_account_access: 2600,
            cold_sload: 2100,
            warm_storage_read: 100,
        }
    }
}

impl GasCosts {
    /// Calculate intrinsic gas for a transaction
    pub fn intrinsic_gas(&self, data: &[u8], is_create: bool, access_list_len: usize) -> u64 {
        let mut gas = self.tx_base;

        // Contract creation
        if is_create {
            gas += self.tx_create;
            // Init code cost (EIP-3860)
            let init_code_words = (data.len() + 31) / 32;
            gas += init_code_words as u64 * self.init_code_word;
        }

        // Calldata cost
        for byte in data {
            if *byte == 0 {
                gas += self.tx_data_zero;
            } else {
                gas += self.tx_data_non_zero;
            }
        }

        // Access list cost
        gas += access_list_len as u64 * self.access_list_address;

        gas
    }

    /// Calculate memory expansion cost
    pub fn memory_expansion_cost(&self, current_size: u64, new_size: u64) -> u64 {
        if new_size <= current_size {
            return 0;
        }

        let new_words = (new_size + 31) / 32;
        let current_words = (current_size + 31) / 32;

        let new_cost = new_words * self.memory_word + (new_words * new_words) / 512;
        let current_cost = current_words * self.memory_word + (current_words * current_words) / 512;

        new_cost.saturating_sub(current_cost)
    }
}

/// Gas configuration for the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Gas costs for operations
    pub costs: GasCosts,
    /// Minimum gas price (wei)
    pub min_gas_price: u128,
    /// Minimum base fee (wei)
    pub min_base_fee: u128,
    /// Maximum base fee (wei)
    pub max_base_fee: u128,
    /// Base fee change denominator (controls rate of change)
    pub base_fee_change_denominator: u64,
    /// Elasticity multiplier (target gas usage as fraction of limit)
    pub elasticity_multiplier: u64,
    /// Maximum gas refund as fraction of gas used
    pub max_refund_quotient: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            costs: GasCosts::default(),
            min_gas_price: 1_000_000_000,        // 1 gwei
            min_base_fee: 1_000_000_000,         // 1 gwei
            max_base_fee: 1_000_000_000_000_000, // 1000 gwei
            base_fee_change_denominator: 8,      // 12.5% max change
            elasticity_multiplier: 2,            // 50% target
            max_refund_quotient: 5,              // Max 20% refund
        }
    }
}

/// EIP-1559 base fee calculator
#[derive(Debug, Clone)]
pub struct BaseFeeCalculator {
    /// Gas configuration
    config: GasConfig,
}

impl BaseFeeCalculator {
    /// Create a new base fee calculator
    pub fn new(config: GasConfig) -> Self {
        Self { config }
    }

    /// Calculate the base fee for the next block
    ///
    /// Following EIP-1559:
    /// - If gas used > target, base fee increases
    /// - If gas used < target, base fee decreases
    /// - Change is limited to 1/BASE_FEE_CHANGE_DENOMINATOR per block
    pub fn calculate_next_base_fee(
        &self,
        parent_gas_used: u64,
        parent_gas_limit: u64,
        parent_base_fee: u128,
    ) -> u128 {
        // Target is 50% of limit (elasticity = 2)
        let target_gas = parent_gas_limit / self.config.elasticity_multiplier;

        if parent_gas_used == target_gas {
            // No change needed
            return parent_base_fee;
        }

        if parent_gas_used > target_gas {
            // Block was more than 50% full, increase base fee
            let gas_used_delta = parent_gas_used - target_gas;
            let base_fee_delta = std::cmp::max(
                parent_base_fee * gas_used_delta as u128
                    / target_gas as u128
                    / self.config.base_fee_change_denominator as u128,
                1, // Ensure at least 1 wei increase
            );

            let new_base_fee = parent_base_fee.saturating_add(base_fee_delta);
            std::cmp::min(new_base_fee, self.config.max_base_fee)
        } else {
            // Block was less than 50% full, decrease base fee
            let gas_used_delta = target_gas - parent_gas_used;
            let base_fee_delta = parent_base_fee * gas_used_delta as u128
                / target_gas as u128
                / self.config.base_fee_change_denominator as u128;

            let new_base_fee = parent_base_fee.saturating_sub(base_fee_delta);
            std::cmp::max(new_base_fee, self.config.min_base_fee)
        }
    }

    /// Calculate effective gas price for a transaction
    ///
    /// Returns the actual price paid = base_fee + min(max_priority_fee, max_fee - base_fee)
    pub fn effective_gas_price(
        &self,
        base_fee: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Option<u128> {
        if max_fee_per_gas < base_fee {
            return None;
        }

        let priority_fee = std::cmp::min(
            max_priority_fee_per_gas,
            max_fee_per_gas.saturating_sub(base_fee),
        );

        Some(base_fee + priority_fee)
    }

    /// Calculate the priority fee (tip to validator)
    pub fn priority_fee(
        &self,
        base_fee: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> u128 {
        std::cmp::min(
            max_priority_fee_per_gas,
            max_fee_per_gas.saturating_sub(base_fee),
        )
    }

    /// Validate that a transaction's gas parameters are acceptable
    pub fn validate_gas_params(
        &self,
        base_fee: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Result<(), GasValidationError> {
        // Max fee must cover base fee
        if max_fee_per_gas < base_fee {
            return Err(GasValidationError::MaxFeeBelowBaseFee {
                max_fee: max_fee_per_gas,
                base_fee,
            });
        }

        // Priority fee cannot exceed max fee
        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(GasValidationError::PriorityFeeExceedsMaxFee {
                priority_fee: max_priority_fee_per_gas,
                max_fee: max_fee_per_gas,
            });
        }

        // Max fee must meet minimum gas price
        if max_fee_per_gas < self.config.min_gas_price {
            return Err(GasValidationError::BelowMinimumGasPrice {
                provided: max_fee_per_gas,
                minimum: self.config.min_gas_price,
            });
        }

        Ok(())
    }

    /// Calculate maximum gas refund for a transaction
    pub fn max_refund(&self, gas_used: u64) -> u64 {
        gas_used / self.config.max_refund_quotient
    }
}

/// Errors in gas parameter validation
#[derive(Debug, thiserror::Error)]
pub enum GasValidationError {
    /// Max fee is below the current base fee
    #[error("max fee {max_fee} is below base fee {base_fee}")]
    MaxFeeBelowBaseFee {
        /// Provided max fee
        max_fee: u128,
        /// Current base fee
        base_fee: u128,
    },

    /// Priority fee exceeds max fee
    #[error("priority fee {priority_fee} exceeds max fee {max_fee}")]
    PriorityFeeExceedsMaxFee {
        /// Provided priority fee
        priority_fee: u128,
        /// Provided max fee
        max_fee: u128,
    },

    /// Fee is below minimum gas price
    #[error("gas price {provided} is below minimum {minimum}")]
    BelowMinimumGasPrice {
        /// Provided gas price
        provided: u128,
        /// Minimum required
        minimum: u128,
    },
}

/// Gas metering context during execution
#[derive(Debug, Clone)]
pub struct GasMeter {
    /// Gas limit for the transaction
    limit: u64,
    /// Gas used so far
    used: u64,
    /// Gas refunded
    refunded: u64,
    /// Memory size for expansion tracking
    memory_size: u64,
    /// Gas costs configuration
    costs: GasCosts,
}

impl GasMeter {
    /// Create a new gas meter with the given limit
    pub fn new(limit: u64, costs: GasCosts) -> Self {
        Self {
            limit,
            used: 0,
            refunded: 0,
            memory_size: 0,
            costs,
        }
    }

    /// Get remaining gas
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Get gas used
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Get gas refunded
    pub fn refunded(&self) -> u64 {
        self.refunded
    }

    /// Consume gas, returns false if out of gas
    pub fn consume(&mut self, amount: u64) -> bool {
        if self.used + amount > self.limit {
            return false;
        }
        self.used += amount;
        true
    }

    /// Add gas refund
    pub fn add_refund(&mut self, amount: u64) {
        self.refunded += amount;
    }

    /// Subtract from gas refund
    pub fn sub_refund(&mut self, amount: u64) {
        self.refunded = self.refunded.saturating_sub(amount);
    }

    /// Record memory expansion and charge gas if needed
    pub fn record_memory(&mut self, new_size: u64) -> bool {
        if new_size <= self.memory_size {
            return true;
        }

        let expansion_cost = self.costs.memory_expansion_cost(self.memory_size, new_size);
        if self.consume(expansion_cost) {
            self.memory_size = new_size;
            true
        } else {
            false
        }
    }

    /// Calculate final gas used after applying refunds
    pub fn final_gas_used(&self) -> u64 {
        let max_refund = self.used / 5; // Max 20% refund (EIP-3529)
        let actual_refund = std::cmp::min(self.refunded, max_refund);
        self.used.saturating_sub(actual_refund)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intrinsic_gas() {
        let costs = GasCosts::default();

        // Empty call transaction
        assert_eq!(costs.intrinsic_gas(&[], false, 0), 21000);

        // Contract creation
        assert!(costs.intrinsic_gas(&[], true, 0) > 21000);

        // Transaction with data
        let data = vec![0u8, 1u8, 0u8, 1u8];
        let gas = costs.intrinsic_gas(&data, false, 0);
        assert_eq!(gas, 21000 + 4 + 16 + 4 + 16); // base + 2 zeros + 2 non-zeros
    }

    #[test]
    fn test_base_fee_calculation() {
        let config = GasConfig::default();
        let calculator = BaseFeeCalculator::new(config);

        let parent_base_fee = 1_000_000_000u128; // 1 gwei
        let parent_gas_limit = 30_000_000u64;

        // At target (50% full), no change
        let target = parent_gas_limit / 2;
        let new_fee = calculator.calculate_next_base_fee(target, parent_gas_limit, parent_base_fee);
        assert_eq!(new_fee, parent_base_fee);

        // Above target, fee increases
        let above_target = (parent_gas_limit * 3) / 4;
        let new_fee =
            calculator.calculate_next_base_fee(above_target, parent_gas_limit, parent_base_fee);
        assert!(new_fee > parent_base_fee);

        // Below target, fee decreases
        let below_target = parent_gas_limit / 4;
        let new_fee =
            calculator.calculate_next_base_fee(below_target, parent_gas_limit, parent_base_fee);
        assert!(new_fee < parent_base_fee);
    }

    #[test]
    fn test_effective_gas_price() {
        let config = GasConfig::default();
        let calculator = BaseFeeCalculator::new(config);

        let base_fee = 10_000_000_000u128; // 10 gwei
        let max_fee = 20_000_000_000u128; // 20 gwei
        let priority_fee = 2_000_000_000u128; // 2 gwei

        let effective = calculator
            .effective_gas_price(base_fee, max_fee, priority_fee)
            .unwrap();
        assert_eq!(effective, 12_000_000_000); // base + priority

        // Max fee too low
        assert!(calculator
            .effective_gas_price(base_fee, 5_000_000_000, priority_fee)
            .is_none());
    }

    #[test]
    fn test_gas_meter() {
        let costs = GasCosts::default();
        let mut meter = GasMeter::new(100000, costs);

        assert_eq!(meter.remaining(), 100000);

        assert!(meter.consume(50000));
        assert_eq!(meter.remaining(), 50000);
        assert_eq!(meter.used(), 50000);

        meter.add_refund(10000);
        assert_eq!(meter.refunded(), 10000);

        // Max refund is 20% of used
        assert_eq!(meter.final_gas_used(), 40000); // 50000 - 10000 (capped at 10000 which is 20%)
    }

    #[test]
    fn test_gas_validation() {
        let config = GasConfig::default();
        let calculator = BaseFeeCalculator::new(config);

        let base_fee = 10_000_000_000u128;

        // Valid params
        assert!(calculator
            .validate_gas_params(base_fee, 20_000_000_000, 2_000_000_000)
            .is_ok());

        // Max fee below base fee
        assert!(calculator
            .validate_gas_params(base_fee, 5_000_000_000, 2_000_000_000)
            .is_err());

        // Priority fee exceeds max fee
        assert!(calculator
            .validate_gas_params(base_fee, 20_000_000_000, 25_000_000_000)
            .is_err());
    }

    #[test]
    fn test_memory_expansion_cost() {
        let costs = GasCosts::default();

        // No expansion
        assert_eq!(costs.memory_expansion_cost(100, 50), 0);

        // First expansion
        let cost = costs.memory_expansion_cost(0, 32);
        assert!(cost > 0);

        // Larger expansion costs more
        let cost1 = costs.memory_expansion_cost(0, 64);
        let cost2 = costs.memory_expansion_cost(0, 128);
        assert!(cost2 > cost1);
    }
}
