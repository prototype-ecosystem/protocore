//! Transaction validation for mempool acceptance.
//!
//! This module provides comprehensive transaction validation including:
//! - Signature verification
//! - Nonce checking
//! - Gas limit validation
//! - Balance verification
//! - Gas price requirements
//! - Transaction format validation

use std::sync::Arc;

use protocore_types::{Address, SignedTransaction};
use tracing::{debug, trace, warn};

/// Configuration for transaction validation
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Minimum gas price required (in wei)
    pub min_gas_price: u128,
    /// Maximum transaction size in bytes
    pub max_tx_size: usize,
    /// Block gas limit (transactions cannot exceed this)
    pub block_gas_limit: u64,
    /// Minimum gas limit for any transaction
    pub min_gas_limit: u64,
    /// Chain ID for replay protection
    pub chain_id: u64,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            min_gas_price: 1_000_000_000, // 1 gwei
            max_tx_size: 131_072,         // 128 KB
            block_gas_limit: 30_000_000,  // 30M gas
            min_gas_limit: 21_000,        // Basic transfer gas
            chain_id: 1,
        }
    }
}

/// Result of transaction validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the transaction is valid
    pub is_valid: bool,
    /// Recovered sender address
    pub sender: Address,
    /// Effective gas price for ordering
    pub effective_gas_price: u128,
    /// Transaction size in bytes
    pub tx_size: usize,
}

/// Errors that can occur during validation
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// Invalid signature - cannot recover sender
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Nonce is lower than expected (transaction may be stale)
    #[error("nonce too low: expected >= {expected}, got {actual}")]
    NonceTooLow {
        /// Expected minimum nonce
        expected: u64,
        /// Actual nonce in transaction
        actual: u64,
    },

    /// Nonce is too far in the future
    #[error("nonce too high: expected {expected}, got {actual}")]
    NonceTooHigh {
        /// Expected nonce
        expected: u64,
        /// Actual nonce in transaction
        actual: u64,
    },

    /// Gas limit exceeds block gas limit
    #[error("gas limit too high: max {max}, got {actual}")]
    GasLimitTooHigh {
        /// Maximum allowed gas
        max: u64,
        /// Actual gas limit in transaction
        actual: u64,
    },

    /// Gas limit too low for basic execution
    #[error("gas limit too low: min {min}, got {actual}")]
    GasLimitTooLow {
        /// Minimum required gas
        min: u64,
        /// Actual gas limit in transaction
        actual: u64,
    },

    /// Insufficient balance to pay for gas and value
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance {
        /// Required balance (gas * gas_price + value)
        required: u128,
        /// Available balance
        available: u128,
    },

    /// Gas price below minimum
    #[error("gas price too low: min {min} wei, got {actual} wei")]
    GasPriceTooLow {
        /// Minimum required gas price
        min: u128,
        /// Actual gas price
        actual: u128,
    },

    /// Transaction too large
    #[error("transaction too large: max {max} bytes, got {actual} bytes")]
    TransactionTooLarge {
        /// Maximum allowed size
        max: usize,
        /// Actual size
        actual: usize,
    },

    /// Invalid transaction format
    #[error("invalid transaction format: {0}")]
    InvalidFormat(String),

    /// Wrong chain ID
    #[error("wrong chain id: expected {expected}, got {actual}")]
    WrongChainId {
        /// Expected chain ID
        expected: u64,
        /// Actual chain ID
        actual: u64,
    },

    /// Invalid recipient address
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    /// Transaction intrinsic gas calculation failed
    #[error("intrinsic gas calculation failed: {0}")]
    IntrinsicGasError(String),
}

/// Account state provider for validation
///
/// This trait allows the validator to query account state (nonce and balance)
/// from the state database.
pub trait AccountStateProvider: Send + Sync {
    /// Get the current nonce for an address
    fn get_nonce(&self, address: &Address) -> u64;

    /// Get the current balance for an address
    fn get_balance(&self, address: &Address) -> u128;
}

/// Mock account state provider for testing
#[derive(Default)]
pub struct MockAccountState {
    nonces: parking_lot::RwLock<std::collections::HashMap<Address, u64>>,
    balances: parking_lot::RwLock<std::collections::HashMap<Address, u128>>,
}

impl MockAccountState {
    /// Create a new mock state provider
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the nonce for an address
    pub fn set_nonce(&self, address: Address, nonce: u64) {
        self.nonces.write().insert(address, nonce);
    }

    /// Set the balance for an address
    pub fn set_balance(&self, address: Address, balance: u128) {
        self.balances.write().insert(address, balance);
    }
}

impl AccountStateProvider for MockAccountState {
    fn get_nonce(&self, address: &Address) -> u64 {
        *self.nonces.read().get(address).unwrap_or(&0)
    }

    fn get_balance(&self, address: &Address) -> u128 {
        *self.balances.read().get(address).unwrap_or(&0)
    }
}

/// Transaction validator
///
/// Validates transactions before they are accepted into the mempool.
pub struct TransactionValidator<S: AccountStateProvider> {
    /// Validation configuration
    config: ValidationConfig,
    /// State provider for account lookups
    state: Arc<S>,
}

impl<S: AccountStateProvider> TransactionValidator<S> {
    /// Create a new transaction validator
    pub fn new(config: ValidationConfig, state: Arc<S>) -> Self {
        Self { config, state }
    }

    /// Validate a signed transaction
    ///
    /// Performs all validation checks:
    /// 1. Signature verification and sender recovery
    /// 2. Transaction size check
    /// 3. Gas limit validation
    /// 4. Gas price validation
    /// 5. Nonce validation
    /// 6. Balance validation
    /// 7. Format validation
    pub fn validate(&self, tx: &SignedTransaction) -> Result<ValidationResult, ValidationError> {
        trace!(tx_hash = ?tx.hash(), "validating transaction");

        // 1. Verify signature and recover sender
        let sender = self.validate_signature(tx)?;

        // 2. Calculate and check transaction size
        let tx_size = self.calculate_tx_size(tx);
        self.validate_tx_size(tx_size)?;

        // 3. Validate gas limit
        self.validate_gas_limit(tx)?;

        // 4. Validate gas price
        let effective_gas_price = self.validate_gas_price(tx)?;

        // 5. Validate nonce
        self.validate_nonce(tx, &sender)?;

        // 6. Validate balance
        self.validate_balance(tx, &sender)?;

        // 7. Validate transaction format
        self.validate_format(tx)?;

        debug!(
            tx_hash = ?tx.hash(),
            sender = ?sender,
            nonce = tx.nonce(),
            gas_price = effective_gas_price,
            "transaction validated successfully"
        );

        Ok(ValidationResult {
            is_valid: true,
            sender,
            effective_gas_price,
            tx_size,
        })
    }

    /// Validate only the intrinsic properties (no state access needed)
    ///
    /// This is useful for quick pre-validation before acquiring locks.
    pub fn validate_intrinsic(&self, tx: &SignedTransaction) -> Result<Address, ValidationError> {
        // Verify signature and recover sender
        let sender = self.validate_signature(tx)?;

        // Check transaction size
        let tx_size = self.calculate_tx_size(tx);
        self.validate_tx_size(tx_size)?;

        // Validate gas limit
        self.validate_gas_limit(tx)?;

        // Validate gas price
        self.validate_gas_price(tx)?;

        // Validate format
        self.validate_format(tx)?;

        Ok(sender)
    }

    /// Validate signature and recover sender address
    fn validate_signature(&self, tx: &SignedTransaction) -> Result<Address, ValidationError> {
        tx.sender()
            .map_err(|e| ValidationError::InvalidSignature(e.to_string()))
    }

    /// Calculate transaction size in bytes
    fn calculate_tx_size(&self, tx: &SignedTransaction) -> usize {
        tx.encoded_size()
    }

    /// Validate transaction size
    fn validate_tx_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.config.max_tx_size {
            warn!(
                size = size,
                max = self.config.max_tx_size,
                "transaction too large"
            );
            return Err(ValidationError::TransactionTooLarge {
                max: self.config.max_tx_size,
                actual: size,
            });
        }
        Ok(())
    }

    /// Validate gas limit
    fn validate_gas_limit(&self, tx: &SignedTransaction) -> Result<(), ValidationError> {
        let gas_limit = tx.gas_limit();

        // Check minimum gas
        if gas_limit < self.config.min_gas_limit {
            return Err(ValidationError::GasLimitTooLow {
                min: self.config.min_gas_limit,
                actual: gas_limit,
            });
        }

        // Check maximum gas (block gas limit)
        if gas_limit > self.config.block_gas_limit {
            return Err(ValidationError::GasLimitTooHigh {
                max: self.config.block_gas_limit,
                actual: gas_limit,
            });
        }

        // Calculate intrinsic gas
        let intrinsic_gas = self.calculate_intrinsic_gas(tx);
        if gas_limit < intrinsic_gas {
            return Err(ValidationError::IntrinsicGasError(format!(
                "gas limit {} is less than intrinsic gas {}",
                gas_limit, intrinsic_gas
            )));
        }

        Ok(())
    }

    /// Calculate intrinsic gas cost for a transaction
    fn calculate_intrinsic_gas(&self, tx: &SignedTransaction) -> u64 {
        // Base transaction cost
        let mut gas: u64 = 21_000;

        // Contract creation cost
        if tx.to().is_none() {
            gas += 32_000;
        }

        // Data cost: 4 gas per zero byte, 16 gas per non-zero byte
        let data = tx.data();
        for &byte in data {
            if byte == 0 {
                gas += 4;
            } else {
                gas += 16;
            }
        }

        // Access list cost (EIP-2930)
        let access_list = tx.access_list();
        for item in access_list {
            gas += 2_400; // Address cost
            gas += 1_900 * item.storage_keys.len() as u64; // Storage key cost
        }

        gas
    }

    /// Validate gas price meets minimum requirements
    fn validate_gas_price(&self, tx: &SignedTransaction) -> Result<u128, ValidationError> {
        let effective_gas_price = tx.effective_gas_price(None);

        if effective_gas_price < self.config.min_gas_price {
            return Err(ValidationError::GasPriceTooLow {
                min: self.config.min_gas_price,
                actual: effective_gas_price,
            });
        }

        Ok(effective_gas_price)
    }

    /// Validate transaction nonce
    fn validate_nonce(
        &self,
        tx: &SignedTransaction,
        sender: &Address,
    ) -> Result<(), ValidationError> {
        let account_nonce = self.state.get_nonce(sender);
        let tx_nonce = tx.nonce();

        // Nonce must be >= account nonce (we allow future nonces for queued pool)
        if tx_nonce < account_nonce {
            return Err(ValidationError::NonceTooLow {
                expected: account_nonce,
                actual: tx_nonce,
            });
        }

        // Prevent extremely high nonces (DoS protection)
        const MAX_NONCE_GAP: u64 = 64;
        if tx_nonce > account_nonce + MAX_NONCE_GAP {
            return Err(ValidationError::NonceTooHigh {
                expected: account_nonce,
                actual: tx_nonce,
            });
        }

        Ok(())
    }

    /// Validate sender has sufficient balance
    fn validate_balance(
        &self,
        tx: &SignedTransaction,
        sender: &Address,
    ) -> Result<(), ValidationError> {
        let balance = self.state.get_balance(sender);

        // Calculate required balance: gas_limit * max_fee_per_gas + value
        let max_fee = tx.max_fee_per_gas();
        let gas_limit = tx.gas_limit() as u128;
        let value = tx.value();

        // Use checked arithmetic to prevent overflow
        let gas_cost = gas_limit.checked_mul(max_fee).ok_or({
            ValidationError::InsufficientBalance {
                required: u128::MAX,
                available: balance,
            }
        })?;

        let required = gas_cost.checked_add(value).ok_or({
            ValidationError::InsufficientBalance {
                required: u128::MAX,
                available: balance,
            }
        })?;

        if balance < required {
            return Err(ValidationError::InsufficientBalance {
                required,
                available: balance,
            });
        }

        Ok(())
    }

    /// Validate transaction format
    fn validate_format(&self, tx: &SignedTransaction) -> Result<(), ValidationError> {
        // Check chain ID if present
        if let Some(chain_id) = tx.chain_id() {
            if chain_id != self.config.chain_id {
                return Err(ValidationError::WrongChainId {
                    expected: self.config.chain_id,
                    actual: chain_id,
                });
            }
        }

        // Validate recipient for non-contract-creation transactions
        // Contract creation has no recipient (None)
        // Regular transactions must have a valid recipient

        // Validate data field is not suspiciously large
        // (already covered by max_tx_size but good to have explicit check)

        Ok(())
    }

    /// Get the current nonce for an address from state
    pub fn get_account_nonce(&self, address: &Address) -> u64 {
        self.state.get_nonce(address)
    }

    /// Get the current balance for an address from state
    pub fn get_account_balance(&self, address: &Address) -> u128 {
        self.state.get_balance(address)
    }
}
