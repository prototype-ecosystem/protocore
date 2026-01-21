//! # Proto Core EVM
//!
//! EVM executor and precompiles for the Proto Core blockchain.
//!
//! This crate provides:
//! - [`EvmExecutor`] - Block and transaction execution engine wrapping revm
//! - [`GasCalculator`] - Gas metering with EIP-1559 support
//! - Precompiled contracts for staking, slashing, and governance
//!
//! ## Precompile Addresses
//!
//! Proto Core extends the standard Ethereum precompiles with system contracts:
//!
//! | Address | Precompile |
//! |---------|------------|
//! | 0x...1000 | Staking |
//! | 0x...1001 | Slashing |
//! | 0x...1002 | Governance |
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_evm::{EvmExecutor, EvmConfig};
//! use protocore_storage::StateDB;
//!
//! // Create executor with state database
//! let config = EvmConfig::mainnet();
//! let executor = EvmExecutor::new(state_db, config);
//!
//! // Execute a block
//! let result = executor.execute_block(&block)?;
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

// pub mod aa;  // Deferred to phase2/
pub mod executor;
pub mod gas;
// pub mod parallel;  // Deferred to phase2/
pub mod precompiles;
mod state_adapter;

// Re-export main types at crate root
pub use executor::{
    BlockContext, BlockExecutionResult, EvmConfig, EvmExecutor, ExecutionError, Log, Receipt,
    TransactionData, TransactionResult,
};
pub use gas::{BaseFeeCalculator, GasConfig, GasCosts};
pub use precompiles::{
    Precompile, PrecompileError, PrecompileOutput, PrecompileRegistry, GOVERNANCE_ADDRESS,
    SLASHING_ADDRESS, STAKING_ADDRESS,
};
pub use state_adapter::{MemoryDb, MemoryDbError, PendingAccountChanges, StateAdapter, StateRootProvider};

// Account abstraction deferred to phase2/
// pub use aa::{...};

/// Result type alias for EVM operations
pub type Result<T> = std::result::Result<T, ExecutionError>;

/// Chain ID for Proto Core mainnet
pub const MAINNET_CHAIN_ID: u64 = 123456;

/// Chain ID for Proto Core testnet
pub const TESTNET_CHAIN_ID: u64 = 123457;

/// Default block gas limit (30 million gas)
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Number of blocks per epoch
pub const BLOCKS_PER_EPOCH: u64 = 43200; // ~24 hours at 2s blocks

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_ids() {
        assert_eq!(MAINNET_CHAIN_ID, 123456);
        assert_eq!(TESTNET_CHAIN_ID, 123457);
    }

    #[test]
    fn test_default_gas_limit() {
        assert_eq!(DEFAULT_BLOCK_GAS_LIMIT, 30_000_000);
    }
}
