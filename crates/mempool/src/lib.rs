//! # Proto Core Mempool
//!
//! Transaction mempool implementation for the Proto Core blockchain.
//!
//! This crate provides a high-performance transaction pool that:
//! - Validates transactions before acceptance
//! - Organizes transactions by gas price for efficient block building
//! - Handles nonce gaps and future transactions (queued pool)
//! - Implements eviction policies when the pool is full
//! - Supports TTL-based expiration of stale transactions
//! - Handles chain reorgs by re-adding transactions from reverted blocks
//!
//! ## Architecture
//!
//! The mempool maintains two pools:
//! - **Pending pool**: Transactions ready for immediate inclusion in blocks
//! - **Queued pool**: Transactions with future nonces waiting for gaps to be filled
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_mempool::{Mempool, MempoolConfig, TransactionValidator};
//!
//! // Create mempool with default configuration
//! let config = MempoolConfig::default();
//! let mempool = Mempool::new(config);
//!
//! // Add a transaction
//! mempool.add_transaction(signed_tx).await?;
//!
//! // Get pending transactions for block building
//! let txs = mempool.get_pending_transactions(30_000_000);
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod pool;
pub mod validation;

// Re-export main types at crate root
pub use pool::{Mempool, MempoolConfig, PendingTransaction, TransactionStatus};
pub use validation::{
    AccountStateProvider, MockAccountState, TransactionValidator, ValidationConfig,
    ValidationError, ValidationResult,
};

/// Result type alias for mempool operations
pub type Result<T> = std::result::Result<T, MempoolError>;

/// Errors that can occur in mempool operations
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Transaction already exists in the pool
    #[error("transaction already exists in pool")]
    AlreadyExists,

    /// Transaction validation failed
    #[error("validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),

    /// Pool is at capacity and cannot accept more transactions
    #[error("mempool is full")]
    PoolFull,

    /// Transaction nonce is too low (already confirmed or pending)
    #[error("nonce too low: expected at least {expected}, got {actual}")]
    NonceTooLow {
        /// Expected minimum nonce
        expected: u64,
        /// Actual nonce provided
        actual: u64,
    },

    /// Transaction not found in pool
    #[error("transaction not found: {0}")]
    NotFound(String),

    /// Transaction has expired (TTL exceeded)
    #[error("transaction expired")]
    Expired,

    /// Replacement transaction gas price too low
    #[error("replacement transaction underpriced: minimum {minimum} gwei, got {provided} gwei")]
    ReplacementUnderpriced {
        /// Minimum required gas price
        minimum: u128,
        /// Provided gas price
        provided: u128,
    },

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}
