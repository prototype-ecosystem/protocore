//! # Proto Core Types
//!
//! Core type definitions for the Proto Core blockchain.
//!
//! This crate provides the fundamental types used throughout Proto Core:
//! - [`Address`] - Ethereum-compatible 20-byte addresses
//! - [`H256`] - 32-byte hashes with Keccak256 support
//! - [`Transaction`] - EIP-1559 compatible transactions
//! - [`Block`] and [`BlockHeader`] - Block structures
//!
//! ## Example
//!
//! ```rust
//! use protocore_types::{Address, H256, Transaction, Block};
//!
//! // Create an address from hex
//! let addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".parse().unwrap();
//!
//! // Create a hash
//! let hash = H256::keccak256(b"hello world");
//!
//! // Check the nil hash constant
//! assert_ne!(hash, H256::NIL);
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod address;
pub mod block;
pub mod hash;
pub mod transaction;

// Re-export main types at crate root
pub use address::Address;
pub use block::{Block, BlockHeader};
pub use hash::H256;
pub use transaction::{Signature, SignedTransaction, Transaction, TxType};

/// Result type alias for Proto Core types operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when working with Proto Core types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid hex string
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Invalid length for a fixed-size type
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Invalid address format
    #[error("invalid address format: {0}")]
    InvalidAddress(String),

    /// Invalid hash format
    #[error("invalid hash format: {0}")]
    InvalidHash(String),

    /// Invalid transaction
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// RLP decoding error
    #[error("RLP decode error: {0}")]
    RlpDecode(#[from] rlp::DecoderError),

    /// Signature error
    #[error("signature error: {0}")]
    Signature(String),

    /// Cryptographic error
    #[error("crypto error: {0}")]
    Crypto(String),
}
