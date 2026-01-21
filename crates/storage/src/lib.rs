//! Proto Core Storage Layer
//!
//! This crate provides the storage infrastructure for the Proto Core blockchain:
//!
//! - **Database**: RocksDB wrapper with column families for blocks, transactions, state, receipts, consensus, and metadata
//! - **Merkle Patricia Trie**: Cryptographic data structure for state verification
//! - **State Management**: Account and storage slot management with commit/revert capabilities
//! - **Snapshots**: State snapshots for fast sync protocol
//! - **State Rent**: Rent-based storage pricing to prevent state bloat
//! - **Hibernation**: Account archival and restoration for dormant accounts

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod db;
// pub mod hibernation;  // Deferred to phase2/ (depends on rent)
pub mod loyalty;
pub mod pruning;
// pub mod rent;  // Deferred to phase2/
pub mod snapshot;
pub mod state;
pub mod testnet_incentives;
pub mod trie;

// Re-exports for convenience
pub use db::{Database, DatabaseConfig, WriteBatch};
// Hibernation and Rent deferred to phase2/
// pub use hibernation::{...};
// pub use rent::{...};
pub use loyalty::{
    LoyaltyError, LoyaltySnapshot, LoyaltyStatus, LoyaltyTracker, ValidatorRegistration,
};
pub use pruning::{
    Checkpoint, PruningConfig, PruningManager, PruningStats, DEFAULT_BLOCKS_RETAINED,
    DEFAULT_CHECKPOINT_INTERVAL, MIN_BLOCKS_RETAINED,
};
pub use snapshot::{Snapshot, SnapshotChunk, SnapshotManager};
pub use state::{Account, StateDB, StateDiff};
pub use testnet_incentives::{
    ActivityType, AirdropExport, LeaderboardSnapshot, ParticipationEvent, TestnetIncentivesConfig,
    TestnetIncentivesTracker, TotalStats, UserStats,
};
pub use trie::{MerkleProof, MerkleTrie, TrieNode};

use sha3::{Digest, Keccak256};
use thiserror::Error;

/// A 32-byte hash type used throughout the storage layer
pub type Hash = [u8; 32];

/// A 20-byte address type
pub type Address = [u8; 20];

/// Empty hash constant (Keccak256 of empty string)
pub const EMPTY_HASH: Hash = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// Empty trie root (Keccak256 of RLP encoded empty string)
pub const EMPTY_ROOT: Hash = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Zero hash constant
pub const ZERO_HASH: Hash = [0u8; 32];

/// Zero address constant
pub const ZERO_ADDRESS: Address = [0u8; 20];

/// Storage error types
#[derive(Error, Debug)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Key not found
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Invalid state root
    #[error("Invalid state root")]
    InvalidStateRoot,

    /// Trie error
    #[error("Trie error: {0}")]
    Trie(String),

    /// Snapshot error
    #[error("Snapshot error: {0}")]
    Snapshot(String),

    /// Column family not found
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),

    /// Invalid proof
    #[error("Invalid proof")]
    InvalidProof,

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;

/// Compute Keccak256 hash of data
#[inline]
pub fn keccak256(data: &[u8]) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute Keccak256 hash of multiple data slices
#[inline]
pub fn keccak256_concat(data: &[&[u8]]) -> Hash {
    let mut hasher = Keccak256::new();
    for d in data {
        hasher.update(d);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_keccak256_concat() {
        let hash1 = keccak256(b"helloworld");
        let hash2 = keccak256_concat(&[b"hello", b"world"]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_empty_hash() {
        let computed = keccak256(&[]);
        assert_eq!(computed, EMPTY_HASH);
    }
}
