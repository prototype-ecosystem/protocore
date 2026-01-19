//! # Proto Core Light Client
//!
//! A light client implementation for the Proto Core blockchain that enables
//! verification of on-chain data with minimal trust assumptions.
//!
//! ## Overview
//!
//! The light client maintains only block headers (not full blocks) and can verify:
//! - Block finality through BFT finality certificates
//! - Account state via Merkle proofs against state_root
//! - Transaction inclusion via proofs against transactions_root
//! - Receipt/log inclusion via proofs against receipts_root
//! - Storage slot values via nested Merkle proofs
//!
//! ## Security Model
//!
//! The light client trusts:
//! - An initial trusted checkpoint (genesis or a known finalized block)
//! - The BFT consensus mechanism (>2/3 stake required for finality)
//!
//! It does NOT trust:
//! - Any individual peer or data provider
//! - Block producers or validators individually
//!
//! ## Architecture
//!
//! ```text
//! +-------------------+
//! |   LightClient     |  Main client interface
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |   HeaderChain     |  Stores verified headers
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |  ValidatorTracker |  Tracks validator set per epoch
//! +-------------------+
//!          |
//!          v
//! +-------------------+
//! |   ProofVerifier   |  Merkle proof verification
//! +-------------------+
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use protocore_light_client::{LightClient, LightClientConfig, Checkpoint};
//!
//! // Create light client from a trusted checkpoint
//! let config = LightClientConfig::default();
//! let checkpoint = Checkpoint::genesis(genesis_header, initial_validators);
//! let client = LightClient::new(config, checkpoint)?;
//!
//! // Sync headers from peers
//! client.sync_headers(&peer_headers).await?;
//!
//! // Verify account state
//! let proof = fetch_state_proof(address, block_hash).await?;
//! let account = client.verify_account_proof(&proof)?;
//!
//! // Verify transaction inclusion
//! let tx_proof = fetch_tx_proof(tx_hash, block_hash).await?;
//! let is_included = client.verify_transaction_proof(&tx_proof)?;
//! ```
//!
//! ## Modules
//!
//! - [`client`] - Main light client implementation
//! - [`proofs`] - Merkle proof verification for state, transactions, and receipts
//! - [`sync`] - Header synchronization and chain management

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod client;
pub mod proofs;
pub mod sync;

// Re-export main types at crate root
pub use client::{
    Checkpoint, HeaderChain, LightClient, LightClientConfig, ValidatorInfo, ValidatorSet,
    ValidatorTracker,
};
pub use proofs::{
    AccountProof, MerkleProof, ProofResult, ProofVerifier, ReceiptProof, StorageProof,
    TransactionProof,
};
pub use sync::{HeaderSync, SyncConfig, SyncError, SyncManager, SyncState, SyncStatus};

/// Result type alias for light client operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in light client operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid finality certificate
    #[error("invalid finality certificate: {0}")]
    InvalidFinalityCert(String),

    /// Insufficient stake in finality certificate
    #[error("insufficient stake: got {got}, required {required}")]
    InsufficientStake {
        /// Stake present in certificate
        got: u64,
        /// Minimum required stake (>2/3 of total)
        required: u64,
    },

    /// Invalid signature in finality certificate
    #[error("invalid signature from validator {validator}")]
    InvalidSignature {
        /// Validator that provided invalid signature
        validator: String,
    },

    /// Block hash mismatch
    #[error("block hash mismatch: expected {expected}, got {got}")]
    BlockHashMismatch {
        /// Expected hash
        expected: String,
        /// Actual hash
        got: String,
    },

    /// State root mismatch
    #[error("state root mismatch: expected {expected}, got {got}")]
    StateRootMismatch {
        /// Expected state root
        expected: String,
        /// Actual state root
        got: String,
    },

    /// Invalid Merkle proof
    #[error("invalid Merkle proof: {0}")]
    InvalidProof(String),

    /// Proof verification failed
    #[error("proof verification failed: computed root {computed} != expected {expected}")]
    ProofVerificationFailed {
        /// Computed root from proof
        computed: String,
        /// Expected root
        expected: String,
    },

    /// Unknown validator
    #[error("unknown validator: {0}")]
    UnknownValidator(String),

    /// Header not found
    #[error("header not found: {0}")]
    HeaderNotFound(String),

    /// Invalid header chain
    #[error("invalid header chain: {0}")]
    InvalidHeaderChain(String),

    /// Gap in header chain
    #[error("gap in header chain: missing block {0}")]
    HeaderChainGap(u64),

    /// Epoch boundary error
    #[error("epoch boundary error: {0}")]
    EpochBoundaryError(String),

    /// Sync error
    #[error("sync error: {0}")]
    SyncError(String),

    /// Invalid checkpoint
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),

    /// Reorg detected (should not happen in BFT)
    #[error("reorg detected at height {height}: expected {expected}, got {got}")]
    ReorgDetected {
        /// Height where reorg was detected
        height: u64,
        /// Expected block hash
        expected: String,
        /// Conflicting block hash
        got: String,
    },

    /// Stale data
    #[error("stale data: block {block_height} is older than finalized {finalized_height}")]
    StaleData {
        /// Height of the provided data
        block_height: u64,
        /// Current finalized height
        finalized_height: u64,
    },

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Network error (for sync operations)
    #[error("network error: {0}")]
    NetworkError(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Internal(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::SerializationError(e.to_string())
    }
}

/// Common type aliases used throughout the crate
pub mod types {
    /// 32-byte hash type
    pub type Hash = [u8; 32];

    /// 20-byte address type
    pub type Address = [u8; 20];

    /// Block height
    pub type BlockHeight = u64;

    /// Epoch number
    pub type Epoch = u64;

    /// Stake amount (in smallest unit)
    pub type Stake = u64;
}

/// Constants used in the light client
pub mod constants {
    /// Minimum stake ratio for finality (2/3)
    pub const FINALITY_THRESHOLD_NUMERATOR: u64 = 2;
    /// Finality threshold denominator
    pub const FINALITY_THRESHOLD_DENOMINATOR: u64 = 3;

    /// Default epoch length in blocks
    pub const DEFAULT_EPOCH_LENGTH: u64 = 1000;

    /// Maximum headers to sync in a single batch
    pub const MAX_HEADERS_PER_SYNC: usize = 100;

    /// Empty hash constant (Keccak256 of empty input)
    pub const EMPTY_HASH: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    /// Empty trie root (root of empty Merkle Patricia Trie)
    pub const EMPTY_TRIE_ROOT: [u8; 32] = [
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ];
}

