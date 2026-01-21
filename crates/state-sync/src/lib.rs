//! # Proto Core State Sync
//!
//! This crate provides state synchronization capabilities for the Proto Core blockchain,
//! enabling new nodes to join the network without replaying the full transaction history.
//!
//! ## Overview
//!
//! State sync allows nodes to download a verified snapshot of the blockchain state at a
//! finalized height, rather than processing every block from genesis. This dramatically
//! reduces the time required for new nodes to become operational.
//!
//! ## Key Components
//!
//! - **[`StateSyncManager`]**: Orchestrates the state sync process, managing peer discovery,
//!   snapshot selection, and chunk downloading.
//!
//! - **[`SnapshotMetadata`]**: Contains metadata about available snapshots including height,
//!   state root, and chunk information.
//!
//! - **[`StateChunk`]**: Represents a portion of the state trie that can be independently
//!   verified and applied.
//!
//! - **[`SnapshotProvider`]**: Serves state sync requests to other peers, creating and
//!   managing snapshots.
//!
//! ## Protocol Flow
//!
//! 1. **Discovery**: The syncing node requests available snapshots from connected peers.
//!
//! 2. **Selection**: The best snapshot is selected based on finality certification and
//!    availability across multiple peers.
//!
//! 3. **Download**: State chunks are downloaded in parallel from multiple peers, with
//!    each chunk independently verified against the snapshot's Merkle root.
//!
//! 4. **Application**: Verified chunks are applied to the local state database,
//!    reconstructing the full state trie.
//!
//! 5. **Verification**: Once all chunks are applied, the final state root is verified
//!    against the snapshot metadata.
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_state_sync::{StateSyncManager, StateSyncConfig};
//!
//! async fn sync_state() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = StateSyncConfig::default();
//!     let manager = StateSyncManager::new(config, storage, network)?;
//!
//!     // Start syncing from the best available snapshot
//!     manager.start_sync().await?;
//!
//!     // Wait for completion
//!     while !manager.is_complete() {
//!         let progress = manager.progress();
//!         println!("Sync progress: {:.2}%", progress.percentage());
//!         tokio::time::sleep(Duration::from_secs(1)).await;
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Chunk Verification
//!
//! Each chunk contains a range of trie nodes that can be independently verified:
//!
//! - Chunks include Merkle proofs linking them to the snapshot root
//! - Invalid chunks are rejected and re-requested from other peers
//! - Chunk boundaries are deterministic based on key ranges
//!
//! ## Resume Capability
//!
//! State sync supports resumption after interruption:
//!
//! - Downloaded chunks are persisted to disk
//! - Sync progress is tracked and can be restored
//! - Only missing chunks need to be re-downloaded

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod chunks;
pub mod multi_peer;
pub mod provider;
pub mod snapshot;
pub mod sync;

// Re-export main types at crate root
pub use chunks::{
    ChunkDownloader, ChunkId, ChunkRequest, ChunkResponse, ChunkVerifier, StateChunk,
};
pub use multi_peer::{
    ChunkAssigner, ChunkProgress, DownloadPipeline, DownloadRequest, DownloadResult,
    MultiPeerConfig, PeerMetrics, PeerScorer, PeerScorerStats,
};
pub use provider::{SnapshotProvider, SnapshotProviderConfig};
pub use snapshot::{
    FinalityCertificate, SnapshotInfo, SnapshotList, SnapshotMetadata, SnapshotRequest,
    SnapshotStatus,
};
pub use sync::{
    StateSyncConfig, StateSyncError, StateSyncManager, SyncPhase, SyncProgress, SyncStatus,
};

use sha3::{Digest, Keccak256};

/// A 32-byte hash type used throughout the state sync layer
pub type Hash = [u8; 32];

/// A 20-byte address type
pub type Address = [u8; 20];

/// Peer identifier type
pub type PeerId = [u8; 32];

/// Result type for state sync operations
pub type Result<T> = std::result::Result<T, StateSyncError>;

/// Default chunk size in bytes (4 MB)
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum concurrent chunk downloads
pub const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 16;

/// Default snapshot interval in blocks
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 4096;

/// Maximum number of snapshots to retain
pub const DEFAULT_MAX_SNAPSHOTS: usize = 5;

/// Request timeout in seconds
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Maximum retry attempts for chunk download
pub const DEFAULT_MAX_RETRIES: u32 = 3;

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

/// Convert a hash to hex string
pub fn hash_to_hex(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Parse a hex string to hash
pub fn hex_to_hash(s: &str) -> std::result::Result<Hash, hex::FromHexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
