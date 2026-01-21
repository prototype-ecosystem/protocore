//! Snapshot Protocol
//!
//! This module defines the snapshot metadata structures and protocol messages
//! for state synchronization. Snapshots represent a verified checkpoint of
//! the blockchain state at a finalized height.
//!
//! ## Snapshot Structure
//!
//! A snapshot consists of:
//! - Metadata describing the snapshot (height, state root, chunk info)
//! - A finality certificate proving the snapshot is on the canonical chain
//! - A set of chunks containing the actual state data
//!
//! ## Protocol Messages
//!
//! - `SnapshotRequest`: Request available snapshots from peers
//! - `SnapshotList`: Response containing available snapshot metadata

use crate::{keccak256_concat, Hash, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Metadata describing a state snapshot.
///
/// Contains all information needed to verify and download a snapshot,
/// including cryptographic commitments to the state and chunk structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height at which the snapshot was taken
    pub height: u64,

    /// State root hash (Merkle root of the state trie)
    pub state_root: Hash,

    /// Block hash at this height
    pub block_hash: Hash,

    /// Total number of chunks in this snapshot
    pub chunk_count: u64,

    /// Size of each chunk in bytes (except possibly the last)
    pub chunk_size: u64,

    /// Total size of the snapshot in bytes
    pub total_size: u64,

    /// Hash of each chunk for verification
    pub chunk_hashes: Vec<Hash>,

    /// Merkle root of chunk hashes for efficient verification
    pub chunks_root: Hash,

    /// Timestamp when the snapshot was created
    pub created_at: u64,

    /// Version of the snapshot format
    pub version: u32,
}

impl SnapshotMetadata {
    /// Current snapshot format version
    pub const CURRENT_VERSION: u32 = 1;

    /// Create new snapshot metadata
    pub fn new(
        height: u64,
        state_root: Hash,
        block_hash: Hash,
        chunk_size: u64,
        chunk_hashes: Vec<Hash>,
        total_size: u64,
    ) -> Self {
        let chunk_count = chunk_hashes.len() as u64;
        let chunks_root = Self::compute_chunks_root(&chunk_hashes);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Self {
            height,
            state_root,
            block_hash,
            chunk_count,
            chunk_size,
            total_size,
            chunk_hashes,
            chunks_root,
            created_at,
            version: Self::CURRENT_VERSION,
        }
    }

    /// Compute the Merkle root of chunk hashes
    pub fn compute_chunks_root(chunk_hashes: &[Hash]) -> Hash {
        if chunk_hashes.is_empty() {
            return [0u8; 32];
        }

        if chunk_hashes.len() == 1 {
            return chunk_hashes[0];
        }

        // Build Merkle tree from leaves
        let mut current_level: Vec<Hash> = chunk_hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for pair in current_level.chunks(2) {
                if pair.len() == 2 {
                    next_level.push(keccak256_concat(&[&pair[0], &pair[1]]));
                } else {
                    // Odd number of elements, promote the last one
                    next_level.push(pair[0]);
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Verify that a chunk hash is valid for this snapshot
    pub fn verify_chunk_hash(&self, chunk_index: u64, chunk_hash: &Hash) -> bool {
        if chunk_index >= self.chunk_count {
            return false;
        }

        self.chunk_hashes
            .get(chunk_index as usize)
            .map(|h| h == chunk_hash)
            .unwrap_or(false)
    }

    /// Get the hash of a specific chunk
    pub fn get_chunk_hash(&self, chunk_index: u64) -> Option<&Hash> {
        self.chunk_hashes.get(chunk_index as usize)
    }

    /// Compute a unique identifier for this snapshot
    pub fn snapshot_id(&self) -> Hash {
        keccak256_concat(&[
            &self.height.to_le_bytes(),
            &self.state_root,
            &self.block_hash,
        ])
    }

    /// Check if the snapshot metadata is valid
    pub fn validate(&self) -> Result<(), SnapshotValidationError> {
        // Check version
        if self.version > Self::CURRENT_VERSION {
            return Err(SnapshotValidationError::UnsupportedVersion(self.version));
        }

        // Check chunk count matches hashes
        if self.chunk_count != self.chunk_hashes.len() as u64 {
            return Err(SnapshotValidationError::ChunkCountMismatch {
                expected: self.chunk_count,
                actual: self.chunk_hashes.len() as u64,
            });
        }

        // Verify chunks root
        let computed_root = Self::compute_chunks_root(&self.chunk_hashes);
        if computed_root != self.chunks_root {
            return Err(SnapshotValidationError::InvalidChunksRoot);
        }

        // Check for empty snapshot
        if self.chunk_count == 0 && self.total_size > 0 {
            return Err(SnapshotValidationError::InvalidSize);
        }

        Ok(())
    }

    /// Estimate download time based on bandwidth
    pub fn estimate_download_time(&self, bandwidth_bytes_per_sec: u64) -> Duration {
        if bandwidth_bytes_per_sec == 0 {
            return Duration::MAX;
        }
        Duration::from_secs(self.total_size / bandwidth_bytes_per_sec)
    }
}

/// Errors that can occur during snapshot validation
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotValidationError {
    /// Snapshot version is not supported
    #[error("unsupported snapshot version: {0}")]
    UnsupportedVersion(u32),

    /// Chunk count doesn't match the number of chunk hashes
    #[error("chunk count mismatch: expected {expected}, got {actual}")]
    ChunkCountMismatch {
        /// Expected count
        expected: u64,
        /// Actual count
        actual: u64,
    },

    /// Computed chunks root doesn't match
    #[error("invalid chunks root")]
    InvalidChunksRoot,

    /// Invalid snapshot size
    #[error("invalid snapshot size")]
    InvalidSize,
}

/// Finality certificate proving a snapshot is on the canonical chain.
///
/// This certificate contains signatures from validators attesting that
/// the block at the snapshot height has been finalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// Block height this certificate attests to
    pub height: u64,

    /// Block hash being certified
    pub block_hash: Hash,

    /// State root at this block
    pub state_root: Hash,

    /// Epoch number when finality was achieved
    pub epoch: u64,

    /// Round number in the consensus protocol
    pub round: u64,

    /// Aggregated signature from validators
    pub aggregated_signature: Vec<u8>,

    /// Bitmap indicating which validators signed
    pub signer_bitmap: Vec<u8>,

    /// Total voting power of signers
    pub signed_weight: u64,

    /// Total voting power in the validator set
    pub total_weight: u64,
}

impl FinalityCertificate {
    /// Minimum percentage of voting power required for finality (2/3)
    pub const FINALITY_THRESHOLD_PERCENT: u64 = 67;

    /// Create a new finality certificate
    pub fn new(
        height: u64,
        block_hash: Hash,
        state_root: Hash,
        epoch: u64,
        round: u64,
        aggregated_signature: Vec<u8>,
        signer_bitmap: Vec<u8>,
        signed_weight: u64,
        total_weight: u64,
    ) -> Self {
        Self {
            height,
            block_hash,
            state_root,
            epoch,
            round,
            aggregated_signature,
            signer_bitmap,
            signed_weight,
            total_weight,
        }
    }

    /// Check if the certificate has sufficient voting power
    pub fn has_quorum(&self) -> bool {
        if self.total_weight == 0 {
            return false;
        }
        (self.signed_weight * 100) / self.total_weight >= Self::FINALITY_THRESHOLD_PERCENT
    }

    /// Compute the message that was signed
    pub fn signing_message(&self) -> Hash {
        keccak256_concat(&[
            &self.height.to_le_bytes(),
            &self.block_hash,
            &self.state_root,
            &self.epoch.to_le_bytes(),
            &self.round.to_le_bytes(),
        ])
    }

    /// Verify the certificate matches the snapshot metadata
    pub fn verify_for_snapshot(&self, metadata: &SnapshotMetadata) -> bool {
        self.height == metadata.height
            && self.block_hash == metadata.block_hash
            && self.state_root == metadata.state_root
    }
}

/// Current status of a snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotStatus {
    /// Snapshot is being created
    Creating,

    /// Snapshot is complete and available
    Available,

    /// Snapshot is being served to peers
    Serving,

    /// Snapshot has been superseded by a newer one
    Archived,

    /// Snapshot is being deleted
    Deleting,
}

impl std::fmt::Display for SnapshotStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "creating"),
            Self::Available => write!(f, "available"),
            Self::Serving => write!(f, "serving"),
            Self::Archived => write!(f, "archived"),
            Self::Deleting => write!(f, "deleting"),
        }
    }
}

/// Extended snapshot information including availability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,

    /// Finality certificate (optional for local snapshots)
    pub finality_cert: Option<FinalityCertificate>,

    /// Current status
    pub status: SnapshotStatus,

    /// Peers that have this snapshot available
    pub available_peers: Vec<PeerId>,

    /// Number of times this snapshot has been served
    pub serve_count: u64,

    /// Local path to snapshot data (if available locally)
    pub local_path: Option<String>,
}

impl SnapshotInfo {
    /// Create new snapshot info
    pub fn new(metadata: SnapshotMetadata, finality_cert: Option<FinalityCertificate>) -> Self {
        Self {
            metadata,
            finality_cert,
            status: SnapshotStatus::Available,
            available_peers: Vec::new(),
            serve_count: 0,
            local_path: None,
        }
    }

    /// Check if the snapshot is verified with a finality certificate
    pub fn is_verified(&self) -> bool {
        self.finality_cert
            .as_ref()
            .map(|cert| cert.has_quorum() && cert.verify_for_snapshot(&self.metadata))
            .unwrap_or(false)
    }

    /// Add a peer that has this snapshot
    pub fn add_peer(&mut self, peer_id: PeerId) {
        if !self.available_peers.contains(&peer_id) {
            self.available_peers.push(peer_id);
        }
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.available_peers.retain(|p| p != peer_id);
    }

    /// Get the number of available peers
    pub fn peer_count(&self) -> usize {
        self.available_peers.len()
    }

    /// Check if snapshot is available from any peer
    pub fn is_available(&self) -> bool {
        !self.available_peers.is_empty() || self.local_path.is_some()
    }
}

/// Request for available snapshots from a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Minimum height for snapshots (0 for any)
    pub min_height: u64,

    /// Maximum height for snapshots (u64::MAX for any)
    pub max_height: u64,

    /// Maximum number of snapshots to return
    pub max_results: u32,

    /// Whether to include finality certificates
    pub include_finality_cert: bool,

    /// Request ID for correlation
    pub request_id: u64,
}

impl SnapshotRequest {
    /// Create a new snapshot request
    pub fn new(min_height: u64, max_height: u64) -> Self {
        Self {
            min_height,
            max_height,
            max_results: 10,
            include_finality_cert: true,
            request_id: rand_request_id(),
        }
    }

    /// Request all available snapshots
    pub fn all() -> Self {
        Self::new(0, u64::MAX)
    }

    /// Request snapshots at or above a minimum height
    pub fn from_height(min_height: u64) -> Self {
        Self::new(min_height, u64::MAX)
    }

    /// Set maximum results
    pub fn with_max_results(mut self, max: u32) -> Self {
        self.max_results = max;
        self
    }

    /// Set whether to include finality certificates
    pub fn with_finality_cert(mut self, include: bool) -> Self {
        self.include_finality_cert = include;
        self
    }
}

/// Response containing a list of available snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotList {
    /// Available snapshots
    pub snapshots: Vec<SnapshotListEntry>,

    /// Request ID this is responding to
    pub request_id: u64,

    /// Whether the list is truncated
    pub truncated: bool,

    /// Peer's current block height
    pub peer_height: u64,
}

impl SnapshotList {
    /// Create a new snapshot list
    pub fn new(snapshots: Vec<SnapshotListEntry>, request_id: u64, peer_height: u64) -> Self {
        Self {
            snapshots,
            request_id,
            truncated: false,
            peer_height,
        }
    }

    /// Get the most recent snapshot
    pub fn most_recent(&self) -> Option<&SnapshotListEntry> {
        self.snapshots.iter().max_by_key(|s| s.metadata.height)
    }

    /// Get snapshots sorted by height (descending)
    pub fn sorted_by_height(&self) -> Vec<&SnapshotListEntry> {
        let mut sorted: Vec<_> = self.snapshots.iter().collect();
        sorted.sort_by(|a, b| b.metadata.height.cmp(&a.metadata.height));
        sorted
    }

    /// Filter to only verified snapshots
    pub fn verified_only(&self) -> Vec<&SnapshotListEntry> {
        self.snapshots
            .iter()
            .filter(|s| {
                s.finality_cert
                    .as_ref()
                    .map(|c| c.has_quorum())
                    .unwrap_or(false)
            })
            .collect()
    }
}

/// Entry in a snapshot list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotListEntry {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,

    /// Finality certificate (if requested and available)
    pub finality_cert: Option<FinalityCertificate>,
}

impl SnapshotListEntry {
    /// Create a new entry
    pub fn new(metadata: SnapshotMetadata, finality_cert: Option<FinalityCertificate>) -> Self {
        Self {
            metadata,
            finality_cert,
        }
    }
}

/// Snapshot selection criteria
#[derive(Debug, Clone)]
pub struct SnapshotSelector {
    /// Minimum required peers having the snapshot
    pub min_peers: usize,

    /// Whether to require finality certificate
    pub require_finality: bool,

    /// Prefer snapshots closer to this height
    pub target_height: Option<u64>,

    /// Maximum age of snapshot in blocks
    pub max_age_blocks: Option<u64>,

    /// Current chain height for age calculation
    pub current_height: u64,
}

impl SnapshotSelector {
    /// Create a new selector with default settings
    pub fn new(current_height: u64) -> Self {
        Self {
            min_peers: 1,
            require_finality: true,
            target_height: None,
            max_age_blocks: None,
            current_height,
        }
    }

    /// Set minimum peer requirement
    pub fn with_min_peers(mut self, min: usize) -> Self {
        self.min_peers = min;
        self
    }

    /// Set finality requirement
    pub fn with_finality(mut self, required: bool) -> Self {
        self.require_finality = required;
        self
    }

    /// Set target height
    pub fn with_target_height(mut self, height: u64) -> Self {
        self.target_height = Some(height);
        self
    }

    /// Set maximum age
    pub fn with_max_age(mut self, max_age: u64) -> Self {
        self.max_age_blocks = Some(max_age);
        self
    }

    /// Select the best snapshot from available options
    pub fn select_best<'a>(&self, snapshots: &'a [SnapshotInfo]) -> Option<&'a SnapshotInfo> {
        let candidates: Vec<_> = snapshots.iter().filter(|s| self.is_candidate(s)).collect();

        if candidates.is_empty() {
            return None;
        }

        // Score and sort candidates
        let mut scored: Vec<_> = candidates.into_iter().map(|s| (self.score(s), s)).collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored.first().map(|(_, s)| *s)
    }

    /// Check if a snapshot is a valid candidate
    fn is_candidate(&self, snapshot: &SnapshotInfo) -> bool {
        // Check peer availability
        if snapshot.peer_count() < self.min_peers && snapshot.local_path.is_none() {
            return false;
        }

        // Check finality
        if self.require_finality && !snapshot.is_verified() {
            return false;
        }

        // Check age
        if let Some(max_age) = self.max_age_blocks {
            if self.current_height.saturating_sub(snapshot.metadata.height) > max_age {
                return false;
            }
        }

        // Check status
        matches!(
            snapshot.status,
            SnapshotStatus::Available | SnapshotStatus::Serving
        )
    }

    /// Score a snapshot (higher is better)
    fn score(&self, snapshot: &SnapshotInfo) -> f64 {
        let mut score = 0.0;

        // Height score: prefer more recent snapshots
        score += snapshot.metadata.height as f64 * 0.001;

        // Target height bonus
        if let Some(target) = self.target_height {
            let distance = (snapshot.metadata.height as i64 - target as i64).unsigned_abs();
            score -= distance as f64 * 0.01;
        }

        // Peer availability bonus
        score += snapshot.peer_count() as f64 * 10.0;

        // Finality bonus
        if snapshot.is_verified() {
            score += 100.0;
        }

        // Size penalty (prefer smaller snapshots for faster sync)
        score -= snapshot.metadata.total_size as f64 * 0.0000001;

        score
    }
}

/// Aggregated snapshot availability from multiple peers
#[derive(Debug, Clone)]
pub struct SnapshotAvailability {
    /// Snapshots indexed by their ID
    pub snapshots: HashMap<Hash, SnapshotInfo>,

    /// Mapping from height to snapshot IDs at that height
    pub by_height: HashMap<u64, Vec<Hash>>,
}

impl Default for SnapshotAvailability {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotAvailability {
    /// Create new empty availability tracker
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            by_height: HashMap::new(),
        }
    }

    /// Add a snapshot from a peer
    pub fn add_snapshot(&mut self, entry: SnapshotListEntry, peer_id: PeerId) {
        let snapshot_id = entry.metadata.snapshot_id();

        // Get or create snapshot info
        let info = self.snapshots.entry(snapshot_id).or_insert_with(|| {
            // Track by height
            self.by_height
                .entry(entry.metadata.height)
                .or_default()
                .push(snapshot_id);

            SnapshotInfo::new(entry.metadata.clone(), entry.finality_cert.clone())
        });

        // Add peer
        info.add_peer(peer_id);

        // Update finality cert if we got a better one
        if entry.finality_cert.is_some() && info.finality_cert.is_none() {
            info.finality_cert = entry.finality_cert;
        }
    }

    /// Remove a peer from all snapshots
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        for info in self.snapshots.values_mut() {
            info.remove_peer(peer_id);
        }
    }

    /// Get all snapshots as a vector
    pub fn all_snapshots(&self) -> Vec<&SnapshotInfo> {
        self.snapshots.values().collect()
    }

    /// Get snapshots at a specific height
    pub fn at_height(&self, height: u64) -> Vec<&SnapshotInfo> {
        self.by_height
            .get(&height)
            .map(|ids| ids.iter().filter_map(|id| self.snapshots.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get the most recent snapshot
    pub fn most_recent(&self) -> Option<&SnapshotInfo> {
        self.by_height
            .keys()
            .max()
            .and_then(|height| self.at_height(*height).into_iter().next())
    }

    /// Clear all snapshots
    pub fn clear(&mut self) {
        self.snapshots.clear();
        self.by_height.clear();
    }
}

/// Generate a random request ID
fn rand_request_id() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64,
    );
    hasher.finish()
}
