//! Snapshot Provider
//!
//! This module provides functionality for serving state sync to other peers:
//! - Creating snapshots at configurable intervals
//! - Serving chunk requests from syncing peers
//! - Managing snapshot storage and lifecycle
//! - Rate limiting and resource management
//!
//! ## Snapshot Creation
//!
//! Snapshots are created at finalized block heights, typically at regular intervals
//! (e.g., every 4096 blocks). Each snapshot captures the complete state trie and
//! divides it into verifiable chunks for efficient distribution.
//!
//! ## Chunk Serving
//!
//! The provider handles incoming chunk requests from peers performing state sync.
//! Requests are rate-limited and prioritized to ensure fair resource distribution.

use crate::{
    chunks::{ChunkProof, ChunkRequest, ChunkResponse, ProofNode, StateChunk},
    keccak256, keccak256_concat,
    snapshot::{
        FinalityCertificate, SnapshotInfo, SnapshotList, SnapshotListEntry, SnapshotMetadata,
        SnapshotRequest, SnapshotStatus,
    },
    Hash, PeerId, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_SNAPSHOTS, DEFAULT_SNAPSHOT_INTERVAL,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Configuration for the snapshot provider
#[derive(Debug, Clone)]
pub struct SnapshotProviderConfig {
    /// Directory for storing snapshots
    pub snapshot_dir: PathBuf,

    /// Interval between snapshots (in blocks)
    pub snapshot_interval: u64,

    /// Maximum number of snapshots to retain
    pub max_snapshots: usize,

    /// Target chunk size in bytes
    pub chunk_size: usize,

    /// Maximum concurrent snapshot creations
    pub max_concurrent_creations: usize,

    /// Maximum concurrent chunk serves
    pub max_concurrent_serves: usize,

    /// Rate limit: max requests per peer per second
    pub rate_limit_per_peer: u32,

    /// Rate limit: max total requests per second
    pub rate_limit_total: u32,

    /// Whether to enable compression
    pub enable_compression: bool,

    /// Compression level (1-9)
    pub compression_level: u32,

    /// Whether to automatically create snapshots
    pub auto_create: bool,

    /// Minimum block height for snapshot creation
    pub min_snapshot_height: u64,
}

impl Default for SnapshotProviderConfig {
    fn default() -> Self {
        Self {
            snapshot_dir: PathBuf::from("./data/snapshots"),
            snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
            max_snapshots: DEFAULT_MAX_SNAPSHOTS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_concurrent_creations: 1,
            max_concurrent_serves: 16,
            rate_limit_per_peer: 100,
            rate_limit_total: 1000,
            enable_compression: true,
            compression_level: 6,
            auto_create: true,
            min_snapshot_height: 0,
        }
    }
}

/// Trait for accessing state data for snapshot creation
#[async_trait::async_trait]
pub trait StateReader: Send + Sync {
    /// Get the current state root
    fn state_root(&self) -> Hash;

    /// Get the current finalized block height
    fn finalized_height(&self) -> u64;

    /// Get the block hash at a specific height
    fn block_hash(&self, height: u64) -> Option<Hash>;

    /// Get the finality certificate for a block
    fn finality_cert(&self, height: u64) -> Option<FinalityCertificate>;

    /// Iterate over state entries in a key range
    async fn iter_state_range(
        &self,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<StateIterator, String>;

    /// Get the total size of the state
    fn state_size(&self) -> u64;

    /// Get the number of state entries
    fn state_entry_count(&self) -> u64;
}

/// Iterator over state entries
pub struct StateIterator {
    /// Entries to iterate
    entries: VecDeque<StateEntry>,
}

impl StateIterator {
    /// Create a new state iterator
    pub fn new(entries: Vec<StateEntry>) -> Self {
        Self {
            entries: entries.into(),
        }
    }

    /// Create an empty iterator
    pub fn empty() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }
}

impl Iterator for StateIterator {
    type Item = StateEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.pop_front()
    }
}

/// A state entry (key-value pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEntry {
    /// Entry key
    pub key: Vec<u8>,

    /// Entry value
    pub value: Vec<u8>,

    /// Entry type
    pub entry_type: StateEntryType,
}

impl StateEntry {
    /// Create a new state entry
    pub fn new(key: Vec<u8>, value: Vec<u8>, entry_type: StateEntryType) -> Self {
        Self {
            key,
            value,
            entry_type,
        }
    }

    /// Get the size of this entry in bytes
    pub fn size(&self) -> usize {
        self.key.len() + self.value.len() + 1
    }
}

/// Type of state entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateEntryType {
    /// Account data
    Account,

    /// Contract storage slot
    Storage,

    /// Contract code
    Code,
}

/// Stored snapshot with metadata and chunk data
#[derive(Debug)]
pub struct StoredSnapshot {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,

    /// Finality certificate
    pub finality_cert: Option<FinalityCertificate>,

    /// Current status
    pub status: SnapshotStatus,

    /// Path to snapshot directory
    pub path: PathBuf,

    /// Cached chunk data (chunk_index -> data)
    chunks: RwLock<HashMap<u64, Vec<u8>>>,

    /// Number of times served
    serve_count: AtomicU64,

    /// Creation timestamp
    created_at: u64,
}

impl StoredSnapshot {
    /// Create a new stored snapshot
    pub fn new(
        metadata: SnapshotMetadata,
        finality_cert: Option<FinalityCertificate>,
        path: PathBuf,
    ) -> Self {
        Self {
            metadata,
            finality_cert,
            status: SnapshotStatus::Creating,
            path,
            chunks: RwLock::new(HashMap::new()),
            serve_count: AtomicU64::new(0),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        }
    }

    /// Get chunk data
    pub async fn get_chunk(&self, chunk_index: u64) -> Option<Vec<u8>> {
        let chunks = self.chunks.read().await;
        chunks.get(&chunk_index).cloned()
    }

    /// Store chunk data
    pub async fn store_chunk(&self, chunk_index: u64, data: Vec<u8>) {
        let mut chunks = self.chunks.write().await;
        chunks.insert(chunk_index, data);
    }

    /// Increment serve count
    pub fn increment_serve_count(&self) {
        self.serve_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get serve count
    pub fn serve_count(&self) -> u64 {
        self.serve_count.load(Ordering::Relaxed)
    }

    /// Convert to SnapshotInfo
    pub fn to_info(&self) -> SnapshotInfo {
        let mut info = SnapshotInfo::new(self.metadata.clone(), self.finality_cert.clone());
        info.status = self.status;
        info.serve_count = self.serve_count();
        info.local_path = Some(self.path.to_string_lossy().to_string());
        info
    }

    /// Convert to SnapshotListEntry
    pub fn to_list_entry(&self) -> SnapshotListEntry {
        SnapshotListEntry::new(self.metadata.clone(), self.finality_cert.clone())
    }
}

/// Rate limiter for request handling
struct RateLimiter {
    /// Per-peer limits
    per_peer: RwLock<HashMap<PeerId, PeerRateState>>,

    /// Total request count in current window
    total_count: AtomicU64,

    /// Window start time
    window_start: RwLock<Instant>,

    /// Max per peer per second
    max_per_peer: u32,

    /// Max total per second
    max_total: u32,
}

struct PeerRateState {
    count: u64,
    window_start: Instant,
}

impl RateLimiter {
    fn new(max_per_peer: u32, max_total: u32) -> Self {
        Self {
            per_peer: RwLock::new(HashMap::new()),
            total_count: AtomicU64::new(0),
            window_start: RwLock::new(Instant::now()),
            max_per_peer,
            max_total,
        }
    }

    async fn check_and_record(&self, peer: PeerId) -> bool {
        let now = Instant::now();

        // Check total rate
        {
            let mut window_start = self.window_start.write().await;
            if now.duration_since(*window_start) >= Duration::from_secs(1) {
                self.total_count.store(0, Ordering::Relaxed);
                *window_start = now;
            }
        }

        let total = self.total_count.fetch_add(1, Ordering::Relaxed);
        if total >= self.max_total as u64 {
            return false;
        }

        // Check per-peer rate
        let mut per_peer = self.per_peer.write().await;
        let state = per_peer.entry(peer).or_insert_with(|| PeerRateState {
            count: 0,
            window_start: now,
        });

        if now.duration_since(state.window_start) >= Duration::from_secs(1) {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;
        state.count <= self.max_per_peer as u64
    }

    async fn cleanup(&self) {
        let now = Instant::now();
        let mut per_peer = self.per_peer.write().await;
        per_peer
            .retain(|_, state| now.duration_since(state.window_start) < Duration::from_secs(60));
    }
}

/// Statistics for the snapshot provider
#[derive(Debug, Clone, Default)]
pub struct ProviderStats {
    /// Total snapshots created
    pub snapshots_created: u64,

    /// Total chunks served
    pub chunks_served: u64,

    /// Total bytes served
    pub bytes_served: u64,

    /// Total requests received
    pub requests_received: u64,

    /// Requests rate limited
    pub requests_rate_limited: u64,

    /// Active snapshot creations
    pub active_creations: usize,

    /// Active chunk serves
    pub active_serves: usize,
}

/// Event emitted by the snapshot provider
#[derive(Debug, Clone)]
pub enum ProviderEvent {
    /// Snapshot creation started
    SnapshotCreationStarted {
        /// Block height
        height: u64,
    },

    /// Snapshot creation completed
    SnapshotCreated {
        /// Block height
        height: u64,
        /// Number of chunks
        chunk_count: u64,
        /// Total size
        total_size: u64,
        /// Creation time
        duration: Duration,
    },

    /// Snapshot creation failed
    SnapshotCreationFailed {
        /// Block height
        height: u64,
        /// Error message
        error: String,
    },

    /// Old snapshot deleted
    SnapshotDeleted {
        /// Block height
        height: u64,
    },

    /// Chunk served to peer
    ChunkServed {
        /// Snapshot height
        height: u64,
        /// Chunk index
        chunk_index: u64,
        /// Peer
        peer: PeerId,
    },

    /// Request rate limited
    RateLimited {
        /// Peer
        peer: PeerId,
    },
}

/// Snapshot provider that creates and serves snapshots to peers
pub struct SnapshotProvider<S: StateReader> {
    /// Configuration
    config: SnapshotProviderConfig,

    /// State reader
    state: Arc<S>,

    /// Stored snapshots (height -> snapshot)
    snapshots: Arc<RwLock<BTreeMap<u64, Arc<StoredSnapshot>>>>,

    /// Semaphore for limiting concurrent creations
    creation_semaphore: Arc<Semaphore>,

    /// Semaphore for limiting concurrent serves
    serve_semaphore: Arc<Semaphore>,

    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,

    /// Statistics
    stats: Arc<RwLock<ProviderStats>>,

    /// Event sender
    event_tx: mpsc::Sender<ProviderEvent>,

    /// Event receiver
    event_rx: Arc<Mutex<mpsc::Receiver<ProviderEvent>>>,

    /// Shutdown flag
    shutdown: Arc<RwLock<bool>>,

    /// Last created snapshot height
    last_snapshot_height: Arc<RwLock<u64>>,
}

impl<S: StateReader + 'static> SnapshotProvider<S> {
    /// Create a new snapshot provider
    pub fn new(config: SnapshotProviderConfig, state: Arc<S>) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);

        Self {
            config: config.clone(),
            state,
            snapshots: Arc::new(RwLock::new(BTreeMap::new())),
            creation_semaphore: Arc::new(Semaphore::new(config.max_concurrent_creations)),
            serve_semaphore: Arc::new(Semaphore::new(config.max_concurrent_serves)),
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_per_peer,
                config.rate_limit_total,
            )),
            stats: Arc::new(RwLock::new(ProviderStats::default())),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            shutdown: Arc::new(RwLock::new(false)),
            last_snapshot_height: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the provider background tasks
    pub async fn start(&self) {
        info!("Starting snapshot provider");

        // Load existing snapshots
        self.load_snapshots().await;

        // Start auto-creation task if enabled
        if self.config.auto_create {
            let provider = self.clone_inner();
            tokio::spawn(async move {
                provider.auto_create_loop().await;
            });
        }

        // Start cleanup task
        let provider = self.clone_inner();
        tokio::spawn(async move {
            provider.cleanup_loop().await;
        });
    }

    /// Stop the provider
    pub async fn stop(&self) {
        info!("Stopping snapshot provider");
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
    }

    /// Get provider statistics
    pub async fn stats(&self) -> ProviderStats {
        self.stats.read().await.clone()
    }

    /// Get an event receiver
    pub async fn take_event_receiver(&self) -> mpsc::Receiver<ProviderEvent> {
        let rx = self.event_rx.lock().await;
        let (new_tx, new_rx) = mpsc::channel(1000);
        // Note: In production, use a broadcast channel
        new_rx
    }

    /// Get available snapshots
    pub async fn get_snapshots(&self) -> Vec<SnapshotInfo> {
        let snapshots = self.snapshots.read().await;
        snapshots.values().map(|s| s.to_info()).collect()
    }

    /// Handle a snapshot list request
    pub async fn handle_snapshot_request(
        &self,
        peer: PeerId,
        request: SnapshotRequest,
    ) -> SnapshotList {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_received += 1;
        }

        // Check rate limit
        if !self.rate_limiter.check_and_record(peer).await {
            let mut stats = self.stats.write().await;
            stats.requests_rate_limited += 1;

            let _ = self
                .event_tx
                .send(ProviderEvent::RateLimited { peer })
                .await;

            return SnapshotList::new(vec![], request.request_id, self.state.finalized_height());
        }

        let snapshots = self.snapshots.read().await;

        let mut entries: Vec<SnapshotListEntry> = snapshots
            .values()
            .filter(|s| {
                s.metadata.height >= request.min_height
                    && s.metadata.height <= request.max_height
                    && s.status == SnapshotStatus::Available
            })
            .take(request.max_results as usize)
            .map(|s| {
                if request.include_finality_cert {
                    s.to_list_entry()
                } else {
                    SnapshotListEntry::new(s.metadata.clone(), None)
                }
            })
            .collect();

        // Sort by height descending
        entries.sort_by(|a, b| b.metadata.height.cmp(&a.metadata.height));

        let truncated = entries.len() >= request.max_results as usize;

        SnapshotList {
            snapshots: entries,
            request_id: request.request_id,
            truncated,
            peer_height: self.state.finalized_height(),
        }
    }

    /// Handle a chunk request
    pub async fn handle_chunk_request(&self, peer: PeerId, request: ChunkRequest) -> ChunkResponse {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_received += 1;
        }

        // Check rate limit
        if !self.rate_limiter.check_and_record(peer).await {
            let mut stats = self.stats.write().await;
            stats.requests_rate_limited += 1;

            let _ = self
                .event_tx
                .send(ProviderEvent::RateLimited { peer })
                .await;

            return ChunkResponse::error(request.request_id, "rate limited".to_string());
        }

        // Acquire serve permit
        let permit = match self.serve_semaphore.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                return ChunkResponse::error(request.request_id, "server busy".to_string());
            }
        };

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_serves += 1;
        }

        // Get the snapshot
        let snapshots = self.snapshots.read().await;
        let snapshot = match snapshots.get(&request.chunk_id.snapshot_height) {
            Some(s) => Arc::clone(s),
            None => {
                drop(permit);
                let mut stats = self.stats.write().await;
                stats.active_serves -= 1;

                return ChunkResponse::error(request.request_id, "snapshot not found".to_string());
            }
        };
        drop(snapshots);

        // Check chunk index
        if request.chunk_id.chunk_index >= snapshot.metadata.chunk_count {
            drop(permit);
            let mut stats = self.stats.write().await;
            stats.active_serves -= 1;

            return ChunkResponse::error(request.request_id, "invalid chunk index".to_string());
        }

        // Get chunk data
        let chunk_data = match snapshot.get_chunk(request.chunk_id.chunk_index).await {
            Some(data) => data,
            None => {
                drop(permit);
                let mut stats = self.stats.write().await;
                stats.active_serves -= 1;

                return ChunkResponse::error(request.request_id, "chunk not available".to_string());
            }
        };

        // Verify expected hash if provided
        let data_hash = keccak256(&chunk_data);
        if data_hash != request.expected_hash {
            drop(permit);
            let mut stats = self.stats.write().await;
            stats.active_serves -= 1;

            return ChunkResponse::error(request.request_id, "hash mismatch".to_string());
        }

        // Build chunk
        let chunk_index = request.chunk_id.chunk_index;
        let chunk_size = snapshot.metadata.chunk_size as usize;

        // Calculate key range for this chunk
        let start_key = vec![(chunk_index as u8).wrapping_mul(85)];
        let end_key = vec![((chunk_index + 1) as u8).wrapping_mul(85)];

        // Build proof
        let proof = if request.include_proof {
            self.build_chunk_proof(&snapshot, chunk_index).await
        } else {
            ChunkProof::empty(snapshot.metadata.state_root)
        };

        let chunk = StateChunk::new(
            request.chunk_id,
            start_key,
            end_key,
            chunk_data.clone(),
            proof,
            0, // Entry count would be computed during creation
        );

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.chunks_served += 1;
            stats.bytes_served += chunk_data.len() as u64;
            stats.active_serves -= 1;
        }

        snapshot.increment_serve_count();

        let _ = self
            .event_tx
            .send(ProviderEvent::ChunkServed {
                height: request.chunk_id.snapshot_height,
                chunk_index,
                peer,
            })
            .await;

        drop(permit);

        ChunkResponse::success(request.request_id, chunk)
    }

    /// Create a snapshot at the given height
    pub async fn create_snapshot(&self, height: u64) -> Result<SnapshotMetadata, String> {
        // Check if snapshot already exists
        {
            let snapshots = self.snapshots.read().await;
            if snapshots.contains_key(&height) {
                return Err("snapshot already exists".to_string());
            }
        }

        // Acquire creation permit
        let permit = self
            .creation_semaphore
            .acquire()
            .await
            .map_err(|_| "failed to acquire creation permit")?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.active_creations += 1;
        }

        let _ = self
            .event_tx
            .send(ProviderEvent::SnapshotCreationStarted { height })
            .await;

        let start_time = Instant::now();

        // Get block hash and state root
        let block_hash = self.state.block_hash(height).ok_or("block not found")?;

        let state_root = self.state.state_root();

        // Get finality certificate
        let finality_cert = self.state.finality_cert(height);

        // Create snapshot directory
        let snapshot_path = self
            .config
            .snapshot_dir
            .join(format!("snapshot_{}", height));
        tokio::fs::create_dir_all(&snapshot_path)
            .await
            .map_err(|e| e.to_string())?;

        // Generate chunks
        let (chunk_hashes, total_size) = self.generate_chunks(height, &snapshot_path).await?;

        // Create metadata
        let metadata = SnapshotMetadata::new(
            height,
            state_root,
            block_hash,
            self.config.chunk_size as u64,
            chunk_hashes.clone(),
            total_size,
        );

        // Validate metadata
        metadata.validate().map_err(|e| e.to_string())?;

        // Create stored snapshot
        let stored = Arc::new(StoredSnapshot::new(
            metadata.clone(),
            finality_cert,
            snapshot_path,
        ));

        // Load chunks into cache
        for (index, _hash) in chunk_hashes.iter().enumerate() {
            let chunk_path = stored.path.join(format!("chunk_{}.bin", index));
            if let Ok(data) = tokio::fs::read(&chunk_path).await {
                stored.store_chunk(index as u64, data).await;
            }
        }

        // Mark as available
        // Note: In a real implementation, we'd modify the Arc<StoredSnapshot> or use interior mutability

        // Store snapshot
        {
            let mut snapshots = self.snapshots.write().await;
            snapshots.insert(height, stored);
        }

        // Update last snapshot height
        {
            let mut last_height = self.last_snapshot_height.write().await;
            *last_height = height;
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.snapshots_created += 1;
            stats.active_creations -= 1;
        }

        let duration = start_time.elapsed();

        let _ = self
            .event_tx
            .send(ProviderEvent::SnapshotCreated {
                height,
                chunk_count: metadata.chunk_count,
                total_size,
                duration,
            })
            .await;

        drop(permit);

        // Prune old snapshots
        self.prune_snapshots().await;

        Ok(metadata)
    }

    /// Generate chunks for a snapshot
    async fn generate_chunks(
        &self,
        height: u64,
        snapshot_path: &Path,
    ) -> Result<(Vec<Hash>, u64), String> {
        let mut chunk_hashes = Vec::new();
        let mut total_size = 0u64;

        let chunk_size = self.config.chunk_size;
        let state_size = self.state.state_size();
        let estimated_chunks = (state_size / chunk_size as u64) + 1;

        info!(
            "Generating approximately {} chunks for snapshot at height {}",
            estimated_chunks, height
        );

        // Generate chunks based on key ranges
        // In a real implementation, this would iterate over the actual state trie
        let mut chunk_index = 0u64;
        let current_chunk_data: Vec<u8> = Vec::with_capacity(chunk_size);

        // Simulate chunk generation with key ranges
        // In production, this would actually iterate over the state
        let total_entries = self.state.state_entry_count();
        let entries_per_chunk = total_entries / estimated_chunks.max(1);

        for i in 0..estimated_chunks {
            // Generate simulated chunk data
            let start_key = vec![(i as u8).wrapping_mul(85)];
            let end_key = vec![((i + 1) as u8).wrapping_mul(85)];

            // In production: iterate over state entries in this range
            let iter = self.state.iter_state_range(&start_key, &end_key).await?;

            let mut chunk_data = Vec::with_capacity(chunk_size);
            let mut entry_count = 0u64;

            for entry in iter {
                let entry_bytes = bincode::serialize(&entry).map_err(|e| e.to_string())?;

                if chunk_data.len() + entry_bytes.len() > chunk_size {
                    // Chunk is full, write it
                    let chunk_hash = keccak256(&chunk_data);
                    chunk_hashes.push(chunk_hash);

                    let chunk_path = snapshot_path.join(format!("chunk_{}.bin", chunk_index));
                    tokio::fs::write(&chunk_path, &chunk_data)
                        .await
                        .map_err(|e| e.to_string())?;

                    total_size += chunk_data.len() as u64;
                    chunk_index += 1;
                    chunk_data.clear();
                }

                chunk_data.extend(entry_bytes);
                entry_count += 1;
            }

            // Write remaining data as final chunk
            if !chunk_data.is_empty() {
                let chunk_hash = keccak256(&chunk_data);
                chunk_hashes.push(chunk_hash);

                let chunk_path = snapshot_path.join(format!("chunk_{}.bin", chunk_index));
                tokio::fs::write(&chunk_path, &chunk_data)
                    .await
                    .map_err(|e| e.to_string())?;

                total_size += chunk_data.len() as u64;
                chunk_index += 1;
            }

            debug!(
                "Generated chunk {} with {} entries",
                chunk_index - 1,
                entry_count
            );
        }

        // If no chunks were generated, create an empty one
        if chunk_hashes.is_empty() {
            let empty_data = Vec::new();
            let chunk_hash = keccak256(&empty_data);
            chunk_hashes.push(chunk_hash);

            let chunk_path = snapshot_path.join("chunk_0.bin");
            tokio::fs::write(&chunk_path, &empty_data)
                .await
                .map_err(|e| e.to_string())?;
        }

        info!(
            "Generated {} chunks totaling {} bytes",
            chunk_hashes.len(),
            total_size
        );

        Ok((chunk_hashes, total_size))
    }

    /// Build a Merkle proof for a chunk
    async fn build_chunk_proof(&self, snapshot: &StoredSnapshot, chunk_index: u64) -> ChunkProof {
        // Build proof from chunk hash to chunks root
        let chunk_hashes = &snapshot.metadata.chunk_hashes;

        if chunk_hashes.is_empty() {
            return ChunkProof::empty(snapshot.metadata.state_root);
        }

        // Build Merkle tree and extract proof
        let mut proof_nodes = Vec::new();
        let mut current_level = chunk_hashes.clone();
        let mut index = chunk_index as usize;

        while current_level.len() > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            let siblings = if sibling_index < current_level.len() {
                vec![current_level[sibling_index]]
            } else {
                vec![]
            };

            let position = (index % 2) as u8;
            proof_nodes.push(ProofNode::new(siblings, position));

            // Move to next level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for pair in current_level.chunks(2) {
                if pair.len() == 2 {
                    next_level.push(keccak256_concat(&[&pair[0], &pair[1]]));
                } else {
                    next_level.push(pair[0]);
                }
            }

            current_level = next_level;
            index /= 2;
        }

        ChunkProof::new(proof_nodes, snapshot.metadata.state_root)
    }

    /// Prune old snapshots to stay within max_snapshots limit
    async fn prune_snapshots(&self) {
        let mut snapshots = self.snapshots.write().await;

        while snapshots.len() > self.config.max_snapshots {
            // Remove oldest snapshot
            if let Some((&height, _)) = snapshots.iter().next() {
                let removed = snapshots.remove(&height);

                if let Some(snapshot) = removed {
                    // Delete snapshot directory
                    let _ = tokio::fs::remove_dir_all(&snapshot.path).await;

                    let _ = self
                        .event_tx
                        .send(ProviderEvent::SnapshotDeleted { height })
                        .await;

                    info!("Deleted old snapshot at height {}", height);
                }
            } else {
                break;
            }
        }
    }

    /// Load existing snapshots from disk
    async fn load_snapshots(&self) {
        info!(
            "Loading existing snapshots from {:?}",
            self.config.snapshot_dir
        );

        // Create snapshot directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&self.config.snapshot_dir).await {
            warn!("Failed to create snapshot directory: {}", e);
            return;
        }

        // Read snapshot directories
        let mut entries = match tokio::fs::read_dir(&self.config.snapshot_dir).await {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read snapshot directory: {}", e);
                return;
            }
        };

        let mut loaded = 0;

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            // Parse snapshot height from directory name
            if !name.starts_with("snapshot_") {
                continue;
            }

            let height: u64 = match name.strip_prefix("snapshot_").and_then(|s| s.parse().ok()) {
                Some(h) => h,
                None => continue,
            };

            // Load metadata
            let metadata_path = path.join("metadata.json");
            let metadata: SnapshotMetadata = match tokio::fs::read_to_string(&metadata_path).await {
                Ok(data) => match serde_json::from_str(&data) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Failed to parse snapshot metadata at {}: {}", height, e);
                        continue;
                    }
                },
                Err(_) => continue,
            };

            // Load finality certificate
            let cert_path = path.join("finality_cert.json");
            let finality_cert: Option<FinalityCertificate> =
                if let Ok(data) = tokio::fs::read_to_string(&cert_path).await {
                    serde_json::from_str(&data).ok()
                } else {
                    None
                };

            // Create stored snapshot
            let stored = Arc::new(StoredSnapshot::new(metadata, finality_cert, path.clone()));

            // Load chunks into cache
            for i in 0..stored.metadata.chunk_count {
                let chunk_path = path.join(format!("chunk_{}.bin", i));
                if let Ok(data) = tokio::fs::read(&chunk_path).await {
                    stored.store_chunk(i, data).await;
                }
            }

            // Add to snapshots
            {
                let mut snapshots = self.snapshots.write().await;
                snapshots.insert(height, stored);
            }

            loaded += 1;
        }

        info!("Loaded {} existing snapshots", loaded);
    }

    /// Auto-create snapshots at configured intervals
    async fn auto_create_loop(&self) {
        info!(
            "Starting auto-create loop with interval {} blocks",
            self.config.snapshot_interval
        );

        loop {
            // Check shutdown
            if *self.shutdown.read().await {
                break;
            }

            // Get current finalized height
            let current_height = self.state.finalized_height();

            // Get last snapshot height
            let last_height = *self.last_snapshot_height.read().await;

            // Check if we should create a new snapshot
            let should_create = current_height >= self.config.min_snapshot_height
                && (last_height == 0
                    || current_height >= last_height + self.config.snapshot_interval);

            if should_create {
                // Calculate target height (align to interval)
                let target_height = (current_height / self.config.snapshot_interval)
                    * self.config.snapshot_interval;

                if target_height > last_height {
                    info!("Auto-creating snapshot at height {}", target_height);

                    match self.create_snapshot(target_height).await {
                        Ok(metadata) => {
                            info!(
                                "Auto-created snapshot at height {} with {} chunks",
                                metadata.height, metadata.chunk_count
                            );
                        }
                        Err(e) => {
                            error!(
                                "Failed to auto-create snapshot at height {}: {}",
                                target_height, e
                            );

                            let _ = self
                                .event_tx
                                .send(ProviderEvent::SnapshotCreationFailed {
                                    height: target_height,
                                    error: e,
                                })
                                .await;
                        }
                    }
                }
            }

            // Sleep before checking again
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    /// Cleanup loop for rate limiter and other maintenance
    async fn cleanup_loop(&self) {
        loop {
            // Check shutdown
            if *self.shutdown.read().await {
                break;
            }

            // Cleanup rate limiter
            self.rate_limiter.cleanup().await;

            // Sleep before next cleanup
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    /// Clone inner state for spawning tasks
    fn clone_inner(&self) -> SnapshotProviderInner<S> {
        SnapshotProviderInner {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            snapshots: Arc::clone(&self.snapshots),
            creation_semaphore: Arc::clone(&self.creation_semaphore),
            serve_semaphore: Arc::clone(&self.serve_semaphore),
            rate_limiter: Arc::clone(&self.rate_limiter),
            stats: Arc::clone(&self.stats),
            event_tx: self.event_tx.clone(),
            shutdown: Arc::clone(&self.shutdown),
            last_snapshot_height: Arc::clone(&self.last_snapshot_height),
        }
    }
}

/// Inner state for spawned tasks
struct SnapshotProviderInner<S: StateReader> {
    config: SnapshotProviderConfig,
    state: Arc<S>,
    snapshots: Arc<RwLock<BTreeMap<u64, Arc<StoredSnapshot>>>>,
    creation_semaphore: Arc<Semaphore>,
    serve_semaphore: Arc<Semaphore>,
    rate_limiter: Arc<RateLimiter>,
    stats: Arc<RwLock<ProviderStats>>,
    event_tx: mpsc::Sender<ProviderEvent>,
    shutdown: Arc<RwLock<bool>>,
    last_snapshot_height: Arc<RwLock<u64>>,
}

impl<S: StateReader + 'static> SnapshotProviderInner<S> {
    async fn auto_create_loop(&self) {
        loop {
            if *self.shutdown.read().await {
                break;
            }

            let current_height = self.state.finalized_height();
            let last_height = *self.last_snapshot_height.read().await;

            let should_create = current_height >= self.config.min_snapshot_height
                && (last_height == 0
                    || current_height >= last_height + self.config.snapshot_interval);

            if should_create {
                let target_height = (current_height / self.config.snapshot_interval)
                    * self.config.snapshot_interval;

                if target_height > last_height {
                    // We would call create_snapshot here, but we need the full provider
                    // In production, this would be restructured
                    debug!("Would create snapshot at height {}", target_height);
                }
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn cleanup_loop(&self) {
        loop {
            if *self.shutdown.read().await {
                break;
            }

            self.rate_limiter.cleanup().await;

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
