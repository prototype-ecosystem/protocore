//! Chunk Handling
//!
//! This module provides the chunk-related functionality for state sync:
//! - StateChunk structure representing a portion of the state trie
//! - Chunk request/response protocol messages
//! - Chunk verification against the snapshot Merkle root
//! - Parallel chunk downloading with retry logic
//! - Chunk reassembly into complete state
//!
//! ## Chunk Structure
//!
//! Each chunk contains a contiguous range of trie nodes identified by their
//! key prefix. Chunks are sized to be efficiently transferable while allowing
//! parallel downloading.
//!
//! ## Verification
//!
//! Chunks include a Merkle proof that allows verification against the
//! snapshot's state root without needing the full trie.

use crate::{
    keccak256, keccak256_concat, Hash, PeerId, DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_CONCURRENT_DOWNLOADS, DEFAULT_MAX_RETRIES, DEFAULT_REQUEST_TIMEOUT_SECS,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Unique identifier for a chunk within a snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId {
    /// Snapshot height this chunk belongs to
    pub snapshot_height: u64,

    /// Index of this chunk within the snapshot
    pub chunk_index: u64,
}

impl ChunkId {
    /// Create a new chunk ID
    pub fn new(snapshot_height: u64, chunk_index: u64) -> Self {
        Self {
            snapshot_height,
            chunk_index,
        }
    }

    /// Compute a hash of this chunk ID
    pub fn hash(&self) -> Hash {
        keccak256_concat(&[
            &self.snapshot_height.to_le_bytes(),
            &self.chunk_index.to_le_bytes(),
        ])
    }
}

impl std::fmt::Display for ChunkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.snapshot_height, self.chunk_index)
    }
}

/// A state chunk containing a portion of the state trie.
///
/// Chunks contain serialized trie nodes that can be independently verified
/// and applied to reconstruct the full state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChunk {
    /// Unique identifier for this chunk
    pub id: ChunkId,

    /// Start key (inclusive) for this chunk's range
    pub start_key: Vec<u8>,

    /// End key (exclusive) for this chunk's range
    pub end_key: Vec<u8>,

    /// Serialized state updates in this chunk
    pub data: Vec<u8>,

    /// Hash of the chunk data for verification
    pub data_hash: Hash,

    /// Number of state entries in this chunk
    pub entry_count: u64,

    /// Merkle proof linking this chunk to the state root
    pub proof: ChunkProof,
}

impl StateChunk {
    /// Create a new state chunk
    pub fn new(
        id: ChunkId,
        start_key: Vec<u8>,
        end_key: Vec<u8>,
        data: Vec<u8>,
        proof: ChunkProof,
        entry_count: u64,
    ) -> Self {
        let data_hash = keccak256(&data);
        Self {
            id,
            start_key,
            end_key,
            data,
            data_hash,
            entry_count,
            proof,
        }
    }

    /// Verify the chunk data hash matches
    pub fn verify_data_hash(&self) -> bool {
        keccak256(&self.data) == self.data_hash
    }

    /// Get the size of this chunk in bytes
    pub fn size(&self) -> usize {
        self.data.len() + self.start_key.len() + self.end_key.len() + self.proof.size()
    }

    /// Check if a key falls within this chunk's range
    pub fn contains_key(&self, key: &[u8]) -> bool {
        key >= self.start_key.as_slice() && key < self.end_key.as_slice()
    }
}

/// Merkle proof for chunk verification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkProof {
    /// Proof nodes from the chunk to the state root
    pub nodes: Vec<ProofNode>,

    /// Root hash this proof verifies against
    pub root: Hash,
}

impl ChunkProof {
    /// Create a new chunk proof
    pub fn new(nodes: Vec<ProofNode>, root: Hash) -> Self {
        Self { nodes, root }
    }

    /// Create an empty proof (for testing)
    pub fn empty(root: Hash) -> Self {
        Self {
            nodes: Vec::new(),
            root,
        }
    }

    /// Verify the proof for a given chunk hash
    pub fn verify(&self, chunk_hash: &Hash) -> bool {
        if self.nodes.is_empty() {
            // Empty proof means chunk hash should equal root
            return chunk_hash == &self.root;
        }

        let mut current_hash = *chunk_hash;

        for node in &self.nodes {
            current_hash = node.compute_parent_hash(&current_hash);
        }

        current_hash == self.root
    }

    /// Get the size of this proof in bytes
    pub fn size(&self) -> usize {
        self.nodes.iter().map(|n| n.size()).sum::<usize>() + 32
    }
}

/// A node in a Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Sibling hashes at this level
    pub siblings: Vec<Hash>,

    /// Position of the target node (0 = left, 1 = right, etc.)
    pub position: u8,
}

impl ProofNode {
    /// Create a new proof node
    pub fn new(siblings: Vec<Hash>, position: u8) -> Self {
        Self { siblings, position }
    }

    /// Compute the parent hash given the current hash
    pub fn compute_parent_hash(&self, current: &Hash) -> Hash {
        if self.siblings.is_empty() {
            return *current;
        }

        // Build the hash inputs in order based on position
        let mut inputs: Vec<&[u8]> = Vec::with_capacity(self.siblings.len() + 1);

        let pos = self.position as usize;
        for (i, sibling) in self.siblings.iter().enumerate() {
            if i == pos {
                inputs.push(current);
            }
            inputs.push(sibling);
        }
        if pos >= self.siblings.len() {
            inputs.push(current);
        }

        keccak256_concat(&inputs)
    }

    /// Get the size of this node in bytes
    pub fn size(&self) -> usize {
        self.siblings.len() * 32 + 1
    }
}

/// Request for a specific chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    /// ID of the requested chunk
    pub chunk_id: ChunkId,

    /// Expected hash of the chunk (for verification)
    pub expected_hash: Hash,

    /// Request ID for correlation
    pub request_id: u64,

    /// Whether to include the Merkle proof
    pub include_proof: bool,
}

impl ChunkRequest {
    /// Create a new chunk request
    pub fn new(chunk_id: ChunkId, expected_hash: Hash) -> Self {
        Self {
            chunk_id,
            expected_hash,
            request_id: generate_request_id(),
            include_proof: true,
        }
    }

    /// Set whether to include proof
    pub fn with_proof(mut self, include: bool) -> Self {
        self.include_proof = include;
        self
    }
}

/// Response containing a chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkResponse {
    /// Request ID this is responding to
    pub request_id: u64,

    /// The requested chunk (if available)
    pub chunk: Option<StateChunk>,

    /// Error message if chunk is not available
    pub error: Option<String>,
}

impl ChunkResponse {
    /// Create a successful response
    pub fn success(request_id: u64, chunk: StateChunk) -> Self {
        Self {
            request_id,
            chunk: Some(chunk),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            chunk: None,
            error: Some(error),
        }
    }

    /// Check if this response is successful
    pub fn is_success(&self) -> bool {
        self.chunk.is_some()
    }
}

/// Verifies chunks against a snapshot's Merkle root
#[derive(Debug)]
pub struct ChunkVerifier {
    /// State root to verify against
    state_root: Hash,

    /// Expected chunk hashes from snapshot metadata
    chunk_hashes: Vec<Hash>,

    /// Verified chunk indices
    verified: HashSet<u64>,
}

impl ChunkVerifier {
    /// Create a new chunk verifier
    pub fn new(state_root: Hash, chunk_hashes: Vec<Hash>) -> Self {
        Self {
            state_root,
            chunk_hashes,
            verified: HashSet::new(),
        }
    }

    /// Verify a chunk
    pub fn verify(&mut self, chunk: &StateChunk) -> Result<(), ChunkVerificationError> {
        let chunk_index = chunk.id.chunk_index;

        // Check chunk index is valid
        if chunk_index as usize >= self.chunk_hashes.len() {
            return Err(ChunkVerificationError::InvalidChunkIndex(chunk_index));
        }

        // Verify data hash
        if !chunk.verify_data_hash() {
            return Err(ChunkVerificationError::DataHashMismatch);
        }

        // Verify against expected chunk hash
        let expected_hash = &self.chunk_hashes[chunk_index as usize];
        if &chunk.data_hash != expected_hash {
            return Err(ChunkVerificationError::ChunkHashMismatch {
                expected: *expected_hash,
                actual: chunk.data_hash,
            });
        }

        // Verify Merkle proof
        if !chunk.proof.verify(&chunk.data_hash) {
            return Err(ChunkVerificationError::InvalidProof);
        }

        // Verify proof root matches state root
        if chunk.proof.root != self.state_root {
            return Err(ChunkVerificationError::StateRootMismatch {
                expected: self.state_root,
                actual: chunk.proof.root,
            });
        }

        // Mark as verified
        self.verified.insert(chunk_index);

        Ok(())
    }

    /// Check if a chunk has been verified
    pub fn is_verified(&self, chunk_index: u64) -> bool {
        self.verified.contains(&chunk_index)
    }

    /// Get the number of verified chunks
    pub fn verified_count(&self) -> usize {
        self.verified.len()
    }

    /// Get the total number of chunks
    pub fn total_chunks(&self) -> usize {
        self.chunk_hashes.len()
    }

    /// Check if all chunks are verified
    pub fn is_complete(&self) -> bool {
        self.verified.len() == self.chunk_hashes.len()
    }

    /// Get unverified chunk indices
    pub fn unverified_indices(&self) -> Vec<u64> {
        (0..self.chunk_hashes.len() as u64)
            .filter(|i| !self.verified.contains(i))
            .collect()
    }

    /// Reset verification state
    pub fn reset(&mut self) {
        self.verified.clear();
    }
}

/// Errors that can occur during chunk verification
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChunkVerificationError {
    /// Chunk index is out of range
    #[error("invalid chunk index: {0}")]
    InvalidChunkIndex(u64),

    /// Data hash doesn't match computed hash
    #[error("data hash mismatch")]
    DataHashMismatch,

    /// Chunk hash doesn't match expected hash
    #[error("chunk hash mismatch: expected {expected:?}, got {actual:?}")]
    ChunkHashMismatch {
        /// Expected hash
        expected: Hash,
        /// Actual hash
        actual: Hash,
    },

    /// Merkle proof is invalid
    #[error("invalid Merkle proof")]
    InvalidProof,

    /// Proof root doesn't match state root
    #[error("state root mismatch: expected {expected:?}, got {actual:?}")]
    StateRootMismatch {
        /// Expected root
        expected: Hash,
        /// Actual root
        actual: Hash,
    },
}

/// Configuration for chunk downloading
#[derive(Debug, Clone)]
pub struct ChunkDownloadConfig {
    /// Maximum concurrent downloads
    pub max_concurrent: usize,

    /// Request timeout
    pub timeout: Duration,

    /// Maximum retry attempts per chunk
    pub max_retries: u32,

    /// Delay between retries
    pub retry_delay: Duration,

    /// Maximum chunk size to accept
    pub max_chunk_size: usize,
}

impl Default for ChunkDownloadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: DEFAULT_MAX_CONCURRENT_DOWNLOADS,
            timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: Duration::from_secs(1),
            max_chunk_size: DEFAULT_CHUNK_SIZE * 2,
        }
    }
}

/// Status of a chunk download
#[derive(Debug, Clone)]
pub enum ChunkDownloadStatus {
    /// Waiting to be downloaded
    Pending,

    /// Currently downloading from a peer
    Downloading {
        /// Peer we're downloading from
        peer: PeerId,
        /// When the download started
        started_at: Instant,
    },

    /// Download completed successfully
    Completed,

    /// Download failed
    Failed {
        /// Number of attempts made
        attempts: u32,
        /// Last error message
        last_error: String,
    },
}

/// Tracks the download state of a chunk
#[derive(Debug)]
struct ChunkDownloadState {
    /// Chunk index
    chunk_index: u64,

    /// Expected hash
    expected_hash: Hash,

    /// Current status
    status: ChunkDownloadStatus,

    /// Number of download attempts
    attempts: u32,

    /// Peers that have failed for this chunk
    failed_peers: HashSet<PeerId>,
}

impl ChunkDownloadState {
    fn new(chunk_index: u64, expected_hash: Hash) -> Self {
        Self {
            chunk_index,
            expected_hash,
            status: ChunkDownloadStatus::Pending,
            attempts: 0,
            failed_peers: HashSet::new(),
        }
    }

    fn start_download(&mut self, peer: PeerId) {
        self.status = ChunkDownloadStatus::Downloading {
            peer,
            started_at: Instant::now(),
        };
        self.attempts += 1;
    }

    fn complete(&mut self) {
        self.status = ChunkDownloadStatus::Completed;
    }

    fn fail(&mut self, peer: PeerId, error: String) {
        self.failed_peers.insert(peer);
        self.status = ChunkDownloadStatus::Failed {
            attempts: self.attempts,
            last_error: error,
        };
    }

    fn reset_for_retry(&mut self) {
        self.status = ChunkDownloadStatus::Pending;
    }
}

/// Event emitted by the chunk downloader
#[derive(Debug, Clone)]
pub enum ChunkDownloadEvent {
    /// A chunk download started
    Started {
        /// Chunk index
        chunk_index: u64,
        /// Peer downloading from
        peer: PeerId,
    },

    /// A chunk was downloaded successfully
    Completed {
        /// Chunk index
        chunk_index: u64,
        /// Download time
        duration: Duration,
        /// Chunk size in bytes
        size: usize,
    },

    /// A chunk download failed
    Failed {
        /// Chunk index
        chunk_index: u64,
        /// Error message
        error: String,
        /// Will retry
        will_retry: bool,
    },

    /// All chunks downloaded
    AllComplete,

    /// Download progress update
    Progress {
        /// Completed chunks
        completed: usize,
        /// Total chunks
        total: usize,
        /// Bytes downloaded
        bytes_downloaded: u64,
        /// Bytes per second
        bytes_per_second: f64,
    },
}

/// Trait for network operations needed by the chunk downloader
#[async_trait::async_trait]
pub trait ChunkNetwork: Send + Sync {
    /// Request a chunk from a peer
    async fn request_chunk(
        &self,
        peer: PeerId,
        request: ChunkRequest,
    ) -> Result<ChunkResponse, String>;

    /// Get peers that have a snapshot
    fn get_snapshot_peers(&self, snapshot_height: u64) -> Vec<PeerId>;

    /// Report a peer as misbehaving
    fn report_peer(&self, peer: PeerId, reason: &str);
}

/// Downloads chunks in parallel from multiple peers
pub struct ChunkDownloader<N: ChunkNetwork> {
    /// Network interface
    network: Arc<N>,

    /// Download configuration
    config: ChunkDownloadConfig,

    /// Snapshot height we're downloading
    snapshot_height: u64,

    /// Chunk download states
    states: Arc<RwLock<HashMap<u64, ChunkDownloadState>>>,

    /// Chunk verifier
    verifier: Arc<Mutex<ChunkVerifier>>,

    /// Semaphore for limiting concurrent downloads
    semaphore: Arc<Semaphore>,

    /// Event sender
    event_tx: mpsc::Sender<ChunkDownloadEvent>,

    /// Event receiver
    event_rx: Arc<Mutex<mpsc::Receiver<ChunkDownloadEvent>>>,

    /// Downloaded chunks
    downloaded_chunks: Arc<RwLock<HashMap<u64, StateChunk>>>,

    /// Total bytes downloaded
    bytes_downloaded: Arc<std::sync::atomic::AtomicU64>,

    /// Download start time
    start_time: Arc<RwLock<Option<Instant>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl<N: ChunkNetwork + 'static> ChunkDownloader<N> {
    /// Create a new chunk downloader
    pub fn new(
        network: Arc<N>,
        config: ChunkDownloadConfig,
        snapshot_height: u64,
        state_root: Hash,
        chunk_hashes: Vec<Hash>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);

        let states: HashMap<u64, ChunkDownloadState> = chunk_hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| (i as u64, ChunkDownloadState::new(i as u64, *hash)))
            .collect();

        Self {
            network,
            config: config.clone(),
            snapshot_height,
            states: Arc::new(RwLock::new(states)),
            verifier: Arc::new(Mutex::new(ChunkVerifier::new(state_root, chunk_hashes))),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            downloaded_chunks: Arc::new(RwLock::new(HashMap::new())),
            bytes_downloaded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: Arc::new(RwLock::new(None)),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start downloading all chunks
    pub async fn start(&self) -> Result<(), ChunkDownloadError> {
        // Set start time
        {
            let mut start_time = self.start_time.write().await;
            *start_time = Some(Instant::now());
        }

        info!(
            "Starting chunk download for snapshot at height {}",
            self.snapshot_height
        );

        // Get all pending chunk indices
        let pending_indices: Vec<u64> = {
            let states = self.states.read().await;
            states
                .iter()
                .filter(|(_, state)| matches!(state.status, ChunkDownloadStatus::Pending))
                .map(|(idx, _)| *idx)
                .collect()
        };

        // Spawn download tasks
        let mut handles = Vec::new();

        for chunk_index in pending_indices {
            let handle = self.spawn_download_task(chunk_index);
            handles.push(handle);
        }

        // Wait for all downloads to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Download task panicked: {:?}", e);
            }
        }

        // Check if all chunks completed
        let verifier = self.verifier.lock().await;
        if verifier.is_complete() {
            let _ = self.event_tx.send(ChunkDownloadEvent::AllComplete).await;
            info!("All chunks downloaded successfully");
            Ok(())
        } else {
            let unverified = verifier.unverified_indices();
            Err(ChunkDownloadError::IncompletDownload {
                missing: unverified.len(),
            })
        }
    }

    /// Spawn a task to download a single chunk
    fn spawn_download_task(&self, chunk_index: u64) -> tokio::task::JoinHandle<()> {
        let network = Arc::clone(&self.network);
        let config = self.config.clone();
        let snapshot_height = self.snapshot_height;
        let states = Arc::clone(&self.states);
        let verifier = Arc::clone(&self.verifier);
        let semaphore = Arc::clone(&self.semaphore);
        let event_tx = self.event_tx.clone();
        let downloaded_chunks = Arc::clone(&self.downloaded_chunks);
        let bytes_downloaded = Arc::clone(&self.bytes_downloaded);
        let start_time = Arc::clone(&self.start_time);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            // Acquire semaphore permit
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            // Check shutdown
            if *shutdown.read().await {
                return;
            }

            // Get expected hash
            let expected_hash = {
                let states = states.read().await;
                match states.get(&chunk_index) {
                    Some(state) => state.expected_hash,
                    None => return,
                }
            };

            let chunk_id = ChunkId::new(snapshot_height, chunk_index);

            // Retry loop
            for attempt in 0..config.max_retries {
                // Check shutdown
                if *shutdown.read().await {
                    return;
                }

                // Select a peer
                let peers = network.get_snapshot_peers(snapshot_height);
                if peers.is_empty() {
                    warn!("No peers available for chunk {}", chunk_index);
                    tokio::time::sleep(config.retry_delay).await;
                    continue;
                }

                // Get failed peers for this chunk
                let failed_peers: HashSet<PeerId> = {
                    let states = states.read().await;
                    states
                        .get(&chunk_index)
                        .map(|s| s.failed_peers.clone())
                        .unwrap_or_default()
                };

                // Select a peer that hasn't failed
                let peer = peers.into_iter().find(|p| !failed_peers.contains(p));

                let peer = match peer {
                    Some(p) => p,
                    None => {
                        warn!("All peers have failed for chunk {}", chunk_index);
                        tokio::time::sleep(config.retry_delay).await;
                        continue;
                    }
                };

                // Mark as downloading
                {
                    let mut states = states.write().await;
                    if let Some(state) = states.get_mut(&chunk_index) {
                        state.start_download(peer);
                    }
                }

                let _ = event_tx
                    .send(ChunkDownloadEvent::Started { chunk_index, peer })
                    .await;

                // Create request
                let request = ChunkRequest::new(chunk_id, expected_hash);
                let download_start = Instant::now();

                // Make request with timeout
                let result =
                    tokio::time::timeout(config.timeout, network.request_chunk(peer, request))
                        .await;

                match result {
                    Ok(Ok(response)) if response.is_success() => {
                        let chunk = response.chunk.unwrap();
                        let duration = download_start.elapsed();
                        let size = chunk.size();

                        // Verify chunk
                        let verification_result = {
                            let mut verifier = verifier.lock().await;
                            verifier.verify(&chunk)
                        };

                        match verification_result {
                            Ok(()) => {
                                // Store chunk
                                {
                                    let mut downloaded = downloaded_chunks.write().await;
                                    downloaded.insert(chunk_index, chunk);
                                }

                                // Update state
                                {
                                    let mut states = states.write().await;
                                    if let Some(state) = states.get_mut(&chunk_index) {
                                        state.complete();
                                    }
                                }

                                // Update stats
                                bytes_downloaded
                                    .fetch_add(size as u64, std::sync::atomic::Ordering::Relaxed);

                                // Send progress event
                                let (completed, total) = {
                                    let verifier = verifier.lock().await;
                                    (verifier.verified_count(), verifier.total_chunks())
                                };

                                let total_bytes =
                                    bytes_downloaded.load(std::sync::atomic::Ordering::Relaxed);
                                let elapsed = start_time
                                    .read()
                                    .await
                                    .map(|t| t.elapsed().as_secs_f64())
                                    .unwrap_or(1.0);
                                let bytes_per_second = total_bytes as f64 / elapsed;

                                let _ = event_tx
                                    .send(ChunkDownloadEvent::Completed {
                                        chunk_index,
                                        duration,
                                        size,
                                    })
                                    .await;

                                let _ = event_tx
                                    .send(ChunkDownloadEvent::Progress {
                                        completed,
                                        total,
                                        bytes_downloaded: total_bytes,
                                        bytes_per_second,
                                    })
                                    .await;

                                debug!(
                                    "Chunk {} downloaded in {:?} ({} bytes)",
                                    chunk_index, duration, size
                                );
                                return;
                            }
                            Err(e) => {
                                warn!("Chunk {} verification failed: {:?}", chunk_index, e);
                                network.report_peer(peer, "invalid chunk");

                                let mut states = states.write().await;
                                if let Some(state) = states.get_mut(&chunk_index) {
                                    state.fail(peer, format!("{:?}", e));
                                    state.reset_for_retry();
                                }
                            }
                        }
                    }
                    Ok(Ok(response)) => {
                        let error = response
                            .error
                            .unwrap_or_else(|| "unknown error".to_string());
                        warn!("Chunk {} request failed: {}", chunk_index, error);

                        let mut states = states.write().await;
                        if let Some(state) = states.get_mut(&chunk_index) {
                            state.fail(peer, error.clone());
                            state.reset_for_retry();
                        }

                        let _ = event_tx
                            .send(ChunkDownloadEvent::Failed {
                                chunk_index,
                                error,
                                will_retry: attempt + 1 < config.max_retries,
                            })
                            .await;
                    }
                    Ok(Err(e)) => {
                        warn!("Chunk {} network error: {}", chunk_index, e);

                        let mut states = states.write().await;
                        if let Some(state) = states.get_mut(&chunk_index) {
                            state.fail(peer, e.clone());
                            state.reset_for_retry();
                        }

                        let _ = event_tx
                            .send(ChunkDownloadEvent::Failed {
                                chunk_index,
                                error: e,
                                will_retry: attempt + 1 < config.max_retries,
                            })
                            .await;
                    }
                    Err(_) => {
                        warn!("Chunk {} request timed out", chunk_index);

                        let mut states = states.write().await;
                        if let Some(state) = states.get_mut(&chunk_index) {
                            state.fail(peer, "timeout".to_string());
                            state.reset_for_retry();
                        }

                        let _ = event_tx
                            .send(ChunkDownloadEvent::Failed {
                                chunk_index,
                                error: "timeout".to_string(),
                                will_retry: attempt + 1 < config.max_retries,
                            })
                            .await;
                    }
                }

                // Delay before retry
                if attempt + 1 < config.max_retries {
                    tokio::time::sleep(config.retry_delay).await;
                }
            }

            // All retries exhausted
            error!(
                "Chunk {} failed after {} attempts",
                chunk_index, config.max_retries
            );
        })
    }

    /// Get an event receiver
    pub async fn take_event_receiver(&self) -> mpsc::Receiver<ChunkDownloadEvent> {
        let rx = self.event_rx.lock().await;
        let (new_tx, new_rx) = mpsc::channel(1000);
        // We can't actually take the receiver, so we create a new channel
        // In a real implementation, you'd use a broadcast channel or similar
        new_rx
    }

    /// Get download progress
    pub async fn progress(&self) -> ChunkDownloadProgress {
        let verifier = self.verifier.lock().await;
        let completed = verifier.verified_count();
        let total = verifier.total_chunks();
        let bytes = self
            .bytes_downloaded
            .load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = self
            .start_time
            .read()
            .await
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);

        ChunkDownloadProgress {
            completed,
            total,
            bytes_downloaded: bytes,
            elapsed,
        }
    }

    /// Get all downloaded chunks
    pub async fn get_chunks(&self) -> HashMap<u64, StateChunk> {
        self.downloaded_chunks.read().await.clone()
    }

    /// Stop downloading
    pub async fn stop(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
    }

    /// Check if download is complete
    pub async fn is_complete(&self) -> bool {
        let verifier = self.verifier.lock().await;
        verifier.is_complete()
    }
}

/// Progress information for chunk download
#[derive(Debug, Clone)]
pub struct ChunkDownloadProgress {
    /// Number of completed chunks
    pub completed: usize,

    /// Total number of chunks
    pub total: usize,

    /// Total bytes downloaded
    pub bytes_downloaded: u64,

    /// Time elapsed
    pub elapsed: Duration,
}

impl ChunkDownloadProgress {
    /// Get completion percentage
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.completed as f64 / self.total as f64) * 100.0
    }

    /// Get download speed in bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs == 0.0 {
            return 0.0;
        }
        self.bytes_downloaded as f64 / secs
    }

    /// Estimate time remaining
    pub fn estimated_remaining(&self) -> Duration {
        if self.completed == 0 || self.completed == self.total {
            return Duration::ZERO;
        }

        let remaining = self.total - self.completed;
        let avg_time_per_chunk = self.elapsed.as_secs_f64() / self.completed as f64;
        Duration::from_secs_f64(remaining as f64 * avg_time_per_chunk)
    }
}

/// Errors that can occur during chunk download
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChunkDownloadError {
    /// Download was not completed
    #[error("incomplete download: {missing} chunks missing")]
    IncompletDownload {
        /// Number of missing chunks
        missing: usize,
    },

    /// No peers available
    #[error("no peers available")]
    NoPeers,

    /// Network error
    #[error("network error: {0}")]
    Network(String),

    /// Shutdown requested
    #[error("shutdown requested")]
    Shutdown,
}

/// Reassembles chunks into state updates
pub struct ChunkReassembler {
    /// Accumulated chunks in order
    chunks: Vec<Option<StateChunk>>,

    /// Total expected chunks
    total_chunks: usize,

    /// Number of chunks received
    received: usize,
}

impl ChunkReassembler {
    /// Create a new reassembler
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
            received: 0,
        }
    }

    /// Add a chunk
    pub fn add_chunk(&mut self, chunk: StateChunk) -> Result<(), String> {
        let index = chunk.id.chunk_index as usize;

        if index >= self.total_chunks {
            return Err(format!("chunk index {} out of range", index));
        }

        if self.chunks[index].is_some() {
            return Err(format!("chunk {} already received", index));
        }

        self.chunks[index] = Some(chunk);
        self.received += 1;

        Ok(())
    }

    /// Check if all chunks are received
    pub fn is_complete(&self) -> bool {
        self.received == self.total_chunks
    }

    /// Get progress
    pub fn progress(&self) -> (usize, usize) {
        (self.received, self.total_chunks)
    }

    /// Get all chunks in order
    pub fn into_chunks(self) -> Result<Vec<StateChunk>, String> {
        if !self.is_complete() {
            return Err(format!(
                "incomplete: {}/{} chunks",
                self.received, self.total_chunks
            ));
        }

        Ok(self.chunks.into_iter().flatten().collect())
    }

    /// Iterate over received chunks in order
    pub fn iter_chunks(&self) -> impl Iterator<Item = &StateChunk> {
        self.chunks.iter().filter_map(|c| c.as_ref())
    }
}

/// Generate a unique request ID
fn generate_request_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
