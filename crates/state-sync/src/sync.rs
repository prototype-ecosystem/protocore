//! State Sync Manager
//!
//! This module provides the main orchestration logic for state synchronization:
//! - Discovering available snapshots from peers
//! - Selecting the best snapshot based on finality and availability
//! - Coordinating chunk downloads
//! - Applying verified chunks to local state
//! - Resuming from partial sync
//! - Progress reporting and monitoring
//!
//! ## Sync Flow
//!
//! 1. Discovery: Query peers for available snapshots
//! 2. Selection: Choose the best snapshot based on height, finality, and peer availability
//! 3. Download: Fetch state chunks in parallel from multiple peers
//! 4. Verification: Verify each chunk against the snapshot's Merkle root
//! 5. Application: Apply verified chunks to the local state database
//! 6. Finalization: Verify final state root and complete sync

use crate::{
    chunks::{
        ChunkDownloadConfig, ChunkDownloadError, ChunkDownloadEvent, ChunkDownloader,
        ChunkNetwork, ChunkReassembler, ChunkVerifier, StateChunk,
    },
    keccak256,
    snapshot::{
        FinalityCertificate, SnapshotAvailability, SnapshotInfo, SnapshotList,
        SnapshotListEntry, SnapshotMetadata, SnapshotRequest, SnapshotSelector,
    },
    Hash, PeerId, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_CONCURRENT_DOWNLOADS,
    DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_SNAPSHOT_INTERVAL,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

/// Configuration for state synchronization
#[derive(Debug, Clone)]
pub struct StateSyncConfig {
    /// Directory for storing sync progress and downloaded chunks
    pub data_dir: PathBuf,

    /// Minimum number of peers required to have a snapshot
    pub min_peers: usize,

    /// Whether to require finality certificate for snapshots
    pub require_finality: bool,

    /// Maximum age of snapshot in blocks
    pub max_snapshot_age: u64,

    /// Chunk download configuration
    pub download_config: ChunkDownloadConfig,

    /// How often to query peers for snapshots (seconds)
    pub discovery_interval_secs: u64,

    /// Request timeout for snapshot discovery
    pub discovery_timeout: Duration,

    /// Maximum concurrent snapshot queries
    pub max_concurrent_queries: usize,

    /// Whether to automatically restart on failure
    pub auto_restart: bool,

    /// Maximum number of automatic restart attempts
    pub max_restart_attempts: u32,

    /// Delay between restart attempts
    pub restart_delay: Duration,

    /// Whether to verify the final state root
    pub verify_final_state: bool,

    /// Progress reporting interval
    pub progress_interval: Duration,
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data/state-sync"),
            min_peers: 1,
            require_finality: true,
            max_snapshot_age: DEFAULT_SNAPSHOT_INTERVAL * 10,
            download_config: ChunkDownloadConfig::default(),
            discovery_interval_secs: 30,
            discovery_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrent_queries: 10,
            auto_restart: true,
            max_restart_attempts: 3,
            restart_delay: Duration::from_secs(5),
            verify_final_state: true,
            progress_interval: Duration::from_secs(1),
        }
    }
}

/// Current phase of state synchronization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {
    /// Not started or idle
    Idle,

    /// Discovering available snapshots
    Discovery,

    /// Selecting best snapshot
    Selection,

    /// Downloading chunks
    Downloading,

    /// Applying chunks to state
    Applying,

    /// Verifying final state
    Verifying,

    /// Sync completed successfully
    Completed,

    /// Sync failed
    Failed,

    /// Sync was cancelled
    Cancelled,
}

impl std::fmt::Display for SyncPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Discovery => write!(f, "discovery"),
            Self::Selection => write!(f, "selection"),
            Self::Downloading => write!(f, "downloading"),
            Self::Applying => write!(f, "applying"),
            Self::Verifying => write!(f, "verifying"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Current status of state synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Current sync phase
    pub phase: SyncPhase,

    /// Selected snapshot (if any)
    pub snapshot: Option<SnapshotMetadata>,

    /// Number of chunks downloaded
    pub chunks_downloaded: usize,

    /// Total number of chunks
    pub total_chunks: usize,

    /// Bytes downloaded
    pub bytes_downloaded: u64,

    /// Total bytes to download
    pub total_bytes: u64,

    /// Number of chunks applied
    pub chunks_applied: usize,

    /// Current download speed (bytes/sec)
    pub download_speed: f64,

    /// Estimated time remaining
    pub estimated_remaining: Duration,

    /// Time elapsed
    pub elapsed: Duration,

    /// Last error (if any)
    pub last_error: Option<String>,

    /// Number of restart attempts
    pub restart_attempts: u32,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            phase: SyncPhase::Idle,
            snapshot: None,
            chunks_downloaded: 0,
            total_chunks: 0,
            bytes_downloaded: 0,
            total_bytes: 0,
            chunks_applied: 0,
            download_speed: 0.0,
            estimated_remaining: Duration::ZERO,
            elapsed: Duration::ZERO,
            last_error: None,
            restart_attempts: 0,
        }
    }
}

impl SyncStatus {
    /// Get download progress as a percentage
    pub fn download_progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        (self.chunks_downloaded as f64 / self.total_chunks as f64) * 100.0
    }

    /// Get apply progress as a percentage
    pub fn apply_progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        (self.chunks_applied as f64 / self.total_chunks as f64) * 100.0
    }

    /// Get overall progress as a percentage
    pub fn overall_progress(&self) -> f64 {
        match self.phase {
            SyncPhase::Idle => 0.0,
            SyncPhase::Discovery => 5.0,
            SyncPhase::Selection => 10.0,
            SyncPhase::Downloading => 10.0 + self.download_progress() * 0.6,
            SyncPhase::Applying => 70.0 + self.apply_progress() * 0.25,
            SyncPhase::Verifying => 95.0,
            SyncPhase::Completed => 100.0,
            SyncPhase::Failed | SyncPhase::Cancelled => self.download_progress() * 0.7,
        }
    }

    /// Check if sync is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self.phase,
            SyncPhase::Discovery
                | SyncPhase::Selection
                | SyncPhase::Downloading
                | SyncPhase::Applying
                | SyncPhase::Verifying
        )
    }

    /// Check if sync is complete
    pub fn is_complete(&self) -> bool {
        self.phase == SyncPhase::Completed
    }

    /// Check if sync has failed
    pub fn is_failed(&self) -> bool {
        self.phase == SyncPhase::Failed
    }
}

/// Progress information for state sync
#[derive(Debug, Clone)]
pub struct SyncProgress {
    /// Current status
    pub status: SyncStatus,

    /// Start time
    pub started_at: Option<Instant>,

    /// End time
    pub ended_at: Option<Instant>,

    /// Number of peers queried
    pub peers_queried: usize,

    /// Number of snapshots discovered
    pub snapshots_discovered: usize,

    /// Active downloads
    pub active_downloads: usize,

    /// Failed chunks (will be retried)
    pub failed_chunks: usize,
}

impl SyncProgress {
    /// Create new progress tracker
    pub fn new() -> Self {
        Self {
            status: SyncStatus::default(),
            started_at: None,
            ended_at: None,
            peers_queried: 0,
            snapshots_discovered: 0,
            active_downloads: 0,
            failed_chunks: 0,
        }
    }

    /// Get formatted progress string
    pub fn format(&self) -> String {
        match self.status.phase {
            SyncPhase::Idle => "State sync idle".to_string(),
            SyncPhase::Discovery => format!(
                "Discovering snapshots... ({} peers queried, {} snapshots found)",
                self.peers_queried, self.snapshots_discovered
            ),
            SyncPhase::Selection => "Selecting best snapshot...".to_string(),
            SyncPhase::Downloading => format!(
                "Downloading chunks: {}/{} ({:.1}%) at {}/s",
                self.status.chunks_downloaded,
                self.status.total_chunks,
                self.status.download_progress(),
                format_bytes(self.status.download_speed as u64)
            ),
            SyncPhase::Applying => format!(
                "Applying chunks: {}/{} ({:.1}%)",
                self.status.chunks_applied,
                self.status.total_chunks,
                self.status.apply_progress()
            ),
            SyncPhase::Verifying => "Verifying final state...".to_string(),
            SyncPhase::Completed => format!(
                "State sync completed at height {} in {:?}",
                self.status.snapshot.as_ref().map(|s| s.height).unwrap_or(0),
                self.status.elapsed
            ),
            SyncPhase::Failed => format!(
                "State sync failed: {}",
                self.status.last_error.as_deref().unwrap_or("unknown error")
            ),
            SyncPhase::Cancelled => "State sync cancelled".to_string(),
        }
    }
}

impl Default for SyncProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Events emitted during state sync
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Sync started
    Started,

    /// Phase changed
    PhaseChanged {
        /// Previous phase
        from: SyncPhase,
        /// New phase
        to: SyncPhase,
    },

    /// Snapshot selected
    SnapshotSelected {
        /// Selected snapshot height
        height: u64,
        /// State root
        state_root: Hash,
        /// Number of chunks
        chunk_count: u64,
    },

    /// Chunk download progress
    DownloadProgress {
        /// Chunks downloaded
        downloaded: usize,
        /// Total chunks
        total: usize,
        /// Bytes downloaded
        bytes: u64,
        /// Speed in bytes/sec
        speed: f64,
    },

    /// Chunk application progress
    ApplyProgress {
        /// Chunks applied
        applied: usize,
        /// Total chunks
        total: usize,
    },

    /// Sync completed
    Completed {
        /// Final height
        height: u64,
        /// Time taken
        duration: Duration,
    },

    /// Sync failed
    Failed {
        /// Error message
        error: String,
    },

    /// Sync cancelled
    Cancelled,

    /// Restarting after failure
    Restarting {
        /// Attempt number
        attempt: u32,
    },
}

/// Errors that can occur during state synchronization
#[derive(Debug, Clone, Error)]
pub enum StateSyncError {
    /// No snapshots available
    #[error("no snapshots available")]
    NoSnapshots,

    /// No suitable snapshot found
    #[error("no suitable snapshot found")]
    NoSuitableSnapshot,

    /// Snapshot verification failed
    #[error("snapshot verification failed: {0}")]
    SnapshotVerification(String),

    /// Chunk download failed
    #[error("chunk download failed: {0}")]
    ChunkDownload(String),

    /// Chunk verification failed
    #[error("chunk verification failed: {0}")]
    ChunkVerification(String),

    /// State application failed
    #[error("state application failed: {0}")]
    StateApplication(String),

    /// Final state verification failed
    #[error("final state verification failed: expected {expected:?}, got {actual:?}")]
    FinalStateVerification {
        /// Expected state root
        expected: Hash,
        /// Actual state root
        actual: Hash,
    },

    /// Network error
    #[error("network error: {0}")]
    Network(String),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Sync was cancelled
    #[error("sync cancelled")]
    Cancelled,

    /// Already syncing
    #[error("sync already in progress")]
    AlreadySyncing,

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Trait for network operations needed by state sync
#[async_trait::async_trait]
pub trait SyncNetwork: ChunkNetwork + Send + Sync {
    /// Request snapshot list from a peer
    async fn request_snapshots(
        &self,
        peer: PeerId,
        request: SnapshotRequest,
    ) -> Result<SnapshotList, String>;

    /// Get all connected peers
    fn get_peers(&self) -> Vec<PeerId>;

    /// Get the current block height from peers
    fn get_peer_height(&self) -> u64;
}

/// Trait for state storage operations
#[async_trait::async_trait]
pub trait StateStorage: Send + Sync {
    /// Apply a state chunk to the database
    async fn apply_chunk(&self, chunk: &StateChunk) -> Result<(), String>;

    /// Get the current state root
    fn state_root(&self) -> Hash;

    /// Begin a state sync session
    async fn begin_sync(&self, snapshot: &SnapshotMetadata) -> Result<(), String>;

    /// Commit the synced state
    async fn commit_sync(&self) -> Result<(), String>;

    /// Rollback a failed sync
    async fn rollback_sync(&self) -> Result<(), String>;

    /// Check if we have a partial sync to resume
    async fn get_resume_state(&self) -> Option<SyncResumeState>;

    /// Save sync progress for resume
    async fn save_progress(&self, state: &SyncResumeState) -> Result<(), String>;

    /// Clear saved progress
    async fn clear_progress(&self) -> Result<(), String>;
}

/// State for resuming a partial sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResumeState {
    /// Snapshot being synced
    pub snapshot: SnapshotMetadata,

    /// Finality certificate
    pub finality_cert: Option<FinalityCertificate>,

    /// Downloaded chunk indices
    pub downloaded_chunks: HashSet<u64>,

    /// Applied chunk indices
    pub applied_chunks: HashSet<u64>,

    /// Last update timestamp
    pub updated_at: u64,
}

impl SyncResumeState {
    /// Create new resume state
    pub fn new(snapshot: SnapshotMetadata, finality_cert: Option<FinalityCertificate>) -> Self {
        Self {
            snapshot,
            finality_cert,
            downloaded_chunks: HashSet::new(),
            applied_chunks: HashSet::new(),
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        }
    }

    /// Mark a chunk as downloaded
    pub fn mark_downloaded(&mut self, chunk_index: u64) {
        self.downloaded_chunks.insert(chunk_index);
        self.update_timestamp();
    }

    /// Mark a chunk as applied
    pub fn mark_applied(&mut self, chunk_index: u64) {
        self.applied_chunks.insert(chunk_index);
        self.update_timestamp();
    }

    /// Get chunks that need to be downloaded
    pub fn pending_download(&self) -> Vec<u64> {
        (0..self.snapshot.chunk_count)
            .filter(|i| !self.downloaded_chunks.contains(i))
            .collect()
    }

    /// Get chunks that need to be applied
    pub fn pending_apply(&self) -> Vec<u64> {
        self.downloaded_chunks
            .iter()
            .filter(|i| !self.applied_chunks.contains(*i))
            .copied()
            .collect()
    }

    /// Check if all chunks are downloaded
    pub fn all_downloaded(&self) -> bool {
        self.downloaded_chunks.len() == self.snapshot.chunk_count as usize
    }

    /// Check if all chunks are applied
    pub fn all_applied(&self) -> bool {
        self.applied_chunks.len() == self.snapshot.chunk_count as usize
    }

    fn update_timestamp(&mut self) {
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
    }
}

/// State synchronization manager
///
/// Coordinates the entire state sync process including discovery,
/// download, verification, and application of state snapshots.
pub struct StateSyncManager<N: SyncNetwork, S: StateStorage> {
    /// Configuration
    config: StateSyncConfig,

    /// Network interface
    network: Arc<N>,

    /// State storage interface
    storage: Arc<S>,

    /// Current sync status
    status: Arc<RwLock<SyncStatus>>,

    /// Sync progress
    progress: Arc<RwLock<SyncProgress>>,

    /// Available snapshots from peers
    availability: Arc<RwLock<SnapshotAvailability>>,

    /// Event broadcaster
    event_tx: broadcast::Sender<SyncEvent>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,

    /// Currently running sync task
    sync_task: Arc<Mutex<Option<tokio::task::JoinHandle<Result<(), StateSyncError>>>>>,

    /// Downloaded chunks awaiting application
    pending_chunks: Arc<RwLock<HashMap<u64, StateChunk>>>,

    /// Resume state (if any)
    resume_state: Arc<RwLock<Option<SyncResumeState>>>,
}

impl<N: SyncNetwork + 'static, S: StateStorage + 'static> StateSyncManager<N, S> {
    /// Create a new state sync manager
    pub fn new(config: StateSyncConfig, network: Arc<N>, storage: Arc<S>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            config,
            network,
            storage,
            status: Arc::new(RwLock::new(SyncStatus::default())),
            progress: Arc::new(RwLock::new(SyncProgress::new())),
            availability: Arc::new(RwLock::new(SnapshotAvailability::new())),
            event_tx,
            shutdown: Arc::new(RwLock::new(false)),
            sync_task: Arc::new(Mutex::new(None)),
            pending_chunks: Arc::new(RwLock::new(HashMap::new())),
            resume_state: Arc::new(RwLock::new(None)),
        }
    }

    /// Get an event receiver
    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_tx.subscribe()
    }

    /// Get current sync status
    pub async fn status(&self) -> SyncStatus {
        self.status.read().await.clone()
    }

    /// Get current progress
    pub async fn progress(&self) -> SyncProgress {
        self.progress.read().await.clone()
    }

    /// Check if sync is in progress
    pub async fn is_syncing(&self) -> bool {
        self.status.read().await.is_in_progress()
    }

    /// Check if sync is complete
    pub async fn is_complete(&self) -> bool {
        self.status.read().await.is_complete()
    }

    /// Start state synchronization
    pub async fn start_sync(&self) -> Result<(), StateSyncError> {
        // Check if already syncing
        if self.is_syncing().await {
            return Err(StateSyncError::AlreadySyncing);
        }

        // Reset shutdown flag
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = false;
        }

        // Check for resume state
        let resume_state = self.storage.get_resume_state().await;
        if let Some(state) = resume_state {
            info!(
                "Found partial sync to resume at height {}",
                state.snapshot.height
            );
            let mut resume = self.resume_state.write().await;
            *resume = Some(state);
        }

        // Update status
        self.set_phase(SyncPhase::Discovery).await;

        // Send started event
        let _ = self.event_tx.send(SyncEvent::Started);

        // Start sync in background
        let manager = self.clone_inner();
        let handle = tokio::spawn(async move {
            manager.run_sync().await
        });

        let mut task = self.sync_task.lock().await;
        *task = Some(handle);

        Ok(())
    }

    /// Stop state synchronization
    pub async fn stop(&self) {
        // Set shutdown flag
        {
            let mut shutdown = self.shutdown.write().await;
            *shutdown = true;
        }

        // Cancel running task
        let mut task = self.sync_task.lock().await;
        if let Some(handle) = task.take() {
            handle.abort();
        }

        // Update status
        self.set_phase(SyncPhase::Cancelled).await;

        let _ = self.event_tx.send(SyncEvent::Cancelled);
    }

    /// Run the sync process
    fn run_sync(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StateSyncError>> + Send + '_>> {
        Box::pin(async move {
        let start_time = Instant::now();

        // Update progress start time
        {
            let mut progress = self.progress.write().await;
            progress.started_at = Some(start_time);
        }

        let result = self.do_sync().await;

        // Update end time
        {
            let mut progress = self.progress.write().await;
            progress.ended_at = Some(Instant::now());
        }

        match &result {
            Ok(()) => {
                self.set_phase(SyncPhase::Completed).await;

                let status = self.status.read().await;
                let _ = self.event_tx.send(SyncEvent::Completed {
                    height: status.snapshot.as_ref().map(|s| s.height).unwrap_or(0),
                    duration: start_time.elapsed(),
                });

                // Clear saved progress
                let _ = self.storage.clear_progress().await;
            }
            Err(e) => {
                let error_str = e.to_string();

                {
                    let mut status = self.status.write().await;
                    status.last_error = Some(error_str.clone());
                }

                // Check if we should retry
                let should_retry = self.config.auto_restart && !matches!(e, StateSyncError::Cancelled);

                if should_retry {
                    let mut status = self.status.write().await;
                    if status.restart_attempts < self.config.max_restart_attempts {
                        status.restart_attempts += 1;
                        let attempt = status.restart_attempts;
                        drop(status);

                        let _ = self.event_tx.send(SyncEvent::Restarting { attempt });

                        tokio::time::sleep(self.config.restart_delay).await;

                        // Recursive retry
                        return self.run_sync().await;
                    }
                }

                self.set_phase(SyncPhase::Failed).await;
                let _ = self.event_tx.send(SyncEvent::Failed { error: error_str });

                // Rollback state
                let _ = self.storage.rollback_sync().await;
            }
        }

        result
        }) // End of Box::pin async block
    }

    /// Execute the sync process
    async fn do_sync(&self) -> Result<(), StateSyncError> {
        // Check for shutdown
        self.check_shutdown().await?;

        // Phase 1: Discovery
        self.set_phase(SyncPhase::Discovery).await;
        self.discover_snapshots().await?;

        self.check_shutdown().await?;

        // Phase 2: Selection
        self.set_phase(SyncPhase::Selection).await;
        let (snapshot, finality_cert) = self.select_snapshot().await?;

        // Initialize sync with storage
        self.storage
            .begin_sync(&snapshot)
            .await
            .map_err(|e| StateSyncError::Storage(e))?;

        // Update status with selected snapshot
        {
            let mut status = self.status.write().await;
            status.snapshot = Some(snapshot.clone());
            status.total_chunks = snapshot.chunk_count as usize;
            status.total_bytes = snapshot.total_size;
        }

        let _ = self.event_tx.send(SyncEvent::SnapshotSelected {
            height: snapshot.height,
            state_root: snapshot.state_root,
            chunk_count: snapshot.chunk_count,
        });

        // Create or update resume state
        let resume_state = {
            let existing = self.resume_state.read().await;
            if let Some(ref state) = *existing {
                if state.snapshot.snapshot_id() == snapshot.snapshot_id() {
                    state.clone()
                } else {
                    SyncResumeState::new(snapshot.clone(), finality_cert.clone())
                }
            } else {
                SyncResumeState::new(snapshot.clone(), finality_cert.clone())
            }
        };

        {
            let mut resume = self.resume_state.write().await;
            *resume = Some(resume_state.clone());
        }

        self.check_shutdown().await?;

        // Phase 3: Download chunks
        self.set_phase(SyncPhase::Downloading).await;
        self.download_chunks(&snapshot, &resume_state).await?;

        self.check_shutdown().await?;

        // Phase 4: Apply chunks
        self.set_phase(SyncPhase::Applying).await;
        self.apply_chunks(&snapshot).await?;

        self.check_shutdown().await?;

        // Phase 5: Verify final state
        if self.config.verify_final_state {
            self.set_phase(SyncPhase::Verifying).await;
            self.verify_final_state(&snapshot).await?;
        }

        // Commit the synced state
        self.storage
            .commit_sync()
            .await
            .map_err(|e| StateSyncError::Storage(e))?;

        Ok(())
    }

    /// Discover available snapshots from peers
    async fn discover_snapshots(&self) -> Result<(), StateSyncError> {
        info!("Discovering available snapshots...");

        let peers = self.network.get_peers();
        if peers.is_empty() {
            return Err(StateSyncError::Network("no peers available".to_string()));
        }

        let current_height = self.network.get_peer_height();
        let min_height = if self.config.max_snapshot_age > 0 {
            current_height.saturating_sub(self.config.max_snapshot_age)
        } else {
            0
        };

        let request = SnapshotRequest::from_height(min_height);

        // Query peers in parallel
        let mut tasks = Vec::new();

        for peer in peers.iter().take(self.config.max_concurrent_queries) {
            let network = Arc::clone(&self.network);
            let peer = *peer;
            let request = request.clone();
            let timeout = self.config.discovery_timeout;

            let task = tokio::spawn(async move {
                let result = tokio::time::timeout(
                    timeout,
                    network.request_snapshots(peer, request),
                )
                .await;

                (peer, result)
            });

            tasks.push(task);
        }

        // Collect results
        let mut peers_queried = 0;
        let mut snapshots_found = 0;

        for task in tasks {
            match task.await {
                Ok((peer, Ok(Ok(list)))) => {
                    peers_queried += 1;

                    let mut availability = self.availability.write().await;
                    for entry in list.snapshots {
                        availability.add_snapshot(entry, peer);
                        snapshots_found += 1;
                    }
                }
                Ok((peer, Ok(Err(e)))) => {
                    debug!("Peer {:?} returned error: {}", peer, e);
                    peers_queried += 1;
                }
                Ok((_, Err(_))) => {
                    debug!("Snapshot request timed out");
                    peers_queried += 1;
                }
                Err(e) => {
                    warn!("Snapshot discovery task failed: {:?}", e);
                }
            }
        }

        // Update progress
        {
            let mut progress = self.progress.write().await;
            progress.peers_queried = peers_queried;
            progress.snapshots_discovered = snapshots_found;
        }

        info!(
            "Discovered {} snapshots from {} peers",
            snapshots_found, peers_queried
        );

        if snapshots_found == 0 {
            return Err(StateSyncError::NoSnapshots);
        }

        Ok(())
    }

    /// Select the best snapshot
    async fn select_snapshot(
        &self,
    ) -> Result<(SnapshotMetadata, Option<FinalityCertificate>), StateSyncError> {
        info!("Selecting best snapshot...");

        let current_height = self.network.get_peer_height();

        let selector = SnapshotSelector::new(current_height)
            .with_min_peers(self.config.min_peers)
            .with_finality(self.config.require_finality);

        let availability = self.availability.read().await;
        let snapshots: Vec<_> = availability.all_snapshots().into_iter().cloned().collect();

        if snapshots.is_empty() {
            return Err(StateSyncError::NoSnapshots);
        }

        // Convert to owned vec for selection
        let best = selector.select_best(&snapshots);

        match best {
            Some(info) => {
                info!(
                    "Selected snapshot at height {} with {} peers",
                    info.metadata.height,
                    info.peer_count()
                );

                Ok((info.metadata.clone(), info.finality_cert.clone()))
            }
            None => Err(StateSyncError::NoSuitableSnapshot),
        }
    }

    /// Download all chunks
    async fn download_chunks(
        &self,
        snapshot: &SnapshotMetadata,
        resume_state: &SyncResumeState,
    ) -> Result<(), StateSyncError> {
        info!("Downloading {} chunks...", snapshot.chunk_count);

        // Create chunk downloader
        let downloader = ChunkDownloader::new(
            Arc::clone(&self.network),
            self.config.download_config.clone(),
            snapshot.height,
            snapshot.state_root,
            snapshot.chunk_hashes.clone(),
        );

        // Start downloading
        let download_result = downloader.start().await;

        // Get downloaded chunks
        let chunks = downloader.get_chunks().await;

        // Store chunks for application
        {
            let mut pending = self.pending_chunks.write().await;
            *pending = chunks;
        }

        // Update status
        let progress = downloader.progress().await;
        {
            let mut status = self.status.write().await;
            status.chunks_downloaded = progress.completed;
            status.bytes_downloaded = progress.bytes_downloaded;
            status.download_speed = progress.bytes_per_second();
        }

        match download_result {
            Ok(()) => Ok(()),
            Err(ChunkDownloadError::IncompletDownload { missing }) => {
                Err(StateSyncError::ChunkDownload(format!(
                    "{} chunks failed to download",
                    missing
                )))
            }
            Err(e) => Err(StateSyncError::ChunkDownload(e.to_string())),
        }
    }

    /// Apply downloaded chunks to state
    async fn apply_chunks(&self, snapshot: &SnapshotMetadata) -> Result<(), StateSyncError> {
        info!("Applying {} chunks to state...", snapshot.chunk_count);

        let chunks = self.pending_chunks.read().await.clone();

        // Apply chunks in order
        for chunk_index in 0..snapshot.chunk_count {
            self.check_shutdown().await?;

            let chunk = chunks.get(&chunk_index).ok_or_else(|| {
                StateSyncError::ChunkDownload(format!("missing chunk {}", chunk_index))
            })?;

            // Apply to storage
            self.storage
                .apply_chunk(chunk)
                .await
                .map_err(|e| StateSyncError::StateApplication(e))?;

            // Update status
            {
                let mut status = self.status.write().await;
                status.chunks_applied = (chunk_index + 1) as usize;
            }

            // Update resume state
            {
                let mut resume = self.resume_state.write().await;
                if let Some(ref mut state) = *resume {
                    state.mark_applied(chunk_index);
                }
            }

            // Periodic save
            if chunk_index % 100 == 0 {
                if let Some(state) = self.resume_state.read().await.clone() {
                    let _ = self.storage.save_progress(&state).await;
                }

                // Send progress event
                let _ = self.event_tx.send(SyncEvent::ApplyProgress {
                    applied: (chunk_index + 1) as usize,
                    total: snapshot.chunk_count as usize,
                });
            }
        }

        info!("All chunks applied successfully");
        Ok(())
    }

    /// Verify the final state root
    async fn verify_final_state(&self, snapshot: &SnapshotMetadata) -> Result<(), StateSyncError> {
        info!("Verifying final state root...");

        let actual_root = self.storage.state_root();

        if actual_root != snapshot.state_root {
            error!(
                "State root mismatch: expected {:?}, got {:?}",
                snapshot.state_root, actual_root
            );

            return Err(StateSyncError::FinalStateVerification {
                expected: snapshot.state_root,
                actual: actual_root,
            });
        }

        info!("Final state verified successfully");
        Ok(())
    }

    /// Set the current sync phase
    async fn set_phase(&self, phase: SyncPhase) {
        let old_phase = {
            let mut status = self.status.write().await;
            let old = status.phase;
            status.phase = phase;
            old
        };

        {
            let mut progress = self.progress.write().await;
            progress.status.phase = phase;
        }

        if old_phase != phase {
            let _ = self.event_tx.send(SyncEvent::PhaseChanged {
                from: old_phase,
                to: phase,
            });
        }
    }

    /// Check if shutdown was requested
    async fn check_shutdown(&self) -> Result<(), StateSyncError> {
        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }
        Ok(())
    }

    /// Clone the inner Arc references for spawning tasks
    fn clone_inner(&self) -> StateSyncManagerInner<N, S> {
        StateSyncManagerInner {
            config: self.config.clone(),
            network: Arc::clone(&self.network),
            storage: Arc::clone(&self.storage),
            status: Arc::clone(&self.status),
            progress: Arc::clone(&self.progress),
            availability: Arc::clone(&self.availability),
            event_tx: self.event_tx.clone(),
            shutdown: Arc::clone(&self.shutdown),
            pending_chunks: Arc::clone(&self.pending_chunks),
            resume_state: Arc::clone(&self.resume_state),
        }
    }
}

/// Inner state for spawned tasks
struct StateSyncManagerInner<N: SyncNetwork, S: StateStorage> {
    config: StateSyncConfig,
    network: Arc<N>,
    storage: Arc<S>,
    status: Arc<RwLock<SyncStatus>>,
    progress: Arc<RwLock<SyncProgress>>,
    availability: Arc<RwLock<SnapshotAvailability>>,
    event_tx: broadcast::Sender<SyncEvent>,
    shutdown: Arc<RwLock<bool>>,
    pending_chunks: Arc<RwLock<HashMap<u64, StateChunk>>>,
    resume_state: Arc<RwLock<Option<SyncResumeState>>>,
}

impl<N: SyncNetwork + 'static, S: StateStorage + 'static> StateSyncManagerInner<N, S> {
    async fn run_sync(&self) -> Result<(), StateSyncError> {
        // Delegate to a method that mirrors StateSyncManager's do_sync
        // For simplicity, we'll just implement the basic flow here

        // Check for shutdown
        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }

        // Phase 1: Discovery
        self.set_phase(SyncPhase::Discovery).await;
        self.discover_snapshots().await?;

        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }

        // Phase 2: Selection
        self.set_phase(SyncPhase::Selection).await;
        let (snapshot, finality_cert) = self.select_snapshot().await?;

        // Initialize sync with storage
        self.storage
            .begin_sync(&snapshot)
            .await
            .map_err(StateSyncError::Storage)?;

        // Update status with selected snapshot
        {
            let mut status = self.status.write().await;
            status.snapshot = Some(snapshot.clone());
            status.total_chunks = snapshot.chunk_count as usize;
            status.total_bytes = snapshot.total_size;
        }

        let _ = self.event_tx.send(SyncEvent::SnapshotSelected {
            height: snapshot.height,
            state_root: snapshot.state_root,
            chunk_count: snapshot.chunk_count,
        });

        // Create resume state
        let resume_state = SyncResumeState::new(snapshot.clone(), finality_cert);
        {
            let mut resume = self.resume_state.write().await;
            *resume = Some(resume_state.clone());
        }

        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }

        // Phase 3: Download chunks
        self.set_phase(SyncPhase::Downloading).await;
        self.download_chunks(&snapshot, &resume_state).await?;

        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }

        // Phase 4: Apply chunks
        self.set_phase(SyncPhase::Applying).await;
        self.apply_chunks(&snapshot).await?;

        if *self.shutdown.read().await {
            return Err(StateSyncError::Cancelled);
        }

        // Phase 5: Verify final state
        if self.config.verify_final_state {
            self.set_phase(SyncPhase::Verifying).await;
            self.verify_final_state(&snapshot).await?;
        }

        // Commit the synced state
        self.storage
            .commit_sync()
            .await
            .map_err(StateSyncError::Storage)?;

        self.set_phase(SyncPhase::Completed).await;

        Ok(())
    }

    async fn set_phase(&self, phase: SyncPhase) {
        let old_phase = {
            let mut status = self.status.write().await;
            let old = status.phase;
            status.phase = phase;
            old
        };

        {
            let mut progress = self.progress.write().await;
            progress.status.phase = phase;
        }

        if old_phase != phase {
            let _ = self.event_tx.send(SyncEvent::PhaseChanged {
                from: old_phase,
                to: phase,
            });
        }
    }

    async fn discover_snapshots(&self) -> Result<(), StateSyncError> {
        let peers = self.network.get_peers();
        if peers.is_empty() {
            return Err(StateSyncError::Network("no peers available".to_string()));
        }

        let current_height = self.network.get_peer_height();
        let min_height = if self.config.max_snapshot_age > 0 {
            current_height.saturating_sub(self.config.max_snapshot_age)
        } else {
            0
        };

        let request = SnapshotRequest::from_height(min_height);

        let mut tasks = Vec::new();
        for peer in peers.iter().take(self.config.max_concurrent_queries) {
            let network = Arc::clone(&self.network);
            let peer = *peer;
            let request = request.clone();
            let timeout = self.config.discovery_timeout;

            let task = tokio::spawn(async move {
                let result = tokio::time::timeout(
                    timeout,
                    network.request_snapshots(peer, request),
                ).await;
                (peer, result)
            });

            tasks.push(task);
        }

        let mut peers_queried = 0;
        let mut snapshots_found = 0;

        for task in tasks {
            if let Ok((peer, Ok(Ok(list)))) = task.await {
                peers_queried += 1;
                let mut availability = self.availability.write().await;
                for entry in list.snapshots {
                    availability.add_snapshot(entry, peer);
                    snapshots_found += 1;
                }
            } else {
                peers_queried += 1;
            }
        }

        {
            let mut progress = self.progress.write().await;
            progress.peers_queried = peers_queried;
            progress.snapshots_discovered = snapshots_found;
        }

        if snapshots_found == 0 {
            return Err(StateSyncError::NoSnapshots);
        }

        Ok(())
    }

    async fn select_snapshot(
        &self,
    ) -> Result<(SnapshotMetadata, Option<FinalityCertificate>), StateSyncError> {
        let current_height = self.network.get_peer_height();

        let selector = SnapshotSelector::new(current_height)
            .with_min_peers(self.config.min_peers)
            .with_finality(self.config.require_finality);

        let availability = self.availability.read().await;
        let snapshots: Vec<_> = availability.all_snapshots().into_iter().cloned().collect();

        if snapshots.is_empty() {
            return Err(StateSyncError::NoSnapshots);
        }

        match selector.select_best(&snapshots) {
            Some(info) => Ok((info.metadata.clone(), info.finality_cert.clone())),
            None => Err(StateSyncError::NoSuitableSnapshot),
        }
    }

    async fn download_chunks(
        &self,
        snapshot: &SnapshotMetadata,
        _resume_state: &SyncResumeState,
    ) -> Result<(), StateSyncError> {
        let downloader = ChunkDownloader::new(
            Arc::clone(&self.network),
            self.config.download_config.clone(),
            snapshot.height,
            snapshot.state_root,
            snapshot.chunk_hashes.clone(),
        );

        let download_result = downloader.start().await;
        let chunks = downloader.get_chunks().await;

        {
            let mut pending = self.pending_chunks.write().await;
            *pending = chunks;
        }

        let progress = downloader.progress().await;
        {
            let mut status = self.status.write().await;
            status.chunks_downloaded = progress.completed;
            status.bytes_downloaded = progress.bytes_downloaded;
            status.download_speed = progress.bytes_per_second();
        }

        match download_result {
            Ok(()) => Ok(()),
            Err(ChunkDownloadError::IncompletDownload { missing }) => {
                Err(StateSyncError::ChunkDownload(format!(
                    "{} chunks failed to download",
                    missing
                )))
            }
            Err(e) => Err(StateSyncError::ChunkDownload(e.to_string())),
        }
    }

    async fn apply_chunks(&self, snapshot: &SnapshotMetadata) -> Result<(), StateSyncError> {
        let chunks = self.pending_chunks.read().await.clone();

        for chunk_index in 0..snapshot.chunk_count {
            if *self.shutdown.read().await {
                return Err(StateSyncError::Cancelled);
            }

            let chunk = chunks.get(&chunk_index).ok_or_else(|| {
                StateSyncError::ChunkDownload(format!("missing chunk {}", chunk_index))
            })?;

            self.storage
                .apply_chunk(chunk)
                .await
                .map_err(StateSyncError::StateApplication)?;

            {
                let mut status = self.status.write().await;
                status.chunks_applied = (chunk_index + 1) as usize;
            }

            {
                let mut resume = self.resume_state.write().await;
                if let Some(ref mut state) = *resume {
                    state.mark_applied(chunk_index);
                }
            }

            if chunk_index % 100 == 0 {
                if let Some(state) = self.resume_state.read().await.clone() {
                    let _ = self.storage.save_progress(&state).await;
                }

                let _ = self.event_tx.send(SyncEvent::ApplyProgress {
                    applied: (chunk_index + 1) as usize,
                    total: snapshot.chunk_count as usize,
                });
            }
        }

        Ok(())
    }

    async fn verify_final_state(&self, snapshot: &SnapshotMetadata) -> Result<(), StateSyncError> {
        let actual_root = self.storage.state_root();

        if actual_root != snapshot.state_root {
            return Err(StateSyncError::FinalStateVerification {
                expected: snapshot.state_root,
                actual: actual_root,
            });
        }

        Ok(())
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

