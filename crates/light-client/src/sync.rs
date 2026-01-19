//! Light Client Synchronization
//!
//! This module handles synchronization of block headers for the light client.
//! It supports:
//!
//! - Sync from trusted checkpoint or genesis
//! - Header chain verification
//! - Checkpoint-based fast sync
//! - Graceful handling of reorgs (shouldn't happen with BFT)
//!
//! ## Sync Protocol
//!
//! 1. Initialize from a trusted checkpoint
//! 2. Request headers from peers starting from checkpoint
//! 3. Verify each header's finality certificate
//! 4. Store verified headers
//! 5. Update validator set at epoch boundaries
//!
//! ## Security
//!
//! The sync process maintains security by:
//! - Always verifying finality certificates (>2/3 stake signatures)
//! - Tracking validator set changes across epochs
//! - Rejecting headers that don't build on the verified chain

use crate::client::{
    Checkpoint, FinalityCertificate, HeaderChain, LightBlockHeader, LightClient, ValidatorSet,
    ValidatorTracker,
};
use crate::constants::MAX_HEADERS_PER_SYNC;
use crate::types::{BlockHeight, Epoch, Hash};
use crate::{Error, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Maximum headers to request per batch
    pub batch_size: usize,
    /// Timeout for header requests
    pub request_timeout: Duration,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// Retry attempts for failed requests
    pub max_retries: u32,
    /// Interval between sync attempts
    pub sync_interval: Duration,
    /// Enable checkpoint sync
    pub checkpoint_sync: bool,
    /// Minimum checkpoint height for fast sync
    pub min_checkpoint_height: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: MAX_HEADERS_PER_SYNC,
            request_timeout: Duration::from_secs(10),
            max_concurrent_requests: 4,
            max_retries: 3,
            sync_interval: Duration::from_secs(12), // ~1 block time
            checkpoint_sync: true,
            min_checkpoint_height: 1000,
        }
    }
}

/// Current sync state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Looking for peers
    FindingPeers,
    /// Syncing headers from checkpoint
    SyncingFromCheckpoint,
    /// Syncing headers sequentially
    SyncingHeaders,
    /// Verifying the chain
    Verifying,
    /// Fully synced
    Synced,
    /// Sync failed
    Failed,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::Idle => write!(f, "Idle"),
            SyncState::FindingPeers => write!(f, "Finding Peers"),
            SyncState::SyncingFromCheckpoint => write!(f, "Syncing from Checkpoint"),
            SyncState::SyncingHeaders => write!(f, "Syncing Headers"),
            SyncState::Verifying => write!(f, "Verifying"),
            SyncState::Synced => write!(f, "Synced"),
            SyncState::Failed => write!(f, "Failed"),
        }
    }
}

/// Sync status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Current sync state
    pub state: SyncState,
    /// Starting height
    pub start_height: BlockHeight,
    /// Current height
    pub current_height: BlockHeight,
    /// Target height (if known)
    pub target_height: Option<BlockHeight>,
    /// Number of peers
    pub peer_count: usize,
    /// Headers synced in current session
    pub headers_synced: u64,
    /// Average sync speed (headers/second)
    pub sync_speed: f64,
    /// Time elapsed
    pub elapsed: Duration,
    /// Estimated time remaining
    pub eta: Option<Duration>,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: SyncState::Idle,
            start_height: 0,
            current_height: 0,
            target_height: None,
            peer_count: 0,
            headers_synced: 0,
            sync_speed: 0.0,
            elapsed: Duration::ZERO,
            eta: None,
        }
    }
}

impl SyncStatus {
    /// Calculate sync progress as percentage
    pub fn progress(&self) -> f64 {
        match self.target_height {
            Some(target) if target > self.start_height => {
                let done = self.current_height.saturating_sub(self.start_height) as f64;
                let total = target.saturating_sub(self.start_height) as f64;
                (done / total * 100.0).min(100.0)
            }
            _ => 0.0,
        }
    }

    /// Check if sync is complete
    pub fn is_synced(&self) -> bool {
        self.state == SyncState::Synced
    }

    /// Check if sync failed
    pub fn is_failed(&self) -> bool {
        self.state == SyncState::Failed
    }
}

/// Error types specific to sync operations
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// No peers available
    #[error("no peers available for sync")]
    NoPeers,

    /// Request timed out
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// Invalid response from peer
    #[error("invalid response from peer {peer}: {reason}")]
    InvalidResponse {
        /// Peer identifier
        peer: String,
        /// Reason for invalidity
        reason: String,
    },

    /// Header verification failed
    #[error("header verification failed at height {height}: {reason}")]
    VerificationFailed {
        /// Block height
        height: BlockHeight,
        /// Failure reason
        reason: String,
    },

    /// Chain discontinuity
    #[error("chain discontinuity at height {height}")]
    ChainDiscontinuity {
        /// Height where discontinuity was found
        height: BlockHeight,
    },

    /// Reorg detected
    #[error("reorg detected at height {height}")]
    ReorgDetected {
        /// Height where reorg was detected
        height: BlockHeight,
    },

    /// Checkpoint invalid
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),

    /// Max retries exceeded
    #[error("max retries exceeded for height {0}")]
    MaxRetriesExceeded(BlockHeight),

    /// Sync cancelled
    #[error("sync cancelled")]
    Cancelled,
}

impl From<SyncError> for Error {
    fn from(e: SyncError) -> Self {
        Error::SyncError(e.to_string())
    }
}

/// Header with its finality certificate for sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHeader {
    /// The block header
    pub header: LightBlockHeader,
    /// Finality certificate
    pub finality_cert: FinalityCertificate,
}

impl SyncHeader {
    /// Create a new sync header
    pub fn new(header: LightBlockHeader, finality_cert: FinalityCertificate) -> Self {
        Self {
            header,
            finality_cert,
        }
    }

    /// Get the block height
    pub fn height(&self) -> BlockHeight {
        self.header.number
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.header.hash
    }
}

/// Trait for fetching headers from peers
#[async_trait]
pub trait HeaderFetcher: Send + Sync {
    /// Fetch headers starting from a height
    async fn fetch_headers(
        &self,
        start_height: BlockHeight,
        count: usize,
    ) -> Result<Vec<SyncHeader>>;

    /// Fetch a specific checkpoint
    async fn fetch_checkpoint(&self, height: BlockHeight) -> Result<Option<Checkpoint>>;

    /// Get the latest known height from peers
    async fn get_latest_height(&self) -> Result<BlockHeight>;

    /// Get the number of connected peers
    fn peer_count(&self) -> usize;
}

/// Simple in-memory header fetcher for testing
#[derive(Default)]
pub struct MockHeaderFetcher {
    headers: RwLock<HashMap<BlockHeight, SyncHeader>>,
    checkpoints: RwLock<HashMap<BlockHeight, Checkpoint>>,
    latest_height: RwLock<BlockHeight>,
}

impl MockHeaderFetcher {
    /// Create a new mock fetcher
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a header for fetching
    pub fn add_header(&self, header: SyncHeader) {
        let height = header.height();
        self.headers.write().insert(height, header);

        let mut latest = self.latest_height.write();
        if height > *latest {
            *latest = height;
        }
    }

    /// Add a checkpoint
    pub fn add_checkpoint(&self, checkpoint: Checkpoint) {
        let height = checkpoint.header.number;
        self.checkpoints.write().insert(height, checkpoint);
    }
}

#[async_trait]
impl HeaderFetcher for MockHeaderFetcher {
    async fn fetch_headers(
        &self,
        start_height: BlockHeight,
        count: usize,
    ) -> Result<Vec<SyncHeader>> {
        let headers = self.headers.read();
        let mut result = Vec::with_capacity(count);

        for height in start_height..start_height + count as u64 {
            if let Some(header) = headers.get(&height) {
                result.push(header.clone());
            } else {
                break;
            }
        }

        Ok(result)
    }

    async fn fetch_checkpoint(&self, height: BlockHeight) -> Result<Option<Checkpoint>> {
        Ok(self.checkpoints.read().get(&height).cloned())
    }

    async fn get_latest_height(&self) -> Result<BlockHeight> {
        Ok(*self.latest_height.read())
    }

    fn peer_count(&self) -> usize {
        1
    }
}

/// Header sync manager
pub struct HeaderSync<F: HeaderFetcher> {
    /// Configuration
    config: SyncConfig,
    /// Header fetcher
    fetcher: Arc<F>,
    /// Verified header chain
    headers: Arc<RwLock<HeaderChain>>,
    /// Validator tracker
    validators: Arc<RwLock<ValidatorTracker>>,
    /// Current sync status
    status: Arc<RwLock<SyncStatus>>,
    /// Pending header requests
    pending_requests: Arc<RwLock<HashSet<BlockHeight>>>,
    /// Headers waiting to be processed
    pending_headers: Arc<RwLock<VecDeque<SyncHeader>>>,
    /// Cancel flag
    cancelled: Arc<RwLock<bool>>,
}

impl<F: HeaderFetcher> HeaderSync<F> {
    /// Create a new header sync manager
    pub fn new(
        config: SyncConfig,
        fetcher: Arc<F>,
        headers: Arc<RwLock<HeaderChain>>,
        validators: Arc<RwLock<ValidatorTracker>>,
    ) -> Self {
        Self {
            config,
            fetcher,
            headers,
            validators,
            status: Arc::new(RwLock::new(SyncStatus::default())),
            pending_requests: Arc::new(RwLock::new(HashSet::new())),
            pending_headers: Arc::new(RwLock::new(VecDeque::new())),
            cancelled: Arc::new(RwLock::new(false)),
        }
    }

    /// Get the current sync status
    pub fn status(&self) -> SyncStatus {
        self.status.read().clone()
    }

    /// Cancel the sync operation
    pub fn cancel(&self) {
        *self.cancelled.write() = true;
    }

    /// Check if cancelled
    fn is_cancelled(&self) -> bool {
        *self.cancelled.read()
    }

    /// Start syncing from the current state
    pub async fn sync(&self) -> Result<()> {
        // Reset cancel flag
        *self.cancelled.write() = false;

        // Get starting state
        let start_height = self.headers.read().latest_height().unwrap_or(0);
        let target_height = self.fetcher.get_latest_height().await?;

        if start_height >= target_height {
            info!("Already synced to height {}", start_height);
            self.update_status(|s| {
                s.state = SyncState::Synced;
                s.current_height = start_height;
                s.target_height = Some(target_height);
            });
            return Ok(());
        }

        info!(
            "Starting sync from {} to {}",
            start_height, target_height
        );

        let sync_start = Instant::now();

        // Update status
        self.update_status(|s| {
            s.state = SyncState::SyncingHeaders;
            s.start_height = start_height;
            s.current_height = start_height;
            s.target_height = Some(target_height);
            s.peer_count = self.fetcher.peer_count();
        });

        // Sync headers in batches
        let mut current_height = start_height + 1;

        while current_height <= target_height && !self.is_cancelled() {
            // Fetch batch of headers
            let batch = self
                .fetcher
                .fetch_headers(current_height, self.config.batch_size)
                .await?;

            if batch.is_empty() {
                // No more headers available
                debug!("No more headers available at height {}", current_height);
                break;
            }

            // Process each header
            for sync_header in batch {
                if self.is_cancelled() {
                    return Err(SyncError::Cancelled.into());
                }

                self.process_header(sync_header).await?;
                current_height += 1;

                // Update progress
                self.update_status(|s| {
                    s.current_height = current_height - 1;
                    s.headers_synced += 1;
                    s.elapsed = sync_start.elapsed();

                    // Calculate sync speed
                    if s.elapsed.as_secs() > 0 {
                        s.sync_speed = s.headers_synced as f64 / s.elapsed.as_secs_f64();
                    }

                    // Estimate remaining time
                    if s.sync_speed > 0.0 {
                        if let Some(target) = s.target_height {
                            let remaining = target.saturating_sub(s.current_height);
                            let eta_secs = remaining as f64 / s.sync_speed;
                            s.eta = Some(Duration::from_secs_f64(eta_secs));
                        }
                    }
                });
            }

            // Check for chain tip update
            let new_target = self.fetcher.get_latest_height().await?;
            if new_target > target_height {
                debug!("Chain tip moved from {} to {}", target_height, new_target);
                self.update_status(|s| s.target_height = Some(new_target));
            }
        }

        // Final status update
        if self.is_cancelled() {
            self.update_status(|s| s.state = SyncState::Idle);
            return Err(SyncError::Cancelled.into());
        }

        self.update_status(|s| {
            s.state = SyncState::Synced;
            s.elapsed = sync_start.elapsed();
        });

        let final_height = self.headers.read().latest_height().unwrap_or(0);
        info!(
            "Sync complete: {} headers in {:?}",
            final_height - start_height,
            sync_start.elapsed()
        );

        Ok(())
    }

    /// Process a single header
    async fn process_header(&self, sync_header: SyncHeader) -> Result<()> {
        let height = sync_header.height();

        // Verify header hash
        if !sync_header.header.verify_hash() {
            return Err(SyncError::VerificationFailed {
                height,
                reason: "header hash mismatch".into(),
            }
            .into());
        }

        // Get validator set for this epoch
        let epoch = {
            let validators = self.validators.read();
            validators.epoch_for_height(height)
        };

        // Verify finality certificate
        {
            let validators = self.validators.read();
            if let Some(validator_set) = validators.get_set(epoch) {
                sync_header.finality_cert.verify(validator_set)?;
            } else {
                // Need to handle missing validator set
                warn!("No validator set for epoch {}, using previous", epoch);
                if let Some(set) = validators.current_set() {
                    sync_header.finality_cert.verify(set)?;
                } else {
                    return Err(Error::EpochBoundaryError(format!(
                        "no validator set available for epoch {}",
                        epoch
                    )));
                }
            }
        }

        // Verify chain link
        {
            let headers = self.headers.read();
            if let Some(parent) = headers.get_by_number(height.saturating_sub(1)) {
                if sync_header.header.parent_hash != parent.hash {
                    return Err(SyncError::ChainDiscontinuity { height }.into());
                }
            }
        }

        // Insert the verified header
        {
            let mut headers = self.headers.write();
            headers.insert(sync_header.header)?;
            headers.set_finalized_height(height);
        }

        trace!("Processed header at height {}", height);

        Ok(())
    }

    /// Sync from a trusted checkpoint
    pub async fn sync_from_checkpoint(&self, checkpoint: Checkpoint) -> Result<()> {
        info!(
            "Syncing from checkpoint at height {}",
            checkpoint.header.number
        );

        // Verify checkpoint
        checkpoint.verify(None)?;

        // Initialize headers and validators from checkpoint
        {
            let mut headers = self.headers.write();
            headers.insert(checkpoint.header.clone())?;
            headers.set_finalized_height(checkpoint.header.number);
        }

        {
            let mut validators = self.validators.write();
            validators.init(checkpoint.validator_set);
        }

        // Continue syncing from checkpoint
        self.sync().await
    }

    /// Find and sync from the best available checkpoint
    pub async fn sync_from_best_checkpoint(&self) -> Result<()> {
        let latest = self.fetcher.get_latest_height().await?;

        // Try to find a checkpoint near the tip
        let checkpoint_height = (latest / 1000) * 1000; // Round to nearest 1000

        if checkpoint_height >= self.config.min_checkpoint_height {
            if let Some(checkpoint) = self.fetcher.fetch_checkpoint(checkpoint_height).await? {
                return self.sync_from_checkpoint(checkpoint).await;
            }
        }

        // No checkpoint available, sync from current state
        self.sync().await
    }

    /// Helper to update status
    fn update_status<U>(&self, update: U)
    where
        U: FnOnce(&mut SyncStatus),
    {
        let mut status = self.status.write();
        update(&mut status);
    }
}

/// Sync manager that coordinates all sync operations
pub struct SyncManager<F: HeaderFetcher> {
    /// Light client
    client: Arc<LightClient>,
    /// Header sync
    header_sync: HeaderSync<F>,
    /// Shutdown channel
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl<F: HeaderFetcher + 'static> SyncManager<F> {
    /// Create a new sync manager
    pub fn new(
        client: Arc<LightClient>,
        fetcher: Arc<F>,
        config: SyncConfig,
        headers: Arc<RwLock<HeaderChain>>,
        validators: Arc<RwLock<ValidatorTracker>>,
    ) -> Self {
        let header_sync = HeaderSync::new(config, fetcher, headers, validators);

        Self {
            client,
            header_sync,
            shutdown_tx: None,
        }
    }

    /// Get sync status
    pub fn status(&self) -> SyncStatus {
        self.header_sync.status()
    }

    /// Start the sync manager
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting sync manager");

        // Perform initial sync
        self.header_sync.sync().await?;

        Ok(())
    }

    /// Stop the sync manager
    pub async fn stop(&mut self) {
        info!("Stopping sync manager");
        self.header_sync.cancel();

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Run continuous sync
    pub async fn run_continuous(&self) -> Result<()> {
        let interval = self.header_sync.config.sync_interval;

        loop {
            if self.header_sync.is_cancelled() {
                break;
            }

            // Try to sync any new headers
            match self.header_sync.sync().await {
                Ok(()) => {
                    debug!("Sync iteration complete");
                }
                Err(e) => {
                    warn!("Sync iteration failed: {}", e);
                }
            }

            // Wait before next iteration
            tokio::time::sleep(interval).await;
        }

        Ok(())
    }
}

/// Verify a chain of headers for consistency
pub fn verify_header_chain(headers: &[LightBlockHeader]) -> Result<()> {
    if headers.is_empty() {
        return Ok(());
    }

    for window in headers.windows(2) {
        let parent = &window[0];
        let child = &window[1];

        // Verify sequential block numbers
        if child.number != parent.number + 1 {
            return Err(Error::HeaderChainGap(parent.number + 1));
        }

        // Verify parent hash link
        if child.parent_hash != parent.hash {
            return Err(Error::InvalidHeaderChain(format!(
                "parent hash mismatch at height {}",
                child.number
            )));
        }

        // Verify child header hash
        if !child.verify_hash() {
            return Err(Error::BlockHashMismatch {
                expected: child.hash_hex(),
                got: format!("0x{}", hex::encode(child.compute_hash())),
            });
        }
    }

    Ok(())
}

/// Handle potential reorg (shouldn't happen with BFT finality)
pub fn handle_reorg(
    headers: &mut HeaderChain,
    conflicting_header: &LightBlockHeader,
) -> Result<()> {
    let height = conflicting_header.number;

    // In BFT consensus, reorgs should never happen after finality
    // This is a safety check
    if let Some(existing) = headers.get_by_number(height) {
        if existing.hash != conflicting_header.hash {
            error!(
                "Reorg detected at height {}! This should not happen with BFT finality.",
                height
            );

            // Log both headers for investigation
            warn!(
                "Existing header: 0x{}, Conflicting: 0x{}",
                hex::encode(existing.hash),
                hex::encode(conflicting_header.hash)
            );

            return Err(Error::ReorgDetected {
                height,
                expected: format!("0x{}", hex::encode(existing.hash)),
                got: format!("0x{}", hex::encode(conflicting_header.hash)),
            });
        }
    }

    Ok(())
}

