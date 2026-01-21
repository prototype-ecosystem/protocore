//! Multi-Peer Syncing
//!
//! This module provides advanced multi-peer synchronization capabilities:
//!
//! - **Peer Scoring**: Track peer performance and reliability
//! - **Adaptive Assignment**: Assign chunks to fastest peers
//! - **Bandwidth Estimation**: Estimate peer bandwidth for optimal scheduling
//! - **Pipeline Management**: Manage concurrent downloads across peers
//! - **Automatic Failover**: Re-assign chunks from slow/failed peers
//!
//! ## Design Goals
//!
//! 1. **Maximize Throughput**: Use all available peers at their optimal capacity
//! 2. **Minimize Latency**: Prioritize fast peers for critical chunks
//! 3. **Handle Failures**: Gracefully handle peer disconnections and timeouts
//! 4. **Fair Distribution**: Don't overload any single peer

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::{PeerId, DEFAULT_MAX_CONCURRENT_DOWNLOADS};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for multi-peer syncing
#[derive(Debug, Clone)]
pub struct MultiPeerConfig {
    /// Maximum concurrent downloads total
    pub max_concurrent_downloads: usize,
    /// Maximum concurrent requests per peer
    pub max_per_peer: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Minimum bandwidth to consider peer (bytes/sec)
    pub min_bandwidth: u64,
    /// Score decay rate per second
    pub score_decay_rate: f64,
    /// Enable adaptive chunk assignment
    pub adaptive_assignment: bool,
    /// Pipeline depth (chunks to keep in flight)
    pub pipeline_depth: usize,
    /// Stall detection timeout
    pub stall_timeout: Duration,
}

impl Default for MultiPeerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: DEFAULT_MAX_CONCURRENT_DOWNLOADS,
            max_per_peer: 4,
            request_timeout: Duration::from_secs(30),
            min_bandwidth: 100_000, // 100 KB/s
            score_decay_rate: 0.01,
            adaptive_assignment: true,
            pipeline_depth: 32,
            stall_timeout: Duration::from_secs(60),
        }
    }
}

// ============================================================================
// Peer Scoring
// ============================================================================

/// Performance metrics for a peer
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    /// Peer identifier
    pub peer_id: PeerId,
    /// Total bytes downloaded from this peer
    pub bytes_downloaded: u64,
    /// Total chunks downloaded
    pub chunks_downloaded: u64,
    /// Total download time in milliseconds
    pub total_download_time_ms: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Current in-flight requests
    pub in_flight: u32,
    /// Estimated bandwidth (bytes/sec)
    pub estimated_bandwidth: u64,
    /// Last successful response time
    pub last_response: Option<Instant>,
    /// Peer score (higher is better)
    pub score: f64,
}

impl PeerMetrics {
    /// Create new peer metrics
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            bytes_downloaded: 0,
            chunks_downloaded: 0,
            total_download_time_ms: 0,
            successful_requests: 0,
            failed_requests: 0,
            in_flight: 0,
            estimated_bandwidth: 0,
            last_response: None,
            score: 100.0, // Start with base score
        }
    }

    /// Record a successful download
    pub fn record_success(&mut self, bytes: u64, duration_ms: u64) {
        self.bytes_downloaded += bytes;
        self.chunks_downloaded += 1;
        self.total_download_time_ms += duration_ms;
        self.successful_requests += 1;
        self.last_response = Some(Instant::now());

        // Update bandwidth estimate (exponential moving average)
        if duration_ms > 0 {
            let current_bandwidth = (bytes * 1000) / duration_ms;
            if self.estimated_bandwidth == 0 {
                self.estimated_bandwidth = current_bandwidth;
            } else {
                self.estimated_bandwidth =
                    (self.estimated_bandwidth * 7 + current_bandwidth * 3) / 10;
            }
        }

        // Boost score
        self.score = (self.score + 10.0).min(200.0);
    }

    /// Record a failed download
    pub fn record_failure(&mut self) {
        self.failed_requests += 1;
        // Penalize score
        self.score = (self.score - 20.0).max(0.0);
    }

    /// Record request start
    pub fn start_request(&mut self) {
        self.in_flight += 1;
    }

    /// Record request end
    pub fn end_request(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Apply score decay over time
    pub fn apply_decay(&mut self, elapsed_secs: f64, decay_rate: f64) {
        self.score = (self.score - decay_rate * elapsed_secs).max(0.0);
    }

    /// Calculate average bandwidth
    pub fn average_bandwidth(&self) -> u64 {
        if self.total_download_time_ms == 0 {
            return 0;
        }
        (self.bytes_downloaded * 1000) / self.total_download_time_ms
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_requests + self.failed_requests;
        if total == 0 {
            return 1.0;
        }
        self.successful_requests as f64 / total as f64
    }

    /// Check if peer is responsive
    pub fn is_responsive(&self, timeout: Duration) -> bool {
        match self.last_response {
            Some(last) => last.elapsed() < timeout,
            None => true, // No data yet, give it a chance
        }
    }
}

/// Peer scorer for selecting best peers
pub struct PeerScorer {
    /// Configuration
    config: MultiPeerConfig,
    /// Metrics per peer
    metrics: HashMap<PeerId, PeerMetrics>,
    /// Last decay application time
    last_decay: Instant,
}

impl PeerScorer {
    /// Create a new peer scorer
    pub fn new(config: MultiPeerConfig) -> Self {
        Self {
            config,
            metrics: HashMap::new(),
            last_decay: Instant::now(),
        }
    }

    /// Add or get peer metrics
    pub fn get_or_create(&mut self, peer_id: PeerId) -> &mut PeerMetrics {
        self.metrics
            .entry(peer_id)
            .or_insert_with(|| PeerMetrics::new(peer_id))
    }

    /// Get peer metrics
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerMetrics> {
        self.metrics.get(peer_id)
    }

    /// Record successful download
    pub fn record_success(&mut self, peer_id: PeerId, bytes: u64, duration_ms: u64) {
        self.get_or_create(peer_id)
            .record_success(bytes, duration_ms);
    }

    /// Record failed download
    pub fn record_failure(&mut self, peer_id: PeerId) {
        self.get_or_create(peer_id).record_failure();
    }

    /// Apply score decay to all peers
    pub fn apply_decay(&mut self) {
        let elapsed = self.last_decay.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return;
        }

        for metrics in self.metrics.values_mut() {
            metrics.apply_decay(elapsed, self.config.score_decay_rate);
        }
        self.last_decay = Instant::now();
    }

    /// Get best peers sorted by score
    pub fn best_peers(&self, count: usize) -> Vec<PeerId> {
        let mut peers: Vec<_> = self
            .metrics
            .iter()
            .filter(|(_, m)| {
                m.is_responsive(self.config.stall_timeout)
                    && m.estimated_bandwidth >= self.config.min_bandwidth
            })
            .collect();

        peers.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap());
        peers.into_iter().take(count).map(|(id, _)| *id).collect()
    }

    /// Select best peer for a chunk download
    pub fn select_peer(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        self.metrics
            .iter()
            .filter(|(id, m)| {
                !exclude.contains(*id)
                    && m.in_flight < self.config.max_per_peer as u32
                    && m.is_responsive(self.config.stall_timeout)
            })
            .max_by(|a, b| a.1.score.partial_cmp(&b.1.score).unwrap())
            .map(|(id, _)| *id)
    }

    /// Get statistics
    pub fn stats(&self) -> PeerScorerStats {
        let active_peers = self
            .metrics
            .values()
            .filter(|m| m.is_responsive(self.config.stall_timeout))
            .count();

        let total_bandwidth: u64 = self.metrics.values().map(|m| m.estimated_bandwidth).sum();

        let total_downloaded: u64 = self.metrics.values().map(|m| m.bytes_downloaded).sum();

        PeerScorerStats {
            total_peers: self.metrics.len(),
            active_peers,
            total_bandwidth,
            total_downloaded,
        }
    }
}

/// Statistics from peer scorer
#[derive(Debug, Clone)]
pub struct PeerScorerStats {
    /// Total peers tracked
    pub total_peers: usize,
    /// Currently active peers
    pub active_peers: usize,
    /// Total estimated bandwidth
    pub total_bandwidth: u64,
    /// Total bytes downloaded
    pub total_downloaded: u64,
}

// ============================================================================
// Chunk Assignment
// ============================================================================

/// Chunk request to be assigned to a peer
#[derive(Debug, Clone)]
pub struct ChunkAssignment {
    /// Chunk index
    pub chunk_index: u64,
    /// Assigned peer
    pub peer_id: PeerId,
    /// Assignment time
    pub assigned_at: Instant,
    /// Number of attempts
    pub attempts: u32,
    /// Priority (higher = download first)
    pub priority: u32,
}

/// Strategy for assigning chunks to peers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AssignmentStrategy {
    /// Round-robin assignment
    RoundRobin,
    /// Assign to fastest available peer
    FastestFirst,
    /// Assign based on peer capacity (bandwidth * available slots)
    #[default]
    Capacity,
    /// Random assignment
    Random,
}

/// Chunk assignment manager
pub struct ChunkAssigner {
    /// Configuration
    config: MultiPeerConfig,
    /// Assignment strategy
    strategy: AssignmentStrategy,
    /// Pending chunks (not yet assigned)
    pending: VecDeque<u64>,
    /// In-flight assignments
    in_flight: HashMap<u64, ChunkAssignment>,
    /// Completed chunks
    completed: HashSet<u64>,
    /// Failed chunks (need reassignment)
    failed: VecDeque<u64>,
    /// Total chunks
    total_chunks: u64,
    /// Round-robin index
    rr_index: usize,
}

impl ChunkAssigner {
    /// Create a new chunk assigner
    pub fn new(config: MultiPeerConfig, total_chunks: u64) -> Self {
        let pending: VecDeque<u64> = (0..total_chunks).collect();

        Self {
            config,
            strategy: AssignmentStrategy::default(),
            pending,
            in_flight: HashMap::new(),
            completed: HashSet::new(),
            failed: VecDeque::new(),
            total_chunks,
            rr_index: 0,
        }
    }

    /// Set assignment strategy
    pub fn with_strategy(mut self, strategy: AssignmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Get next chunk to assign
    pub fn next_chunk(&mut self) -> Option<u64> {
        // Prioritize failed chunks (retries)
        if let Some(chunk) = self.failed.pop_front() {
            return Some(chunk);
        }

        self.pending.pop_front()
    }

    /// Assign a chunk to a peer
    pub fn assign(&mut self, chunk_index: u64, peer_id: PeerId, priority: u32) {
        let assignment = ChunkAssignment {
            chunk_index,
            peer_id,
            assigned_at: Instant::now(),
            attempts: self.get_attempt_count(chunk_index),
            priority,
        };

        self.in_flight.insert(chunk_index, assignment);
    }

    /// Get attempt count for a chunk
    fn get_attempt_count(&self, chunk_index: u64) -> u32 {
        // Count based on whether it was in failed queue
        if self.failed.contains(&chunk_index) {
            2
        } else {
            1
        }
    }

    /// Mark chunk as completed
    pub fn complete(&mut self, chunk_index: u64) {
        self.in_flight.remove(&chunk_index);
        self.completed.insert(chunk_index);
    }

    /// Mark chunk as failed (will be reassigned)
    pub fn fail(&mut self, chunk_index: u64) {
        if let Some(assignment) = self.in_flight.remove(&chunk_index) {
            if assignment.attempts < self.config.max_per_peer as u32 {
                // Retry
                self.failed.push_back(chunk_index);
            } else {
                warn!("Chunk {} exceeded max attempts", chunk_index);
                // Could optionally add to a permanent failure list
            }
        }
    }

    /// Check for timed out assignments
    pub fn check_timeouts(&mut self) -> Vec<u64> {
        let timeout = self.config.request_timeout;
        let timed_out: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, a)| a.assigned_at.elapsed() > timeout)
            .map(|(idx, _)| *idx)
            .collect();

        for idx in &timed_out {
            self.fail(*idx);
        }

        timed_out
    }

    /// Get progress
    pub fn progress(&self) -> ChunkProgress {
        ChunkProgress {
            total: self.total_chunks,
            completed: self.completed.len() as u64,
            in_flight: self.in_flight.len() as u64,
            pending: self.pending.len() as u64,
            failed: self.failed.len() as u64,
        }
    }

    /// Check if all chunks are completed
    pub fn is_complete(&self) -> bool {
        self.completed.len() as u64 == self.total_chunks
    }

    /// Get in-flight count for a peer
    pub fn peer_in_flight(&self, peer_id: &PeerId) -> usize {
        self.in_flight
            .values()
            .filter(|a| a.peer_id == *peer_id)
            .count()
    }
}

/// Chunk download progress
#[derive(Debug, Clone)]
pub struct ChunkProgress {
    /// Total chunks
    pub total: u64,
    /// Completed chunks
    pub completed: u64,
    /// In-flight chunks
    pub in_flight: u64,
    /// Pending chunks
    pub pending: u64,
    /// Failed chunks awaiting retry
    pub failed: u64,
}

impl ChunkProgress {
    /// Calculate completion percentage
    pub fn percentage(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.completed as f64 / self.total as f64) * 100.0
    }
}

// ============================================================================
// Pipeline Manager
// ============================================================================

/// Download request for the pipeline
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    /// Chunk index
    pub chunk_index: u64,
    /// Target peer
    pub peer_id: PeerId,
    /// Request time
    pub requested_at: Instant,
}

/// Download result
#[derive(Debug)]
pub enum DownloadResult {
    /// Successful download with data
    Success {
        chunk_index: u64,
        peer_id: PeerId,
        data: Vec<u8>,
        duration_ms: u64,
    },
    /// Download failed
    Failure {
        chunk_index: u64,
        peer_id: PeerId,
        error: String,
    },
    /// Download timed out
    Timeout { chunk_index: u64, peer_id: PeerId },
}

/// Multi-peer download pipeline
pub struct DownloadPipeline {
    /// Configuration
    config: MultiPeerConfig,
    /// Peer scorer
    scorer: RwLock<PeerScorer>,
    /// Chunk assigner
    assigner: RwLock<ChunkAssigner>,
    /// Concurrent download semaphore
    semaphore: Semaphore,
    /// Active download count
    active_downloads: std::sync::atomic::AtomicU64,
    /// Start time
    start_time: RwLock<Option<Instant>>,
}

impl DownloadPipeline {
    /// Create a new download pipeline
    pub fn new(config: MultiPeerConfig, total_chunks: u64) -> Self {
        let max_concurrent = config.max_concurrent_downloads;
        Self {
            scorer: RwLock::new(PeerScorer::new(config.clone())),
            assigner: RwLock::new(ChunkAssigner::new(config.clone(), total_chunks)),
            semaphore: Semaphore::new(max_concurrent),
            config,
            active_downloads: std::sync::atomic::AtomicU64::new(0),
            start_time: RwLock::new(None),
        }
    }

    /// Add a peer to the pipeline
    pub fn add_peer(&self, peer_id: PeerId) {
        let mut scorer = self.scorer.write();
        scorer.get_or_create(peer_id);
    }

    /// Remove a peer from the pipeline
    pub fn remove_peer(&self, peer_id: &PeerId) {
        // Cancel any in-flight requests from this peer
        let mut assigner = self.assigner.write();
        let chunks_to_fail: Vec<u64> = assigner
            .in_flight
            .iter()
            .filter(|(_, a)| a.peer_id == *peer_id)
            .map(|(idx, _)| *idx)
            .collect();

        for idx in chunks_to_fail {
            assigner.fail(idx);
        }
    }

    /// Get next download request
    pub fn next_request(&self) -> Option<DownloadRequest> {
        let mut assigner = self.assigner.write();
        let scorer = self.scorer.read();

        // Get next chunk
        let chunk_index = assigner.next_chunk()?;

        // Find peers already assigned to this chunk (to exclude)
        let excluded: HashSet<PeerId> = HashSet::new();

        // Select best peer
        let peer_id = scorer.select_peer(&excluded)?;

        // Assign chunk
        assigner.assign(chunk_index, peer_id, 0);

        // Update scorer
        drop(scorer);
        let mut scorer = self.scorer.write();
        scorer.get_or_create(peer_id).start_request();

        Some(DownloadRequest {
            chunk_index,
            peer_id,
            requested_at: Instant::now(),
        })
    }

    /// Handle download result
    pub fn handle_result(&self, result: DownloadResult) {
        match result {
            DownloadResult::Success {
                chunk_index,
                peer_id,
                data,
                duration_ms,
            } => {
                let mut scorer = self.scorer.write();
                scorer.record_success(peer_id, data.len() as u64, duration_ms);
                if let Some(m) = scorer.metrics.get_mut(&peer_id) {
                    m.end_request();
                }

                let mut assigner = self.assigner.write();
                assigner.complete(chunk_index);

                debug!(
                    chunk = chunk_index,
                    peer = ?peer_id,
                    bytes = data.len(),
                    duration_ms,
                    "Chunk downloaded successfully"
                );
            }
            DownloadResult::Failure {
                chunk_index,
                peer_id,
                error,
            } => {
                let mut scorer = self.scorer.write();
                scorer.record_failure(peer_id);
                if let Some(m) = scorer.metrics.get_mut(&peer_id) {
                    m.end_request();
                }

                let mut assigner = self.assigner.write();
                assigner.fail(chunk_index);

                warn!(
                    chunk = chunk_index,
                    peer = ?peer_id,
                    error,
                    "Chunk download failed"
                );
            }
            DownloadResult::Timeout {
                chunk_index,
                peer_id,
            } => {
                let mut scorer = self.scorer.write();
                scorer.record_failure(peer_id);
                if let Some(m) = scorer.metrics.get_mut(&peer_id) {
                    m.end_request();
                }

                let mut assigner = self.assigner.write();
                assigner.fail(chunk_index);

                warn!(
                    chunk = chunk_index,
                    peer = ?peer_id,
                    "Chunk download timed out"
                );
            }
        }
    }

    /// Check for timed out requests
    pub fn check_timeouts(&self) -> Vec<u64> {
        let mut assigner = self.assigner.write();
        let timed_out = assigner.check_timeouts();

        // Update scorer for timed out peers
        let mut scorer = self.scorer.write();
        for idx in &timed_out {
            if let Some(assignment) = assigner.in_flight.get(idx) {
                if let Some(m) = scorer.metrics.get_mut(&assignment.peer_id) {
                    m.end_request();
                }
            }
        }

        timed_out
    }

    /// Get progress
    pub fn progress(&self) -> ChunkProgress {
        self.assigner.read().progress()
    }

    /// Check if complete
    pub fn is_complete(&self) -> bool {
        self.assigner.read().is_complete()
    }

    /// Get peer statistics
    pub fn peer_stats(&self) -> PeerScorerStats {
        self.scorer.read().stats()
    }

    /// Get best peers
    pub fn best_peers(&self, count: usize) -> Vec<PeerId> {
        self.scorer.read().best_peers(count)
    }

    /// Acquire download permit
    pub async fn acquire_permit(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.semaphore.acquire().await.ok()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id(n: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_peer_metrics() {
        let mut metrics = PeerMetrics::new(test_peer_id(1));

        assert_eq!(metrics.score, 100.0);
        assert_eq!(metrics.success_rate(), 1.0); // No data yet

        // Record success
        metrics.record_success(1_000_000, 1000); // 1MB in 1 second = 1MB/s
        assert_eq!(metrics.bytes_downloaded, 1_000_000);
        assert_eq!(metrics.chunks_downloaded, 1);
        assert_eq!(metrics.estimated_bandwidth, 1_000_000);
        assert!(metrics.score > 100.0); // Should increase

        // Record failure
        metrics.record_failure();
        assert!(metrics.score < 110.0); // Should decrease
    }

    #[test]
    fn test_peer_scorer() {
        let config = MultiPeerConfig::default();
        let mut scorer = PeerScorer::new(config);

        // Add peers with different performance (multiple successes to differentiate scores)
        for _ in 0..5 {
            scorer.record_success(test_peer_id(1), 2_000_000, 1000); // 2 MB/s
        }
        for _ in 0..3 {
            scorer.record_success(test_peer_id(2), 1_000_000, 1000); // 1 MB/s
        }
        scorer.record_success(test_peer_id(3), 500_000, 1000); // 0.5 MB/s

        // Best peers should be in order of score
        let best = scorer.best_peers(3);
        assert_eq!(best.len(), 3);
        // Peer 1 should be first (highest score due to most successes)
        assert_eq!(best[0], test_peer_id(1));
        // Peer 2 should be second
        assert_eq!(best[1], test_peer_id(2));
    }

    #[test]
    fn test_chunk_assigner() {
        let config = MultiPeerConfig::default();
        let mut assigner = ChunkAssigner::new(config, 10);

        // Get next chunks
        assert_eq!(assigner.next_chunk(), Some(0));
        assert_eq!(assigner.next_chunk(), Some(1));

        // Assign chunks
        assigner.assign(0, test_peer_id(1), 0);
        assigner.assign(1, test_peer_id(2), 0);

        let progress = assigner.progress();
        assert_eq!(progress.in_flight, 2);
        assert_eq!(progress.pending, 8);

        // Complete one
        assigner.complete(0);
        let progress = assigner.progress();
        assert_eq!(progress.completed, 1);
        assert_eq!(progress.in_flight, 1);

        // Fail one
        assigner.fail(1);
        let progress = assigner.progress();
        assert_eq!(progress.in_flight, 0);
        assert_eq!(progress.failed, 1);

        // Failed chunk should be next
        assert_eq!(assigner.next_chunk(), Some(1));
    }

    #[test]
    fn test_chunk_progress() {
        let progress = ChunkProgress {
            total: 100,
            completed: 50,
            in_flight: 10,
            pending: 35,
            failed: 5,
        };

        assert_eq!(progress.percentage(), 50.0);
    }

    #[test]
    fn test_download_pipeline() {
        let config = MultiPeerConfig::default();
        let pipeline = DownloadPipeline::new(config, 100);

        // Add peers
        pipeline.add_peer(test_peer_id(1));
        pipeline.add_peer(test_peer_id(2));

        // Request download
        let request = pipeline.next_request();
        assert!(request.is_some());

        let request = request.unwrap();
        assert_eq!(request.chunk_index, 0);

        // Handle success
        pipeline.handle_result(DownloadResult::Success {
            chunk_index: 0,
            peer_id: request.peer_id,
            data: vec![0; 1000],
            duration_ms: 100,
        });

        let progress = pipeline.progress();
        assert_eq!(progress.completed, 1);
    }
}
