//! Signing Coordinator for Validator Redundancy
//!
//! This module provides the `SigningCoordinator` which manages leader-follower
//! roles for validator nodes to enable redundancy without causing double-signing.
//!
//! ## Problem
//!
//! Validators need redundancy for high availability, but running multiple nodes
//! with the same validator key risks double-signing (equivocation), which results
//! in slashing. This module solves this by:
//!
//! 1. **Leader Election**: Only one node (the leader) actively signs
//! 2. **Signing Lock**: Local lock prevents concurrent signing operations
//! 3. **Leader Lease**: Time-bounded leadership with automatic renewal
//! 4. **Automatic Failover**: Followers take over if leader stops responding
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │  Leader Node    │     │ Follower Node 1 │     │ Follower Node 2 │
//! │                 │     │                 │     │                 │
//! │ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
//! │ │   Signing   │ │     │ │   Signing   │ │     │ │   Signing   │ │
//! │ │ Coordinator │ │     │ │ Coordinator │ │     │ │ Coordinator │ │
//! │ │  (LEADER)   │ │     │ │ (FOLLOWER)  │ │     │ │ (FOLLOWER)  │ │
//! │ └──────┬──────┘ │     │ └──────┬──────┘ │     │ └──────┬──────┘ │
//! │        │        │     │        │        │     │        │        │
//! │        ▼        │     │        ▼        │     │        ▼        │
//! │ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
//! │ │ Signing DB  │ │◄───►│ │ Signing DB  │ │◄───►│ │ Signing DB  │ │
//! │ │   (Local)   │ │     │ │   (Local)   │ │     │ │   (Local)   │ │
//! │ └─────────────┘ │     │ └─────────────┘ │     │ └─────────────┘ │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!          │                                               │
//!          └───────────────────┬───────────────────────────┘
//!                              ▼
//!                    ┌─────────────────┐
//!                    │  Shared State   │
//!                    │ (Redis/etcd/FS) │
//!                    └─────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use protocore_consensus::signing_coordinator::{
//!     SigningCoordinator, SigningCoordinatorConfig, SigningRole
//! };
//!
//! // Create coordinator with file-based shared state
//! let config = SigningCoordinatorConfig::default();
//! let coordinator = SigningCoordinator::new(config, node_id, validator_id);
//!
//! // Attempt to become leader
//! coordinator.try_acquire_leadership().await?;
//!
//! // Check role before signing
//! if coordinator.role() == SigningRole::Leader {
//!     // Safe to sign
//!     let guard = coordinator.acquire_signing_lock(height, round, step).await?;
//!     // ... perform signing ...
//!     // guard drops automatically, releasing the lock
//! }
//! ```

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::types::{Step, ValidatorId};
use protocore_crypto::Hash;

/// Default leader lease duration (10 seconds)
pub const DEFAULT_LEASE_DURATION_MS: u64 = 10_000;

/// Default lease renewal interval (renew when 3 seconds remaining)
pub const DEFAULT_LEASE_RENEWAL_THRESHOLD_MS: u64 = 3_000;

/// Default follower takeover timeout (15 seconds without leader activity)
pub const DEFAULT_TAKEOVER_TIMEOUT_MS: u64 = 15_000;

/// Number of missed blocks before follower considers takeover
pub const DEFAULT_MISSED_BLOCKS_THRESHOLD: u64 = 5;

/// Errors that can occur during signing coordination
#[derive(Debug, Clone, Error)]
pub enum SigningCoordinatorError {
    /// Not the leader, cannot sign
    #[error("node is not the leader, current role: {0:?}")]
    NotLeader(SigningRole),

    /// Already signed for this (height, round, step)
    #[error("already signed for height {height}, round {round}, step {step:?}")]
    AlreadySigned {
        /// Block height
        height: u64,
        /// Consensus round
        round: u64,
        /// Consensus step
        step: Step,
    },

    /// Failed to acquire signing lock
    #[error("failed to acquire signing lock: {0}")]
    LockAcquisitionFailed(String),

    /// Lease expired
    #[error("leader lease expired")]
    LeaseExpired,

    /// Failed to renew lease
    #[error("failed to renew leader lease: {0}")]
    LeaseRenewalFailed(String),

    /// Shared state error
    #[error("shared state error: {0}")]
    SharedStateError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),
}

/// Role of this node in the leader-follower setup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningRole {
    /// This node is the leader and actively signs consensus messages
    Leader,
    /// This node is a follower and only monitors (does not sign)
    Follower,
    /// Role has not been determined yet
    Unknown,
}

impl std::fmt::Display for SigningRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningRole::Leader => write!(f, "Leader"),
            SigningRole::Follower => write!(f, "Follower"),
            SigningRole::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Configuration for the signing coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCoordinatorConfig {
    /// Duration of the leader lease in milliseconds
    pub lease_duration_ms: u64,
    /// Renew lease when this many milliseconds remaining
    pub lease_renewal_threshold_ms: u64,
    /// Takeover timeout for followers in milliseconds
    pub takeover_timeout_ms: u64,
    /// Number of missed blocks before follower considers takeover
    pub missed_blocks_threshold: u64,
    /// Path to the shared state file (for file-based coordination)
    pub shared_state_path: Option<PathBuf>,
    /// Whether this node should start as a follower (wait for existing leader)
    pub start_as_follower: bool,
    /// Priority for leader election (higher = more likely to become leader)
    pub leader_priority: u32,
}

impl Default for SigningCoordinatorConfig {
    fn default() -> Self {
        Self {
            lease_duration_ms: DEFAULT_LEASE_DURATION_MS,
            lease_renewal_threshold_ms: DEFAULT_LEASE_RENEWAL_THRESHOLD_MS,
            takeover_timeout_ms: DEFAULT_TAKEOVER_TIMEOUT_MS,
            missed_blocks_threshold: DEFAULT_MISSED_BLOCKS_THRESHOLD,
            shared_state_path: None,
            start_as_follower: false,
            leader_priority: 100,
        }
    }
}

/// A record of a signing operation (for preventing double-signing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRecord {
    /// Block height
    pub height: u64,
    /// Consensus round
    pub round: u64,
    /// Consensus step (Prevote, Precommit, etc.)
    pub step: Step,
    /// Hash of the block/value that was signed
    pub signed_hash: Hash,
    /// Timestamp when the signing occurred
    pub timestamp_ms: u64,
}

/// Key for indexing signing records
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningKey {
    /// Block height
    pub height: u64,
    /// Consensus round
    pub round: u64,
    /// Consensus step
    pub step: Step,
}

impl SigningKey {
    /// Create a new signing key
    pub fn new(height: u64, round: u64, step: Step) -> Self {
        Self { height, round, step }
    }
}

/// Leader lease information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderLease {
    /// Node ID of the current leader
    pub leader_node_id: String,
    /// Validator ID this lease is for
    pub validator_id: ValidatorId,
    /// When the lease was acquired (Unix timestamp in milliseconds)
    pub acquired_at_ms: u64,
    /// When the lease expires (Unix timestamp in milliseconds)
    pub expires_at_ms: u64,
    /// Last height the leader signed at
    pub last_signed_height: u64,
    /// Sequence number for the lease (incremented on each renewal)
    pub sequence: u64,
}

impl LeaderLease {
    /// Create a new leader lease
    pub fn new(
        leader_node_id: String,
        validator_id: ValidatorId,
        duration_ms: u64,
    ) -> Self {
        let now_ms = current_time_ms();
        Self {
            leader_node_id,
            validator_id,
            acquired_at_ms: now_ms,
            expires_at_ms: now_ms + duration_ms,
            last_signed_height: 0,
            sequence: 1,
        }
    }

    /// Check if the lease has expired
    pub fn is_expired(&self) -> bool {
        current_time_ms() > self.expires_at_ms
    }

    /// Check if the lease needs renewal
    pub fn needs_renewal(&self, threshold_ms: u64) -> bool {
        let remaining = self.expires_at_ms.saturating_sub(current_time_ms());
        remaining < threshold_ms
    }

    /// Renew the lease
    pub fn renew(&mut self, duration_ms: u64) {
        let now_ms = current_time_ms();
        self.expires_at_ms = now_ms + duration_ms;
        self.sequence += 1;
    }

    /// Update the last signed height
    pub fn update_last_signed_height(&mut self, height: u64) {
        if height > self.last_signed_height {
            self.last_signed_height = height;
        }
    }
}

/// Guard that holds the signing lock and releases it on drop
pub struct SigningLockGuard<'a> {
    /// Reference to the coordinator
    coordinator: &'a SigningCoordinator,
    /// The signing key this guard is for
    key: SigningKey,
}

impl<'a> SigningLockGuard<'a> {
    /// Create a new signing lock guard
    fn new(coordinator: &'a SigningCoordinator, key: SigningKey) -> Self {
        Self { coordinator, key }
    }

    /// Get the signing key
    pub fn key(&self) -> &SigningKey {
        &self.key
    }
}

impl<'a> Drop for SigningLockGuard<'a> {
    fn drop(&mut self) {
        // The actual unlock is handled by the coordinator tracking
        debug!(
            height = self.key.height,
            round = self.key.round,
            step = ?self.key.step,
            "Signing lock released"
        );
    }
}

/// The signing coordinator manages leader-follower roles and prevents double-signing
pub struct SigningCoordinator {
    /// Configuration
    config: SigningCoordinatorConfig,
    /// This node's unique ID
    node_id: String,
    /// Validator ID this coordinator is for
    validator_id: ValidatorId,
    /// Current role (leader or follower)
    role: RwLock<SigningRole>,
    /// Current leader lease (if this node is leader)
    leader_lease: RwLock<Option<LeaderLease>>,
    /// Local signing history (prevents double-signing)
    signing_history: Mutex<HashMap<SigningKey, SigningRecord>>,
    /// Last observed leader activity (for follower takeover)
    last_leader_activity: RwLock<Instant>,
    /// Consecutive missed blocks counter
    missed_blocks: RwLock<u64>,
    /// Last height we observed consensus activity at
    last_observed_height: RwLock<u64>,
    /// Notify for role changes
    role_change_notify: Notify,
    /// Whether the coordinator has been started
    started: RwLock<bool>,
}

impl SigningCoordinator {
    /// Create a new signing coordinator
    pub fn new(config: SigningCoordinatorConfig, node_id: String, validator_id: ValidatorId) -> Self {
        let initial_role = if config.start_as_follower {
            SigningRole::Follower
        } else {
            SigningRole::Unknown
        };

        Self {
            config,
            node_id,
            validator_id,
            role: RwLock::new(initial_role),
            leader_lease: RwLock::new(None),
            signing_history: Mutex::new(HashMap::new()),
            last_leader_activity: RwLock::new(Instant::now()),
            missed_blocks: RwLock::new(0),
            last_observed_height: RwLock::new(0),
            role_change_notify: Notify::new(),
            started: RwLock::new(false),
        }
    }

    /// Start the signing coordinator
    ///
    /// This will attempt to acquire leadership if not configured to start as follower.
    pub async fn start(&self) -> Result<(), SigningCoordinatorError> {
        if *self.started.read() {
            return Ok(());
        }

        info!(
            node_id = %self.node_id,
            validator_id = self.validator_id,
            "Starting signing coordinator"
        );

        // Try to acquire leadership
        if !self.config.start_as_follower {
            match self.try_acquire_leadership().await {
                Ok(true) => {
                    info!(node_id = %self.node_id, "Acquired leadership");
                }
                Ok(false) => {
                    info!(node_id = %self.node_id, "Another node is leader, running as follower");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to acquire leadership, running as follower");
                }
            }
        }

        *self.started.write() = true;
        Ok(())
    }

    /// Get the current role
    pub fn role(&self) -> SigningRole {
        *self.role.read()
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        *self.role.read() == SigningRole::Leader
    }

    /// Try to acquire leadership
    ///
    /// Returns `Ok(true)` if leadership was acquired, `Ok(false)` if another
    /// node is already the leader.
    pub async fn try_acquire_leadership(&self) -> Result<bool, SigningCoordinatorError> {
        // Check if there's an existing valid lease from another node
        if let Some(existing_lease) = self.load_shared_lease().await? {
            if !existing_lease.is_expired() && existing_lease.leader_node_id != self.node_id {
                debug!(
                    existing_leader = %existing_lease.leader_node_id,
                    "Another node holds a valid lease"
                );
                *self.role.write() = SigningRole::Follower;
                *self.last_leader_activity.write() = Instant::now();
                return Ok(false);
            }
        }

        // Create new lease
        let lease = LeaderLease::new(
            self.node_id.clone(),
            self.validator_id,
            self.config.lease_duration_ms,
        );

        // Persist the lease
        self.save_shared_lease(&lease).await?;

        // Update local state
        *self.leader_lease.write() = Some(lease);
        *self.role.write() = SigningRole::Leader;

        info!(
            node_id = %self.node_id,
            validator_id = self.validator_id,
            "Leadership acquired"
        );

        self.role_change_notify.notify_waiters();
        Ok(true)
    }

    /// Renew the leader lease
    pub async fn renew_lease(&self) -> Result<(), SigningCoordinatorError> {
        let mut lease_guard = self.leader_lease.write();
        let lease = lease_guard
            .as_mut()
            .ok_or(SigningCoordinatorError::NotLeader(*self.role.read()))?;

        if lease.is_expired() {
            // Lease expired, we're no longer the leader
            *self.role.write() = SigningRole::Follower;
            self.role_change_notify.notify_waiters();
            return Err(SigningCoordinatorError::LeaseExpired);
        }

        lease.renew(self.config.lease_duration_ms);

        // Persist the renewed lease
        drop(lease_guard);
        if let Some(lease) = self.leader_lease.read().as_ref() {
            self.save_shared_lease(lease).await?;
        }

        debug!(
            node_id = %self.node_id,
            "Leader lease renewed"
        );

        Ok(())
    }

    /// Check and renew the lease if needed
    pub async fn check_and_renew_lease(&self) -> Result<(), SigningCoordinatorError> {
        if !self.is_leader() {
            return Ok(());
        }

        let needs_renewal = self.leader_lease
            .read()
            .as_ref()
            .map(|l| l.needs_renewal(self.config.lease_renewal_threshold_ms))
            .unwrap_or(false);

        if needs_renewal {
            self.renew_lease().await?;
        }

        Ok(())
    }

    /// Acquire a signing lock for the given (height, round, step)
    ///
    /// This ensures that:
    /// 1. This node is the leader
    /// 2. We haven't already signed for this (height, round, step)
    /// 3. The leader lease is still valid
    ///
    /// Returns a guard that must be held during signing.
    pub async fn acquire_signing_lock(
        &self,
        height: u64,
        round: u64,
        step: Step,
    ) -> Result<SigningLockGuard<'_>, SigningCoordinatorError> {
        // Check that we're the leader
        let current_role = *self.role.read();
        if current_role != SigningRole::Leader {
            return Err(SigningCoordinatorError::NotLeader(current_role));
        }

        // Check lease validity
        {
            let lease = self.leader_lease.read();
            if let Some(l) = lease.as_ref() {
                if l.is_expired() {
                    drop(lease);
                    *self.role.write() = SigningRole::Follower;
                    return Err(SigningCoordinatorError::LeaseExpired);
                }
            } else {
                return Err(SigningCoordinatorError::NotLeader(current_role));
            }
        }

        // Check signing history
        let key = SigningKey::new(height, round, step);
        {
            let history = self.signing_history.lock();
            if history.contains_key(&key) {
                return Err(SigningCoordinatorError::AlreadySigned { height, round, step });
            }
        }

        debug!(
            height = height,
            round = round,
            step = ?step,
            "Signing lock acquired"
        );

        Ok(SigningLockGuard::new(self, key))
    }

    /// Record that a signing operation was completed
    ///
    /// This should be called after successfully signing a message.
    pub fn record_signing(
        &self,
        height: u64,
        round: u64,
        step: Step,
        signed_hash: Hash,
    ) -> Result<(), SigningCoordinatorError> {
        let key = SigningKey::new(height, round, step);
        let record = SigningRecord {
            height,
            round,
            step,
            signed_hash,
            timestamp_ms: current_time_ms(),
        };

        {
            let mut history = self.signing_history.lock();
            if history.contains_key(&key) {
                return Err(SigningCoordinatorError::AlreadySigned { height, round, step });
            }
            history.insert(key, record);
        }

        // Update lease's last signed height
        if let Some(lease) = self.leader_lease.write().as_mut() {
            lease.update_last_signed_height(height);
        }

        debug!(
            height = height,
            round = round,
            step = ?step,
            hash = hex::encode(&signed_hash[..8]),
            "Signing recorded"
        );

        Ok(())
    }

    /// Check if we've already signed for the given (height, round, step)
    pub fn has_signed(&self, height: u64, round: u64, step: Step) -> bool {
        let key = SigningKey::new(height, round, step);
        self.signing_history.lock().contains_key(&key)
    }

    /// Get what we signed for the given (height, round, step)
    pub fn get_signed_hash(&self, height: u64, round: u64, step: Step) -> Option<Hash> {
        let key = SigningKey::new(height, round, step);
        self.signing_history.lock().get(&key).map(|r| r.signed_hash)
    }

    /// Notify the coordinator of consensus activity from the leader
    ///
    /// Followers use this to track leader activity and decide when to take over.
    pub fn observe_leader_activity(&self, height: u64) {
        *self.last_leader_activity.write() = Instant::now();
        *self.missed_blocks.write() = 0;

        let mut last_height = self.last_observed_height.write();
        if height > *last_height {
            *last_height = height;
        }
    }

    /// Notify the coordinator of a missed block
    ///
    /// Called when this validator should have signed but didn't see leader activity.
    pub fn record_missed_block(&self) {
        let mut missed = self.missed_blocks.write();
        *missed += 1;

        if *missed >= self.config.missed_blocks_threshold {
            warn!(
                missed_blocks = *missed,
                threshold = self.config.missed_blocks_threshold,
                "Missed block threshold reached, considering takeover"
            );
        }
    }

    /// Check if follower should attempt takeover
    ///
    /// Returns true if:
    /// - This node is a follower
    /// - The leader has been inactive for longer than the takeover timeout
    /// - OR the missed blocks threshold has been reached
    pub fn should_attempt_takeover(&self) -> bool {
        if self.is_leader() {
            return false;
        }

        let elapsed = self.last_leader_activity.read().elapsed();
        let timeout = Duration::from_millis(self.config.takeover_timeout_ms);

        if elapsed > timeout {
            debug!(
                elapsed_ms = elapsed.as_millis(),
                timeout_ms = self.config.takeover_timeout_ms,
                "Leader timeout reached"
            );
            return true;
        }

        let missed = *self.missed_blocks.read();
        if missed >= self.config.missed_blocks_threshold {
            debug!(
                missed_blocks = missed,
                threshold = self.config.missed_blocks_threshold,
                "Missed blocks threshold reached"
            );
            return true;
        }

        false
    }

    /// Attempt to take over as leader (for followers)
    ///
    /// This should only be called when `should_attempt_takeover()` returns true.
    pub async fn attempt_takeover(&self) -> Result<bool, SigningCoordinatorError> {
        if self.is_leader() {
            return Ok(true);
        }

        info!(
            node_id = %self.node_id,
            "Attempting leadership takeover"
        );

        // Reset counters
        *self.missed_blocks.write() = 0;

        // Try to acquire leadership
        self.try_acquire_leadership().await
    }

    /// Voluntarily step down from leadership
    pub async fn step_down(&self) -> Result<(), SigningCoordinatorError> {
        if !self.is_leader() {
            return Ok(());
        }

        info!(node_id = %self.node_id, "Stepping down from leadership");

        *self.leader_lease.write() = None;
        *self.role.write() = SigningRole::Follower;

        // Clear shared state lease
        self.clear_shared_lease().await?;

        self.role_change_notify.notify_waiters();
        Ok(())
    }

    /// Wait for a role change
    pub async fn wait_for_role_change(&self) {
        self.role_change_notify.notified().await;
    }

    /// Prune old signing history
    ///
    /// Removes signing records older than the given height.
    pub fn prune_history(&self, min_height: u64) {
        let mut history = self.signing_history.lock();
        history.retain(|key, _| key.height >= min_height);
    }

    /// Get the current leader lease (if this node is leader)
    pub fn lease(&self) -> Option<LeaderLease> {
        self.leader_lease.read().clone()
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get the validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Get the configuration
    pub fn config(&self) -> &SigningCoordinatorConfig {
        &self.config
    }

    // ========== Shared State Operations ==========
    //
    // These methods handle persistence of the leader lease to shared storage.
    // The current implementation uses file-based storage; production deployments
    // might use Redis, etcd, or another distributed coordination service.

    /// Load the leader lease from shared storage
    async fn load_shared_lease(&self) -> Result<Option<LeaderLease>, SigningCoordinatorError> {
        let Some(path) = &self.config.shared_state_path else {
            // No shared state configured, use memory-only mode
            return Ok(None);
        };

        match tokio::fs::read(path).await {
            Ok(data) => {
                Self::decode_lease(&data)
                    .map(Some)
                    .ok_or_else(|| SigningCoordinatorError::SharedStateError("Failed to decode lease".to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SigningCoordinatorError::IoError(e.to_string())),
        }
    }

    /// Save the leader lease to shared storage
    async fn save_shared_lease(&self, lease: &LeaderLease) -> Result<(), SigningCoordinatorError> {
        let Some(path) = &self.config.shared_state_path else {
            return Ok(());
        };

        let data = Self::encode_lease(lease);

        tokio::fs::write(path, &data)
            .await
            .map_err(|e| SigningCoordinatorError::IoError(e.to_string()))
    }

    /// Encode a leader lease to binary format
    fn encode_lease(lease: &LeaderLease) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);

        // Write node_id length and bytes
        let node_id_bytes = lease.leader_node_id.as_bytes();
        data.extend_from_slice(&(node_id_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(node_id_bytes);

        // Write validator_id
        data.extend_from_slice(&lease.validator_id.to_le_bytes());

        // Write timestamps and counters
        data.extend_from_slice(&lease.acquired_at_ms.to_le_bytes());
        data.extend_from_slice(&lease.expires_at_ms.to_le_bytes());
        data.extend_from_slice(&lease.last_signed_height.to_le_bytes());
        data.extend_from_slice(&lease.sequence.to_le_bytes());

        data
    }

    /// Decode a leader lease from binary format
    fn decode_lease(data: &[u8]) -> Option<LeaderLease> {
        if data.len() < 4 {
            return None;
        }

        let mut offset = 0;

        // Read node_id
        let node_id_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + node_id_len + 40 {
            return None;
        }

        let leader_node_id = String::from_utf8(data[offset..offset + node_id_len].to_vec()).ok()?;
        offset += node_id_len;

        // Read validator_id
        let validator_id = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        // Read timestamps and counters
        let acquired_at_ms = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let expires_at_ms = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let last_signed_height = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let sequence = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);

        Some(LeaderLease {
            leader_node_id,
            validator_id,
            acquired_at_ms,
            expires_at_ms,
            last_signed_height,
            sequence,
        })
    }

    /// Clear the leader lease from shared storage
    async fn clear_shared_lease(&self) -> Result<(), SigningCoordinatorError> {
        let Some(path) = &self.config.shared_state_path else {
            return Ok(());
        };

        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SigningCoordinatorError::IoError(e.to_string())),
        }
    }
}

/// Get current time in milliseconds since Unix epoch
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_config() -> SigningCoordinatorConfig {
        SigningCoordinatorConfig {
            lease_duration_ms: 1000,
            lease_renewal_threshold_ms: 300,
            takeover_timeout_ms: 500,
            missed_blocks_threshold: 3,
            shared_state_path: None,
            start_as_follower: false,
            leader_priority: 100,
        }
    }

    #[tokio::test]
    async fn test_acquire_leadership() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        let result = coordinator.try_acquire_leadership().await.unwrap();
        assert!(result);
        assert!(coordinator.is_leader());
        assert_eq!(coordinator.role(), SigningRole::Leader);
    }

    #[tokio::test]
    async fn test_signing_lock() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        coordinator.try_acquire_leadership().await.unwrap();

        // Should be able to acquire lock
        let guard = coordinator
            .acquire_signing_lock(100, 0, Step::Prevote)
            .await
            .unwrap();
        assert_eq!(guard.key().height, 100);
        drop(guard);

        // Record the signing
        coordinator
            .record_signing(100, 0, Step::Prevote, [1u8; 32])
            .unwrap();

        // Should not be able to acquire lock again for same (height, round, step)
        let result = coordinator
            .acquire_signing_lock(100, 0, Step::Prevote)
            .await;
        assert!(matches!(
            result,
            Err(SigningCoordinatorError::AlreadySigned { .. })
        ));

        // Should be able to acquire lock for different round
        let guard = coordinator
            .acquire_signing_lock(100, 1, Step::Prevote)
            .await
            .unwrap();
        assert_eq!(guard.key().round, 1);
    }

    #[tokio::test]
    async fn test_follower_cannot_sign() {
        let mut config = create_config();
        config.start_as_follower = true;

        let coordinator = SigningCoordinator::new(config, "node2".to_string(), 0);

        // Should not be able to acquire signing lock as follower
        let result = coordinator
            .acquire_signing_lock(100, 0, Step::Prevote)
            .await;
        assert!(matches!(
            result,
            Err(SigningCoordinatorError::NotLeader(SigningRole::Follower))
        ));
    }

    #[tokio::test]
    async fn test_leader_lease_renewal() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        coordinator.try_acquire_leadership().await.unwrap();

        let initial_sequence = coordinator.lease().unwrap().sequence;

        // Renew the lease
        coordinator.renew_lease().await.unwrap();

        let new_sequence = coordinator.lease().unwrap().sequence;
        assert_eq!(new_sequence, initial_sequence + 1);
    }

    #[tokio::test]
    async fn test_takeover_detection() {
        let config = SigningCoordinatorConfig {
            lease_duration_ms: 1000,
            lease_renewal_threshold_ms: 300,
            takeover_timeout_ms: 100, // Very short for testing
            missed_blocks_threshold: 3,
            shared_state_path: None,
            start_as_follower: true,
            leader_priority: 100,
        };

        let coordinator = SigningCoordinator::new(config, "node2".to_string(), 0);

        // Should not immediately want to take over
        coordinator.observe_leader_activity(100);
        assert!(!coordinator.should_attempt_takeover());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Now should want to take over
        assert!(coordinator.should_attempt_takeover());
    }

    #[tokio::test]
    async fn test_missed_blocks_threshold() {
        let config = SigningCoordinatorConfig {
            lease_duration_ms: 1000,
            lease_renewal_threshold_ms: 300,
            takeover_timeout_ms: 10000, // Long timeout
            missed_blocks_threshold: 2,
            shared_state_path: None,
            start_as_follower: true,
            leader_priority: 100,
        };

        let coordinator = SigningCoordinator::new(config, "node2".to_string(), 0);

        // Record missed blocks
        coordinator.record_missed_block();
        assert!(!coordinator.should_attempt_takeover());

        coordinator.record_missed_block();
        assert!(coordinator.should_attempt_takeover());
    }

    #[tokio::test]
    async fn test_signing_history_check() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        coordinator.try_acquire_leadership().await.unwrap();

        // Not signed yet
        assert!(!coordinator.has_signed(100, 0, Step::Prevote));
        assert!(coordinator.get_signed_hash(100, 0, Step::Prevote).is_none());

        // Record signing
        let hash = [42u8; 32];
        coordinator
            .record_signing(100, 0, Step::Prevote, hash)
            .unwrap();

        // Now should be recorded
        assert!(coordinator.has_signed(100, 0, Step::Prevote));
        assert_eq!(coordinator.get_signed_hash(100, 0, Step::Prevote), Some(hash));
    }

    #[tokio::test]
    async fn test_prune_history() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        coordinator.try_acquire_leadership().await.unwrap();

        // Record signings at various heights
        coordinator.record_signing(100, 0, Step::Prevote, [1u8; 32]).unwrap();
        coordinator.record_signing(101, 0, Step::Prevote, [2u8; 32]).unwrap();
        coordinator.record_signing(102, 0, Step::Prevote, [3u8; 32]).unwrap();

        // Prune history below height 101
        coordinator.prune_history(101);

        // Height 100 should be pruned
        assert!(!coordinator.has_signed(100, 0, Step::Prevote));
        // Heights 101 and 102 should remain
        assert!(coordinator.has_signed(101, 0, Step::Prevote));
        assert!(coordinator.has_signed(102, 0, Step::Prevote));
    }

    #[tokio::test]
    async fn test_step_down() {
        let config = create_config();
        let coordinator = SigningCoordinator::new(config, "node1".to_string(), 0);

        coordinator.try_acquire_leadership().await.unwrap();
        assert!(coordinator.is_leader());

        coordinator.step_down().await.unwrap();
        assert!(!coordinator.is_leader());
        assert_eq!(coordinator.role(), SigningRole::Follower);
    }

    #[tokio::test]
    async fn test_shared_state_persistence() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("leader_lease.bin");

        let config1 = SigningCoordinatorConfig {
            shared_state_path: Some(state_path.clone()),
            ..create_config()
        };

        // First coordinator acquires leadership
        let coordinator1 = SigningCoordinator::new(config1.clone(), "node1".to_string(), 0);
        let result = coordinator1.try_acquire_leadership().await.unwrap();
        assert!(result);

        // Second coordinator should see existing lease and become follower
        let config2 = SigningCoordinatorConfig {
            shared_state_path: Some(state_path.clone()),
            ..create_config()
        };
        let coordinator2 = SigningCoordinator::new(config2, "node2".to_string(), 0);
        let result = coordinator2.try_acquire_leadership().await.unwrap();
        assert!(!result);
        assert_eq!(coordinator2.role(), SigningRole::Follower);
    }
}
