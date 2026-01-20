//! Epoch System for Validator Set Changes
//!
//! This module implements the epoch system that governs validator set transitions
//! in Proto Core consensus. Validator set changes only occur at epoch boundaries
//! to ensure consensus safety.
//!
//! # Epoch System Design
//!
//! - **Epoch**: A contiguous range of blocks sharing the same validator set
//! - **Epoch Boundary**: The block height where validator set transitions occur
//! - **Epoch Length**: Configurable number of blocks per epoch (default ~1 day)
//!
//! # Transition Safety Rules
//!
//! 1. Use old validator set until epoch commit is finalized
//! 2. New set becomes active at first block of new epoch
//! 3. Validators in both sets can participate during transition
//! 4. Stake changes are only effective at epoch boundaries
//!
//! # Example
//!
//! ```rust,ignore
//! use protocore_consensus::epoch::{EpochConfig, EpochManager};
//!
//! // Create epoch config with 14400 blocks per epoch (~1 day at 6s blocks)
//! let config = EpochConfig::new(14400);
//!
//! // Calculate epoch for a block height
//! let epoch = config.epoch_for_height(28800);
//! assert_eq!(epoch, 2);
//!
//! // Check if height is at epoch boundary
//! let is_boundary = config.is_epoch_boundary(14400);
//! assert!(is_boundary);
//! ```

use std::collections::BTreeMap;

use protocore_crypto::Hash;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::types::{Validator, ValidatorId, ValidatorSet};

/// Number of blocks in an epoch (default ~1 day at 6s block time)
pub const DEFAULT_EPOCH_LENGTH: u64 = 14400;

/// Minimum epoch length to prevent too frequent transitions
pub const MIN_EPOCH_LENGTH: u64 = 100;

/// Maximum epoch length to ensure reasonable validator set updates
pub const MAX_EPOCH_LENGTH: u64 = 100_000;

/// Type alias for epoch number
pub type EpochNumber = u64;

/// Errors that can occur during epoch management
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EpochError {
    /// Invalid epoch length configuration
    #[error("invalid epoch length {length}: must be between {min} and {max}")]
    InvalidEpochLength {
        /// The invalid length
        length: u64,
        /// Minimum allowed
        min: u64,
        /// Maximum allowed
        max: u64,
    },

    /// No validator set for epoch
    #[error("no validator set found for epoch {epoch}")]
    NoValidatorSet {
        /// The epoch without a validator set
        epoch: EpochNumber,
    },

    /// Validator set transition error
    #[error("validator set transition error at epoch {epoch}: {reason}")]
    TransitionError {
        /// The epoch where transition failed
        epoch: EpochNumber,
        /// Reason for failure
        reason: String,
    },

    /// Epoch height mismatch
    #[error("epoch height mismatch: expected {expected}, got {actual}")]
    HeightMismatch {
        /// Expected height
        expected: u64,
        /// Actual height
        actual: u64,
    },

    /// Validator not in current epoch
    #[error("validator {validator_id} not in epoch {epoch}")]
    ValidatorNotInEpoch {
        /// The validator ID
        validator_id: ValidatorId,
        /// The epoch
        epoch: EpochNumber,
    },

    /// Epoch already finalized
    #[error("epoch {epoch} is already finalized")]
    EpochAlreadyFinalized {
        /// The finalized epoch
        epoch: EpochNumber,
    },
}

/// Result type for epoch operations
pub type EpochResult<T> = Result<T, EpochError>;

/// Configuration for the epoch system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Number of blocks per epoch
    epoch_length: u64,
    /// First height where epoch system is active (typically 1 or genesis+1)
    genesis_epoch_height: u64,
}

impl EpochConfig {
    /// Creates a new epoch configuration
    ///
    /// # Arguments
    ///
    /// * `epoch_length` - Number of blocks per epoch
    ///
    /// # Returns
    ///
    /// Result with the configuration or an error if the length is invalid
    pub fn new(epoch_length: u64) -> EpochResult<Self> {
        if epoch_length < MIN_EPOCH_LENGTH || epoch_length > MAX_EPOCH_LENGTH {
            return Err(EpochError::InvalidEpochLength {
                length: epoch_length,
                min: MIN_EPOCH_LENGTH,
                max: MAX_EPOCH_LENGTH,
            });
        }
        Ok(Self {
            epoch_length,
            genesis_epoch_height: 1,
        })
    }

    /// Creates a config with a custom genesis epoch height
    pub fn with_genesis_height(epoch_length: u64, genesis_height: u64) -> EpochResult<Self> {
        let mut config = Self::new(epoch_length)?;
        config.genesis_epoch_height = genesis_height;
        Ok(config)
    }

    /// Returns the number of blocks per epoch
    #[inline]
    pub fn epoch_length(&self) -> u64 {
        self.epoch_length
    }

    /// Returns the genesis epoch height
    #[inline]
    pub fn genesis_epoch_height(&self) -> u64 {
        self.genesis_epoch_height
    }

    /// Calculates the epoch number for a given block height
    ///
    /// # Arguments
    ///
    /// * `height` - The block height
    ///
    /// # Returns
    ///
    /// The epoch number (0-indexed)
    pub fn epoch_for_height(&self, height: u64) -> EpochNumber {
        if height < self.genesis_epoch_height {
            return 0;
        }
        (height - self.genesis_epoch_height) / self.epoch_length
    }

    /// Returns the first block height of an epoch
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number
    ///
    /// # Returns
    ///
    /// The first block height of the epoch
    pub fn epoch_start_height(&self, epoch: EpochNumber) -> u64 {
        self.genesis_epoch_height + epoch * self.epoch_length
    }

    /// Returns the last block height of an epoch
    ///
    /// # Arguments
    ///
    /// * `epoch` - The epoch number
    ///
    /// # Returns
    ///
    /// The last block height of the epoch
    pub fn epoch_end_height(&self, epoch: EpochNumber) -> u64 {
        self.epoch_start_height(epoch + 1) - 1
    }

    /// Checks if a height is at an epoch boundary (first block of new epoch)
    ///
    /// # Arguments
    ///
    /// * `height` - The block height to check
    ///
    /// # Returns
    ///
    /// True if this height starts a new epoch
    pub fn is_epoch_boundary(&self, height: u64) -> bool {
        if height < self.genesis_epoch_height {
            return false;
        }
        (height - self.genesis_epoch_height) % self.epoch_length == 0
    }

    /// Checks if a height is the last block of an epoch
    ///
    /// # Arguments
    ///
    /// * `height` - The block height to check
    ///
    /// # Returns
    ///
    /// True if this is the last block before an epoch boundary
    pub fn is_epoch_end(&self, height: u64) -> bool {
        if height < self.genesis_epoch_height {
            return false;
        }
        self.is_epoch_boundary(height + 1)
    }

    /// Returns the number of blocks remaining in the current epoch
    ///
    /// # Arguments
    ///
    /// * `height` - The current block height
    ///
    /// # Returns
    ///
    /// Number of blocks until the next epoch boundary
    pub fn blocks_until_epoch_end(&self, height: u64) -> u64 {
        if height < self.genesis_epoch_height {
            return self.genesis_epoch_height - height;
        }
        let position_in_epoch = (height - self.genesis_epoch_height) % self.epoch_length;
        self.epoch_length - position_in_epoch - 1
    }

    /// Returns the progress through the current epoch as a fraction
    ///
    /// # Arguments
    ///
    /// * `height` - The current block height
    ///
    /// # Returns
    ///
    /// Progress as a value between 0.0 and 1.0
    pub fn epoch_progress(&self, height: u64) -> f64 {
        if height < self.genesis_epoch_height {
            return 0.0;
        }
        let position_in_epoch = (height - self.genesis_epoch_height) % self.epoch_length;
        (position_in_epoch as f64 + 1.0) / (self.epoch_length as f64)
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            epoch_length: DEFAULT_EPOCH_LENGTH,
            genesis_epoch_height: 1,
        }
    }
}

/// Represents a validator set for a specific epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochValidatorSet {
    /// The epoch number
    pub epoch: EpochNumber,
    /// The validator set for this epoch
    pub validator_set: ValidatorSet,
    /// Hash of the validator set (for light client verification)
    pub validator_set_hash: Hash,
    /// Whether this epoch has been finalized
    pub finalized: bool,
    /// The height at which this epoch starts
    pub start_height: u64,
    /// The height at which this epoch ends
    pub end_height: u64,
}

impl EpochValidatorSet {
    /// Creates a new epoch validator set
    pub fn new(
        epoch: EpochNumber,
        validator_set: ValidatorSet,
        start_height: u64,
        end_height: u64,
    ) -> Self {
        let validator_set_hash = compute_validator_set_hash(&validator_set);
        Self {
            epoch,
            validator_set,
            validator_set_hash,
            finalized: false,
            start_height,
            end_height,
        }
    }

    /// Returns the number of validators in this epoch
    pub fn validator_count(&self) -> usize {
        self.validator_set.len()
    }

    /// Returns the total stake in this epoch
    pub fn total_stake(&self) -> u128 {
        self.validator_set.total_stake
    }

    /// Checks if a validator is in this epoch's set
    pub fn contains_validator(&self, id: ValidatorId) -> bool {
        self.validator_set.get_validator(id).is_some()
    }

    /// Gets a validator by ID
    pub fn get_validator(&self, id: ValidatorId) -> Option<&Validator> {
        self.validator_set.get_validator(id)
    }

    /// Marks this epoch as finalized
    pub fn finalize(&mut self) {
        self.finalized = true;
    }
}

/// Computes the hash of a validator set for light client verification
///
/// The hash is computed as:
/// ```text
/// keccak256(
///     validator_count ||
///     for each validator (sorted by id):
///         id || pubkey || address || stake
/// )
/// ```
pub fn compute_validator_set_hash(validator_set: &ValidatorSet) -> Hash {
    let mut hasher = Keccak256::new();

    // Include validator count
    hasher.update(&(validator_set.len() as u64).to_le_bytes());

    // Include total stake for quorum verification
    hasher.update(&validator_set.total_stake.to_le_bytes());

    // Include each validator's data (validators are already sorted by id)
    for validator in &validator_set.validators {
        hasher.update(&validator.id.to_le_bytes());
        hasher.update(&validator.pubkey.to_bytes());
        hasher.update(&validator.address);
        hasher.update(&validator.stake.to_le_bytes());
        hasher.update(&validator.commission.to_le_bytes());
        hasher.update(&[validator.active as u8]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Manages validator sets across epochs
///
/// The EpochManager maintains the validator set for each epoch and handles
/// transitions between epochs. It ensures that:
///
/// 1. Validator set changes only occur at epoch boundaries
/// 2. The old set is used until the epoch commit is finalized
/// 3. Validators in both sets can participate during transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochManager {
    /// Epoch configuration
    config: EpochConfig,
    /// Validator sets by epoch number
    epoch_sets: BTreeMap<EpochNumber, EpochValidatorSet>,
    /// Current epoch number
    current_epoch: EpochNumber,
    /// Pending validator set for next epoch (set before epoch boundary)
    pending_validator_set: Option<ValidatorSet>,
    /// Number of historical epochs to retain
    max_historical_epochs: usize,
}

impl EpochManager {
    /// Creates a new epoch manager with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - The epoch configuration
    /// * `initial_validator_set` - The validator set for epoch 0
    pub fn new(config: EpochConfig, initial_validator_set: ValidatorSet) -> Self {
        let epoch_set = EpochValidatorSet::new(
            0,
            initial_validator_set,
            config.genesis_epoch_height(),
            config.epoch_end_height(0),
        );

        let mut epoch_sets = BTreeMap::new();
        epoch_sets.insert(0, epoch_set);

        Self {
            config,
            epoch_sets,
            current_epoch: 0,
            pending_validator_set: None,
            max_historical_epochs: 10,
        }
    }

    /// Returns the epoch configuration
    pub fn config(&self) -> &EpochConfig {
        &self.config
    }

    /// Returns the current epoch number
    pub fn current_epoch(&self) -> EpochNumber {
        self.current_epoch
    }

    /// Returns the validator set for the current epoch
    pub fn current_validator_set(&self) -> EpochResult<&ValidatorSet> {
        self.validator_set_for_epoch(self.current_epoch)
    }

    /// Returns the validator set for a specific epoch
    pub fn validator_set_for_epoch(&self, epoch: EpochNumber) -> EpochResult<&ValidatorSet> {
        self.epoch_sets
            .get(&epoch)
            .map(|es| &es.validator_set)
            .ok_or(EpochError::NoValidatorSet { epoch })
    }

    /// Returns the validator set hash for an epoch
    pub fn validator_set_hash_for_epoch(&self, epoch: EpochNumber) -> EpochResult<Hash> {
        self.epoch_sets
            .get(&epoch)
            .map(|es| es.validator_set_hash)
            .ok_or(EpochError::NoValidatorSet { epoch })
    }

    /// Returns the epoch validator set struct for an epoch
    pub fn epoch_validator_set(&self, epoch: EpochNumber) -> Option<&EpochValidatorSet> {
        self.epoch_sets.get(&epoch)
    }

    /// Gets the validator set for a specific block height
    ///
    /// This handles the edge case at epoch boundaries where the old set
    /// is used until the epoch commit is finalized.
    pub fn validator_set_for_height(&self, height: u64) -> EpochResult<&ValidatorSet> {
        let epoch = self.config.epoch_for_height(height);
        self.validator_set_for_epoch(epoch)
    }

    /// Sets the pending validator set for the next epoch
    ///
    /// This should be called at the end of the epoch (typically computed
    /// from staking state at the epoch boundary).
    ///
    /// # Arguments
    ///
    /// * `validator_set` - The new validator set for the next epoch
    pub fn set_pending_validator_set(&mut self, validator_set: ValidatorSet) {
        info!(
            current_epoch = self.current_epoch,
            next_epoch = self.current_epoch + 1,
            new_validator_count = validator_set.len(),
            new_total_stake = %validator_set.total_stake,
            "Setting pending validator set for next epoch"
        );
        self.pending_validator_set = Some(validator_set);
    }

    /// Processes a block and handles epoch transitions
    ///
    /// This should be called after each block is committed. It handles:
    /// - Finalizing the current epoch if at boundary
    /// - Transitioning to a new epoch if needed
    /// - Activating the pending validator set
    ///
    /// # Arguments
    ///
    /// * `height` - The committed block height
    ///
    /// # Returns
    ///
    /// True if an epoch transition occurred
    pub fn process_block(&mut self, height: u64) -> EpochResult<bool> {
        let block_epoch = self.config.epoch_for_height(height);

        // Check if we're at an epoch boundary (start of new epoch)
        if self.config.is_epoch_boundary(height) && height > self.config.genesis_epoch_height() {
            return self.transition_to_epoch(block_epoch, height);
        }

        // Ensure current epoch matches block epoch
        if block_epoch != self.current_epoch {
            // This can happen during catch-up, just update epoch
            debug!(
                current_epoch = self.current_epoch,
                block_epoch = block_epoch,
                height = height,
                "Epoch mismatch during block processing, updating"
            );
            self.current_epoch = block_epoch;
        }

        Ok(false)
    }

    /// Transitions to a new epoch
    ///
    /// # Arguments
    ///
    /// * `new_epoch` - The new epoch number
    /// * `start_height` - The first block height of the new epoch
    ///
    /// # Returns
    ///
    /// Ok(true) on successful transition, Err on failure
    fn transition_to_epoch(&mut self, new_epoch: EpochNumber, start_height: u64) -> EpochResult<bool> {
        info!(
            old_epoch = self.current_epoch,
            new_epoch = new_epoch,
            start_height = start_height,
            "Transitioning to new epoch"
        );

        // Finalize the previous epoch
        if let Some(prev_epoch_set) = self.epoch_sets.get_mut(&self.current_epoch) {
            prev_epoch_set.finalize();
        }

        // Get the validator set for the new epoch
        let new_validator_set = match self.pending_validator_set.take() {
            Some(pending) => {
                info!(
                    new_epoch = new_epoch,
                    validator_count = pending.len(),
                    "Activating pending validator set"
                );
                pending
            }
            None => {
                // No pending set, carry over the previous epoch's set
                warn!(
                    new_epoch = new_epoch,
                    "No pending validator set, carrying over from previous epoch"
                );
                let prev_set = self
                    .validator_set_for_epoch(self.current_epoch)?
                    .clone();
                prev_set
            }
        };

        // Create the new epoch validator set
        let epoch_set = EpochValidatorSet::new(
            new_epoch,
            new_validator_set,
            start_height,
            self.config.epoch_end_height(new_epoch),
        );

        self.epoch_sets.insert(new_epoch, epoch_set);
        self.current_epoch = new_epoch;

        // Prune old epochs to manage memory
        self.prune_old_epochs();

        Ok(true)
    }

    /// Prunes epoch data older than max_historical_epochs
    fn prune_old_epochs(&mut self) {
        if self.current_epoch <= self.max_historical_epochs as u64 {
            return;
        }

        let prune_before = self.current_epoch - self.max_historical_epochs as u64;
        let epochs_to_remove: Vec<EpochNumber> = self
            .epoch_sets
            .keys()
            .filter(|&&e| e < prune_before)
            .copied()
            .collect();

        for epoch in epochs_to_remove {
            debug!(epoch = epoch, "Pruning old epoch data");
            self.epoch_sets.remove(&epoch);
        }
    }

    /// Checks if a validator is active in the current epoch
    pub fn is_validator_active(&self, validator_id: ValidatorId) -> bool {
        self.epoch_sets
            .get(&self.current_epoch)
            .map(|es| es.contains_validator(validator_id))
            .unwrap_or(false)
    }

    /// Checks if a validator is active in a specific epoch
    pub fn is_validator_active_in_epoch(
        &self,
        validator_id: ValidatorId,
        epoch: EpochNumber,
    ) -> bool {
        self.epoch_sets
            .get(&epoch)
            .map(|es| es.contains_validator(validator_id))
            .unwrap_or(false)
    }

    /// Returns the proposer for a given height and round
    ///
    /// Uses the validator set for the epoch containing the height.
    pub fn get_proposer(&self, height: u64, round: u64) -> EpochResult<&Validator> {
        let validator_set = self.validator_set_for_height(height)?;
        Ok(validator_set.proposer(height, round))
    }

    /// Returns the proposer ID for a given height and round
    pub fn get_proposer_id(&self, height: u64, round: u64) -> EpochResult<ValidatorId> {
        let validator_set = self.validator_set_for_height(height)?;
        Ok(validator_set.proposer_id(height, round))
    }

    /// Gets the next epoch's validator set hash if known
    ///
    /// This is included in block headers at epoch boundaries for light client support.
    pub fn next_validator_set_hash(&self) -> Option<Hash> {
        self.pending_validator_set
            .as_ref()
            .map(compute_validator_set_hash)
    }

    /// Returns epoch info for a given height
    pub fn epoch_info_for_height(&self, height: u64) -> EpochInfo {
        let epoch = self.config.epoch_for_height(height);
        let is_boundary = self.config.is_epoch_boundary(height);
        let is_end = self.config.is_epoch_end(height);
        let blocks_remaining = self.config.blocks_until_epoch_end(height);
        let progress = self.config.epoch_progress(height);

        EpochInfo {
            epoch,
            height,
            is_epoch_boundary: is_boundary,
            is_epoch_end: is_end,
            blocks_until_epoch_end: blocks_remaining,
            epoch_progress: progress,
            epoch_start_height: self.config.epoch_start_height(epoch),
            epoch_end_height: self.config.epoch_end_height(epoch),
        }
    }

    /// Sets the maximum number of historical epochs to retain
    pub fn set_max_historical_epochs(&mut self, max: usize) {
        self.max_historical_epochs = max;
    }
}

/// Information about an epoch at a specific height
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EpochInfo {
    /// The epoch number
    pub epoch: EpochNumber,
    /// The block height
    pub height: u64,
    /// Whether this height is at an epoch boundary
    pub is_epoch_boundary: bool,
    /// Whether this height is the last block of an epoch
    pub is_epoch_end: bool,
    /// Number of blocks until the epoch ends
    pub blocks_until_epoch_end: u64,
    /// Progress through the epoch (0.0 - 1.0)
    pub epoch_progress: f64,
    /// First height of this epoch
    pub epoch_start_height: u64,
    /// Last height of this epoch
    pub epoch_end_height: u64,
}

/// Snapshot of the epoch manager state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochManagerSnapshot {
    /// Epoch configuration
    pub config: EpochConfig,
    /// Current epoch number
    pub current_epoch: EpochNumber,
    /// Epoch sets (for recent epochs)
    pub epoch_sets: BTreeMap<EpochNumber, EpochValidatorSet>,
    /// Pending validator set for next epoch
    pub pending_validator_set: Option<ValidatorSet>,
    /// Maximum historical epochs to retain
    pub max_historical_epochs: usize,
}

impl EpochManager {
    /// Creates a snapshot of the current state for persistence
    pub fn snapshot(&self) -> EpochManagerSnapshot {
        EpochManagerSnapshot {
            config: self.config,
            current_epoch: self.current_epoch,
            epoch_sets: self.epoch_sets.clone(),
            pending_validator_set: self.pending_validator_set.clone(),
            max_historical_epochs: self.max_historical_epochs,
        }
    }

    /// Restores from a snapshot
    pub fn from_snapshot(snapshot: EpochManagerSnapshot) -> Self {
        Self {
            config: snapshot.config,
            current_epoch: snapshot.current_epoch,
            epoch_sets: snapshot.epoch_sets,
            pending_validator_set: snapshot.pending_validator_set,
            max_historical_epochs: snapshot.max_historical_epochs,
        }
    }
}

/// Builder for validator set changes at epoch boundaries
///
/// This struct helps compute the new validator set from staking state changes.
#[derive(Debug, Clone)]
pub struct ValidatorSetBuilder {
    /// Validators being built
    validators: Vec<Validator>,
}

impl ValidatorSetBuilder {
    /// Creates a new builder starting from an existing validator set
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    /// Creates a builder from an existing validator set
    pub fn from_validator_set(validator_set: &ValidatorSet) -> Self {
        Self {
            validators: validator_set.validators.clone(),
        }
    }

    /// Adds a new validator
    pub fn add_validator(&mut self, validator: Validator) -> &mut Self {
        self.validators.push(validator);
        self
    }

    /// Removes a validator by ID
    pub fn remove_validator(&mut self, id: ValidatorId) -> &mut Self {
        self.validators.retain(|v| v.id != id);
        self
    }

    /// Removes a validator by address
    pub fn remove_validator_by_address(&mut self, address: &[u8; 20]) -> &mut Self {
        self.validators.retain(|v| &v.address != address);
        self
    }

    /// Updates a validator's stake
    pub fn update_stake(&mut self, id: ValidatorId, new_stake: u128) -> &mut Self {
        if let Some(validator) = self.validators.iter_mut().find(|v| v.id == id) {
            validator.stake = new_stake;
        }
        self
    }

    /// Updates a validator's active status
    pub fn set_active(&mut self, id: ValidatorId, active: bool) -> &mut Self {
        if let Some(validator) = self.validators.iter_mut().find(|v| v.id == id) {
            validator.active = active;
        }
        self
    }

    /// Builds the final validator set
    ///
    /// Validators are sorted by stake (descending) and assigned sequential IDs.
    pub fn build(mut self) -> ValidatorSet {
        // Sort by stake descending, then by address for determinism
        self.validators.sort_by(|a, b| {
            b.stake
                .cmp(&a.stake)
                .then_with(|| a.address.cmp(&b.address))
        });

        // Filter to only active validators
        self.validators.retain(|v| v.active && v.stake > 0);

        // Reassign IDs
        for (i, validator) in self.validators.iter_mut().enumerate() {
            validator.id = i as ValidatorId;
        }

        ValidatorSet::new(self.validators)
    }
}

impl Default for ValidatorSetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocore_crypto::bls::BlsPrivateKey;

    fn make_test_validator(id: ValidatorId, stake: u128) -> Validator {
        // Generate a random key pair for testing
        let private_key = BlsPrivateKey::random();
        let pubkey = private_key.public_key();
        Validator {
            id,
            pubkey,
            address: [id as u8; 20],
            stake,
            commission: 100,
            active: true,
        }
    }

    fn make_test_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<Validator> = (0..count)
            .map(|i| make_test_validator(i as ValidatorId, 1000 * (count - i) as u128))
            .collect();
        ValidatorSet::new(validators)
    }

    #[test]
    fn test_epoch_config_calculation() {
        let config = EpochConfig::new(100).unwrap();

        // Test epoch calculation
        assert_eq!(config.epoch_for_height(1), 0);
        assert_eq!(config.epoch_for_height(50), 0);
        assert_eq!(config.epoch_for_height(100), 0);
        assert_eq!(config.epoch_for_height(101), 1);
        assert_eq!(config.epoch_for_height(200), 1);
        assert_eq!(config.epoch_for_height(201), 2);

        // Test epoch boundaries
        assert!(config.is_epoch_boundary(1)); // First block is epoch start
        assert!(!config.is_epoch_boundary(50));
        assert!(config.is_epoch_boundary(101));
        assert!(config.is_epoch_boundary(201));

        // Test epoch end
        assert!(config.is_epoch_end(100));
        assert!(config.is_epoch_end(200));
        assert!(!config.is_epoch_end(50));
    }

    #[test]
    fn test_epoch_start_end_heights() {
        let config = EpochConfig::new(100).unwrap();

        assert_eq!(config.epoch_start_height(0), 1);
        assert_eq!(config.epoch_end_height(0), 100);
        assert_eq!(config.epoch_start_height(1), 101);
        assert_eq!(config.epoch_end_height(1), 200);
        assert_eq!(config.epoch_start_height(2), 201);
    }

    #[test]
    fn test_blocks_until_epoch_end() {
        let config = EpochConfig::new(100).unwrap();

        assert_eq!(config.blocks_until_epoch_end(1), 99);
        assert_eq!(config.blocks_until_epoch_end(50), 50);
        assert_eq!(config.blocks_until_epoch_end(100), 0);
        assert_eq!(config.blocks_until_epoch_end(101), 99);
    }

    #[test]
    fn test_epoch_progress() {
        let config = EpochConfig::new(100).unwrap();

        assert!((config.epoch_progress(1) - 0.01).abs() < 0.001);
        assert!((config.epoch_progress(50) - 0.50).abs() < 0.001);
        assert!((config.epoch_progress(100) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_invalid_epoch_length() {
        assert!(EpochConfig::new(50).is_err()); // Too short
        assert!(EpochConfig::new(200_000).is_err()); // Too long
        assert!(EpochConfig::new(100).is_ok());
        assert!(EpochConfig::new(100_000).is_ok());
    }

    #[test]
    fn test_validator_set_hash() {
        let vs1 = make_test_validator_set(4);

        // Same set should produce consistent hash (idempotent)
        let hash1 = compute_validator_set_hash(&vs1);
        let hash2 = compute_validator_set_hash(&vs1);
        assert_eq!(hash1, hash2, "Hash should be idempotent");

        // Different sets should have different hashes
        let vs2 = make_test_validator_set(5);
        let hash3 = compute_validator_set_hash(&vs2);
        assert_ne!(hash1, hash3, "Different validator counts should produce different hashes");

        // Cloned set should have same hash
        let vs1_clone = vs1.clone();
        let hash4 = compute_validator_set_hash(&vs1_clone);
        assert_eq!(hash1, hash4, "Cloned set should have same hash");
    }

    #[test]
    fn test_epoch_manager_basic() {
        let config = EpochConfig::new(100).unwrap();
        let initial_set = make_test_validator_set(4);
        let manager = EpochManager::new(config, initial_set.clone());

        assert_eq!(manager.current_epoch(), 0);
        assert!(manager.current_validator_set().is_ok());
        assert_eq!(manager.current_validator_set().unwrap().len(), 4);
    }

    #[test]
    fn test_epoch_transition() {
        let config = EpochConfig::new(100).unwrap();
        let initial_set = make_test_validator_set(4);
        let mut manager = EpochManager::new(config, initial_set);

        // Process blocks up to epoch boundary
        for height in 1..=100 {
            let transitioned = manager.process_block(height).unwrap();
            assert!(!transitioned, "Should not transition before boundary");
        }

        // Set pending validator set before transition
        let new_set = make_test_validator_set(5);
        manager.set_pending_validator_set(new_set.clone());

        // Process first block of new epoch
        let transitioned = manager.process_block(101).unwrap();
        assert!(transitioned, "Should transition at epoch boundary");
        assert_eq!(manager.current_epoch(), 1);
        assert_eq!(manager.current_validator_set().unwrap().len(), 5);
    }

    #[test]
    fn test_validator_set_builder() {
        let mut builder = ValidatorSetBuilder::new();
        builder.add_validator(make_test_validator(0, 1000));
        builder.add_validator(make_test_validator(1, 2000));
        builder.add_validator(make_test_validator(2, 500));

        let vs = builder.build();

        // Validators should be sorted by stake descending
        assert_eq!(vs.validators[0].stake, 2000);
        assert_eq!(vs.validators[1].stake, 1000);
        assert_eq!(vs.validators[2].stake, 500);

        // IDs should be reassigned sequentially
        assert_eq!(vs.validators[0].id, 0);
        assert_eq!(vs.validators[1].id, 1);
        assert_eq!(vs.validators[2].id, 2);
    }

    #[test]
    fn test_validator_set_builder_modifications() {
        let initial_set = make_test_validator_set(4);
        let mut builder = ValidatorSetBuilder::from_validator_set(&initial_set);

        // Update stake
        builder.update_stake(0, 5000);

        // Remove a validator
        builder.remove_validator(2);

        let vs = builder.build();

        // Should have 3 validators
        assert_eq!(vs.len(), 3);

        // Validator with updated stake should be first (highest stake)
        assert_eq!(vs.validators[0].stake, 5000);
    }

    #[test]
    fn test_epoch_info() {
        let config = EpochConfig::new(100).unwrap();
        let initial_set = make_test_validator_set(4);
        let manager = EpochManager::new(config, initial_set);

        let info = manager.epoch_info_for_height(50);
        assert_eq!(info.epoch, 0);
        assert!(!info.is_epoch_boundary);
        assert!(!info.is_epoch_end);
        assert_eq!(info.blocks_until_epoch_end, 50);

        let info_boundary = manager.epoch_info_for_height(101);
        assert_eq!(info_boundary.epoch, 1);
        assert!(info_boundary.is_epoch_boundary);
    }

    #[test]
    fn test_epoch_validator_set_finalization() {
        let config = EpochConfig::new(100).unwrap();
        let initial_set = make_test_validator_set(4);
        let mut manager = EpochManager::new(config, initial_set);

        // Set pending and transition
        manager.set_pending_validator_set(make_test_validator_set(5));

        // Process to trigger transition
        for height in 1..=101 {
            manager.process_block(height).unwrap();
        }

        // Epoch 0 should be finalized
        let epoch0 = manager.epoch_validator_set(0).unwrap();
        assert!(epoch0.finalized);

        // Epoch 1 should not be finalized yet
        let epoch1 = manager.epoch_validator_set(1).unwrap();
        assert!(!epoch1.finalized);
    }
}
