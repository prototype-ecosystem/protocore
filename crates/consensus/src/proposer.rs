//! # Shuffled Round-Robin Proposer Selection
//!
//! This module implements the proposer selection mechanism for Proto Core.
//! It combines the fairness of round-robin (like ARK/Solar) with the
//! unpredictability of VRF randomness.
//!
//! ## How It Works
//!
//! - Each epoch consists of N blocks, where N = number of active validators
//! - At the start of each epoch, validators are shuffled using VRF randomness
//! - Each validator proposes exactly one block per epoch
//! - The order is deterministic (verifiable) but unpredictable before the epoch starts
//!
//! ## Benefits
//!
//! 1. **Fair**: Every validator proposes exactly once per round
//! 2. **Unpredictable**: Order is randomized each epoch
//! 3. **DDoS Resistant**: Attacker can't know who to target next
//! 4. **Verifiable**: Anyone can verify the shuffle was done correctly

use protocore_types::Address;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Domain separator for proposer shuffle seed generation
const SHUFFLE_DOMAIN: &[u8] = b"PROTOCORE_PROPOSER_SHUFFLE_V1";

/// Errors that can occur during proposer selection
#[derive(Debug, Error)]
pub enum ProposerError {
    /// No validators in the set
    #[error("Empty validator set")]
    EmptyValidatorSet,

    /// Invalid block height
    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(u64),

    /// Proposer mismatch during verification
    #[error("Wrong proposer: expected {expected}, got {got}")]
    WrongProposer {
        /// Expected proposer address
        expected: Address,
        /// Actual proposer address
        got: Address,
    },

    /// Epoch mismatch
    #[error("Epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch {
        /// Expected epoch
        expected: u64,
        /// Actual epoch
        got: u64,
    },
}

/// Result type for proposer operations
pub type ProposerResult<T> = Result<T, ProposerError>;

/// Proposer selection state machine
///
/// Manages the shuffled round-robin proposer selection for each epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerSelector {
    /// Current epoch number
    epoch: u64,

    /// Shuffled validator order for current epoch
    current_order: Vec<Address>,

    /// Current position in the order (0 to epoch_length-1)
    position: usize,

    /// Blocks per epoch (= number of validators)
    epoch_length: usize,

    /// VRF randomness used for current epoch's shuffle
    epoch_randomness: [u8; 32],

    /// Canonical validator set (sorted by address for determinism)
    validators: Vec<Address>,

    /// Pending validator set changes (applied at next epoch boundary)
    pending_validators: Option<Vec<Address>>,
}

impl ProposerSelector {
    /// Create a new proposer selector at genesis
    ///
    /// # Arguments
    ///
    /// * `validators` - Initial validator set (will be sorted for determinism)
    /// * `genesis_randomness` - Initial randomness for first epoch shuffle
    ///
    /// # Returns
    ///
    /// A new `ProposerSelector` ready for epoch 0
    pub fn new(validators: Vec<Address>, genesis_randomness: [u8; 32]) -> ProposerResult<Self> {
        if validators.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        // Sort validators for deterministic ordering
        let mut sorted_validators = validators;
        sorted_validators.sort();

        let epoch_length = sorted_validators.len();
        let current_order = Self::shuffle(&sorted_validators, &genesis_randomness, 0);

        info!(
            epoch = 0,
            validators = epoch_length,
            first_proposer = %current_order[0],
            "ProposerSelector initialized"
        );

        Ok(Self {
            epoch: 0,
            current_order,
            position: 0,
            epoch_length,
            epoch_randomness: genesis_randomness,
            validators: sorted_validators,
            pending_validators: None,
        })
    }

    /// Get the proposer for a specific block height
    ///
    /// This can compute the proposer for any height, even in future epochs,
    /// as long as the randomness for that epoch is known.
    pub fn get_proposer(&self, block_height: u64) -> ProposerResult<Address> {
        if self.epoch_length == 0 {
            return Err(ProposerError::EmptyValidatorSet);
        }

        let epoch = block_height / self.epoch_length as u64;
        let position = (block_height % self.epoch_length as u64) as usize;

        if epoch == self.epoch {
            // Current epoch - use cached order
            Ok(self.current_order[position])
        } else if epoch < self.epoch {
            // Past epoch - would need historical randomness
            // For now, this requires the caller to have the historical randomness
            warn!(
                requested_epoch = epoch,
                current_epoch = self.epoch,
                "Requested proposer for past epoch"
            );
            // Recompute with current randomness (caller should provide correct randomness)
            let order = Self::shuffle(&self.validators, &self.epoch_randomness, epoch);
            Ok(order[position])
        } else {
            // Future epoch - cannot predict without knowing future randomness
            debug!(
                requested_epoch = epoch,
                current_epoch = self.epoch,
                "Requested proposer for future epoch - using projected randomness"
            );
            // Project forward using current randomness (not secure, just for estimation)
            let projected_randomness = Self::project_randomness(&self.epoch_randomness, epoch);
            let order = Self::shuffle(&self.validators, &projected_randomness, epoch);
            Ok(order[position])
        }
    }

    /// Get the proposer for a specific block height with explicit randomness
    ///
    /// Use this for verification when you have the exact epoch randomness.
    pub fn get_proposer_with_randomness(
        &self,
        block_height: u64,
        epoch_randomness: &[u8; 32],
    ) -> ProposerResult<Address> {
        if self.validators.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        let epoch = block_height / self.validators.len() as u64;
        let position = (block_height % self.validators.len() as u64) as usize;

        let order = Self::shuffle(&self.validators, epoch_randomness, epoch);
        Ok(order[position])
    }

    /// Advance to the next block and return the current proposer
    ///
    /// If the epoch ends, advances to the new epoch with the provided randomness.
    ///
    /// # Arguments
    ///
    /// * `new_randomness` - New randomness for the next epoch (if epoch transition occurs)
    ///
    /// # Returns
    ///
    /// The proposer for the current position before advancing
    pub fn next_proposer(&mut self, new_randomness: Option<[u8; 32]>) -> ProposerResult<Address> {
        if self.current_order.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        let proposer = self.current_order[self.position];

        self.position += 1;

        // Check if epoch ended
        if self.position >= self.epoch_length {
            let randomness = new_randomness.unwrap_or(self.epoch_randomness);
            self.advance_epoch(randomness)?;
        }

        Ok(proposer)
    }

    /// Get the backup proposer for a given height
    ///
    /// If the primary proposer misses their slot, the backup takes over.
    ///
    /// # Arguments
    ///
    /// * `block_height` - The block height
    /// * `backup_level` - Which backup (1 = first backup, 2 = second, etc.)
    pub fn get_backup_proposer(&self, block_height: u64, backup_level: usize) -> ProposerResult<Address> {
        if self.current_order.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        let position = (block_height % self.epoch_length as u64) as usize;
        let backup_position = (position + backup_level) % self.epoch_length;

        Ok(self.current_order[backup_position])
    }

    /// Verify that a proposer is correct for a given block
    ///
    /// # Arguments
    ///
    /// * `block_height` - The block height
    /// * `claimed_proposer` - The proposer claimed in the block
    /// * `epoch_randomness` - The randomness for this epoch
    ///
    /// # Returns
    ///
    /// `Ok(())` if the proposer is correct, `Err(WrongProposer)` otherwise
    pub fn verify_proposer(
        &self,
        block_height: u64,
        claimed_proposer: Address,
        epoch_randomness: &[u8; 32],
    ) -> ProposerResult<()> {
        let expected = self.get_proposer_with_randomness(block_height, epoch_randomness)?;

        if expected != claimed_proposer {
            return Err(ProposerError::WrongProposer {
                expected,
                got: claimed_proposer,
            });
        }

        Ok(())
    }

    /// Advance to a new epoch
    ///
    /// This applies any pending validator set changes and reshuffles.
    fn advance_epoch(&mut self, new_randomness: [u8; 32]) -> ProposerResult<()> {
        self.epoch += 1;
        self.position = 0;
        self.epoch_randomness = new_randomness;

        // Apply pending validator set changes if any
        if let Some(pending) = self.pending_validators.take() {
            self.validators = pending;
            self.validators.sort(); // Ensure deterministic ordering
        }

        if self.validators.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        self.epoch_length = self.validators.len();

        // Shuffle for new epoch
        self.current_order = Self::shuffle(&self.validators, &new_randomness, self.epoch);

        info!(
            epoch = self.epoch,
            validators = self.epoch_length,
            first_proposer = %self.current_order[0],
            "Advanced to new epoch"
        );

        Ok(())
    }

    /// Schedule a validator set change for the next epoch boundary
    ///
    /// Changes take effect at the next epoch transition to ensure
    /// the current epoch's proposer order remains valid.
    pub fn schedule_validator_change(&mut self, new_validators: Vec<Address>) {
        info!(
            current_epoch = self.epoch,
            current_validators = self.validators.len(),
            new_validators = new_validators.len(),
            "Validator set change scheduled for next epoch"
        );
        self.pending_validators = Some(new_validators);
    }

    /// Force an immediate validator set change and reshuffle
    ///
    /// Use with caution - this invalidates the current epoch's remaining proposer slots.
    pub fn force_validator_change(&mut self, new_validators: Vec<Address>, randomness: [u8; 32]) -> ProposerResult<()> {
        warn!(
            epoch = self.epoch,
            position = self.position,
            "Forcing immediate validator set change"
        );

        self.validators = new_validators;
        self.validators.sort();
        self.pending_validators = None;

        // Reshuffle immediately
        self.advance_epoch(randomness)
    }

    /// Fisher-Yates shuffle using deterministic randomness
    ///
    /// This produces the same shuffle given the same inputs, making it verifiable.
    fn shuffle(validators: &[Address], randomness: &[u8; 32], epoch: u64) -> Vec<Address> {
        let mut order: Vec<Address> = validators.to_vec();
        let n = order.len();

        if n <= 1 {
            return order;
        }

        // Create deterministic RNG from randomness + epoch
        let mut rng = Self::create_rng(randomness, epoch);

        // Fisher-Yates shuffle (inside-out variant)
        for i in (1..n).rev() {
            let j = rng.gen_range(0..=i);
            order.swap(i, j);
        }

        order
    }

    /// Create a deterministic RNG seeded from randomness and epoch
    fn create_rng(randomness: &[u8; 32], epoch: u64) -> ChaCha20Rng {
        let mut hasher = Sha256::new();
        hasher.update(SHUFFLE_DOMAIN);
        hasher.update(randomness);
        hasher.update(&epoch.to_le_bytes());

        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash);

        ChaCha20Rng::from_seed(seed)
    }

    /// Project randomness for a future epoch (not cryptographically secure)
    ///
    /// This is only used for estimation purposes when future randomness is unknown.
    fn project_randomness(current: &[u8; 32], target_epoch: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PROJECTED_RANDOMNESS");
        hasher.update(current);
        hasher.update(&target_epoch.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    // Getters

    /// Get the current epoch number
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the current position within the epoch
    pub fn current_position(&self) -> usize {
        self.position
    }

    /// Get the epoch length (number of validators)
    pub fn epoch_length(&self) -> usize {
        self.epoch_length
    }

    /// Get the current epoch's shuffled order
    pub fn current_order(&self) -> &[Address] {
        &self.current_order
    }

    /// Get the canonical validator set
    pub fn validators(&self) -> &[Address] {
        &self.validators
    }

    /// Get the current epoch's randomness
    pub fn epoch_randomness(&self) -> &[u8; 32] {
        &self.epoch_randomness
    }

    /// Check if there are pending validator changes
    pub fn has_pending_changes(&self) -> bool {
        self.pending_validators.is_some()
    }

    /// Get the number of remaining blocks in the current epoch
    pub fn remaining_in_epoch(&self) -> usize {
        self.epoch_length.saturating_sub(self.position)
    }

    /// Calculate which epoch a block height belongs to
    pub fn epoch_for_height(&self, height: u64) -> u64 {
        if self.epoch_length == 0 {
            return 0;
        }
        height / self.epoch_length as u64
    }

    /// Calculate the position within an epoch for a block height
    pub fn position_for_height(&self, height: u64) -> usize {
        if self.epoch_length == 0 {
            return 0;
        }
        (height % self.epoch_length as u64) as usize
    }

    /// Get the first block height of an epoch
    pub fn epoch_start_height(&self, epoch: u64) -> u64 {
        epoch * self.epoch_length as u64
    }

    /// Get the last block height of an epoch
    pub fn epoch_end_height(&self, epoch: u64) -> u64 {
        (epoch + 1) * self.epoch_length as u64 - 1
    }

    /// Create a snapshot for persistence
    pub fn snapshot(&self) -> ProposerSnapshot {
        ProposerSnapshot {
            epoch: self.epoch,
            position: self.position,
            epoch_randomness: self.epoch_randomness,
            validators: self.validators.clone(),
            pending_validators: self.pending_validators.clone(),
        }
    }

    /// Restore from a snapshot
    pub fn restore(snapshot: ProposerSnapshot) -> ProposerResult<Self> {
        if snapshot.validators.is_empty() {
            return Err(ProposerError::EmptyValidatorSet);
        }

        let mut validators = snapshot.validators;
        validators.sort();

        let epoch_length = validators.len();
        let current_order = Self::shuffle(&validators, &snapshot.epoch_randomness, snapshot.epoch);

        Ok(Self {
            epoch: snapshot.epoch,
            current_order,
            position: snapshot.position,
            epoch_length,
            epoch_randomness: snapshot.epoch_randomness,
            validators,
            pending_validators: snapshot.pending_validators,
        })
    }
}

/// Snapshot of proposer selector state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerSnapshot {
    /// Current epoch
    pub epoch: u64,
    /// Position within epoch
    pub position: usize,
    /// Current epoch randomness
    pub epoch_randomness: [u8; 32],
    /// Validator set
    pub validators: Vec<Address>,
    /// Pending validator changes
    pub pending_validators: Option<Vec<Address>>,
}

/// Proposer selection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerConfig {
    /// Selection mechanism
    pub selection: ProposerSelection,

    /// Timeout for proposer to produce block (milliseconds)
    pub propose_timeout_ms: u64,

    /// Maximum backup proposers to try before giving up
    pub max_backup_attempts: u32,

    /// Timeout multiplier for backup proposers (e.g., 0.5 = half the time)
    pub backup_timeout_multiplier: f64,
}

/// Proposer selection mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposerSelection {
    /// Shuffled round-robin (default, recommended)
    ShuffledRoundRobin,
    /// Pure round-robin (predictable, like ARK)
    RoundRobin,
}

impl Default for ProposerConfig {
    fn default() -> Self {
        Self {
            selection: ProposerSelection::ShuffledRoundRobin,
            propose_timeout_ms: 2000,
            max_backup_attempts: 3,
            backup_timeout_multiplier: 0.5,
        }
    }
}

/// Statistics about proposer selection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposerStats {
    /// Current epoch
    pub epoch: u64,
    /// Progress through current epoch
    pub epoch_progress: String,
    /// Current proposer (if known)
    pub current_proposer: Option<Address>,
    /// Blocks produced this epoch
    pub blocks_produced: u64,
    /// Blocks missed this epoch
    pub blocks_missed: u64,
    /// Per-validator miss counts
    pub validator_misses: HashMap<Address, u64>,
}

impl ProposerStats {
    /// Create new stats from selector state
    pub fn from_selector(selector: &ProposerSelector) -> Self {
        Self {
            epoch: selector.current_epoch(),
            epoch_progress: format!("{}/{}", selector.current_position(), selector.epoch_length()),
            current_proposer: selector.current_order().get(selector.current_position()).copied(),
            blocks_produced: selector.current_position() as u64,
            blocks_missed: 0,
            validator_misses: HashMap::new(),
        }
    }

    /// Record a missed block
    pub fn record_miss(&mut self, validator: Address) {
        self.blocks_missed += 1;
        *self.validator_misses.entry(validator).or_insert(0) += 1;
    }
}

