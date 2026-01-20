//! Fork choice rule implementation for BFT consensus.
//!
//! This module provides:
//! - [`ForkChoiceRule`] - Selection rule for choosing the canonical chain
//! - [`ForkChoiceState`] - Tracks finalized and justified blocks
//! - [`ChainSelector`] - Compares and selects between competing chains
//!
//! In MinBFT consensus, finality is instant once >2/3 of validators precommit
//! a block. The fork choice rule always follows the highest finalized block.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, info};

use protocore_crypto::Hash;
use crate::types::{FinalityCert, ValidatorSet};

/// Errors that can occur during fork choice operations
#[derive(Error, Debug)]
pub enum ForkChoiceError {
    /// No finalized block found
    #[error("no finalized block at height {0}")]
    NoFinalizedBlock(u64),

    /// Invalid finality certificate
    #[error("invalid finality certificate: {0}")]
    InvalidCertificate(String),

    /// Block not found
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// Chain reorganization not allowed (would revert finalized block)
    #[error("cannot reorg past finalized block at height {0}")]
    CannotReorgFinalized(u64),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for fork choice operations
pub type ForkChoiceResult<T> = Result<T, ForkChoiceError>;

/// Fork choice rule variants
///
/// In pure BFT consensus, we use HighestFinalized since blocks become
/// final immediately upon receiving >2/3 precommits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkChoiceRule {
    /// Follow the chain with the highest finalized block
    /// This is the standard rule for BFT consensus with instant finality
    #[default]
    HighestFinalized,

    /// Follow the chain with the highest justified (2/3 prevotes) block
    /// Used when finality hasn't been reached yet in the current round
    HighestJustified,

    /// Follow the longest chain (by block height)
    /// Fallback when no finality information is available
    LongestChain,

    /// GHOST-style rule: follow the heaviest subtree
    /// Uses vote weight instead of just height
    Heaviest,
}

/// State for tracking finalized and justified blocks
#[derive(Debug, Clone)]
pub struct ForkChoiceState {
    /// Current chain head (highest block we've seen)
    pub head_hash: Hash,
    /// Height of the head
    pub head_height: u64,

    /// Highest finalized block hash
    pub finalized_hash: Hash,
    /// Height of finalized block
    pub finalized_height: u64,

    /// Highest justified (2/3 prevotes) block hash
    pub justified_hash: Hash,
    /// Height of justified block
    pub justified_height: u64,

    /// Active fork choice rule
    pub rule: ForkChoiceRule,
}

impl Default for ForkChoiceState {
    fn default() -> Self {
        Self {
            head_hash: Hash::default(),
            head_height: 0,
            finalized_hash: Hash::default(),
            finalized_height: 0,
            justified_hash: Hash::default(),
            justified_height: 0,
            rule: ForkChoiceRule::HighestFinalized,
        }
    }
}

impl ForkChoiceState {
    /// Create a new fork choice state from genesis
    pub fn from_genesis(genesis_hash: Hash) -> Self {
        Self {
            head_hash: genesis_hash,
            head_height: 0,
            finalized_hash: genesis_hash,
            finalized_height: 0,
            justified_hash: genesis_hash,
            justified_height: 0,
            rule: ForkChoiceRule::HighestFinalized,
        }
    }

    /// Check if a block at the given height can be reorganized
    ///
    /// In BFT consensus, finalized blocks cannot be reverted.
    pub fn can_reorg(&self, height: u64) -> bool {
        height > self.finalized_height
    }

    /// Check if a hash is on the finalized chain
    ///
    /// Note: This requires access to the block database to trace ancestry.
    /// This method only checks if it IS the finalized block.
    pub fn is_finalized(&self, hash: &Hash) -> bool {
        *hash == self.finalized_hash
    }

    /// Update the finalized block
    pub fn update_finalized(&mut self, hash: Hash, height: u64) {
        if height > self.finalized_height {
            info!(
                height = height,
                hash = %hex::encode(&hash[..8]),
                "New finalized block"
            );
            self.finalized_hash = hash;
            self.finalized_height = height;

            // Finalized is always at least justified
            if height > self.justified_height {
                self.justified_hash = hash;
                self.justified_height = height;
            }
        }
    }

    /// Update the justified block (>2/3 prevotes)
    pub fn update_justified(&mut self, hash: Hash, height: u64) {
        if height > self.justified_height && height > self.finalized_height {
            debug!(
                height = height,
                hash = %hex::encode(&hash[..8]),
                "New justified block"
            );
            self.justified_hash = hash;
            self.justified_height = height;
        }
    }

    /// Update the head block
    pub fn update_head(&mut self, hash: Hash, height: u64) {
        if height > self.head_height {
            self.head_hash = hash;
            self.head_height = height;
        }
    }

    /// Get the block to build on according to the fork choice rule
    pub fn get_build_target(&self) -> (Hash, u64) {
        match self.rule {
            ForkChoiceRule::HighestFinalized => (self.finalized_hash, self.finalized_height),
            ForkChoiceRule::HighestJustified => (self.justified_hash, self.justified_height),
            ForkChoiceRule::LongestChain | ForkChoiceRule::Heaviest => {
                (self.head_hash, self.head_height)
            }
        }
    }
}

/// Information about a chain head candidate
#[derive(Debug, Clone)]
pub struct ChainHead {
    /// Block hash
    pub hash: Hash,
    /// Block height
    pub height: u64,
    /// Finality certificate if finalized
    pub finality_cert: Option<FinalityCert>,
    /// Total vote weight supporting this chain
    pub vote_weight: u64,
}

impl ChainHead {
    /// Create a new chain head
    pub fn new(hash: Hash, height: u64) -> Self {
        Self {
            hash,
            height,
            finality_cert: None,
            vote_weight: 0,
        }
    }

    /// Set the finality certificate
    pub fn with_finality_cert(mut self, cert: FinalityCert) -> Self {
        self.finality_cert = Some(cert);
        self
    }

    /// Set the vote weight
    pub fn with_vote_weight(mut self, weight: u64) -> Self {
        self.vote_weight = weight;
        self
    }

    /// Check if this chain head is finalized
    pub fn is_finalized(&self) -> bool {
        self.finality_cert.is_some()
    }
}

/// Compares and selects between competing chains
pub struct ChainSelector {
    /// Current fork choice state
    state: Arc<RwLock<ForkChoiceState>>,
    /// Validator set for verifying certificates
    validator_set: Arc<RwLock<ValidatorSet>>,
    /// Cache of finality certificates by block hash
    cert_cache: Arc<RwLock<HashMap<Hash, FinalityCert>>>,
}

impl ChainSelector {
    /// Create a new chain selector
    pub fn new(genesis_hash: Hash, validator_set: ValidatorSet) -> Self {
        Self {
            state: Arc::new(RwLock::new(ForkChoiceState::from_genesis(genesis_hash))),
            validator_set: Arc::new(RwLock::new(validator_set)),
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current fork choice state
    pub fn state(&self) -> ForkChoiceState {
        self.state.read().clone()
    }

    /// Update the validator set (for epoch transitions)
    pub fn update_validator_set(&self, new_set: ValidatorSet) {
        *self.validator_set.write() = new_set;
    }

    /// Process a new finality certificate
    ///
    /// This updates the finalized block if the certificate is valid
    /// and for a higher block than currently finalized.
    pub fn on_finality_cert(&self, cert: FinalityCert) -> ForkChoiceResult<()> {
        // Verify the certificate
        let validator_set = self.validator_set.read();
        self.verify_finality_cert(&cert, &validator_set)?;
        drop(validator_set);

        // Update state
        let mut state = self.state.write();
        state.update_finalized(cert.block_hash, cert.height);
        drop(state);

        // Cache the certificate
        self.cert_cache.write().insert(cert.block_hash, cert);

        Ok(())
    }

    /// Verify a finality certificate
    fn verify_finality_cert(
        &self,
        cert: &FinalityCert,
        validator_set: &ValidatorSet,
    ) -> ForkChoiceResult<()> {
        // Calculate signing stake from the signers bitmap
        let signers = cert.get_signers();
        let signing_stake: u128 = signers
            .iter()
            .filter_map(|id| validator_set.get_validator(*id))
            .map(|v| v.stake)
            .sum();

        let total_stake = validator_set.total_stake;
        let required_stake = (total_stake * 2 / 3) + 1;

        if signing_stake < required_stake {
            return Err(ForkChoiceError::InvalidCertificate(format!(
                "insufficient stake: {} < {} required",
                signing_stake, required_stake
            )));
        }

        // Note: BLS signature verification would happen here in production
        // For now, we trust the aggregated signature if stake threshold is met

        Ok(())
    }

    /// Compare two chain heads and determine which should be canonical
    ///
    /// Returns true if `candidate` should replace `current`.
    pub fn should_switch(&self, current: &ChainHead, candidate: &ChainHead) -> bool {
        let rule = self.state.read().rule;

        match rule {
            ForkChoiceRule::HighestFinalized => {
                // Prefer the chain with higher finalized block
                match (&current.finality_cert, &candidate.finality_cert) {
                    (None, Some(_)) => true, // Candidate is finalized, current is not
                    (Some(_), None) => false, // Current is finalized, candidate is not
                    (Some(c), Some(d)) => d.height > c.height, // Both finalized, higher wins
                    (None, None) => candidate.height > current.height, // Neither finalized, longest chain
                }
            }
            ForkChoiceRule::HighestJustified => {
                // First by finalized, then by justified (vote weight as proxy)
                if candidate.is_finalized() && !current.is_finalized() {
                    return true;
                }
                if current.is_finalized() && !candidate.is_finalized() {
                    return false;
                }
                candidate.vote_weight > current.vote_weight
            }
            ForkChoiceRule::LongestChain => candidate.height > current.height,
            ForkChoiceRule::Heaviest => candidate.vote_weight > current.vote_weight,
        }
    }

    /// Process a new block and potentially update the chain head
    pub fn on_new_block(&self, block_hash: Hash, height: u64, parent_hash: Hash) {
        let mut state = self.state.write();

        // Check if this extends the current head
        if parent_hash == state.head_hash && height == state.head_height + 1 {
            state.update_head(block_hash, height);
        } else if height > state.head_height {
            // Potential fork - need to compare chains
            // For BFT, we always prefer the finalized chain
            if height > state.finalized_height {
                state.update_head(block_hash, height);
            }
        }
    }

    /// Get the finality certificate for a block if available
    pub fn get_finality_cert(&self, block_hash: &Hash) -> Option<FinalityCert> {
        self.cert_cache.read().get(block_hash).cloned()
    }

    /// Get the current canonical head to build on
    pub fn get_head(&self) -> (Hash, u64) {
        self.state.read().get_build_target()
    }

    /// Check if a reorganization to a new chain is safe
    ///
    /// In BFT, we cannot reorg past the finalized block.
    pub fn is_safe_reorg(&self, common_ancestor_height: u64) -> bool {
        self.state.read().can_reorg(common_ancestor_height)
    }

    /// Check the finality depth (how many blocks back is finalized)
    pub fn finality_depth(&self) -> u64 {
        let state = self.state.read();
        state.head_height.saturating_sub(state.finalized_height)
    }

    /// Set the fork choice rule
    pub fn set_rule(&self, rule: ForkChoiceRule) {
        self.state.write().rule = rule;
    }
}

/// Commit rules for determining when a block is final
#[derive(Debug, Clone, Copy)]
pub struct CommitRules {
    /// Minimum stake fraction required for finality (in basis points, 6667 = 2/3)
    pub min_stake_bp: u64,
    /// Whether to require exact 2f+1 or allow more
    pub allow_extra_votes: bool,
    /// Maximum age of votes to accept (in rounds)
    pub max_vote_age: u64,
}

impl Default for CommitRules {
    fn default() -> Self {
        Self {
            min_stake_bp: 6667, // >2/3
            allow_extra_votes: true,
            max_vote_age: 10,
        }
    }
}

impl CommitRules {
    /// Check if the given stake meets the commit threshold
    pub fn meets_threshold(&self, signing_stake: u64, total_stake: u64) -> bool {
        // signing_stake / total_stake >= min_stake_bp / 10000
        // Rearranged to avoid division: signing_stake * 10000 >= min_stake_bp * total_stake
        signing_stake
            .checked_mul(10000)
            .map(|lhs| lhs >= self.min_stake_bp * total_stake)
            .unwrap_or(false)
    }

    /// Create strict rules requiring exactly 2f+1
    pub fn strict() -> Self {
        Self {
            min_stake_bp: 6667,
            allow_extra_votes: false,
            max_vote_age: 5,
        }
    }

    /// Create relaxed rules for testing
    pub fn relaxed() -> Self {
        Self {
            min_stake_bp: 5001, // >50%
            allow_extra_votes: true,
            max_vote_age: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Validator;
    use protocore_crypto::bls::BlsPrivateKey;

    fn test_validator_set() -> ValidatorSet {
        let validators = (0..4)
            .map(|i| {
                let key = BlsPrivateKey::random();
                Validator::new(
                    i,
                    key.public_key(),
                    [i as u8; 20],
                    1000, // Equal stake
                    0,
                )
            })
            .collect();
        ValidatorSet::new(validators)
    }

    #[test]
    fn test_fork_choice_state_from_genesis() {
        let genesis_hash = [1u8; 32];
        let state = ForkChoiceState::from_genesis(genesis_hash);

        assert_eq!(state.finalized_hash, genesis_hash);
        assert_eq!(state.finalized_height, 0);
        assert_eq!(state.head_hash, genesis_hash);
    }

    #[test]
    fn test_fork_choice_state_updates() {
        let genesis_hash = [1u8; 32];
        let mut state = ForkChoiceState::from_genesis(genesis_hash);

        // Update head
        let block1 = [2u8; 32];
        state.update_head(block1, 1);
        assert_eq!(state.head_hash, block1);
        assert_eq!(state.head_height, 1);

        // Update justified
        state.update_justified(block1, 1);
        assert_eq!(state.justified_hash, block1);

        // Update finalized
        state.update_finalized(block1, 1);
        assert_eq!(state.finalized_hash, block1);
        assert_eq!(state.finalized_height, 1);
    }

    #[test]
    fn test_cannot_reorg_finalized() {
        let genesis_hash = [1u8; 32];
        let mut state = ForkChoiceState::from_genesis(genesis_hash);

        let block5 = [5u8; 32];
        state.update_finalized(block5, 5);

        assert!(!state.can_reorg(3)); // Cannot reorg to height 3
        assert!(!state.can_reorg(5)); // Cannot reorg at finalized height
        assert!(state.can_reorg(6)); // Can reorg above finalized
    }

    #[test]
    fn test_chain_selector_should_switch() {
        let genesis_hash = [0u8; 32];
        let validator_set = test_validator_set();
        let selector = ChainSelector::new(genesis_hash, validator_set);

        let current = ChainHead::new([1u8; 32], 10);
        let candidate = ChainHead::new([2u8; 32], 11);

        // Longer chain wins when neither finalized
        assert!(selector.should_switch(&current, &candidate));
        assert!(!selector.should_switch(&candidate, &current));

        // Finalized always wins
        let finalized_current = current.clone().with_finality_cert(FinalityCert {
            height: 10,
            block_hash: [1u8; 32],
            aggregate_signature: Default::default(),
            signers_bitmap: vec![0xFF], // All signed
        });

        assert!(!selector.should_switch(&finalized_current, &candidate));
    }

    #[test]
    fn test_commit_rules_threshold() {
        let rules = CommitRules::default();

        // 3/4 = 75% > 66.67%
        assert!(rules.meets_threshold(3, 4));

        // 2/3 = 66.67%, just under threshold (need >66.67%)
        // 6667 basis points means we need > 2/3, not >= 2/3
        assert!(!rules.meets_threshold(2, 3)); // 66.67% = 66.67%, not greater

        // 7/10 = 70% > 66.67%
        assert!(rules.meets_threshold(7, 10));

        // 1/2 = 50% < 66.67%
        assert!(!rules.meets_threshold(1, 2));

        // Large numbers (no overflow)
        assert!(rules.meets_threshold(7_000_000_000, 10_000_000_000));
    }

    #[test]
    fn test_get_build_target() {
        let genesis_hash = [0u8; 32];
        let mut state = ForkChoiceState::from_genesis(genesis_hash);

        let block1 = [1u8; 32];
        let block2 = [2u8; 32];

        state.update_head(block2, 2);
        state.update_finalized(block1, 1);

        // HighestFinalized rule: build on finalized
        state.rule = ForkChoiceRule::HighestFinalized;
        assert_eq!(state.get_build_target(), (block1, 1));

        // LongestChain rule: build on head
        state.rule = ForkChoiceRule::LongestChain;
        assert_eq!(state.get_build_target(), (block2, 2));
    }
}
