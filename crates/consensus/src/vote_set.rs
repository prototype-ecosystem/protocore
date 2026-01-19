//! Vote collection and quorum detection for MinBFT consensus.
//!
//! This module handles:
//! - Collecting votes from validators at a specific (height, round, step)
//! - Verifying vote signatures using BLS
//! - Detecting when quorum (>2/3 stake) is reached
//! - Aggregating signatures for finality certificates

use std::collections::HashMap;

use protocore_crypto::{bls::BlsSignature, Hash};
use tracing::{debug, trace, warn};

use crate::types::{ValidatorId, ValidatorSet, Vote, VoteType, NIL_HASH};

/// Error types for vote set operations
#[derive(Debug, thiserror::Error)]
pub enum VoteSetError {
    /// Vote is for wrong height
    #[error("vote height {vote_height} does not match expected {expected_height}")]
    WrongHeight { vote_height: u64, expected_height: u64 },

    /// Vote is for wrong round
    #[error("vote round {vote_round} does not match expected {expected_round}")]
    WrongRound { vote_round: u64, expected_round: u64 },

    /// Vote is for wrong type
    #[error("vote type mismatch")]
    WrongType,

    /// Duplicate vote from same validator
    #[error("duplicate vote from validator {0}")]
    DuplicateVote(ValidatorId),

    /// Invalid validator ID
    #[error("invalid validator ID: {0}")]
    InvalidValidator(ValidatorId),

    /// Invalid signature
    #[error("invalid signature from validator {0}")]
    InvalidSignature(ValidatorId),
}

/// Collection of votes for a specific (height, round, vote_type)
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// Block height
    height: u64,
    /// Round number
    round: u64,
    /// Type of votes in this set
    vote_type: VoteType,
    /// Votes indexed by validator ID
    votes: HashMap<ValidatorId, Vote>,
    /// Validator IDs grouped by block hash they voted for
    votes_by_hash: HashMap<Hash, Vec<ValidatorId>>,
    /// Cached stake totals by hash
    stake_by_hash: HashMap<Hash, u128>,
    /// Total stake that has voted
    total_voted_stake: u128,
}

impl VoteSet {
    /// Create a new vote set for the given height, round, and vote type
    pub fn new(height: u64, round: u64, vote_type: VoteType) -> Self {
        Self {
            height,
            round,
            vote_type,
            votes: HashMap::new(),
            votes_by_hash: HashMap::new(),
            stake_by_hash: HashMap::new(),
            total_voted_stake: 0,
        }
    }

    /// Get the height of this vote set
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get the round of this vote set
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Get the vote type of this set
    pub fn vote_type(&self) -> VoteType {
        self.vote_type
    }

    /// Add a vote to the set with signature verification
    ///
    /// Returns `Ok(Some(hash))` if this vote completes a quorum for that hash,
    /// `Ok(None)` if the vote was added but no quorum yet,
    /// or an error if the vote is invalid.
    pub fn add_vote(
        &mut self,
        vote: Vote,
        validator_set: &ValidatorSet,
    ) -> Result<Option<Hash>, VoteSetError> {
        // Validate vote matches this set
        if vote.height != self.height {
            return Err(VoteSetError::WrongHeight {
                vote_height: vote.height,
                expected_height: self.height,
            });
        }

        if vote.round != self.round {
            return Err(VoteSetError::WrongRound {
                vote_round: vote.round,
                expected_round: self.round,
            });
        }

        if vote.vote_type != self.vote_type {
            return Err(VoteSetError::WrongType);
        }

        // Check for duplicate vote
        if self.votes.contains_key(&vote.validator_id) {
            return Err(VoteSetError::DuplicateVote(vote.validator_id));
        }

        // Get validator
        let validator = validator_set
            .get_validator(vote.validator_id)
            .ok_or(VoteSetError::InvalidValidator(vote.validator_id))?;

        // Verify signature
        if !vote
            .signature
            .verify(&vote.signing_bytes(), &validator.pubkey)
        {
            warn!(
                validator_id = vote.validator_id,
                "Invalid vote signature"
            );
            return Err(VoteSetError::InvalidSignature(vote.validator_id));
        }

        let block_hash = vote.block_hash;
        let stake = validator.stake;

        trace!(
            height = self.height,
            round = self.round,
            vote_type = %self.vote_type,
            validator_id = vote.validator_id,
            block_hash = hex::encode(&block_hash[..8]),
            stake = stake,
            "Adding vote"
        );

        // Add vote
        self.votes.insert(vote.validator_id, vote);
        self.votes_by_hash
            .entry(block_hash)
            .or_default()
            .push(validator.id);

        // Update stake tracking
        *self.stake_by_hash.entry(block_hash).or_default() += stake;
        self.total_voted_stake += stake;

        // Check for quorum
        let hash_stake = self.stake_by_hash[&block_hash];
        let quorum_stake = validator_set.quorum_stake();

        if hash_stake >= quorum_stake {
            debug!(
                height = self.height,
                round = self.round,
                vote_type = %self.vote_type,
                block_hash = hex::encode(&block_hash[..8]),
                stake = hash_stake,
                quorum = quorum_stake,
                "Quorum reached"
            );
            Ok(Some(block_hash))
        } else {
            Ok(None)
        }
    }

    /// Check if we have quorum for any value (including nil)
    pub fn has_any_quorum(&self, validator_set: &ValidatorSet) -> Option<Hash> {
        let quorum_stake = validator_set.quorum_stake();

        for (hash, stake) in &self.stake_by_hash {
            if *stake >= quorum_stake {
                return Some(*hash);
            }
        }
        None
    }

    /// Check if we have quorum for a specific block hash
    pub fn has_quorum_for(&self, block_hash: &Hash, validator_set: &ValidatorSet) -> bool {
        let stake = self.stake_by_hash.get(block_hash).copied().unwrap_or(0);
        stake >= validator_set.quorum_stake()
    }

    /// Check if we have quorum for any non-nil value
    pub fn has_quorum_for_non_nil(&self, validator_set: &ValidatorSet) -> Option<Hash> {
        let quorum_stake = validator_set.quorum_stake();

        for (hash, stake) in &self.stake_by_hash {
            if *hash != NIL_HASH && *stake >= quorum_stake {
                return Some(*hash);
            }
        }
        None
    }

    /// Get all validators who voted for a specific hash
    pub fn get_voters_for(&self, block_hash: &Hash) -> Vec<ValidatorId> {
        self.votes_by_hash
            .get(block_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all votes for a specific hash
    pub fn get_votes_for(&self, block_hash: &Hash) -> Vec<&Vote> {
        self.votes_by_hash
            .get(block_hash)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.votes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a specific vote by validator ID
    pub fn get_vote(&self, validator_id: ValidatorId) -> Option<&Vote> {
        self.votes.get(&validator_id)
    }

    /// Get the total number of votes
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Get the stake that has voted for a specific hash
    pub fn stake_for(&self, block_hash: &Hash) -> u128 {
        self.stake_by_hash.get(block_hash).copied().unwrap_or(0)
    }

    /// Get the total stake that has voted
    pub fn total_voted_stake(&self) -> u128 {
        self.total_voted_stake
    }

    /// Check if a validator has voted
    pub fn has_voted(&self, validator_id: ValidatorId) -> bool {
        self.votes.contains_key(&validator_id)
    }

    /// Create an aggregated signature for all votes for a specific hash
    pub fn aggregate_signatures_for(&self, block_hash: &Hash) -> Option<BlsSignature> {
        let votes = self.get_votes_for(block_hash);
        if votes.is_empty() {
            return None;
        }

        let signatures: Vec<&BlsSignature> = votes.iter().map(|v| &v.signature).collect();
        BlsSignature::aggregate(&signatures).ok()
    }

    /// Create a bitmap of signers for a specific block hash
    ///
    /// The bitmap has bit i set if validator i voted for this hash
    pub fn create_signers_bitmap(&self, block_hash: &Hash, validator_set: &ValidatorSet) -> Vec<u8> {
        let voters = self.get_voters_for(block_hash);
        if voters.is_empty() {
            return Vec::new();
        }

        let max_id = validator_set.len().saturating_sub(1);
        let bitmap_len = (max_id / 8) + 1;
        let mut bitmap = vec![0u8; bitmap_len];

        for id in voters {
            let byte_idx = (id as usize) / 8;
            let bit_idx = (id as usize) % 8;
            if byte_idx < bitmap.len() {
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        bitmap
    }

    /// Get all unique block hashes that have been voted for
    pub fn voted_hashes(&self) -> Vec<Hash> {
        self.votes_by_hash.keys().copied().collect()
    }

    /// Clear all votes (used when moving to new round)
    pub fn clear(&mut self) {
        self.votes.clear();
        self.votes_by_hash.clear();
        self.stake_by_hash.clear();
        self.total_voted_stake = 0;
    }
}

/// Tracks vote sets across multiple rounds for a single height
#[derive(Debug)]
pub struct HeightVoteSet {
    /// Block height
    height: u64,
    /// Prevotes indexed by round
    prevotes: HashMap<u64, VoteSet>,
    /// Precommits indexed by round
    precommits: HashMap<u64, VoteSet>,
}

impl HeightVoteSet {
    /// Create a new height vote set
    pub fn new(height: u64) -> Self {
        Self {
            height,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
        }
    }

    /// Get or create the prevote set for a round
    pub fn prevotes(&mut self, round: u64) -> &mut VoteSet {
        self.prevotes
            .entry(round)
            .or_insert_with(|| VoteSet::new(self.height, round, VoteType::Prevote))
    }

    /// Get or create the precommit set for a round
    pub fn precommits(&mut self, round: u64) -> &mut VoteSet {
        self.precommits
            .entry(round)
            .or_insert_with(|| VoteSet::new(self.height, round, VoteType::Precommit))
    }

    /// Get the prevote set for a round (immutable)
    pub fn get_prevotes(&self, round: u64) -> Option<&VoteSet> {
        self.prevotes.get(&round)
    }

    /// Get the precommit set for a round (immutable)
    pub fn get_precommits(&self, round: u64) -> Option<&VoteSet> {
        self.precommits.get(&round)
    }

    /// Check if we have POL (Proof of Lock) for a value from any round >= min_round
    pub fn has_pol_from(
        &self,
        block_hash: &Hash,
        min_round: u64,
        validator_set: &ValidatorSet,
    ) -> Option<u64> {
        for round in min_round..=self.max_round() {
            if let Some(prevotes) = self.prevotes.get(&round) {
                if prevotes.has_quorum_for(block_hash, validator_set) {
                    return Some(round);
                }
            }
        }
        None
    }

    /// Get the maximum round we have votes for
    fn max_round(&self) -> u64 {
        let max_prevote = self.prevotes.keys().max().copied().unwrap_or(0);
        let max_precommit = self.precommits.keys().max().copied().unwrap_or(0);
        max_prevote.max(max_precommit)
    }

    /// Get the height
    pub fn height(&self) -> u64 {
        self.height
    }
}
