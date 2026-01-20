//! Consensus message deduplication for replay protection.
//!
//! This module provides caching and deduplication of consensus messages to prevent
//! replay attacks within the same chain. Messages are identified by a unique key
//! derived from their content, and the cache automatically evicts old entries
//! based on block height.
//!
//! ## Message ID Computation
//!
//! Each message type has a unique ID computed from:
//! - For Proposals: `hash(height || round || block_hash || proposer_id)`
//! - For Votes: `hash(height || round || step || validator_id || block_hash)`
//!
//! ## Eviction Policy
//!
//! The cache uses height-based eviction:
//! - Messages older than `current_height - retention_depth` are evicted
//! - This bounds memory usage while allowing for reorg handling

use std::collections::{HashMap, HashSet};

use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use tracing::{debug, trace};

use crate::types::{ConsensusMessage, Proposal, Vote, VoteType};

/// Message ID type - 32 bytes derived from message content
pub type MessageId = [u8; 32];

/// Configuration for the deduplication cache
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Number of heights to retain messages for (eviction threshold)
    /// Messages older than `current_height - retention_depth` are evicted.
    /// Recommended: 2-10 heights depending on expected reorg depth.
    pub retention_depth: u64,
    /// Maximum number of messages to cache per height
    /// Prevents memory exhaustion from spam attacks.
    pub max_messages_per_height: usize,
    /// Maximum total messages in the cache
    pub max_total_messages: usize,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            retention_depth: 5,
            max_messages_per_height: 10_000,
            max_total_messages: 100_000,
        }
    }
}

/// Result of checking a message for duplicates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeduplicationResult {
    /// Message is new (not seen before)
    New,
    /// Message is a duplicate (already seen)
    Duplicate,
    /// Message is too old (below retention threshold)
    TooOld,
    /// Cache is full for this height
    RateLimited,
}

/// Message deduplication cache with height-based eviction
///
/// Thread-safe cache for detecting and rejecting duplicate consensus messages.
/// Uses height-based eviction to bound memory usage.
pub struct MessageDeduplicationCache {
    /// Configuration
    config: DeduplicationConfig,
    /// Messages indexed by height, then by message ID
    messages_by_height: RwLock<HashMap<u64, HashSet<MessageId>>>,
    /// Current highest known height (for eviction)
    current_height: RwLock<u64>,
    /// Total message count (for global limit)
    total_count: RwLock<usize>,
}

impl MessageDeduplicationCache {
    /// Create a new deduplication cache with the given configuration
    pub fn new(config: DeduplicationConfig) -> Self {
        Self {
            config,
            messages_by_height: RwLock::new(HashMap::new()),
            current_height: RwLock::new(0),
            total_count: RwLock::new(0),
        }
    }

    /// Create a new deduplication cache with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DeduplicationConfig::default())
    }

    /// Update the current height and trigger eviction of old messages
    pub fn update_height(&self, height: u64) {
        let mut current = self.current_height.write();
        if height > *current {
            *current = height;
            drop(current); // Release lock before eviction
            self.evict_old_messages(height);
        }
    }

    /// Check if a consensus message is a duplicate and optionally record it
    ///
    /// Returns `DeduplicationResult::New` if the message is new and was recorded,
    /// `DeduplicationResult::Duplicate` if it was already seen.
    pub fn check_and_record(&self, message: &ConsensusMessage) -> DeduplicationResult {
        let (height, message_id) = match message {
            ConsensusMessage::Proposal(p) => (p.height, compute_proposal_id(p)),
            ConsensusMessage::Vote(v) => (v.height, compute_vote_id(v)),
        };

        self.check_and_record_id(height, message_id)
    }

    /// Check if a message ID is a duplicate and optionally record it
    pub fn check_and_record_id(&self, height: u64, message_id: MessageId) -> DeduplicationResult {
        let current_height = *self.current_height.read();

        // Check if message is too old
        if current_height > 0 && height + self.config.retention_depth < current_height {
            trace!(
                height = height,
                current = current_height,
                "Message too old, rejecting"
            );
            return DeduplicationResult::TooOld;
        }

        // Check global limit
        let total = *self.total_count.read();
        if total >= self.config.max_total_messages {
            debug!(
                total = total,
                max = self.config.max_total_messages,
                "Cache at global limit"
            );
            return DeduplicationResult::RateLimited;
        }

        let mut messages = self.messages_by_height.write();
        let height_set = messages.entry(height).or_insert_with(HashSet::new);

        // Check per-height limit
        if height_set.len() >= self.config.max_messages_per_height {
            debug!(
                height = height,
                count = height_set.len(),
                max = self.config.max_messages_per_height,
                "Height at message limit"
            );
            return DeduplicationResult::RateLimited;
        }

        // Check for duplicate
        if height_set.contains(&message_id) {
            trace!(
                height = height,
                message_id = hex::encode(&message_id[..8]),
                "Duplicate message detected"
            );
            return DeduplicationResult::Duplicate;
        }

        // Record new message
        height_set.insert(message_id);
        drop(messages);

        // Increment total count
        *self.total_count.write() += 1;

        trace!(
            height = height,
            message_id = hex::encode(&message_id[..8]),
            "New message recorded"
        );

        DeduplicationResult::New
    }

    /// Check if a message has been seen (without recording it)
    pub fn is_duplicate(&self, message: &ConsensusMessage) -> bool {
        let (height, message_id) = match message {
            ConsensusMessage::Proposal(p) => (p.height, compute_proposal_id(p)),
            ConsensusMessage::Vote(v) => (v.height, compute_vote_id(v)),
        };

        self.is_duplicate_id(height, &message_id)
    }

    /// Check if a message ID has been seen
    pub fn is_duplicate_id(&self, height: u64, message_id: &MessageId) -> bool {
        let messages = self.messages_by_height.read();
        messages
            .get(&height)
            .map(|set| set.contains(message_id))
            .unwrap_or(false)
    }

    /// Evict messages older than the retention threshold
    fn evict_old_messages(&self, current_height: u64) {
        if current_height <= self.config.retention_depth {
            return;
        }

        let eviction_threshold = current_height - self.config.retention_depth;
        let mut messages = self.messages_by_height.write();
        let mut total = self.total_count.write();

        // Collect heights to evict
        let heights_to_evict: Vec<u64> = messages
            .keys()
            .filter(|&&h| h < eviction_threshold)
            .copied()
            .collect();

        let mut evicted_count = 0usize;
        for height in heights_to_evict {
            if let Some(set) = messages.remove(&height) {
                evicted_count += set.len();
            }
        }

        *total = total.saturating_sub(evicted_count);

        if evicted_count > 0 {
            debug!(
                evicted = evicted_count,
                threshold = eviction_threshold,
                remaining = *total,
                "Evicted old messages"
            );
        }
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> CacheStats {
        let messages = self.messages_by_height.read();
        let total = *self.total_count.read();
        let current_height = *self.current_height.read();

        let heights_tracked = messages.len();
        let min_height = messages.keys().min().copied();
        let max_height = messages.keys().max().copied();

        CacheStats {
            total_messages: total,
            heights_tracked,
            current_height,
            min_height,
            max_height,
        }
    }

    /// Clear all cached messages
    pub fn clear(&self) {
        self.messages_by_height.write().clear();
        *self.total_count.write() = 0;
    }
}

/// Statistics about the deduplication cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of messages in the cache
    pub total_messages: usize,
    /// Number of distinct heights being tracked
    pub heights_tracked: usize,
    /// Current highest known height
    pub current_height: u64,
    /// Minimum height in the cache
    pub min_height: Option<u64>,
    /// Maximum height in the cache
    pub max_height: Option<u64>,
}

/// Compute a unique ID for a proposal
///
/// ID = keccak256(height || round || block_hash)
pub fn compute_proposal_id(proposal: &Proposal) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"PROPOSAL");
    hasher.update(proposal.height.to_le_bytes());
    hasher.update(proposal.round.to_le_bytes());
    hasher.update(proposal.block.hash().as_bytes());
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Compute a unique ID for a vote
///
/// ID = keccak256(vote_type || height || round || validator_id || block_hash)
pub fn compute_vote_id(vote: &Vote) -> MessageId {
    let mut hasher = Sha256::new();
    match vote.vote_type {
        VoteType::Prevote => hasher.update(b"PREVOTE"),
        VoteType::Precommit => hasher.update(b"PRECOMMIT"),
    }
    hasher.update(vote.height.to_le_bytes());
    hasher.update(vote.round.to_le_bytes());
    hasher.update(vote.validator_id.to_le_bytes());
    hasher.update(&vote.block_hash);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Compute a unique ID for any consensus message
pub fn compute_message_id(message: &ConsensusMessage) -> MessageId {
    match message {
        ConsensusMessage::Proposal(p) => compute_proposal_id(p),
        ConsensusMessage::Vote(v) => compute_vote_id(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ValidatorId, Vote, VoteType, NIL_HASH};
    use protocore_crypto::bls::BlsSignature;

    fn create_test_vote(height: u64, round: u64, validator_id: ValidatorId) -> Vote {
        Vote {
            vote_type: VoteType::Prevote,
            height,
            round,
            block_hash: NIL_HASH,
            validator_id,
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn test_new_message_recorded() {
        let cache = MessageDeduplicationCache::with_defaults();
        let vote = create_test_vote(1, 0, 0);
        let msg = ConsensusMessage::Vote(vote);

        let result = cache.check_and_record(&msg);
        assert_eq!(result, DeduplicationResult::New);
    }

    #[test]
    fn test_duplicate_detected() {
        let cache = MessageDeduplicationCache::with_defaults();
        let vote = create_test_vote(1, 0, 0);
        let msg = ConsensusMessage::Vote(vote);

        // First time - new
        let result = cache.check_and_record(&msg);
        assert_eq!(result, DeduplicationResult::New);

        // Second time - duplicate
        let result = cache.check_and_record(&msg);
        assert_eq!(result, DeduplicationResult::Duplicate);
    }

    #[test]
    fn test_different_validators_not_duplicates() {
        let cache = MessageDeduplicationCache::with_defaults();
        let vote1 = create_test_vote(1, 0, 0);
        let vote2 = create_test_vote(1, 0, 1);
        let msg1 = ConsensusMessage::Vote(vote1);
        let msg2 = ConsensusMessage::Vote(vote2);

        let result1 = cache.check_and_record(&msg1);
        let result2 = cache.check_and_record(&msg2);

        assert_eq!(result1, DeduplicationResult::New);
        assert_eq!(result2, DeduplicationResult::New);
    }

    #[test]
    fn test_height_eviction() {
        let config = DeduplicationConfig {
            retention_depth: 2,
            max_messages_per_height: 100,
            max_total_messages: 1000,
        };
        let cache = MessageDeduplicationCache::new(config);

        // Add messages at height 1
        let vote1 = create_test_vote(1, 0, 0);
        cache.check_and_record(&ConsensusMessage::Vote(vote1.clone()));

        // Update height to trigger eviction
        cache.update_height(5);

        // Check that old message is considered too old
        let result = cache.check_and_record(&ConsensusMessage::Vote(vote1));
        assert_eq!(result, DeduplicationResult::TooOld);
    }

    #[test]
    fn test_stats() {
        let cache = MessageDeduplicationCache::with_defaults();

        let vote1 = create_test_vote(1, 0, 0);
        let vote2 = create_test_vote(2, 0, 0);
        cache.check_and_record(&ConsensusMessage::Vote(vote1));
        cache.check_and_record(&ConsensusMessage::Vote(vote2));

        let stats = cache.stats();
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.heights_tracked, 2);
        assert_eq!(stats.min_height, Some(1));
        assert_eq!(stats.max_height, Some(2));
    }

    #[test]
    fn test_vote_id_deterministic() {
        let vote = create_test_vote(1, 0, 0);
        let id1 = compute_vote_id(&vote);
        let id2 = compute_vote_id(&vote);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_vote_types_different_ids() {
        let prevote = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            block_hash: NIL_HASH,
            validator_id: 0,
            signature: BlsSignature::default(),
        };
        let precommit = Vote {
            vote_type: VoteType::Precommit,
            height: 1,
            round: 0,
            block_hash: NIL_HASH,
            validator_id: 0,
            signature: BlsSignature::default(),
        };

        let id1 = compute_vote_id(&prevote);
        let id2 = compute_vote_id(&precommit);
        assert_ne!(id1, id2);
    }
}
