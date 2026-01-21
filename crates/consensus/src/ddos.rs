//! DDoS protection for consensus layer.
//!
//! This module provides multi-layered protection against denial of service attacks
//! targeting the consensus mechanism:
//! - Proposer validation (reject proposals from non-proposers)
//! - Message rate limiting per validator
//! - Duplicate message detection
//! - Resource limits for consensus messages

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, warn};

use crate::types::{ValidatorId, ValidatorSet};

/// Configuration for consensus DDoS protection
#[derive(Debug, Clone)]
pub struct ConsensusDdosConfig {
    /// Maximum proposals per validator per height
    pub max_proposals_per_height: u32,
    /// Maximum votes per validator per height per round
    pub max_votes_per_height_round: u32,
    /// Maximum consensus messages per validator per second
    pub max_messages_per_validator_per_sec: u32,
    /// Maximum bytes per consensus message
    pub max_message_bytes: usize,
    /// Duration to track messages for deduplication
    pub dedup_window: Duration,
    /// Maximum proposal size (block size limit)
    pub max_proposal_size: usize,
    /// Score penalty for sending proposal when not proposer
    pub unauthorized_proposal_penalty: i64,
    /// Score penalty for duplicate messages
    pub duplicate_message_penalty: i64,
    /// Score penalty for malformed messages
    pub malformed_message_penalty: i64,
    /// Score threshold for temporary ban
    pub ban_threshold: i64,
    /// Ban duration
    pub ban_duration: Duration,
    /// Window duration for rate limiting
    pub rate_limit_window: Duration,
}

impl Default for ConsensusDdosConfig {
    fn default() -> Self {
        Self {
            max_proposals_per_height: 2,   // Allow retry after timeout
            max_votes_per_height_round: 2, // Prevote + precommit
            max_messages_per_validator_per_sec: 50,
            max_message_bytes: 2_000_000, // 2 MB max (for large blocks)
            dedup_window: Duration::from_secs(60),
            max_proposal_size: 1_500_000, // 1.5 MB max block
            unauthorized_proposal_penalty: 100,
            duplicate_message_penalty: 10,
            malformed_message_penalty: 50,
            ban_threshold: -200,
            ban_duration: Duration::from_secs(300), // 5 minutes
            rate_limit_window: Duration::from_secs(1),
        }
    }
}

/// Per-validator rate limiting state
#[derive(Debug, Clone)]
struct ValidatorRateLimitState {
    /// Messages in current window
    messages_in_window: u32,
    /// Window start time
    window_start: Instant,
    /// Proposals at current height
    proposals_at_height: u32,
    /// Current height being tracked for proposals
    current_height: u64,
    /// Votes by (height, round)
    votes_by_height_round: HashMap<(u64, u64), u32>,
    /// Behavior score (negative = bad)
    score: i64,
    /// Last score update time (for decay calculation)
    #[allow(dead_code)]
    last_score_update: Instant,
}

impl Default for ValidatorRateLimitState {
    fn default() -> Self {
        Self {
            messages_in_window: 0,
            window_start: Instant::now(),
            proposals_at_height: 0,
            current_height: 0,
            votes_by_height_round: HashMap::new(),
            score: 0,
            last_score_update: Instant::now(),
        }
    }
}

/// Type of consensus message being validated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMessageType {
    /// Block proposal
    Proposal,
    /// Prevote
    Prevote,
    /// Precommit
    Precommit,
    /// New view message
    NewView,
    /// Finality certificate
    FinalityCert,
}

impl std::fmt::Display for ConsensusMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusMessageType::Proposal => write!(f, "Proposal"),
            ConsensusMessageType::Prevote => write!(f, "Prevote"),
            ConsensusMessageType::Precommit => write!(f, "Precommit"),
            ConsensusMessageType::NewView => write!(f, "NewView"),
            ConsensusMessageType::FinalityCert => write!(f, "FinalityCert"),
        }
    }
}

/// Reason for rejecting a consensus message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusRejectReason {
    /// Not the designated proposer for this height/round
    UnauthorizedProposer,
    /// Message rate limit exceeded
    RateLimited,
    /// Too many proposals at this height
    TooManyProposals,
    /// Too many votes at this height/round
    TooManyVotes,
    /// Message is too large
    MessageTooLarge,
    /// Validator is not in the active set
    UnknownValidator,
    /// Validator is banned
    ValidatorBanned,
    /// Duplicate message
    DuplicateMessage,
}

impl std::fmt::Display for ConsensusRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusRejectReason::UnauthorizedProposer => write!(f, "not authorized proposer"),
            ConsensusRejectReason::RateLimited => write!(f, "rate limited"),
            ConsensusRejectReason::TooManyProposals => write!(f, "too many proposals"),
            ConsensusRejectReason::TooManyVotes => write!(f, "too many votes"),
            ConsensusRejectReason::MessageTooLarge => write!(f, "message too large"),
            ConsensusRejectReason::UnknownValidator => write!(f, "unknown validator"),
            ConsensusRejectReason::ValidatorBanned => write!(f, "validator banned"),
            ConsensusRejectReason::DuplicateMessage => write!(f, "duplicate message"),
        }
    }
}

/// Result of consensus message validation
#[derive(Debug, Clone)]
pub struct ConsensusValidationResult {
    /// Whether the message is allowed
    pub allowed: bool,
    /// Reason for rejection (if not allowed)
    pub reject_reason: Option<ConsensusRejectReason>,
    /// Remaining messages allowed in current window
    pub remaining_in_window: u32,
}

/// Consensus DDoS protection manager
pub struct ConsensusDdosProtection {
    config: ConsensusDdosConfig,
    /// Per-validator state
    validator_states: RwLock<HashMap<ValidatorId, ValidatorRateLimitState>>,
    /// Banned validators with expiry
    banned_validators: RwLock<HashMap<ValidatorId, Instant>>,
    /// Message hash cache for deduplication
    seen_messages: RwLock<HashMap<[u8; 32], Instant>>,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl ConsensusDdosProtection {
    /// Create a new consensus DDoS protection manager
    pub fn new(config: ConsensusDdosConfig) -> Self {
        Self {
            config,
            validator_states: RwLock::new(HashMap::new()),
            banned_validators: RwLock::new(HashMap::new()),
            seen_messages: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ConsensusDdosConfig::default())
    }

    /// Validate a proposal message
    ///
    /// Checks:
    /// 1. Validator is the designated proposer for this height/round
    /// 2. Message size is within limits
    /// 3. Rate limits are not exceeded
    /// 4. Validator is not banned
    pub fn validate_proposal(
        &self,
        validator_id: ValidatorId,
        height: u64,
        round: u64,
        message_size: usize,
        validator_set: &ValidatorSet,
    ) -> ConsensusValidationResult {
        self.maybe_cleanup();

        // Check if validator is banned
        if self.is_validator_banned(validator_id) {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::ValidatorBanned),
                remaining_in_window: 0,
            };
        }

        // Verify validator is in the active set
        if validator_set.get_validator(validator_id).is_none() {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::UnknownValidator),
                remaining_in_window: 0,
            };
        }

        // Verify this validator is the designated proposer
        let expected_proposer = validator_set.proposer_id(height, round);
        if validator_id != expected_proposer {
            self.penalize_validator(validator_id, self.config.unauthorized_proposal_penalty);
            warn!(
                validator_id,
                height, round, expected_proposer, "rejected unauthorized proposal"
            );
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::UnauthorizedProposer),
                remaining_in_window: 0,
            };
        }

        // Check message size
        if message_size > self.config.max_proposal_size {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::MessageTooLarge),
                remaining_in_window: 0,
            };
        }

        // Check rate limits
        self.check_and_update_rate_limits(
            validator_id,
            height,
            round,
            ConsensusMessageType::Proposal,
        )
    }

    /// Validate a vote message (prevote or precommit)
    pub fn validate_vote(
        &self,
        validator_id: ValidatorId,
        height: u64,
        round: u64,
        message_size: usize,
        validator_set: &ValidatorSet,
    ) -> ConsensusValidationResult {
        self.maybe_cleanup();

        // Check if validator is banned
        if self.is_validator_banned(validator_id) {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::ValidatorBanned),
                remaining_in_window: 0,
            };
        }

        // Verify validator is in the active set
        if validator_set.get_validator(validator_id).is_none() {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::UnknownValidator),
                remaining_in_window: 0,
            };
        }

        // Check message size
        if message_size > self.config.max_message_bytes {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::MessageTooLarge),
                remaining_in_window: 0,
            };
        }

        // Check rate limits
        self.check_and_update_rate_limits(
            validator_id,
            height,
            round,
            ConsensusMessageType::Prevote,
        )
    }

    /// Check and update rate limits for a validator
    fn check_and_update_rate_limits(
        &self,
        validator_id: ValidatorId,
        height: u64,
        round: u64,
        msg_type: ConsensusMessageType,
    ) -> ConsensusValidationResult {
        let mut states = self.validator_states.write();
        let state = states.entry(validator_id).or_default();
        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(state.window_start) >= self.config.rate_limit_window {
            state.messages_in_window = 0;
            state.window_start = now;
        }

        // Check overall message rate limit
        if state.messages_in_window >= self.config.max_messages_per_validator_per_sec {
            return ConsensusValidationResult {
                allowed: false,
                reject_reason: Some(ConsensusRejectReason::RateLimited),
                remaining_in_window: 0,
            };
        }

        // Check message-type specific limits
        match msg_type {
            ConsensusMessageType::Proposal => {
                // Reset proposal counter for new height
                if height != state.current_height {
                    state.current_height = height;
                    state.proposals_at_height = 0;
                }

                if state.proposals_at_height >= self.config.max_proposals_per_height {
                    return ConsensusValidationResult {
                        allowed: false,
                        reject_reason: Some(ConsensusRejectReason::TooManyProposals),
                        remaining_in_window: self
                            .config
                            .max_messages_per_validator_per_sec
                            .saturating_sub(state.messages_in_window),
                    };
                }

                state.proposals_at_height += 1;
            }
            ConsensusMessageType::Prevote | ConsensusMessageType::Precommit => {
                let key = (height, round);
                let votes = state.votes_by_height_round.entry(key).or_insert(0);

                if *votes >= self.config.max_votes_per_height_round {
                    return ConsensusValidationResult {
                        allowed: false,
                        reject_reason: Some(ConsensusRejectReason::TooManyVotes),
                        remaining_in_window: self
                            .config
                            .max_messages_per_validator_per_sec
                            .saturating_sub(state.messages_in_window),
                    };
                }

                *votes += 1;
            }
            _ => {}
        }

        // Update message counter
        state.messages_in_window += 1;

        ConsensusValidationResult {
            allowed: true,
            reject_reason: None,
            remaining_in_window: self
                .config
                .max_messages_per_validator_per_sec
                .saturating_sub(state.messages_in_window),
        }
    }

    /// Check if a message hash has been seen (deduplication)
    pub fn check_duplicate(&self, message_hash: &[u8; 32]) -> bool {
        let seen = self.seen_messages.read();
        if let Some(&time) = seen.get(message_hash) {
            Instant::now().duration_since(time) < self.config.dedup_window
        } else {
            false
        }
    }

    /// Record a message hash as seen
    pub fn record_message(&self, message_hash: [u8; 32]) {
        self.seen_messages
            .write()
            .insert(message_hash, Instant::now());
    }

    /// Penalize a validator for misbehavior
    pub fn penalize_validator(&self, validator_id: ValidatorId, penalty: i64) {
        let mut states = self.validator_states.write();
        let state = states.entry(validator_id).or_default();
        state.score -= penalty;

        debug!(
            validator_id,
            penalty,
            new_score = state.score,
            "penalized validator"
        );

        if state.score <= self.config.ban_threshold {
            drop(states);
            self.ban_validator(validator_id);
        }
    }

    /// Reward a validator for good behavior
    pub fn reward_validator(&self, validator_id: ValidatorId, reward: i64) {
        let mut states = self.validator_states.write();
        let state = states.entry(validator_id).or_default();
        // Cap at 0 (neutral)
        state.score = (state.score + reward).min(0);
    }

    /// Ban a validator
    pub fn ban_validator(&self, validator_id: ValidatorId) {
        let expiry = Instant::now() + self.config.ban_duration;
        self.banned_validators.write().insert(validator_id, expiry);
        warn!(validator_id, "validator banned for consensus misbehavior");
    }

    /// Unban a validator
    pub fn unban_validator(&self, validator_id: ValidatorId) {
        self.banned_validators.write().remove(&validator_id);
        self.validator_states.write().remove(&validator_id);
    }

    /// Check if a validator is banned
    pub fn is_validator_banned(&self, validator_id: ValidatorId) -> bool {
        let banned = self.banned_validators.read();
        if let Some(&expiry) = banned.get(&validator_id) {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Get validator score
    pub fn get_validator_score(&self, validator_id: ValidatorId) -> i64 {
        self.validator_states
            .read()
            .get(&validator_id)
            .map(|s| s.score)
            .unwrap_or(0)
    }

    /// Periodic cleanup
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let cleanup_interval = Duration::from_secs(60);

        let should_cleanup = {
            let last = self.last_cleanup.read();
            now.duration_since(*last) >= cleanup_interval
        };

        if !should_cleanup {
            return;
        }

        *self.last_cleanup.write() = now;

        // Clean up expired bans
        {
            let mut banned = self.banned_validators.write();
            banned.retain(|_, expiry| now < *expiry);
        }

        // Clean up old seen messages
        {
            let mut seen = self.seen_messages.write();
            seen.retain(|_, time| now.duration_since(*time) < self.config.dedup_window);
        }

        // Clean up stale validator state
        {
            let mut states = self.validator_states.write();
            states.retain(|_, state| {
                // Keep if recently active or has negative score
                state.score < 0 || now.duration_since(state.window_start) < Duration::from_secs(300)
            });

            // Clean up old vote tracking entries
            for state in states.values_mut() {
                state.votes_by_height_round.retain(|(h, _), _| {
                    // Keep votes for recent heights (within 100 blocks)
                    *h + 100 >= state.current_height
                });
            }
        }

        debug!("consensus DDoS protection cleanup completed");
    }

    /// Get statistics
    pub fn stats(&self) -> ConsensusDdosStats {
        ConsensusDdosStats {
            tracked_validators: self.validator_states.read().len(),
            banned_validators: self.banned_validators.read().len(),
            cached_message_hashes: self.seen_messages.read().len(),
        }
    }
}

/// Statistics for consensus DDoS protection
#[derive(Debug, Clone)]
pub struct ConsensusDdosStats {
    /// Number of tracked validators
    pub tracked_validators: usize,
    /// Number of banned validators
    pub banned_validators: usize,
    /// Number of cached message hashes
    pub cached_message_hashes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Validator;
    use protocore_crypto::bls::BlsPrivateKey;

    fn create_test_validator_set() -> ValidatorSet {
        let validators: Vec<Validator> = (0..4)
            .map(|i| {
                let private_key = BlsPrivateKey::random();
                Validator::new(i, private_key.public_key(), [i as u8; 20], 1000, 100)
            })
            .collect();
        ValidatorSet::new(validators)
    }

    #[test]
    fn test_unauthorized_proposer_rejected() {
        let protection = ConsensusDdosProtection::with_defaults();
        let validator_set = create_test_validator_set();

        // Height 0, round 0: proposer should be validator 0
        let result = protection.validate_proposal(1, 0, 0, 1000, &validator_set);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(ConsensusRejectReason::UnauthorizedProposer)
        );

        // Correct proposer should be allowed
        let result = protection.validate_proposal(0, 0, 0, 1000, &validator_set);
        assert!(result.allowed);
    }

    #[test]
    fn test_proposal_rate_limiting() {
        let config = ConsensusDdosConfig {
            max_proposals_per_height: 2,
            ..Default::default()
        };
        let protection = ConsensusDdosProtection::new(config);
        let validator_set = create_test_validator_set();

        // First two proposals should succeed
        assert!(
            protection
                .validate_proposal(0, 0, 0, 1000, &validator_set)
                .allowed
        );
        assert!(
            protection
                .validate_proposal(0, 0, 0, 1000, &validator_set)
                .allowed
        );

        // Third should fail
        let result = protection.validate_proposal(0, 0, 0, 1000, &validator_set);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(ConsensusRejectReason::TooManyProposals)
        );

        // New height should reset counter
        assert!(
            protection
                .validate_proposal(1, 1, 0, 1000, &validator_set)
                .allowed
        );
    }

    #[test]
    fn test_vote_rate_limiting() {
        let config = ConsensusDdosConfig {
            max_votes_per_height_round: 2,
            ..Default::default()
        };
        let protection = ConsensusDdosProtection::new(config);
        let validator_set = create_test_validator_set();

        // First two votes should succeed
        assert!(
            protection
                .validate_vote(0, 0, 0, 100, &validator_set)
                .allowed
        );
        assert!(
            protection
                .validate_vote(0, 0, 0, 100, &validator_set)
                .allowed
        );

        // Third should fail
        let result = protection.validate_vote(0, 0, 0, 100, &validator_set);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(ConsensusRejectReason::TooManyVotes)
        );

        // Different round should allow votes
        assert!(
            protection
                .validate_vote(0, 0, 1, 100, &validator_set)
                .allowed
        );
    }

    #[test]
    fn test_validator_banning() {
        let config = ConsensusDdosConfig {
            ban_threshold: -100,
            unauthorized_proposal_penalty: 110,
            ban_duration: Duration::from_secs(3600),
            ..Default::default()
        };
        let protection = ConsensusDdosProtection::new(config);
        let validator_set = create_test_validator_set();

        // Unauthorized proposal should trigger ban
        let _ = protection.validate_proposal(1, 0, 0, 1000, &validator_set);

        // Validator should now be banned
        assert!(protection.is_validator_banned(1));

        // Further messages should be rejected
        let result = protection.validate_vote(1, 0, 0, 100, &validator_set);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(ConsensusRejectReason::ValidatorBanned)
        );
    }
}
