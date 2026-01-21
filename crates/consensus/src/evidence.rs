//! Equivocation Evidence Handling for MinBFT Consensus
//!
//! This module provides:
//! - [`EquivocationEvidence`] - Proof of double-signing (equivocation) by a validator
//! - Evidence validation with cryptographic signature verification
//! - Serialization for on-chain submission to slashing precompile
//!
//! ## What is Equivocation?
//!
//! Equivocation (double-signing) occurs when a validator signs two different votes
//! at the same (height, round, vote_type). This is a severe Byzantine fault that
//! undermines consensus safety and must be punished via slashing.
//!
//! ## Evidence Structure
//!
//! Evidence consists of two conflicting votes that prove equivocation:
//! - Same validator (validator_id matches)
//! - Same height
//! - Same round
//! - Same vote type (both prevotes or both precommits)
//! - Different block hashes (this is the offense)
//!
//! Both votes must have valid BLS signatures from the same validator.
//!
//! ## Evidence Lifecycle
//!
//! 1. **Detection**: Nodes detect equivocation when receiving conflicting votes
//! 2. **Validation**: Evidence is validated (signatures, matching criteria)
//! 3. **Serialization**: Evidence is ABI-encoded for on-chain submission
//! 4. **Submission**: Evidence submitted to slashing precompile
//! 5. **Slashing**: Validator is slashed and permanently jailed
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_consensus::evidence::{EquivocationEvidence, EvidenceError};
//! use protocore_consensus::types::{Vote, VoteType, ValidatorSet};
//!
//! // Detect conflicting votes
//! let vote_a = receive_vote();
//! let vote_b = receive_vote();
//!
//! // Create evidence
//! let evidence = EquivocationEvidence::new(vote_a, vote_b)?;
//!
//! // Validate signatures
//! evidence.validate(&validator_set)?;
//!
//! // Serialize for on-chain submission
//! let encoded = evidence.encode_for_submission();
//! ```

use protocore_crypto::{keccak256, Hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{ValidatorId, ValidatorSet, Vote, VoteType};

/// Maximum age of evidence in blocks (~24 hours at 2s blocks)
///
/// Evidence older than this is rejected to prevent ancient evidence attacks
/// and limit the storage/verification burden on nodes.
pub const EVIDENCE_MAX_AGE_BLOCKS: u64 = 43200;

/// Domain separator for evidence hashing
pub const EVIDENCE_DOMAIN: &[u8] = b"PROTOCORE_EVIDENCE_V1";

/// Errors that can occur during evidence handling
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// Votes are from different validators
    #[error("votes from different validators: {0} vs {1}")]
    DifferentValidators(ValidatorId, ValidatorId),

    /// Votes are at different heights
    #[error("votes at different heights: {0} vs {1}")]
    DifferentHeights(u64, u64),

    /// Votes are in different rounds
    #[error("votes in different rounds: {0} vs {1}")]
    DifferentRounds(u64, u64),

    /// Votes have different types (prevote vs precommit)
    #[error("votes have different types: {0} vs {1}")]
    DifferentVoteTypes(VoteType, VoteType),

    /// Votes have the same block hash (not equivocation)
    #[error("votes have same block hash - not equivocation")]
    SameBlockHash,

    /// Invalid signature on vote A
    #[error("invalid signature on vote A from validator {0}")]
    InvalidSignatureA(ValidatorId),

    /// Invalid signature on vote B
    #[error("invalid signature on vote B from validator {0}")]
    InvalidSignatureB(ValidatorId),

    /// Validator not found in validator set
    #[error("validator {0} not found in validator set")]
    ValidatorNotFound(ValidatorId),

    /// Evidence is too old
    #[error(
        "evidence too old: height {evidence_height}, current {current_height}, max age {max_age}"
    )]
    EvidenceTooOld {
        /// Height of the evidence
        evidence_height: u64,
        /// Current block height
        current_height: u64,
        /// Maximum allowed age in blocks
        max_age: u64,
    },

    /// Duplicate evidence (already processed)
    #[error("duplicate evidence: {0}")]
    DuplicateEvidence(String),
}

/// Equivocation evidence - proof that a validator double-signed
///
/// Contains two conflicting votes that prove a validator signed votes
/// for different blocks at the same (height, round, vote_type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// First conflicting vote
    pub vote_a: Vote,
    /// Second conflicting vote
    pub vote_b: Vote,
    /// Height at which equivocation occurred (cached for efficiency)
    pub height: u64,
    /// Validator who equivocated (cached for efficiency)
    pub validator_id: ValidatorId,
}

impl EquivocationEvidence {
    /// Create new equivocation evidence from two conflicting votes
    ///
    /// This performs basic structural validation but does NOT verify signatures.
    /// Call [`validate`] with the validator set to verify signatures.
    ///
    /// # Arguments
    ///
    /// * `vote_a` - First vote
    /// * `vote_b` - Second conflicting vote
    ///
    /// # Returns
    ///
    /// `Ok(evidence)` if the votes represent valid equivocation structure,
    /// or an error describing why the evidence is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let evidence = EquivocationEvidence::new(vote1, vote2)?;
    /// ```
    pub fn new(vote_a: Vote, vote_b: Vote) -> Result<Self, EvidenceError> {
        // Must be same validator
        if vote_a.validator_id != vote_b.validator_id {
            return Err(EvidenceError::DifferentValidators(
                vote_a.validator_id,
                vote_b.validator_id,
            ));
        }

        // Must be same height
        if vote_a.height != vote_b.height {
            return Err(EvidenceError::DifferentHeights(
                vote_a.height,
                vote_b.height,
            ));
        }

        // Must be same round
        if vote_a.round != vote_b.round {
            return Err(EvidenceError::DifferentRounds(vote_a.round, vote_b.round));
        }

        // Must be same vote type
        if vote_a.vote_type != vote_b.vote_type {
            return Err(EvidenceError::DifferentVoteTypes(
                vote_a.vote_type,
                vote_b.vote_type,
            ));
        }

        // Must have DIFFERENT block hashes (this is the offense)
        if vote_a.block_hash == vote_b.block_hash {
            return Err(EvidenceError::SameBlockHash);
        }

        Ok(Self {
            height: vote_a.height,
            validator_id: vote_a.validator_id,
            vote_a,
            vote_b,
        })
    }

    /// Validate the evidence with full cryptographic verification
    ///
    /// Verifies:
    /// 1. The validator exists in the validator set
    /// 2. Both signatures are valid BLS signatures from the validator
    ///
    /// # Arguments
    ///
    /// * `validator_set` - Current validator set for signature verification
    ///
    /// # Returns
    ///
    /// `Ok(())` if the evidence is cryptographically valid,
    /// or an error describing the validation failure.
    pub fn validate(&self, validator_set: &ValidatorSet) -> Result<(), EvidenceError> {
        // Get the validator
        let validator = validator_set
            .get_validator(self.validator_id)
            .ok_or(EvidenceError::ValidatorNotFound(self.validator_id))?;

        // Verify signature on vote A
        if !self
            .vote_a
            .signature
            .verify(&self.vote_a.signing_bytes(), &validator.pubkey)
        {
            return Err(EvidenceError::InvalidSignatureA(self.validator_id));
        }

        // Verify signature on vote B
        if !self
            .vote_b
            .signature
            .verify(&self.vote_b.signing_bytes(), &validator.pubkey)
        {
            return Err(EvidenceError::InvalidSignatureB(self.validator_id));
        }

        Ok(())
    }

    /// Check if evidence is within the acceptable age window
    ///
    /// # Arguments
    ///
    /// * `current_height` - Current block height
    ///
    /// # Returns
    ///
    /// `Ok(())` if evidence is recent enough, or an error if too old.
    pub fn check_age(&self, current_height: u64) -> Result<(), EvidenceError> {
        if current_height > self.height && current_height - self.height > EVIDENCE_MAX_AGE_BLOCKS {
            return Err(EvidenceError::EvidenceTooOld {
                evidence_height: self.height,
                current_height,
                max_age: EVIDENCE_MAX_AGE_BLOCKS,
            });
        }
        Ok(())
    }

    /// Calculate the unique hash of this evidence
    ///
    /// Used for deduplication and on-chain storage.
    pub fn hash(&self) -> Hash {
        // Build the data to hash
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(EVIDENCE_DOMAIN);
        data.extend_from_slice(&self.validator_id.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(&self.vote_a.round.to_le_bytes());
        data.push(self.vote_a.vote_type as u8);
        data.extend_from_slice(&self.vote_a.block_hash);
        data.extend_from_slice(&self.vote_b.block_hash);
        data.extend_from_slice(&self.vote_a.signature.to_bytes());
        data.extend_from_slice(&self.vote_b.signature.to_bytes());

        keccak256(&data)
    }

    /// Encode evidence for submission to the slashing precompile
    ///
    /// Returns ABI-encoded bytes that can be submitted to the
    /// `submitDoubleSignEvidence` function on the slashing precompile.
    ///
    /// # ABI Format
    ///
    /// The encoding follows Solidity ABI format:
    /// - offset to vote_a data (uint256)
    /// - offset to vote_b data (uint256)
    /// - vote_a: height (u64), round (u64), vote_type (u8), block_hash (32), validator_id (u64), signature (96)
    /// - vote_b: height (u64), round (u64), vote_type (u8), block_hash (32), validator_id (u64), signature (96)
    pub fn encode_for_submission(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(512);

        // Offsets to dynamic data
        // vote_a starts at offset 64 (after two 32-byte offset values)
        encoded.extend_from_slice(&encode_u256(64));
        // vote_b starts at offset 64 + vote_a_size (256 bytes for vote)
        encoded.extend_from_slice(&encode_u256(64 + 256));

        // Encode vote_a
        encoded.extend_from_slice(&self.encode_vote(&self.vote_a));

        // Encode vote_b
        encoded.extend_from_slice(&self.encode_vote(&self.vote_b));

        encoded
    }

    /// Encode a single vote for ABI encoding
    fn encode_vote(&self, vote: &Vote) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(256);

        // height (u64 as u256)
        encoded.extend_from_slice(&encode_u256(vote.height as u128));

        // round (u64 as u256)
        encoded.extend_from_slice(&encode_u256(vote.round as u128));

        // vote_type (u8 as u256)
        encoded.extend_from_slice(&encode_u256(vote.vote_type as u8 as u128));

        // block_hash (32 bytes, left-padded to 32)
        encoded.extend_from_slice(&vote.block_hash);

        // validator_id (u64 as u256)
        encoded.extend_from_slice(&encode_u256(vote.validator_id as u128));

        // signature (96 bytes, split into 3 words)
        let sig_bytes = vote.signature.to_bytes();
        encoded.extend_from_slice(&sig_bytes[0..32]);
        encoded.extend_from_slice(&sig_bytes[32..64]);
        encoded.extend_from_slice(&sig_bytes[64..96]);

        encoded
    }

    /// Decode evidence from ABI-encoded submission data
    ///
    /// # Arguments
    ///
    /// * `data` - ABI-encoded evidence bytes
    ///
    /// # Returns
    ///
    /// Decoded evidence or None if decoding fails.
    pub fn decode_from_submission(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }

        // Read offsets
        let vote_a_offset = decode_u256(data, 0)? as usize;
        let vote_b_offset = decode_u256(data, 32)? as usize;

        // Decode votes
        let vote_a = Self::decode_vote(data, vote_a_offset)?;
        let vote_b = Self::decode_vote(data, vote_b_offset)?;

        // Construct evidence (will validate structure)
        Self::new(vote_a, vote_b).ok()
    }

    /// Decode a single vote from ABI-encoded data
    fn decode_vote(data: &[u8], offset: usize) -> Option<Vote> {
        if data.len() < offset + 256 {
            return None;
        }

        let height = decode_u256(data, offset)? as u64;
        let round = decode_u256(data, offset + 32)? as u64;
        let vote_type_raw = decode_u256(data, offset + 64)? as u8;
        let vote_type = match vote_type_raw {
            0 => VoteType::Prevote,
            1 => VoteType::Precommit,
            _ => return None,
        };

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[offset + 96..offset + 128]);

        let validator_id = decode_u256(data, offset + 128)? as ValidatorId;

        // Read signature (96 bytes from 3 words)
        let mut sig_bytes = [0u8; 96];
        sig_bytes[0..32].copy_from_slice(&data[offset + 160..offset + 192]);
        sig_bytes[32..64].copy_from_slice(&data[offset + 192..offset + 224]);
        sig_bytes[64..96].copy_from_slice(&data[offset + 224..offset + 256]);

        let signature = protocore_crypto::bls::BlsSignature::from_bytes(&sig_bytes).ok()?;

        Some(Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator_id,
            signature,
        })
    }

    /// Get a human-readable summary of this evidence
    pub fn summary(&self) -> String {
        format!(
            "Equivocation by validator {} at height {}, round {}: voted for {} and {}",
            self.validator_id,
            self.height,
            self.vote_a.round,
            hex::encode(&self.vote_a.block_hash[..8]),
            hex::encode(&self.vote_b.block_hash[..8]),
        )
    }

    /// Check if this evidence conflicts with another
    ///
    /// Two pieces of evidence conflict if they accuse the same validator
    /// of equivocation at the same (height, round, vote_type).
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.validator_id == other.validator_id
            && self.height == other.height
            && self.vote_a.round == other.vote_a.round
            && self.vote_a.vote_type == other.vote_a.vote_type
    }

    /// Get the vote type of the equivocating votes
    pub fn vote_type(&self) -> VoteType {
        self.vote_a.vote_type
    }

    /// Get the round number
    pub fn round(&self) -> u64 {
        self.vote_a.round
    }
}

/// Evidence tracker for collecting and managing equivocation evidence
///
/// Used by consensus nodes to track detected equivocations and prepare
/// them for on-chain submission.
#[derive(Debug, Clone, Default)]
pub struct EvidencePool {
    /// Pending evidence awaiting submission
    pending: Vec<EquivocationEvidence>,
    /// Hashes of submitted evidence (to prevent re-submission)
    submitted: std::collections::HashSet<Hash>,
}

impl EvidencePool {
    /// Create a new empty evidence pool
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            submitted: std::collections::HashSet::new(),
        }
    }

    /// Add evidence to the pool
    ///
    /// Returns `Ok(true)` if evidence was added, `Ok(false)` if it was a duplicate,
    /// or `Err` if the evidence is too old.
    ///
    /// # Arguments
    /// * `evidence` - The equivocation evidence to add
    /// * `current_height` - Current blockchain height for age validation
    ///
    /// # Security
    /// This method enforces evidence age checking to prevent ancient evidence attacks.
    /// Evidence older than EVIDENCE_MAX_AGE_BLOCKS is rejected.
    pub fn add(
        &mut self,
        evidence: EquivocationEvidence,
        current_height: u64,
    ) -> Result<bool, EvidenceError> {
        // SECURITY: Check evidence age before accepting
        // This prevents ancient evidence attacks where old equivocations
        // are submitted long after validators have changed stake
        evidence.check_age(current_height)?;

        let hash = evidence.hash();

        // Check if already submitted or pending
        if self.submitted.contains(&hash) {
            return Ok(false);
        }

        if self.pending.iter().any(|e| e.hash() == hash) {
            return Ok(false);
        }

        self.pending.push(evidence);
        Ok(true)
    }

    /// Add evidence without age checking (for testing only)
    #[cfg(test)]
    pub fn add_unchecked(&mut self, evidence: EquivocationEvidence) -> bool {
        let hash = evidence.hash();
        if self.submitted.contains(&hash) || self.pending.iter().any(|e| e.hash() == hash) {
            return false;
        }
        self.pending.push(evidence);
        true
    }

    /// Get pending evidence for submission
    ///
    /// Returns up to `limit` pieces of evidence.
    pub fn get_pending(&self, limit: usize) -> Vec<&EquivocationEvidence> {
        self.pending.iter().take(limit).collect()
    }

    /// Mark evidence as submitted
    pub fn mark_submitted(&mut self, evidence_hash: &Hash) {
        self.submitted.insert(*evidence_hash);
        self.pending.retain(|e| e.hash() != *evidence_hash);
    }

    /// Remove stale evidence older than the given height
    pub fn prune(&mut self, min_height: u64) {
        self.pending.retain(|e| e.height >= min_height);
    }

    /// Get count of pending evidence
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if we have pending evidence for a specific validator
    pub fn has_evidence_for(&self, validator_id: ValidatorId) -> bool {
        self.pending.iter().any(|e| e.validator_id == validator_id)
    }
}

/// Equivocation detector that integrates with the vote collection process
///
/// Call `check_vote` for each vote received. If equivocation is detected,
/// evidence is automatically added to the pool.
#[derive(Debug, Clone)]
pub struct EquivocationDetector {
    /// Votes seen per (height, round, vote_type, validator)
    /// Key: (height, round, vote_type, validator_id)
    /// Value: (block_hash, signature_bytes)
    seen_votes: std::collections::HashMap<(u64, u64, u8, ValidatorId), Vote>,
    /// Evidence pool for detected equivocations
    evidence_pool: EvidencePool,
}

impl EquivocationDetector {
    /// Create a new equivocation detector
    pub fn new() -> Self {
        Self {
            seen_votes: std::collections::HashMap::new(),
            evidence_pool: EvidencePool::new(),
        }
    }

    /// Check a vote for equivocation
    ///
    /// If this vote conflicts with a previously seen vote from the same
    /// validator at the same (height, round, vote_type), equivocation
    /// evidence is created and added to the pool.
    ///
    /// # Arguments
    ///
    /// * `vote` - The vote to check
    /// * `current_height` - Current blockchain height for evidence age validation
    ///
    /// # Returns
    ///
    /// `Some(evidence)` if equivocation was detected, `None` otherwise.
    /// Evidence is only returned if it passes age validation.
    pub fn check_vote(&mut self, vote: Vote, current_height: u64) -> Option<EquivocationEvidence> {
        let key = (
            vote.height,
            vote.round,
            vote.vote_type as u8,
            vote.validator_id,
        );

        if let Some(existing_vote) = self.seen_votes.get(&key) {
            // Check if it's a conflicting vote (different block hash)
            if existing_vote.block_hash != vote.block_hash {
                // Equivocation detected!
                if let Ok(evidence) = EquivocationEvidence::new(existing_vote.clone(), vote.clone())
                {
                    // Add with age checking - silently ignore if too old
                    if self
                        .evidence_pool
                        .add(evidence.clone(), current_height)
                        .unwrap_or(false)
                    {
                        return Some(evidence);
                    }
                }
            }
            // Same vote seen again, ignore
            return None;
        }

        // First time seeing this vote, record it
        self.seen_votes.insert(key, vote);
        None
    }

    /// Get the evidence pool
    pub fn evidence_pool(&self) -> &EvidencePool {
        &self.evidence_pool
    }

    /// Get mutable reference to evidence pool
    pub fn evidence_pool_mut(&mut self) -> &mut EvidencePool {
        &mut self.evidence_pool
    }

    /// Clear votes for old heights to prevent memory growth
    ///
    /// # Arguments
    ///
    /// * `min_height` - Remove votes older than this height
    pub fn prune(&mut self, min_height: u64) {
        self.seen_votes
            .retain(|(height, _, _, _), _| *height >= min_height);
        self.evidence_pool.prune(min_height);
    }
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ABI encoding helpers

fn encode_u256(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn decode_u256(data: &[u8], offset: usize) -> Option<u128> {
    if data.len() < offset + 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[offset + 16..offset + 32]);
    Some(u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Validator, ValidatorSet, VoteType};
    use protocore_crypto::bls::BlsPrivateKey;

    fn create_test_validator_set() -> (ValidatorSet, BlsPrivateKey) {
        let private_key = BlsPrivateKey::random();
        let pubkey = private_key.public_key();

        let validator = Validator::new(0, pubkey, [0u8; 20], 1000, 500);
        let validator_set = ValidatorSet::new(vec![validator]);

        (validator_set, private_key)
    }

    fn create_signed_vote(
        private_key: &BlsPrivateKey,
        vote_type: VoteType,
        height: u64,
        round: u64,
        block_hash: Hash,
        validator_id: ValidatorId,
    ) -> Vote {
        let mut vote = Vote::new(vote_type, height, round, block_hash, validator_id);
        vote.signature = private_key.sign(&vote.signing_bytes());
        vote
    }

    #[test]
    fn test_equivocation_detection() {
        let (validator_set, private_key) = create_test_validator_set();

        // Create two conflicting votes
        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        let vote_b = create_signed_vote(
            &private_key,
            VoteType::Prevote,
            100,
            0,
            [2u8; 32], // Different block hash
            0,
        );

        // Create evidence
        let evidence = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        // Validate
        assert!(evidence.validate(&validator_set).is_ok());
        assert_eq!(evidence.height, 100);
        assert_eq!(evidence.validator_id, 0);
    }

    #[test]
    fn test_same_block_hash_rejected() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        let vote_b = create_signed_vote(
            &private_key,
            VoteType::Prevote,
            100,
            0,
            [1u8; 32], // Same block hash - not equivocation!
            0,
        );

        let result = EquivocationEvidence::new(vote_a, vote_b);
        assert!(matches!(result, Err(EvidenceError::SameBlockHash)));
    }

    #[test]
    fn test_different_validators_rejected() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(
            &private_key,
            VoteType::Prevote,
            100,
            0,
            [1u8; 32],
            0, // Validator 0
        );

        let vote_b = create_signed_vote(
            &private_key,
            VoteType::Prevote,
            100,
            0,
            [2u8; 32],
            1, // Validator 1 - different!
        );

        let result = EquivocationEvidence::new(vote_a, vote_b);
        assert!(matches!(
            result,
            Err(EvidenceError::DifferentValidators(0, 1))
        ));
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let (validator_set, private_key) = create_test_validator_set();
        let wrong_key = BlsPrivateKey::random();

        // Vote A signed with correct key
        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        // Vote B signed with wrong key
        let vote_b = create_signed_vote(&wrong_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);

        let evidence = EquivocationEvidence::new(vote_a, vote_b).unwrap();
        let result = evidence.validate(&validator_set);
        assert!(matches!(result, Err(EvidenceError::InvalidSignatureB(0))));
    }

    #[test]
    fn test_evidence_age_check() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);

        let evidence = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        // Recent enough
        assert!(evidence.check_age(100 + 1000).is_ok());

        // Too old
        assert!(matches!(
            evidence.check_age(100 + EVIDENCE_MAX_AGE_BLOCKS + 1),
            Err(EvidenceError::EvidenceTooOld { .. })
        ));
    }

    #[test]
    fn test_evidence_serialization_roundtrip() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 5, [1u8; 32], 0);

        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 5, [2u8; 32], 0);

        let original = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        // Encode
        let encoded = original.encode_for_submission();

        // Decode
        let decoded = EquivocationEvidence::decode_from_submission(&encoded).unwrap();

        // Verify fields match
        assert_eq!(decoded.height, original.height);
        assert_eq!(decoded.validator_id, original.validator_id);
        assert_eq!(decoded.vote_a.block_hash, original.vote_a.block_hash);
        assert_eq!(decoded.vote_b.block_hash, original.vote_b.block_hash);
    }

    #[test]
    fn test_evidence_hash_uniqueness() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);

        let evidence1 = EquivocationEvidence::new(vote_a.clone(), vote_b.clone()).unwrap();
        let evidence2 = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        // Same evidence should have same hash
        assert_eq!(evidence1.hash(), evidence2.hash());
    }

    #[test]
    fn test_equivocation_detector() {
        let private_key = BlsPrivateKey::random();

        let mut detector = EquivocationDetector::new();
        let current_height = 101; // Just past the vote height of 100

        // First vote - no equivocation
        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);
        assert!(detector.check_vote(vote_a, current_height).is_none());

        // Second vote for different block - equivocation!
        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);
        let evidence = detector.check_vote(vote_b, current_height);
        assert!(evidence.is_some());

        // Evidence should be in pool
        assert_eq!(detector.evidence_pool().pending_count(), 1);
    }

    #[test]
    fn test_evidence_pool_deduplication() {
        let private_key = BlsPrivateKey::random();

        let vote_a = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [1u8; 32], 0);

        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);

        let evidence = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        let mut pool = EvidencePool::new();

        // First add succeeds (evidence at height 100, current height 101 - well within age limit)
        assert!(pool.add(evidence.clone(), 101).unwrap());

        // Duplicate is rejected
        assert!(!pool.add(evidence, 101).unwrap());

        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn test_evidence_pool_rejects_old_evidence() {
        let private_key = BlsPrivateKey::random();
        let vote_a = create_signed_vote(
            &private_key,
            VoteType::Prevote,
            100, // evidence at height 100
            0,
            [1u8; 32],
            0,
        );

        let vote_b = create_signed_vote(&private_key, VoteType::Prevote, 100, 0, [2u8; 32], 0);

        let evidence = EquivocationEvidence::new(vote_a, vote_b).unwrap();

        let mut pool = EvidencePool::new();

        // Current height is way beyond max age - should be rejected
        let too_old_height = 100 + EVIDENCE_MAX_AGE_BLOCKS + 100;
        let result = pool.add(evidence.clone(), too_old_height);
        assert!(result.is_err());
        matches!(result.unwrap_err(), EvidenceError::EvidenceTooOld { .. });
        assert_eq!(pool.pending_count(), 0);

        // Within age limit - should succeed
        let ok_height = 100 + EVIDENCE_MAX_AGE_BLOCKS - 1;
        assert!(pool.add(evidence, ok_height).unwrap());
        assert_eq!(pool.pending_count(), 1);
    }
}
