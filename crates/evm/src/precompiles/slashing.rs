//! Slashing Precompile
//!
//! Precompiled contract at address 0x0000...1001 for slashing operations.
//!
//! ## Slashable Offenses
//!
//! | Offense | Severity | Slash Amount | Jail Duration |
//! |---------|----------|--------------|---------------|
//! | Double Signing | Critical | 5% of stake | Permanent |
//! | Downtime (>24h) | Medium | 0.1% of stake | 24 hours |
//! | Invalid Block | Critical | 5% of stake | Permanent |
//! | Censorship (proven) | High | 2% of stake | 7 days |
//!
//! ## Functions
//!
//! ### Write Operations
//! - `submitDoubleSignEvidence(bytes,bytes)` - Submit equivocation evidence
//! - `unjail()` - Request unjailing after jail period
//!
//! ### View Functions
//! - `getSlashingInfo(validator)` - Get slashing history and status
//! - `isJailed(validator)` - Check if validator is jailed
//!
//! ## Evidence Verification
//!
//! Evidence is verified using BLS signatures from the consensus layer:
//! 1. Decode the two conflicting votes from ABI-encoded input
//! 2. Verify structural requirements (same validator, height, round, different blocks)
//! 3. Verify BLS signatures on both votes
//! 4. Check evidence age (must be within EVIDENCE_MAX_AGE_BLOCKS)
//! 5. Apply slashing and jail the validator

use alloy_primitives::{Address, Bytes, B256, U256};
use protocore_consensus::evidence::{EquivocationEvidence, EVIDENCE_MAX_AGE_BLOCKS};
use protocore_consensus::types::{ValidatorId, ValidatorSet, Vote, VoteType};
use protocore_crypto::bls::{BlsPublicKey, BlsSignature};
use revm::Database;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use super::{abi, slashing_selectors, PrecompileError, PrecompileOutput, SLASHING_ADDRESS};
use crate::state_adapter::StateAdapter;

/// Slash percentage for double signing (5%)
pub const DOUBLE_SIGN_SLASH_PERCENT: u8 = 5;

/// Slash percentage for downtime (0.1%)
pub const DOWNTIME_SLASH_PERCENT_BPS: u16 = 10; // 10 basis points = 0.1%

/// Slash percentage for invalid block (5%)
pub const INVALID_BLOCK_SLASH_PERCENT: u8 = 5;

/// Slash percentage for censorship (2%)
pub const CENSORSHIP_SLASH_PERCENT: u8 = 2;

/// Jail duration for downtime (~24 hours at 2s blocks)
pub const DOWNTIME_JAIL_DURATION: u64 = 43200;

/// Jail duration for censorship (~7 days at 2s blocks)
pub const CENSORSHIP_JAIL_DURATION: u64 = 302400;

/// Permanent jail value
pub const PERMANENT_JAIL: u64 = u64::MAX;

/// Percentage of slashed amount given to evidence reporter (10%)
pub const REPORTER_REWARD_PERCENT: u8 = 10;

/// Percentage of slashed amount that is burned (90%)
pub const BURN_PERCENT: u8 = 90;

/// Minimum stake required to submit evidence (spam prevention)
pub const MIN_EVIDENCE_SUBMITTER_STAKE: u128 = 1_000 * 10u128.pow(18); // 1,000 MCN

/// Rate limit: max evidence submissions per block per submitter
pub const MAX_EVIDENCE_PER_BLOCK_PER_SUBMITTER: u8 = 3;

/// Gas costs for slashing operations
pub const GAS_SUBMIT_EVIDENCE: u64 = 200_000;
pub const GAS_UNJAIL: u64 = 50_000;
pub const GAS_GET_SLASHING_INFO: u64 = 10_000;
pub const GAS_IS_JAILED: u64 = 5_000;

/// Evidence type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EvidenceType {
    /// Double signing - signed two different blocks at same height
    DoubleSigning = 0,
    /// Downtime - missed too many blocks
    Downtime = 1,
    /// Invalid block - proposed an invalid block
    InvalidBlock = 2,
    /// Censorship - proven transaction censorship
    Censorship = 3,
}

impl TryFrom<u8> for EvidenceType {
    type Error = PrecompileError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EvidenceType::DoubleSigning),
            1 => Ok(EvidenceType::Downtime),
            2 => Ok(EvidenceType::InvalidBlock),
            3 => Ok(EvidenceType::Censorship),
            _ => Err(PrecompileError::InvalidInput(format!(
                "unknown evidence type: {}",
                value
            ))),
        }
    }
}

/// Slashing record for tracking slashing history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Block height when slashing occurred
    pub height: u64,
    /// Amount slashed
    pub amount: u128,
    /// Type of offense
    pub offense_type: EvidenceType,
    /// Evidence hash
    pub evidence_hash: B256,
    /// Reporter who submitted the evidence
    pub reporter: Address,
    /// Reporter reward paid
    pub reporter_reward: u128,
}

/// Validator slashing info
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorSlashingInfo {
    /// Whether currently jailed
    pub jailed: bool,
    /// Block height until which validator is jailed
    pub jailed_until: u64,
    /// Total amount slashed
    pub total_slashed: u128,
    /// Slashing history
    pub slashing_history: Vec<SlashingRecord>,
    /// Number of missed blocks in current window
    pub missed_blocks: u64,
    /// Start of current missed blocks window
    pub missed_blocks_window_start: u64,
}

/// Rate limit tracker for evidence submission
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceRateLimiter {
    /// Submissions per address per block: (block_number, address) -> count
    pub submissions: HashMap<(u64, Address), u8>,
}

impl EvidenceRateLimiter {
    /// Check if submission is allowed and increment counter
    pub fn check_and_increment(
        &mut self,
        block_number: u64,
        submitter: Address,
    ) -> Result<(), PrecompileError> {
        let key = (block_number, submitter);
        let count = self.submissions.entry(key).or_insert(0);

        if *count >= MAX_EVIDENCE_PER_BLOCK_PER_SUBMITTER {
            return Err(PrecompileError::InvalidInput(
                "rate limit exceeded: too many evidence submissions this block".into(),
            ));
        }

        *count += 1;
        Ok(())
    }

    /// Clean up old entries (call periodically)
    pub fn prune(&mut self, min_block: u64) {
        self.submissions.retain(|(block, _), _| *block >= min_block);
    }
}

/// Slashing state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlashingState {
    /// Validator slashing info by validator address
    pub validators: HashMap<Address, ValidatorSlashingInfo>,
    /// Processed evidence hashes to prevent duplicates
    pub processed_evidence: HashSet<B256>,
    /// Rate limiter for evidence submission
    pub rate_limiter: EvidenceRateLimiter,
    /// Validator set for signature verification (updated each epoch)
    #[serde(skip)]
    pub validator_set: Option<ValidatorSet>,
}

/// Slashing precompile implementation
pub struct SlashingPrecompile;

impl SlashingPrecompile {
    /// Execute a slashing precompile call
    pub fn execute_static<DB: Database>(
        caller: Address,
        input: &[u8],
        _value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Decode function selector
        let selector = abi::decode_selector(input)
            .ok_or_else(|| PrecompileError::InvalidInput("input too short".into()))?;

        let data = if input.len() > 4 { &input[4..] } else { &[] };

        match selector {
            slashing_selectors::SUBMIT_DOUBLE_SIGN_EVIDENCE => {
                Self::submit_double_sign_evidence(caller, data, block_number, db)
            }
            slashing_selectors::UNJAIL => Self::unjail(caller, block_number, db),
            slashing_selectors::GET_SLASHING_INFO => Self::get_slashing_info(data, db),
            _ => Err(PrecompileError::UnknownSelector { selector }),
        }
    }

    /// Submit double-signing evidence
    ///
    /// Evidence format (ABI-encoded):
    /// - vote_a: encoded Vote struct
    /// - vote_b: encoded Vote struct
    ///
    /// The votes must:
    /// 1. Be from the same validator
    /// 2. Be at the same height and round
    /// 3. Be the same vote type (prevote or precommit)
    /// 4. Have different block hashes
    /// 5. Have valid BLS signatures
    fn submit_double_sign_evidence<DB: Database>(
        reporter: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(reporter = %reporter, block = block_number, "Processing double-sign evidence");

        // Load slashing state
        let mut state = Self::load_state(db)?;

        // Check rate limit (DoS protection)
        state.rate_limiter.check_and_increment(block_number, reporter)?;

        // Decode the evidence from ABI-encoded data
        let evidence = Self::decode_evidence(data)?;

        // Calculate evidence hash for deduplication
        let evidence_hash = B256::from(evidence.hash());

        // Check for duplicate evidence
        if state.processed_evidence.contains(&evidence_hash) {
            return Err(PrecompileError::DuplicateEvidence);
        }

        // Check evidence age
        Self::check_evidence_age(&evidence, block_number)?;

        // Get validator set for signature verification
        let validator_set = state.validator_set.clone().ok_or_else(|| {
            PrecompileError::InvalidInput("validator set not available".into())
        })?;

        // Validate the evidence (verifies signatures)
        evidence.validate(&validator_set).map_err(|e| {
            PrecompileError::InvalidEvidence(format!("evidence validation failed: {}", e))
        })?;

        // Get the validator's address from their ID
        let validator = validator_set
            .get_validator(evidence.validator_id)
            .ok_or_else(|| {
                PrecompileError::InvalidEvidence(format!(
                    "validator {} not found",
                    evidence.validator_id
                ))
            })?;

        let validator_addr = Address::from(validator.address);

        // Get validator slashing info
        let validator_info = state.validators.entry(validator_addr).or_default();

        // Check if already permanently jailed for this offense type
        if validator_info.jailed && validator_info.jailed_until == PERMANENT_JAIL {
            return Err(PrecompileError::PermanentlyJailed);
        }

        // Get validator's stake for slashing calculation
        let validator_stake = Self::get_validator_stake(db, validator_addr)?;

        // Calculate slash amount (5% for double signing)
        let slash_amount = validator_stake * DOUBLE_SIGN_SLASH_PERCENT as u128 / 100;

        // Calculate reporter reward (10% of slashed amount)
        let reporter_reward = slash_amount * REPORTER_REWARD_PERCENT as u128 / 100;
        let burn_amount = slash_amount - reporter_reward;

        // Apply slashing
        validator_info.jailed = true;
        validator_info.jailed_until = PERMANENT_JAIL;
        validator_info.total_slashed += slash_amount;
        validator_info.slashing_history.push(SlashingRecord {
            height: block_number,
            amount: slash_amount,
            offense_type: EvidenceType::DoubleSigning,
            evidence_hash,
            reporter,
            reporter_reward,
        });

        // Record evidence as processed
        state.processed_evidence.insert(evidence_hash);

        // Clean up rate limiter (keep last 100 blocks)
        if block_number > 100 {
            state.rate_limiter.prune(block_number - 100);
        }

        // Save state
        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_validator_slashed_event(
            validator_addr,
            slash_amount,
            EvidenceType::DoubleSigning,
            PERMANENT_JAIL,
            reporter,
            reporter_reward,
        );

        warn!(
            validator = %validator_addr,
            slash_amount = slash_amount,
            reporter = %reporter,
            reporter_reward = reporter_reward,
            burn_amount = burn_amount,
            evidence_hash = %evidence_hash,
            evidence_height = evidence.height,
            "Validator slashed for double signing"
        );

        // Return slashing result
        let mut output = Vec::new();
        output.extend_from_slice(&evidence_hash.0);
        output.extend_from_slice(&abi::encode_u256(U256::from(slash_amount)));
        output.extend_from_slice(&abi::encode_u256(U256::from(reporter_reward)));

        Ok(PrecompileOutput::with_logs(
            Bytes::from(output),
            GAS_SUBMIT_EVIDENCE,
            vec![log],
        ))
    }

    /// Decode equivocation evidence from ABI-encoded data
    fn decode_evidence(data: &[u8]) -> Result<EquivocationEvidence, PrecompileError> {
        // Try to decode using the consensus layer's decoder first
        if let Some(evidence) = EquivocationEvidence::decode_from_submission(data) {
            return Ok(evidence);
        }

        // Fallback: decode manually for backward compatibility
        if data.len() < 64 {
            return Err(PrecompileError::InvalidInput("evidence data too short".into()));
        }

        // Decode vote offsets
        let vote1_offset = abi::decode_u256(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote1 offset".into()))?
            .as_limbs()[0] as usize;

        let vote2_offset = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote2 offset".into()))?
            .as_limbs()[0] as usize;

        let vote_a = Self::decode_vote(data, vote1_offset)?;
        let vote_b = Self::decode_vote(data, vote2_offset)?;

        EquivocationEvidence::new(vote_a, vote_b).map_err(|e| {
            PrecompileError::InvalidEvidence(format!("invalid evidence structure: {}", e))
        })
    }

    /// Decode a consensus Vote from ABI-encoded data
    fn decode_vote(data: &[u8], offset: usize) -> Result<Vote, PrecompileError> {
        if data.len() < offset + 256 {
            return Err(PrecompileError::InvalidInput("vote data too short".into()));
        }

        let height = abi::decode_u64(data, offset)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote height".into()))?;

        let round = abi::decode_u64(data, offset + 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote round".into()))?;

        let vote_type_raw = abi::decode_u8(data, offset + 64)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote type".into()))?;

        let vote_type = match vote_type_raw {
            0 => VoteType::Prevote,
            1 => VoteType::Precommit,
            _ => {
                return Err(PrecompileError::InvalidInput(format!(
                    "invalid vote type: {}",
                    vote_type_raw
                )))
            }
        };

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[offset + 96..offset + 128]);

        let validator_id = abi::decode_u64(data, offset + 128)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid validator index".into()))?
            as ValidatorId;

        // Read signature (96 bytes from 3 words starting at offset + 160)
        let mut sig_bytes = [0u8; 96];
        if data.len() >= offset + 256 {
            sig_bytes[0..32].copy_from_slice(&data[offset + 160..offset + 192]);
            sig_bytes[32..64].copy_from_slice(&data[offset + 192..offset + 224]);
            sig_bytes[64..96].copy_from_slice(&data[offset + 224..offset + 256]);
        }

        let signature = BlsSignature::from_bytes(&sig_bytes)
            .map_err(|e| PrecompileError::InvalidInput(format!("invalid BLS signature: {}", e)))?;

        Ok(Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator_id,
            signature,
        })
    }

    /// Check if evidence is within the acceptable age window
    fn check_evidence_age(
        evidence: &EquivocationEvidence,
        current_height: u64,
    ) -> Result<(), PrecompileError> {
        if current_height > evidence.height
            && current_height - evidence.height > EVIDENCE_MAX_AGE_BLOCKS
        {
            return Err(PrecompileError::InvalidEvidence(format!(
                "evidence too old: height {}, current {}, max age {}",
                evidence.height, current_height, EVIDENCE_MAX_AGE_BLOCKS
            )));
        }
        Ok(())
    }

    /// Request unjailing after jail period expires
    fn unjail<DB: Database>(
        caller: Address,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        debug!(validator = %caller, "Processing unjail request");

        let mut state = Self::load_state(db)?;

        let validator_info = state
            .validators
            .get_mut(&caller)
            .ok_or(PrecompileError::NotJailed)?;

        if !validator_info.jailed {
            return Err(PrecompileError::NotJailed);
        }

        if validator_info.jailed_until == PERMANENT_JAIL {
            return Err(PrecompileError::PermanentlyJailed);
        }

        if block_number < validator_info.jailed_until {
            return Err(PrecompileError::JailNotExpired(validator_info.jailed_until));
        }

        // Unjail the validator
        validator_info.jailed = false;
        validator_info.jailed_until = 0;

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_validator_unjailed_event(caller);

        info!(validator = %caller, "Validator unjailed");

        Ok(PrecompileOutput::with_logs(
            Bytes::new(),
            GAS_UNJAIL,
            vec![log],
        ))
    }

    /// Get slashing information for a validator (view function)
    fn get_slashing_info<DB: Database>(
        data: &[u8],
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let validator_addr = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected validator address".into()))?;

        let state = Self::load_state(db)?;

        let info = state.validators.get(&validator_addr);

        // ABI encode response
        let mut output = Vec::new();

        if let Some(info) = info {
            output.extend_from_slice(&abi::encode_bool(info.jailed));
            output.extend_from_slice(&abi::encode_u256(U256::from(info.jailed_until)));
            output.extend_from_slice(&abi::encode_u256(U256::from(info.total_slashed)));
            output.extend_from_slice(&abi::encode_u256(U256::from(info.slashing_history.len())));

            // Encode slashing history (simplified - just heights, amounts, and reporters)
            // Offset to dynamic array
            output.extend_from_slice(&abi::encode_u256(U256::from(5 * 32)));

            for record in &info.slashing_history {
                output.extend_from_slice(&abi::encode_u256(U256::from(record.height)));
                output.extend_from_slice(&abi::encode_u256(U256::from(record.amount)));
                output.extend_from_slice(&abi::encode_u8(record.offense_type as u8));
                output.extend_from_slice(&abi::encode_address(record.reporter));
                output.extend_from_slice(&abi::encode_u256(U256::from(record.reporter_reward)));
            }
        } else {
            // Default values for non-existent validator
            output.extend_from_slice(&abi::encode_bool(false));
            output.extend_from_slice(&abi::encode_u256(U256::ZERO));
            output.extend_from_slice(&abi::encode_u256(U256::ZERO));
            output.extend_from_slice(&abi::encode_u256(U256::ZERO));
        }

        Ok(PrecompileOutput::new(
            Bytes::from(output),
            GAS_GET_SLASHING_INFO,
        ))
    }

    /// Get validator's total stake from staking state
    fn get_validator_stake<DB: Database>(
        _db: &StateAdapter<DB>,
        _validator: Address,
    ) -> Result<u128, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would read from the staking state
        // For now, return a placeholder value
        Ok(100_000 * 10u128.pow(18)) // 100,000 MCN
    }

    /// Load slashing state from storage
    fn load_state<DB: Database>(
        _db: &StateAdapter<DB>,
    ) -> Result<SlashingState, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would read from the state trie
        Ok(SlashingState::default())
    }

    /// Save slashing state to storage
    fn save_state<DB: Database>(
        _db: &mut StateAdapter<DB>,
        _state: &SlashingState,
    ) -> Result<(), PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would write to the state trie
        Ok(())
    }

    /// Set the validator set for signature verification
    ///
    /// This should be called at the beginning of each epoch to update
    /// the validator set used for evidence verification.
    pub fn set_validator_set(state: &mut SlashingState, validator_set: ValidatorSet) {
        state.validator_set = Some(validator_set);
    }

    /// Create ValidatorSlashed event log
    fn create_validator_slashed_event(
        validator: Address,
        amount: u128,
        offense_type: EvidenceType,
        jailed_until: u64,
        reporter: Address,
        reporter_reward: u128,
    ) -> revm::primitives::Log {
        let event_sig =
            keccak256(b"ValidatorSlashed(address,uint256,uint8,uint256,address,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(validator.as_slice());

        let mut topic2 = [0u8; 32];
        topic2[12..32].copy_from_slice(reporter.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
            B256::from(topic2),
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u256(U256::from(amount)));
        data.extend_from_slice(&abi::encode_u8(offense_type as u8));
        data.extend_from_slice(&abi::encode_u256(U256::from(jailed_until)));
        data.extend_from_slice(&abi::encode_u256(U256::from(reporter_reward)));

        revm::primitives::Log::new_unchecked(SLASHING_ADDRESS, topics, Bytes::from(data))
    }

    /// Create ValidatorUnjailed event log
    fn create_validator_unjailed_event(validator: Address) -> revm::primitives::Log {
        let event_sig = keccak256(b"ValidatorUnjailed(address)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![B256::from(event_sig), B256::from(topic1)];

        revm::primitives::Log::new_unchecked(SLASHING_ADDRESS, topics, Bytes::new())
    }
}

/// Compute Keccak256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_type_conversion() {
        assert_eq!(EvidenceType::try_from(0).unwrap(), EvidenceType::DoubleSigning);
        assert_eq!(EvidenceType::try_from(1).unwrap(), EvidenceType::Downtime);
        assert_eq!(EvidenceType::try_from(2).unwrap(), EvidenceType::InvalidBlock);
        assert_eq!(EvidenceType::try_from(3).unwrap(), EvidenceType::Censorship);
        assert!(EvidenceType::try_from(4).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = EvidenceRateLimiter::default();
        let addr = Address::ZERO;

        // First 3 submissions should succeed
        for _ in 0..MAX_EVIDENCE_PER_BLOCK_PER_SUBMITTER {
            assert!(limiter.check_and_increment(100, addr).is_ok());
        }

        // 4th submission should fail
        assert!(limiter.check_and_increment(100, addr).is_err());

        // Different block should succeed
        assert!(limiter.check_and_increment(101, addr).is_ok());
    }

    #[test]
    fn test_slash_calculation() {
        let stake = 100_000 * 10u128.pow(18); // 100,000 tokens

        // Double signing: 5%
        let slash = stake * DOUBLE_SIGN_SLASH_PERCENT as u128 / 100;
        assert_eq!(slash, 5_000 * 10u128.pow(18));

        // Reporter reward: 10% of slashed
        let reward = slash * REPORTER_REWARD_PERCENT as u128 / 100;
        assert_eq!(reward, 500 * 10u128.pow(18));
    }

    #[test]
    fn test_validator_slashing_info_default() {
        let info = ValidatorSlashingInfo::default();
        assert!(!info.jailed);
        assert_eq!(info.jailed_until, 0);
        assert_eq!(info.total_slashed, 0);
        assert!(info.slashing_history.is_empty());
    }
}
