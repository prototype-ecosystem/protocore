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
//! - `submitEvidence(evidence)` - Submit evidence of misbehavior
//! - `unjail()` - Request unjailing after jail period
//!
//! ### View Functions
//! - `getSlashingInfo(validator)` - Get slashing history and status

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::Database;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

use super::{
    abi, slashing_selectors, PrecompileError, PrecompileOutput, SLASHING_ADDRESS,
};
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

/// Gas costs for slashing operations
pub const GAS_SUBMIT_EVIDENCE: u64 = 150_000;
pub const GAS_UNJAIL: u64 = 50_000;
pub const GAS_GET_SLASHING_INFO: u64 = 10_000;

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

/// Vote structure for double-sign evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Block height
    pub height: u64,
    /// Voting round
    pub round: u32,
    /// Vote type (0 = prevote, 1 = precommit)
    pub vote_type: u8,
    /// Block hash being voted for
    pub block_hash: B256,
    /// Validator index
    pub validator_index: u32,
    /// Signature over the vote (BLS signature, 96 bytes)
    pub signature: Vec<u8>,
}

/// Double-sign evidence containing two conflicting votes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    /// First vote
    pub vote_a: Vote,
    /// Second conflicting vote
    pub vote_b: Vote,
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

/// Slashing state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlashingState {
    /// Validator slashing info by address
    pub validators: HashMap<Address, ValidatorSlashingInfo>,
    /// Processed evidence hashes to prevent duplicates
    pub processed_evidence: HashSet<B256>,
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
            slashing_selectors::UNJAIL => {
                Self::unjail(caller, block_number, db)
            }
            slashing_selectors::GET_SLASHING_INFO => {
                Self::get_slashing_info(data, db)
            }
            _ => Err(PrecompileError::UnknownSelector { selector }),
        }
    }

    /// Submit double-signing evidence
    fn submit_double_sign_evidence<DB: Database>(
        reporter: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(reporter = %reporter, "Processing double-sign evidence");

        // Decode the two votes from ABI-encoded data
        // Format: vote1_offset, vote2_offset, vote1_data, vote2_data
        let vote1_offset = abi::decode_u256(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote1 offset".into()))?
            .as_limbs()[0] as usize;

        let vote2_offset = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote2 offset".into()))?
            .as_limbs()[0] as usize;

        let vote_a = Self::decode_vote(data, vote1_offset)?;
        let vote_b = Self::decode_vote(data, vote2_offset)?;

        let evidence = DoubleSignEvidence { vote_a, vote_b };

        // Verify evidence validity
        let validator_addr = Self::verify_double_sign_evidence(&evidence)?;

        // Calculate evidence hash
        let evidence_hash = Self::hash_evidence(&evidence);

        // Load slashing state
        let mut state = Self::load_state(db)?;

        // Check for duplicate evidence
        if state.processed_evidence.contains(&evidence_hash) {
            return Err(PrecompileError::DuplicateEvidence);
        }

        // Get validator slashing info
        let validator_info = state.validators.entry(validator_addr).or_default();

        // Check if already jailed for this offense type
        if validator_info.jailed && validator_info.jailed_until == PERMANENT_JAIL {
            return Err(PrecompileError::PermanentlyJailed);
        }

        // Load staking state to get validator's stake
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
        });

        // Record evidence as processed
        state.processed_evidence.insert(evidence_hash);

        // Save state
        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_validator_slashed_event(
            validator_addr,
            slash_amount,
            EvidenceType::DoubleSigning,
            PERMANENT_JAIL,
        );

        warn!(
            validator = %validator_addr,
            slash_amount = slash_amount,
            reporter = %reporter,
            reporter_reward = reporter_reward,
            burn_amount = burn_amount,
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

            // Encode slashing history (simplified - just heights and amounts)
            // Offset to dynamic array
            output.extend_from_slice(&abi::encode_u256(U256::from(5 * 32)));

            for record in &info.slashing_history {
                output.extend_from_slice(&abi::encode_u256(U256::from(record.height)));
                output.extend_from_slice(&abi::encode_u256(U256::from(record.amount)));
                output.extend_from_slice(&abi::encode_u8(record.offense_type as u8));
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

    /// Decode a vote from ABI-encoded data
    fn decode_vote(data: &[u8], offset: usize) -> Result<Vote, PrecompileError> {
        if data.len() < offset + 192 {
            // 6 fields * 32 bytes each
            return Err(PrecompileError::InvalidInput("vote data too short".into()));
        }

        let height = abi::decode_u64(data, offset)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote height".into()))?;

        let round = abi::decode_u256(data, offset + 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote round".into()))?
            .as_limbs()[0] as u32;

        let vote_type = abi::decode_u8(data, offset + 64)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid vote type".into()))?;

        let block_hash_bytes: [u8; 32] = data[offset + 96..offset + 128]
            .try_into()
            .map_err(|_| PrecompileError::InvalidInput("invalid block hash".into()))?;
        let block_hash = B256::from(block_hash_bytes);

        let validator_index = abi::decode_u256(data, offset + 128)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid validator index".into()))?
            .as_limbs()[0] as u32;

        // Signature is in the next 96 bytes (3 words), but only first 96 bytes used
        let mut signature = vec![0u8; 96];
        if data.len() >= offset + 256 {
            signature.copy_from_slice(&data[offset + 160..offset + 256]);
        }

        Ok(Vote {
            height,
            round,
            vote_type,
            block_hash,
            validator_index,
            signature,
        })
    }

    /// Verify double-sign evidence and return the validator address
    fn verify_double_sign_evidence(
        evidence: &DoubleSignEvidence,
    ) -> Result<Address, PrecompileError> {
        let vote_a = &evidence.vote_a;
        let vote_b = &evidence.vote_b;

        // Must be same validator
        if vote_a.validator_index != vote_b.validator_index {
            return Err(PrecompileError::InvalidEvidence(
                "votes from different validators".into(),
            ));
        }

        // Must be same height
        if vote_a.height != vote_b.height {
            return Err(PrecompileError::InvalidEvidence(
                "votes at different heights".into(),
            ));
        }

        // Must be same round
        if vote_a.round != vote_b.round {
            return Err(PrecompileError::InvalidEvidence(
                "votes in different rounds".into(),
            ));
        }

        // Must be same vote type
        if vote_a.vote_type != vote_b.vote_type {
            return Err(PrecompileError::InvalidEvidence(
                "different vote types".into(),
            ));
        }

        // Must have DIFFERENT block hashes (this is the actual offense)
        if vote_a.block_hash == vote_b.block_hash {
            return Err(PrecompileError::InvalidEvidence(
                "same block hash - not double signing".into(),
            ));
        }

        // In a real implementation, we would:
        // 1. Look up the validator by index from the validator set
        // 2. Verify both signatures against the validator's BLS public key
        // 3. Return the validator's address

        // For now, derive a deterministic address from the validator index
        let mut addr_bytes = [0u8; 20];
        addr_bytes[16..20].copy_from_slice(&vote_a.validator_index.to_be_bytes());
        Ok(Address::from(addr_bytes))
    }

    /// Hash evidence for deduplication
    fn hash_evidence(evidence: &DoubleSignEvidence) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(&evidence.vote_a.height.to_be_bytes());
        hasher.update(&evidence.vote_a.round.to_be_bytes());
        hasher.update(&evidence.vote_a.validator_index.to_be_bytes());
        hasher.update(&evidence.vote_a.block_hash.0);
        hasher.update(&evidence.vote_b.block_hash.0);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        B256::from(hash)
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

    /// Create ValidatorSlashed event log
    fn create_validator_slashed_event(
        validator: Address,
        amount: u128,
        offense_type: EvidenceType,
        jailed_until: u64,
    ) -> revm::primitives::Log {
        let event_sig = keccak256(b"ValidatorSlashed(address,uint256,uint8,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u256(U256::from(amount)));
        data.extend_from_slice(&abi::encode_u8(offense_type as u8));
        data.extend_from_slice(&abi::encode_u256(U256::from(jailed_until)));

        revm::primitives::Log::new_unchecked(
            SLASHING_ADDRESS,
            topics,
            Bytes::from(data),
        )
    }

    /// Create ValidatorUnjailed event log
    fn create_validator_unjailed_event(validator: Address) -> revm::primitives::Log {
        let event_sig = keccak256(b"ValidatorUnjailed(address)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
        ];

        revm::primitives::Log::new_unchecked(
            SLASHING_ADDRESS,
            topics,
            Bytes::new(),
        )
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
