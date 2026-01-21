//! Staking Precompile
//!
//! Precompiled contract at address 0x0000...1000 for staking operations.
//!
//! ## Functions
//!
//! ### Write Operations
//! - `stake(amount)` - Stake tokens (uses msg.value)
//! - `unstake(amount)` - Begin unbonding period
//! - `withdraw()` - Withdraw after unbonding period
//! - `delegate(validator, amount)` - Delegate to a validator (uses msg.value)
//! - `redelegate(from, to, amount)` - Move delegation between validators
//! - `claimRewards()` - Claim accumulated staking rewards
//!
//! ### View Functions
//! - `getStake(address)` - Get stake information for an address
//! - `getValidator(address)` - Get validator information

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::Database;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tracing::{debug, info};

use super::{abi, staking_selectors, PrecompileError, PrecompileOutput, STAKING_ADDRESS};
use crate::state_adapter::StateAdapter;

/// Minimum stake required to become a validator (100,000 MCN)
pub const MIN_VALIDATOR_STAKE: u128 = 100_000 * 10u128.pow(18);

/// Minimum delegation amount (1 MCN)
pub const MIN_DELEGATION: u128 = 10u128.pow(18);

/// Maximum number of active validators
pub const MAX_VALIDATORS: u32 = 51;

/// Unbonding period in blocks (~7 days at 2s blocks)
pub const UNBONDING_PERIOD: u64 = 302_400;

/// Maximum commission rate in basis points (50%)
pub const MAX_COMMISSION: u16 = 5000;

/// Maximum commission change per epoch in basis points (1%)
pub const MAX_COMMISSION_CHANGE: u16 = 100;

/// Gas costs for staking operations
pub const GAS_CREATE_VALIDATOR: u64 = 100_000;
pub const GAS_DELEGATE: u64 = 50_000;
pub const GAS_UNDELEGATE: u64 = 50_000;
pub const GAS_REDELEGATE: u64 = 75_000;
pub const GAS_CLAIM_REWARDS: u64 = 30_000;
pub const GAS_WITHDRAW: u64 = 30_000;
pub const GAS_GET_VALIDATOR: u64 = 5_000;
pub const GAS_GET_STAKE: u64 = 5_000;

// Multi-validator delegation gas costs
/// Base gas for batch delegation + per-validator cost
pub const GAS_BATCH_DELEGATE_BASE: u64 = 30_000;
pub const GAS_BATCH_DELEGATE_PER_VALIDATOR: u64 = 25_000;
/// Gas for auto-rebalancing stake
pub const GAS_AUTO_REBALANCE: u64 = 100_000;
/// Gas for getting all delegations
pub const GAS_GET_ALL_DELEGATIONS: u64 = 10_000;
/// Maximum validators per batch operation
pub const MAX_BATCH_VALIDATORS: usize = 10;

/// Validator record stored in state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// BLS public key for consensus (48 bytes)
    pub pubkey: Vec<u8>,
    /// Total stake (self + delegated)
    pub total_stake: u128,
    /// Validator's own stake
    pub self_stake: u128,
    /// Commission rate in basis points (100 = 1%)
    pub commission: u16,
    /// Whether the validator is active
    pub active: bool,
    /// Whether the validator is jailed
    pub jailed: bool,
    /// Block height until which validator is jailed (u64::MAX = permanent)
    pub jailed_until: u64,
    /// Accumulated commission earnings
    pub accumulated_commission: u128,
    /// Last block the validator proposed
    pub last_proposed_block: u64,
    /// Blocks proposed count
    pub blocks_proposed: u64,
}

impl Default for ValidatorRecord {
    fn default() -> Self {
        Self {
            pubkey: vec![0u8; 48],
            total_stake: 0,
            self_stake: 0,
            commission: 0,
            active: false,
            jailed: false,
            jailed_until: 0,
            accumulated_commission: 0,
            last_proposed_block: 0,
            blocks_proposed: 0,
        }
    }
}

/// Unbonding entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// Validator address
    pub validator: Address,
    /// Amount being unbonded
    pub amount: u128,
    /// Block height at which unbonding completes
    pub unlock_height: u64,
}

/// Delegation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    /// Amount delegated
    pub amount: u128,
    /// Pending rewards
    pub pending_rewards: u128,
    /// Last height rewards were calculated
    pub last_reward_height: u64,
}

/// Summary of all delegations for a user (used in multi-validator queries)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiDelegationSummary {
    /// List of validators the user has delegated to
    pub validators: Vec<Address>,
    /// Amounts delegated to each validator (same order as validators)
    pub amounts: Vec<u128>,
    /// Pending rewards from each validator
    pub rewards: Vec<u128>,
    /// Total amount delegated across all validators
    pub total_delegated: u128,
    /// Total pending rewards
    pub total_rewards: u128,
}

impl MultiDelegationSummary {
    /// Create a new empty summary
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
            amounts: Vec::new(),
            rewards: Vec::new(),
            total_delegated: 0,
            total_rewards: 0,
        }
    }

    /// Add a delegation to the summary
    pub fn add_delegation(&mut self, validator: Address, amount: u128, rewards: u128) {
        self.validators.push(validator);
        self.amounts.push(amount);
        self.rewards.push(rewards);
        self.total_delegated += amount;
        self.total_rewards += rewards;
    }
}

impl Default for MultiDelegationSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Staking state stored in the EVM state trie
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StakingState {
    /// Validator records by address
    pub validators: HashMap<Address, ValidatorRecord>,
    /// Delegations: delegator -> validator -> record
    pub delegations: HashMap<Address, HashMap<Address, DelegationRecord>>,
    /// Unbonding entries by delegator
    pub unbonding: HashMap<Address, Vec<UnbondingEntry>>,
    /// Total staked across all validators
    pub total_stake: u128,
    /// Next epoch number
    pub current_epoch: u64,
}

/// Staking precompile implementation
pub struct StakingPrecompile;

impl StakingPrecompile {
    /// Execute a staking precompile call
    pub fn execute_static<DB: Database>(
        caller: Address,
        input: &[u8],
        value: U256,
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
            staking_selectors::CREATE_VALIDATOR => {
                Self::create_validator(caller, data, value, block_number, db)
            }
            staking_selectors::DELEGATE => Self::delegate(caller, data, value, block_number, db),
            staking_selectors::UNDELEGATE => Self::undelegate(caller, data, block_number, db),
            staking_selectors::REDELEGATE => Self::redelegate(caller, data, block_number, db),
            staking_selectors::CLAIM_REWARDS => Self::claim_rewards(caller, db),
            staking_selectors::WITHDRAW_UNBONDED => {
                Self::withdraw_unbonded(caller, block_number, db)
            }
            staking_selectors::GET_VALIDATOR => Self::get_validator(data, db),
            staking_selectors::GET_STAKE => Self::get_stake(data, db),
            // Multi-validator delegation functions
            staking_selectors::BATCH_DELEGATE => {
                Self::batch_delegate(caller, data, value, block_number, db)
            }
            staking_selectors::SPLIT_DELEGATE => {
                Self::split_delegate(caller, data, value, block_number, db)
            }
            staking_selectors::GET_ALL_DELEGATIONS => Self::get_all_delegations(data, db),
            staking_selectors::AUTO_REBALANCE => {
                Self::auto_rebalance(caller, data, block_number, db)
            }
            _ => Err(PrecompileError::UnknownSelector { selector }),
        }
    }

    /// Create a new validator
    fn create_validator<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        _block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(caller = %caller, value = %value, "Creating validator");

        // Check minimum stake
        let stake_amount = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if stake_amount < MIN_VALIDATOR_STAKE {
            return Err(PrecompileError::InsufficientStake {
                required: U256::from(MIN_VALIDATOR_STAKE),
                provided: value,
            });
        }

        // Load staking state
        let mut state = Self::load_state(db)?;

        // Check if already a validator
        if state.validators.contains_key(&caller) {
            return Err(PrecompileError::ValidatorAlreadyExists(caller));
        }

        // Decode input: pubkey (48 bytes) + commission (2 bytes as u16 in 32-byte slot)
        if data.len() < 80 {
            return Err(PrecompileError::InvalidInput(
                "expected pubkey and commission".into(),
            ));
        }

        // Pubkey is dynamic bytes, need to decode offset and length
        let pubkey_offset = abi::decode_u256(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid pubkey offset".into()))?
            .as_limbs()[0] as usize;

        let commission = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid commission".into()))?
            .as_limbs()[0] as u16;

        // Validate commission
        if commission > MAX_COMMISSION {
            return Err(PrecompileError::InvalidCommission(
                commission,
                MAX_COMMISSION,
            ));
        }

        // Get pubkey bytes
        let pubkey_len = if data.len() > pubkey_offset + 32 {
            abi::decode_u256(data, pubkey_offset)
                .ok_or_else(|| PrecompileError::InvalidInput("invalid pubkey length".into()))?
                .as_limbs()[0] as usize
        } else {
            48 // Default BLS pubkey length
        };

        if pubkey_len != 48 {
            return Err(PrecompileError::InvalidPubkey);
        }

        let pubkey_start = pubkey_offset + 32;
        if data.len() < pubkey_start + 48 {
            return Err(PrecompileError::InvalidPubkey);
        }

        let pubkey = data[pubkey_start..pubkey_start + 48].to_vec();

        // Create validator record
        let validator = ValidatorRecord {
            pubkey: pubkey.clone(),
            total_stake: stake_amount,
            self_stake: stake_amount,
            commission,
            active: true,
            jailed: false,
            jailed_until: 0,
            accumulated_commission: 0,
            last_proposed_block: 0,
            blocks_proposed: 0,
        };

        state.validators.insert(caller, validator);
        state.total_stake += stake_amount;

        // Save state
        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_validator_created_event(caller, &pubkey, stake_amount, commission);

        debug!(
            validator = %caller,
            stake = stake_amount,
            commission = commission,
            "Validator created"
        );

        Ok(PrecompileOutput::with_logs(
            Bytes::new(),
            GAS_CREATE_VALIDATOR,
            vec![log],
        ))
    }

    /// Delegate stake to a validator
    fn delegate<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Check minimum delegation
        let amount = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if amount < MIN_DELEGATION {
            return Err(PrecompileError::InsufficientStake {
                required: U256::from(MIN_DELEGATION),
                provided: value,
            });
        }

        // Decode validator address
        let validator = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected validator address".into()))?;

        let mut state = Self::load_state(db)?;

        // Check validator exists and is active
        let val = state
            .validators
            .get_mut(&validator)
            .ok_or(PrecompileError::ValidatorNotFound(validator))?;

        if !val.active {
            return Err(PrecompileError::ValidatorNotActive);
        }

        if val.jailed {
            return Err(PrecompileError::ValidatorJailed(val.jailed_until));
        }

        // Update validator stake
        val.total_stake += amount;
        state.total_stake += amount;

        // Update or create delegation record
        let delegator_delegations = state.delegations.entry(caller).or_default();
        let delegation = delegator_delegations
            .entry(validator)
            .or_insert(DelegationRecord {
                amount: 0,
                pending_rewards: 0,
                last_reward_height: block_number,
            });
        delegation.amount += amount;

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_delegated_event(caller, validator, amount);

        debug!(
            delegator = %caller,
            validator = %validator,
            amount = amount,
            "Delegation added"
        );

        Ok(PrecompileOutput::with_logs(
            Bytes::new(),
            GAS_DELEGATE,
            vec![log],
        ))
    }

    /// Undelegate stake from a validator
    fn undelegate<DB: Database>(
        caller: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Decode validator address and amount
        let validator = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected validator address".into()))?;
        let amount_u256 = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("expected amount".into()))?;
        let amount =
            amount_u256.as_limbs()[0] as u128 | ((amount_u256.as_limbs()[1] as u128) << 64);

        let mut state = Self::load_state(db)?;

        // Get delegation
        let delegation = state
            .delegations
            .get_mut(&caller)
            .and_then(|d| d.get_mut(&validator))
            .ok_or(PrecompileError::NoDelegation)?;

        if delegation.amount < amount {
            return Err(PrecompileError::InsufficientDelegation);
        }

        // Reduce delegation
        delegation.amount -= amount;

        // Reduce validator stake
        if let Some(val) = state.validators.get_mut(&validator) {
            val.total_stake = val.total_stake.saturating_sub(amount);
        }
        state.total_stake = state.total_stake.saturating_sub(amount);

        // Create unbonding entry
        let unlock_height = block_number + UNBONDING_PERIOD;
        let unbonding_entries = state.unbonding.entry(caller).or_default();
        unbonding_entries.push(UnbondingEntry {
            validator,
            amount,
            unlock_height,
        });

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_undelegated_event(caller, validator, amount, unlock_height);

        debug!(
            delegator = %caller,
            validator = %validator,
            amount = amount,
            unlock_height = unlock_height,
            "Undelegation started"
        );

        Ok(PrecompileOutput::with_logs(
            Bytes::new(),
            GAS_UNDELEGATE,
            vec![log],
        ))
    }

    /// Redelegate stake between validators
    fn redelegate<DB: Database>(
        caller: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Decode from_validator, to_validator, and amount
        let from_validator = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected from validator".into()))?;
        let to_validator = abi::decode_address(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("expected to validator".into()))?;
        let amount_u256 = abi::decode_u256(data, 64)
            .ok_or_else(|| PrecompileError::InvalidInput("expected amount".into()))?;
        let amount =
            amount_u256.as_limbs()[0] as u128 | ((amount_u256.as_limbs()[1] as u128) << 64);

        let mut state = Self::load_state(db)?;

        // Verify source delegation exists
        let from_delegation = state
            .delegations
            .get_mut(&caller)
            .and_then(|d| d.get_mut(&from_validator))
            .ok_or(PrecompileError::NoDelegation)?;

        if from_delegation.amount < amount {
            return Err(PrecompileError::InsufficientDelegation);
        }

        // Verify destination validator is valid
        {
            let to_val = state
                .validators
                .get(&to_validator)
                .ok_or(PrecompileError::ValidatorNotFound(to_validator))?;

            if !to_val.active {
                return Err(PrecompileError::ValidatorNotActive);
            }

            if to_val.jailed {
                return Err(PrecompileError::ValidatorJailed(to_val.jailed_until));
            }
        }

        // Move stake
        from_delegation.amount -= amount;

        if let Some(from_val) = state.validators.get_mut(&from_validator) {
            from_val.total_stake = from_val.total_stake.saturating_sub(amount);
        }

        if let Some(to_val) = state.validators.get_mut(&to_validator) {
            to_val.total_stake += amount;
        }

        // Update destination delegation
        let delegator_delegations = state.delegations.entry(caller).or_default();
        let to_delegation = delegator_delegations
            .entry(to_validator)
            .or_insert(DelegationRecord {
                amount: 0,
                pending_rewards: 0,
                last_reward_height: block_number,
            });
        to_delegation.amount += amount;

        Self::save_state(db, &state)?;

        debug!(
            delegator = %caller,
            from = %from_validator,
            to = %to_validator,
            amount = amount,
            "Redelegation complete"
        );

        Ok(PrecompileOutput::new(Bytes::new(), GAS_REDELEGATE))
    }

    /// Claim accumulated staking rewards
    fn claim_rewards<DB: Database>(
        caller: Address,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let mut state = Self::load_state(db)?;

        // Calculate total rewards across all delegations
        let delegations = state
            .delegations
            .get_mut(&caller)
            .ok_or(PrecompileError::NoRewards)?;

        let mut total_rewards = 0u128;

        for delegation in delegations.values_mut() {
            total_rewards += delegation.pending_rewards;
            delegation.pending_rewards = 0;
        }

        if total_rewards == 0 {
            return Err(PrecompileError::NoRewards);
        }

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_rewards_claimed_event(caller, total_rewards);

        // Encode rewards amount for return
        let output = abi::encode_u256(U256::from(total_rewards));

        debug!(
            delegator = %caller,
            rewards = total_rewards,
            "Rewards claimed"
        );

        Ok(PrecompileOutput::with_logs(
            Bytes::copy_from_slice(&output),
            GAS_CLAIM_REWARDS,
            vec![log],
        ))
    }

    /// Withdraw unbonded stake after unbonding period
    fn withdraw_unbonded<DB: Database>(
        caller: Address,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let mut state = Self::load_state(db)?;

        let unbonding_entries = state
            .unbonding
            .get_mut(&caller)
            .ok_or(PrecompileError::NoUnbonding)?;

        // Partition into ready and pending
        let (ready, pending): (Vec<_>, Vec<_>) = unbonding_entries
            .drain(..)
            .partition(|e| e.unlock_height <= block_number);

        if ready.is_empty() {
            return Err(PrecompileError::NoUnbonding);
        }

        *unbonding_entries = pending;

        let total_amount: u128 = ready.iter().map(|e| e.amount).sum();

        Self::save_state(db, &state)?;

        // Encode amount for return
        let output = abi::encode_u256(U256::from(total_amount));

        debug!(
            caller = %caller,
            amount = total_amount,
            entries = ready.len(),
            "Unbonded stake withdrawn"
        );

        Ok(PrecompileOutput::new(
            Bytes::copy_from_slice(&output),
            GAS_WITHDRAW,
        ))
    }

    /// Get validator information (view function)
    fn get_validator<DB: Database>(
        data: &[u8],
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let validator_addr = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected validator address".into()))?;

        let state = Self::load_state(db)?;

        let validator = state
            .validators
            .get(&validator_addr)
            .ok_or(PrecompileError::ValidatorNotFound(validator_addr))?;

        // ABI encode response:
        // - pubkey (bytes - dynamic)
        // - totalStake (uint256)
        // - selfStake (uint256)
        // - commission (uint16 as uint256)
        // - active (bool)
        // - jailed (bool)
        // - jailedUntil (uint256)
        let mut output = Vec::new();

        // Offset to pubkey data (7 * 32 bytes for fixed fields)
        output.extend_from_slice(&abi::encode_u256(U256::from(7 * 32)));
        output.extend_from_slice(&abi::encode_u256(U256::from(validator.total_stake)));
        output.extend_from_slice(&abi::encode_u256(U256::from(validator.self_stake)));
        output.extend_from_slice(&abi::encode_u256(U256::from(validator.commission)));
        output.extend_from_slice(&abi::encode_bool(validator.active));
        output.extend_from_slice(&abi::encode_bool(validator.jailed));
        output.extend_from_slice(&abi::encode_u256(U256::from(validator.jailed_until)));

        // Pubkey bytes (length + data)
        output.extend_from_slice(&abi::encode_u256(U256::from(validator.pubkey.len())));
        let mut pubkey_padded = vec![0u8; 64]; // Pad to 64 bytes (2 words)
        let copy_len = std::cmp::min(validator.pubkey.len(), 48);
        pubkey_padded[..copy_len].copy_from_slice(&validator.pubkey[..copy_len]);
        output.extend_from_slice(&pubkey_padded);

        Ok(PrecompileOutput::new(
            Bytes::from(output),
            GAS_GET_VALIDATOR,
        ))
    }

    /// Get stake information for an address (view function)
    fn get_stake<DB: Database>(
        data: &[u8],
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let staker_addr = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected staker address".into()))?;

        let state = Self::load_state(db)?;

        // Calculate total staked and pending rewards
        let mut total_staked = 0u128;
        let mut total_rewards = 0u128;

        if let Some(delegations) = state.delegations.get(&staker_addr) {
            for delegation in delegations.values() {
                total_staked += delegation.amount;
                total_rewards += delegation.pending_rewards;
            }
        }

        // Check if also a validator
        if let Some(validator) = state.validators.get(&staker_addr) {
            total_staked += validator.self_stake;
        }

        // Calculate total unbonding
        let total_unbonding: u128 = state
            .unbonding
            .get(&staker_addr)
            .map(|entries| entries.iter().map(|e| e.amount).sum())
            .unwrap_or(0);

        // ABI encode response
        let mut output = Vec::new();
        output.extend_from_slice(&abi::encode_u256(U256::from(total_staked)));
        output.extend_from_slice(&abi::encode_u256(U256::from(total_rewards)));
        output.extend_from_slice(&abi::encode_u256(U256::from(total_unbonding)));

        Ok(PrecompileOutput::new(Bytes::from(output), GAS_GET_STAKE))
    }

    // ==============================
    // Multi-Validator Delegation Functions
    // ==============================

    /// Batch delegate to multiple validators with specific amounts
    ///
    /// Input format: validators (address[]) + amounts (uint256[])
    /// The msg.value must equal the sum of amounts
    fn batch_delegate<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(caller = %caller, value = %value, "Batch delegating to multiple validators");

        // Parse validators array offset and amounts array offset
        if data.len() < 64 {
            return Err(PrecompileError::InvalidInput(
                "insufficient data for batch delegate".into(),
            ));
        }

        // Decode arrays (simplified - assumes contiguous encoding)
        let (validators, amounts) = Self::decode_batch_delegate_params(data)?;

        if validators.len() != amounts.len() {
            return Err(PrecompileError::InvalidInput(
                "validators and amounts length mismatch".into(),
            ));
        }

        if validators.len() > MAX_BATCH_VALIDATORS {
            return Err(PrecompileError::InvalidInput(format!(
                "too many validators: {} > {}",
                validators.len(),
                MAX_BATCH_VALIDATORS
            )));
        }

        // Verify total amount matches msg.value
        let total_amount: u128 = amounts.iter().sum();
        let msg_value = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if total_amount != msg_value {
            return Err(PrecompileError::InvalidInput(format!(
                "amounts sum ({}) doesn't match msg.value ({})",
                total_amount, msg_value
            )));
        }

        let mut state = Self::load_state(db)?;
        let mut logs = Vec::new();

        // Process each delegation
        for (validator, amount) in validators.iter().zip(amounts.iter()) {
            if *amount < MIN_DELEGATION {
                return Err(PrecompileError::InsufficientStake {
                    required: U256::from(MIN_DELEGATION),
                    provided: U256::from(*amount),
                });
            }

            // Check validator exists and is active
            let val = state
                .validators
                .get_mut(validator)
                .ok_or(PrecompileError::ValidatorNotFound(*validator))?;

            if !val.active || val.jailed {
                return Err(PrecompileError::ValidatorInactive(*validator));
            }

            // Update validator's total stake
            val.total_stake += *amount;

            // Update or create delegation record
            let delegations = state.delegations.entry(caller).or_default();
            let delegation = delegations.entry(*validator).or_insert(DelegationRecord {
                amount: 0,
                pending_rewards: 0,
                last_reward_height: block_number,
            });
            delegation.amount += *amount;

            logs.push(Self::create_delegated_event(caller, *validator, *amount));
        }

        // Update total stake
        state.total_stake += total_amount;

        Self::save_state(db, &state)?;

        // Calculate gas: base + per-validator cost
        let gas_used =
            GAS_BATCH_DELEGATE_BASE + (validators.len() as u64 * GAS_BATCH_DELEGATE_PER_VALIDATOR);

        debug!(
            caller = %caller,
            validators = validators.len(),
            total_amount = total_amount,
            "Batch delegation complete"
        );

        let mut output = PrecompileOutput::new(
            Bytes::copy_from_slice(&abi::encode_u256(U256::from(total_amount))),
            gas_used,
        );
        for log in logs {
            output.add_log(log);
        }
        Ok(output)
    }

    /// Split delegate evenly among multiple validators
    ///
    /// Input format: validators (address[])
    /// The msg.value is split evenly among validators, remainder goes to first validator
    fn split_delegate<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(caller = %caller, value = %value, "Split delegating to validators");

        let validators = Self::decode_address_array(data)?;

        if validators.is_empty() {
            return Err(PrecompileError::InvalidInput(
                "no validators provided".into(),
            ));
        }

        if validators.len() > MAX_BATCH_VALIDATORS {
            return Err(PrecompileError::InvalidInput(format!(
                "too many validators: {} > {}",
                validators.len(),
                MAX_BATCH_VALIDATORS
            )));
        }

        let total_amount = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        let per_validator = total_amount / validators.len() as u128;
        let remainder = total_amount % validators.len() as u128;

        if per_validator < MIN_DELEGATION {
            return Err(PrecompileError::InsufficientStake {
                required: U256::from(MIN_DELEGATION * validators.len() as u128),
                provided: value,
            });
        }

        // Build amounts array: first validator gets remainder
        let amounts: Vec<u128> = validators
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if i == 0 {
                    per_validator + remainder
                } else {
                    per_validator
                }
            })
            .collect();

        // Encode as batch delegate params and delegate
        Self::batch_delegate_internal(caller, &validators, &amounts, block_number, db)
    }

    /// Get all delegations for an address
    fn get_all_delegations<DB: Database>(
        data: &[u8],
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let staker_addr = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected staker address".into()))?;

        let state = Self::load_state(db)?;

        let mut summary = MultiDelegationSummary::new();

        if let Some(delegations) = state.delegations.get(&staker_addr) {
            for (validator, record) in delegations {
                summary.add_delegation(*validator, record.amount, record.pending_rewards);
            }
        }

        // Encode response: total_delegated, total_rewards, count, then arrays
        let mut output = Vec::new();
        output.extend_from_slice(&abi::encode_u256(U256::from(summary.total_delegated)));
        output.extend_from_slice(&abi::encode_u256(U256::from(summary.total_rewards)));
        output.extend_from_slice(&abi::encode_u256(U256::from(summary.validators.len())));

        // Offset to validators array (3 * 32 + offset)
        output.extend_from_slice(&abi::encode_u256(U256::from(128))); // offset to validators
        output.extend_from_slice(&abi::encode_u256(U256::from(
            128 + 32 + summary.validators.len() * 32,
        ))); // offset to amounts

        // Validators array
        output.extend_from_slice(&abi::encode_u256(U256::from(summary.validators.len())));
        for validator in &summary.validators {
            let mut padded = [0u8; 32];
            padded[12..32].copy_from_slice(validator.as_slice());
            output.extend_from_slice(&padded);
        }

        // Amounts array
        output.extend_from_slice(&abi::encode_u256(U256::from(summary.amounts.len())));
        for amount in &summary.amounts {
            output.extend_from_slice(&abi::encode_u256(U256::from(*amount)));
        }

        Ok(PrecompileOutput::new(
            Bytes::from(output),
            GAS_GET_ALL_DELEGATIONS,
        ))
    }

    /// Auto-rebalance stake when validators become inactive
    ///
    /// Moves stake from inactive/jailed validators to active ones from the provided list
    fn auto_rebalance<DB: Database>(
        caller: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(caller = %caller, "Auto-rebalancing stake");

        let target_validators = Self::decode_address_array(data)?;

        if target_validators.is_empty() {
            return Err(PrecompileError::InvalidInput(
                "no target validators provided".into(),
            ));
        }

        let mut state = Self::load_state(db)?;
        let mut logs = Vec::new();

        // Get caller's delegations
        let delegations = match state.delegations.get_mut(&caller) {
            Some(d) => d,
            None => return Err(PrecompileError::NoUnbonding), // No delegations to rebalance
        };

        // Find inactive validators and collect their stake
        let mut stake_to_redistribute: u128 = 0;
        let mut validators_to_remove = Vec::new();

        for (validator, record) in delegations.iter() {
            if let Some(val) = state.validators.get(validator) {
                if !val.active || val.jailed {
                    stake_to_redistribute += record.amount;
                    validators_to_remove.push(*validator);
                }
            }
        }

        if stake_to_redistribute == 0 {
            return Err(PrecompileError::InvalidInput(
                "no inactive validators to rebalance from".into(),
            ));
        }

        // Filter target validators to only active ones
        let active_targets: Vec<Address> = target_validators
            .into_iter()
            .filter(|v| {
                state
                    .validators
                    .get(v)
                    .map(|val| val.active && !val.jailed)
                    .unwrap_or(false)
            })
            .collect();

        if active_targets.is_empty() {
            return Err(PrecompileError::InvalidInput(
                "no active target validators".into(),
            ));
        }

        // Remove stake from inactive validators
        for validator in &validators_to_remove {
            if let Some(record) = delegations.remove(validator) {
                if let Some(val) = state.validators.get_mut(validator) {
                    val.total_stake = val.total_stake.saturating_sub(record.amount);
                }
                logs.push(Self::create_undelegated_event(
                    caller,
                    *validator,
                    record.amount,
                    block_number,
                ));
            }
        }

        // Distribute to active validators evenly
        let per_validator = stake_to_redistribute / active_targets.len() as u128;
        let remainder = stake_to_redistribute % active_targets.len() as u128;

        for (i, validator) in active_targets.iter().enumerate() {
            let amount = if i == 0 {
                per_validator + remainder
            } else {
                per_validator
            };

            if let Some(val) = state.validators.get_mut(validator) {
                val.total_stake += amount;
            }

            let delegation = delegations.entry(*validator).or_insert(DelegationRecord {
                amount: 0,
                pending_rewards: 0,
                last_reward_height: block_number,
            });
            delegation.amount += amount;

            logs.push(Self::create_delegated_event(caller, *validator, amount));
        }

        Self::save_state(db, &state)?;

        debug!(
            caller = %caller,
            redistributed = stake_to_redistribute,
            from_validators = validators_to_remove.len(),
            to_validators = active_targets.len(),
            "Auto-rebalance complete"
        );

        let mut output = PrecompileOutput::new(
            Bytes::copy_from_slice(&abi::encode_u256(U256::from(stake_to_redistribute))),
            GAS_AUTO_REBALANCE,
        );
        for log in logs {
            output.add_log(log);
        }
        Ok(output)
    }

    /// Internal batch delegate helper
    fn batch_delegate_internal<DB: Database>(
        caller: Address,
        validators: &[Address],
        amounts: &[u128],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let mut state = Self::load_state(db)?;
        let mut logs = Vec::new();
        let mut total_amount: u128 = 0;

        for (validator, amount) in validators.iter().zip(amounts.iter()) {
            let val = state
                .validators
                .get_mut(validator)
                .ok_or(PrecompileError::ValidatorNotFound(*validator))?;

            if !val.active || val.jailed {
                return Err(PrecompileError::ValidatorInactive(*validator));
            }

            val.total_stake += *amount;

            let delegations = state.delegations.entry(caller).or_default();
            let delegation = delegations.entry(*validator).or_insert(DelegationRecord {
                amount: 0,
                pending_rewards: 0,
                last_reward_height: block_number,
            });
            delegation.amount += *amount;
            total_amount += *amount;

            logs.push(Self::create_delegated_event(caller, *validator, *amount));
        }

        state.total_stake += total_amount;
        Self::save_state(db, &state)?;

        let gas_used =
            GAS_BATCH_DELEGATE_BASE + (validators.len() as u64 * GAS_BATCH_DELEGATE_PER_VALIDATOR);

        let mut output = PrecompileOutput::new(
            Bytes::copy_from_slice(&abi::encode_u256(U256::from(total_amount))),
            gas_used,
        );
        for log in logs {
            output.add_log(log);
        }
        Ok(output)
    }

    /// Decode batch delegate parameters (validators[], amounts[])
    fn decode_batch_delegate_params(
        data: &[u8],
    ) -> Result<(Vec<Address>, Vec<u128>), PrecompileError> {
        // Simplified ABI decoding for two dynamic arrays
        if data.len() < 128 {
            return Err(PrecompileError::InvalidInput(
                "insufficient data for batch params".into(),
            ));
        }

        let validators_offset = abi::decode_u256(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid validators offset".into()))?
            .as_limbs()[0] as usize;
        let amounts_offset = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid amounts offset".into()))?
            .as_limbs()[0] as usize;

        let validators = Self::decode_address_array_at(data, validators_offset)?;
        let amounts = Self::decode_u128_array_at(data, amounts_offset)?;

        Ok((validators, amounts))
    }

    /// Decode address array from data
    fn decode_address_array(data: &[u8]) -> Result<Vec<Address>, PrecompileError> {
        if data.len() < 32 {
            return Err(PrecompileError::InvalidInput(
                "insufficient data for array".into(),
            ));
        }

        let offset = abi::decode_u256(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid array offset".into()))?
            .as_limbs()[0] as usize;
        Self::decode_address_array_at(data, offset)
    }

    /// Decode address array at specific offset
    fn decode_address_array_at(
        data: &[u8],
        offset: usize,
    ) -> Result<Vec<Address>, PrecompileError> {
        if offset + 32 > data.len() {
            return Err(PrecompileError::InvalidInput(
                "array offset out of bounds".into(),
            ));
        }

        let length = abi::decode_u256(data, offset)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid array length".into()))?
            .as_limbs()[0] as usize;
        let mut addresses = Vec::with_capacity(length);

        for i in 0..length {
            let addr_offset = offset + 32 + i * 32;
            if addr_offset + 32 > data.len() {
                return Err(PrecompileError::InvalidInput(
                    "array element out of bounds".into(),
                ));
            }
            if let Some(addr) = abi::decode_address(data, addr_offset) {
                addresses.push(addr);
            } else {
                return Err(PrecompileError::InvalidInput(
                    "invalid address in array".into(),
                ));
            }
        }

        Ok(addresses)
    }

    /// Decode u128 array at specific offset
    fn decode_u128_array_at(data: &[u8], offset: usize) -> Result<Vec<u128>, PrecompileError> {
        if offset + 32 > data.len() {
            return Err(PrecompileError::InvalidInput(
                "array offset out of bounds".into(),
            ));
        }

        let length = abi::decode_u256(data, offset)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid array length".into()))?
            .as_limbs()[0] as usize;
        let mut values = Vec::with_capacity(length);

        for i in 0..length {
            let val_offset = offset + 32 + i * 32;
            if val_offset + 32 > data.len() {
                return Err(PrecompileError::InvalidInput(
                    "array element out of bounds".into(),
                ));
            }
            let val = abi::decode_u256(data, val_offset)
                .ok_or_else(|| PrecompileError::InvalidInput("invalid value in array".into()))?;
            // Convert U256 to u128 (take lower 128 bits)
            let lower = val.as_limbs()[0] as u128 | ((val.as_limbs()[1] as u128) << 64);
            values.push(lower);
        }

        Ok(values)
    }

    // State management helpers

    /// Get staking state for external access (e.g., governance voting power)
    ///
    /// This is the public accessor for other precompiles to read staking state.
    pub fn get_staking_state<DB: Database>(
        db: &mut StateAdapter<DB>,
    ) -> Result<StakingState, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        Self::load_state(db)
    }

    /// Storage slot for state length (in bytes)
    const STATE_LENGTH_SLOT: U256 = U256::ZERO;

    /// Base slot for state data (chunked in 32-byte slots)
    const STATE_DATA_BASE_SLOT: u64 = 1;

    /// Load staking state from storage
    ///
    /// State is stored as JSON, chunked across multiple 32-byte storage slots:
    /// - Slot 0: Length of serialized state in bytes
    /// - Slots 1..n: 32-byte chunks of serialized JSON
    fn load_state<DB: Database>(db: &mut StateAdapter<DB>) -> Result<StakingState, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Read state length from slot 0
        let length_slot = db
            .get_storage(STAKING_ADDRESS, Self::STATE_LENGTH_SLOT)
            .map_err(|e| PrecompileError::StateError(format!("{:?}", e)))?;

        let length: usize = length_slot.try_into().unwrap_or(0);

        // If no state stored, return default
        if length == 0 {
            return Ok(StakingState::default());
        }

        // Calculate number of slots needed
        let num_slots = (length + 31) / 32;

        // Read state data from consecutive slots
        let mut data = Vec::with_capacity(length);
        for i in 0..num_slots {
            let slot = U256::from(Self::STATE_DATA_BASE_SLOT + i as u64);
            let value = db
                .get_storage(STAKING_ADDRESS, slot)
                .map_err(|e| PrecompileError::StateError(format!("{:?}", e)))?;

            // Convert U256 to bytes (big-endian)
            let bytes: [u8; 32] = value.to_be_bytes();
            data.extend_from_slice(&bytes);
        }

        // Truncate to actual length
        data.truncate(length);

        // Deserialize from JSON
        serde_json::from_slice(&data)
            .map_err(|e| PrecompileError::StateError(format!("deserialize error: {}", e)))
    }

    /// Save staking state to storage
    ///
    /// State is stored as JSON, chunked across multiple 32-byte storage slots:
    /// - Slot 0: Length of serialized state in bytes
    /// - Slots 1..n: 32-byte chunks of serialized JSON
    fn save_state<DB: Database>(
        db: &mut StateAdapter<DB>,
        state: &StakingState,
    ) -> Result<(), PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Serialize state to JSON
        let data = serde_json::to_vec(state)
            .map_err(|e| PrecompileError::StateError(format!("serialize error: {}", e)))?;

        let length = data.len();

        // Store length in slot 0
        db.set_storage(STAKING_ADDRESS, Self::STATE_LENGTH_SLOT, U256::from(length));

        // Store data in consecutive 32-byte slots
        let num_slots = (length + 31) / 32;
        for i in 0..num_slots {
            let slot = U256::from(Self::STATE_DATA_BASE_SLOT + i as u64);
            let start = i * 32;
            let end = (start + 32).min(length);

            // Pad to 32 bytes if needed
            let mut chunk = [0u8; 32];
            chunk[..end - start].copy_from_slice(&data[start..end]);

            let value = U256::from_be_bytes(chunk);
            db.set_storage(STAKING_ADDRESS, slot, value);
        }

        debug!(
            length = length,
            slots = num_slots,
            "Saved staking state to storage"
        );

        Ok(())
    }

    // Event creation helpers

    /// Create ValidatorCreated event log
    fn create_validator_created_event(
        validator: Address,
        pubkey: &[u8],
        stake: u128,
        commission: u16,
    ) -> revm::primitives::Log {
        // Event: ValidatorCreated(address indexed validator, bytes pubkey, uint256 stake, uint16 commission)
        let event_sig = keccak256(b"ValidatorCreated(address,bytes,uint256,uint16)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![B256::from(event_sig), B256::from(topic1)];

        // Encode data: pubkey offset, stake, commission, pubkey length, pubkey data
        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u256(U256::from(96))); // offset to pubkey
        data.extend_from_slice(&abi::encode_u256(U256::from(stake)));
        data.extend_from_slice(&abi::encode_u256(U256::from(commission)));
        data.extend_from_slice(&abi::encode_u256(U256::from(pubkey.len()))); // pubkey length
        let mut pubkey_padded = vec![0u8; 64];
        let copy_len = std::cmp::min(pubkey.len(), 48);
        pubkey_padded[..copy_len].copy_from_slice(&pubkey[..copy_len]);
        data.extend_from_slice(&pubkey_padded);

        revm::primitives::Log::new_unchecked(STAKING_ADDRESS, topics, Bytes::from(data))
    }

    /// Create Delegated event log
    fn create_delegated_event(
        delegator: Address,
        validator: Address,
        amount: u128,
    ) -> revm::primitives::Log {
        let event_sig = keccak256(b"Delegated(address,address,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(delegator.as_slice());

        let mut topic2 = [0u8; 32];
        topic2[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
            B256::from(topic2),
        ];

        let data = abi::encode_u256(U256::from(amount));

        revm::primitives::Log::new_unchecked(STAKING_ADDRESS, topics, Bytes::copy_from_slice(&data))
    }

    /// Create Undelegated event log
    fn create_undelegated_event(
        delegator: Address,
        validator: Address,
        amount: u128,
        unlock_height: u64,
    ) -> revm::primitives::Log {
        let event_sig = keccak256(b"Undelegated(address,address,uint256,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(delegator.as_slice());

        let mut topic2 = [0u8; 32];
        topic2[12..32].copy_from_slice(validator.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
            B256::from(topic2),
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u256(U256::from(amount)));
        data.extend_from_slice(&abi::encode_u256(U256::from(unlock_height)));

        revm::primitives::Log::new_unchecked(STAKING_ADDRESS, topics, Bytes::from(data))
    }

    /// Create RewardsClaimed event log
    fn create_rewards_claimed_event(delegator: Address, amount: u128) -> revm::primitives::Log {
        let event_sig = keccak256(b"RewardsClaimed(address,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[12..32].copy_from_slice(delegator.as_slice());

        let topics = vec![B256::from(event_sig), B256::from(topic1)];

        let data = abi::encode_u256(U256::from(amount));

        revm::primitives::Log::new_unchecked(STAKING_ADDRESS, topics, Bytes::copy_from_slice(&data))
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
