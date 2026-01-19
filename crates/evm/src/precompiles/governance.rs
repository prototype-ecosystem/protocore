//! Governance Precompile
//!
//! Precompiled contract at address 0x0000...1002 for on-chain governance.
//!
//! ## Proposal Types
//!
//! - `ParameterChange` - Modify chain parameters
//! - `Upgrade` - Protocol upgrade
//! - `Treasury` - Treasury spending
//! - `Text` - Non-binding text proposal
//!
//! ## Proposal States
//!
//! - Pending - Waiting for voting to start
//! - Active - Voting is open
//! - Canceled - Proposer canceled
//! - Defeated - Did not pass
//! - Succeeded - Passed, awaiting execution
//! - Executed - Successfully executed
//!
//! ## Functions
//!
//! ### Write Operations
//! - `propose(type, data, description)` - Create a proposal
//! - `vote(proposalId, support)` - Vote on a proposal
//! - `execute(proposalId)` - Execute a passed proposal
//!
//! ### View Functions
//! - `getProposal(id)` - Get proposal details

use alloy_primitives::{Address, Bytes, B256, U256};
use revm::Database;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tracing::{debug, info};

use super::{
    abi, governance_selectors, PrecompileError, PrecompileOutput, GOVERNANCE_ADDRESS,
};
use crate::state_adapter::StateAdapter;

/// Minimum stake required to create a proposal (10,000 MCN)
pub const PROPOSAL_THRESHOLD: u128 = 10_000 * 10u128.pow(18);

/// Required deposit to create a proposal (1,000 MCN)
pub const PROPOSAL_DEPOSIT: u128 = 1_000 * 10u128.pow(18);

/// Voting delay in blocks (~200 seconds at 2s blocks)
pub const VOTING_DELAY: u64 = 100;

/// Voting period in blocks (~12 hours at 2s blocks)
pub const VOTING_PERIOD: u64 = 21600;

/// Quorum percentage (33%)
pub const QUORUM_PERCENTAGE: u8 = 33;

/// Pass threshold percentage (50%)
pub const PASS_THRESHOLD: u8 = 50;

/// Gas costs for governance operations
pub const GAS_PROPOSE: u64 = 100_000;
pub const GAS_VOTE: u64 = 50_000;
pub const GAS_EXECUTE: u64 = 100_000;
pub const GAS_GET_PROPOSAL: u64 = 10_000;

/// Proposal type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProposalType {
    /// Change chain parameters
    ParameterChange = 0,
    /// Protocol upgrade
    Upgrade = 1,
    /// Treasury spending
    Treasury = 2,
    /// Non-binding text proposal
    Text = 3,
}

impl TryFrom<u8> for ProposalType {
    type Error = PrecompileError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProposalType::ParameterChange),
            1 => Ok(ProposalType::Upgrade),
            2 => Ok(ProposalType::Treasury),
            3 => Ok(ProposalType::Text),
            _ => Err(PrecompileError::InvalidInput(format!(
                "unknown proposal type: {}",
                value
            ))),
        }
    }
}

/// Vote support options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteSupport {
    /// Vote against the proposal
    Against = 0,
    /// Vote for the proposal
    For = 1,
    /// Abstain from voting
    Abstain = 2,
}

impl TryFrom<u8> for VoteSupport {
    type Error = PrecompileError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(VoteSupport::Against),
            1 => Ok(VoteSupport::For),
            2 => Ok(VoteSupport::Abstain),
            _ => Err(PrecompileError::InvalidInput(format!(
                "invalid vote support: {}",
                value
            ))),
        }
    }
}

/// Proposal state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProposalState {
    /// Proposal created, waiting for voting to start
    Pending = 0,
    /// Voting is active
    Active = 1,
    /// Proposal was canceled
    Canceled = 2,
    /// Proposal was defeated (did not pass)
    Defeated = 3,
    /// Proposal succeeded, awaiting execution
    Succeeded = 4,
    /// Proposal was queued (if timelock is used)
    Queued = 5,
    /// Proposal expired without execution
    Expired = 6,
    /// Proposal was executed
    Executed = 7,
}

/// Proposal data based on type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalData {
    /// Parameter change proposal
    ParameterChange {
        /// Parameter key (e.g., keccak256("MIN_STAKE"))
        key: B256,
        /// New value (ABI-encoded)
        value: Bytes,
    },
    /// Protocol upgrade proposal
    Upgrade {
        /// Block height at which upgrade activates
        activation_height: u64,
        /// Hash of new code/binary
        code_hash: B256,
    },
    /// Treasury spending proposal
    Treasury {
        /// Recipient address
        recipient: Address,
        /// Amount to transfer
        amount: u128,
    },
    /// Text proposal (non-binding)
    Text {
        /// IPFS hash of proposal text
        description_hash: B256,
    },
}

/// A governance proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: u64,
    /// Proposer address
    pub proposer: Address,
    /// Proposal type
    pub proposal_type: ProposalType,
    /// Block height when voting starts
    pub voting_start: u64,
    /// Block height when voting ends
    pub voting_end: u64,
    /// Total votes for
    pub for_votes: u128,
    /// Total votes against
    pub against_votes: u128,
    /// Total abstain votes
    pub abstain_votes: u128,
    /// Whether proposal has been executed
    pub executed: bool,
    /// Whether proposal has been canceled
    pub canceled: bool,
    /// Proposal-specific data
    pub data: ProposalData,
    /// Deposit amount
    pub deposit: u128,
    /// Description hash (IPFS)
    pub description_hash: B256,
}

/// Vote record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    /// Vote support (against/for/abstain)
    pub support: VoteSupport,
    /// Voting weight used
    pub weight: u128,
}

/// Governance state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceState {
    /// All proposals by ID
    pub proposals: HashMap<u64, Proposal>,
    /// Votes: (proposal_id, voter) -> vote record
    pub votes: HashMap<(u64, Address), VoteRecord>,
    /// Next proposal ID
    pub next_proposal_id: u64,
    /// Treasury balance
    pub treasury_balance: u128,
    /// Total staked tokens (for quorum calculation)
    pub total_stake: u128,
}

/// Governance precompile implementation
pub struct GovernancePrecompile;

impl GovernancePrecompile {
    /// Execute a governance precompile call
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
            governance_selectors::PROPOSE_PARAMETER_CHANGE => {
                Self::propose_parameter_change(caller, data, value, block_number, db)
            }
            governance_selectors::PROPOSE_TREASURY_SPEND => {
                Self::propose_treasury_spend(caller, data, value, block_number, db)
            }
            governance_selectors::PROPOSE_UPGRADE => {
                Self::propose_upgrade(caller, data, value, block_number, db)
            }
            governance_selectors::VOTE => Self::vote(caller, data, block_number, db),
            governance_selectors::EXECUTE => Self::execute_proposal(data, block_number, db),
            governance_selectors::GET_PROPOSAL => Self::get_proposal(data, db),
            _ => Err(PrecompileError::UnknownSelector { selector }),
        }
    }

    /// Create a parameter change proposal
    fn propose_parameter_change<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(proposer = %caller, "Creating parameter change proposal");

        // Check deposit
        let deposit = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if deposit < PROPOSAL_DEPOSIT {
            return Err(PrecompileError::InsufficientDeposit {
                required: U256::from(PROPOSAL_DEPOSIT),
                provided: value,
            });
        }

        // Check voting power
        let voting_power = Self::get_voting_power(db, caller)?;
        if voting_power < PROPOSAL_THRESHOLD {
            return Err(PrecompileError::InsufficientVotingPower {
                required: U256::from(PROPOSAL_THRESHOLD),
                available: U256::from(voting_power),
            });
        }

        // Decode proposal data: parameterKey (bytes32), newValue (bytes), description (bytes32)
        if data.len() < 96 {
            return Err(PrecompileError::InvalidInput(
                "expected parameter key, value, and description".into(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&data[0..32]);

        let _value_offset = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("invalid value offset".into()))?
            .as_limbs()[0] as usize;

        let mut description_hash = [0u8; 32];
        description_hash.copy_from_slice(&data[64..96]);

        let param_value = abi::decode_bytes(data, 32).unwrap_or_default();

        let mut state = Self::load_state(db)?;

        let proposal_id = state.next_proposal_id;
        state.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            proposer: caller,
            proposal_type: ProposalType::ParameterChange,
            voting_start: block_number + VOTING_DELAY,
            voting_end: block_number + VOTING_DELAY + VOTING_PERIOD,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed: false,
            canceled: false,
            data: ProposalData::ParameterChange {
                key: B256::from(key),
                value: param_value,
            },
            deposit,
            description_hash: B256::from(description_hash),
        };

        state.proposals.insert(proposal_id, proposal);

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_proposal_created_event(
            proposal_id,
            caller,
            ProposalType::ParameterChange,
            B256::from(description_hash),
            block_number + VOTING_DELAY,
            block_number + VOTING_DELAY + VOTING_PERIOD,
        );

        debug!(
            proposal_id = proposal_id,
            proposer = %caller,
            "Parameter change proposal created"
        );

        // Return proposal ID
        let output = abi::encode_u256(U256::from(proposal_id));

        Ok(PrecompileOutput::with_logs(
            Bytes::copy_from_slice(&output),
            GAS_PROPOSE,
            vec![log],
        ))
    }

    /// Create a treasury spending proposal
    fn propose_treasury_spend<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(proposer = %caller, "Creating treasury spend proposal");

        // Check deposit
        let deposit = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if deposit < PROPOSAL_DEPOSIT {
            return Err(PrecompileError::InsufficientDeposit {
                required: U256::from(PROPOSAL_DEPOSIT),
                provided: value,
            });
        }

        // Check voting power
        let voting_power = Self::get_voting_power(db, caller)?;
        if voting_power < PROPOSAL_THRESHOLD {
            return Err(PrecompileError::InsufficientVotingPower {
                required: U256::from(PROPOSAL_THRESHOLD),
                available: U256::from(voting_power),
            });
        }

        // Decode: recipient (address), amount (uint256), description (bytes32)
        let recipient = abi::decode_address(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected recipient".into()))?;

        let amount_u256 = abi::decode_u256(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("expected amount".into()))?;
        let amount = amount_u256.as_limbs()[0] as u128 | ((amount_u256.as_limbs()[1] as u128) << 64);

        let mut description_hash = [0u8; 32];
        if data.len() >= 96 {
            description_hash.copy_from_slice(&data[64..96]);
        }

        let mut state = Self::load_state(db)?;

        let proposal_id = state.next_proposal_id;
        state.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            proposer: caller,
            proposal_type: ProposalType::Treasury,
            voting_start: block_number + VOTING_DELAY,
            voting_end: block_number + VOTING_DELAY + VOTING_PERIOD,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed: false,
            canceled: false,
            data: ProposalData::Treasury { recipient, amount },
            deposit,
            description_hash: B256::from(description_hash),
        };

        state.proposals.insert(proposal_id, proposal);

        Self::save_state(db, &state)?;

        let log = Self::create_proposal_created_event(
            proposal_id,
            caller,
            ProposalType::Treasury,
            B256::from(description_hash),
            block_number + VOTING_DELAY,
            block_number + VOTING_DELAY + VOTING_PERIOD,
        );

        debug!(
            proposal_id = proposal_id,
            recipient = %recipient,
            amount = amount,
            "Treasury spend proposal created"
        );

        let output = abi::encode_u256(U256::from(proposal_id));

        Ok(PrecompileOutput::with_logs(
            Bytes::copy_from_slice(&output),
            GAS_PROPOSE,
            vec![log],
        ))
    }

    /// Create a protocol upgrade proposal
    fn propose_upgrade<DB: Database>(
        caller: Address,
        data: &[u8],
        value: U256,
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        info!(proposer = %caller, "Creating upgrade proposal");

        // Check deposit
        let deposit = value.as_limbs()[0] as u128 | ((value.as_limbs()[1] as u128) << 64);
        if deposit < PROPOSAL_DEPOSIT {
            return Err(PrecompileError::InsufficientDeposit {
                required: U256::from(PROPOSAL_DEPOSIT),
                provided: value,
            });
        }

        // Check voting power
        let voting_power = Self::get_voting_power(db, caller)?;
        if voting_power < PROPOSAL_THRESHOLD {
            return Err(PrecompileError::InsufficientVotingPower {
                required: U256::from(PROPOSAL_THRESHOLD),
                available: U256::from(voting_power),
            });
        }

        // Decode: upgradeHeight (uint256), codeHash (bytes32), description (bytes32)
        let activation_height = abi::decode_u64(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected upgrade height".into()))?;

        let mut code_hash = [0u8; 32];
        if data.len() >= 64 {
            code_hash.copy_from_slice(&data[32..64]);
        }

        let mut description_hash = [0u8; 32];
        if data.len() >= 96 {
            description_hash.copy_from_slice(&data[64..96]);
        }

        let mut state = Self::load_state(db)?;

        let proposal_id = state.next_proposal_id;
        state.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            proposer: caller,
            proposal_type: ProposalType::Upgrade,
            voting_start: block_number + VOTING_DELAY,
            voting_end: block_number + VOTING_DELAY + VOTING_PERIOD,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            executed: false,
            canceled: false,
            data: ProposalData::Upgrade {
                activation_height,
                code_hash: B256::from(code_hash),
            },
            deposit,
            description_hash: B256::from(description_hash),
        };

        state.proposals.insert(proposal_id, proposal);

        Self::save_state(db, &state)?;

        let log = Self::create_proposal_created_event(
            proposal_id,
            caller,
            ProposalType::Upgrade,
            B256::from(description_hash),
            block_number + VOTING_DELAY,
            block_number + VOTING_DELAY + VOTING_PERIOD,
        );

        debug!(
            proposal_id = proposal_id,
            activation_height = activation_height,
            "Upgrade proposal created"
        );

        let output = abi::encode_u256(U256::from(proposal_id));

        Ok(PrecompileOutput::with_logs(
            Bytes::copy_from_slice(&output),
            GAS_PROPOSE,
            vec![log],
        ))
    }

    /// Vote on a proposal
    fn vote<DB: Database>(
        caller: Address,
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Decode: proposalId (uint256), support (uint8)
        let proposal_id = abi::decode_u64(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected proposal ID".into()))?;

        let support_u8 = abi::decode_u8(data, 32)
            .ok_or_else(|| PrecompileError::InvalidInput("expected support value".into()))?;

        let support = VoteSupport::try_from(support_u8)?;

        debug!(
            voter = %caller,
            proposal_id = proposal_id,
            support = ?support,
            "Processing vote"
        );

        let mut state = Self::load_state(db)?;

        // Get proposal
        let proposal = state
            .proposals
            .get_mut(&proposal_id)
            .ok_or(PrecompileError::ProposalNotFound(proposal_id))?;

        // Check voting is active
        if block_number < proposal.voting_start || block_number > proposal.voting_end {
            return Err(PrecompileError::VotingNotActive);
        }

        // Check hasn't already voted
        if state.votes.contains_key(&(proposal_id, caller)) {
            return Err(PrecompileError::AlreadyVoted);
        }

        // Get voting power
        let voting_power = Self::get_voting_power(db, caller)?;
        if voting_power == 0 {
            return Err(PrecompileError::InsufficientVotingPower {
                required: U256::from(1),
                available: U256::ZERO,
            });
        }

        // Record vote
        match support {
            VoteSupport::Against => proposal.against_votes += voting_power,
            VoteSupport::For => proposal.for_votes += voting_power,
            VoteSupport::Abstain => proposal.abstain_votes += voting_power,
        }

        state.votes.insert(
            (proposal_id, caller),
            VoteRecord {
                support,
                weight: voting_power,
            },
        );

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_vote_cast_event(proposal_id, caller, support, voting_power);

        debug!(
            voter = %caller,
            proposal_id = proposal_id,
            weight = voting_power,
            "Vote recorded"
        );

        Ok(PrecompileOutput::with_logs(Bytes::new(), GAS_VOTE, vec![log]))
    }

    /// Execute a passed proposal
    fn execute_proposal<DB: Database>(
        data: &[u8],
        block_number: u64,
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let proposal_id = abi::decode_u64(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected proposal ID".into()))?;

        info!(proposal_id = proposal_id, "Executing proposal");

        let mut state = Self::load_state(db)?;

        // First, check proposal state without mutable borrow
        let (proposal_state, executed, data_clone) = {
            let proposal = state
                .proposals
                .get(&proposal_id)
                .ok_or(PrecompileError::ProposalNotFound(proposal_id))?;

            let ps = Self::get_proposal_state(proposal, block_number, &state);
            (ps, proposal.executed, proposal.data.clone())
        };

        if proposal_state != ProposalState::Succeeded {
            return Err(PrecompileError::ProposalNotSucceeded);
        }

        if executed {
            return Err(PrecompileError::ProposalAlreadyExecuted);
        }

        // Execute based on proposal type
        match &data_clone {
            ProposalData::ParameterChange { key, value: _ } => {
                debug!(
                    key = %key,
                    "Executing parameter change"
                );
                // In a real implementation, this would update the parameter in storage
            }
            ProposalData::Upgrade {
                activation_height,
                code_hash,
            } => {
                debug!(
                    activation_height = activation_height,
                    code_hash = %code_hash,
                    "Scheduling upgrade"
                );
                // In a real implementation, this would schedule the upgrade
            }
            ProposalData::Treasury { recipient, amount } => {
                debug!(
                    recipient = %recipient,
                    amount = amount,
                    "Executing treasury transfer"
                );
                // In a real implementation, this would transfer from treasury
                if state.treasury_balance < *amount {
                    return Err(PrecompileError::InvalidInput(
                        "insufficient treasury balance".into(),
                    ));
                }
                state.treasury_balance -= *amount;
            }
            ProposalData::Text { .. } => {
                debug!("Text proposal executed (no-op)");
                // Text proposals don't have executable actions
            }
        }

        // Mark proposal as executed
        if let Some(proposal) = state.proposals.get_mut(&proposal_id) {
            proposal.executed = true;
        }

        Self::save_state(db, &state)?;

        // Create event log
        let log = Self::create_proposal_executed_event(proposal_id);

        info!(proposal_id = proposal_id, "Proposal executed");

        Ok(PrecompileOutput::with_logs(Bytes::new(), GAS_EXECUTE, vec![log]))
    }

    /// Get proposal details (view function)
    fn get_proposal<DB: Database>(
        data: &[u8],
        db: &mut StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        let proposal_id = abi::decode_u64(data, 0)
            .ok_or_else(|| PrecompileError::InvalidInput("expected proposal ID".into()))?;

        let state = Self::load_state(db)?;

        let proposal = state
            .proposals
            .get(&proposal_id)
            .ok_or(PrecompileError::ProposalNotFound(proposal_id))?;

        // ABI encode response:
        // - proposer (address)
        // - proposalType (uint8)
        // - votingStart (uint256)
        // - votingEnd (uint256)
        // - forVotes (uint256)
        // - againstVotes (uint256)
        // - abstainVotes (uint256)
        // - executed (bool)
        // - canceled (bool)
        let mut output = Vec::new();
        output.extend_from_slice(&abi::encode_address(proposal.proposer));
        output.extend_from_slice(&abi::encode_u8(proposal.proposal_type as u8));
        output.extend_from_slice(&abi::encode_u256(U256::from(proposal.voting_start)));
        output.extend_from_slice(&abi::encode_u256(U256::from(proposal.voting_end)));
        output.extend_from_slice(&abi::encode_u256(U256::from(proposal.for_votes)));
        output.extend_from_slice(&abi::encode_u256(U256::from(proposal.against_votes)));
        output.extend_from_slice(&abi::encode_u256(U256::from(proposal.abstain_votes)));
        output.extend_from_slice(&abi::encode_bool(proposal.executed));
        output.extend_from_slice(&abi::encode_bool(proposal.canceled));

        Ok(PrecompileOutput::new(Bytes::from(output), GAS_GET_PROPOSAL))
    }

    /// Calculate proposal state
    fn get_proposal_state(
        proposal: &Proposal,
        current_height: u64,
        state: &GovernanceState,
    ) -> ProposalState {
        if proposal.canceled {
            return ProposalState::Canceled;
        }
        if proposal.executed {
            return ProposalState::Executed;
        }
        if current_height < proposal.voting_start {
            return ProposalState::Pending;
        }
        if current_height <= proposal.voting_end {
            return ProposalState::Active;
        }

        // Voting ended, check results
        let total_votes =
            proposal.for_votes + proposal.against_votes + proposal.abstain_votes;
        let quorum = (QUORUM_PERCENTAGE as u128) * state.total_stake / 100;

        if total_votes < quorum {
            return ProposalState::Defeated; // Quorum not met
        }

        // Calculate pass threshold (for votes must be > 50% of for + against)
        let total_voting = proposal.for_votes + proposal.against_votes;
        if total_voting == 0 {
            return ProposalState::Defeated;
        }

        let pass_threshold = (PASS_THRESHOLD as u128) * total_voting / 100;
        if proposal.for_votes >= pass_threshold {
            ProposalState::Succeeded
        } else {
            ProposalState::Defeated
        }
    }

    /// Get voting power for an address
    fn get_voting_power<DB: Database>(
        _db: &StateAdapter<DB>,
        _account: Address,
    ) -> Result<u128, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would read from staking state
        // Voting power = own stake + delegations received
        Ok(100_000 * 10u128.pow(18)) // Placeholder: 100,000 MCN
    }

    /// Load governance state from storage
    fn load_state<DB: Database>(
        _db: &StateAdapter<DB>,
    ) -> Result<GovernanceState, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would read from the state trie
        Ok(GovernanceState {
            total_stake: 1_000_000 * 10u128.pow(18), // Placeholder: 1M MCN total stake
            treasury_balance: 10_000_000 * 10u128.pow(18), // Placeholder: 10M MCN treasury
            ..Default::default()
        })
    }

    /// Save governance state to storage
    fn save_state<DB: Database>(
        _db: &mut StateAdapter<DB>,
        _state: &GovernanceState,
    ) -> Result<(), PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // In a real implementation, this would write to the state trie
        Ok(())
    }

    /// Create ProposalCreated event log
    fn create_proposal_created_event(
        proposal_id: u64,
        proposer: Address,
        proposal_type: ProposalType,
        description_hash: B256,
        voting_start: u64,
        voting_end: u64,
    ) -> revm::primitives::Log {
        let event_sig =
            keccak256(b"ProposalCreated(uint256,address,uint8,bytes32,uint256,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[24..32].copy_from_slice(&proposal_id.to_be_bytes());

        let mut topic2 = [0u8; 32];
        topic2[12..32].copy_from_slice(proposer.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
            B256::from(topic2),
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u8(proposal_type as u8));
        data.extend_from_slice(&description_hash.0);
        data.extend_from_slice(&abi::encode_u256(U256::from(voting_start)));
        data.extend_from_slice(&abi::encode_u256(U256::from(voting_end)));

        revm::primitives::Log::new_unchecked(
            GOVERNANCE_ADDRESS,
            topics,
            Bytes::from(data),
        )
    }

    /// Create VoteCast event log
    fn create_vote_cast_event(
        proposal_id: u64,
        voter: Address,
        support: VoteSupport,
        weight: u128,
    ) -> revm::primitives::Log {
        let event_sig = keccak256(b"VoteCast(uint256,address,uint8,uint256)");

        let mut topic1 = [0u8; 32];
        topic1[24..32].copy_from_slice(&proposal_id.to_be_bytes());

        let mut topic2 = [0u8; 32];
        topic2[12..32].copy_from_slice(voter.as_slice());

        let topics = vec![
            B256::from(event_sig),
            B256::from(topic1),
            B256::from(topic2),
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&abi::encode_u8(support as u8));
        data.extend_from_slice(&abi::encode_u256(U256::from(weight)));

        revm::primitives::Log::new_unchecked(
            GOVERNANCE_ADDRESS,
            topics,
            Bytes::from(data),
        )
    }

    /// Create ProposalExecuted event log
    fn create_proposal_executed_event(proposal_id: u64) -> revm::primitives::Log {
        let event_sig = keccak256(b"ProposalExecuted(uint256)");

        let mut topic1 = [0u8; 32];
        topic1[24..32].copy_from_slice(&proposal_id.to_be_bytes());

        let topics = vec![B256::from(event_sig), B256::from(topic1)];

        revm::primitives::Log::new_unchecked(GOVERNANCE_ADDRESS, topics, Bytes::new())
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
