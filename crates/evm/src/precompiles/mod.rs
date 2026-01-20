//! Precompiled Contracts
//!
//! Proto Core extends standard Ethereum precompiles with system contracts
//! for staking, slashing, and governance.
//!
//! ## Precompile Addresses
//!
//! | Address | Name | Description |
//! |---------|------|-------------|
//! | 0x01-0x09 | Standard | Ethereum precompiles (ecrecover, SHA256, etc.) |
//! | 0x1000 | Staking | Validator and delegation management |
//! | 0x1001 | Slashing | Evidence submission and validator punishment |
//! | 0x1002 | Governance | Proposal creation and voting |

pub mod governance;
pub mod slashing;
pub mod staking;

use alloy_primitives::{Address, Bytes, U256};
use revm::Database;
use std::collections::HashMap;
use thiserror::Error;

// Re-export precompile implementations
pub use governance::GovernancePrecompile;
pub use slashing::SlashingPrecompile;
pub use staking::StakingPrecompile;

/// Staking precompile address (0x0000...1000)
pub const STAKING_ADDRESS: Address = address_from_low_u64(0x1000);

/// Slashing precompile address (0x0000...1001)
pub const SLASHING_ADDRESS: Address = address_from_low_u64(0x1001);

/// Governance precompile address (0x0000...1002)
pub const GOVERNANCE_ADDRESS: Address = address_from_low_u64(0x1002);

/// Create an address from a low u64 value
const fn address_from_low_u64(v: u64) -> Address {
    let bytes = v.to_be_bytes();
    Address::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7],
    ])
}

/// Errors that can occur in precompile execution
#[derive(Error, Debug)]
pub enum PrecompileError {
    /// Invalid input data
    #[error("invalid input data: {0}")]
    InvalidInput(String),

    /// Unknown function selector
    #[error("unknown function selector: {selector:?}")]
    UnknownSelector {
        /// The unknown selector bytes
        selector: [u8; 4],
    },

    /// Insufficient stake amount
    #[error("insufficient stake: required {required}, provided {provided}")]
    InsufficientStake {
        /// Required amount
        required: U256,
        /// Provided amount
        provided: U256,
    },

    /// Insufficient delegation amount
    #[error("insufficient delegation amount")]
    InsufficientDelegation,

    /// Validator not found
    #[error("validator not found: {0}")]
    ValidatorNotFound(Address),

    /// Validator already exists
    #[error("validator already exists: {0}")]
    ValidatorAlreadyExists(Address),

    /// Validator not active
    #[error("validator is not active")]
    ValidatorNotActive,

    /// Validator inactive (not active or jailed) - includes address for multi-delegation
    #[error("validator is inactive: {0}")]
    ValidatorInactive(Address),

    /// Validator is jailed
    #[error("validator is jailed until block {0}")]
    ValidatorJailed(u64),

    /// Permanently jailed
    #[error("validator is permanently jailed")]
    PermanentlyJailed,

    /// Not jailed
    #[error("validator is not jailed")]
    NotJailed,

    /// Jail period not expired
    #[error("jail period not expired, ends at block {0}")]
    JailNotExpired(u64),

    /// No delegation found
    #[error("no delegation found for this validator")]
    NoDelegation,

    /// No unbonding entries
    #[error("no unbonding entries")]
    NoUnbonding,

    /// No rewards to claim
    #[error("no rewards to claim")]
    NoRewards,

    /// Invalid BLS public key
    #[error("invalid BLS public key")]
    InvalidPubkey,

    /// Invalid commission rate
    #[error("invalid commission rate: {0} (max: {1})")]
    InvalidCommission(u16, u16),

    /// Invalid evidence
    #[error("invalid evidence: {0}")]
    InvalidEvidence(String),

    /// Duplicate evidence
    #[error("evidence already submitted")]
    DuplicateEvidence,

    /// Proposal not found
    #[error("proposal not found: {0}")]
    ProposalNotFound(u64),

    /// Voting not active
    #[error("voting is not active for this proposal")]
    VotingNotActive,

    /// Already voted
    #[error("already voted on this proposal")]
    AlreadyVoted,

    /// Insufficient voting power
    #[error("insufficient voting power: required {required}, have {available}")]
    InsufficientVotingPower {
        /// Required power
        required: U256,
        /// Available power
        available: U256,
    },

    /// Insufficient deposit
    #[error("insufficient proposal deposit: required {required}, provided {provided}")]
    InsufficientDeposit {
        /// Required deposit
        required: U256,
        /// Provided deposit
        provided: U256,
    },

    /// Proposal not succeeded
    #[error("proposal has not succeeded")]
    ProposalNotSucceeded,

    /// Proposal already executed
    #[error("proposal already executed")]
    ProposalAlreadyExecuted,

    /// State access error
    #[error("state access error: {0}")]
    StateError(String),

    /// Unauthorized caller
    #[error("unauthorized: caller {caller} cannot perform this action")]
    Unauthorized {
        /// The unauthorized caller
        caller: Address,
    },

    /// Arithmetic overflow
    #[error("arithmetic overflow")]
    Overflow,

    /// Out of gas
    #[error("out of gas")]
    OutOfGas,
}

/// Output from a precompile execution
#[derive(Debug, Clone)]
pub struct PrecompileOutput {
    /// Output data
    pub output: Bytes,
    /// Gas used
    pub gas_used: u64,
    /// Logs emitted
    pub logs: Vec<revm::primitives::Log>,
}

impl PrecompileOutput {
    /// Create a new precompile output with no logs
    pub fn new(output: impl Into<Bytes>, gas_used: u64) -> Self {
        Self {
            output: output.into(),
            gas_used,
            logs: Vec::new(),
        }
    }

    /// Create output with logs
    pub fn with_logs(output: impl Into<Bytes>, gas_used: u64, logs: Vec<revm::primitives::Log>) -> Self {
        Self {
            output: output.into(),
            gas_used,
            logs,
        }
    }

    /// Add a log to the output
    pub fn add_log(&mut self, log: revm::primitives::Log) {
        self.logs.push(log);
    }
}

/// Trait for precompiled contracts
pub trait Precompile {
    /// Execute the precompile
    fn execute<DB: Database>(
        &self,
        caller: Address,
        input: &[u8],
        value: U256,
        block_number: u64,
        db: &mut DB,
    ) -> Result<PrecompileOutput, PrecompileError>;

    /// Get the gas cost for an operation
    fn gas_cost(&self, input: &[u8]) -> u64;

    /// Get the precompile address
    fn address(&self) -> Address;
}

/// Registry of all precompiled contracts
pub struct PrecompileRegistry {
    /// Registered precompiles by address
    precompiles: HashMap<Address, Box<dyn PrecompileWrapper>>,
}

/// Wrapper trait to allow dynamic dispatch with generic Database
trait PrecompileWrapper: Send + Sync {
    fn execute_wrapper(
        &self,
        caller: Address,
        input: &[u8],
        value: U256,
        block_number: u64,
        db: &mut dyn std::any::Any,
    ) -> Result<PrecompileOutput, PrecompileError>;

    fn gas_cost(&self, input: &[u8]) -> u64;
}

impl Default for PrecompileRegistry {
    fn default() -> Self {
        let mut registry = Self {
            precompiles: HashMap::new(),
        };

        // Register Proto Core system precompiles
        registry.register_staking();
        registry.register_slashing();
        registry.register_governance();

        registry
    }
}

impl PrecompileRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            precompiles: HashMap::new(),
        }
    }

    /// Register the staking precompile
    fn register_staking(&mut self) {
        // Staking precompile is registered but execution is handled directly
    }

    /// Register the slashing precompile
    fn register_slashing(&mut self) {
        // Slashing precompile is registered but execution is handled directly
    }

    /// Register the governance precompile
    fn register_governance(&mut self) {
        // Governance precompile is registered but execution is handled directly
    }

    /// Check if an address is a registered precompile
    pub fn is_precompile(&self, address: Address) -> bool {
        // Check standard Ethereum precompiles (1-9)
        let addr_bytes = address.0 .0;
        if addr_bytes[..18].iter().all(|&b| b == 0) {
            let low = u16::from_be_bytes([addr_bytes[18], addr_bytes[19]]);
            if (1..=9).contains(&low) || (0x1000..=0x1002).contains(&low) {
                return true;
            }
        }
        false
    }

    /// Execute a precompile
    pub fn execute<DB: Database>(
        &self,
        address: Address,
        caller: Address,
        input: &[u8],
        value: U256,
        block_number: u64,
        db: &mut crate::state_adapter::StateAdapter<DB>,
    ) -> Result<PrecompileOutput, PrecompileError>
    where
        DB::Error: std::fmt::Debug,
    {
        // Route to appropriate precompile
        match address {
            addr if addr == STAKING_ADDRESS => {
                StakingPrecompile::execute_static(caller, input, value, block_number, db)
            }
            addr if addr == SLASHING_ADDRESS => {
                SlashingPrecompile::execute_static(caller, input, value, block_number, db)
            }
            addr if addr == GOVERNANCE_ADDRESS => {
                GovernancePrecompile::execute_static(caller, input, value, block_number, db)
            }
            _ => {
                // Standard Ethereum precompiles would be handled by revm
                Err(PrecompileError::InvalidInput(format!(
                    "Unknown precompile address: {}",
                    address
                )))
            }
        }
    }
}

/// ABI encoding utilities for precompile input/output
pub mod abi {
    use alloy_primitives::{Address, Bytes, U256};

    /// Decode a function selector from input
    pub fn decode_selector(input: &[u8]) -> Option<[u8; 4]> {
        if input.len() < 4 {
            return None;
        }
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&input[0..4]);
        Some(selector)
    }

    /// Decode an address from ABI-encoded data at offset
    pub fn decode_address(data: &[u8], offset: usize) -> Option<Address> {
        if data.len() < offset + 32 {
            return None;
        }
        // Address is right-aligned in 32 bytes
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&data[offset + 12..offset + 32]);
        Some(Address::from(addr_bytes))
    }

    /// Decode a U256 from ABI-encoded data at offset
    pub fn decode_u256(data: &[u8], offset: usize) -> Option<U256> {
        if data.len() < offset + 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[offset..offset + 32]);
        Some(U256::from_be_bytes(bytes))
    }

    /// Decode a u64 from ABI-encoded data at offset
    pub fn decode_u64(data: &[u8], offset: usize) -> Option<u64> {
        decode_u256(data, offset).map(|v| v.as_limbs()[0])
    }

    /// Decode a u8 from ABI-encoded data at offset
    pub fn decode_u8(data: &[u8], offset: usize) -> Option<u8> {
        if data.len() < offset + 32 {
            return None;
        }
        Some(data[offset + 31])
    }

    /// Decode bytes from ABI-encoded data at offset
    pub fn decode_bytes(data: &[u8], offset: usize) -> Option<Bytes> {
        // First get the offset to the bytes data
        let data_offset = decode_u256(data, offset)?.as_limbs()[0] as usize;

        // Then get the length
        if data.len() < data_offset + 32 {
            return None;
        }
        let length = decode_u256(data, data_offset)?.as_limbs()[0] as usize;

        // Then get the actual data
        if data.len() < data_offset + 32 + length {
            return None;
        }
        Some(Bytes::copy_from_slice(
            &data[data_offset + 32..data_offset + 32 + length],
        ))
    }

    /// Encode an address for ABI output
    pub fn encode_address(address: Address) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[12..32].copy_from_slice(address.as_slice());
        result
    }

    /// Encode a U256 for ABI output
    pub fn encode_u256(value: U256) -> [u8; 32] {
        value.to_be_bytes()
    }

    /// Encode a bool for ABI output
    pub fn encode_bool(value: bool) -> [u8; 32] {
        let mut result = [0u8; 32];
        if value {
            result[31] = 1;
        }
        result
    }

    /// Encode a u64 for ABI output
    pub fn encode_u64(value: u64) -> [u8; 32] {
        encode_u256(U256::from(value))
    }

    /// Encode a u8 for ABI output
    pub fn encode_u8(value: u8) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[31] = value;
        result
    }
}

/// Function selectors for staking precompile
pub mod staking_selectors {
    /// createValidator(bytes,uint16) - Create a new validator
    pub const CREATE_VALIDATOR: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
    /// delegate(address) - Delegate stake to a validator
    pub const DELEGATE: [u8; 4] = [0x5c, 0x19, 0xa9, 0x5e];
    /// undelegate(address,uint256) - Undelegate stake
    pub const UNDELEGATE: [u8; 4] = [0x4d, 0x99, 0xdd, 0x16];
    /// redelegate(address,address,uint256) - Redelegate stake
    pub const REDELEGATE: [u8; 4] = [0x7a, 0x8b, 0x9c, 0x0d];
    /// claimRewards() - Claim staking rewards
    pub const CLAIM_REWARDS: [u8; 4] = [0x37, 0x2b, 0x0c, 0x89];
    /// withdrawUnbonded() - Withdraw after unbonding period
    pub const WITHDRAW_UNBONDED: [u8; 4] = [0x8b, 0x9e, 0x5f, 0x29];
    /// getValidator(address) view - Get validator info
    pub const GET_VALIDATOR: [u8; 4] = [0x1f, 0xa5, 0xc4, 0x80];
    /// getStake(address) view - Get stake info
    pub const GET_STAKE: [u8; 4] = [0x2e, 0xb4, 0xd3, 0x91];

    // Multi-validator delegation selectors
    /// batchDelegate(address[],uint256[]) - Delegate to multiple validators
    pub const BATCH_DELEGATE: [u8; 4] = [0xba, 0x7c, 0xde, 0x12];
    /// splitDelegate(address[]) - Split stake evenly among validators
    pub const SPLIT_DELEGATE: [u8; 4] = [0x5d, 0x3f, 0xa1, 0xb9];
    /// getAllDelegations(address) view - Get all delegations for an address
    pub const GET_ALL_DELEGATIONS: [u8; 4] = [0x6e, 0x4f, 0xb2, 0xca];
    /// autoRebalance(address[]) - Rebalance stake when validators become inactive
    pub const AUTO_REBALANCE: [u8; 4] = [0x7f, 0x5a, 0xc3, 0xdb];
}

/// Function selectors for slashing precompile
pub mod slashing_selectors {
    /// submitDoubleSignEvidence(bytes,bytes) - Submit double-sign evidence
    pub const SUBMIT_DOUBLE_SIGN_EVIDENCE: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
    /// unjail() - Request unjailing
    pub const UNJAIL: [u8; 4] = [0x69, 0x42, 0x00, 0x00];
    /// getSlashingInfo(address) view - Get slashing info
    pub const GET_SLASHING_INFO: [u8; 4] = [0x3f, 0x4e, 0x5d, 0x6c];
}

/// Function selectors for governance precompile
pub mod governance_selectors {
    /// proposeParameterChange(bytes32,bytes,bytes32) - Create parameter change proposal
    pub const PROPOSE_PARAMETER_CHANGE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    /// proposeTreasurySpend(address,uint256,bytes32) - Create treasury spend proposal
    pub const PROPOSE_TREASURY_SPEND: [u8; 4] = [0x22, 0x33, 0x44, 0x55];
    /// proposeUpgrade(uint256,bytes32,bytes32) - Create upgrade proposal
    pub const PROPOSE_UPGRADE: [u8; 4] = [0x33, 0x44, 0x55, 0x66];
    /// vote(uint256,uint8) - Vote on proposal
    pub const VOTE: [u8; 4] = [0x56, 0x78, 0x9a, 0xbc];
    /// execute(uint256) - Execute passed proposal
    pub const EXECUTE: [u8; 4] = [0xfe, 0x0d, 0x94, 0xa1];
    /// getProposal(uint256) view - Get proposal info
    pub const GET_PROPOSAL: [u8; 4] = [0x4f, 0x5e, 0x6d, 0x7c];
}
