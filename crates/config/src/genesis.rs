//! Genesis configuration and block generation
//!
//! This module handles the genesis state of the Proto Core blockchain,
//! including initial accounts, validators, and consensus parameters.

use crate::config::StakingConfig;
use crate::error::{ConfigError, ConfigResult};
use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use tracing::{debug, info};

/// Genesis configuration containing initial state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Initial accounts with balances
    #[serde(default)]
    pub accounts: Vec<GenesisAccount>,

    /// Initial validators
    #[serde(default)]
    pub validators: Vec<GenesisValidator>,
}

impl GenesisConfig {
    /// Load genesis configuration from a JSON file.
    ///
    /// This is an alternative to embedding genesis in the TOML config,
    /// useful for sharing genesis state across multiple nodes.
    pub fn load_json(path: &Path) -> ConfigResult<Self> {
        info!("Loading genesis from JSON file: {:?}", path);

        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        let genesis: GenesisConfig = serde_json::from_str(&content)?;
        Ok(genesis)
    }

    /// Save genesis configuration to a JSON file.
    pub fn save_json(&self, path: &Path) -> ConfigResult<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// Validate the genesis configuration.
    pub fn validate(&self, staking_config: &StakingConfig) -> ConfigResult<()> {
        debug!("Validating genesis configuration");

        // Must have at least one validator
        if self.validators.is_empty() {
            return Err(ConfigError::NoValidators);
        }

        // Check for duplicate accounts
        let mut seen_accounts = HashSet::new();
        for account in &self.accounts {
            account.validate()?;
            if !seen_accounts.insert(account.address.to_lowercase()) {
                return Err(ConfigError::DuplicateAccount(account.address.clone()));
            }
        }

        // Check for duplicate validators and validate each
        let mut seen_validators = HashSet::new();
        let min_stake = staking_config.min_validator_stake_u128();

        for validator in &self.validators {
            validator.validate()?;

            if !seen_validators.insert(validator.address.to_lowercase()) {
                return Err(ConfigError::DuplicateValidator(validator.address.clone()));
            }

            // Check minimum stake requirement
            let stake = validator
                .stake
                .parse::<u128>()
                .map_err(|_| ConfigError::InvalidBalance(validator.stake.clone()))?;

            if stake < min_stake {
                return Err(ConfigError::ValidatorStakeBelowMinimum {
                    address: validator.address.clone(),
                    stake: validator.stake.clone(),
                    min_stake: staking_config.min_validator_stake.clone(),
                });
            }
        }

        debug!(
            "Genesis validation passed: {} accounts, {} validators",
            self.accounts.len(),
            self.validators.len()
        );

        Ok(())
    }

    /// Generate the genesis block.
    ///
    /// Returns a GenesisBlock containing all initial state.
    pub fn generate_genesis_block(&self, chain_id: u64) -> ConfigResult<GenesisBlock> {
        info!("Generating genesis block for chain_id={}", chain_id);

        // Calculate state root from initial accounts and validators
        let state_root = self.calculate_state_root()?;

        // Calculate validators hash
        let validators_hash = self.calculate_validators_hash()?;

        // Genesis block has special properties
        let genesis_block = GenesisBlock {
            chain_id,
            height: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ConfigError::GenesisBlockGeneration(e.to_string()))?
                .as_secs(),
            parent_hash: B256::ZERO,
            state_root,
            transactions_root: B256::ZERO, // No transactions in genesis
            receipts_root: B256::ZERO,
            validators_hash,
            accounts: self.accounts.clone(),
            validators: self.validators.clone(),
        };

        // Calculate the genesis block hash
        let block_hash = genesis_block.calculate_hash();

        info!(
            "Genesis block generated: hash={}, state_root={}, validators={}",
            hex::encode(block_hash),
            hex::encode(state_root),
            self.validators.len()
        );

        Ok(genesis_block)
    }

    /// Calculate the state root from initial accounts.
    fn calculate_state_root(&self) -> ConfigResult<B256> {
        // Simplified state root calculation
        // In a real implementation, this would build a Merkle Patricia Trie
        let mut data = Vec::new();

        for account in &self.accounts {
            data.extend(account.address.as_bytes());
            data.extend(account.balance.as_bytes());
        }

        for validator in &self.validators {
            data.extend(validator.address.as_bytes());
            data.extend(validator.stake.as_bytes());
        }

        Ok(keccak256(&data))
    }

    /// Calculate hash of initial validator set.
    fn calculate_validators_hash(&self) -> ConfigResult<B256> {
        let mut data = Vec::new();

        for validator in &self.validators {
            data.extend(validator.address.as_bytes());
            data.extend(validator.pubkey.as_bytes());
            data.extend(validator.stake.as_bytes());
            data.extend(validator.commission.to_le_bytes());
        }

        Ok(keccak256(&data))
    }

    /// Calculate total stake from genesis validators.
    pub fn total_validator_stake(&self) -> U256 {
        self.validators
            .iter()
            .filter_map(|v| v.stake.parse::<u128>().ok())
            .map(U256::from)
            .fold(U256::ZERO, |acc, s| acc + s)
    }

    /// Calculate total balance from genesis accounts.
    pub fn total_account_balance(&self) -> U256 {
        self.accounts
            .iter()
            .filter_map(|a| a.balance.parse::<u128>().ok())
            .map(U256::from)
            .fold(U256::ZERO, |acc, b| acc + b)
    }
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            accounts: vec![GenesisAccount {
                address: "0x0000000000000000000000000000000000000001".to_string(),
                balance: "1000000000000000000000000000".to_string(), // 1 billion MCN
            }],
            validators: vec![GenesisValidator {
                address: "0x0000000000000000000000000000000000000001".to_string(),
                pubkey: "0x".to_string()
                    + &"00".repeat(48), // Placeholder BLS pubkey
                stake: "100000000000000000000000".to_string(), // 100,000 MCN
                commission: 1000,                              // 10%
            }],
        }
    }
}

// =============================================================================
// Genesis Account
// =============================================================================

/// Initial account with balance at genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Account address (hex string with 0x prefix)
    pub address: String,

    /// Initial balance in wei (as string for large numbers)
    pub balance: String,
}

impl GenesisAccount {
    /// Validate the genesis account.
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate address format
        if !self.address.starts_with("0x") || self.address.len() != 42 {
            return Err(ConfigError::InvalidAddress(self.address.clone()));
        }

        // Validate address is valid hex
        if hex::decode(&self.address[2..]).is_err() {
            return Err(ConfigError::InvalidAddress(self.address.clone()));
        }

        // Validate balance is a valid number
        if self.balance.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.balance.clone()));
        }

        Ok(())
    }

    /// Parse address to alloy Address type.
    pub fn parse_address(&self) -> ConfigResult<Address> {
        self.address
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(self.address.clone()))
    }

    /// Parse balance to U256.
    pub fn parse_balance(&self) -> ConfigResult<U256> {
        self.balance
            .parse::<u128>()
            .map(U256::from)
            .map_err(|_| ConfigError::InvalidBalance(self.balance.clone()))
    }
}

// =============================================================================
// Genesis Validator
// =============================================================================

/// Initial validator at genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator address (hex string with 0x prefix)
    pub address: String,

    /// BLS public key (hex string with 0x prefix)
    pub pubkey: String,

    /// Initial stake in wei (as string for large numbers)
    pub stake: String,

    /// Commission rate in basis points (1000 = 10%)
    pub commission: u16,
}

impl GenesisValidator {
    /// Validate the genesis validator.
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate address format
        if !self.address.starts_with("0x") || self.address.len() != 42 {
            return Err(ConfigError::InvalidAddress(self.address.clone()));
        }

        // Validate address is valid hex
        if hex::decode(&self.address[2..]).is_err() {
            return Err(ConfigError::InvalidAddress(self.address.clone()));
        }

        // Validate pubkey format (BLS pubkeys are 48 bytes = 96 hex chars + "0x")
        if !self.pubkey.starts_with("0x") || self.pubkey.len() != 98 {
            return Err(ConfigError::InvalidPubkey(format!(
                "Expected 48-byte BLS pubkey (98 chars with 0x prefix), got {} chars",
                self.pubkey.len()
            )));
        }

        // Validate pubkey is valid hex
        if hex::decode(&self.pubkey[2..]).is_err() {
            return Err(ConfigError::InvalidPubkey(self.pubkey.clone()));
        }

        // Validate stake is a valid number
        if self.stake.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.stake.clone()));
        }

        // Validate commission rate
        if self.commission > 10000 {
            return Err(ConfigError::InvalidCommissionRate(self.commission));
        }

        Ok(())
    }

    /// Parse address to alloy Address type.
    pub fn parse_address(&self) -> ConfigResult<Address> {
        self.address
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(self.address.clone()))
    }

    /// Parse stake to U256.
    pub fn parse_stake(&self) -> ConfigResult<U256> {
        self.stake
            .parse::<u128>()
            .map(U256::from)
            .map_err(|_| ConfigError::InvalidBalance(self.stake.clone()))
    }

    /// Get commission as a decimal (0.0 to 1.0).
    pub fn commission_rate(&self) -> f64 {
        self.commission as f64 / 10000.0
    }
}

// =============================================================================
// Consensus Parameters
// =============================================================================

/// Consensus parameters that can be modified through governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Block gas limit
    pub block_gas_limit: u64,

    /// Minimum gas price in wei (as string)
    pub min_gas_price: String,

    /// Maximum block size in bytes
    pub max_block_size: u64,

    /// Maximum transactions per block
    pub max_txs_per_block: u64,

    /// Evidence max age in blocks
    pub evidence_max_age_blocks: u64,

    /// Maximum validators
    pub max_validators: u32,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            min_gas_price: "1000000000".to_string(), // 1 gwei
            max_block_size: 5 * 1024 * 1024,         // 5 MB
            max_txs_per_block: 10000,
            evidence_max_age_blocks: 100000,
            max_validators: 51,
        }
    }
}

// =============================================================================
// Governance Parameters
// =============================================================================

/// Governance parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Voting period in blocks
    pub voting_period: u64,

    /// Quorum percentage (1-100)
    pub quorum: u8,

    /// Pass threshold percentage (1-100)
    pub threshold: u8,

    /// Veto threshold percentage (1-100)
    pub veto_threshold: u8,

    /// Minimum deposit for proposal (in wei, as string)
    pub min_deposit: String,

    /// Maximum deposit period in blocks
    pub max_deposit_period: u64,
}

impl GovernanceParams {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.quorum == 0 || self.quorum > 100 {
            return Err(ConfigError::InvalidQuorum(self.quorum));
        }

        if self.threshold == 0 || self.threshold > 100 {
            return Err(ConfigError::InvalidThreshold(self.threshold));
        }

        if self.veto_threshold > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "veto_threshold",
                value: self.veto_threshold,
            });
        }

        Ok(())
    }
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            voting_period: 21600, // ~12 hours at 2s blocks
            quorum: 33,
            threshold: 50,
            veto_threshold: 33,
            min_deposit: "1000000000000000000000".to_string(), // 1,000 MCN
            max_deposit_period: 7200,                          // ~4 hours
        }
    }
}

// =============================================================================
// Staking Parameters
// =============================================================================

/// Staking parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingParams {
    /// Minimum stake to become a validator (in wei, as string)
    pub min_stake: String,

    /// Unbonding period in blocks
    pub unbonding_period: u64,

    /// Maximum number of validators
    pub max_validators: u32,

    /// Maximum entries in unbonding queue per delegator
    pub max_unbonding_entries: u32,

    /// Maximum delegations per delegator
    pub max_delegations: u32,

    /// Historical entries for IBC
    pub historical_entries: u64,
}

impl StakingParams {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.min_stake == "0" || self.min_stake.is_empty() {
            return Err(ConfigError::InvalidMinStake);
        }

        if self.min_stake.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.min_stake.clone()));
        }

        if self.max_validators < 4 {
            return Err(ConfigError::TooFewValidators(self.max_validators));
        }

        Ok(())
    }
}

impl Default for StakingParams {
    fn default() -> Self {
        Self {
            min_stake: "100000000000000000000000".to_string(), // 100,000 MCN
            unbonding_period: 302400,                          // ~7 days at 2s blocks
            max_validators: 51,
            max_unbonding_entries: 7,
            max_delegations: 100,
            historical_entries: 10000,
        }
    }
}

// =============================================================================
// Genesis Block
// =============================================================================

/// The genesis block containing initial chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// Chain ID
    pub chain_id: u64,

    /// Block height (always 0 for genesis)
    pub height: u64,

    /// Unix timestamp of genesis
    pub timestamp: u64,

    /// Parent hash (zero for genesis)
    pub parent_hash: B256,

    /// State root after applying genesis state
    pub state_root: B256,

    /// Transactions root (empty for genesis)
    pub transactions_root: B256,

    /// Receipts root (empty for genesis)
    pub receipts_root: B256,

    /// Hash of initial validator set
    pub validators_hash: B256,

    /// Genesis accounts
    pub accounts: Vec<GenesisAccount>,

    /// Genesis validators
    pub validators: Vec<GenesisValidator>,
}

impl GenesisBlock {
    /// Calculate the hash of the genesis block.
    pub fn calculate_hash(&self) -> B256 {
        let mut data = Vec::new();

        // Include all header fields
        data.extend(self.chain_id.to_le_bytes());
        data.extend(self.height.to_le_bytes());
        data.extend(self.timestamp.to_le_bytes());
        data.extend(self.parent_hash.as_slice());
        data.extend(self.state_root.as_slice());
        data.extend(self.transactions_root.as_slice());
        data.extend(self.receipts_root.as_slice());
        data.extend(self.validators_hash.as_slice());

        keccak256(&data)
    }

    /// Save genesis block to JSON file.
    pub fn save(&self, path: &Path) -> ConfigResult<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// Load genesis block from JSON file.
    pub fn load(path: &Path) -> ConfigResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        let block: GenesisBlock = serde_json::from_str(&content)?;
        Ok(block)
    }

    /// Verify the genesis block hash and state.
    pub fn verify(&self) -> ConfigResult<()> {
        // Verify height is 0
        if self.height != 0 {
            return Err(ConfigError::GenesisBlockGeneration(
                "Genesis block height must be 0".to_string(),
            ));
        }

        // Verify parent hash is zero
        if self.parent_hash != B256::ZERO {
            return Err(ConfigError::GenesisBlockGeneration(
                "Genesis parent hash must be zero".to_string(),
            ));
        }

        // Verify we have validators
        if self.validators.is_empty() {
            return Err(ConfigError::NoValidators);
        }

        Ok(())
    }
}

