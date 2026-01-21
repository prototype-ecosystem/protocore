//! Main configuration module for Proto Core
//!
//! This module implements the single-config philosophy where all chain settings
//! are defined in one `protocore.toml` file.

use crate::error::{ConfigError, ConfigResult};
use crate::genesis::GenesisConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Main configuration struct containing all Proto Core settings.
///
/// Loaded from a single `protocore.toml` file following Proto Core's
/// single-config philosophy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Chain identity configuration
    pub chain: ChainConfig,

    /// Consensus parameters
    pub consensus: ConsensusConfig,

    /// Economic parameters
    pub economics: EconomicsConfig,

    /// Staking parameters
    pub staking: StakingConfig,

    /// Slashing parameters
    pub slashing: SlashingConfig,

    /// Governance parameters
    pub governance: GovernanceConfig,

    /// Privacy features configuration
    pub privacy: PrivacyConfig,

    /// P2P network configuration
    pub network: NetworkConfig,

    /// RPC server configuration
    pub rpc: RpcConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Metrics/telemetry configuration
    pub metrics: MetricsConfig,

    /// Genesis configuration (accounts and validators)
    pub genesis: GenesisConfig,

    /// Inverse rewards configuration (optional)
    /// When enabled, rewards smaller validators proportionally more than larger ones
    #[serde(default)]
    pub inverse_rewards: Option<InverseRewardsConfig>,

    /// Binary integrity and tamper prevention configuration (optional)
    #[serde(default)]
    pub integrity: Option<IntegrityConfig>,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    ///
    /// The parsed and validated configuration, or an error if loading fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use protocore_config::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::load(Path::new("protocore.toml"))?;
    /// ```
    pub fn load(path: &Path) -> ConfigResult<Self> {
        info!("Loading configuration from {:?}", path);

        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        let config: Config = toml::from_str(&content)?;

        debug!("Configuration parsed successfully, validating...");
        config.validate()?;

        info!(
            "Configuration loaded: chain_id={}, chain_name={}",
            config.chain.chain_id, config.chain.chain_name
        );

        Ok(config)
    }

    /// Load configuration from a TOML string.
    ///
    /// Useful for testing or when configuration is provided as a string.
    pub fn from_str(content: &str) -> ConfigResult<Self> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    ///
    /// Checks that all values are within acceptable ranges and that
    /// the configuration is internally consistent.
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate chain config
        self.chain.validate()?;

        // Validate consensus config
        self.consensus.validate()?;

        // Validate economics config
        self.economics.validate()?;

        // Validate staking config
        self.staking.validate()?;

        // Validate slashing config
        self.slashing.validate()?;

        // Validate governance config
        self.governance.validate()?;

        // Validate network config
        self.network.validate()?;

        // Validate RPC config
        self.rpc.validate()?;

        // Validate storage config
        self.storage.validate()?;

        // Validate logging config
        self.logging.validate()?;

        // Validate genesis config
        self.genesis.validate(&self.staking)?;

        // Validate inverse rewards config if present
        if let Some(ref inverse_rewards) = self.inverse_rewards {
            inverse_rewards.validate()?;
        }

        // Validate integrity config if present
        if let Some(ref integrity) = self.integrity {
            integrity.validate()?;
        }

        debug!("Configuration validation passed");
        Ok(())
    }

    /// Save configuration to a TOML file.
    pub fn save(&self, path: &Path) -> ConfigResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::GenesisBlockGeneration(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| ConfigError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

// =============================================================================
// Chain Configuration
// =============================================================================

/// Chain identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique chain identifier
    pub chain_id: u64,

    /// Human-readable chain name
    pub chain_name: String,

    /// Native token name
    pub token_name: String,

    /// Native token symbol
    pub token_symbol: String,

    /// Token decimal places (max 18)
    pub token_decimals: u8,

    /// Total supply at genesis (in smallest unit, as string for large numbers)
    pub total_supply: String,
}

impl ChainConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.chain_id == 0 {
            return Err(ConfigError::InvalidChainId);
        }

        if self.token_decimals > 18 {
            return Err(ConfigError::InvalidTokenDecimals(self.token_decimals));
        }

        // Validate total_supply is a valid number
        if self.total_supply.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.total_supply.clone()));
        }

        Ok(())
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            chain_name: "Proto Core Local".to_string(),
            token_name: "MicroCoin".to_string(),
            token_symbol: "MCN".to_string(),
            token_decimals: 18,
            total_supply: "1000000000000000000000000000".to_string(), // 1 billion with 18 decimals
        }
    }
}

// =============================================================================
// Consensus Configuration
// =============================================================================

/// Consensus parameters for Tendermint-style BFT consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Target block time in milliseconds
    pub block_time_ms: u64,

    /// Blocks per epoch (validator set changes at epoch boundaries)
    pub blocks_per_epoch: u64,

    /// Maximum number of active validators
    pub max_validators: u32,

    /// Base timeout for propose phase (milliseconds)
    pub propose_timeout_base: u64,

    /// Timeout increment per round for propose phase (milliseconds)
    pub propose_timeout_delta: u64,

    /// Base timeout for prevote phase (milliseconds)
    pub prevote_timeout_base: u64,

    /// Timeout increment per round for prevote phase (milliseconds)
    pub prevote_timeout_delta: u64,

    /// Base timeout for precommit phase (milliseconds)
    pub precommit_timeout_base: u64,

    /// Timeout increment per round for precommit phase (milliseconds)
    pub precommit_timeout_delta: u64,

    /// Proposer selection configuration
    #[serde(default)]
    pub proposer: ProposerConfig,
}

/// Proposer selection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposerConfig {
    /// Selection mechanism
    pub selection: ProposerSelection,

    /// Timeout for proposer to produce block (milliseconds)
    pub propose_timeout_ms: u64,

    /// Maximum backup proposers to try before giving up
    pub max_backup_attempts: u32,

    /// Timeout multiplier for backup proposers (e.g., 0.5 = half the time)
    pub backup_timeout_multiplier: f64,
}

/// Proposer selection mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposerSelection {
    /// Shuffled round-robin (default, recommended)
    /// Combines fairness with unpredictability
    #[default]
    ShuffledRoundRobin,
    /// Pure round-robin (predictable, like ARK)
    RoundRobin,
}

impl Default for ProposerConfig {
    fn default() -> Self {
        Self {
            selection: ProposerSelection::ShuffledRoundRobin,
            propose_timeout_ms: 2000,
            max_backup_attempts: 3,
            backup_timeout_multiplier: 0.5,
        }
    }
}

impl ConsensusConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.block_time_ms < 100 {
            return Err(ConfigError::InvalidBlockTime(self.block_time_ms));
        }

        if self.max_validators < 4 {
            return Err(ConfigError::TooFewValidators(self.max_validators));
        }

        // Validate timeouts
        if self.propose_timeout_base == 0 {
            return Err(ConfigError::InvalidTimeout {
                name: "propose_timeout_base",
                value: 0,
            });
        }

        if self.prevote_timeout_base == 0 {
            return Err(ConfigError::InvalidTimeout {
                name: "prevote_timeout_base",
                value: 0,
            });
        }

        if self.precommit_timeout_base == 0 {
            return Err(ConfigError::InvalidTimeout {
                name: "precommit_timeout_base",
                value: 0,
            });
        }

        Ok(())
    }

    /// Calculate the propose timeout for a given round.
    pub fn propose_timeout(&self, round: u32) -> u64 {
        self.propose_timeout_base + self.propose_timeout_delta * round as u64
    }

    /// Calculate the prevote timeout for a given round.
    pub fn prevote_timeout(&self, round: u32) -> u64 {
        self.prevote_timeout_base + self.prevote_timeout_delta * round as u64
    }

    /// Calculate the precommit timeout for a given round.
    pub fn precommit_timeout(&self, round: u32) -> u64 {
        self.precommit_timeout_base + self.precommit_timeout_delta * round as u64
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 2000,
            blocks_per_epoch: 43200, // ~24 hours at 2s blocks
            max_validators: 51,
            propose_timeout_base: 1000,
            propose_timeout_delta: 500,
            prevote_timeout_base: 1000,
            prevote_timeout_delta: 500,
            precommit_timeout_base: 1000,
            precommit_timeout_delta: 500,
            proposer: ProposerConfig::default(),
        }
    }
}

// =============================================================================
// Economics Configuration
// =============================================================================

/// Economic parameters (fees, rewards, inflation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfig {
    /// Block reward in wei (as string for large numbers)
    pub block_reward: String,

    /// Annual inflation rate in basis points (500 = 5%)
    pub inflation_rate: u16,

    /// Minimum base fee per gas in wei (as string)
    pub min_base_fee: String,

    /// Base fee elasticity multiplier (EIP-1559)
    pub base_fee_elasticity: u8,

    /// Maximum base fee change per block in basis points (125 = 12.5%)
    pub base_fee_max_change: u16,

    /// Block gas limit
    pub block_gas_limit: u64,
}

impl EconomicsConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.block_gas_limit < 21000 {
            return Err(ConfigError::InvalidGasLimit(self.block_gas_limit));
        }

        // Validate block_reward is a valid number
        if self.block_reward.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.block_reward.clone()));
        }

        // Validate min_base_fee is a valid number
        if self.min_base_fee.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.min_base_fee.clone()));
        }

        Ok(())
    }
}

impl Default for EconomicsConfig {
    fn default() -> Self {
        Self {
            block_reward: "2000000000000000000".to_string(), // 2 MCN
            inflation_rate: 500,                             // 5%
            min_base_fee: "1000000000".to_string(),          // 1 gwei
            base_fee_elasticity: 2,
            base_fee_max_change: 125, // 12.5%
            block_gas_limit: 30_000_000,
        }
    }
}

// =============================================================================
// Staking Configuration
// =============================================================================

/// Staking parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake to become a validator (in wei, as string)
    pub min_validator_stake: String,

    /// Minimum delegation amount (in wei, as string)
    pub min_delegation: String,

    /// Unbonding period in blocks
    pub unbonding_period_blocks: u64,

    /// Maximum commission rate in basis points (5000 = 50%)
    pub max_commission: u16,

    /// Maximum commission change per epoch in basis points
    pub max_commission_change: u16,
}

impl StakingConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.min_validator_stake == "0" || self.min_validator_stake.is_empty() {
            return Err(ConfigError::InvalidMinStake);
        }

        // Validate stake values are valid numbers
        if self.min_validator_stake.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(
                self.min_validator_stake.clone(),
            ));
        }

        if self.min_delegation.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.min_delegation.clone()));
        }

        if self.max_commission > 10000 {
            return Err(ConfigError::InvalidBasisPoints {
                name: "max_commission",
                value: self.max_commission,
            });
        }

        Ok(())
    }

    /// Get minimum validator stake as u128.
    pub fn min_validator_stake_u128(&self) -> u128 {
        self.min_validator_stake.parse().unwrap_or(0)
    }
}

impl Default for StakingConfig {
    fn default() -> Self {
        Self {
            min_validator_stake: "100000000000000000000000".to_string(), // 100,000 MCN
            min_delegation: "1000000000000000000".to_string(),           // 1 MCN
            unbonding_period_blocks: 302400,                             // ~7 days at 2s blocks
            max_commission: 5000,                                        // 50%
            max_commission_change: 100,                                  // 1%
        }
    }
}

// =============================================================================
// Slashing Configuration
// =============================================================================

/// Slashing parameters for validator misbehavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Percentage of stake slashed for double signing
    pub double_sign_slash_percent: u8,

    /// Percentage of stake slashed per 24h of downtime
    pub downtime_slash_percent: f64,

    /// Consecutive missed blocks threshold for downtime
    pub downtime_threshold: u64,

    /// Jail duration in blocks (for non-permanent offenses)
    pub jail_duration: u64,
}

impl SlashingConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.double_sign_slash_percent > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "double_sign_slash_percent",
                value: self.double_sign_slash_percent,
            });
        }
        Ok(())
    }
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_sign_slash_percent: 5,
            downtime_slash_percent: 0.1,
            downtime_threshold: 43200, // ~24 hours at 2s blocks
            jail_duration: 43200,
        }
    }
}

// =============================================================================
// Governance Configuration
// =============================================================================

/// Governance parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum stake to create a proposal (in wei, as string)
    pub proposal_threshold: String,

    /// Proposal deposit required (returned if passed, in wei, as string)
    pub proposal_deposit: String,

    /// Voting delay in blocks (after proposal creation)
    pub voting_delay: u64,

    /// Voting period in blocks
    pub voting_period: u64,

    /// Quorum percentage of total stake required
    pub quorum_percentage: u8,

    /// Pass threshold percentage of votes cast
    pub pass_threshold: u8,
}

impl GovernanceConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.quorum_percentage == 0 || self.quorum_percentage > 100 {
            return Err(ConfigError::InvalidQuorum(self.quorum_percentage));
        }

        if self.pass_threshold == 0 || self.pass_threshold > 100 {
            return Err(ConfigError::InvalidThreshold(self.pass_threshold));
        }

        // Validate deposit values
        if self.proposal_threshold.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.proposal_threshold.clone()));
        }

        if self.proposal_deposit.parse::<u128>().is_err() {
            return Err(ConfigError::InvalidBalance(self.proposal_deposit.clone()));
        }

        Ok(())
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            proposal_threshold: "10000000000000000000000".to_string(), // 10,000 MCN
            proposal_deposit: "1000000000000000000000".to_string(),    // 1,000 MCN
            voting_delay: 100,
            voting_period: 21600, // ~12 hours at 2s blocks
            quorum_percentage: 33,
            pass_threshold: 50,
        }
    }
}

// =============================================================================
// Privacy Configuration
// =============================================================================

/// Privacy features configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Enable stealth addresses
    pub stealth_addresses_enabled: bool,

    /// Enable confidential transactions
    pub confidential_tx_enabled: bool,

    /// Default transaction type
    #[serde(default = "default_tx_type")]
    pub default_tx_type: TransactionType,
}

fn default_tx_type() -> TransactionType {
    TransactionType::Transparent
}

/// Transaction privacy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    /// Fully transparent transaction
    Transparent,
    /// Uses stealth address for recipient
    Stealth,
    /// Uses confidential amounts
    Confidential,
    /// Full privacy (stealth + confidential)
    Private,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            stealth_addresses_enabled: true,
            confidential_tx_enabled: false,
            default_tx_type: TransactionType::Transparent,
        }
    }
}

// =============================================================================
// Network Configuration
// =============================================================================

/// P2P network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P listen address (multiaddr format)
    pub listen_address: String,

    /// External address for NAT traversal (optional)
    #[serde(default)]
    pub external_address: Option<String>,

    /// Maximum peer connections
    pub max_peers: u32,

    /// Bootstrap nodes
    #[serde(default)]
    pub boot_nodes: Vec<String>,
}

impl NetworkConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        // Basic validation of listen address format
        if self.listen_address.is_empty() {
            return Err(ConfigError::InvalidMultiaddr(
                "listen_address cannot be empty".to_string(),
            ));
        }

        // Validate multiaddr format (basic check)
        if !self.listen_address.starts_with("/ip4/") && !self.listen_address.starts_with("/ip6/") {
            return Err(ConfigError::InvalidMultiaddr(format!(
                "listen_address must start with /ip4/ or /ip6/: {}",
                self.listen_address
            )));
        }

        Ok(())
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_address: "/ip4/0.0.0.0/tcp/30303".to_string(),
            external_address: None,
            max_peers: 50,
            boot_nodes: Vec::new(),
        }
    }
}

// =============================================================================
// RPC Configuration
// =============================================================================

/// RPC server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// HTTP RPC listen address
    pub http_address: String,

    /// WebSocket RPC listen address
    pub ws_address: String,

    /// Maximum batch request size
    pub max_batch_size: u32,

    /// Rate limit (requests per second per IP)
    pub rate_limit: u32,

    /// CORS allowed origins
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// Enabled RPC methods (empty = all enabled)
    #[serde(default)]
    pub enabled_methods: Vec<String>,

    /// Disabled RPC methods
    #[serde(default)]
    pub disabled_methods: Vec<String>,
}

impl RpcConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        // Validate socket addresses (basic format check)
        if self.http_address.is_empty() {
            return Err(ConfigError::InvalidSocketAddr(
                "http_address cannot be empty".to_string(),
            ));
        }

        if self.ws_address.is_empty() {
            return Err(ConfigError::InvalidSocketAddr(
                "ws_address cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if a method is enabled.
    pub fn is_method_enabled(&self, method: &str) -> bool {
        // If disabled_methods contains the method, it's disabled
        if self.disabled_methods.contains(&method.to_string()) {
            return false;
        }

        // If enabled_methods is empty, all methods are enabled
        // Otherwise, only methods in enabled_methods are enabled
        if self.enabled_methods.is_empty() {
            true
        } else {
            self.enabled_methods.contains(&method.to_string())
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_address: "0.0.0.0:8545".to_string(),
            ws_address: "0.0.0.0:8546".to_string(),
            max_batch_size: 100,
            rate_limit: 100,
            cors_origins: vec!["*".to_string()],
            enabled_methods: Vec::new(),
            disabled_methods: Vec::new(),
        }
    }
}

// =============================================================================
// Storage Configuration
// =============================================================================

/// Storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory path
    pub data_dir: String,

    /// State pruning (blocks to keep, 0 = archive mode)
    pub state_pruning: u64,

    /// Enable state snapshots
    pub snapshots_enabled: bool,

    /// Snapshot interval in blocks
    pub snapshot_interval: u64,

    /// Cache size in megabytes
    #[serde(default = "default_cache_size")]
    pub cache_size_mb: u64,
}

fn default_cache_size() -> u64 {
    256
}

impl StorageConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.data_dir.is_empty() {
            return Err(ConfigError::MissingField("storage.data_dir"));
        }
        Ok(())
    }

    /// Check if running in archive mode (no pruning).
    pub fn is_archive_mode(&self) -> bool {
        self.state_pruning == 0
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: "./data".to_string(),
            state_pruning: 0, // Archive mode by default
            snapshots_enabled: true,
            snapshot_interval: 10000,
            cache_size_mb: 256,
        }
    }
}

// =============================================================================
// Logging Configuration
// =============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Log format (json, pretty)
    pub format: String,

    /// Log file path (optional)
    #[serde(default)]
    pub file: Option<String>,

    /// Maximum log file size in MB
    #[serde(default = "default_log_size")]
    pub max_size_mb: u64,

    /// Maximum number of log files to keep
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

fn default_log_size() -> u64 {
    100
}

fn default_max_files() -> u32 {
    10
}

impl LoggingConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.level.to_lowercase().as_str()) {
            return Err(ConfigError::InvalidLogLevel(self.level.clone()));
        }

        let valid_formats = ["json", "pretty"];
        if !valid_formats.contains(&self.format.to_lowercase().as_str()) {
            return Err(ConfigError::InvalidLogFormat(self.format.clone()));
        }

        Ok(())
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            file: Some("./logs/protocore.log".to_string()),
            max_size_mb: 100,
            max_files: 10,
        }
    }
}

// =============================================================================
// Metrics/Telemetry Configuration
// =============================================================================

/// Prometheus metrics configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    pub enabled: bool,

    /// Metrics endpoint address
    pub address: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "0.0.0.0:9090".to_string(),
        }
    }
}

// =============================================================================
// Inverse Rewards Configuration
// =============================================================================

use alloy_primitives::U256;

/// Inverse rewards configuration.
///
/// This optional module rewards smaller validators proportionally more than larger ones,
/// promoting decentralization without enabling Sybil attacks through multi-factor
/// anti-Sybil design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseRewardsConfig {
    /// Whether inverse rewards are enabled
    pub enabled: bool,

    /// Fixed bond required to become a validator (primary Sybil defense)
    /// Higher = more Sybil resistant, but higher barrier to entry
    #[serde(
        deserialize_with = "deserialize_u256",
        serialize_with = "serialize_u256"
    )]
    pub validator_bond: U256,

    /// Minimum stake on top of bond to prevent spam registrations
    #[serde(
        deserialize_with = "deserialize_u256",
        serialize_with = "serialize_u256"
    )]
    pub minimum_stake: U256,

    /// Reward distribution weights
    pub weights: RewardWeights,

    /// Anti-Sybil parameters
    pub sybil_resistance: SybilResistanceConfig,
}

/// Custom deserializer for U256 from string
fn deserialize_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
}

/// Custom serializer for U256 to string
fn serialize_u256<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

impl InverseRewardsConfig {
    /// Validate the inverse rewards configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        self.weights.validate()?;
        Ok(())
    }
}

impl Default for InverseRewardsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // 10,000 MICRO tokens (assuming 18 decimals)
            validator_bond: U256::from_str_radix("10000000000000000000000", 10).unwrap(),
            // 1,000 MICRO tokens
            minimum_stake: U256::from_str_radix("1000000000000000000000", 10).unwrap(),
            weights: RewardWeights::default(),
            sybil_resistance: SybilResistanceConfig::default(),
        }
    }
}

/// Reward distribution weights.
///
/// These weights determine how rewards are distributed among validators.
/// All weights must sum to 1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardWeights {
    /// Base reward: Equal share for all active validators
    /// Higher = more egalitarian, but less stake incentive
    pub base: f64,

    /// Stake reward: Quadratic (sqrt(stake)) scaling
    /// Higher = more stake matters, but still diminishing returns
    pub stake: f64,

    /// Participation reward: Based on actual validator work
    /// Higher = rewards reliability over wealth
    pub participation: f64,

    /// Loyalty reward: Time-based, cannot be faked
    /// Higher = rewards long-term commitment
    pub loyalty: f64,
}

impl RewardWeights {
    /// Validate that weights sum to 1.0.
    pub fn validate(&self) -> ConfigResult<()> {
        let sum = self.base + self.stake + self.participation + self.loyalty;
        // Allow small floating point tolerance
        if (sum - 1.0).abs() > 0.0001 {
            return Err(ConfigError::InvalidRewardWeights(sum));
        }
        Ok(())
    }
}

impl Default for RewardWeights {
    fn default() -> Self {
        Self {
            base: 0.10,
            stake: 0.30,
            participation: 0.40,
            loyalty: 0.20,
        }
    }
}

/// Anti-Sybil parameters for the inverse rewards system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilResistanceConfig {
    /// Maximum validators allowed (prevents validator spam)
    pub max_validators: u32,

    /// Months until full loyalty bonus
    /// Longer = more Sybil resistant, but slower bootstrap
    pub loyalty_maturity_months: u32,

    /// Cooldown after unregistering before can re-register
    /// Prevents reset-and-restart attacks
    pub re_registration_cooldown_days: u32,

    /// Days before penalty takes effect (appeal window)
    pub appeal_grace_period_days: u32,

    /// Ban duration after confirmed Sybil attack
    pub sybil_ban_duration_days: u32,

    /// Where penalized rewards go
    /// - Burn: Deflationary, tokens destroyed (simplest)
    /// - Treasury: Sent to DAO treasury for community use
    /// - Redistribute: Split among honest validators
    #[serde(default)]
    pub penalty_destination: PenaltyDestination,

    /// Tiered penalty caps based on confidence level
    pub penalties: SybilPenalties,

    /// Signal weights for confidence scoring
    pub signals: SybilSignalWeights,
}

/// Where penalized rewards are directed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PenaltyDestination {
    /// Burn the penalized rewards (deflationary, simplest)
    #[default]
    Burn,
    /// Send to DAO treasury for community governance
    Treasury,
    /// Redistribute to honest validators proportionally
    Redistribute,
}

impl Default for SybilResistanceConfig {
    fn default() -> Self {
        Self {
            max_validators: 100,
            loyalty_maturity_months: 24,
            re_registration_cooldown_days: 90,
            appeal_grace_period_days: 7,
            sybil_ban_duration_days: 365,
            penalty_destination: PenaltyDestination::default(),
            penalties: SybilPenalties::default(),
            signals: SybilSignalWeights::default(),
        }
    }
}

/// Tiered penalty caps based on Sybil confidence level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilPenalties {
    /// Penalty cap for medium confidence (2+ signals)
    pub penalty_cap_medium: f64,

    /// Penalty cap for high confidence (3.5+ signals)
    pub penalty_cap_high: f64,

    /// Penalty cap for confirmed Sybil (5+ signals or governance flagged)
    pub penalty_cap_confirmed: f64,
}

impl Default for SybilPenalties {
    fn default() -> Self {
        Self {
            penalty_cap_medium: 0.80,
            penalty_cap_high: 0.95,
            penalty_cap_confirmed: 0.99,
        }
    }
}

/// Signal weights for Sybil confidence scoring.
///
/// These weights are used to calculate the confidence level that a set of
/// validators are controlled by the same entity (Sybil attack).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilSignalWeights {
    /// Weight for controversial vote correlation (strong signal, low false positive risk)
    pub weight_controversial_vote_correlation: f64,

    /// Weight for same withdrawal address (strong signal, auto-confirms if matched)
    pub weight_same_withdrawal_address: f64,

    /// Weight for same IP subnet (medium signal)
    pub weight_same_ip_subnet: f64,

    /// Weight for vote timing correlation (medium signal)
    pub weight_vote_timing_correlation: f64,

    /// Weight for same registration epoch (weak signal, high false positive risk)
    pub weight_same_registration_epoch: f64,

    /// Weight for identical stake amount (weak signal, high false positive risk)
    pub weight_identical_stake_amount: f64,

    /// Threshold for controversial vote correlation to trigger signal (e.g., 0.80 = 80%+ correlation)
    pub controversial_vote_threshold: f64,

    /// Threshold for vote timing correlation in milliseconds (votes within this window)
    pub vote_timing_threshold_ms: u64,
}

impl Default for SybilSignalWeights {
    fn default() -> Self {
        Self {
            weight_controversial_vote_correlation: 2.0,
            weight_same_withdrawal_address: 3.0,
            weight_same_ip_subnet: 1.0,
            weight_vote_timing_correlation: 1.5,
            weight_same_registration_epoch: 0.5,
            weight_identical_stake_amount: 0.3,
            controversial_vote_threshold: 0.80,
            vote_timing_threshold_ms: 50,
        }
    }
}

// =============================================================================
// Integrity Configuration
// =============================================================================

/// Binary integrity and tamper prevention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityConfig {
    /// Verify binary on startup
    pub verify_on_startup: bool,

    /// Allow skipping verification (development only)
    pub allow_skip: bool,

    /// Attestation configuration
    pub attestation: AttestationConfig,

    /// Slashing configuration for misbehavior
    pub slashing: IntegritySlashingConfig,

    /// Upgrade governance configuration
    pub upgrades: UpgradeConfig,
}

impl IntegrityConfig {
    /// Validate the integrity configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        self.attestation.validate()?;
        self.slashing.validate()?;
        self.upgrades.validate()?;
        Ok(())
    }
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            verify_on_startup: true,
            allow_skip: false,
            attestation: AttestationConfig::default(),
            slashing: IntegritySlashingConfig::default(),
            upgrades: UpgradeConfig::default(),
        }
    }
}

/// Attestation configuration for runtime integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Enable runtime attestation
    pub enabled: bool,

    /// Challenge interval in seconds
    pub challenge_interval_secs: u64,

    /// Timeout for attestation response in seconds
    pub response_timeout_secs: u64,

    /// Action on failure
    pub failure_action: FailureAction,

    /// Consecutive failures before jail
    pub jail_threshold: u32,
}

impl AttestationConfig {
    /// Validate the attestation configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.challenge_interval_secs == 0 {
            return Err(ConfigError::InvalidTimeout {
                name: "challenge_interval_secs",
                value: 0,
            });
        }

        if self.response_timeout_secs == 0 {
            return Err(ConfigError::InvalidTimeout {
                name: "response_timeout_secs",
                value: 0,
            });
        }

        Ok(())
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            challenge_interval_secs: 300, // 5 minutes
            response_timeout_secs: 30,
            failure_action: FailureAction::ReduceScore,
            jail_threshold: 3,
        }
    }
}

/// Action to take on attestation failure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureAction {
    /// Log the failure only
    Log,
    /// Reduce the validator's score
    ReduceScore,
    /// Jail the validator
    Jail,
}

impl Default for FailureAction {
    fn default() -> Self {
        Self::ReduceScore
    }
}

/// Slashing configuration for integrity-related misbehavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegritySlashingConfig {
    /// Double proposal/vote slash percent
    pub double_sign_slash_percent: u8,

    /// Double sign ban type
    pub double_sign_ban: BanType,

    /// Invalid block slash percent
    pub invalid_block_slash_percent: u8,

    /// Invalid block jail days
    pub invalid_block_jail_days: u32,

    /// Censorship slash percent
    pub censorship_slash_percent: u8,

    /// Censorship jail days
    pub censorship_jail_days: u32,

    /// Reward for submitting evidence (% of slashed)
    pub evidence_reward_percent: u8,
}

impl IntegritySlashingConfig {
    /// Validate the integrity slashing configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.double_sign_slash_percent > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "double_sign_slash_percent",
                value: self.double_sign_slash_percent,
            });
        }

        if self.invalid_block_slash_percent > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "invalid_block_slash_percent",
                value: self.invalid_block_slash_percent,
            });
        }

        if self.censorship_slash_percent > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "censorship_slash_percent",
                value: self.censorship_slash_percent,
            });
        }

        if self.evidence_reward_percent > 100 {
            return Err(ConfigError::InvalidPercentage {
                name: "evidence_reward_percent",
                value: self.evidence_reward_percent,
            });
        }

        Ok(())
    }
}

impl Default for IntegritySlashingConfig {
    fn default() -> Self {
        Self {
            double_sign_slash_percent: 5,
            double_sign_ban: BanType::Permanent,
            invalid_block_slash_percent: 10,
            invalid_block_jail_days: 7,
            censorship_slash_percent: 2,
            censorship_jail_days: 3,
            evidence_reward_percent: 10,
        }
    }
}

/// Ban type for serious offenses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BanType {
    /// Permanent ban from the network
    Permanent,
    /// Temporary ban with possibility of return
    Temporary,
}

impl Default for BanType {
    fn default() -> Self {
        Self::Permanent
    }
}

/// Upgrade governance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeConfig {
    /// Minimum signatures on release
    pub required_signatures: u8,

    /// Minimum delay before activation (blocks)
    pub min_activation_delay_blocks: u64,

    /// Approval threshold (0.0 - 1.0)
    pub approval_threshold: f64,
}

impl UpgradeConfig {
    /// Validate the upgrade configuration.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.required_signatures == 0 {
            return Err(ConfigError::InvalidRequiredSignatures(0));
        }

        if !(0.0..=1.0).contains(&self.approval_threshold) {
            return Err(ConfigError::InvalidApprovalThreshold(
                self.approval_threshold,
            ));
        }

        Ok(())
    }
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            required_signatures: 3,
            min_activation_delay_blocks: 43200, // ~24 hours at 2s blocks
            approval_threshold: 0.67,           // 2/3 majority
        }
    }
}

// =============================================================================
// Mempool Configuration (convenience alias)
// =============================================================================

/// Mempool configuration.
///
/// This is derived from other config sections but provided as a convenience.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in mempool
    pub max_size: usize,

    /// Maximum transaction size in bytes
    pub max_tx_size: usize,

    /// Transaction time-to-live in seconds
    pub ttl_seconds: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_tx_size: 128 * 1024, // 128 KB
            ttl_seconds: 3600,       // 1 hour
        }
    }
}
