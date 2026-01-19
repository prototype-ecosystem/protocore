//! Configuration error types

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during configuration loading and validation
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read configuration file
    #[error("Failed to read config file at {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse TOML configuration
    #[error("Failed to parse TOML config: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// Failed to parse JSON (genesis)
    #[error("Failed to parse JSON: {0}")]
    JsonParse(#[from] serde_json::Error),

    /// Invalid chain ID (must be non-zero)
    #[error("Invalid chain ID: chain_id must be non-zero")]
    InvalidChainId,

    /// Too few validators configured
    #[error("Too few validators: max_validators must be at least 4, got {0}")]
    TooFewValidators(u32),

    /// Invalid gas limit
    #[error("Invalid gas limit: block_gas_limit must be at least 21000 (minimum tx gas), got {0}")]
    InvalidGasLimit(u64),

    /// Invalid minimum stake
    #[error("Invalid minimum stake: min_validator_stake cannot be zero")]
    InvalidMinStake,

    /// Invalid token decimals
    #[error("Invalid token decimals: must be <= 18, got {0}")]
    InvalidTokenDecimals(u8),

    /// Invalid block time
    #[error("Invalid block time: must be at least 100ms, got {0}ms")]
    InvalidBlockTime(u64),

    /// Invalid timeout configuration
    #[error("Invalid timeout: {name} must be positive, got {value}ms")]
    InvalidTimeout { name: &'static str, value: u64 },

    /// Invalid commission rate
    #[error("Invalid commission rate: must be <= 10000 basis points (100%), got {0}")]
    InvalidCommissionRate(u16),

    /// Invalid percentage value
    #[error("Invalid {name}: must be <= 100, got {value}")]
    InvalidPercentage { name: &'static str, value: u8 },

    /// Invalid basis points value
    #[error("Invalid {name}: must be <= 10000 basis points, got {value}")]
    InvalidBasisPoints { name: &'static str, value: u16 },

    /// Invalid address format
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Invalid public key format
    #[error("Invalid public key format: {0}")]
    InvalidPubkey(String),

    /// Invalid balance string
    #[error("Invalid balance value: {0}")]
    InvalidBalance(String),

    /// Duplicate genesis account
    #[error("Duplicate genesis account: {0}")]
    DuplicateAccount(String),

    /// Duplicate genesis validator
    #[error("Duplicate genesis validator: {0}")]
    DuplicateValidator(String),

    /// No genesis validators configured
    #[error("No genesis validators configured: at least one validator required")]
    NoValidators,

    /// Genesis validator stake below minimum
    #[error("Genesis validator {address} has stake {stake} below minimum {min_stake}")]
    ValidatorStakeBelowMinimum {
        address: String,
        stake: String,
        min_stake: String,
    },

    /// Total genesis supply mismatch
    #[error("Genesis supply mismatch: total_supply={total_supply}, distributed={distributed}")]
    SupplyMismatch {
        total_supply: String,
        distributed: String,
    },

    /// Invalid quorum percentage
    #[error("Invalid quorum percentage: must be between 1 and 100, got {0}")]
    InvalidQuorum(u8),

    /// Invalid threshold percentage
    #[error("Invalid threshold percentage: must be between 1 and 100, got {0}")]
    InvalidThreshold(u8),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid multiaddr format
    #[error("Invalid multiaddr format: {0}")]
    InvalidMultiaddr(String),

    /// Invalid socket address format
    #[error("Invalid socket address format: {0}")]
    InvalidSocketAddr(String),

    /// Invalid log level
    #[error("Invalid log level: {0}. Valid values: trace, debug, info, warn, error")]
    InvalidLogLevel(String),

    /// Invalid log format
    #[error("Invalid log format: {0}. Valid values: json, pretty")]
    InvalidLogFormat(String),

    /// Invalid pruning mode
    #[error("Invalid pruning configuration")]
    InvalidPruningConfig,

    /// Genesis block generation failed
    #[error("Failed to generate genesis block: {0}")]
    GenesisBlockGeneration(String),

    /// Invalid reward weights - must sum to 1.0
    #[error("Invalid reward weights: must sum to 1.0, got {0}")]
    InvalidRewardWeights(f64),

    /// Invalid approval threshold - must be between 0 and 1
    #[error("Invalid approval threshold: must be between 0.0 and 1.0, got {0}")]
    InvalidApprovalThreshold(f64),

    /// Invalid required signatures - must be at least 1
    #[error("Invalid required signatures: must be at least 1, got {0}")]
    InvalidRequiredSignatures(u8),
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;
