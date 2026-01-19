//! Shared utilities for CLI commands.
//!
//! This module provides common functionality used across CLI commands:
//! - Error types and result handling
//! - Output formatting
//! - RPC client for node communication
//! - Transaction signing utilities
//! - Display formatting helpers

use clap::ValueEnum;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// CLI error types
#[derive(Error, Debug)]
pub enum CliError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Invalid argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Key-related error
    #[error("Key error: {0}")]
    KeyError(String),

    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// User cancelled operation
    #[error("Operation cancelled by user")]
    Cancelled,

    /// Feature not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Dialoguer interaction error
    #[error("Input error: {0}")]
    DialoguerError(#[from] dialoguer::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// CLI result type alias
pub type CliResult<T> = Result<T, CliError>;

// ============================================================================
// Output Formatting
// ============================================================================

/// Output format options
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output for scripting
    Json,
}

/// Print an info message to stderr (so JSON output stays clean)
pub fn print_info(msg: &str) {
    use console::style;
    eprintln!("{} {}", style("[INFO]").cyan().bold(), msg);
}

/// Print a success message to stderr
pub fn print_success(msg: &str) {
    use console::style;
    eprintln!("{} {}", style("[OK]").green().bold(), msg);
}

/// Print a warning message to stderr
pub fn print_warning(msg: &str) {
    use console::style;
    eprintln!("{} {}", style("[WARN]").yellow().bold(), msg);
}

/// Print an error message to stderr
pub fn print_error(msg: &str) {
    use console::style;
    eprintln!("{} {}", style("[ERROR]").red().bold(), msg);
}

/// Print a debug message to stderr (only if verbose)
pub fn print_debug(msg: &str) {
    use console::style;
    if tracing::enabled!(tracing::Level::DEBUG) {
        eprintln!("{} {}", style("[DEBUG]").magenta(), msg);
    }
}

// ============================================================================
// Amount Parsing and Formatting
// ============================================================================

/// Parse an amount string with optional suffixes (k, m, b, etc.)
/// Returns the amount in base units (wei-equivalent)
pub fn parse_amount(s: &str) -> CliResult<u128> {
    let s = s.trim().to_lowercase();

    // Check for suffix
    let (num_part, multiplier) = if s.ends_with("eth") || s.ends_with("mct") {
        // Parse as whole tokens, multiply by 10^18
        (&s[..s.len()-3], 1_000_000_000_000_000_000u128)
    } else if s.ends_with('k') {
        (&s[..s.len()-1], 1_000u128)
    } else if s.ends_with('m') {
        (&s[..s.len()-1], 1_000_000u128)
    } else if s.ends_with('b') {
        (&s[..s.len()-1], 1_000_000_000u128)
    } else if s.ends_with('t') {
        (&s[..s.len()-1], 1_000_000_000_000u128)
    } else {
        (s.as_str(), 1u128)
    };

    // Handle decimal numbers for token amounts
    if num_part.contains('.') {
        let parts: Vec<&str> = num_part.split('.').collect();
        if parts.len() != 2 {
            return Err(CliError::InvalidArgument(format!("Invalid amount format: {}", s)));
        }

        let whole: u128 = parts[0].parse()
            .map_err(|_| CliError::InvalidArgument(format!("Invalid amount: {}", s)))?;

        let decimals = parts[1];
        let decimal_places = decimals.len();

        let frac: u128 = decimals.parse()
            .map_err(|_| CliError::InvalidArgument(format!("Invalid amount: {}", s)))?;

        // Calculate the fractional part relative to multiplier
        let frac_multiplier = multiplier / 10u128.pow(decimal_places as u32);
        let frac_value = frac * frac_multiplier;

        Ok(whole * multiplier + frac_value)
    } else {
        let value: u128 = num_part.parse()
            .map_err(|_| CliError::InvalidArgument(format!("Invalid amount: {}", s)))?;
        Ok(value * multiplier)
    }
}

/// Format a balance for display (converts from wei to tokens with decimals)
pub fn format_balance(wei: &str) -> String {
    let wei: u128 = match wei.parse() {
        Ok(v) => v,
        Err(_) => return wei.to_string(),
    };

    if wei == 0 {
        return "0 MCT".to_string();
    }

    let decimals = 18u32;
    let divisor = 10u128.pow(decimals);

    let whole = wei / divisor;
    let frac = wei % divisor;

    if frac == 0 {
        format!("{} MCT", format_with_commas(whole))
    } else {
        // Format fractional part, trimming trailing zeros
        let frac_str = format!("{:018}", frac);
        let frac_str = frac_str.trim_end_matches('0');
        // Show at most 6 decimal places
        let frac_display = if frac_str.len() > 6 {
            &frac_str[..6]
        } else {
            frac_str
        };
        format!("{}.{} MCT", format_with_commas(whole), frac_display)
    }
}

/// Format a number with thousand separators
pub fn format_with_commas(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format a timestamp for display
pub fn format_timestamp(timestamp: u64) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_opt(timestamp as i64, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        _ => timestamp.to_string(),
    }
}

/// Format a duration for display
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ============================================================================
// RPC Client
// ============================================================================

/// RPC client for communicating with a Proto Core node
pub struct RpcClient {
    endpoint: String,
    timeout: Duration,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(endpoint: &str) -> CliResult<Self> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Set the timeout for RPC calls
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Make an RPC call
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> CliResult<T> {
        // TODO: Implement actual HTTP JSON-RPC client
        // For now, return placeholder data for demonstration

        tracing::debug!("RPC call: {} with params: {}", method, params);

        Err(CliError::RpcError(format!(
            "RPC client not fully implemented. Method: {}, Endpoint: {}",
            method, self.endpoint
        )))
    }

    // -------------------------------------------------------------------------
    // Query methods
    // -------------------------------------------------------------------------

    /// Get block by number or tag
    pub async fn get_block(
        &self,
        block: crate::commands::query::BlockParam,
        full_txs: bool,
    ) -> CliResult<crate::commands::query::BlockInfo> {
        // Placeholder implementation
        Ok(crate::commands::query::BlockInfo {
            number: 12345,
            hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            parent_hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            proposer: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
            state_root: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            transactions_root: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            transactions: vec![],
        })
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, hash: &str) -> CliResult<crate::commands::query::TransactionInfo> {
        Ok(crate::commands::query::TransactionInfo {
            hash: hash.to_string(),
            status: true,
            block_number: 12345,
            transaction_index: 0,
            from: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
            to: Some("0x1234567890123456789012345678901234567890".to_string()),
            value: "1000000000000000000".to_string(),
            gas: 21000,
            gas_used: 21000,
            gas_price: 1_000_000_000,
            nonce: 0,
            input: "0x".to_string(),
        })
    }

    /// Get account information
    pub async fn get_account(&self, address: &str, block: &str) -> CliResult<crate::commands::query::AccountInfo> {
        Ok(crate::commands::query::AccountInfo {
            balance: "1000000000000000000000".to_string(),
            nonce: 5,
            code_hash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".to_string(),
            storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
            is_contract: false,
            code_size: 0,
        })
    }

    /// Get validators
    pub async fn get_validators(&self, active_only: bool) -> CliResult<Vec<crate::commands::query::ValidatorInfo>> {
        Ok(vec![
            crate::commands::query::ValidatorInfo {
                address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
                bls_public_key: "0xabcdef...".to_string(),
                stake: 100_000_000_000_000_000_000_000u128,
                commission_rate: 1000,
                active: true,
                jailed: false,
            },
        ])
    }

    /// Get chain status
    pub async fn get_status(&self) -> CliResult<crate::commands::query::ChainStatus> {
        Ok(crate::commands::query::ChainStatus {
            chain_id: 1,
            network_name: "mainnet".to_string(),
            block_height: 12345,
            latest_block_hash: "0x1234...".to_string(),
            latest_block_time: chrono::Utc::now().timestamp() as u64,
            peer_count: 25,
            syncing: false,
            sync_progress: 1.0,
            validator_count: 100,
            current_epoch: 100,
        })
    }

    /// Get pending transactions
    pub async fn get_pending_transactions(
        &self,
        limit: usize,
        from: Option<&str>,
    ) -> CliResult<crate::commands::query::PendingTransactions> {
        Ok(crate::commands::query::PendingTransactions {
            transactions: vec![],
            pending_count: 0,
            queued_count: 0,
        })
    }

    /// Get transaction receipt
    pub async fn get_receipt(&self, hash: &str) -> CliResult<crate::commands::query::TransactionReceipt> {
        Ok(crate::commands::query::TransactionReceipt {
            transaction_hash: hash.to_string(),
            status: true,
            block_number: 12345,
            block_hash: "0x1234...".to_string(),
            transaction_index: 0,
            from: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
            to: Some("0x1234567890123456789012345678901234567890".to_string()),
            contract_address: None,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            logs: vec![],
        })
    }

    /// Get contract code
    pub async fn get_code(&self, address: &str, block: &str) -> CliResult<crate::commands::query::CodeResponse> {
        Ok(crate::commands::query::CodeResponse {
            code: "0x".to_string(),
            size: 0,
        })
    }

    /// Get storage at slot
    pub async fn get_storage(&self, address: &str, slot: &str, block: &str) -> CliResult<String> {
        Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }

    // -------------------------------------------------------------------------
    // Staking methods
    // -------------------------------------------------------------------------

    /// Send stake transaction
    pub async fn send_stake_transaction(
        &self,
        signer: &TransactionSigner,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send unstake transaction
    pub async fn send_unstake_transaction(
        &self,
        signer: &TransactionSigner,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send delegate transaction
    pub async fn send_delegate_transaction(
        &self,
        signer: &TransactionSigner,
        validator: &str,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send undelegate transaction
    pub async fn send_undelegate_transaction(
        &self,
        signer: &TransactionSigner,
        validator: &str,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send redelegate transaction
    pub async fn send_redelegate_transaction(
        &self,
        signer: &TransactionSigner,
        from_validator: &str,
        to_validator: &str,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send withdraw transaction
    pub async fn send_withdraw_transaction(
        &self,
        signer: &TransactionSigner,
        validator: Option<&str>,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Get rewards
    pub async fn get_rewards(&self, address: &str) -> CliResult<crate::commands::staking::RewardsResponse> {
        Ok(crate::commands::staking::RewardsResponse {
            total: 1_000_000_000_000_000_000u128,
            by_validator: vec![],
        })
    }

    /// Get delegations
    pub async fn get_delegations(&self, address: &str) -> CliResult<crate::commands::staking::DelegationsResponse> {
        Ok(crate::commands::staking::DelegationsResponse {
            total_delegated: 0,
            total_unbonding: 0,
            delegations: vec![],
            unbonding: vec![],
        })
    }

    /// Send create validator transaction
    pub async fn send_create_validator_transaction(
        &self,
        signer: &TransactionSigner,
        info: crate::commands::staking::ValidatorCreateInfo,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send update validator transaction
    pub async fn send_update_validator_transaction(
        &self,
        signer: &TransactionSigner,
        info: crate::commands::staking::ValidatorUpdateInfo,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send unjail transaction
    pub async fn send_unjail_transaction(
        &self,
        signer: &TransactionSigner,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    // -------------------------------------------------------------------------
    // Governance methods
    // -------------------------------------------------------------------------

    /// Get proposal
    pub async fn get_proposal(&self, id: u64) -> CliResult<crate::commands::governance::ProposalInfo> {
        Ok(crate::commands::governance::ProposalInfo {
            id,
            proposal_type: "Text".to_string(),
            title: "Test Proposal".to_string(),
            description: "A test proposal description".to_string(),
            status: "VotingPeriod".to_string(),
            proposer: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
            total_deposit: 10_000_000_000_000_000_000_000u128,
            min_deposit: 10_000_000_000_000_000_000_000u128,
            submit_time: chrono::Utc::now().timestamp() as u64 - 86400,
            deposit_end_time: Some(chrono::Utc::now().timestamp() as u64 - 43200),
            voting_start_time: Some(chrono::Utc::now().timestamp() as u64 - 43200),
            voting_end_time: Some(chrono::Utc::now().timestamp() as u64 + 43200),
            yes_votes: 50_000_000_000_000_000_000_000u128,
            no_votes: 10_000_000_000_000_000_000_000u128,
            abstain_votes: 5_000_000_000_000_000_000_000u128,
            veto_votes: 1_000_000_000_000_000_000_000u128,
            yes_percentage: 75.76,
            no_percentage: 15.15,
            abstain_percentage: 7.58,
            veto_percentage: 1.52,
            turnout_percentage: 66.0,
            content: None,
        })
    }

    /// Get proposals list
    pub async fn get_proposals(
        &self,
        status: Option<&str>,
        proposer: Option<&str>,
        limit: usize,
    ) -> CliResult<Vec<crate::commands::governance::ProposalInfo>> {
        Ok(vec![])
    }

    /// Get proposal votes
    pub async fn get_proposal_votes(&self, id: u64) -> CliResult<Vec<crate::commands::governance::VoteEntry>> {
        Ok(vec![])
    }

    /// Get governance params
    pub async fn get_governance_params(&self) -> CliResult<crate::commands::governance::GovernanceParams> {
        Ok(crate::commands::governance::GovernanceParams {
            min_deposit: 10_000_000_000_000_000_000_000u128,
            deposit_period_blocks: 17280,
            voting_period_blocks: 17280,
            quorum_bps: 3400,
            threshold_bps: 5000,
            veto_threshold_bps: 3340,
            expedited_enabled: false,
            expedited_quorum_bps: 6700,
            expedited_threshold_bps: 6670,
        })
    }

    /// Get voting history
    pub async fn get_voting_history(
        &self,
        address: &str,
        limit: usize,
    ) -> CliResult<Vec<crate::commands::governance::VotingHistoryEntry>> {
        Ok(vec![])
    }

    /// Send proposal transaction
    pub async fn send_proposal_transaction(
        &self,
        signer: &TransactionSigner,
        proposal: crate::commands::governance::ProposalSubmission,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<(String, u64)> {
        Ok((format!("0x{}", hex::encode(&[0u8; 32])), 1))
    }

    /// Send vote transaction
    pub async fn send_vote_transaction(
        &self,
        signer: &TransactionSigner,
        proposal_id: u64,
        option: u8,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Send deposit transaction
    pub async fn send_deposit_transaction(
        &self,
        signer: &TransactionSigner,
        proposal_id: u64,
        amount: u128,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    // -------------------------------------------------------------------------
    // Integrity verification methods
    // -------------------------------------------------------------------------

    /// Verify binary integrity against on-chain signatures
    pub async fn verify_binary_integrity(
        &self,
        binary_hash: &str,
    ) -> CliResult<crate::commands::integrity::BinaryVerificationResult> {
        // Placeholder implementation - in production, this would query
        // the on-chain registry of authorized binary hashes and signatures
        Ok(crate::commands::integrity::BinaryVerificationResult {
            verified: true,
            valid_signatures: 3,
            required_signatures: 5,
            signers: vec![
                crate::commands::integrity::SignerInfo {
                    address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".to_string(),
                    name: "Core Team".to_string(),
                    valid: true,
                },
                crate::commands::integrity::SignerInfo {
                    address: "0x8ba1f109551bD432803012645Ac136ddd64DBA72".to_string(),
                    name: "Security Auditor".to_string(),
                    valid: true,
                },
                crate::commands::integrity::SignerInfo {
                    address: "0xaB5801a7D398351b8bE11C439e05C5B3259aeC9B".to_string(),
                    name: "Foundation".to_string(),
                    valid: true,
                },
            ],
        })
    }

    /// Get attestation status
    pub async fn get_attestation_status(&self) -> CliResult<crate::commands::integrity::AttestationStatus> {
        // Placeholder implementation
        Ok(crate::commands::integrity::AttestationStatus {
            last_attestation_time: chrono::Utc::now().timestamp() as u64 - 3600, // 1 hour ago
            binary_verified: true,
            next_challenge_seconds: 2700, // 45 minutes
            challenge_window_seconds: 3600,
            attestation_required: false,
        })
    }

    // -------------------------------------------------------------------------
    // Upgrade methods
    // -------------------------------------------------------------------------

    /// Get pending upgrade information
    pub async fn get_pending_upgrade(&self) -> CliResult<crate::commands::upgrade::UpgradeStatus> {
        // Placeholder implementation
        Ok(crate::commands::upgrade::UpgradeStatus {
            pending_upgrade: Some(crate::commands::upgrade::PendingUpgrade {
                proposal_id: 42,
                version: "v1.1.0".to_string(),
                activation_block: 1_234_567,
                current_block: 1_212_567,
                blocks_remaining: 22_000,
                approval_percentage: 78.0,
                threshold_percentage: 67.0,
                yes_votes: 78,
                no_votes: 22,
                total_validators: 100,
                your_vote: Some("yes".to_string()),
                binary_hash: "a7f3c2b1e9d8f4a2b6c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5".to_string(),
                changelog: vec![
                    "Improved consensus performance".to_string(),
                    "Added new RPC methods".to_string(),
                    "Security patches".to_string(),
                ],
            }),
            latest_upgrade: Some(crate::commands::upgrade::CompletedUpgrade {
                version: "v1.0.0".to_string(),
                activation_block: 1_000_000,
                final_approval: 85.0,
                status: "applied".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64 - 86400 * 30, // 30 days ago
            }),
        })
    }

    /// Send upgrade vote transaction
    pub async fn send_upgrade_vote_transaction(
        &self,
        signer: &TransactionSigner,
        proposal_id: u64,
        vote_yes: bool,
        gas: u64,
        gas_price: Option<u64>,
    ) -> CliResult<String> {
        Ok(format!("0x{}", hex::encode(&[0u8; 32])))
    }

    /// Get upgrade history
    pub async fn get_upgrade_history(
        &self,
        limit: usize,
    ) -> CliResult<Vec<crate::commands::upgrade::CompletedUpgrade>> {
        // Placeholder implementation
        Ok(vec![
            crate::commands::upgrade::CompletedUpgrade {
                version: "v1.0.0".to_string(),
                activation_block: 1_000_000,
                final_approval: 85.0,
                status: "applied".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64 - 86400 * 30,
            },
            crate::commands::upgrade::CompletedUpgrade {
                version: "v0.9.0".to_string(),
                activation_block: 500_000,
                final_approval: 92.0,
                status: "applied".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64 - 86400 * 90,
            },
        ])
    }
}

// ============================================================================
// Transaction Signer
// ============================================================================

/// Transaction signer for signing blockchain transactions
pub struct TransactionSigner {
    address: String,
    private_key: Vec<u8>,
}

impl TransactionSigner {
    /// Load a signer from keystore
    pub fn load(keystore_dir: &Path, key_identifier: &str) -> CliResult<Self> {
        // Find the key file
        let key_file = find_key_file(keystore_dir, key_identifier)?;

        // Load the key file
        let content = std::fs::read_to_string(&key_file)?;
        let key_data: serde_json::Value = serde_json::from_str(&content)?;

        let address = key_data["address"]
            .as_str()
            .ok_or_else(|| CliError::KeyError("Missing address in key file".to_string()))?
            .to_string();

        // Get private key (handle both encrypted and unencrypted)
        let private_key = if let Some(pk) = key_data["private_key"].as_str() {
            hex::decode(pk).map_err(|e| CliError::KeyError(format!("Invalid private key: {}", e)))?
        } else if key_data["crypto"].is_object() {
            // TODO: Prompt for password and decrypt
            return Err(CliError::NotImplemented("Encrypted key decryption".to_string()));
        } else {
            return Err(CliError::KeyError("No private key found in key file".to_string()));
        };

        Ok(Self { address, private_key })
    }

    /// Get the address of this signer
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> CliResult<Vec<u8>> {
        use protocore_crypto::ecdsa::PrivateKey;

        // Convert Vec<u8> to fixed-size array
        let key_array: [u8; 32] = self.private_key.as_slice().try_into()
            .map_err(|_| CliError::KeyError("Private key must be exactly 32 bytes".to_string()))?;

        let private_key = PrivateKey::from_bytes(&key_array)
            .map_err(|e| CliError::KeyError(format!("Invalid private key: {}", e)))?;

        let signature = private_key.sign_message(message)
            .map_err(|e| CliError::KeyError(format!("Signing failed: {}", e)))?;

        Ok(signature.to_bytes().to_vec())
    }
}

/// Find a key file by address or name
fn find_key_file(keystore_dir: &Path, identifier: &str) -> CliResult<PathBuf> {
    if !keystore_dir.exists() {
        return Err(CliError::FileNotFound(keystore_dir.to_string_lossy().to_string()));
    }

    let id_lower = identifier.to_lowercase();

    for entry in std::fs::read_dir(keystore_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "json") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(key_data) = serde_json::from_str::<serde_json::Value>(&content) {
                    let address = key_data["address"].as_str().unwrap_or("");
                    let name = key_data["name"].as_str().unwrap_or("");

                    if address.to_lowercase() == id_lower
                        || address.to_lowercase().contains(&id_lower)
                        || name.to_lowercase() == id_lower
                    {
                        return Ok(path);
                    }
                }
            }
        }
    }

    Err(CliError::KeyNotFound(identifier.to_string()))
}

// ============================================================================
// Progress Indicators
// ============================================================================

/// Create a spinner for long-running operations
pub fn create_spinner(message: &str) -> indicatif::ProgressBar {
    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner
}

/// Create a progress bar
pub fn create_progress_bar(total: u64, message: &str) -> indicatif::ProgressBar {
    let bar = indicatif::ProgressBar::new(total);
    bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("##-")
    );
    bar.set_message(message.to_string());
    bar
}

