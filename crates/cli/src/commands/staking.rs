//! Staking operations commands.
//!
//! This module provides commands for staking operations:
//! - Stake tokens to become a validator
//! - Unstake tokens with unbonding period
//! - Delegate tokens to existing validators
//! - Withdraw rewards
//! - Query staking information

use clap::{Parser, Subcommand};
use dialoguer::Confirm;
use std::path::PathBuf;

use crate::default_keystore_dir;
use crate::utils::{
    format_balance, parse_amount, print_info, print_success, print_warning, CliError, CliResult,
    OutputFormat, RpcClient, TransactionSigner,
};

/// Staking subcommands
#[derive(Subcommand, Debug)]
pub enum StakingCommands {
    /// Stake tokens (create validator or increase stake)
    Stake(StakeArgs),

    /// Unstake tokens (begin unbonding)
    Unstake(UnstakeArgs),

    /// Delegate tokens to a validator
    Delegate(DelegateArgs),

    /// Undelegate tokens from a validator
    Undelegate(UndelegateArgs),

    /// Redelegate tokens to a different validator
    Redelegate(RedelegateArgs),

    /// Withdraw accumulated rewards
    Withdraw(WithdrawArgs),

    /// Query staking rewards
    Rewards(RewardsArgs),

    /// Query delegations
    Delegations(DelegationsArgs),

    /// Create a new validator
    CreateValidator(CreateValidatorArgs),

    /// Update validator information
    UpdateValidator(UpdateValidatorArgs),

    /// Unjail a jailed validator
    Unjail(UnjailArgs),
}

/// Arguments for stake command
#[derive(Parser, Debug)]
pub struct StakeArgs {
    /// Amount to stake (in base units or with suffix like "100k", "1m")
    pub amount: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "100000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for unstake command
#[derive(Parser, Debug)]
pub struct UnstakeArgs {
    /// Amount to unstake
    pub amount: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "100000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for delegate command
#[derive(Parser, Debug)]
pub struct DelegateArgs {
    /// Validator address to delegate to
    #[arg(long)]
    pub validator: String,

    /// Amount to delegate
    pub amount: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "150000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for undelegate command
#[derive(Parser, Debug)]
pub struct UndelegateArgs {
    /// Validator address to undelegate from
    #[arg(long)]
    pub validator: String,

    /// Amount to undelegate
    pub amount: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "150000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for redelegate command
#[derive(Parser, Debug)]
pub struct RedelegateArgs {
    /// Source validator address
    #[arg(long)]
    pub from_validator: String,

    /// Destination validator address
    #[arg(long)]
    pub to_validator: String,

    /// Amount to redelegate
    pub amount: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "200000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for withdraw command
#[derive(Parser, Debug)]
pub struct WithdrawArgs {
    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Specific validator to withdraw from (optional, default: all)
    #[arg(long)]
    pub validator: Option<String>,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "100000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for rewards query
#[derive(Parser, Debug)]
pub struct RewardsArgs {
    /// Address to query rewards for
    pub address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for delegations query
#[derive(Parser, Debug)]
pub struct DelegationsArgs {
    /// Delegator address
    pub address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for create-validator command
#[derive(Parser, Debug)]
pub struct CreateValidatorArgs {
    /// Initial stake amount
    #[arg(long)]
    pub amount: String,

    /// Commission rate in basis points (e.g., 1000 = 10%)
    #[arg(long)]
    pub commission: u16,

    /// Maximum commission rate change per day (basis points)
    #[arg(long, default_value = "100")]
    pub max_commission_change: u16,

    /// Validator moniker (display name)
    #[arg(long)]
    pub moniker: Option<String>,

    /// Validator website
    #[arg(long)]
    pub website: Option<String>,

    /// Validator details/description
    #[arg(long)]
    pub details: Option<String>,

    /// BLS public key (hex)
    #[arg(long)]
    pub bls_pubkey: String,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "500000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for update-validator command
#[derive(Parser, Debug)]
pub struct UpdateValidatorArgs {
    /// New commission rate in basis points (optional)
    #[arg(long)]
    pub commission: Option<u16>,

    /// New moniker (optional)
    #[arg(long)]
    pub moniker: Option<String>,

    /// New website (optional)
    #[arg(long)]
    pub website: Option<String>,

    /// New details (optional)
    #[arg(long)]
    pub details: Option<String>,

    /// Wallet key to sign transaction
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "200000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for unjail command
#[derive(Parser, Debug)]
pub struct UnjailArgs {
    /// Wallet key to sign transaction (validator address)
    #[arg(long)]
    pub from: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Gas limit
    #[arg(long, default_value = "100000")]
    pub gas: u64,

    /// Gas price in Gwei
    #[arg(long)]
    pub gas_price: Option<u64>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Execute staking commands
pub async fn execute(cmd: StakingCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        StakingCommands::Stake(args) => execute_stake(args, output_format).await,
        StakingCommands::Unstake(args) => execute_unstake(args, output_format).await,
        StakingCommands::Delegate(args) => execute_delegate(args, output_format).await,
        StakingCommands::Undelegate(args) => execute_undelegate(args, output_format).await,
        StakingCommands::Redelegate(args) => execute_redelegate(args, output_format).await,
        StakingCommands::Withdraw(args) => execute_withdraw(args, output_format).await,
        StakingCommands::Rewards(args) => execute_rewards(args, output_format).await,
        StakingCommands::Delegations(args) => execute_delegations(args, output_format).await,
        StakingCommands::CreateValidator(args) => {
            execute_create_validator(args, output_format).await
        }
        StakingCommands::UpdateValidator(args) => {
            execute_update_validator(args, output_format).await
        }
        StakingCommands::Unjail(args) => execute_unjail(args, output_format).await,
    }
}

/// Execute stake command
async fn execute_stake(args: StakeArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Staking {} tokens...",
        format_balance(&amount.to_string())
    ));

    // Confirm transaction
    if !args.yes {
        println!();
        println!("Transaction Details:");
        println!("  Action:  Stake");
        println!("  Amount:  {}", format_balance(&amount.to_string()));
        println!("  From:    {}", args.from);
        println!("  Gas:     {}", args.gas);
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with staking?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    // Load key and sign transaction
    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    // Build and send transaction
    let tx_hash = client
        .send_stake_transaction(&signer, amount, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Stake", output_format)?;
    Ok(())
}

/// Execute unstake command
async fn execute_unstake(args: UnstakeArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Unstaking {} tokens...",
        format_balance(&amount.to_string())
    ));
    print_warning(
        "Unstaked tokens will be available after the unbonding period (typically 21 days).",
    );

    // Confirm transaction
    if !args.yes {
        println!();
        println!("Transaction Details:");
        println!("  Action:  Unstake");
        println!("  Amount:  {}", format_balance(&amount.to_string()));
        println!("  From:    {}", args.from);
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with unstaking?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_unstake_transaction(&signer, amount, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Unstake", output_format)?;
    Ok(())
}

/// Execute delegate command
async fn execute_delegate(args: DelegateArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Delegating {} tokens to validator {}...",
        format_balance(&amount.to_string()),
        &args.validator[..10]
    ));

    // Confirm transaction
    if !args.yes {
        println!();
        println!("Transaction Details:");
        println!("  Action:     Delegate");
        println!("  Amount:     {}", format_balance(&amount.to_string()));
        println!("  Validator:  {}", args.validator);
        println!("  From:       {}", args.from);
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with delegation?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_delegate_transaction(&signer, &args.validator, amount, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Delegation", output_format)?;
    Ok(())
}

/// Execute undelegate command
async fn execute_undelegate(args: UndelegateArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Undelegating {} tokens from validator {}...",
        format_balance(&amount.to_string()),
        &args.validator[..10]
    ));
    print_warning("Undelegated tokens will be available after the unbonding period.");

    if !args.yes {
        println!();
        println!("Transaction Details:");
        println!("  Action:     Undelegate");
        println!("  Amount:     {}", format_balance(&amount.to_string()));
        println!("  Validator:  {}", args.validator);
        println!("  From:       {}", args.from);
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with undelegation?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_undelegate_transaction(&signer, &args.validator, amount, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Undelegation", output_format)?;
    Ok(())
}

/// Execute redelegate command
async fn execute_redelegate(args: RedelegateArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Redelegating {} tokens from {} to {}...",
        format_balance(&amount.to_string()),
        &args.from_validator[..10],
        &args.to_validator[..10]
    ));

    if !args.yes {
        println!();
        println!("Transaction Details:");
        println!("  Action:          Redelegate");
        println!("  Amount:          {}", format_balance(&amount.to_string()));
        println!("  From Validator:  {}", args.from_validator);
        println!("  To Validator:    {}", args.to_validator);
        println!("  From:            {}", args.from);
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with redelegation?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_redelegate_transaction(
            &signer,
            &args.from_validator,
            &args.to_validator,
            amount,
            args.gas,
            args.gas_price,
        )
        .await?;

    output_transaction_result(&tx_hash, "Redelegation", output_format)?;
    Ok(())
}

/// Execute withdraw command
async fn execute_withdraw(args: WithdrawArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if let Some(ref validator) = args.validator {
        print_info(&format!(
            "Withdrawing rewards from validator {}...",
            &validator[..10]
        ));
    } else {
        print_info("Withdrawing all accumulated rewards...");
    }

    if !args.yes {
        // Query rewards first
        let rewards = client.get_rewards(&args.from).await?;

        println!();
        println!(
            "Pending Rewards: {}",
            format_balance(&rewards.total.to_string())
        );
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with withdrawal?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_withdraw_transaction(&signer, args.validator.as_deref(), args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Withdrawal", output_format)?;
    Ok(())
}

/// Execute rewards query
async fn execute_rewards(args: RewardsArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!("Querying rewards for {}...", &args.address[..10]));

    let rewards = client.get_rewards(&args.address).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rewards)?);
        }
        OutputFormat::Text => {
            println!("Staking Rewards for {}", args.address);
            println!("===================");
            println!();
            println!(
                "Total Pending: {}",
                format_balance(&rewards.total.to_string())
            );
            println!();

            if !rewards.by_validator.is_empty() {
                println!("By Validator:");
                println!("{:<44} {:<20}", "VALIDATOR", "REWARDS");
                println!("{}", "-".repeat(66));
                for (validator, amount) in &rewards.by_validator {
                    println!(
                        "{:<44} {:<20}",
                        validator,
                        format_balance(&amount.to_string())
                    );
                }
            }
        }
    }

    Ok(())
}

/// Execute delegations query
async fn execute_delegations(args: DelegationsArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Querying delegations for {}...",
        &args.address[..10]
    ));

    let delegations = client.get_delegations(&args.address).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&delegations)?);
        }
        OutputFormat::Text => {
            println!("Delegations for {}", args.address);
            println!("===============");
            println!();
            println!(
                "Total Delegated: {}",
                format_balance(&delegations.total_delegated.to_string())
            );
            println!(
                "Total Unbonding: {}",
                format_balance(&delegations.total_unbonding.to_string())
            );
            println!();

            if !delegations.delegations.is_empty() {
                println!("Active Delegations:");
                println!("{:<44} {:<20} {:<10}", "VALIDATOR", "AMOUNT", "SHARES");
                println!("{}", "-".repeat(76));
                for d in &delegations.delegations {
                    println!(
                        "{:<44} {:<20} {:<10.4}",
                        d.validator,
                        format_balance(&d.amount.to_string()),
                        d.shares
                    );
                }
            }

            if !delegations.unbonding.is_empty() {
                println!();
                println!("Unbonding:");
                println!("{:<44} {:<20} {:<20}", "VALIDATOR", "AMOUNT", "COMPLETION");
                println!("{}", "-".repeat(86));
                for u in &delegations.unbonding {
                    println!(
                        "{:<44} {:<20} {:<20}",
                        u.validator,
                        format_balance(&u.amount.to_string()),
                        u.completion_time
                    );
                }
            }
        }
    }

    Ok(())
}

/// Execute create-validator command
async fn execute_create_validator(
    args: CreateValidatorArgs,
    output_format: OutputFormat,
) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    if args.commission > 10000 {
        return Err(CliError::InvalidArgument(
            "Commission cannot exceed 100% (10000 bps)".to_string(),
        ));
    }

    print_info("Creating new validator...");

    if !args.yes {
        println!();
        println!("Validator Details:");
        println!("  Initial Stake:   {}", format_balance(&amount.to_string()));
        println!("  Commission:      {:.2}%", args.commission as f64 / 100.0);
        println!(
            "  Max Change/Day:  {:.2}%",
            args.max_commission_change as f64 / 100.0
        );
        println!(
            "  Moniker:         {}",
            args.moniker.as_deref().unwrap_or("(not set)")
        );
        println!(
            "  Website:         {}",
            args.website.as_deref().unwrap_or("(not set)")
        );
        println!("  BLS Public Key:  {}...", &args.bls_pubkey[..40]);
        println!();
        print_warning(
            "Creating a validator requires a minimum stake and proper uptime commitment.",
        );

        if !Confirm::new()
            .with_prompt("Proceed with validator creation?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let validator_info = ValidatorCreateInfo {
        stake: amount,
        commission_rate: args.commission,
        max_commission_change: args.max_commission_change,
        moniker: args.moniker,
        website: args.website,
        details: args.details,
        bls_public_key: args.bls_pubkey,
    };

    let tx_hash = client
        .send_create_validator_transaction(&signer, validator_info, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Validator Creation", output_format)?;
    Ok(())
}

/// Execute update-validator command
async fn execute_update_validator(
    args: UpdateValidatorArgs,
    output_format: OutputFormat,
) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if args.commission.is_none()
        && args.moniker.is_none()
        && args.website.is_none()
        && args.details.is_none()
    {
        return Err(CliError::InvalidArgument(
            "At least one update parameter must be specified".to_string(),
        ));
    }

    print_info("Updating validator information...");

    if !args.yes {
        println!();
        println!("Updates:");
        if let Some(comm) = args.commission {
            println!("  Commission:  {:.2}%", comm as f64 / 100.0);
        }
        if let Some(ref m) = args.moniker {
            println!("  Moniker:     {}", m);
        }
        if let Some(ref w) = args.website {
            println!("  Website:     {}", w);
        }
        if let Some(ref d) = args.details {
            println!("  Details:     {}", d);
        }
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with validator update?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let update_info = ValidatorUpdateInfo {
        commission_rate: args.commission,
        moniker: args.moniker,
        website: args.website,
        details: args.details,
    };

    let tx_hash = client
        .send_update_validator_transaction(&signer, update_info, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Validator Update", output_format)?;
    Ok(())
}

/// Execute unjail command
async fn execute_unjail(args: UnjailArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Requesting unjail for validator...");

    if !args.yes {
        print_warning("Unjailing is only possible after the jail period has elapsed and any slashing conditions are resolved.");
        println!();

        if !Confirm::new()
            .with_prompt("Proceed with unjail request?")
            .default(false)
            .interact()?
        {
            println!("Transaction cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_unjail_transaction(&signer, args.gas, args.gas_price)
        .await?;

    output_transaction_result(&tx_hash, "Unjail", output_format)?;
    Ok(())
}

/// Output transaction result
fn output_transaction_result(
    tx_hash: &str,
    action: &str,
    output_format: OutputFormat,
) -> CliResult<()> {
    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "submitted",
                    "action": action,
                    "transaction_hash": tx_hash,
                }))?
            );
        }
        OutputFormat::Text => {
            print_success(&format!("{} transaction submitted!", action));
            println!();
            println!("  Transaction Hash: {}", tx_hash);
            println!();
            println!("Use 'protocore query tx {}' to check status.", tx_hash);
        }
    }
    Ok(())
}

// ============================================================================
// Data types
// ============================================================================

/// Validator creation info
#[derive(Debug, serde::Serialize)]
pub struct ValidatorCreateInfo {
    pub stake: u128,
    pub commission_rate: u16,
    pub max_commission_change: u16,
    pub moniker: Option<String>,
    pub website: Option<String>,
    pub details: Option<String>,
    pub bls_public_key: String,
}

/// Validator update info
#[derive(Debug, serde::Serialize)]
pub struct ValidatorUpdateInfo {
    pub commission_rate: Option<u16>,
    pub moniker: Option<String>,
    pub website: Option<String>,
    pub details: Option<String>,
}

/// Rewards response
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RewardsResponse {
    pub total: u128,
    pub by_validator: Vec<(String, u128)>,
}

/// Delegations response
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DelegationsResponse {
    pub total_delegated: u128,
    pub total_unbonding: u128,
    pub delegations: Vec<DelegationEntry>,
    pub unbonding: Vec<UnbondingEntry>,
}

/// Delegation entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DelegationEntry {
    pub validator: String,
    pub amount: u128,
    pub shares: f64,
}

/// Unbonding entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UnbondingEntry {
    pub validator: String,
    pub amount: u128,
    pub completion_time: String,
}
