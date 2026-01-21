//! Query commands for blockchain state.
//!
//! This module provides commands to query various aspects of the blockchain:
//! - Blocks by number or hash
//! - Transactions by hash
//! - Account balances and state
//! - Validator information

use clap::{Parser, Subcommand};

use crate::utils::{
    format_balance, format_timestamp, print_info, CliError, CliResult, OutputFormat, RpcClient,
};

/// Query subcommands
#[derive(Subcommand, Debug)]
pub enum QueryCommands {
    /// Get block information
    Block(BlockArgs),

    /// Get transaction information
    Tx(TxArgs),

    /// Get account information
    Account(AccountArgs),

    /// Get current validators
    Validators(ValidatorsArgs),

    /// Get chain status
    Status(StatusArgs),

    /// Get pending transactions
    Pending(PendingArgs),

    /// Get receipt for a transaction
    Receipt(ReceiptArgs),

    /// Get code at an address (for contracts)
    Code(CodeArgs),

    /// Get storage at a specific slot
    Storage(StorageArgs),
}

/// Arguments for block query
#[derive(Parser, Debug)]
pub struct BlockArgs {
    /// Block number or "latest", "earliest", "pending"
    #[arg(default_value = "latest")]
    pub block: String,

    /// Include full transaction data
    #[arg(long)]
    pub full: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for transaction query
#[derive(Parser, Debug)]
pub struct TxArgs {
    /// Transaction hash (0x-prefixed)
    pub hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for account query
#[derive(Parser, Debug)]
pub struct AccountArgs {
    /// Account address (0x-prefixed)
    pub address: String,

    /// Block number for historical query
    #[arg(long)]
    pub block: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for validators query
#[derive(Parser, Debug)]
pub struct ValidatorsArgs {
    /// Show only active validators
    #[arg(long)]
    pub active: bool,

    /// Include staking information
    #[arg(long)]
    pub staking: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for status query
#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for pending transactions query
#[derive(Parser, Debug)]
pub struct PendingArgs {
    /// Maximum number of transactions to show
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Filter by sender address
    #[arg(long)]
    pub from: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for receipt query
#[derive(Parser, Debug)]
pub struct ReceiptArgs {
    /// Transaction hash (0x-prefixed)
    pub hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for code query
#[derive(Parser, Debug)]
pub struct CodeArgs {
    /// Contract address (0x-prefixed)
    pub address: String,

    /// Block number for historical query
    #[arg(long)]
    pub block: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for storage query
#[derive(Parser, Debug)]
pub struct StorageArgs {
    /// Contract address (0x-prefixed)
    pub address: String,

    /// Storage slot (0x-prefixed hex)
    pub slot: String,

    /// Block number for historical query
    #[arg(long)]
    pub block: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Execute query commands
pub async fn execute(cmd: QueryCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        QueryCommands::Block(args) => execute_block(args, output_format).await,
        QueryCommands::Tx(args) => execute_tx(args, output_format).await,
        QueryCommands::Account(args) => execute_account(args, output_format).await,
        QueryCommands::Validators(args) => execute_validators(args, output_format).await,
        QueryCommands::Status(args) => execute_status(args, output_format).await,
        QueryCommands::Pending(args) => execute_pending(args, output_format).await,
        QueryCommands::Receipt(args) => execute_receipt(args, output_format).await,
        QueryCommands::Code(args) => execute_code(args, output_format).await,
        QueryCommands::Storage(args) => execute_storage(args, output_format).await,
    }
}

/// Execute block query
async fn execute_block(args: BlockArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    let block_param = parse_block_param(&args.block)?;

    print_info(&format!("Querying block {}...", args.block));

    let block = client.get_block(block_param, args.full).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&block)?);
        }
        OutputFormat::Text => {
            println!("Block Information");
            println!("=================");
            println!("  Number:          {}", block.number);
            println!("  Hash:            {}", block.hash);
            println!("  Parent Hash:     {}", block.parent_hash);
            println!("  Timestamp:       {}", format_timestamp(block.timestamp));
            println!("  Proposer:        {}", block.proposer);
            println!("  State Root:      {}", block.state_root);
            println!("  Tx Root:         {}", block.transactions_root);
            println!("  Receipts Root:   {}", block.receipts_root);
            println!(
                "  Gas Used:        {} / {}",
                block.gas_used, block.gas_limit
            );
            println!("  Transactions:    {}", block.transactions.len());

            if args.full && !block.transactions.is_empty() {
                println!();
                println!("Transactions:");
                for (i, tx) in block.transactions.iter().enumerate() {
                    println!("  [{}] {}", i, tx);
                }
            }
        }
    }

    Ok(())
}

/// Execute transaction query
async fn execute_tx(args: TxArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if !args.hash.starts_with("0x") || args.hash.len() != 66 {
        return Err(CliError::InvalidArgument(
            "Invalid transaction hash format".to_string(),
        ));
    }

    print_info(&format!("Querying transaction {}...", &args.hash[..18]));

    let tx = client.get_transaction(&args.hash).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&tx)?);
        }
        OutputFormat::Text => {
            println!("Transaction Information");
            println!("=======================");
            println!("  Hash:            {}", tx.hash);
            println!(
                "  Status:          {}",
                if tx.status { "Success" } else { "Failed" }
            );
            println!(
                "  Block:           {} (index {})",
                tx.block_number, tx.transaction_index
            );
            println!("  From:            {}", tx.from);
            println!(
                "  To:              {}",
                tx.to.as_deref().unwrap_or("Contract Creation")
            );
            println!("  Value:           {}", format_balance(&tx.value));
            println!("  Gas:             {} / {}", tx.gas_used, tx.gas);
            println!("  Gas Price:       {} Gwei", tx.gas_price / 1_000_000_000);
            println!("  Nonce:           {}", tx.nonce);
            if tx.input.len() > 2 {
                println!("  Data:            {} bytes", (tx.input.len() - 2) / 2);
            }
        }
    }

    Ok(())
}

/// Execute account query
async fn execute_account(args: AccountArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if !args.address.starts_with("0x") || args.address.len() != 42 {
        return Err(CliError::InvalidArgument(
            "Invalid address format".to_string(),
        ));
    }

    let block = args.block.as_deref().unwrap_or("latest");
    print_info(&format!(
        "Querying account {} at block {}...",
        &args.address[..10],
        block
    ));

    let account = client.get_account(&args.address, block).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&account)?);
        }
        OutputFormat::Text => {
            println!("Account Information");
            println!("===================");
            println!("  Address:         {}", args.address);
            println!("  Balance:         {}", format_balance(&account.balance));
            println!("  Nonce:           {}", account.nonce);
            println!("  Code Hash:       {}", account.code_hash);
            println!("  Storage Root:    {}", account.storage_root);

            if account.is_contract {
                println!("  Type:            Contract");
                println!("  Code Size:       {} bytes", account.code_size);
            } else {
                println!("  Type:            EOA (Externally Owned Account)");
            }
        }
    }

    Ok(())
}

/// Execute validators query
async fn execute_validators(args: ValidatorsArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Querying validators...");

    let validators = client.get_validators(args.active).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&validators)?);
        }
        OutputFormat::Text => {
            println!("Validators ({} total)", validators.len());
            println!("=================");
            println!();
            println!(
                "{:<6} {:<44} {:<20} {:<10} {:<12}",
                "RANK", "ADDRESS", "STAKE", "COMM %", "STATUS"
            );
            println!("{}", "-".repeat(94));

            for (i, v) in validators.iter().enumerate() {
                let status = if v.jailed {
                    "Jailed"
                } else if v.active {
                    "Active"
                } else {
                    "Inactive"
                };

                println!(
                    "{:<6} {:<44} {:<20} {:<10} {:<12}",
                    i + 1,
                    v.address,
                    format_balance(&v.stake.to_string()),
                    format!("{:.2}", v.commission_rate as f64 / 100.0),
                    status
                );
            }

            if args.staking {
                println!();
                let total_stake: u128 = validators.iter().map(|v| v.stake).sum();
                println!("Total Staked: {}", format_balance(&total_stake.to_string()));
            }
        }
    }

    Ok(())
}

/// Execute status query
async fn execute_status(args: StatusArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Querying chain status...");

    let status = client.get_status().await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        OutputFormat::Text => {
            println!("Chain Status");
            println!("============");
            println!("  Chain ID:        {}", status.chain_id);
            println!("  Network:         {}", status.network_name);
            println!("  Block Height:    {}", status.block_height);
            println!("  Block Hash:      {}", status.latest_block_hash);
            println!(
                "  Block Time:      {}",
                format_timestamp(status.latest_block_time)
            );
            println!();
            println!("Network:");
            println!("  Peers:           {}", status.peer_count);
            println!(
                "  Syncing:         {}",
                if status.syncing { "Yes" } else { "No" }
            );
            if status.syncing {
                println!("  Sync Progress:   {:.2}%", status.sync_progress * 100.0);
            }
            println!();
            println!("Consensus:");
            println!("  Validators:      {}", status.validator_count);
            println!("  Current Epoch:   {}", status.current_epoch);
        }
    }

    Ok(())
}

/// Execute pending transactions query
async fn execute_pending(args: PendingArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Querying pending transactions...");

    let pending = client
        .get_pending_transactions(args.limit, args.from.as_deref())
        .await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&pending)?);
        }
        OutputFormat::Text => {
            println!(
                "Pending Transactions ({} found)",
                pending.transactions.len()
            );
            println!("======================");

            if pending.transactions.is_empty() {
                println!("No pending transactions.");
            } else {
                println!();
                println!(
                    "{:<66} {:<44} {:<20} {:<10}",
                    "HASH", "FROM", "VALUE", "GAS"
                );
                println!("{}", "-".repeat(142));

                for tx in &pending.transactions {
                    println!(
                        "{:<66} {:<44} {:<20} {:<10}",
                        tx.hash,
                        tx.from,
                        format_balance(&tx.value),
                        tx.gas
                    );
                }
            }

            println!();
            println!(
                "Mempool: {} pending, {} queued",
                pending.pending_count, pending.queued_count
            );
        }
    }

    Ok(())
}

/// Execute receipt query
async fn execute_receipt(args: ReceiptArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if !args.hash.starts_with("0x") || args.hash.len() != 66 {
        return Err(CliError::InvalidArgument(
            "Invalid transaction hash format".to_string(),
        ));
    }

    print_info(&format!("Querying receipt for {}...", &args.hash[..18]));

    let receipt = client.get_receipt(&args.hash).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        OutputFormat::Text => {
            println!("Transaction Receipt");
            println!("===================");
            println!("  Transaction Hash:  {}", receipt.transaction_hash);
            println!(
                "  Status:            {}",
                if receipt.status { "Success" } else { "Failed" }
            );
            println!("  Block Number:      {}", receipt.block_number);
            println!("  Block Hash:        {}", receipt.block_hash);
            println!("  Transaction Index: {}", receipt.transaction_index);
            println!("  From:              {}", receipt.from);
            println!(
                "  To:                {}",
                receipt.to.as_deref().unwrap_or("Contract Creation")
            );
            if let Some(ref addr) = receipt.contract_address {
                println!("  Contract Created:  {}", addr);
            }
            println!("  Gas Used:          {}", receipt.gas_used);
            println!("  Cumulative Gas:    {}", receipt.cumulative_gas_used);
            println!("  Logs:              {}", receipt.logs.len());

            if !receipt.logs.is_empty() {
                println!();
                println!("Event Logs:");
                for (i, log) in receipt.logs.iter().enumerate() {
                    println!("  [{}] Address: {}", i, log.address);
                    println!("      Topics:  {}", log.topics.len());
                    println!("      Data:    {} bytes", (log.data.len() - 2) / 2);
                }
            }
        }
    }

    Ok(())
}

/// Execute code query
async fn execute_code(args: CodeArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if !args.address.starts_with("0x") || args.address.len() != 42 {
        return Err(CliError::InvalidArgument(
            "Invalid address format".to_string(),
        ));
    }

    let block = args.block.as_deref().unwrap_or("latest");
    print_info(&format!(
        "Querying code at {} at block {}...",
        &args.address[..10],
        block
    ));

    let code = client.get_code(&args.address, block).await?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "address": args.address,
                    "block": block,
                    "code": code.code,
                    "size": code.size,
                }))?
            );
        }
        OutputFormat::Text => {
            if code.code == "0x" {
                println!(
                    "No code at address {} (EOA or empty contract)",
                    args.address
                );
            } else {
                println!("Contract Code at {}", args.address);
                println!("Code Size: {} bytes", code.size);
                println!();
                if code.size <= 1000 {
                    println!("{}", code.code);
                } else {
                    println!(
                        "{}... (truncated, {} bytes total)",
                        &code.code[..200],
                        code.size
                    );
                }
            }
        }
    }

    Ok(())
}

/// Execute storage query
async fn execute_storage(args: StorageArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    if !args.address.starts_with("0x") || args.address.len() != 42 {
        return Err(CliError::InvalidArgument(
            "Invalid address format".to_string(),
        ));
    }

    let block = args.block.as_deref().unwrap_or("latest");
    print_info(&format!(
        "Querying storage at {} slot {} at block {}...",
        &args.address[..10],
        &args.slot,
        block
    ));

    let value = client.get_storage(&args.address, &args.slot, block).await?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "address": args.address,
                    "slot": args.slot,
                    "block": block,
                    "value": value,
                }))?
            );
        }
        OutputFormat::Text => {
            println!("Storage Query Result");
            println!("====================");
            println!("  Address: {}", args.address);
            println!("  Slot:    {}", args.slot);
            println!("  Block:   {}", block);
            println!("  Value:   {}", value);
        }
    }

    Ok(())
}

/// Parse block parameter
fn parse_block_param(block: &str) -> CliResult<BlockParam> {
    match block.to_lowercase().as_str() {
        "latest" => Ok(BlockParam::Latest),
        "earliest" => Ok(BlockParam::Earliest),
        "pending" => Ok(BlockParam::Pending),
        s if s.starts_with("0x") => {
            if s.len() == 66 {
                Ok(BlockParam::Hash(s.to_string()))
            } else {
                let num = u64::from_str_radix(&s[2..], 16)
                    .map_err(|_| CliError::InvalidArgument("Invalid block number".to_string()))?;
                Ok(BlockParam::Number(num))
            }
        }
        s => {
            let num: u64 = s
                .parse()
                .map_err(|_| CliError::InvalidArgument("Invalid block number".to_string()))?;
            Ok(BlockParam::Number(num))
        }
    }
}

/// Block parameter types
#[derive(Debug)]
pub enum BlockParam {
    Number(u64),
    Hash(String),
    Latest,
    Earliest,
    Pending,
}

// ============================================================================
// Response types (for deserialization from RPC)
// ============================================================================

/// Block information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub proposer: String,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub transactions: Vec<String>,
}

/// Transaction information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub status: bool,
    pub block_number: u64,
    pub transaction_index: u64,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas: u64,
    pub gas_used: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub input: String,
}

/// Account information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccountInfo {
    pub balance: String,
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
    pub is_contract: bool,
    pub code_size: usize,
}

/// Validator information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub bls_public_key: String,
    pub stake: u128,
    pub commission_rate: u16,
    pub active: bool,
    pub jailed: bool,
}

/// Chain status
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainStatus {
    pub chain_id: u64,
    pub network_name: String,
    pub block_height: u64,
    pub latest_block_hash: String,
    pub latest_block_time: u64,
    pub peer_count: usize,
    pub syncing: bool,
    pub sync_progress: f64,
    pub validator_count: usize,
    pub current_epoch: u64,
}

/// Pending transactions
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingTransactions {
    pub transactions: Vec<PendingTx>,
    pub pending_count: usize,
    pub queued_count: usize,
}

/// Pending transaction entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas: u64,
    pub gas_price: u64,
    pub nonce: u64,
}

/// Transaction receipt
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: String,
    pub status: bool,
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_index: u64,
    pub from: String,
    pub to: Option<String>,
    pub contract_address: Option<String>,
    pub gas_used: u64,
    pub cumulative_gas_used: u64,
    pub logs: Vec<LogEntry>,
}

/// Log entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// Code response
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CodeResponse {
    pub code: String,
    pub size: usize,
}
