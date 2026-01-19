//! Software upgrade commands.
//!
//! This module provides commands for managing protocol upgrades:
//! - Check pending upgrade status and approval progress
//! - Vote on upgrade proposals as a validator
//! - View upgrade history

use clap::{Parser, Subcommand};
use console::style;
use dialoguer::Confirm;
use std::path::PathBuf;

use crate::utils::{
    format_timestamp, format_with_commas, CliError, CliResult, OutputFormat, RpcClient,
    TransactionSigner, print_info, print_success, print_warning,
};
use crate::default_keystore_dir;

/// Upgrade subcommands
#[derive(Subcommand, Debug)]
pub enum UpgradeCommands {
    /// Check pending upgrade status
    Status(StatusArgs),

    /// Vote on a pending upgrade proposal
    Vote(VoteArgs),

    /// List upgrade history
    History(HistoryArgs),
}

/// Arguments for status command
#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Show detailed information including voter breakdown
    #[arg(long, short)]
    pub verbose: bool,
}

/// Arguments for vote command
#[derive(Parser, Debug)]
pub struct VoteArgs {
    /// Proposal ID to vote on
    pub proposal_id: u64,

    /// Vote yes on the proposal
    #[arg(long, conflicts_with = "no")]
    pub yes: bool,

    /// Vote no on the proposal
    #[arg(long, conflicts_with = "yes")]
    pub no: bool,

    /// Wallet key to sign transaction (must be a validator)
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
    #[arg(long, name = "confirm")]
    pub skip_confirm: bool,
}

/// Arguments for history command
#[derive(Parser, Debug)]
pub struct HistoryArgs {
    /// Number of upgrades to show
    #[arg(long, default_value = "10")]
    pub limit: usize,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Execute upgrade commands
pub async fn execute(cmd: UpgradeCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        UpgradeCommands::Status(args) => execute_status(args, output_format).await,
        UpgradeCommands::Vote(args) => execute_vote(args, output_format).await,
        UpgradeCommands::History(args) => execute_history(args, output_format).await,
    }
}

/// Execute status command
async fn execute_status(args: StatusArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Checking upgrade status...");

    let upgrade_status = client.get_pending_upgrade().await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&upgrade_status)?);
        }
        OutputFormat::Text => {
            match upgrade_status.pending_upgrade {
                Some(ref upgrade) => {
                    println!("Pending upgrade: {}", style(&upgrade.version).cyan().bold());

                    // Activation info
                    let activation_str = format!(
                        "block {} (in ~{})",
                        format_with_commas(upgrade.activation_block as u128),
                        estimate_time_to_block(upgrade.blocks_remaining)
                    );
                    println!("Activation:      {}", activation_str);

                    // Approval progress
                    let approval_met = upgrade.approval_percentage >= upgrade.threshold_percentage;
                    let approval_icon = if approval_met {
                        style("✓").green().bold()
                    } else {
                        style("○").yellow()
                    };
                    println!("Approval:        {:.0}% (threshold: {:.0}%) {}",
                        upgrade.approval_percentage,
                        upgrade.threshold_percentage,
                        approval_icon
                    );

                    // Your vote status
                    let vote_display = match &upgrade.your_vote {
                        Some(vote) => {
                            if vote == "yes" {
                                style("YES").green().bold().to_string()
                            } else {
                                style("NO").red().bold().to_string()
                            }
                        }
                        None => style("NOT VOTED").yellow().to_string(),
                    };
                    println!("Your vote:       {}", vote_display);

                    if args.verbose {
                        println!();
                        println!("Details:");
                        println!("  Proposal ID:     {}", upgrade.proposal_id);
                        println!("  Current block:   {}", format_with_commas(upgrade.current_block as u128));
                        println!("  Binary hash:     {}...", &upgrade.binary_hash[..40]);
                        println!("  Total validators: {}", upgrade.total_validators);
                        println!("  Votes (yes/no):  {}/{}", upgrade.yes_votes, upgrade.no_votes);

                        if !upgrade.changelog.is_empty() {
                            println!();
                            println!("Changelog:");
                            for item in &upgrade.changelog {
                                println!("  - {}", item);
                            }
                        }
                    }

                    // Warnings
                    if !approval_met {
                        println!();
                        print_warning(&format!(
                            "Upgrade needs {:.0}% more approval to pass.",
                            upgrade.threshold_percentage - upgrade.approval_percentage
                        ));
                    }

                    if upgrade.your_vote.is_none() {
                        println!();
                        print_warning("You have not voted on this upgrade. Use 'protocore upgrade vote' to cast your vote.");
                    }
                }
                None => {
                    println!("No pending upgrades.");
                    println!();
                    println!("Current version: v{}", env!("CARGO_PKG_VERSION"));
                    if let Some(ref latest) = upgrade_status.latest_upgrade {
                        println!("Last upgrade:    {} (block {})",
                            latest.version,
                            format_with_commas(latest.activation_block as u128)
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Execute vote command
async fn execute_vote(args: VoteArgs, output_format: OutputFormat) -> CliResult<()> {
    // Validate vote choice
    if !args.yes && !args.no {
        return Err(CliError::InvalidArgument(
            "Must specify either --yes or --no".to_string()
        ));
    }

    let vote_choice = if args.yes { "yes" } else { "no" };
    let client = RpcClient::new(&args.rpc)?;

    // Get the pending upgrade to verify proposal exists
    let upgrade_status = client.get_pending_upgrade().await?;

    let upgrade = upgrade_status.pending_upgrade.ok_or_else(|| {
        CliError::InvalidArgument("No pending upgrade to vote on".to_string())
    })?;

    if upgrade.proposal_id != args.proposal_id {
        return Err(CliError::InvalidArgument(format!(
            "Proposal #{} not found. Current pending upgrade is proposal #{}",
            args.proposal_id, upgrade.proposal_id
        )));
    }

    // Check if already voted
    if let Some(ref existing_vote) = upgrade.your_vote {
        print_warning(&format!(
            "You have already voted {} on this proposal.",
            existing_vote.to_uppercase()
        ));
    }

    print_info(&format!(
        "Voting {} on upgrade proposal #{}...",
        vote_choice.to_uppercase(),
        args.proposal_id
    ));

    if !args.skip_confirm {
        println!();
        println!("Upgrade Details:");
        println!("  Proposal ID:  {}", upgrade.proposal_id);
        println!("  Version:      {}", upgrade.version);
        println!("  Activation:   block {}", format_with_commas(upgrade.activation_block as u128));
        println!("  Your vote:    {}", vote_choice.to_uppercase());
        println!();

        if !Confirm::new()
            .with_prompt(&format!("Submit {} vote on upgrade proposal #{}?",
                vote_choice.to_uppercase(), args.proposal_id))
            .default(false)
            .interact()?
        {
            println!("Vote cancelled.");
            return Ok(());
        }
    }

    let keystore = args.keystore.map(PathBuf::from).unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client.send_upgrade_vote_transaction(
        &signer,
        args.proposal_id,
        args.yes, // true = yes, false = no
        args.gas,
        args.gas_price,
    ).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "submitted",
                "proposal_id": args.proposal_id,
                "vote": vote_choice,
                "transaction_hash": tx_hash,
            }))?);
        }
        OutputFormat::Text => {
            print_success(&format!(
                "Vote recorded: {} on proposal #{}",
                vote_choice.to_uppercase(),
                args.proposal_id
            ));
            println!();
            println!("  Transaction Hash: {}", tx_hash);
        }
    }

    Ok(())
}

/// Execute history command
async fn execute_history(args: HistoryArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Fetching upgrade history...");

    let history = client.get_upgrade_history(args.limit).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&history)?);
        }
        OutputFormat::Text => {
            if history.is_empty() {
                println!("No upgrade history found.");
            } else {
                println!("Upgrade History ({} upgrades)", history.len());
                println!();
                println!("{:<12} {:<16} {:<14} {:<12} {:<20}",
                    "VERSION", "BLOCK", "APPROVAL", "STATUS", "DATE");
                println!("{}", "-".repeat(76));

                for upgrade in &history {
                    let status_styled = match upgrade.status.as_str() {
                        "applied" => style("Applied").green().to_string(),
                        "rejected" => style("Rejected").red().to_string(),
                        "cancelled" => style("Cancelled").yellow().to_string(),
                        _ => upgrade.status.clone(),
                    };

                    println!("{:<12} {:<16} {:<14} {:<12} {:<20}",
                        upgrade.version,
                        format_with_commas(upgrade.activation_block as u128),
                        format!("{:.1}%", upgrade.final_approval),
                        status_styled,
                        format_timestamp(upgrade.timestamp)
                    );
                }
            }
        }
    }

    Ok(())
}

/// Estimate time to reach a target block
fn estimate_time_to_block(blocks_remaining: u64) -> String {
    // Assume ~12 seconds per block (Ethereum-like)
    let seconds = blocks_remaining * 12;

    if seconds < 60 {
        "< 1 minute".to_string()
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        format!("{} minute{}", minutes, if minutes == 1 { "" } else { "s" })
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
    } else {
        let days = seconds / 86400;
        format!("~{} day{}", days, if days == 1 { "" } else { "s" })
    }
}

// ============================================================================
// Data types
// ============================================================================

/// Upgrade status response
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UpgradeStatus {
    /// Currently pending upgrade (if any)
    pub pending_upgrade: Option<PendingUpgrade>,
    /// Most recent completed upgrade
    pub latest_upgrade: Option<CompletedUpgrade>,
}

/// Pending upgrade information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingUpgrade {
    /// Proposal ID for the upgrade
    pub proposal_id: u64,
    /// Version string (e.g., "v1.1.0")
    pub version: String,
    /// Block number at which upgrade activates
    pub activation_block: u64,
    /// Current block number
    pub current_block: u64,
    /// Blocks remaining until activation
    pub blocks_remaining: u64,
    /// Current approval percentage
    pub approval_percentage: f64,
    /// Required threshold percentage
    pub threshold_percentage: f64,
    /// Number of yes votes
    pub yes_votes: u32,
    /// Number of no votes
    pub no_votes: u32,
    /// Total number of validators
    pub total_validators: u32,
    /// Your vote (if any)
    pub your_vote: Option<String>,
    /// Hash of the new binary
    pub binary_hash: String,
    /// Changelog items
    pub changelog: Vec<String>,
}

/// Completed upgrade information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CompletedUpgrade {
    /// Version string
    pub version: String,
    /// Block at which upgrade was applied
    pub activation_block: u64,
    /// Final approval percentage
    pub final_approval: f64,
    /// Status (applied, rejected, cancelled)
    pub status: String,
    /// Timestamp when upgrade was finalized
    pub timestamp: u64,
}

