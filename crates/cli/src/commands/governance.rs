//! Governance operations commands.
//!
//! This module provides commands for on-chain governance:
//! - Creating proposals (parameter changes, upgrades, spending)
//! - Voting on active proposals
//! - Querying proposal status and results
//! - Depositing to proposals

use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::Confirm;
use std::path::PathBuf;

use crate::default_keystore_dir;
use crate::utils::{
    format_balance, format_timestamp, parse_amount, print_info, print_success, print_warning,
    CliError, CliResult, OutputFormat, RpcClient, TransactionSigner,
};

/// Governance subcommands
#[derive(Subcommand, Debug)]
pub enum GovernanceCommands {
    /// Create a new proposal
    Propose(ProposeArgs),

    /// Vote on an active proposal
    Vote(VoteArgs),

    /// Deposit to a proposal to meet the minimum deposit
    Deposit(DepositArgs),

    /// List all proposals
    List(ListArgs),

    /// Show detailed information about a proposal
    Show(ShowArgs),

    /// Query governance parameters
    Params(ParamsArgs),

    /// Query your voting history
    VotingHistory(VotingHistoryArgs),
}

/// Arguments for propose command
#[derive(Parser, Debug)]
pub struct ProposeArgs {
    /// Proposal type
    #[arg(long, value_enum)]
    pub proposal_type: ProposalType,

    /// Proposal title
    #[arg(long)]
    pub title: String,

    /// Proposal description
    #[arg(long)]
    pub description: String,

    /// Initial deposit amount
    #[arg(long)]
    pub deposit: String,

    /// For parameter-change: parameter key (e.g., "consensus.block_time_ms")
    #[arg(long)]
    pub param_key: Option<String>,

    /// For parameter-change: new parameter value
    #[arg(long)]
    pub param_value: Option<String>,

    /// For upgrade: target block height
    #[arg(long)]
    pub upgrade_height: Option<u64>,

    /// For upgrade: upgrade name/version
    #[arg(long)]
    pub upgrade_name: Option<String>,

    /// For community-spend: recipient address
    #[arg(long)]
    pub recipient: Option<String>,

    /// For community-spend: spending amount
    #[arg(long)]
    pub spend_amount: Option<String>,

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

/// Proposal types
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProposalType {
    /// Change a chain parameter
    ParameterChange,
    /// Schedule a software upgrade
    SoftwareUpgrade,
    /// Spend from community pool
    CommunitySpend,
    /// Plain text proposal (signaling)
    Text,
}

impl std::fmt::Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::ParameterChange => write!(f, "Parameter Change"),
            ProposalType::SoftwareUpgrade => write!(f, "Software Upgrade"),
            ProposalType::CommunitySpend => write!(f, "Community Spend"),
            ProposalType::Text => write!(f, "Text"),
        }
    }
}

/// Arguments for vote command
#[derive(Parser, Debug)]
pub struct VoteArgs {
    /// Proposal ID to vote on
    #[arg(long)]
    pub proposal_id: u64,

    /// Vote option
    #[arg(long, value_enum)]
    pub vote: VoteOption,

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

/// Vote options
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VoteOption {
    /// Vote in favor
    Yes,
    /// Vote against
    No,
    /// Abstain from voting
    Abstain,
    /// Vote against with veto
    NoWithVeto,
}

impl std::fmt::Display for VoteOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteOption::Yes => write!(f, "Yes"),
            VoteOption::No => write!(f, "No"),
            VoteOption::Abstain => write!(f, "Abstain"),
            VoteOption::NoWithVeto => write!(f, "No With Veto"),
        }
    }
}

/// Arguments for deposit command
#[derive(Parser, Debug)]
pub struct DepositArgs {
    /// Proposal ID to deposit to
    #[arg(long)]
    pub proposal_id: u64,

    /// Deposit amount
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

/// Arguments for list command
#[derive(Parser, Debug)]
pub struct ListArgs {
    /// Filter by status
    #[arg(long, value_enum)]
    pub status: Option<ProposalStatus>,

    /// Limit number of results
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// Show proposals by proposer address
    #[arg(long)]
    pub proposer: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Proposal status filter
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProposalStatus {
    /// Deposit period
    DepositPeriod,
    /// Voting period
    VotingPeriod,
    /// Passed
    Passed,
    /// Rejected
    Rejected,
    /// Failed (didn't meet deposit)
    Failed,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::DepositPeriod => write!(f, "Deposit Period"),
            ProposalStatus::VotingPeriod => write!(f, "Voting Period"),
            ProposalStatus::Passed => write!(f, "Passed"),
            ProposalStatus::Rejected => write!(f, "Rejected"),
            ProposalStatus::Failed => write!(f, "Failed"),
        }
    }
}

/// Arguments for show command
#[derive(Parser, Debug)]
pub struct ShowArgs {
    /// Proposal ID to show
    pub proposal_id: u64,

    /// Include all votes
    #[arg(long)]
    pub votes: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for params command
#[derive(Parser, Debug)]
pub struct ParamsArgs {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Arguments for voting history command
#[derive(Parser, Debug)]
pub struct VotingHistoryArgs {
    /// Address to query
    pub address: String,

    /// Limit number of results
    #[arg(long, default_value = "20")]
    pub limit: usize,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Execute governance commands
pub async fn execute(cmd: GovernanceCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        GovernanceCommands::Propose(args) => execute_propose(args, output_format).await,
        GovernanceCommands::Vote(args) => execute_vote(args, output_format).await,
        GovernanceCommands::Deposit(args) => execute_deposit(args, output_format).await,
        GovernanceCommands::List(args) => execute_list(args, output_format).await,
        GovernanceCommands::Show(args) => execute_show(args, output_format).await,
        GovernanceCommands::Params(args) => execute_params(args, output_format).await,
        GovernanceCommands::VotingHistory(args) => {
            execute_voting_history(args, output_format).await
        }
    }
}

/// Execute propose command
async fn execute_propose(args: ProposeArgs, output_format: OutputFormat) -> CliResult<()> {
    let deposit = parse_amount(&args.deposit)?;
    let client = RpcClient::new(&args.rpc)?;

    // Validate proposal type-specific arguments
    let content = match args.proposal_type {
        ProposalType::ParameterChange => {
            let key = args.param_key.ok_or_else(|| {
                CliError::InvalidArgument("--param-key required for parameter-change".to_string())
            })?;
            let value = args.param_value.ok_or_else(|| {
                CliError::InvalidArgument("--param-value required for parameter-change".to_string())
            })?;
            ProposalContent::ParameterChange { key, value }
        }
        ProposalType::SoftwareUpgrade => {
            let height = args.upgrade_height.ok_or_else(|| {
                CliError::InvalidArgument(
                    "--upgrade-height required for software-upgrade".to_string(),
                )
            })?;
            let name = args.upgrade_name.ok_or_else(|| {
                CliError::InvalidArgument(
                    "--upgrade-name required for software-upgrade".to_string(),
                )
            })?;
            ProposalContent::SoftwareUpgrade { height, name }
        }
        ProposalType::CommunitySpend => {
            let recipient = args.recipient.ok_or_else(|| {
                CliError::InvalidArgument("--recipient required for community-spend".to_string())
            })?;
            let amount = args.spend_amount.ok_or_else(|| {
                CliError::InvalidArgument("--spend-amount required for community-spend".to_string())
            })?;
            let amount = parse_amount(&amount)?;
            ProposalContent::CommunitySpend { recipient, amount }
        }
        ProposalType::Text => ProposalContent::Text,
    };

    print_info(&format!("Creating {} proposal...", args.proposal_type));

    if !args.yes {
        println!();
        println!("Proposal Details:");
        println!("  Type:        {}", args.proposal_type);
        println!("  Title:       {}", args.title);
        println!("  Description: {}", truncate_text(&args.description, 60));
        println!("  Deposit:     {}", format_balance(&deposit.to_string()));
        match &content {
            ProposalContent::ParameterChange { key, value } => {
                println!("  Parameter:   {} = {}", key, value);
            }
            ProposalContent::SoftwareUpgrade { height, name } => {
                println!("  Upgrade:     {} at block {}", name, height);
            }
            ProposalContent::CommunitySpend { recipient, amount } => {
                println!("  Recipient:   {}", recipient);
                println!("  Amount:      {}", format_balance(&amount.to_string()));
            }
            ProposalContent::Text => {}
        }
        println!();
        print_warning("Your deposit will be refunded if the proposal passes or is rejected.");
        print_warning(
            "If the proposal fails to meet quorum or is vetoed, the deposit may be burned.",
        );

        if !Confirm::new()
            .with_prompt("Submit this proposal?")
            .default(false)
            .interact()?
        {
            println!("Proposal cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let proposal = ProposalSubmission {
        proposal_type: format!("{:?}", args.proposal_type),
        title: args.title,
        description: args.description,
        deposit,
        content,
    };

    let (tx_hash, proposal_id) = client
        .send_proposal_transaction(&signer, proposal, args.gas, args.gas_price)
        .await?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "submitted",
                    "proposal_id": proposal_id,
                    "transaction_hash": tx_hash,
                }))?
            );
        }
        OutputFormat::Text => {
            print_success("Proposal submitted successfully!");
            println!();
            println!("  Proposal ID:       {}", proposal_id);
            println!("  Transaction Hash:  {}", tx_hash);
            println!();
            println!(
                "Use 'protocore governance show {}' to check status.",
                proposal_id
            );
        }
    }

    Ok(())
}

/// Execute vote command
async fn execute_vote(args: VoteArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    // Get proposal info first
    let proposal = client.get_proposal(args.proposal_id).await?;

    if proposal.status != "VotingPeriod" {
        return Err(CliError::InvalidArgument(format!(
            "Proposal {} is not in voting period (status: {})",
            args.proposal_id, proposal.status
        )));
    }

    print_info(&format!(
        "Voting {} on proposal {}...",
        args.vote, args.proposal_id
    ));

    if !args.yes {
        println!();
        println!("Proposal: {}", proposal.title);
        println!("Status:   {}", proposal.status);
        println!("Vote:     {}", args.vote);
        println!();

        if !Confirm::new()
            .with_prompt("Submit this vote?")
            .default(false)
            .interact()?
        {
            println!("Vote cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let vote_option = match args.vote {
        VoteOption::Yes => 1,
        VoteOption::No => 2,
        VoteOption::Abstain => 3,
        VoteOption::NoWithVeto => 4,
    };

    let tx_hash = client
        .send_vote_transaction(
            &signer,
            args.proposal_id,
            vote_option,
            args.gas,
            args.gas_price,
        )
        .await?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "submitted",
                    "proposal_id": args.proposal_id,
                    "vote": format!("{}", args.vote),
                    "transaction_hash": tx_hash,
                }))?
            );
        }
        OutputFormat::Text => {
            print_success(&format!(
                "Vote submitted: {} on proposal {}",
                args.vote, args.proposal_id
            ));
            println!();
            println!("  Transaction Hash: {}", tx_hash);
        }
    }

    Ok(())
}

/// Execute deposit command
async fn execute_deposit(args: DepositArgs, output_format: OutputFormat) -> CliResult<()> {
    let amount = parse_amount(&args.amount)?;
    let client = RpcClient::new(&args.rpc)?;

    // Get proposal info
    let proposal = client.get_proposal(args.proposal_id).await?;

    print_info(&format!(
        "Depositing {} to proposal {}...",
        format_balance(&amount.to_string()),
        args.proposal_id
    ));

    if !args.yes {
        println!();
        println!("Proposal: {}", proposal.title);
        println!("Status:   {}", proposal.status);
        println!(
            "Current Deposit: {}",
            format_balance(&proposal.total_deposit.to_string())
        );
        println!("Your Deposit:    {}", format_balance(&amount.to_string()));
        println!();

        if !Confirm::new()
            .with_prompt("Submit this deposit?")
            .default(false)
            .interact()?
        {
            println!("Deposit cancelled.");
            return Ok(());
        }
    }

    let keystore = args
        .keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    let signer = TransactionSigner::load(&keystore, &args.from)?;

    let tx_hash = client
        .send_deposit_transaction(&signer, args.proposal_id, amount, args.gas, args.gas_price)
        .await?;

    match output_format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "submitted",
                    "proposal_id": args.proposal_id,
                    "amount": amount.to_string(),
                    "transaction_hash": tx_hash,
                }))?
            );
        }
        OutputFormat::Text => {
            print_success(&format!(
                "Deposit submitted to proposal {}",
                args.proposal_id
            ));
            println!();
            println!("  Transaction Hash: {}", tx_hash);
        }
    }

    Ok(())
}

/// Execute list command
async fn execute_list(args: ListArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Querying proposals...");

    let status_filter = args.status.map(|s| format!("{:?}", s));
    let proposals = client
        .get_proposals(
            status_filter.as_deref(),
            args.proposer.as_deref(),
            args.limit,
        )
        .await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&proposals)?);
        }
        OutputFormat::Text => {
            if proposals.is_empty() {
                println!("No proposals found.");
            } else {
                println!("Proposals ({} found)", proposals.len());
                println!();
                println!(
                    "{:<6} {:<40} {:<20} {:<16}",
                    "ID", "TITLE", "TYPE", "STATUS"
                );
                println!("{}", "-".repeat(84));

                for p in &proposals {
                    println!(
                        "{:<6} {:<40} {:<20} {:<16}",
                        p.id,
                        truncate_text(&p.title, 38),
                        truncate_text(&p.proposal_type, 18),
                        p.status
                    );
                }
            }
        }
    }

    Ok(())
}

/// Execute show command
async fn execute_show(args: ShowArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!("Querying proposal {}...", args.proposal_id));

    let proposal = client.get_proposal(args.proposal_id).await?;

    let votes = if args.votes {
        Some(client.get_proposal_votes(args.proposal_id).await?)
    } else {
        None
    };

    match output_format {
        OutputFormat::Json => {
            let mut output = serde_json::to_value(&proposal)?;
            if let Some(v) = votes {
                output["votes"] = serde_json::to_value(v)?;
            }
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            println!("Proposal #{}", proposal.id);
            println!("===========");
            println!();
            println!("Title:       {}", proposal.title);
            println!("Type:        {}", proposal.proposal_type);
            println!("Status:      {}", proposal.status);
            println!("Proposer:    {}", proposal.proposer);
            println!();
            println!("Description:");
            println!("{}", wrap_text(&proposal.description, 80));
            println!();
            println!(
                "Deposit:     {} / {} (min)",
                format_balance(&proposal.total_deposit.to_string()),
                format_balance(&proposal.min_deposit.to_string())
            );
            println!();

            if let Some(ref content) = proposal.content {
                println!("Content:");
                println!("{}", serde_json::to_string_pretty(content)?);
                println!();
            }

            println!("Timeline:");
            println!(
                "  Submit Time:        {}",
                format_timestamp(proposal.submit_time)
            );
            if let Some(end) = proposal.deposit_end_time {
                println!("  Deposit End:        {}", format_timestamp(end));
            }
            if let Some(start) = proposal.voting_start_time {
                println!("  Voting Start:       {}", format_timestamp(start));
            }
            if let Some(end) = proposal.voting_end_time {
                println!("  Voting End:         {}", format_timestamp(end));
            }

            println!();
            println!("Voting Results:");
            println!(
                "  Yes:          {} ({:.1}%)",
                proposal.yes_votes, proposal.yes_percentage
            );
            println!(
                "  No:           {} ({:.1}%)",
                proposal.no_votes, proposal.no_percentage
            );
            println!(
                "  Abstain:      {} ({:.1}%)",
                proposal.abstain_votes, proposal.abstain_percentage
            );
            println!(
                "  No w/ Veto:   {} ({:.1}%)",
                proposal.veto_votes, proposal.veto_percentage
            );
            println!("  Turnout:      {:.1}%", proposal.turnout_percentage);

            if let Some(v) = votes {
                println!();
                println!("Individual Votes ({} total):", v.len());
                println!("{:<44} {:<12} {:<20}", "VOTER", "VOTE", "VOTING POWER");
                println!("{}", "-".repeat(78));
                for vote in v.iter().take(20) {
                    println!(
                        "{:<44} {:<12} {:<20}",
                        vote.voter,
                        vote.option,
                        format_balance(&vote.voting_power.to_string())
                    );
                }
                if v.len() > 20 {
                    println!("... and {} more votes", v.len() - 20);
                }
            }
        }
    }

    Ok(())
}

/// Execute params command
async fn execute_params(args: ParamsArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Querying governance parameters...");

    let params = client.get_governance_params().await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&params)?);
        }
        OutputFormat::Text => {
            println!("Governance Parameters");
            println!("=====================");
            println!();
            println!("Deposit:");
            println!(
                "  Minimum Deposit:    {}",
                format_balance(&params.min_deposit.to_string())
            );
            println!(
                "  Deposit Period:     {} blocks",
                params.deposit_period_blocks
            );
            println!();
            println!("Voting:");
            println!(
                "  Voting Period:      {} blocks",
                params.voting_period_blocks
            );
            println!(
                "  Quorum:             {:.1}%",
                params.quorum_bps as f64 / 100.0
            );
            println!(
                "  Threshold:          {:.1}%",
                params.threshold_bps as f64 / 100.0
            );
            println!(
                "  Veto Threshold:     {:.1}%",
                params.veto_threshold_bps as f64 / 100.0
            );
            println!();
            println!("Other:");
            println!(
                "  Expedited Enabled:  {}",
                if params.expedited_enabled {
                    "Yes"
                } else {
                    "No"
                }
            );
            if params.expedited_enabled {
                println!(
                    "  Expedited Quorum:   {:.1}%",
                    params.expedited_quorum_bps as f64 / 100.0
                );
                println!(
                    "  Expedited Threshold: {:.1}%",
                    params.expedited_threshold_bps as f64 / 100.0
                );
            }
        }
    }

    Ok(())
}

/// Execute voting history command
async fn execute_voting_history(
    args: VotingHistoryArgs,
    output_format: OutputFormat,
) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info(&format!(
        "Querying voting history for {}...",
        &args.address[..10]
    ));

    let history = client.get_voting_history(&args.address, args.limit).await?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&history)?);
        }
        OutputFormat::Text => {
            if history.is_empty() {
                println!("No voting history found for {}", args.address);
            } else {
                println!("Voting History for {}", args.address);
                println!();
                println!(
                    "{:<8} {:<40} {:<12} {:<16}",
                    "PROP ID", "TITLE", "VOTE", "TIMESTAMP"
                );
                println!("{}", "-".repeat(78));

                for vote in &history {
                    println!(
                        "{:<8} {:<40} {:<12} {:<16}",
                        vote.proposal_id,
                        truncate_text(&vote.proposal_title, 38),
                        vote.option,
                        format_timestamp(vote.timestamp)
                    );
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

fn truncate_text(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn wrap_text(s: &str, width: usize) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for word in s.split_whitespace() {
        if line_len + word.len() + 1 > width {
            result.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }

    result
}

// ============================================================================
// Data types
// ============================================================================

/// Proposal content
#[derive(Debug, serde::Serialize)]
pub enum ProposalContent {
    ParameterChange { key: String, value: String },
    SoftwareUpgrade { height: u64, name: String },
    CommunitySpend { recipient: String, amount: u128 },
    Text,
}

/// Proposal submission
#[derive(Debug, serde::Serialize)]
pub struct ProposalSubmission {
    pub proposal_type: String,
    pub title: String,
    pub description: String,
    pub deposit: u128,
    pub content: ProposalContent,
}

/// Proposal info from RPC
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProposalInfo {
    pub id: u64,
    pub proposal_type: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub proposer: String,
    pub total_deposit: u128,
    pub min_deposit: u128,
    pub submit_time: u64,
    pub deposit_end_time: Option<u64>,
    pub voting_start_time: Option<u64>,
    pub voting_end_time: Option<u64>,
    pub yes_votes: u128,
    pub no_votes: u128,
    pub abstain_votes: u128,
    pub veto_votes: u128,
    pub yes_percentage: f64,
    pub no_percentage: f64,
    pub abstain_percentage: f64,
    pub veto_percentage: f64,
    pub turnout_percentage: f64,
    pub content: Option<serde_json::Value>,
}

/// Vote entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VoteEntry {
    pub voter: String,
    pub option: String,
    pub voting_power: u128,
    pub timestamp: u64,
}

/// Governance parameters
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GovernanceParams {
    pub min_deposit: u128,
    pub deposit_period_blocks: u64,
    pub voting_period_blocks: u64,
    pub quorum_bps: u16,
    pub threshold_bps: u16,
    pub veto_threshold_bps: u16,
    pub expedited_enabled: bool,
    pub expedited_quorum_bps: u16,
    pub expedited_threshold_bps: u16,
}

/// Voting history entry
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VotingHistoryEntry {
    pub proposal_id: u64,
    pub proposal_title: String,
    pub option: String,
    pub timestamp: u64,
}
