//! CLI command definitions and handlers.
//!
//! This module defines all available CLI commands using clap's derive macros.
//! Each subcommand has its own module with implementation details.

pub mod init;
pub mod integrity;
pub mod keys;
pub mod query;
pub mod staking;
pub mod start;

use crate::utils::{CliResult, OutputFormat};
use clap::{Parser, Subcommand};

/// Proto Core - A high-performance blockchain implementation
#[derive(Parser, Debug)]
#[command(name = "protocore")]
#[command(author = "Proto Core Team")]
#[command(version)]
#[command(about = "Proto Core node and command-line tools", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Global output format for command results
    #[arg(global = true, long, value_enum, default_value = "text")]
    pub output: OutputFormat,

    /// Enable verbose logging
    #[arg(global = true, short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress all output except errors
    #[arg(global = true, short, long)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new Proto Core node
    Init(init::InitArgs),

    /// Start the Proto Core node
    Start(start::StartArgs),

    /// Key management commands
    #[command(subcommand)]
    Keys(keys::KeysCommands),

    /// Query blockchain state
    #[command(subcommand)]
    Query(query::QueryCommands),

    /// Staking operations
    #[command(subcommand)]
    Staking(staking::StakingCommands),

    /// Binary integrity verification
    #[command(subcommand)]
    Integrity(integrity::IntegrityCommands),

    /// Show version information
    Version,
}

/// Execute the CLI with parsed arguments
pub async fn run_cli(cli: Cli) -> CliResult<()> {
    // Set up logging based on verbosity
    let log_level = match (cli.quiet, cli.verbose) {
        (true, _) => tracing::Level::ERROR,
        (_, 0) => tracing::Level::INFO,
        (_, 1) => tracing::Level::DEBUG,
        (_, _) => tracing::Level::TRACE,
    };

    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(cli.verbose >= 2)
        .init();

    match cli.command {
        Commands::Init(args) => init::execute(args, cli.output).await,
        Commands::Start(args) => start::execute(args, cli.output).await,
        Commands::Keys(cmd) => keys::execute(cmd, cli.output).await,
        Commands::Query(cmd) => query::execute(cmd, cli.output).await,
        Commands::Staking(cmd) => staking::execute(cmd, cli.output).await,
        Commands::Integrity(cmd) => integrity::execute(cmd, cli.output).await,
        Commands::Version => execute_version(cli.output),
    }
}

/// Execute the version command
fn execute_version(output_format: OutputFormat) -> CliResult<()> {
    let version_info = VersionInfo::new();

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&version_info)?);
        }
        OutputFormat::Text => {
            println!("Proto Core CLI");
            println!("  Version:     {}", version_info.version);
            println!("  Git Commit:  {}", version_info.git_commit);
            println!("  Build Time:  {}", version_info.build_time);
            println!("  Rust:        {}", version_info.rust_version);
            println!("  Target:      {}", version_info.target);
        }
    }

    Ok(())
}

/// Version information structure
#[derive(Debug, serde::Serialize)]
struct VersionInfo {
    version: String,
    git_commit: String,
    build_time: String,
    rust_version: String,
    target: String,
}

impl VersionInfo {
    fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            build_time: option_env!("BUILD_TIME").unwrap_or("unknown").to_string(),
            rust_version: option_env!("RUSTC_VERSION")
                .unwrap_or(env!("CARGO_PKG_RUST_VERSION"))
                .to_string(),
            target: std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS,
        }
    }
}
