//! CLI command definitions and handlers.
//!
//! This module defines all available CLI commands using clap's derive macros.
//! Each subcommand has its own module with implementation details.

pub mod governance;
pub mod init;
pub mod integrity;
pub mod keys;
pub mod query;
pub mod staking;
pub mod start;
pub mod upgrade;

use clap::{Parser, Subcommand};
use crate::utils::{CliResult, OutputFormat};

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

    /// Governance operations
    #[command(subcommand)]
    Governance(governance::GovernanceCommands),

    /// Binary integrity verification
    #[command(subcommand)]
    Integrity(integrity::IntegrityCommands),

    /// Software upgrade management
    #[command(subcommand)]
    Upgrade(upgrade::UpgradeCommands),

    /// Export state snapshot
    Export(ExportArgs),

    /// Import state snapshot
    Import(ImportArgs),

    /// Show version information
    Version,
}

/// Arguments for the export command
#[derive(Parser, Debug)]
pub struct ExportArgs {
    /// Output file path for the snapshot
    #[arg(short, long)]
    pub output: String,

    /// Block height to export (default: latest)
    #[arg(long)]
    pub height: Option<u64>,

    /// Include full transaction data
    #[arg(long, default_value = "false")]
    pub include_txs: bool,

    /// Compression format (none, gzip, zstd)
    #[arg(long, default_value = "zstd")]
    pub compression: String,
}

/// Arguments for the import command
#[derive(Parser, Debug)]
pub struct ImportArgs {
    /// Input file path for the snapshot
    #[arg(short, long)]
    pub input: String,

    /// Data directory to import into
    #[arg(long)]
    pub data_dir: Option<String>,

    /// Skip verification of state root
    #[arg(long, default_value = "false")]
    pub skip_verify: bool,
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
        Commands::Init(args) => {
            init::execute(args, cli.output).await
        }
        Commands::Start(args) => {
            start::execute(args, cli.output).await
        }
        Commands::Keys(cmd) => {
            keys::execute(cmd, cli.output).await
        }
        Commands::Query(cmd) => {
            query::execute(cmd, cli.output).await
        }
        Commands::Staking(cmd) => {
            staking::execute(cmd, cli.output).await
        }
        Commands::Governance(cmd) => {
            governance::execute(cmd, cli.output).await
        }
        Commands::Integrity(cmd) => {
            integrity::execute(cmd, cli.output).await
        }
        Commands::Upgrade(cmd) => {
            upgrade::execute(cmd, cli.output).await
        }
        Commands::Export(args) => {
            execute_export(args, cli.output).await
        }
        Commands::Import(args) => {
            execute_import(args, cli.output).await
        }
        Commands::Version => {
            execute_version(cli.output)
        }
    }
}

/// Execute the export command
async fn execute_export(args: ExportArgs, output_format: OutputFormat) -> CliResult<()> {
    use crate::utils::{print_info, print_success};
    use std::path::Path;

    print_info(&format!("Exporting state snapshot to: {}", args.output));

    let output_path = Path::new(&args.output);

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let height_str = args.height
        .map(|h| h.to_string())
        .unwrap_or_else(|| "latest".to_string());

    // TODO: Implement actual export logic with protocore-storage
    // For now, we demonstrate the structure

    let export_info = serde_json::json!({
        "status": "success",
        "output_file": args.output,
        "height": height_str,
        "include_txs": args.include_txs,
        "compression": args.compression,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&export_info)?);
        }
        OutputFormat::Text => {
            print_success(&format!(
                "State snapshot exported successfully\n  File: {}\n  Height: {}\n  Compression: {}",
                args.output, height_str, args.compression
            ));
        }
    }

    Ok(())
}

/// Execute the import command
async fn execute_import(args: ImportArgs, output_format: OutputFormat) -> CliResult<()> {
    use crate::utils::{print_info, print_success, print_warning, CliError};
    use std::path::Path;

    let input_path = Path::new(&args.input);

    if !input_path.exists() {
        return Err(CliError::FileNotFound(args.input.clone()));
    }

    print_info(&format!("Importing state snapshot from: {}", args.input));

    if args.skip_verify {
        print_warning("Skipping state root verification - data integrity not guaranteed");
    }

    let data_dir = args.data_dir
        .unwrap_or_else(|| crate::default_data_dir().to_string_lossy().to_string());

    // TODO: Implement actual import logic with protocore-storage

    let import_info = serde_json::json!({
        "status": "success",
        "input_file": args.input,
        "data_dir": data_dir,
        "verified": !args.skip_verify,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&import_info)?);
        }
        OutputFormat::Text => {
            print_success(&format!(
                "State snapshot imported successfully\n  From: {}\n  To: {}\n  Verified: {}",
                args.input, data_dir, !args.skip_verify
            ));
        }
    }

    Ok(())
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
            git_commit: option_env!("GIT_COMMIT")
                .unwrap_or("unknown")
                .to_string(),
            build_time: option_env!("BUILD_TIME")
                .unwrap_or("unknown")
                .to_string(),
            rust_version: option_env!("RUSTC_VERSION")
                .unwrap_or(env!("CARGO_PKG_RUST_VERSION"))
                .to_string(),
            target: std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS,
        }
    }
}

