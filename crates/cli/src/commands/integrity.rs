//! Binary integrity verification commands.
//!
//! This module provides commands for verifying the integrity of the protocore binary:
//! - Verify binary hash against known signatures
//! - Check attestation status and challenge timing
//! - Ensure the running binary is authorized by the network

use clap::{Parser, Subcommand};
use console::style;
use std::env;

use crate::utils::{
    format_timestamp, CliError, CliResult, OutputFormat, RpcClient,
    print_info, print_success, print_warning, print_error,
};

/// Integrity verification subcommands
#[derive(Subcommand, Debug)]
pub enum IntegrityCommands {
    /// Verify current binary integrity
    Verify(VerifyArgs),

    /// Attestation-related commands
    #[command(subcommand)]
    Attestation(AttestationCommands),
}

/// Attestation subcommands
#[derive(Subcommand, Debug)]
pub enum AttestationCommands {
    /// Check attestation status
    Status(AttestationStatusArgs),
}

/// Arguments for verify command
#[derive(Parser, Debug)]
pub struct VerifyArgs {
    /// Path to binary (default: current executable)
    #[arg(long)]
    pub binary: Option<String>,

    /// RPC endpoint for signature verification
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Show detailed verification information
    #[arg(long, short)]
    pub verbose: bool,
}

/// Arguments for attestation status command
#[derive(Parser, Debug)]
pub struct AttestationStatusArgs {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Execute integrity commands
pub async fn execute(cmd: IntegrityCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        IntegrityCommands::Verify(args) => execute_verify(args, output_format).await,
        IntegrityCommands::Attestation(cmd) => execute_attestation(cmd, output_format).await,
    }
}

/// Execute attestation subcommands
async fn execute_attestation(cmd: AttestationCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        AttestationCommands::Status(args) => execute_attestation_status(args, output_format).await,
    }
}

/// Execute verify command
async fn execute_verify(args: VerifyArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    // Get the binary path
    let binary_path = match args.binary {
        Some(ref path) => std::path::PathBuf::from(path),
        None => env::current_exe()
            .map_err(|e| CliError::Other(format!("Failed to get current executable: {}", e)))?,
    };

    if !binary_path.exists() {
        return Err(CliError::FileNotFound(binary_path.to_string_lossy().to_string()));
    }

    print_info("Verifying binary integrity...");

    // Read the binary and compute hash
    let binary_data = std::fs::read(&binary_path)
        .map_err(|e| CliError::Io(e))?;

    let binary_hash = compute_sha256(&binary_data);

    // Query the network for authorized binary hashes and signatures
    let verification_result = client.verify_binary_integrity(&binary_hash).await?;

    match output_format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "binary": binary_path.to_string_lossy(),
                "version": env!("CARGO_PKG_VERSION"),
                "hash": binary_hash,
                "verified": verification_result.verified,
                "signatures": {
                    "valid": verification_result.valid_signatures,
                    "required": verification_result.required_signatures,
                },
                "signers": verification_result.signers,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            println!("Binary: protocore v{}", env!("CARGO_PKG_VERSION"));
            println!("Hash:   {}...", &binary_hash[..40]);

            if verification_result.verified {
                println!("Status: {} Verified ({}/{} signatures)",
                    style("✓").green().bold(),
                    verification_result.valid_signatures,
                    verification_result.required_signatures
                );
            } else {
                println!("Status: {} Unverified ({}/{} signatures)",
                    style("✗").red().bold(),
                    verification_result.valid_signatures,
                    verification_result.required_signatures
                );
            }

            if args.verbose {
                println!();
                println!("Signers:");
                for signer in &verification_result.signers {
                    let status_icon = if signer.valid {
                        style("✓").green()
                    } else {
                        style("✗").red()
                    };
                    println!("  {} {} ({})",
                        status_icon,
                        signer.address,
                        signer.name
                    );
                }
            }

            if !verification_result.verified {
                println!();
                print_warning("Binary is not fully verified. This may indicate:");
                println!("  - Running an unofficial or modified binary");
                println!("  - Binary hash not yet registered on-chain");
                println!("  - Insufficient signer participation");
            }
        }
    }

    Ok(())
}

/// Execute attestation status command
async fn execute_attestation_status(args: AttestationStatusArgs, output_format: OutputFormat) -> CliResult<()> {
    let client = RpcClient::new(&args.rpc)?;

    print_info("Checking attestation status...");

    let attestation_status = client.get_attestation_status().await?;

    match output_format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "last_attestation": attestation_status.last_attestation_time,
                "last_attestation_formatted": format_timestamp(attestation_status.last_attestation_time),
                "binary_verified": attestation_status.binary_verified,
                "next_challenge_seconds": attestation_status.next_challenge_seconds,
                "challenge_window_seconds": attestation_status.challenge_window_seconds,
                "attestation_required": attestation_status.attestation_required,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            // Format last attestation
            let last_attestation = format_timestamp(attestation_status.last_attestation_time);

            // Format next challenge time
            let next_challenge = format_time_remaining(attestation_status.next_challenge_seconds);

            println!("Last attestation: {}", last_attestation);

            // Binary verified status with icon
            let verified_icon = if attestation_status.binary_verified {
                style("✓").green().bold()
            } else {
                style("✗").red().bold()
            };
            println!("Binary verified:  {}", verified_icon);

            // Next challenge time
            println!("Next challenge:   in {}", next_challenge);

            if attestation_status.attestation_required {
                println!();
                print_warning("Attestation is required soon. Ensure your node is running with a verified binary.");
            }

            if !attestation_status.binary_verified {
                println!();
                print_error("Binary is not verified! Run 'protocore integrity verify' for details.");
            }
        }
    }

    Ok(())
}

/// Compute SHA-256 hash of data
fn compute_sha256(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Format remaining seconds as human-readable time
fn format_time_remaining(seconds: u64) -> String {
    if seconds < 60 {
        format!("{} seconds", seconds)
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        format!("{} minute{}", minutes, if minutes == 1 { "" } else { "s" })
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        if minutes > 0 {
            format!("{} hour{} {} minute{}",
                hours, if hours == 1 { "" } else { "s" },
                minutes, if minutes == 1 { "" } else { "s" })
        } else {
            format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
        }
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        if hours > 0 {
            format!("{} day{} {} hour{}",
                days, if days == 1 { "" } else { "s" },
                hours, if hours == 1 { "" } else { "s" })
        } else {
            format!("{} day{}", days, if days == 1 { "" } else { "s" })
        }
    }
}

// ============================================================================
// Data types
// ============================================================================

/// Binary verification result
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BinaryVerificationResult {
    /// Whether the binary is fully verified
    pub verified: bool,
    /// Number of valid signatures found
    pub valid_signatures: u32,
    /// Number of signatures required for verification
    pub required_signatures: u32,
    /// List of signers and their verification status
    pub signers: Vec<SignerInfo>,
}

/// Signer information
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignerInfo {
    /// Signer address
    pub address: String,
    /// Human-readable name (if known)
    pub name: String,
    /// Whether this signer's signature is valid
    pub valid: bool,
}

/// Attestation status
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestationStatus {
    /// Timestamp of last successful attestation
    pub last_attestation_time: u64,
    /// Whether the current binary is verified
    pub binary_verified: bool,
    /// Seconds until next challenge
    pub next_challenge_seconds: u64,
    /// Challenge window duration in seconds
    pub challenge_window_seconds: u64,
    /// Whether attestation is required soon
    pub attestation_required: bool,
}

