//! Tests for commands/mod.rs CLI parsing

use clap::{CommandFactory, Parser};
use protocore_cli::commands::{
    integrity::AttestationCommands, integrity::IntegrityCommands, keys::KeysCommands,
    query::QueryCommands, Cli, Commands,
};
use protocore_cli::OutputFormat;

#[test]
fn verify_cli() {
    Cli::command().debug_assert();
}

#[test]
fn test_parse_init() {
    let cli = Cli::parse_from(["protocore", "init", "--data-dir", "/tmp/test"]);
    assert!(matches!(cli.command, Commands::Init(_)));
}

#[test]
fn test_parse_start() {
    let cli = Cli::parse_from(["protocore", "start", "--config", "config.toml"]);
    assert!(matches!(cli.command, Commands::Start(_)));
}

#[test]
fn test_parse_keys_generate() {
    let cli = Cli::parse_from(["protocore", "keys", "generate", "--key-type", "wallet"]);
    assert!(matches!(
        cli.command,
        Commands::Keys(KeysCommands::Generate { .. })
    ));
}

#[test]
fn test_parse_query_block() {
    let cli = Cli::parse_from(["protocore", "query", "block", "100"]);
    assert!(matches!(
        cli.command,
        Commands::Query(QueryCommands::Block { .. })
    ));
}

#[test]
fn test_output_format() {
    let cli = Cli::parse_from(["protocore", "--output", "json", "version"]);
    assert!(matches!(cli.output, OutputFormat::Json));
}

#[test]
fn test_verbose_flags() {
    let cli = Cli::parse_from(["protocore", "-vv", "version"]);
    assert_eq!(cli.verbose, 2);
}

#[test]
fn test_parse_integrity_verify() {
    let cli = Cli::parse_from(["protocore", "integrity", "verify"]);
    assert!(matches!(
        cli.command,
        Commands::Integrity(IntegrityCommands::Verify(_))
    ));
}

#[test]
fn test_parse_integrity_attestation_status() {
    let cli = Cli::parse_from(["protocore", "integrity", "attestation", "status"]);
    assert!(matches!(
        cli.command,
        Commands::Integrity(IntegrityCommands::Attestation(AttestationCommands::Status(
            _
        )))
    ));
}

