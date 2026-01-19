//! Tests for commands/mod.rs CLI parsing

use clap::{CommandFactory, Parser};
use protocore_cli::commands::{
    Cli, Commands,
    keys::KeysCommands,
    query::QueryCommands,
    integrity::IntegrityCommands,
    integrity::AttestationCommands,
    upgrade::UpgradeCommands,
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
    assert!(matches!(cli.command, Commands::Keys(KeysCommands::Generate { .. })));
}

#[test]
fn test_parse_query_block() {
    let cli = Cli::parse_from(["protocore", "query", "block", "100"]);
    assert!(matches!(cli.command, Commands::Query(QueryCommands::Block { .. })));
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
    assert!(matches!(cli.command, Commands::Integrity(IntegrityCommands::Verify(_))));
}

#[test]
fn test_parse_integrity_attestation_status() {
    let cli = Cli::parse_from(["protocore", "integrity", "attestation", "status"]);
    assert!(matches!(
        cli.command,
        Commands::Integrity(IntegrityCommands::Attestation(
            AttestationCommands::Status(_)
        ))
    ));
}

#[test]
fn test_parse_upgrade_status() {
    let cli = Cli::parse_from(["protocore", "upgrade", "status"]);
    assert!(matches!(cli.command, Commands::Upgrade(UpgradeCommands::Status(_))));
}

#[test]
fn test_parse_upgrade_vote_yes() {
    let cli = Cli::parse_from([
        "protocore", "upgrade", "vote", "42",
        "--yes", "--from", "0x1234"
    ]);
    match cli.command {
        Commands::Upgrade(UpgradeCommands::Vote(args)) => {
            assert_eq!(args.proposal_id, 42);
            assert!(args.yes);
            assert!(!args.no);
        }
        _ => panic!("Expected Upgrade Vote command"),
    }
}

#[test]
fn test_parse_upgrade_vote_no() {
    let cli = Cli::parse_from([
        "protocore", "upgrade", "vote", "42",
        "--no", "--from", "0x1234"
    ]);
    match cli.command {
        Commands::Upgrade(UpgradeCommands::Vote(args)) => {
            assert_eq!(args.proposal_id, 42);
            assert!(!args.yes);
            assert!(args.no);
        }
        _ => panic!("Expected Upgrade Vote command"),
    }
}

#[test]
fn test_parse_upgrade_history() {
    let cli = Cli::parse_from(["protocore", "upgrade", "history", "--limit", "5"]);
    match cli.command {
        Commands::Upgrade(UpgradeCommands::History(args)) => {
            assert_eq!(args.limit, 5);
        }
        _ => panic!("Expected Upgrade History command"),
    }
}
