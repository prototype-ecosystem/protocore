//! Tests for commands/start.rs node startup functionality

use clap::Parser;
use protocore_cli::commands::start::StartArgs;

#[test]
fn test_sync_mode_parsing() {
    // SyncMode is a private enum, test through StartArgs parsing
    let args = StartArgs::parse_from(["start", "--config", "test.toml", "--sync-mode", "full"]);
    assert_eq!(args.sync_mode, "full");

    let args = StartArgs::parse_from(["start", "--config", "test.toml", "--sync-mode", "fast"]);
    assert_eq!(args.sync_mode, "fast");

    let args = StartArgs::parse_from(["start", "--config", "test.toml", "--sync-mode", "light"]);
    assert_eq!(args.sync_mode, "light");
}

#[test]
fn test_start_args_defaults() {
    let args = StartArgs::parse_from(["start", "--config", "test.toml"]);
    assert_eq!(args.config, "test.toml");
    assert!(!args.validator);
    assert!(!args.no_rpc);
    assert!(!args.no_network);
    assert_eq!(args.sync_mode, "full");
}

#[test]
fn test_start_args_validator() {
    let args = StartArgs::parse_from([
        "start",
        "--config",
        "test.toml",
        "--validator",
        "--validator-key",
        "/path/to/key",
    ]);
    assert!(args.validator);
    assert_eq!(args.validator_key, Some("/path/to/key".to_string()));
}
