//! Tests for commands/query.rs blockchain query functionality

use clap::Parser;
use protocore_cli::commands::query::{AccountArgs, BlockArgs};

#[test]
fn test_parse_block_param() {
    // Test various block parameter parsing through BlockArgs
    let args = BlockArgs::parse_from(["block", "latest"]);
    assert_eq!(args.block, "latest");

    let args = BlockArgs::parse_from(["block", "earliest"]);
    assert_eq!(args.block, "earliest");

    let args = BlockArgs::parse_from(["block", "pending"]);
    assert_eq!(args.block, "pending");

    let args = BlockArgs::parse_from(["block", "100"]);
    assert_eq!(args.block, "100");

    let args = BlockArgs::parse_from(["block", "0x64"]);
    assert_eq!(args.block, "0x64");
}

#[test]
fn test_block_args_default() {
    let args = BlockArgs::parse_from(["block"]);
    assert_eq!(args.block, "latest");
    assert!(!args.full);
}

#[test]
fn test_account_args() {
    let args = AccountArgs::parse_from(["account", "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"]);
    assert_eq!(args.address, "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1");
    assert!(args.block.is_none());
}
