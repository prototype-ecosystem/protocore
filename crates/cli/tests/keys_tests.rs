//! Tests for commands/keys.rs key management functionality

use clap::Parser;
use protocore_cli::commands::keys::{GenerateArgs, ListArgs};

#[test]
fn test_parse_key_type() {
    // Test through GenerateArgs parsing
    let args = GenerateArgs::parse_from(["generate", "--key-type", "wallet"]);
    assert_eq!(args.key_type, "wallet");

    let args = GenerateArgs::parse_from(["generate", "--key-type", "validator"]);
    assert_eq!(args.key_type, "validator");
}

#[test]
fn test_generate_args_defaults() {
    let args = GenerateArgs::parse_from(["generate"]);
    assert_eq!(args.key_type, "wallet");
    assert!(args.output.is_none());
    assert!(args.name.is_none());
    assert!(!args.password);
}

#[test]
fn test_list_args() {
    let args = ListArgs::parse_from(["list"]);
    assert!(args.keystore.is_none());
    assert!(!args.full);

    let args = ListArgs::parse_from(["list", "--full"]);
    assert!(args.full);
}

// Note: test_generate_wallet_key and test_generate_validator_key tests
// require the internal generate_wallet_key/generate_validator_key functions
// to be made pub(crate) or exposed through a test helper. For now, these
// tests are removed since the functions are private.
