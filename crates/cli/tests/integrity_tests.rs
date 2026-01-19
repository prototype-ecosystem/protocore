//! Tests for commands/integrity.rs binary integrity verification

use clap::Parser;
use protocore_cli::commands::integrity::VerifyArgs;

#[test]
fn test_verify_args_default() {
    let args = VerifyArgs::parse_from(["verify"]);
    assert!(args.binary.is_none());
    assert_eq!(args.rpc, "http://127.0.0.1:8545");
    assert!(!args.verbose);
}

#[test]
fn test_verify_args_with_options() {
    let args = VerifyArgs::parse_from([
        "verify",
        "--binary", "/path/to/binary",
        "--rpc", "http://localhost:9000",
        "--verbose"
    ]);
    assert_eq!(args.binary, Some("/path/to/binary".to_string()));
    assert_eq!(args.rpc, "http://localhost:9000");
    assert!(args.verbose);
}

// Note: format_time_remaining and compute_sha256 are private functions.
// If tests for these are needed, consider making them pub(crate) or
// exposing them through a test module.
