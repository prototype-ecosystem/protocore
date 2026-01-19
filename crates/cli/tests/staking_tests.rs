//! Tests for commands/staking.rs staking operations

use clap::Parser;
use protocore_cli::commands::staking::{StakeArgs, DelegateArgs, CreateValidatorArgs};

#[test]
fn test_stake_args() {
    let args = StakeArgs::parse_from(["stake", "1000", "--from", "0x1234"]);
    assert_eq!(args.amount, "1000");
    assert_eq!(args.from, "0x1234");
}

#[test]
fn test_delegate_args() {
    let args = DelegateArgs::parse_from([
        "delegate",
        "1000",
        "--validator", "0xvalidator",
        "--from", "0x1234"
    ]);
    assert_eq!(args.amount, "1000");
    assert_eq!(args.validator, "0xvalidator");
}

#[test]
fn test_create_validator_args() {
    let args = CreateValidatorArgs::parse_from([
        "create-validator",
        "--amount", "100000",
        "--commission", "1000",
        "--bls-pubkey", "0xabcdef",
        "--from", "0x1234"
    ]);
    assert_eq!(args.amount, "100000");
    assert_eq!(args.commission, 1000);
}
