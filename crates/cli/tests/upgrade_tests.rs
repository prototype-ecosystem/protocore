//! Tests for commands/upgrade.rs software upgrade management

use clap::Parser;
use protocore_cli::commands::upgrade::{StatusArgs, VoteArgs, HistoryArgs};

#[test]
fn test_status_args_default() {
    let args = StatusArgs::parse_from(["status"]);
    assert_eq!(args.rpc, "http://127.0.0.1:8545");
    assert!(!args.verbose);
}

#[test]
fn test_vote_args_yes() {
    let args = VoteArgs::parse_from([
        "vote", "42",
        "--yes",
        "--from", "0x1234"
    ]);
    assert_eq!(args.proposal_id, 42);
    assert!(args.yes);
    assert!(!args.no);
}

#[test]
fn test_vote_args_no() {
    let args = VoteArgs::parse_from([
        "vote", "42",
        "--no",
        "--from", "0x1234"
    ]);
    assert_eq!(args.proposal_id, 42);
    assert!(!args.yes);
    assert!(args.no);
}

#[test]
fn test_history_args() {
    let args = HistoryArgs::parse_from([
        "history",
        "--limit", "5"
    ]);
    assert_eq!(args.limit, 5);
}

// Note: estimate_time_to_block is a private function.
// If tests are needed, consider making it pub(crate).
