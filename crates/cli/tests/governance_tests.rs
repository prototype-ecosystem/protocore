//! Tests for commands/governance.rs governance operations

use clap::Parser;
use protocore_cli::commands::governance::{
    ProposalType, VoteOption, VoteArgs,
};

#[test]
fn test_proposal_type_display() {
    assert_eq!(format!("{}", ProposalType::ParameterChange), "Parameter Change");
    assert_eq!(format!("{}", ProposalType::SoftwareUpgrade), "Software Upgrade");
    assert_eq!(format!("{}", ProposalType::CommunitySpend), "Community Spend");
    assert_eq!(format!("{}", ProposalType::Text), "Text");
}

#[test]
fn test_vote_option_display() {
    assert_eq!(format!("{}", VoteOption::Yes), "Yes");
    assert_eq!(format!("{}", VoteOption::No), "No");
    assert_eq!(format!("{}", VoteOption::Abstain), "Abstain");
    assert_eq!(format!("{}", VoteOption::NoWithVeto), "No With Veto");
}

#[test]
fn test_vote_args() {
    let args = VoteArgs::parse_from([
        "vote",
        "--proposal-id", "1",
        "--vote", "yes",
        "--from", "0x1234"
    ]);
    assert_eq!(args.proposal_id, 1);
    assert!(matches!(args.vote, VoteOption::Yes));
}

// Note: truncate_text and wrap_text are private helper functions.
// If tests for these are needed, consider making them pub(crate).
