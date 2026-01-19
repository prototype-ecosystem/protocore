//! Integration tests for governance precompile

use protocore_evm::precompiles::governance::{
    ProposalType, VoteSupport, PASS_THRESHOLD, PROPOSAL_DEPOSIT, PROPOSAL_THRESHOLD,
    QUORUM_PERCENTAGE, VOTING_DELAY, VOTING_PERIOD,
};

#[test]
fn test_proposal_type_conversion() {
    assert_eq!(
        ProposalType::try_from(0).unwrap(),
        ProposalType::ParameterChange
    );
    assert_eq!(ProposalType::try_from(1).unwrap(), ProposalType::Upgrade);
    assert_eq!(ProposalType::try_from(2).unwrap(), ProposalType::Treasury);
    assert_eq!(ProposalType::try_from(3).unwrap(), ProposalType::Text);
    assert!(ProposalType::try_from(4).is_err());
}

#[test]
fn test_vote_support_conversion() {
    assert_eq!(VoteSupport::try_from(0).unwrap(), VoteSupport::Against);
    assert_eq!(VoteSupport::try_from(1).unwrap(), VoteSupport::For);
    assert_eq!(VoteSupport::try_from(2).unwrap(), VoteSupport::Abstain);
    assert!(VoteSupport::try_from(3).is_err());
}

#[test]
fn test_governance_constants() {
    assert_eq!(PROPOSAL_THRESHOLD, 10_000 * 10u128.pow(18));
    assert_eq!(PROPOSAL_DEPOSIT, 1_000 * 10u128.pow(18));
    assert_eq!(VOTING_DELAY, 100);
    assert_eq!(VOTING_PERIOD, 21600);
    assert_eq!(QUORUM_PERCENTAGE, 33);
    assert_eq!(PASS_THRESHOLD, 50);
}
