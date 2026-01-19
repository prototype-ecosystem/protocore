//! Tests for consensus-specific types.
//!
//! These tests verify the core data structures used in the MinBFT consensus protocol
//! including validators, validator sets, votes, and finality certificates.

use protocore_consensus::{
    domains, FinalityCert, NIL_HASH, ValidatorId, ValidatorSet, Validator, Vote, VoteType,
};
use protocore_crypto::bls::BlsPrivateKey;

fn create_test_validator_set(n: usize) -> ValidatorSet {
    let validators: Vec<Validator> = (0..n)
        .map(|i| {
            let key = BlsPrivateKey::random();
            Validator::new(
                i as ValidatorId,
                key.public_key(),
                [i as u8; 20],
                1000,
                500, // 5% commission
            )
        })
        .collect();
    ValidatorSet::new(validators)
}

#[test]
fn test_proposer_selection() {
    let vs = create_test_validator_set(4);

    // Round-robin selection: (height + round) % n
    assert_eq!(vs.proposer_id(0, 0), 0);
    assert_eq!(vs.proposer_id(0, 1), 1);
    assert_eq!(vs.proposer_id(1, 0), 1);
    assert_eq!(vs.proposer_id(1, 1), 2);
    assert_eq!(vs.proposer_id(4, 0), 0); // Wraps around
}

#[test]
fn test_quorum_calculation() {
    // n = 4 validators with equal stake
    let vs = create_test_validator_set(4);
    // Total stake = 4000
    // Quorum = (4000 * 2 / 3) + 1 = 2667
    // So we need 3 validators (3000 stake)
    assert_eq!(vs.quorum_stake(), 2667);
}

#[test]
fn test_byzantine_tolerance() {
    // n = 4 = 3*1 + 1, so f = 1
    let vs4 = create_test_validator_set(4);
    assert_eq!(vs4.max_byzantine(), 1);
    assert_eq!(vs4.min_honest(), 3);

    // n = 7 = 3*2 + 1, so f = 2
    let vs7 = create_test_validator_set(7);
    assert_eq!(vs7.max_byzantine(), 2);
    assert_eq!(vs7.min_honest(), 5);

    // n = 51 = 3*17, so f = 16 (with n-1 = 50 = 3*16 + 2)
    let vs51 = create_test_validator_set(51);
    assert_eq!(vs51.max_byzantine(), 16);
    assert_eq!(vs51.min_honest(), 35);
}

#[test]
fn test_finality_cert_signers() {
    let mut cert = FinalityCert::default();
    // Set bits for validators 0, 2, 5
    cert.signers_bitmap = vec![0b00100101]; // Bits 0, 2, 5

    let signers = cert.get_signers();
    assert_eq!(signers, vec![0, 2, 5]);
    assert_eq!(cert.signer_count(), 3);
}

#[test]
fn test_vote_signing_bytes() {
    let vote = Vote::new(VoteType::Prevote, 100, 2, [1u8; 32], 5);
    let bytes = vote.signing_bytes();

    // Should be: domain (21) + height (8) + round (8) + block_hash (32) = 69 bytes
    // Domain separators prevent cross-protocol signature replay attacks
    // Note: The domain implicitly encodes the vote type, so vote_type byte is not separately included
    let expected_len = domains::PREVOTE.len() + 8 + 8 + 32;
    assert_eq!(bytes.len(), expected_len);

    // Verify domain prefix is correct
    assert_eq!(&bytes[..domains::PREVOTE.len()], domains::PREVOTE);
}

#[test]
fn test_nil_vote() {
    let vote = Vote::new(VoteType::Prevote, 100, 0, NIL_HASH, 0);
    assert!(vote.is_nil());

    let vote2 = Vote::new(VoteType::Prevote, 100, 0, [1u8; 32], 0);
    assert!(!vote2.is_nil());
}
