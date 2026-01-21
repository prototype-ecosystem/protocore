//! Tests for vote collection and quorum detection.
//!
//! These tests verify the vote set functionality including:
//! - Collecting votes from validators
//! - Detecting quorum conditions
//! - Signature verification
//! - Aggregated signature creation

use protocore_consensus::{
    HeightVoteSet, Validator, ValidatorId, ValidatorSet, Vote, VoteSet, VoteSetError, VoteType,
    NIL_HASH,
};
use protocore_crypto::bls::BlsPrivateKey;

fn create_test_validator_set(n: usize) -> (ValidatorSet, Vec<BlsPrivateKey>) {
    let mut validators = Vec::new();
    let mut keys = Vec::new();

    for i in 0..n {
        let key = BlsPrivateKey::random();
        validators.push(Validator::new(
            i as ValidatorId,
            key.public_key(),
            [i as u8; 20],
            1000, // Equal stake
            500,
        ));
        keys.push(key);
    }

    (ValidatorSet::new(validators), keys)
}

fn create_signed_vote(
    vote_type: VoteType,
    height: u64,
    round: u64,
    block_hash: [u8; 32],
    validator_id: ValidatorId,
    key: &BlsPrivateKey,
) -> Vote {
    let mut vote = Vote::new(vote_type, height, round, block_hash, validator_id);
    vote.signature = key.sign(&vote.signing_bytes());
    vote
}

#[test]
fn test_vote_set_basic() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote);

    let block_hash = [1u8; 32];

    // Add first vote - no quorum yet
    let vote1 = create_signed_vote(VoteType::Prevote, 1, 0, block_hash, 0, &keys[0]);
    let result = vote_set.add_vote(vote1, &vs).unwrap();
    assert!(result.is_none());
    assert_eq!(vote_set.vote_count(), 1);

    // Add second vote - no quorum yet
    let vote2 = create_signed_vote(VoteType::Prevote, 1, 0, block_hash, 1, &keys[1]);
    let result = vote_set.add_vote(vote2, &vs).unwrap();
    assert!(result.is_none());
    assert_eq!(vote_set.vote_count(), 2);

    // Add third vote - should reach quorum (3/4 = 75% > 66.67%)
    let vote3 = create_signed_vote(VoteType::Prevote, 1, 0, block_hash, 2, &keys[2]);
    let result = vote_set.add_vote(vote3, &vs).unwrap();
    assert_eq!(result, Some(block_hash));
    assert_eq!(vote_set.vote_count(), 3);
}

#[test]
fn test_duplicate_vote_rejected() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote);

    let block_hash = [1u8; 32];
    let vote = create_signed_vote(VoteType::Prevote, 1, 0, block_hash, 0, &keys[0]);

    // First vote succeeds
    vote_set.add_vote(vote.clone(), &vs).unwrap();

    // Duplicate vote fails
    let result = vote_set.add_vote(vote, &vs);
    assert!(matches!(result, Err(VoteSetError::DuplicateVote(0))));
}

#[test]
fn test_wrong_height_rejected() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote);

    let vote = create_signed_vote(VoteType::Prevote, 2, 0, [1u8; 32], 0, &keys[0]);
    let result = vote_set.add_vote(vote, &vs);
    assert!(matches!(
        result,
        Err(VoteSetError::WrongHeight {
            vote_height: 2,
            expected_height: 1
        })
    ));
}

#[test]
fn test_invalid_signature_rejected() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote);

    // Sign with wrong key
    let mut vote = Vote::new(VoteType::Prevote, 1, 0, [1u8; 32], 0);
    vote.signature = keys[1].sign(&vote.signing_bytes()); // Wrong key!

    let result = vote_set.add_vote(vote, &vs);
    assert!(matches!(result, Err(VoteSetError::InvalidSignature(0))));
}

#[test]
fn test_quorum_for_nil() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Prevote);

    // Three validators vote nil
    for i in 0..3 {
        let vote = create_signed_vote(VoteType::Prevote, 1, 0, NIL_HASH, i, &keys[i as usize]);
        vote_set.add_vote(vote, &vs).unwrap();
    }

    assert!(vote_set.has_quorum_for(&NIL_HASH, &vs));
    assert!(vote_set.has_any_quorum(&vs).is_some());
    assert!(vote_set.has_quorum_for_non_nil(&vs).is_none());
}

#[test]
fn test_signers_bitmap() {
    let (vs, keys) = create_test_validator_set(4);
    let mut vote_set = VoteSet::new(1, 0, VoteType::Precommit);

    let block_hash = [1u8; 32];

    // Validators 0, 2, 3 vote for block
    for i in [0, 2, 3] {
        let vote = create_signed_vote(VoteType::Precommit, 1, 0, block_hash, i, &keys[i as usize]);
        vote_set.add_vote(vote, &vs).unwrap();
    }

    let bitmap = vote_set.create_signers_bitmap(&block_hash, &vs);
    // Bits 0, 2, 3 should be set = 0b1101 = 13
    assert_eq!(bitmap, vec![0b00001101]);
}

#[test]
fn test_height_vote_set() {
    let (vs, keys) = create_test_validator_set(4);
    let mut hvs = HeightVoteSet::new(5);

    let block_hash = [1u8; 32];

    // Add prevotes for round 0
    for i in 0..3 {
        let vote = create_signed_vote(VoteType::Prevote, 5, 0, block_hash, i, &keys[i as usize]);
        hvs.prevotes(0).add_vote(vote, &vs).unwrap();
    }

    assert!(hvs
        .get_prevotes(0)
        .unwrap()
        .has_quorum_for(&block_hash, &vs));

    // Check POL
    assert_eq!(hvs.has_pol_from(&block_hash, 0, &vs), Some(0));
    assert!(hvs.has_pol_from(&block_hash, 1, &vs).is_none());
}
