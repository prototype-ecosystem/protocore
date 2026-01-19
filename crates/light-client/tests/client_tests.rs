//! Tests for the light client implementation

use protocore_light_client::{
    client::{
        Checkpoint, FinalityCertificate, HeaderChain, LightBlockHeader, LightClient,
        LightClientConfig, ValidatorInfo, ValidatorSet, ValidatorSignature, ValidatorTracker,
    },
    constants::DEFAULT_EPOCH_LENGTH,
    types::Hash,
    Error,
};

fn create_test_header(number: u64, parent_hash: Hash) -> LightBlockHeader {
    let mut header = LightBlockHeader {
        number,
        hash: [0u8; 32],
        parent_hash,
        state_root: [1u8; 32],
        transactions_root: [2u8; 32],
        receipts_root: [3u8; 32],
        timestamp: 1000 + number * 12,
        proposer: [0u8; 20],
        epoch: number / DEFAULT_EPOCH_LENGTH,
    };
    header.hash = header.compute_hash();
    header
}

fn create_test_validator_set(epoch: u64) -> ValidatorSet {
    let validators = vec![
        ValidatorInfo::new([1u8; 20], vec![1u8; 48], 1000),
        ValidatorInfo::new([2u8; 20], vec![2u8; 48], 1000),
        ValidatorInfo::new([3u8; 20], vec![3u8; 48], 1000),
    ];
    ValidatorSet::new(epoch, validators)
}

#[test]
fn test_validator_set_threshold() {
    let set = create_test_validator_set(0);
    assert_eq!(set.total_stake, 3000);
    // 2/3 of 3000 = 2000, + 1 = 2001
    assert_eq!(set.finality_threshold(), 2001);
}

#[test]
fn test_header_chain_insert() {
    let mut chain = HeaderChain::new(100, false);
    let header = create_test_header(0, [0u8; 32]);

    chain.insert(header.clone()).unwrap();

    assert_eq!(chain.len(), 1);
    assert!(chain.has_height(0));
    assert!(chain.has_hash(&header.hash));
}

#[test]
fn test_header_chain_conflict() {
    let mut chain = HeaderChain::new(100, false);
    let header1 = create_test_header(0, [0u8; 32]);
    let mut header2 = create_test_header(0, [1u8; 32]); // Different parent
    header2.hash = header2.compute_hash();

    chain.insert(header1).unwrap();
    let result = chain.insert(header2);

    assert!(matches!(result, Err(Error::ReorgDetected { .. })));
}

#[test]
fn test_validator_tracker() {
    let mut tracker = ValidatorTracker::new(DEFAULT_EPOCH_LENGTH);
    let set0 = create_test_validator_set(0);
    let set1 = create_test_validator_set(1);

    tracker.init(set0);
    assert_eq!(tracker.epoch_count(), 1);

    tracker.update_set(set1).unwrap();
    assert_eq!(tracker.epoch_count(), 2);
}

#[test]
fn test_checkpoint_verify() {
    let header = create_test_header(0, [0u8; 32]);
    let validator_set = create_test_validator_set(0);
    let checkpoint = Checkpoint::genesis(header, validator_set);

    checkpoint.verify(None).unwrap();
}

#[test]
fn test_light_client_creation() {
    let header = create_test_header(0, [0u8; 32]);
    let validator_set = create_test_validator_set(0);
    let checkpoint = Checkpoint::genesis(header.clone(), validator_set);
    let config = LightClientConfig::default();

    let client = LightClient::new(config, checkpoint).unwrap();

    assert!(client.is_initialized());
    assert_eq!(client.finalized_height(), 0);
    assert_eq!(client.current_epoch(), 0);
}

#[test]
fn test_finality_certificate_basic() {
    let set = create_test_validator_set(0);
    let block_hash = [42u8; 32];

    // Create signatures from all 3 validators
    let signatures = vec![
        ValidatorSignature {
            validator: [1u8; 20],
            signature: vec![1u8; 96],
        },
        ValidatorSignature {
            validator: [2u8; 20],
            signature: vec![2u8; 96],
        },
        ValidatorSignature {
            validator: [3u8; 20],
            signature: vec![3u8; 96],
        },
    ];

    let cert = FinalityCertificate::new(block_hash, 0, 0, signatures);

    // Should verify with full stake
    assert!(cert.verify(&set).is_ok());
}

#[test]
fn test_finality_certificate_insufficient_stake() {
    let set = create_test_validator_set(0);
    let block_hash = [42u8; 32];

    // Only 1 validator signature (1000 stake, need 2001)
    let signatures = vec![ValidatorSignature {
        validator: [1u8; 20],
        signature: vec![1u8; 96],
    }];

    let cert = FinalityCertificate::new(block_hash, 0, 0, signatures);

    let result = cert.verify(&set);
    assert!(matches!(result, Err(Error::InsufficientStake { .. })));
}
