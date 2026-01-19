//! Integration tests for randomness beacon module.

use protocore_consensus::randomness::{BlockRandomness, RandomnessBeacon, RandomnessError};
use protocore_crypto::vrf::{VrfProof, VrfSecretKey};

fn create_test_vrf_key(seed: u8) -> VrfSecretKey {
    VrfSecretKey::from_seed(&[seed; 32])
}

#[test]
fn test_beacon_creation() {
    let genesis = [1u8; 32];
    let beacon = RandomnessBeacon::new(genesis, 100);

    assert_eq!(beacon.current(), &genesis);
    assert_eq!(beacon.epoch(), 0);
    assert_eq!(beacon.blocks_per_epoch(), 100);
}

#[test]
fn test_generate_and_verify_block_randomness() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let vrf_key = create_test_vrf_key(42);
    let parent_hash = [0u8; 32];

    // Generate randomness for block 1
    let block_randomness = beacon.generate_block_randomness(&vrf_key, 1, &parent_hash);

    // Verify and apply
    let result =
        beacon.verify_and_apply(1, &parent_hash, vrf_key.public_key(), &block_randomness);

    assert!(result.is_ok());
    assert_eq!(beacon.epoch_contribution_count(), 1);
}

#[test]
fn test_verification_with_wrong_key() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let vrf_key = create_test_vrf_key(42);
    let wrong_key = create_test_vrf_key(99);
    let parent_hash = [0u8; 32];

    // Generate with correct key
    let block_randomness = beacon.generate_block_randomness(&vrf_key, 1, &parent_hash);

    // Verify with wrong key
    let result =
        beacon.verify_and_apply(1, &parent_hash, wrong_key.public_key(), &block_randomness);

    assert!(matches!(result, Err(RandomnessError::InvalidVrfProof)));
}

#[test]
fn test_verification_with_wrong_parent_hash() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let vrf_key = create_test_vrf_key(42);
    let parent_hash = [0u8; 32];
    let wrong_parent_hash = [1u8; 32];

    // Generate with correct parent hash
    let block_randomness = beacon.generate_block_randomness(&vrf_key, 1, &parent_hash);

    // Verify with wrong parent hash
    let result = beacon.verify_and_apply(
        1,
        &wrong_parent_hash,
        vrf_key.public_key(),
        &block_randomness,
    );

    assert!(matches!(result, Err(RandomnessError::InvalidVrfProof)));
}

#[test]
fn test_epoch_transition() {
    let genesis = [1u8; 32];
    let blocks_per_epoch = 5;
    let mut beacon = RandomnessBeacon::new(genesis, blocks_per_epoch);

    let vrf_key = create_test_vrf_key(42);

    // Process blocks 1-5 (epoch 0)
    for height in 1..=blocks_per_epoch {
        let parent_hash = [height as u8; 32];
        let block_randomness =
            beacon.generate_block_randomness(&vrf_key, height, &parent_hash);
        beacon
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
    }

    // Should have transitioned to epoch 1
    assert_eq!(beacon.epoch(), 1);
    assert_eq!(beacon.epoch_contribution_count(), 0); // Contributions cleared
    assert_ne!(beacon.current(), &genesis); // Randomness changed

    // Previous randomness should be available
    let prev_randomness = beacon.for_epoch(0);
    assert!(prev_randomness.is_some());
    assert_eq!(prev_randomness.unwrap(), genesis);
}

#[test]
fn test_deterministic_randomness() {
    let genesis = [1u8; 32];
    let mut beacon1 = RandomnessBeacon::new(genesis, 3);
    let mut beacon2 = RandomnessBeacon::new(genesis, 3);

    let vrf_key = create_test_vrf_key(42);

    // Process same blocks on both beacons
    for height in 1..=6 {
        let parent_hash = [height as u8; 32];
        let block_randomness =
            beacon1.generate_block_randomness(&vrf_key, height, &parent_hash);

        beacon1
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
        beacon2
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
    }

    // Both beacons should have identical state
    assert_eq!(beacon1.current(), beacon2.current());
    assert_eq!(beacon1.epoch(), beacon2.epoch());
}

#[test]
fn test_snapshot_and_restore() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let vrf_key = create_test_vrf_key(42);

    // Add some contributions
    for height in 1..=10 {
        let parent_hash = [height as u8; 32];
        let block_randomness =
            beacon.generate_block_randomness(&vrf_key, height, &parent_hash);
        beacon
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
    }

    // Create snapshot
    let snapshot = beacon.snapshot();

    // Restore from snapshot
    let restored = RandomnessBeacon::restore_from_snapshot(snapshot.clone());

    assert_eq!(restored.current(), beacon.current());
    assert_eq!(restored.epoch(), beacon.epoch());
    assert_eq!(restored.current_height(), beacon.current_height());
}

#[test]
fn test_for_epoch_queries() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 2);

    let vrf_key = create_test_vrf_key(42);

    // Still in epoch 0
    assert_eq!(beacon.for_epoch(0), Some(genesis));
    assert_eq!(beacon.for_epoch(1), None);

    // Process blocks to transition epochs
    for height in 1..=4 {
        let parent_hash = [height as u8; 32];
        let block_randomness =
            beacon.generate_block_randomness(&vrf_key, height, &parent_hash);
        beacon
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
    }

    // Now in epoch 2
    assert_eq!(beacon.epoch(), 2);

    // Current epoch available
    assert!(beacon.for_epoch(2).is_some());
    // Previous epoch available
    assert!(beacon.for_epoch(1).is_some());
    // Epoch 0 no longer available
    assert!(beacon.for_epoch(0).is_none());
}

#[test]
fn test_apply_without_verification() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let block_randomness = BlockRandomness {
        vrf_proof: VrfProof::default(),
        random_value: [42u8; 32],
        vrf_input: [0u8; 32],
    };

    beacon.apply_without_verification(1, &block_randomness);

    assert_eq!(beacon.epoch_contribution_count(), 1);
    assert_eq!(beacon.current_height(), 1);
}

#[test]
fn test_reset() {
    let genesis = [1u8; 32];
    let mut beacon = RandomnessBeacon::new(genesis, 100);

    let vrf_key = create_test_vrf_key(42);

    // Add some state
    for height in 1..=10 {
        let parent_hash = [height as u8; 32];
        let block_randomness =
            beacon.generate_block_randomness(&vrf_key, height, &parent_hash);
        beacon
            .verify_and_apply(height, &parent_hash, vrf_key.public_key(), &block_randomness)
            .unwrap();
    }

    // Reset
    let new_randomness = [99u8; 32];
    beacon.reset(new_randomness, 5, 500);

    assert_eq!(beacon.current(), &new_randomness);
    assert_eq!(beacon.epoch(), 5);
    assert_eq!(beacon.current_height(), 500);
    assert_eq!(beacon.epoch_contribution_count(), 0);
}
