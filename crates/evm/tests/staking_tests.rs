//! Integration tests for staking precompile

use protocore_evm::precompiles::staking::{
    ValidatorRecord, MIN_DELEGATION, MIN_VALIDATOR_STAKE, UNBONDING_PERIOD,
};
use sha3::{Digest, Keccak256};

/// Compute Keccak256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[test]
fn test_validator_record_default() {
    let record = ValidatorRecord::default();
    assert_eq!(record.total_stake, 0);
    assert!(!record.active);
    assert!(!record.jailed);
}

#[test]
fn test_min_stake_constants() {
    assert_eq!(MIN_VALIDATOR_STAKE, 100_000 * 10u128.pow(18));
    assert_eq!(MIN_DELEGATION, 10u128.pow(18));
}

#[test]
fn test_unbonding_period() {
    // ~7 days at 2s blocks
    assert_eq!(UNBONDING_PERIOD, 302_400);
}

#[test]
fn test_keccak256() {
    let hash = keccak256(b"hello");
    assert_eq!(hash.len(), 32);
}
