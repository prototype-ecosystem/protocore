//! Tests for the main light-client library types and errors

use protocore_light_client::{constants, Error};

#[test]
fn test_error_display() {
    let err = Error::InsufficientStake {
        got: 100,
        required: 200,
    };
    assert!(err.to_string().contains("100"));
    assert!(err.to_string().contains("200"));
}

#[test]
fn test_empty_hash_constant() {
    use sha3::{Digest, Keccak256};
    let computed: [u8; 32] = Keccak256::digest([]).into();
    assert_eq!(constants::EMPTY_HASH, computed);
}
