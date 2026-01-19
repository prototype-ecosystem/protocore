//! Tests for the core state-sync library functions
//!
//! Tests extracted from lib.rs

use protocore_state_sync::{hash_to_hex, hex_to_hash, keccak256, keccak256_concat};

#[test]
fn test_keccak256() {
    let hash = keccak256(b"hello");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_keccak256_concat() {
    let hash1 = keccak256(b"helloworld");
    let hash2 = keccak256_concat(&[b"hello", b"world"]);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_hex_conversion() {
    let hash = keccak256(b"test");
    let hex_str = hash_to_hex(&hash);
    let recovered = hex_to_hash(&hex_str).unwrap();
    assert_eq!(hash, recovered);

    // With 0x prefix
    let hex_with_prefix = format!("0x{}", hex_str);
    let recovered_with_prefix = hex_to_hash(&hex_with_prefix).unwrap();
    assert_eq!(hash, recovered_with_prefix);
}
