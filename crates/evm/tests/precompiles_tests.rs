//! Integration tests for precompiles module

use alloy_primitives::{Address, U256};
use protocore_evm::precompiles::{
    abi, GOVERNANCE_ADDRESS, SLASHING_ADDRESS, STAKING_ADDRESS,
};

/// Helper function to create an address from a low u64 value
fn address_from_low_u64(v: u64) -> Address {
    let bytes = v.to_be_bytes();
    Address::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7],
    ])
}

#[test]
fn test_address_from_low_u64() {
    let addr = address_from_low_u64(0x1000);
    assert_eq!(addr.0 .0[19], 0x10);
    assert_eq!(addr.0 .0[18], 0x00);

    // First 12 bytes should be zero
    for i in 0..12 {
        assert_eq!(addr.0 .0[i], 0);
    }
}

#[test]
fn test_precompile_addresses() {
    assert_eq!(STAKING_ADDRESS.0 .0[18], 0x10);
    assert_eq!(STAKING_ADDRESS.0 .0[19], 0x00);

    assert_eq!(SLASHING_ADDRESS.0 .0[18], 0x10);
    assert_eq!(SLASHING_ADDRESS.0 .0[19], 0x01);

    assert_eq!(GOVERNANCE_ADDRESS.0 .0[18], 0x10);
    assert_eq!(GOVERNANCE_ADDRESS.0 .0[19], 0x02);
}

#[test]
fn test_abi_decode_address() {
    let mut data = vec![0u8; 64];
    // Put an address at offset 0 (right-aligned in 32 bytes)
    data[12..32].copy_from_slice(&[0xAB; 20]);

    let decoded = abi::decode_address(&data, 0).unwrap();
    assert_eq!(decoded.0 .0, [0xAB; 20]);
}

#[test]
fn test_abi_decode_u256() {
    let mut data = vec![0u8; 32];
    data[31] = 42;

    let decoded = abi::decode_u256(&data, 0).unwrap();
    assert_eq!(decoded, U256::from(42));
}

#[test]
fn test_abi_encode_decode_roundtrip() {
    let addr = Address::from([0x42; 20]);
    let encoded = abi::encode_address(addr);

    let mut data = [0u8; 32];
    data.copy_from_slice(&encoded);
    let decoded = abi::decode_address(&data, 0).unwrap();

    assert_eq!(addr, decoded);
}
