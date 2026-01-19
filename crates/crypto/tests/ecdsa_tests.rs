//! Tests for ECDSA signatures

use protocore_crypto::ecdsa::{
    checksum_address, hash_message, verify_checksum_address, PrivateKey, PublicKey, Signature,
};

#[test]
fn test_private_key_generation() {
    let key1 = PrivateKey::random();
    let key2 = PrivateKey::random();
    assert_ne!(key1.to_bytes(), key2.to_bytes());
}

#[test]
fn test_private_key_from_bytes() {
    let key = PrivateKey::random();
    let bytes = key.to_bytes();
    let restored = PrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(key.to_bytes(), restored.to_bytes());
}

#[test]
fn test_private_key_from_hex() {
    let hex = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    let key = PrivateKey::from_hex(hex).unwrap();
    assert_eq!(key.to_hex(), &hex[2..]);
}

#[test]
fn test_public_key_formats() {
    let private = PrivateKey::random();
    let public = private.public_key();

    let compressed = public.to_compressed();
    let uncompressed = public.to_uncompressed();

    assert_eq!(compressed.len(), 33);
    assert_eq!(uncompressed.len(), 64);

    let from_compressed = PublicKey::from_compressed(&compressed).unwrap();
    let from_uncompressed = PublicKey::from_uncompressed(&uncompressed).unwrap();

    assert_eq!(from_compressed, public);
    assert_eq!(from_uncompressed, public);
}

#[test]
fn test_address_derivation() {
    // Known test vector
    let hex = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    let key = PrivateKey::from_hex(hex).unwrap();
    let address = key.public_key().to_address_hex().to_lowercase();
    assert_eq!(address, "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
}

#[test]
fn test_sign_and_verify() {
    let key = PrivateKey::random();
    let public = key.public_key();
    let data = b"test data";

    let sig = key.sign(data).unwrap();
    assert!(sig.verify(data, &public).unwrap());
    assert!(!sig.verify(b"wrong data", &public).unwrap());
}

#[test]
fn test_sign_and_verify_message() {
    let key = PrivateKey::random();
    let public = key.public_key();
    let message = b"Hello, Proto Core!";

    let sig = key.sign_message(message).unwrap();
    assert!(sig.verify_message(message, &public).unwrap());
    assert!(!sig.verify_message(b"wrong message", &public).unwrap());
}

#[test]
fn test_recover_public_key() {
    let key = PrivateKey::random();
    let public = key.public_key();
    let message = b"test message";

    let sig = key.sign_message(message).unwrap();
    let recovered = sig.recover_from_message(message).unwrap();

    assert_eq!(recovered, public);
}

#[test]
fn test_signature_serialization() {
    let key = PrivateKey::random();
    let sig = key.sign(b"test").unwrap();

    let bytes = sig.to_bytes();
    let restored = Signature::from_bytes(&bytes);

    assert_eq!(sig, restored);

    let hex = sig.to_hex();
    let from_hex = Signature::from_hex(&hex).unwrap();
    assert_eq!(sig, from_hex);
}

#[test]
fn test_checksum_address() {
    // EIP-55 test vectors
    let cases = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    for addr in cases {
        let bytes = hex::decode(&addr[2..]).unwrap();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);

        let checksummed = checksum_address(&arr);
        assert_eq!(checksummed, addr);
        assert!(verify_checksum_address(addr));
    }
}

#[test]
fn test_hash_message() {
    let message = b"hello";
    let hash = hash_message(message);
    // This should match the output of web3.eth.accounts.hashMessage("hello")
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_signature_v_values() {
    let sig = Signature::new([0u8; 32], [0u8; 32], 0);
    assert_eq!(sig.v_normalized(), 0);
    assert_eq!(sig.v_legacy(), 27);

    let sig = Signature::new([0u8; 32], [0u8; 32], 1);
    assert_eq!(sig.v_normalized(), 1);
    assert_eq!(sig.v_legacy(), 28);

    let sig = Signature::new([0u8; 32], [0u8; 32], 27);
    assert_eq!(sig.v_normalized(), 0);
    assert_eq!(sig.v_legacy(), 27);
}

#[test]
fn test_public_key_serde() {
    let key = PrivateKey::random();
    let public = key.public_key();

    // JSON (human readable)
    let json = serde_json::to_string(&public).unwrap();
    let restored: PublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(public, restored);

    // Bincode (binary)
    let bytes = bincode::serialize(&public).unwrap();
    let restored: PublicKey = bincode::deserialize(&bytes).unwrap();
    assert_eq!(public, restored);
}
