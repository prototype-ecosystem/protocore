//! Tests for Schnorr signatures

use protocore_crypto::schnorr::{
    batch_verify, multisig, SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature,
};

#[test]
fn test_schnorr_sign_verify() {
    let secret = SchnorrSecretKey::random();
    let public = secret.public_key();
    let message = b"Hello, Schnorr!";

    let signature = secret.sign(message);
    assert!(public.verify(message, &signature));

    // Wrong message should fail
    assert!(!public.verify(b"Wrong message", &signature));
}

#[test]
fn test_schnorr_from_seed_deterministic() {
    let seed = [0x42u8; 32];
    let key1 = SchnorrSecretKey::from_seed(&seed);
    let key2 = SchnorrSecretKey::from_seed(&seed);

    assert_eq!(key1.public_key().bytes, key2.public_key().bytes);
}

#[test]
fn test_schnorr_signature_serialization() {
    let secret = SchnorrSecretKey::random();
    let message = b"Test message";

    let signature = secret.sign(message);
    let bytes = signature.to_bytes();
    let restored = SchnorrSignature::from_bytes(&bytes);

    assert_eq!(signature, restored);
}

#[test]
fn test_batch_verify() {
    let keys: Vec<SchnorrSecretKey> = (0..5).map(|_| SchnorrSecretKey::random()).collect();
    let pubkeys: Vec<SchnorrPublicKey> = keys.iter().map(|k| k.to_public_key()).collect();

    let messages: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    let signatures: Vec<SchnorrSignature> = keys
        .iter()
        .zip(messages.iter())
        .map(|(k, m)| k.sign(m))
        .collect();

    assert!(batch_verify(&message_refs, &signatures, &pubkeys));
}

#[test]
fn test_address_derivation() {
    let secret = SchnorrSecretKey::random();
    let public = secret.public_key();
    let address = public.to_address();

    assert_eq!(address.len(), 20);
}

#[test]
fn test_multisig_key_aggregation() {
    let keys: Vec<SchnorrSecretKey> = (0..3).map(|_| SchnorrSecretKey::random()).collect();
    let pubkeys: Vec<SchnorrPublicKey> = keys.iter().map(|k| k.to_public_key()).collect();

    let agg_pubkey = multisig::aggregate_pubkeys(&pubkeys);

    // Aggregated key should be different from individual keys
    for pk in &pubkeys {
        assert_ne!(agg_pubkey.bytes, pk.bytes);
    }
}

#[test]
fn test_derive_from_path() {
    let seed = b"master seed for testing purposes";
    let path1 = "m/44'/60'/0'/0/0";
    let path2 = "m/44'/60'/0'/0/1";

    let key1 = SchnorrSecretKey::derive_from_path(seed, path1);
    let key2 = SchnorrSecretKey::derive_from_path(seed, path2);

    // Different paths should give different keys
    assert_ne!(key1.public_key().bytes, key2.public_key().bytes);

    // Same path should give same key
    let key1_again = SchnorrSecretKey::derive_from_path(seed, path1);
    assert_eq!(key1.public_key().bytes, key1_again.public_key().bytes);
}
