//! Tests for BLS12-381 signatures

use protocore_crypto::bls::{
    bls_aggregate, bls_verify_aggregate, BlsPrivateKey, BlsPublicKey, BlsSignature,
};

#[test]
fn test_key_generation() {
    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    assert_ne!(sk1.to_bytes(), sk2.to_bytes());
}

#[test]
fn test_key_from_bytes() {
    let sk = BlsPrivateKey::random();
    let bytes = sk.to_bytes();
    let restored = BlsPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk.to_bytes(), restored.to_bytes());
}

#[test]
fn test_key_from_seed() {
    let seed = [42u8; 32];
    let sk1 = BlsPrivateKey::from_seed(&seed).unwrap();
    let sk2 = BlsPrivateKey::from_seed(&seed).unwrap();
    assert_eq!(sk1.to_bytes(), sk2.to_bytes());
}

#[test]
fn test_sign_verify() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"test message";

    let sig = sk.sign(message);
    assert!(sig.verify(message, &pk));
    assert!(!sig.verify(b"wrong message", &pk));
}

#[test]
fn test_public_key_verify() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"test";

    let sig = sk.sign(message);
    assert!(pk.verify(message, &sig));
}

#[test]
fn test_aggregate_signatures() {
    let n = 5;
    let keys: Vec<_> = (0..n).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"consensus message";

    let signatures: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    let pk_refs: Vec<_> = pubkeys.iter().collect();

    assert!(aggregate.verify_aggregate(message, &pk_refs));
}

#[test]
fn test_aggregate_wrong_message() {
    let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"original message";

    let signatures: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    let pk_refs: Vec<_> = pubkeys.iter().collect();

    assert!(!aggregate.verify_aggregate(b"wrong message", &pk_refs));
}

#[test]
fn test_aggregate_missing_signer() {
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"message";

    // Only sign with first 4 keys
    let signatures: Vec<_> = keys.iter().take(4).map(|k| k.sign(message)).collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();

    // Verify against all 5 pubkeys - should fail
    let pk_refs: Vec<_> = pubkeys.iter().collect();
    assert!(!aggregate.verify_aggregate(message, &pk_refs));

    // Verify against first 4 pubkeys - should succeed
    let pk_refs: Vec<_> = pubkeys.iter().take(4).collect();
    assert!(aggregate.verify_aggregate(message, &pk_refs));
}

#[test]
fn test_fast_aggregate_verify() {
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkey_bytes: Vec<[u8; 48]> = keys.iter().map(|k| k.public_key().to_bytes()).collect();
    let message = b"fast verify test";

    let signatures: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    assert!(aggregate.fast_aggregate_verify(message, &pubkey_bytes));
}

#[test]
fn test_bls_verify_aggregate_helper() {
    let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
    let pubkey_bytes: Vec<[u8; 48]> = keys.iter().map(|k| k.public_key().to_bytes()).collect();
    let mut message = [0u8; 32];
    message.copy_from_slice(b"32 byte message for block hash!!");

    let signatures: Vec<_> = keys.iter().map(|k| k.sign(&message)).collect();
    let sig_bytes: Vec<[u8; 96]> = signatures.iter().map(|s| s.to_bytes()).collect();

    let aggregate_bytes = bls_aggregate(&sig_bytes).unwrap();
    assert!(bls_verify_aggregate(&pubkey_bytes, &message, &aggregate_bytes));
}

#[test]
fn test_aggregate_public_keys() {
    let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let pk_refs: Vec<_> = pubkeys.iter().collect();

    let agg_pk = BlsPublicKey::aggregate(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().len(), 48);
}

#[test]
fn test_signature_serialization() {
    let sk = BlsPrivateKey::random();
    let sig = sk.sign(b"test");

    let bytes = sig.to_bytes();
    let restored = BlsSignature::from_bytes(&bytes).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());

    let hex = sig.to_hex();
    let from_hex = BlsSignature::from_hex(&hex).unwrap();
    assert_eq!(sig.to_bytes(), from_hex.to_bytes());
}

#[test]
fn test_pubkey_serde() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();

    // JSON
    let json = serde_json::to_string(&pk).unwrap();
    let restored: BlsPublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, restored);

    // Bincode
    let bytes = bincode::serialize(&pk).unwrap();
    let restored: BlsPublicKey = bincode::deserialize(&bytes).unwrap();
    assert_eq!(pk, restored);
}

#[test]
fn test_signature_serde() {
    let sk = BlsPrivateKey::random();
    let sig = sk.sign(b"test");

    // JSON
    let json = serde_json::to_string(&sig).unwrap();
    let restored: BlsSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, restored);

    // Bincode
    let bytes = bincode::serialize(&sig).unwrap();
    let restored: BlsSignature = bincode::deserialize(&bytes).unwrap();
    assert_eq!(sig, restored);
}

#[test]
fn test_deterministic_signing() {
    let sk = BlsPrivateKey::random();
    let message = b"deterministic test";

    let sig1 = sk.sign(message);
    let sig2 = sk.sign(message);

    // BLS signatures should be deterministic
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn test_empty_aggregate_fails() {
    let result = BlsSignature::aggregate(&[]);
    assert!(result.is_err());

    let result = BlsPublicKey::aggregate(&[]);
    assert!(result.is_err());
}

#[test]
fn test_single_signature_aggregate() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"single sig";

    let sig = sk.sign(message);

    // Aggregating a single signature should work
    let aggregate = BlsSignature::aggregate(&[&sig]).unwrap();
    assert!(aggregate.verify_aggregate(message, &[&pk]));

    // And should equal the original
    assert_eq!(sig.to_bytes(), aggregate.to_bytes());
}

#[test]
fn test_cross_key_verification_fails() {
    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    let pk2 = sk2.public_key();
    let message = b"test";

    let sig = sk1.sign(message);
    // Signature by sk1 should not verify against pk2
    assert!(!sig.verify(message, &pk2));
}
