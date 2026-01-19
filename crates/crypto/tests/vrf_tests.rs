//! Tests for VRF (Verifiable Random Function)

use protocore_crypto::vrf::{VrfProof, VrfPublicKey, VrfSecretKey};

#[test]
fn test_vrf_prove_verify() {
    let seed = [42u8; 32];
    let secret_key = VrfSecretKey::from_seed(&seed);
    let public_key = secret_key.public_key();

    let input = b"test input for VRF";
    let (output, proof) = secret_key.prove(input);

    // Verification should succeed and return the same output
    let verified_output = public_key.verify(input, &proof);
    assert!(verified_output.is_some());
    assert_eq!(verified_output.unwrap(), output);
}

#[test]
fn test_vrf_deterministic() {
    let seed = [42u8; 32];
    let secret_key = VrfSecretKey::from_seed(&seed);

    let input = b"deterministic test";
    let (output1, proof1) = secret_key.prove(input);
    let (output2, proof2) = secret_key.prove(input);

    // Same input should produce same output and proof
    assert_eq!(output1, output2);
    assert_eq!(proof1.gamma, proof2.gamma);
    assert_eq!(proof1.c, proof2.c);
    assert_eq!(proof1.s, proof2.s);
}

#[test]
fn test_vrf_different_inputs() {
    let seed = [42u8; 32];
    let secret_key = VrfSecretKey::from_seed(&seed);

    let (output1, _) = secret_key.prove(b"input 1");
    let (output2, _) = secret_key.prove(b"input 2");

    // Different inputs should produce different outputs
    assert_ne!(output1, output2);
}

#[test]
fn test_vrf_different_keys() {
    let secret_key1 = VrfSecretKey::from_seed(&[1u8; 32]);
    let secret_key2 = VrfSecretKey::from_seed(&[2u8; 32]);

    let input = b"same input";
    let (output1, _) = secret_key1.prove(input);
    let (output2, _) = secret_key2.prove(input);

    // Different keys should produce different outputs
    assert_ne!(output1, output2);
}

#[test]
fn test_vrf_wrong_key_verification() {
    let secret_key = VrfSecretKey::from_seed(&[1u8; 32]);
    let wrong_key = VrfSecretKey::from_seed(&[2u8; 32]);

    let input = b"test input";
    let (_, proof) = secret_key.prove(input);

    // Verification with wrong public key should fail
    let result = wrong_key.public_key().verify(input, &proof);
    assert!(result.is_none());
}

#[test]
fn test_vrf_wrong_input_verification() {
    let secret_key = VrfSecretKey::from_seed(&[42u8; 32]);

    let (_, proof) = secret_key.prove(b"original input");

    // Verification with wrong input should fail
    let result = secret_key.public_key().verify(b"wrong input", &proof);
    assert!(result.is_none());
}

#[test]
fn test_vrf_tampered_proof() {
    let secret_key = VrfSecretKey::from_seed(&[42u8; 32]);
    let input = b"test input";
    let (_, mut proof) = secret_key.prove(input);

    // Tamper with the proof
    proof.gamma[0] ^= 0xFF;

    // Verification should fail
    let result = secret_key.public_key().verify(input, &proof);
    assert!(result.is_none());
}

#[test]
fn test_public_key_serialization() {
    let secret_key = VrfSecretKey::from_seed(&[42u8; 32]);
    let public_key = secret_key.public_key();

    let bytes = public_key.to_bytes();
    let restored = VrfPublicKey::from_bytes(&bytes);

    assert!(restored.is_some());
    assert_eq!(restored.unwrap(), *public_key);
}

#[test]
fn test_proof_serialization() {
    let secret_key = VrfSecretKey::from_seed(&[42u8; 32]);
    let input = b"serialization test";
    let (_, proof) = secret_key.prove(input);

    // Serialize and deserialize
    let serialized = serde_json::to_string(&proof).unwrap();
    let deserialized: VrfProof = serde_json::from_str(&serialized).unwrap();

    assert_eq!(proof.gamma, deserialized.gamma);
    assert_eq!(proof.c, deserialized.c);
    assert_eq!(proof.s, deserialized.s);

    // Verify deserialized proof still works
    let result = secret_key.public_key().verify(input, &deserialized);
    assert!(result.is_some());
}
