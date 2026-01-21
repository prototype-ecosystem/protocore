//! Tests for BLS12-381 signatures with security features
//!
//! Tests cover:
//! - Basic signing and verification
//! - Proof-of-possession (rogue key protection)
//! - Domain separation
//! - Signature aggregation with domain checks
//! - Canonical encoding validation
//! - Deterministic aggregation ordering

use protocore_crypto::bls::{
    aggregate_sorted_with_domain, batch_verify_proofs_of_possession, bls_aggregate,
    bls_verify_aggregate, verify_proof_of_possession, BlsPrivateKey, BlsProofOfPossession,
    BlsPublicKey, BlsSignature, DomainTag, MessageType, ValidatorKeyPair,
};

// ============================================================================
// Basic Key Operations
// ============================================================================

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

// ============================================================================
// Basic Signing (Legacy)
// ============================================================================

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
fn test_deterministic_signing() {
    let sk = BlsPrivateKey::random();
    let message = b"deterministic test";

    let sig1 = sk.sign(message);
    let sig2 = sk.sign(message);

    // BLS signatures should be deterministic
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
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

// ============================================================================
// Proof of Possession Tests
// ============================================================================

#[test]
fn test_proof_of_possession_generation() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let pop = sk.generate_proof_of_possession();

    assert!(pop.verify(&pk));
}

#[test]
fn test_proof_of_possession_wrong_key_fails() {
    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    let pk2 = sk2.public_key();

    let pop = sk1.generate_proof_of_possession();

    // PoP from sk1 should not verify against pk2
    assert!(!pop.verify(&pk2));
}

#[test]
fn test_proof_of_possession_serialization() {
    let sk = BlsPrivateKey::random();
    let pop = sk.generate_proof_of_possession();

    let bytes = pop.to_bytes();
    let restored = BlsProofOfPossession::from_bytes(&bytes).unwrap();
    assert_eq!(pop.to_bytes(), restored.to_bytes());

    let hex = pop.to_hex();
    let from_hex = BlsProofOfPossession::from_hex(&hex).unwrap();
    assert_eq!(pop.to_bytes(), from_hex.to_bytes());
}

#[test]
fn test_verify_proof_of_possession_helper() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let pop = sk.generate_proof_of_possession();

    assert!(verify_proof_of_possession(&pk, &pop));
}

#[test]
fn test_batch_verify_proofs_of_possession() {
    let keypairs: Vec<_> = (0..5)
        .map(|_| {
            let sk = BlsPrivateKey::random();
            let pk = sk.public_key();
            let pop = sk.generate_proof_of_possession();
            (pk, pop)
        })
        .collect();

    let refs: Vec<_> = keypairs.iter().map(|(pk, pop)| (pk, pop)).collect();
    assert!(batch_verify_proofs_of_possession(&refs));
}

#[test]
fn test_batch_verify_proofs_of_possession_fails_with_invalid() {
    let mut keypairs: Vec<_> = (0..5)
        .map(|_| {
            let sk = BlsPrivateKey::random();
            let pk = sk.public_key();
            let pop = sk.generate_proof_of_possession();
            (pk, pop)
        })
        .collect();

    // Replace one PoP with an invalid one
    let wrong_sk = BlsPrivateKey::random();
    keypairs[2].1 = wrong_sk.generate_proof_of_possession();

    let refs: Vec<_> = keypairs.iter().map(|(pk, pop)| (pk, pop)).collect();
    assert!(!batch_verify_proofs_of_possession(&refs));
}

// ============================================================================
// Domain Separation Tests
// ============================================================================

#[test]
fn test_domain_tag_creation() {
    let domain = DomainTag::new_prevote("mainnet-1");
    assert_eq!(domain.message_type(), MessageType::Prevote);
    assert_eq!(domain.chain_id(), "mainnet-1");
}

#[test]
fn test_domain_tag_types() {
    let proposal = DomainTag::new_proposal("test");
    let prevote = DomainTag::new_prevote("test");
    let precommit = DomainTag::new_precommit("test");
    let finality = DomainTag::new_finality("test");

    assert_eq!(proposal.message_type(), MessageType::Proposal);
    assert_eq!(prevote.message_type(), MessageType::Prevote);
    assert_eq!(precommit.message_type(), MessageType::Precommit);
    assert_eq!(finality.message_type(), MessageType::Finality);
}

#[test]
fn test_sign_verify_with_domain() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let domain = DomainTag::new_prevote("mainnet-1");
    let message = b"block hash";

    let sig = sk.sign_with_domain(message, &domain);
    assert!(sig.verify_with_domain(message, &pk, &domain));
}

#[test]
fn test_domain_separation_prevents_cross_domain_verification() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"block hash";

    let prevote_domain = DomainTag::new_prevote("mainnet-1");
    let precommit_domain = DomainTag::new_precommit("mainnet-1");

    let sig = sk.sign_with_domain(message, &prevote_domain);

    // Should verify with correct domain
    assert!(sig.verify_with_domain(message, &pk, &prevote_domain));

    // Should NOT verify with wrong domain
    assert!(!sig.verify_with_domain(message, &pk, &precommit_domain));
}

#[test]
fn test_domain_separation_prevents_cross_chain_verification() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"block hash";

    let mainnet_domain = DomainTag::new_prevote("mainnet-1");
    let testnet_domain = DomainTag::new_prevote("testnet-1");

    let sig = sk.sign_with_domain(message, &mainnet_domain);

    // Should verify with correct chain
    assert!(sig.verify_with_domain(message, &pk, &mainnet_domain));

    // Should NOT verify with wrong chain
    assert!(!sig.verify_with_domain(message, &pk, &testnet_domain));
}

#[test]
fn test_legacy_signature_not_valid_with_domain() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();
    let message = b"block hash";

    // Sign with legacy DST
    let legacy_sig = sk.sign(message);

    // Should verify with legacy method
    assert!(legacy_sig.verify(message, &pk));

    // Should NOT verify with any domain
    let domain = DomainTag::new_prevote("mainnet-1");
    assert!(!legacy_sig.verify_with_domain(message, &pk, &domain));
}

// ============================================================================
// Signature Aggregation Tests (Legacy)
// ============================================================================

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

// ============================================================================
// Signature Aggregation with Domain Tests
// ============================================================================

#[test]
fn test_aggregate_with_domain() {
    let domain = DomainTag::new_prevote("mainnet-1");
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"consensus message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|k| k.sign_with_domain(message, &domain))
        .collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate_with_domain(&sig_refs, &domain).unwrap();
    let pk_refs: Vec<_> = pubkeys.iter().collect();

    assert!(aggregate.verify_aggregate_with_domain(message, &pk_refs, &domain));
}

#[test]
fn test_aggregate_with_domain_rejects_mixed_domains() {
    let prevote_domain = DomainTag::new_prevote("mainnet-1");
    let precommit_domain = DomainTag::new_precommit("mainnet-1");

    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    let message = b"consensus message";

    // Sign with different domains
    let sig1 = sk1.sign_with_domain(message, &prevote_domain);
    let sig2 = sk2.sign_with_domain(message, &precommit_domain);

    // Aggregation should fail due to domain mismatch
    let result = BlsSignature::aggregate_with_domain(&[&sig1, &sig2], &prevote_domain);
    assert!(result.is_err());
}

#[test]
fn test_aggregate_with_domain_rejects_legacy_signatures() {
    let domain = DomainTag::new_prevote("mainnet-1");

    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    let message = b"consensus message";

    // One domain-aware signature, one legacy
    let sig1 = sk1.sign_with_domain(message, &domain);
    let sig2 = sk2.sign(message); // Legacy signature

    // Aggregation should fail because sig2 has no domain
    let result = BlsSignature::aggregate_with_domain(&[&sig1, &sig2], &domain);
    assert!(result.is_err());
}

#[test]
fn test_aggregate_sorted_with_domain() {
    let domain = DomainTag::new_finality("mainnet-1");
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"finality message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|k| k.sign_with_domain(message, &domain))
        .collect();

    // Create signed messages in random order
    let signed_messages: Vec<_> = pubkeys.iter().zip(signatures.iter()).collect();

    let (sorted_pks, aggregate) = aggregate_sorted_with_domain(&signed_messages, &domain).unwrap();

    // Verify with sorted public keys
    let pk_refs: Vec<_> = sorted_pks.iter().collect();
    assert!(aggregate.verify_aggregate_with_domain(message, &pk_refs, &domain));
}

#[test]
fn test_aggregate_sorted_deterministic() {
    let domain = DomainTag::new_finality("mainnet-1");
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let message = b"finality message";

    let signatures: Vec<_> = keys
        .iter()
        .map(|k| k.sign_with_domain(message, &domain))
        .collect();

    // Create signed messages in different orders
    let order1: Vec<_> = pubkeys.iter().zip(signatures.iter()).collect();
    let order2: Vec<_> = pubkeys.iter().zip(signatures.iter()).rev().collect();

    let (sorted_pks1, aggregate1) = aggregate_sorted_with_domain(&order1, &domain).unwrap();
    let (sorted_pks2, aggregate2) = aggregate_sorted_with_domain(&order2, &domain).unwrap();

    // Results should be identical regardless of input order
    assert_eq!(
        sorted_pks1
            .iter()
            .map(|pk| pk.to_bytes())
            .collect::<Vec<_>>(),
        sorted_pks2
            .iter()
            .map(|pk| pk.to_bytes())
            .collect::<Vec<_>>()
    );
    assert_eq!(aggregate1.to_bytes(), aggregate2.to_bytes());
}

// ============================================================================
// Fast Aggregate Verification Tests
// ============================================================================

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
fn test_fast_aggregate_verify_with_domain() {
    let domain = DomainTag::new_precommit("mainnet-1");
    let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    let pubkey_bytes: Vec<[u8; 48]> = keys.iter().map(|k| k.public_key().to_bytes()).collect();
    let message = b"fast verify test";

    let signatures: Vec<_> = keys
        .iter()
        .map(|k| k.sign_with_domain(message, &domain))
        .collect();
    let sig_refs: Vec<_> = signatures.iter().collect();

    let aggregate = BlsSignature::aggregate_with_domain(&sig_refs, &domain).unwrap();
    assert!(aggregate.fast_aggregate_verify_with_domain(message, &pubkey_bytes, &domain));
}

// ============================================================================
// ValidatorKeyPair Tests
// ============================================================================

#[test]
fn test_validator_keypair_generation() {
    let keypair = ValidatorKeyPair::generate();
    assert!(keypair.verify_proof_of_possession());
}

#[test]
fn test_validator_keypair_from_private_key() {
    let sk = BlsPrivateKey::random();
    let keypair = ValidatorKeyPair::from_private_key(sk);
    assert!(keypair.verify_proof_of_possession());
}

#[test]
fn test_validator_keypair_from_components() {
    let sk = BlsPrivateKey::random();
    let pop = sk.generate_proof_of_possession();

    let keypair = ValidatorKeyPair::from_components(sk.clone(), pop).unwrap();
    assert!(keypair.verify_proof_of_possession());
}

#[test]
fn test_validator_keypair_from_components_rejects_invalid_pop() {
    let sk1 = BlsPrivateKey::random();
    let sk2 = BlsPrivateKey::random();
    let wrong_pop = sk2.generate_proof_of_possession();

    let result = ValidatorKeyPair::from_components(sk1, wrong_pop);
    assert!(result.is_err());
}

#[test]
fn test_validator_keypair_sign_with_domain() {
    let keypair = ValidatorKeyPair::generate();
    let domain = DomainTag::new_proposal("mainnet-1");
    let message = b"block proposal";

    let sig = keypair.sign_with_domain(message, &domain);
    assert!(sig.verify_with_domain(message, keypair.public_key(), &domain));
}

// ============================================================================
// Public Key Operations
// ============================================================================

#[test]
fn test_public_key_ordering() {
    let keys: Vec<_> = (0..10)
        .map(|_| BlsPrivateKey::random().public_key())
        .collect();

    let mut sorted = keys.clone();
    sorted.sort();

    // Verify ordering is consistent
    for i in 0..sorted.len() - 1 {
        assert!(sorted[i] <= sorted[i + 1]);
    }
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
fn test_aggregate_public_keys_sorted() {
    let keys: Vec<_> = (0..5)
        .map(|_| BlsPrivateKey::random().public_key())
        .collect();
    let pk_refs: Vec<_> = keys.iter().collect();

    // Different input orders should produce same result
    let order1: Vec<_> = pk_refs.clone();
    let order2: Vec<_> = pk_refs.iter().rev().cloned().collect();

    let agg1 = BlsPublicKey::aggregate_sorted(&order1).unwrap();
    let agg2 = BlsPublicKey::aggregate_sorted(&order2).unwrap();

    assert_eq!(agg1.to_bytes(), agg2.to_bytes());
}

// ============================================================================
// Serialization Tests
// ============================================================================

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
fn test_domain_tag_serde() {
    let domain = DomainTag::new_prevote("mainnet-1");

    let json = serde_json::to_string(&domain).unwrap();
    let restored: DomainTag = serde_json::from_str(&json).unwrap();

    assert_eq!(domain.message_type(), restored.message_type());
    assert_eq!(domain.chain_id(), restored.chain_id());
}

// ============================================================================
// Helper Function Tests
// ============================================================================

#[test]
fn test_bls_verify_aggregate_helper() {
    let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
    let pubkey_bytes: Vec<[u8; 48]> = keys.iter().map(|k| k.public_key().to_bytes()).collect();
    let mut message = [0u8; 32];
    message.copy_from_slice(b"32 byte message for block hash!!");

    let signatures: Vec<_> = keys.iter().map(|k| k.sign(&message)).collect();
    let sig_bytes: Vec<[u8; 96]> = signatures.iter().map(|s| s.to_bytes()).collect();

    let aggregate_bytes = bls_aggregate(&sig_bytes).unwrap();
    assert!(bls_verify_aggregate(
        &pubkey_bytes,
        &message,
        &aggregate_bytes
    ));
}

// ============================================================================
// Security Tests - Rogue Key Attack Prevention
// ============================================================================

#[test]
fn test_rogue_key_attack_prevented_by_pop() {
    // In a rogue key attack, an attacker creates a key that cancels out another key
    // when aggregated. The PoP requirement prevents this because the attacker
    // cannot create a valid PoP for such a crafted key.

    let honest_sk = BlsPrivateKey::random();
    let honest_pk = honest_sk.public_key();
    let honest_pop = honest_sk.generate_proof_of_possession();

    // Honest key's PoP is valid
    assert!(honest_pop.verify(&honest_pk));

    // An attacker would need to create a rogue key with valid PoP
    // to participate in aggregation, but cannot do so without
    // knowing the private key
    let attacker_sk = BlsPrivateKey::random();
    let attacker_pop = attacker_sk.generate_proof_of_possession();

    // Attacker's PoP doesn't verify against honest key
    assert!(!attacker_pop.verify(&honest_pk));

    // This ensures that any key used in aggregation has been proven
    // to be created by someone who knows the private key
}

// ============================================================================
// Security Tests - Cross-Message Signature Reuse Prevention
// ============================================================================

#[test]
fn test_cross_message_signature_reuse_prevented() {
    let sk = BlsPrivateKey::random();
    let pk = sk.public_key();

    let prevote_domain = DomainTag::new_prevote("mainnet-1");
    let precommit_domain = DomainTag::new_precommit("mainnet-1");

    // Sign a prevote
    let prevote_sig = sk.sign_with_domain(b"block hash", &prevote_domain);

    // Attacker tries to reuse prevote signature as precommit
    // This should fail
    assert!(!prevote_sig.verify_with_domain(b"block hash", &pk, &precommit_domain));

    // Valid precommit requires new signature
    let precommit_sig = sk.sign_with_domain(b"block hash", &precommit_domain);
    assert!(precommit_sig.verify_with_domain(b"block hash", &pk, &precommit_domain));
}
