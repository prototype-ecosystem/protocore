//! # Proto Core Crypto
//!
//! Cryptographic primitives for the Proto Core blockchain.
//!
//! This crate provides:
//! - **Keccak256 hashing** - Ethereum-compatible hashing
//! - **ECDSA signatures** - secp256k1 signing and verification (Ethereum-style)
//! - **BLS12-381 signatures** - Aggregatable signatures for consensus
//!
//! ## Example
//!
//! ```rust
//! use protocore_crypto::{keccak256, ecdsa, bls};
//!
//! // Hash some data
//! let hash = keccak256(b"hello world");
//!
//! // Generate ECDSA key and sign
//! let private_key = ecdsa::PrivateKey::random();
//! let public_key = private_key.public_key();
//! let signature = private_key.sign_message(b"message").unwrap();
//!
//! // Verify signature
//! assert!(signature.verify_message(b"message", &public_key).unwrap());
//!
//! // Get Ethereum address
//! let address = public_key.to_address();
//! ```

pub mod bls;
pub mod ecdsa;
pub mod hash;
pub mod schnorr;
pub mod vrf;

// Re-export commonly used items
pub use bls::{
    BlsPrivateKey, BlsPublicKey, BlsSignature, BlsProofOfPossession,
    DomainTag, MessageType, ValidatorKeyPair,
    aggregate_sorted_with_domain, verify_proof_of_possession, batch_verify_proofs_of_possession,
};
pub use ecdsa::{Address, PrivateKey, PublicKey, Signature};
pub use hash::{keccak256, keccak256_concat, Hasher};
pub use schnorr::{batch_verify, SchnorrPublicKey, SchnorrSecretKey, SchnorrSignature};
pub use vrf::{VrfSecretKey, VrfPublicKey, VrfProof, VrfOutput};

/// Common type alias for 32-byte hash
pub type Hash = [u8; 32];

/// Error types for cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Invalid private key bytes
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid public key bytes
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature bytes
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    VerificationFailed,

    /// Failed to recover public key from signature
    #[error("failed to recover public key: {0}")]
    RecoveryFailed(String),

    /// BLS operation failed
    #[error("BLS operation failed: {0}")]
    BlsError(String),

    /// Invalid input length
    #[error("invalid input length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Hex decoding error
    #[error("hex decoding error: {0}")]
    HexError(String),
}

impl From<hex::FromHexError> for CryptoError {
    fn from(e: hex::FromHexError) -> Self {
        CryptoError::HexError(e.to_string())
    }
}

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_basic() {
        let hash = keccak256(b"hello");
        assert_eq!(hash.len(), 32);
        // Known Keccak256 hash of "hello"
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let private_key = ecdsa::PrivateKey::random();
        let public_key = private_key.public_key();
        let message = b"test message";

        let signature = private_key.sign_message(message).unwrap();
        assert!(signature.verify_message(message, &public_key).unwrap());
    }

    #[test]
    fn test_ecdsa_address_derivation() {
        let private_key = ecdsa::PrivateKey::random();
        let public_key = private_key.public_key();
        let address = public_key.to_address();

        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_bls_sign_verify() {
        let private_key = bls::BlsPrivateKey::random();
        let public_key = private_key.public_key();
        let message = b"test message";

        let signature = private_key.sign(message);
        assert!(signature.verify(message, &public_key));
    }

    #[test]
    fn test_bls_aggregate() {
        let keys: Vec<_> = (0..3).map(|_| bls::BlsPrivateKey::random()).collect();
        let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let message = b"consensus message";

        let signatures: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
        let sig_refs: Vec<_> = signatures.iter().collect();

        let aggregate = bls::BlsSignature::aggregate(&sig_refs).unwrap();
        let pubkey_refs: Vec<_> = pubkeys.iter().collect();
        assert!(aggregate.verify_aggregate(message, &pubkey_refs));
    }
}
