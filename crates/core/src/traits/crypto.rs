//! Cryptographic traits for signing and verification.
//!
//! This module defines abstract traits for cryptographic operations,
//! allowing different signature schemes (ECDSA, BLS, Schnorr, Ed25519)
//! to be used interchangeably.

use bytes::Bytes;
use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// The signature is invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// The public key is malformed.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The private key is malformed.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// The message is too long or malformed.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Aggregation operation failed (for BLS).
    #[error("aggregation failed: {0}")]
    AggregationFailed(String),

    /// The proof of possession is invalid (for BLS).
    #[error("invalid proof of possession")]
    InvalidProofOfPossession,

    /// Generic cryptographic error.
    #[error("crypto error: {0}")]
    Internal(String),
}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// A cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature(pub Bytes);

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get the raw bytes of the signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to owned bytes.
    pub fn to_bytes(&self) -> Bytes {
        self.0.clone()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A public key for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub Bytes);

impl PublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to owned bytes.
    pub fn to_bytes(&self) -> Bytes {
        self.0.clone()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Trait for digital signature creation.
///
/// Implementations provide signing capability for different
/// signature schemes (ECDSA, BLS, Schnorr, etc.).
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`).
///
/// # Example
///
/// ```ignore
/// use protocore_core::traits::{Signer, CryptoResult};
///
/// fn sign_message(signer: &impl Signer, message: &[u8]) -> CryptoResult<Signature> {
///     signer.sign(message)
/// }
/// ```
pub trait Signer: Send + Sync {
    /// Sign a message and return the signature.
    fn sign(&self, message: &[u8]) -> CryptoResult<Signature>;

    /// Get the public key corresponding to this signer.
    fn public_key(&self) -> PublicKey;

    /// Get the signature scheme identifier.
    fn scheme(&self) -> SignatureScheme;
}

/// Trait for signature verification.
///
/// Implementations verify signatures for different signature schemes.
///
/// # Thread Safety
///
/// Implementations must be thread-safe (`Send + Sync`).
///
/// # Example
///
/// ```ignore
/// use protocore_core::traits::{Verifier, PublicKey, Signature};
///
/// fn verify_signature(
///     verifier: &impl Verifier,
///     message: &[u8],
///     signature: &Signature,
///     pubkey: &PublicKey,
/// ) -> bool {
///     verifier.verify(message, signature, pubkey).is_ok()
/// }
/// ```
pub trait Verifier: Send + Sync {
    /// Verify a signature against a message and public key.
    ///
    /// Returns `Ok(())` if the signature is valid, `Err(CryptoError::InvalidSignature)` otherwise.
    fn verify(&self, message: &[u8], signature: &Signature, pubkey: &PublicKey)
        -> CryptoResult<()>;

    /// Get the signature scheme this verifier supports.
    fn scheme(&self) -> SignatureScheme;
}

/// Supported signature schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// ECDSA with secp256k1 (Ethereum compatible).
    Secp256k1Ecdsa,
    /// BLS12-381 signatures (used for consensus).
    Bls12381,
    /// Schnorr signatures.
    Schnorr,
    /// Ed25519 signatures.
    Ed25519,
}

impl SignatureScheme {
    /// Get the expected signature length in bytes.
    pub fn signature_length(&self) -> usize {
        match self {
            SignatureScheme::Secp256k1Ecdsa => 65, // r (32) + s (32) + v (1)
            SignatureScheme::Bls12381 => 96,       // G1 point
            SignatureScheme::Schnorr => 64,        // r (32) + s (32)
            SignatureScheme::Ed25519 => 64,        // signature
        }
    }

    /// Get the expected public key length in bytes.
    pub fn public_key_length(&self) -> usize {
        match self {
            SignatureScheme::Secp256k1Ecdsa => 33, // Compressed
            SignatureScheme::Bls12381 => 48,       // G1 point
            SignatureScheme::Schnorr => 33,        // Compressed
            SignatureScheme::Ed25519 => 32,        // Public key
        }
    }
}

/// Trait for BLS signature aggregation.
///
/// BLS signatures can be aggregated into a single signature that verifies
/// against multiple public keys, reducing storage and verification costs.
pub trait BlsAggregator: Send + Sync {
    /// Aggregate multiple signatures into one.
    fn aggregate_signatures(&self, signatures: &[Signature]) -> CryptoResult<Signature>;

    /// Aggregate multiple public keys into one.
    fn aggregate_public_keys(&self, pubkeys: &[PublicKey]) -> CryptoResult<PublicKey>;

    /// Verify an aggregated signature against aggregated public keys.
    fn verify_aggregated(
        &self,
        message: &[u8],
        signature: &Signature,
        pubkeys: &[PublicKey],
    ) -> CryptoResult<()>;

    /// Verify proof of possession for a BLS public key.
    ///
    /// PoP prevents rogue key attacks by proving the signer knows the private key.
    fn verify_proof_of_possession(&self, pubkey: &PublicKey, proof: &Signature)
        -> CryptoResult<()>;
}

/// Trait for key pair generation.
pub trait KeyGenerator: Send + Sync {
    /// Generate a new random key pair.
    fn generate(&self) -> CryptoResult<(Box<dyn Signer>, PublicKey)>;

    /// Derive a key pair from a seed.
    fn from_seed(&self, seed: &[u8]) -> CryptoResult<(Box<dyn Signer>, PublicKey)>;

    /// Get the signature scheme this generator produces.
    fn scheme(&self) -> SignatureScheme;
}

/// Trait for hash functions.
pub trait Hasher: Send + Sync {
    /// Compute the hash of the input.
    fn hash(&self, data: &[u8]) -> Bytes;

    /// Get the output length of this hash function.
    fn output_length(&self) -> usize;

    /// Get the hash function identifier.
    fn algorithm(&self) -> HashAlgorithm;
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// Keccak-256 (Ethereum compatible).
    Keccak256,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
    /// Blake2b-256.
    Blake2b256,
    /// Blake3.
    Blake3,
}

impl HashAlgorithm {
    /// Get the output length in bytes.
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Keccak256 => 32,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Blake2b256 => 32,
            HashAlgorithm::Blake3 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_scheme_lengths() {
        assert_eq!(SignatureScheme::Secp256k1Ecdsa.signature_length(), 65);
        assert_eq!(SignatureScheme::Bls12381.signature_length(), 96);
        assert_eq!(SignatureScheme::Secp256k1Ecdsa.public_key_length(), 33);
        assert_eq!(SignatureScheme::Bls12381.public_key_length(), 48);
    }

    #[test]
    fn test_signature_from_bytes() {
        let sig = Signature::from_bytes(vec![1, 2, 3, 4]);
        assert_eq!(sig.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let pk = PublicKey::from_bytes(vec![5, 6, 7, 8]);
        assert_eq!(pk.as_bytes(), &[5, 6, 7, 8]);
    }
}
